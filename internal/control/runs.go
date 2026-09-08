package control

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/cyber-shuttle/cs-control/internal/authn"
)

// A card outlives its allocations and a machine accumulates cards, so the
// history is bounded here rather than growing with use.
const maxRunRecords = 200

// RunResponse is what one finished allocation did. A card outlives its
// allocations, so a run is named by the generation that ran it: relaunching a
// card leaves the previous run behind rather than overwriting it.
type RunResponse struct {
	RuntimeID  string         `json:"runtimeId"`
	Generation string         `json:"generation"`
	SSHHost    string         `json:"sshHost"`
	Account    string         `json:"account,omitempty"`
	Partition  string         `json:"partition"`
	RootFolder string         `json:"rootFolder"`
	Resources  Resources      `json:"resources"`
	FinalState string         `json:"finalState"`
	Error      string         `json:"error,omitempty"`
	StartedAt  time.Time      `json:"startedAt,omitzero"`
	EndedAt    time.Time      `json:"endedAt"`
	Stats      *RunStats      `json:"stats,omitempty"`
	Samples    []MetricSample `json:"samples,omitempty"`
}

// RunRecord is the persisted run. Owner is held for filtering and, like the
// runtime's, is never returned.
type RunRecord struct {
	RunResponse
	Owner authn.Principal `json:"owner"`
}

type RunList struct {
	Runs []RunResponse `json:"runs"`
}

func publicRuns(runs []RunRecord) []RunResponse {
	result := make([]RunResponse, len(runs))
	for index := range runs {
		result[index] = runs[index].RunResponse
	}
	return result
}

// runOf freezes what an allocation did, taking the sample window with it: the
// window is process-local and about to be dropped, and it is most of what makes
// the report readable when Slurm's accounting has nothing to add.
//
// It ended when it reached its terminal state, which is what UpdatedAt holds:
// the reconciliation that retires a runtime stamps it, and a relaunch or a
// delete days later must not restamp that run as having just finished.
func (s Service) runOf(runtime *Runtime) RunRecord {
	return RunRecord{
		RunResponse: RunResponse{
			RuntimeID: runtime.ID, Generation: runtime.Generation, SSHHost: runtime.SSHHost,
			Account: runtime.Account, Partition: runtime.Partition, RootFolder: runtime.RootFolder,
			Resources:  runtime.Resources,
			FinalState: runtime.State, Error: runtime.Error, StartedAt: runtime.StartedAt,
			EndedAt: runtime.UpdatedAt, Samples: s.Metrics.Series(runtime.ID),
		},
		Owner: runtime.Owner,
	}
}

// recordRun keeps one allocation's outcome, newest first and bounded. A run is
// recorded once: the reconciliation that first sees a terminal state writes it,
// and a later stop, relaunch or delete of the same generation finds it already
// there.
func recordRun(current *state, record RunRecord) bool {
	if record.Generation == "" || slices.ContainsFunc(current.Runs, func(existing RunRecord) bool {
		return existing.RuntimeID == record.RuntimeID && existing.Generation == record.Generation
	}) {
		return false
	}
	current.Runs = append([]RunRecord{record}, current.Runs...)
	if len(current.Runs) > maxRunRecords {
		current.Runs = current.Runs[:maxRunRecords]
	}
	return true
}

// RecordRun freezes a finished allocation under the store's lock, so a record
// cannot be lost to the delete that drops the runtime beside it.
func (s Service) RecordRun(runtime *Runtime) error {
	return s.Store.withLock(func(store Store, current *state) error {
		if !recordRun(current, s.runOf(runtime)) {
			return nil
		}
		return store.save(current)
	})
}

// ListRuns answers the caller's own history, newest first.
func (s Service) ListRuns(principal authn.Principal) ([]RunRecord, error) {
	var owned []RunRecord
	if err := s.Store.withLock(func(_ Store, current *state) error {
		for _, run := range current.Runs {
			if run.Owner == principal {
				owned = append(owned, run)
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return owned, nil
}

// completeRunStats fills in Slurm's accounting for runs frozen without it.
// slurmdbd flushes step usage a beat after a job ends, so the reconciliation
// that first sees the terminal state is too early to read it and this is
// retried until the flush lands or the run ages out of the window below.
const runStatsWindow = 10 * time.Minute

func (s Service) completeRunStats(ctx context.Context) {
	pending, err := s.pendingRunStats()
	if err != nil {
		return
	}
	for scope, jobs := range pending {
		for _, job := range jobs {
			stats, err := s.forPrincipal(scope.owner).readRunStats(ctx, scope.host, job.jobName)
			if err != nil || !stats.Complete() {
				continue
			}
			_ = s.attachRunStats(job.runtimeID, job.generation, stats)
		}
	}
}

type pendingRun struct {
	runtimeID  string
	generation string
	jobName    string
}

// pendingRunStats groups by owner and host, since that is what an SSH round is.
func (s Service) pendingRunStats() (map[schedulerScope][]pendingRun, error) {
	pending := map[schedulerScope][]pendingRun{}
	cutoff := s.now().Add(-runStatsWindow)
	err := s.Store.withLock(func(_ Store, current *state) error {
		for _, run := range current.Runs {
			if run.Stats != nil || run.EndedAt.Before(cutoff) {
				continue
			}
			scope := schedulerScope{owner: run.Owner, host: run.SSHHost}
			pending[scope] = append(pending[scope], pendingRun{
				runtimeID: run.RuntimeID, generation: run.Generation,
				jobName: jobName(run.RuntimeID, run.Generation),
			})
		}
		return nil
	})
	return pending, err
}

func (s Service) readRunStats(ctx context.Context, host, name string) (RunStats, error) {
	output, err := s.Runner.Run(ctx, host, nil, "sacct", "-P", "-n", "--units=K", "--name="+name, "--format="+sacctUtilFormat)
	if err != nil {
		return RunStats{}, err
	}
	return parseSacctUtil(strings.TrimSpace(output)), nil
}

func (s Service) attachRunStats(runtimeID, generation string, stats RunStats) error {
	return s.Store.withLock(func(store Store, current *state) error {
		for index := range current.Runs {
			run := &current.Runs[index]
			if run.RuntimeID != runtimeID || run.Generation != generation || run.Stats != nil {
				continue
			}
			run.Stats = &stats
			return store.save(current)
		}
		return nil
	})
}

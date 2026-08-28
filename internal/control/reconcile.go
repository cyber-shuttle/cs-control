package control

import (
	"context"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cyber-shuttle/cs-control/internal/sshexec"
)

type schedulerObservation struct {
	jobID string
	state string
	node  string
	// How long Slurm says the job has been running, in whole seconds. Absent
	// from squeue, so zero means "not reported" rather than "just started".
	elapsedSeconds int64
}

type cancellationTarget struct {
	key     string
	flag    string
	value   string
	runtime string
}

const schedulerMarkerCancel = "__CSCTL_SCANCEL__"
const schedulerMarkerQueue = "__CSCTL_SQUEUE__"
const schedulerMarkerAccounting = "__CSCTL_SACCT__"

// Slurm stops reporting a job eventually and a login node is not always
// reachable, so an observation cannot be the only thing that retires a runtime.
const (
	// How long after submission a job may be missing from squeue and sacct both.
	schedulerPropagationWindow = 2 * time.Minute
	// The gap between a job reaching its --time and Slurm reaping it.
	allocationWallGrace = 10 * time.Minute
	// How much further back than the oldest runtime sacct is asked to look, so a
	// clock that disagrees with ours cannot clip the newest one out of the answer.
	schedulerLookbackSlack = time.Hour
	// The furthest back it is ever asked to look. A window is a query against the
	// cluster's accounting database, so an unbounded one is slow for everybody;
	// and a runtime still unaccounted for after this long is one the scheduler has
	// already stopped knowing about, which absence retires on its own.
	schedulerLookbackMax = 30 * 24 * time.Hour
)

// startedRuntime reports whether Slurm had begun running the allocation, which
// is what makes its --time a deadline rather than an open-ended queue wait.
func startedRuntime(runtime Runtime) bool {
	return runtime.State == "STARTING" || runtime.State == "READY"
}

// outlivedAllocation reports that the allocation cannot still be running,
// whatever the scheduler last said: Slurm kills a job at its --time. A queued
// one has no such deadline -- it may wait for days -- so only the scheduler can
// retire that.
func outlivedAllocation(runtime Runtime, now time.Time) bool {
	if !startedRuntime(runtime) || runtime.StartedAt.IsZero() || runtime.Resources.WallMinutes <= 0 {
		return false
	}
	limit := time.Duration(runtime.Resources.WallMinutes)*time.Minute + allocationWallGrace
	return now.Sub(runtime.StartedAt) > limit
}

// unknownToScheduler reports that a scheduler which answered has had long
// enough to know this job and does not. Measured from the submission, not the
// card: a relaunch keeps the card's creation time, whose window ran out during
// the run it replaced.
func unknownToScheduler(runtime Runtime, now time.Time) bool {
	return now.Sub(runtime.UpdatedAt) > schedulerPropagationWindow
}

// reconcileSnapshots performs all scheduler and endpoint I/O without holding
// the state lock. Scheduler calls are batched into one SSH execution per host.
func (s Service) reconcileSnapshots(ctx context.Context, snapshots []Runtime) []Runtime {
	results := append([]Runtime(nil), snapshots...)
	byHost := map[string][]int{}
	for i := range results {
		if reconcile(results[i].State) {
			byHost[results[i].SSHHost] = append(byHost[results[i].SSHHost], i)
		}
	}
	var wg sync.WaitGroup
	for host, indexes := range byHost {
		host, indexes := host, indexes
		wg.Add(1)
		go func() {
			defer wg.Done()
			group := make([]Runtime, len(indexes))
			for position, index := range indexes {
				group[position] = results[index]
			}
			observations, cancelErrors, err := s.schedulerObservations(ctx, host, group)
			if err != nil {
				// Service shutdown or a superseded background refresh must leave the
				// last good persisted runtime state completely untouched.
				if ctx.Err() != nil {
					return
				}
				for _, index := range indexes {
					if !s.reconciliationSnapshotCurrent(snapshots[index]) {
						continue
					}
					// No answer is not the same as no allocation, so the last good
					// state stands -- until the allocation's own --time has passed,
					// after which Slurm has certainly reaped it and a host we cannot
					// reach must not pin the runtime to a state it left long ago.
					if outlivedAllocation(results[index], s.now()) {
						results[index].State = "STOPPED"
						results[index].Error = ""
						s.runtimeStatus(results[index].ID, "Allocation reached its wall-time limit")
						continue
					}
					results[index].Error = err.Error()
					s.runtimeStatus(results[index].ID, "Runtime status check failed")
				}
				return
			}
			for _, index := range indexes {
				if !s.reconciliationSnapshotCurrent(snapshots[index]) {
					continue
				}
				runtime := &results[index]
				previousState, previousNode := runtime.State, runtime.Node
				observation, ok := observations[runtime.ID]
				if !ok {
					// Slurm can briefly omit a newly submitted job from both squeue and
					// sacct. Retain the last good active state without presenting that
					// expected propagation window as a runtime failure. STOPPING still
					// exposes missing cancellation state because cleanup depends on it.
					if runtime.State != "STOPPING" {
						// Past that window the scheduler answered and does not know this
						// job, which is an observation in its own right: the allocation
						// is over, however it ended. Retaining the last state here is
						// what used to leave a finished runtime reading READY forever.
						if unknownToScheduler(*runtime, s.now()) {
							runtime.State = "STOPPED"
							runtime.Error = ""
							s.runtimeStatus(runtime.ID, "Allocation is no longer known to the scheduler")
						}
						continue
					}
					if message := cancelErrors[runtime.ID]; message != "" {
						runtime.Error = message
					} else {
						runtime.Error = "scheduler returned no state"
					}
					s.runtimeStatus(runtime.ID, "Runtime status is temporarily unavailable")
					continue
				}
				if runtime.JobID == "" && observation.jobID != "" {
					runtime.JobID = observation.jobID
				}
				_ = setRuntimeNode(runtime, observation.node)
				if runtime.Node != "" && runtime.Node != previousNode {
					s.runtimeStatus(runtime.ID, "Compute node assigned: "+runtime.Node)
				}
				class := classifySchedulerState(observation.state)
				// A word this scheduler vocabulary does not cover says nothing about
				// the allocation, so it is not an observation. Retaining the last good
				// state here is what lets every state below be a pure function of the
				// class, with no fall-through and no second opinion about readiness.
				if class == schedulerUnknown {
					continue
				}
				if class == schedulerActive && runtime.StartedAt.IsZero() {
					// Anchor the wall-time countdown to Slurm's reported elapsed
					// run-time rather than to this poll: the allocation may have been
					// running long before anyone looked, and cs-bridge anchors the same
					// deadline the same way. Without an elapsed figure the poll is the
					// best estimate available, and it only ever errs late.
					runtime.StartedAt = s.now().Add(-time.Duration(observation.elapsedSeconds) * time.Second)
				}
				wasStopping := runtime.State == "STOPPING"
				next := nextState(runtime.State, class)
				if next == "STOPPED" || next == "FAILED" {
					s.runtimeStatus(runtime.ID, "Cleaning up runtime credentials")
					cleanupErr := s.Credentials.Delete(runtime.ID, runtime.Generation)
					if cleanupErr != nil {
						runtime.State = "STOPPING"
						runtime.Error = "runtime cleanup pending: " + cleanupErr.Error()
						s.runtimeStatus(runtime.ID, "Runtime cleanup is pending")
						continue
					}
					s.runtimeStatus(runtime.ID, "Runtime credential cleanup complete")
				}
				runtime.State = next
				if next != previousState {
					switch next {
					case "QUEUED":
						s.runtimeStatus(runtime.ID, "Runtime is queued")
					case "STARTING":
						s.runtimeStatus(runtime.ID, "Allocation is starting")
					case "READY":
						s.runtimeStatus(runtime.ID, "Allocation is running")
					case "STOPPED":
						if class == schedulerExpired {
							s.runtimeStatus(runtime.ID, "Runtime reached its walltime")
						} else {
							s.runtimeStatus(runtime.ID, "Runtime stopped")
						}
					case "FAILED":
						s.runtimeStatus(runtime.ID, "Runtime failed")
					}
				}
				if wasStopping && runtime.State == "STOPPING" {
					runtime.Error = cancelErrors[runtime.ID]
				} else {
					runtime.Error = ""
				}
			}
		}()
	}
	wg.Wait()
	if ctx.Err() != nil {
		return snapshots
	}

	// Startup file collection shares the first running reconciliation round.
	// Keep the allocation in STARTING until that collection completes, then
	// expose scheduler-confirmed readiness without consulting Linkspan.
	collected := s.collectStartingRuntimeLogs(ctx, results)
	if ctx.Err() != nil {
		return snapshots
	}
	for index := range results {
		if _, ok := collected[results[index].ID]; ok && results[index].State == "STARTING" {
			results[index].State = "READY"
			s.runtimeStatus(results[index].ID, "Allocation is running")
		}
	}

	return results
}

// schedulerClass is the family a raw Slurm state belongs to. The scheduler's
// vocabulary is parsed in exactly one place so the policies below cannot drift.
type schedulerClass int

const (
	schedulerUnknown schedulerClass = iota
	schedulerPending
	schedulerActive
	schedulerStopped
	schedulerExpired
	schedulerFailed
)

func classifySchedulerState(raw string) schedulerClass {
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return schedulerUnknown
	}
	switch strings.TrimSuffix(strings.ToUpper(fields[0]), "+") {
	case "PENDING", "REQUEUED", "REQUEUE_FED", "REQUEUE_HOLD", "SUSPENDED":
		return schedulerPending
	case "RUNNING", "CONFIGURING", "COMPLETING", "RESIZING", "SIGNALING", "STAGE_OUT":
		return schedulerActive
	case "COMPLETED", "CANCELLED", "STOPPED":
		return schedulerStopped
	// An allocation that runs out its walltime has done exactly what it was
	// asked to do, so it ends stopped rather than failed; the class is kept
	// apart only so the owner is told which of the two happened.
	case "TIMEOUT":
		return schedulerExpired
	case "BOOT_FAIL", "DEADLINE", "FAILED", "NODE_FAIL", "OUT_OF_MEMORY", "PREEMPTED", "REVOKED", "SPECIAL_EXIT":
		return schedulerFailed
	}
	return schedulerUnknown
}

// nextState is the allocation's state after one scheduler observation. A stop in
// progress and a runtime already reported ready both latch, so a live
// observation can never regress either. Callers must have excluded
// schedulerUnknown, which is the absence of an observation rather than a class.
func nextState(current string, class schedulerClass) string {
	switch {
	case current == "STOPPING" && (class == schedulerPending || class == schedulerActive):
		return "STOPPING"
	case class == schedulerPending:
		return "QUEUED"
	case class == schedulerActive && current == "READY":
		return "READY"
	case class == schedulerActive:
		return "STARTING"
	case class == schedulerStopped || class == schedulerExpired:
		return "STOPPED"
	}
	return "FAILED"
}

func cancellationTargets(runtimes []Runtime) []cancellationTarget {
	seen := map[string]bool{}
	targets := make([]cancellationTarget, 0)
	for _, runtime := range runtimes {
		if runtime.State != "STOPPING" {
			continue
		}
		target := cancellationTarget{runtime: runtime.ID}
		if runtime.JobID != "" {
			target.key, target.value = "id:"+runtime.JobID, runtime.JobID
		} else {
			target.key, target.flag, target.value = "name:"+runtime.JobName, "--name", runtime.JobName
		}
		if seen[target.key] {
			continue
		}
		seen[target.key] = true
		targets = append(targets, target)
	}
	slices.SortFunc(targets, func(a, b cancellationTarget) int { return strings.Compare(a.key, b.key) })
	return targets
}

func appendCancellation(script *strings.Builder, target cancellationTarget) {
	// scancel is deliberately outside `set -e`: an already-terminal job is a
	// normal race and must never prevent the scheduler observations below.
	script.WriteString("csctl_cancel_output=$(scancel ")
	if target.flag != "" {
		script.WriteString(target.flag)
		script.WriteString("=")
	}
	script.WriteString(sshexec.ShellQuote(target.value))
	script.WriteString(" 2>&1)\ncsctl_cancel_status=$?\n")
	script.WriteString("if [ \"$csctl_cancel_status\" -ne 0 ]; then\n")
	script.WriteString("  csctl_cancel_message=$(printf '%s' \"$csctl_cancel_output\" | tr '\\n|' '  ')\n")
	script.WriteString("  printf '%s|%s|%s\\n' ")
	script.WriteString(sshexec.ShellQuote(schedulerMarkerCancel))
	script.WriteString(" ")
	script.WriteString(sshexec.ShellQuote(target.key))
	script.WriteString(" \"$csctl_cancel_message\"\nfi\n")
}

func (s Service) schedulerObservations(ctx context.Context, host string, runtimes []Runtime) (map[string]schedulerObservation, map[string]string, error) {
	names := make([]string, 0, len(runtimes))
	for _, runtime := range runtimes {
		names = append(names, runtime.JobName)
	}
	slices.Sort(names)
	targets := cancellationTargets(runtimes)
	var script strings.Builder
	script.WriteString("set -u\n")
	for _, target := range targets {
		appendCancellation(&script, target)
	}
	script.WriteString("printf '%s\\n' ")
	script.WriteString(sshexec.ShellQuote(schedulerMarkerQueue))
	script.WriteString("\nsqueue --me --noheader --format='%i|%T|%N|%j'\n")
	script.WriteString("printf '%s\\n' ")
	script.WriteString(sshexec.ShellQuote(schedulerMarkerAccounting))
	// sacct defaults to jobs from midnight today, which silently hides every
	// allocation submitted before it -- the runtime then reads as missing rather
	// than finished, and keeps its last state. Ask far enough back to cover the
	// oldest runtime in this batch instead.
	script.WriteString("\nsacct --noheader -X --starttime=")
	script.WriteString(sshexec.ShellQuote(schedulerLookback(runtimes, s.now())))
	script.WriteString(" --name=")
	script.WriteString(sshexec.ShellQuote(strings.Join(names, ",")))
	script.WriteString(" --format=JobIDRaw,State,NodeList,JobName,ElapsedRaw --parsable2\n")
	output, err := s.Runner.Run(ctx, host, strings.NewReader(script.String()), "sh", "-s", "--", "csctl-runtime-status")
	if err != nil {
		return nil, nil, err
	}
	byID, byName := map[string]schedulerObservation{}, map[string]schedulerObservation{}
	cancelByKey := map[string]string{}
	section := ""
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, schedulerMarkerCancel+"|") {
			parts := strings.SplitN(line, "|", 3)
			if len(parts) == 3 {
				cancelByKey[parts[1]] = strings.TrimSpace(parts[2])
			}
			continue
		}
		switch line {
		case schedulerMarkerQueue:
			section = "queue"
			continue
		case schedulerMarkerAccounting:
			section = "accounting"
			continue
		case "":
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) < 4 || !jobPattern.MatchString(strings.TrimSpace(parts[0])) {
			continue
		}
		observation := schedulerObservation{jobID: strings.TrimSpace(parts[0]), state: strings.TrimSpace(parts[1]), node: strings.TrimSpace(parts[2])}
		if len(parts) > 4 {
			if seconds, err := strconv.ParseInt(strings.TrimSpace(parts[4]), 10, 64); err == nil && seconds >= 0 {
				observation.elapsedSeconds = seconds
			}
		}
		name := strings.TrimSpace(parts[3])
		if section == "queue" || byID[observation.jobID].jobID == "" {
			byID[observation.jobID], byName[name] = observation, observation
		}
	}
	result := make(map[string]schedulerObservation, len(runtimes))
	cancelErrors := make(map[string]string)
	for _, runtime := range runtimes {
		if runtime.JobID != "" {
			if observation, ok := byID[runtime.JobID]; ok {
				result[runtime.ID] = observation
			}
		} else if observation, ok := byName[runtime.JobName]; ok {
			result[runtime.ID] = observation
		}
		if runtime.State == "STOPPING" {
			key := "name:" + runtime.JobName
			if runtime.JobID != "" {
				key = "id:" + runtime.JobID
			}
			if message := cancelByKey[key]; message != "" {
				cancelErrors[runtime.ID] = message
			}
		}
	}
	return result, cancelErrors, nil
}

func (s Service) reconciliationSnapshotCurrent(snapshot Runtime) bool {
	current := false
	_ = s.Store.withLock(func(_ Store, state *state) error {
		runtime := state.Runtimes[snapshot.ID]
		current = runtime != nil && runtime.UpdatedAt.Equal(snapshot.UpdatedAt) && runtime.State == snapshot.State && runtime.JobID == snapshot.JobID
		return nil
	})
	return current
}

func changedReconciliation(before, after Runtime) bool {
	return before.State != after.State || before.Error != after.Error || before.JobID != after.JobID || before.Node != after.Node || !before.StartedAt.Equal(after.StartedAt)
}

func mergeReconciled(current, snapshot, candidate *Runtime, now time.Time) bool {
	if current == nil || !current.UpdatedAt.Equal(snapshot.UpdatedAt) || current.State != snapshot.State || current.JobID != snapshot.JobID {
		return false
	}
	if !changedReconciliation(*snapshot, *candidate) {
		return false
	}
	current.State, current.Error, current.JobID, current.Node, current.UpdatedAt = candidate.State, candidate.Error, candidate.JobID, candidate.Node, now
	current.StartedAt = candidate.StartedAt
	return true
}

func sortedRuntimeCopies(current *state) []Runtime {
	result := make([]Runtime, 0, len(current.Runtimes))
	for _, id := range slices.Sorted(maps.Keys(current.Runtimes)) {
		result = append(result, *current.Runtimes[id])
	}
	return result
}

// schedulerLookback is how far back sacct is asked to look: far enough to cover
// the oldest runtime in the batch, plus an hour so a clock that disagrees with
// ours cannot clip the newest one out of the answer.
//
// It is deliberately relative. Slurm reads an absolute --starttime in the
// cluster's own timezone, which is not necessarily ours, so an absolute stamp
// can land in the cluster's future -- and sacct then refuses the whole range
// with "Start time ... is after end time", failing every status check. A
// relative one the cluster evaluates against its own clock needs no agreement
// about zones at all.
func schedulerLookback(runtimes []Runtime, now time.Time) string {
	oldest := now
	for _, runtime := range runtimes {
		if !runtime.CreatedAt.IsZero() && runtime.CreatedAt.Before(oldest) {
			oldest = runtime.CreatedAt
		}
	}
	window := now.Sub(oldest) + schedulerLookbackSlack
	if window < schedulerLookbackSlack {
		window = schedulerLookbackSlack
	}
	if window > schedulerLookbackMax {
		window = schedulerLookbackMax
	}
	return "now-" + strconv.FormatInt(int64(window.Seconds()), 10) + "seconds"
}

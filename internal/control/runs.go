// A run is the one durable trace a session leaves once it ends, named by the seq that ran it.
// recordRun freezes a run the moment a session first reaches a terminal state.
// completeRunStats then rides the sampling tick to fill in Slurm's accounting, which lands after the job ends.
//
//	maxRunRecords, runStatsWindow
//	runResponse, runRecord, runList
//	sacctUtilFormat
//	runStats
//	field, parseKiB, humanKiB, hmsSeconds
//	parseSacctUtil, Complete
//	recordRun
//	Service
//	runOf, freezeRun, freezeIfTerminal, listRuns
//	readRunStats, attachRunStats, pendingRunStats, completeRunStats
package control

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/cyber-shuttle/cs-control/internal/authn"
)

const maxRunRecords = 200

type runResponse struct {
	SessionID  string           `json:"sessionId"`
	Seq        int              `json:"seq"`
	SSHHost    string           `json:"sshHost"`
	Account    string           `json:"account,omitempty"`
	Partition  string           `json:"partition"`
	RootFolder string           `json:"rootFolder"`
	Resources  resources        `json:"resources"`
	FinalState string           `json:"finalState"`
	Error      string           `json:"error,omitempty"`
	StartedAt  time.Time        `json:"startedAt,omitzero"`
	EndedAt    time.Time        `json:"endedAt"`
	Stats      *runStats        `json:"stats,omitempty"`
	Samples    []metricSample   `json:"samples,omitempty"`
	Logs       []sessionLogLine `json:"logs,omitempty"`
}

type runRecord struct {
	runResponse
	Owner authn.Principal `json:"owner"`
}

type runList struct {
	Runs []runResponse `json:"runs"`
}

const sacctUtilFormat = "JobID,AllocCPUs,ReqMem,ElapsedRaw,CPUTimeRAW,MaxRSS,TotalCPU"

const runStatsWindow = 10 * time.Minute

type runStats struct {
	Cores               int     `json:"cores,omitempty"`
	RequestedMemory     string  `json:"requestedMemory,omitempty"`
	ElapsedSeconds      int64   `json:"elapsedSeconds,omitempty"`
	MaxRSS              string  `json:"maxRss,omitempty"`
	CPUEfficiencyPct    float64 `json:"cpuEfficiencyPct,omitempty"`
	MemoryEfficiencyPct float64 `json:"memoryEfficiencyPct,omitempty"`
}

func field(row []string, index int) string {
	if index >= len(row) {
		return ""
	}
	return row[index]
}

func parseKiB(value string) (float64, bool) {
	text := strings.TrimSpace(value)
	end := 0
	for end < len(text) && (text[end] >= '0' && text[end] <= '9' || text[end] == '.' || end == 0 && (text[end] == '-' || text[end] == '+')) {
		end++
	}
	number, err := strconv.ParseFloat(text[:end], 64)
	return number, err == nil
}

func humanKiB(kib float64) string {
	switch {
	case kib >= 1024*1024:
		return fmt.Sprintf("%.1f GB", kib/(1024*1024))
	case kib >= 1024:
		return fmt.Sprintf("%.1f MB", kib/1024)
	default:
		return fmt.Sprintf("%.0f KB", kib)
	}
}

func hmsSeconds(value string) float64 {
	text := strings.TrimSpace(value)
	if text == "" {
		return 0
	}
	days, rest := "0", text
	if before, after, found := strings.Cut(text, "-"); found {
		days, rest = before, after
	}
	parts := strings.Split(rest, ":")
	if len(parts) < 2 {
		return 0
	}
	seconds := 0.0
	for _, part := range parts {
		value, err := strconv.ParseFloat(strings.TrimSpace(part), 64)
		if err != nil {
			return 0
		}
		seconds = seconds*60 + value
	}
	dayCount, err := strconv.ParseFloat(strings.TrimSpace(days), 64)
	if err != nil {
		return 0
	}
	return dayCount*86400 + seconds
}

func parseSacctUtil(output string) runStats {
	var rows [][]string
	for _, line := range strings.Split(output, "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			rows = append(rows, strings.Split(trimmed, "|"))
		}
	}
	if len(rows) == 0 {
		return runStats{}
	}
	alloc, usage := rows[0], rows[0]
	for _, row := range rows {
		if !strings.Contains(row[0], ".") {
			alloc = row
			break
		}
	}
	for _, row := range rows {
		if strings.HasSuffix(row[0], ".batch") {
			usage = row
			break
		}
	}

	stats := runStats{}
	if cores, err := strconv.Atoi(strings.TrimSpace(field(alloc, 1))); err == nil && cores > 0 {
		stats.Cores = cores
	}
	if elapsed, err := strconv.ParseInt(strings.TrimSpace(field(alloc, 3)), 10, 64); err == nil {
		stats.ElapsedSeconds = elapsed
	}
	requestedKiB, hasRequested := parseKiB(field(alloc, 2))
	allocCPUSeconds, _ := strconv.ParseFloat(strings.TrimSpace(field(alloc, 4)), 64)
	maxRSSKiB, hasMaxRSS := parseKiB(field(usage, 5))
	usedCPUSeconds := hmsSeconds(field(usage, 6))

	if hasRequested {
		stats.RequestedMemory = humanKiB(requestedKiB)
	}
	if hasMaxRSS {
		stats.MaxRSS = humanKiB(maxRSSKiB)
	}
	if usedCPUSeconds > 0 && allocCPUSeconds > 0 {
		stats.CPUEfficiencyPct = usedCPUSeconds / allocCPUSeconds * 100
	}
	if hasMaxRSS && hasRequested && requestedKiB > 0 {
		stats.MemoryEfficiencyPct = maxRSSKiB / requestedKiB * 100
	}
	return stats
}

func (s runStats) Complete() bool { return s.MaxRSS != "" }

func recordRun(current *state, record runRecord) bool {
	if record.Seq == 0 || slices.ContainsFunc(current.Runs, func(existing runRecord) bool {
		return existing.SessionID == record.SessionID && existing.Seq == record.Seq
	}) {
		return false
	}
	current.Runs = append([]runRecord{record}, current.Runs...)
	if len(current.Runs) > maxRunRecords {
		current.Runs = current.Runs[:maxRunRecords]
	}
	return true
}

func (s Service) runOf(session *Session) runRecord {
	logTail, _ := s.Logs.Tail(session.ID)
	return runRecord{
		runResponse: runResponse{
			SessionID: session.ID, Seq: session.Seq, SSHHost: session.SSHHost,
			Account: session.Account, Partition: session.Partition, RootFolder: session.RootFolder,
			Resources:  session.Resources,
			FinalState: session.State, Error: session.Error, StartedAt: session.StartedAt,
			EndedAt: session.UpdatedAt, Samples: s.Metrics.Series(session.ID),
			Logs: logTail.Lines,
		},
		Owner: session.Owner,
	}
}

func (s Service) freezeRun(session *Session) error {
	return s.Store.withLock(func(current *state) error {
		changed, err := s.freezeIfTerminal(current, session)
		if !changed {
			return err
		}
		if saveErr := s.Store.save(current); saveErr != nil {
			return saveErr
		}
		return err
	})
}

func (s Service) freezeIfTerminal(current *state, session *Session) (bool, error) {
	if !terminalSession(session.State) {
		return false, nil
	}
	if err := s.Credentials.Delete(session.ID, session.Seq); err != nil {
		session.State, session.Error = "STOPPING", "session cleanup pending: "+boundedSessionError(err)
		return true, err
	}
	if !recordRun(current, s.runOf(session)) {
		return false, nil
	}
	s.forgetSessionBuffers(session.ID)
	return true, nil
}

func (s Service) listRuns(principal authn.Principal) ([]runRecord, error) {
	var owned []runRecord
	if err := s.Store.withLock(func(current *state) error {
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

func (s Service) readRunStats(ctx context.Context, host, name string, startedAt time.Time) (runStats, error) {
	lookback := sacctLookback(startedAt, s.now())
	output, err := s.Runner.Run(ctx, host, nil, "sacct", "-P", "-n", "--units=K", "--starttime="+lookback, "--name="+name, "--format="+sacctUtilFormat)
	if err != nil {
		return runStats{}, err
	}
	return parseSacctUtil(strings.TrimSpace(output)), nil
}

func (s Service) attachRunStats(sessionID string, seq int, stats runStats) error {
	return s.Store.withLock(func(current *state) error {
		for index := range current.Runs {
			run := &current.Runs[index]
			if run.SessionID != sessionID || run.Seq != seq || run.Stats != nil {
				continue
			}
			run.Stats = &stats
			return s.Store.save(current)
		}
		return nil
	})
}

func (s Service) pendingRunStats() ([]runRecord, error) {
	cutoff := s.now().Add(-runStatsWindow)
	var due []runRecord
	err := s.Store.withLock(func(current *state) error {
		for _, run := range current.Runs {
			if run.Stats == nil && !run.EndedAt.Before(cutoff) {
				due = append(due, run)
			}
		}
		return nil
	})
	return due, err
}

func (s Service) completeRunStats() {
	due, err := s.pendingRunStats()
	if err != nil {
		return
	}
	for _, run := range due {
		ctx, cancel := s.ownTimeout()
		stats, err := s.forPrincipal(run.Owner).readRunStats(ctx, run.SSHHost, jobName(run.SessionID, run.Seq), run.StartedAt)
		cancel()
		if err != nil || !stats.Complete() {
			continue
		}
		_ = s.attachRunStats(run.SessionID, run.Seq, stats)
	}
}

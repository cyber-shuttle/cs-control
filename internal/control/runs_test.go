// A run is recorded once a session first reaches a terminal state, keeping its final window and narration.
// Each generation gets its own run, and history is filtered to its owner and bounded.
// This file also covers the sacct accounting parser reading a finished job's usage.
//
//	runsIn
//	Test*
package control

import (
	"context"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/cyber-shuttle/cs-control/internal/sshexec"
	"github.com/cyber-shuttle/cs-control/internal/testutil"
)

const sacctRows = `12345|4|8192000K|3600|14400|||
12345.batch|4|8192000K|3600|14400|4096000K|02:00:00
12345.extern|4|8192000K|3600|14400|4K|00:00:00`

func runsIn(t *testing.T, service Service) []runRecord {
	t.Helper()
	runs, err := service.listRuns(testPrincipal)
	testutil.Check(t, err)
	return runs
}

func TestARunOutlivesTheSessionThatEnded(t *testing.T) {
	service, _, _ := reconciliationService(t)
	session := pendingSession("s-111111111111", "alpha", "101")
	session.State = "READY"
	putSessions(t, service, session)
	used := int64(4096)
	service.Metrics.Append(session.ID, metricSample{At: time.Now(), MemBytes: &used})

	t.Setenv("FAKE_STATUS_LINES", "101|COMPLETED|node1|"+session.JobName+"|3600")
	testutil.Check(t, service.reconcileAll(context.Background()))
	runs := runsIn(t, service)
	if len(runs) != 1 || runs[0].FinalState != "STOPPED" || runs[0].SessionID != session.ID {
		t.Fatalf("a finished session left no usable record: %+v", runs)
	}
	if len(runs[0].Samples) != 1 || *runs[0].Samples[0].MemBytes != used {
		t.Fatalf("the sample window did not travel with the run: %+v", runs[0].Samples)
	}
	if got := service.Metrics.Series(session.ID); len(got) != 0 {
		t.Fatalf("a finished session kept its live window: %+v", got)
	}
	endedAt := runs[0].EndedAt

	testutil.Check(t, service.reconcileAll(context.Background()))
	if runs := runsIn(t, service); len(runs) != 1 {
		t.Fatalf("the same run was recorded %d times", len(runs))
	} else if !runs[0].EndedAt.Equal(endedAt) {
		t.Fatalf("a later reconcile moved EndedAt from %s to %s, the terminal transition's own time", endedAt, runs[0].EndedAt)
	}
}

func TestEachGenerationIsItsOwnRun(t *testing.T) {
	service, _, _ := reconciliationService(t)
	session := pendingSession("s-111111111111", "alpha", "101")
	session.State = "STOPPED"
	setTestSessionMetadata(&session)
	testutil.Check(t, service.freezeRun(&session))
	second := session
	second.Generation = "g-fedcba9876543210"
	second.Resources.Cores = 8
	testutil.Check(t, service.freezeRun(&second))
	runs := runsIn(t, service)
	if len(runs) != 2 {
		t.Fatalf("a relaunch overwrote the previous run: %+v", runs)
	}
	if runs[0].Generation != second.Generation || runs[0].Resources.Cores != 8 {
		t.Fatalf("the newest run is not first, or lost its own session: %+v", runs[0])
	}
	testutil.Check(t, service.freezeRun(&second))
	if runs := runsIn(t, service); len(runs) != 2 {
		t.Fatalf("recording the same generation twice kept %d runs", len(runs))
	}
}

func TestRunHistoryIsFilteredToItsOwner(t *testing.T) {
	service, _, _ := reconciliationService(t)
	mine := pendingSession("s-111111111111", "alpha", "101")
	mine.State = "STOPPED"
	setTestSessionMetadata(&mine)
	theirs := pendingSession("s-222222222222", "alpha", "102")
	theirs.State = "STOPPED"
	setTestSessionMetadata(&theirs)
	theirs.Owner.Subject = "someone-else"
	for _, session := range []*Session{&mine, &theirs} {
		testutil.Check(t, service.freezeRun(session))
	}
	runs := runsIn(t, service)
	if len(runs) != 1 || runs[0].SessionID != mine.ID {
		t.Fatalf("the history is not the caller's own: %+v", runs)
	}
}

func TestARunKeepsTheNarrationAndTheSessionLosesIt(t *testing.T) {
	service, _, _ := reconciliationService(t)
	session := pendingSession("s-111111111111", "alpha", "101")
	session.State = "READY"
	putSessions(t, service, session)
	service.Logs.Append(session.ID, "Session is running", service.now())

	t.Setenv("FAKE_STATUS_LINES", "101|COMPLETED|node1|"+session.JobName+"|3600")
	testutil.Check(t, service.reconcileAll(context.Background()))
	runs := runsIn(t, service)
	testutil.Equal(t, len(runs), 1, "run count")
	if len(runs[0].Logs) == 0 {
		t.Fatal("the run kept none of what the session said")
	}
	var found bool
	for _, line := range runs[0].Logs {
		if line.Text == "Session is running" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the run lost the narration: %+v", runs[0].Logs)
	}
	if _, ok := service.Logs.Tail(session.ID); ok {
		t.Fatal("a finished session kept its live tail")
	}
}

func TestRunHistoryIsBounded(t *testing.T) {
	current := &state{Version: stateVersion, Sessions: map[string]*Session{}}
	for index := 0; index < maxRunRecords+10; index++ {
		recordRun(current, runRecord{runResponse: runResponse{
			SessionID: "s-111111111111", Generation: "g-" + strconv.Itoa(index),
		}})
	}
	testutil.Equal(t, len(current.Runs), maxRunRecords, "run history length")
}

func TestParseSacctUtilReadsUsageFromTheBatchStep(t *testing.T) {
	stats := parseSacctUtil(sacctRows)
	if stats.Cores != 4 || stats.ElapsedSeconds != 3600 {
		t.Fatalf("session figures came from the wrong row: %+v", stats)
	}
	if stats.RequestedMemory != "7.8 GB" || stats.MaxRSS != "3.9 GB" {
		t.Fatalf("memory was not read in KiB from the right rows: %+v", stats)
	}
	if stats.CPUEfficiencyPct < 49.9 || stats.CPUEfficiencyPct > 50.1 {
		t.Fatalf("CPU efficiency = %v, want ~50", stats.CPUEfficiencyPct)
	}
	if stats.MemoryEfficiencyPct < 49.9 || stats.MemoryEfficiencyPct > 50.1 {
		t.Fatalf("memory efficiency = %v, want ~50", stats.MemoryEfficiencyPct)
	}
	if !stats.Complete() {
		t.Fatal("a row carrying a peak reads as incomplete")
	}
}

func TestParseSacctUtilTreatsAnUnflushedRowAsIncomplete(t *testing.T) {
	stats := parseSacctUtil("12345|4|8192000K|3600|14400||\n12345.batch|4|8192000K|3600|14400||00:00:00")
	if stats.Complete() {
		t.Fatalf("an unflushed row reads as a finished report: %+v", stats)
	}
	if stats.CPUEfficiencyPct != 0 || stats.MaxRSS != "" {
		t.Fatalf("an unflushed row invented figures: %+v", stats)
	}
	if stats.Cores != 4 || stats.ElapsedSeconds != 3600 {
		t.Fatalf("what the session asked for is known regardless: %+v", stats)
	}
	if stats := parseSacctUtil("\n  \n"); stats != (runStats{}) {
		t.Fatalf("empty accounting produced %+v", stats)
	}
}

func TestReadRunStatsBoundsSacctByTheRunsStartTimeNotSacctsMidnightDefault(t *testing.T) {
	ssh, _, _ := fakeSSH(t)
	runStatsLog := filepath.Join(t.TempDir(), "run-stats")
	t.Setenv("FAKE_RUN_STATS_LOG", runStatsLog)
	t.Setenv("FAKE_RUN_STATS_OUTPUT", sacctRows)
	service := Service{Runner: sshexec.Runner{SSHBin: ssh, Timeout: 5 * time.Second, ControlNamespace: filepath.Join(t.TempDir(), "masters")}}

	startedAt := time.Now().Add(-36 * time.Hour)
	stats, err := service.readRunStats(context.Background(), "alpha", "job-name", startedAt)
	testutil.Check(t, err)
	if !stats.Complete() {
		t.Fatalf("stats did not parse: %+v", stats)
	}
	sent := string(mustRead(t, runStatsLog))
	match := regexp.MustCompile(`--starttime=now-(\d+)seconds`).FindStringSubmatch(sent)
	if match == nil {
		t.Fatalf("run stats did not bound sacct by a lookback, letting it default to midnight: %s", sent)
	}
	seconds, err := strconv.ParseInt(match[1], 10, 64)
	testutil.Check(t, err)
	if want := int64((36 * time.Hour).Seconds()); seconds < want {
		t.Fatalf("lookback of %d seconds does not reach the run's start, 36 hours ago", seconds)
	}
}

func TestCompleteRunStatsGivesEachPendingRunItsOwnTimeout(t *testing.T) {
	ssh, _, _ := fakeSSH(t)
	sleepOnce := filepath.Join(t.TempDir(), "sacct-slept-once")
	t.Setenv("FAKE_RUN_STATS_SLEEP_ONCE", sleepOnce)
	t.Setenv("FAKE_RUN_STATS_SLEEP_SECONDS", "2")
	t.Setenv("FAKE_RUN_STATS_OUTPUT", sacctRows)
	service := Service{Runner: sshexec.Runner{SSHBin: ssh, Timeout: time.Second}, Store: Store{Dir: t.TempDir()}, Config: Config{HostsDir: filepath.Join(t.TempDir(), "hosts")}, Logs: NewSessionLogs(), Metrics: NewSessionMetrics()}
	registerTestHosts(t, service, testPrincipal, "delta")
	slow := runRecord{runResponse: runResponse{SessionID: "s-111111111111", Generation: "g-0000000000000001", SSHHost: "delta", EndedAt: service.now()}, Owner: testPrincipal}
	fast := runRecord{runResponse: runResponse{SessionID: "s-222222222222", Generation: "g-0000000000000002", SSHHost: "delta", EndedAt: service.now()}, Owner: testPrincipal}
	if err := service.Store.withLock(func(current *state) error {
		current.Runs = []runRecord{slow, fast}
		return service.Store.save(current)
	}); err != nil {
		t.Fatal(err)
	}

	service.completeRunStats()

	runs := runsIn(t, service)
	var gotFast bool
	for _, run := range runs {
		if run.Generation == fast.Generation {
			gotFast = run.Stats != nil
		}
	}
	if !gotFast {
		t.Fatal("a slow run starved the timeout of the pending run behind it")
	}
}

func TestHMSSecondsReadsSlurmDurations(t *testing.T) {
	for text, want := range map[string]float64{
		"02:00:00":   7200,
		"1-00:00:00": 86400,
		"05:30":      330,
		"":           0,
		"not-a-time": 0,
		"00:00:00":   0,
	} {
		if got := hmsSeconds(text); got != want {
			t.Errorf("hmsSeconds(%q) = %v, want %v", text, got, want)
		}
	}
}

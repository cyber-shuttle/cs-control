package control

import (
	"context"
	"strconv"
	"testing"
	"time"
)

func runsIn(t *testing.T, service Service) []RunRecord {
	t.Helper()
	runs, err := service.ListRuns(testPrincipal)
	if err != nil {
		t.Fatal(err)
	}
	return runs
}

// The reconciliation that first sees a terminal state is the last moment the
// allocation's own sample window still describes it, so that is where the run
// is frozen -- and it must survive the delete that drops the runtime beside it.
func TestAFinishedAllocationIsRecordedAndOutlivesItsRuntime(t *testing.T) {
	service, _, _ := reconciliationService(t)
	service.Metrics = NewRuntimeMetrics()
	runtime := pendingRuntime("rt-111111111111", "alpha", "101")
	runtime.State = "READY"
	putRuntimes(t, service, runtime)
	used := int64(4096)
	service.Metrics.Append(runtime.ID, MetricSample{At: time.Now(), MemBytes: &used})

	t.Setenv("FAKE_STATUS_LINES", "101|COMPLETED|node1|"+runtime.JobName+"|3600")
	if err := service.ReconcileAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	runs := runsIn(t, service)
	if len(runs) != 1 || runs[0].FinalState != "STOPPED" || runs[0].RuntimeID != runtime.ID {
		t.Fatalf("a finished allocation left no usable record: %+v", runs)
	}
	// The window is process-local and about to be dropped, so it rides along.
	if len(runs[0].Samples) != 1 || *runs[0].Samples[0].MemBytes != used {
		t.Fatalf("the sample window did not travel with the run: %+v", runs[0].Samples)
	}
	if got := service.Metrics.Series(runtime.ID); len(got) != 0 {
		t.Fatalf("a finished allocation kept its live window: %+v", got)
	}

	// Reconciling again must not write the run a second time.
	if err := service.ReconcileAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if runs := runsIn(t, service); len(runs) != 1 {
		t.Fatalf("the same run was recorded %d times", len(runs))
	}
}

// A run belongs to the generation that ran it, not to the card: a caller's
// history keeps both, and each carries what its own allocation asked for.
func TestEachGenerationIsItsOwnRun(t *testing.T) {
	service, _, _ := reconciliationService(t)
	service.Metrics = NewRuntimeMetrics()
	runtime := pendingRuntime("rt-111111111111", "alpha", "101")
	runtime.State = "STOPPED"
	setTestRuntimeMetadata(&runtime)
	if err := service.RecordRun(&runtime); err != nil {
		t.Fatal(err)
	}
	second := runtime
	second.Generation = "g-fedcba9876543210"
	second.Resources.Cores = 8
	if err := service.RecordRun(&second); err != nil {
		t.Fatal(err)
	}
	runs := runsIn(t, service)
	if len(runs) != 2 {
		t.Fatalf("a relaunch overwrote the previous run: %+v", runs)
	}
	// Newest first, so the history reads as it happened.
	if runs[0].Generation != second.Generation || runs[0].Resources.Cores != 8 {
		t.Fatalf("the newest run is not first, or lost its own allocation: %+v", runs[0])
	}
	if err := service.RecordRun(&second); err != nil {
		t.Fatal(err)
	}
	if runs := runsIn(t, service); len(runs) != 2 {
		t.Fatalf("recording the same generation twice kept %d runs", len(runs))
	}
}

// The history is one caller's own, like the runtime list.
func TestRunHistoryIsFilteredToItsOwner(t *testing.T) {
	service, _, _ := reconciliationService(t)
	service.Metrics = NewRuntimeMetrics()
	mine := pendingRuntime("rt-111111111111", "alpha", "101")
	setTestRuntimeMetadata(&mine)
	theirs := pendingRuntime("rt-222222222222", "alpha", "102")
	setTestRuntimeMetadata(&theirs)
	theirs.Owner.Subject = "someone-else"
	for _, runtime := range []*Runtime{&mine, &theirs} {
		if err := service.RecordRun(runtime); err != nil {
			t.Fatal(err)
		}
	}
	runs := runsIn(t, service)
	if len(runs) != 1 || runs[0].RuntimeID != mine.ID {
		t.Fatalf("the history is not the caller's own: %+v", runs)
	}
}

// A card outlives its allocations and a machine accumulates cards, so the
// history is bounded rather than growing with use.
// A card that stopped days ago and is run again today did not finish today. The
// relaunch used to restamp the previous run as having just ended, which made a
// long-finished run read as the live one.
func TestARunKeepsTheTimeItActuallyEnded(t *testing.T) {
	service, _, _ := reconciliationService(t)
	service.Metrics = NewRuntimeMetrics()
	stopped := pendingRuntime("rt-111111111111", "alpha", "101")
	stopped.State = "STOPPED"
	ended := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	stopped.UpdatedAt = ended
	setTestRuntimeMetadata(&stopped)

	if err := service.RecordRun(&stopped); err != nil {
		t.Fatal(err)
	}
	runs := runsIn(t, service)
	if len(runs) != 1 {
		t.Fatalf("expected one run, got %d", len(runs))
	}
	if !runs[0].EndedAt.Equal(ended) {
		t.Fatalf("run ended at %s, want the terminal transition at %s", runs[0].EndedAt, ended)
	}
}

// What a runtime said belongs to the run that said it: the live tail is
// process-local and dropped the moment the run ends, so a card that is no
// longer running has no log and its run carries the whole of it.
func TestARunKeepsTheNarrationAndTheCardLosesIt(t *testing.T) {
	service, _, _ := reconciliationService(t)
	service.Metrics = NewRuntimeMetrics()
	runtime := pendingRuntime("rt-111111111111", "alpha", "101")
	runtime.State = "READY"
	putRuntimes(t, service, runtime)
	service.Logs.Append(runtime.ID, "Allocation is running")

	t.Setenv("FAKE_STATUS_LINES", "101|COMPLETED|node1|"+runtime.JobName+"|3600")
	if err := service.ReconcileAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	runs := runsIn(t, service)
	if len(runs) != 1 {
		t.Fatalf("expected one run, got %d", len(runs))
	}
	if len(runs[0].Logs) == 0 {
		t.Fatal("the run kept none of what the allocation said")
	}
	var found bool
	for _, line := range runs[0].Logs {
		if line.Text == "Allocation is running" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the run lost the narration: %+v", runs[0].Logs)
	}
	// The card is over, so nothing live remains to show beside its run.
	if _, ok := service.Logs.Tail(runtime.ID); ok {
		t.Fatal("a finished runtime kept its live tail")
	}
}

func TestRunHistoryIsBounded(t *testing.T) {
	current := &state{Version: stateVersion, Runtimes: map[string]*Runtime{}}
	for index := 0; index < maxRunRecords+10; index++ {
		recordRun(current, RunRecord{RunResponse: RunResponse{
			RuntimeID: "rt-111111111111", Generation: "g-" + strconv.Itoa(index),
		}})
	}
	if len(current.Runs) != maxRunRecords {
		t.Fatalf("history grew to %d records", len(current.Runs))
	}
}

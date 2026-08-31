package control

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cyber-shuttle/cs-control/internal/sshexec"
)

// reconciliationService is a service whose scheduler answers are the rows in
// FAKE_STATUS_LINES. It returns the fake's command log and the path the fake
// waits on before answering.
func reconciliationService(t *testing.T) (Service, string, string) {
	t.Helper()
	ssh, _, commandLog := fakeSSH(t)
	dir := t.TempDir()
	service := Service{Runner: sshexec.Runner{SSHBin: ssh, Timeout: 5 * time.Second}, Store: Store{Dir: filepath.Join(dir, "state")}}
	configureTestTunnel(t, &service)
	return service, commandLog, filepath.Join(dir, "release")
}

func setTestRuntimeMetadata(runtime *Runtime) {
	if runtime.Generation == "" {
		runtime.Generation = "g-0123456789abcdef"
		runtime.Owner = testPrincipal
		runtime.Tunnel = TunnelMetadata{ID: runtime.ID + "-" + runtime.Generation, ClusterID: "use", ExpiresAt: time.Now().Add(time.Hour)}
	}
}

func putRuntimes(t *testing.T, service Service, runtimes ...Runtime) {
	t.Helper()
	if err := service.Store.withLock(func(store Store, current *state) error {
		for i := range runtimes {
			copy := runtimes[i]
			setTestRuntimeMetadata(&copy)
			current.Runtimes[copy.ID] = &copy
		}
		return store.save(current)
	}); err != nil {
		t.Fatal(err)
	}
}

func pendingRuntime(id, host, jobID string) Runtime {
	now := time.Unix(1, 0).UTC()
	return Runtime{
		RuntimeResponse: RuntimeResponse{ID: id, State: "QUEUED", SSHHost: host, Partition: "cpu", RootFolder: ".", Resources: Resources{Cores: 1, MemoryMB: 1024, WallMinutes: 60}, CreatedAt: now, UpdatedAt: now},
		JobID:           jobID, JobName: "cs-" + id, PrivateRoot: "/home/test/.cybershuttle/runtimes/" + id, WorkspaceRoot: "/home/test",
	}
}

func TestCancelledReconciliationPreservesLastGoodRuntime(t *testing.T) {
	service, _, _ := reconciliationService(t)
	runtime := pendingRuntime("rt-111111111111", "alpha", "101")
	runtime.State = "READY"
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got := service.reconcileSnapshots(ctx, []Runtime{runtime})
	if !reflect.DeepEqual(got, []Runtime{runtime}) {
		t.Fatalf("cancelled refresh changed persisted presentation state: %#v", got)
	}
}

func TestReconcileUsesOneRoundPerMixedHostAndNoneForTerminal(t *testing.T) {
	service, log, _ := reconciliationService(t)
	one := pendingRuntime("rt-111111111111", "alpha", "101")
	two := pendingRuntime("rt-222222222222", "beta", "202")
	terminal := pendingRuntime("rt-333333333333", "gamma", "303")
	terminal.State = "FAILED"
	t.Setenv("FAKE_STATUS_LINES", "101|PENDING||"+one.JobName+"\\n202|PENDING||"+two.JobName)
	putRuntimes(t, service, one, two, terminal)
	if _, err := reconciledList(context.Background(), service); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(log)
	if got := strings.Count(string(data), "csctl-runtime-status"); got != 2 || strings.Contains(string(data), "gamma|") {
		t.Fatalf("unexpected scheduler rounds: %s", data)
	}
}

func stoppingRuntime(id, host, jobID string) Runtime {
	runtime := pendingRuntime(id, host, jobID)
	runtime.State = "STOPPING"
	return runtime
}

func TestStoppingFailedCancelKeepsActiveStateAndDiagnostic(t *testing.T) {
	service, log, _ := reconciliationService(t)
	stopping := stoppingRuntime("rt-111111111111", "alpha", "101")
	unrelated := pendingRuntime("rt-222222222222", "alpha", "202")
	t.Setenv("FAKE_CANCEL_ERRORS", "id:101|scheduler temporarily unavailable")
	t.Setenv("FAKE_STATUS_LINES", "101|RUNNING|cn001|"+stopping.JobName+"\\n202|PENDING|cn002|"+unrelated.JobName)
	putRuntimes(t, service, stopping, unrelated)

	listed, err := reconciledList(context.Background(), service)
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]Runtime{}
	for _, runtime := range listed {
		byID[runtime.ID] = runtime
	}
	if got := byID[stopping.ID]; got.State != "STOPPING" || got.Error != "scheduler temporarily unavailable" {
		t.Fatalf("active stopping runtime lost cancellation diagnostic: %#v", got)
	}
	if got := byID[unrelated.ID]; got.State != "QUEUED" || got.Error != "" || got.Node != "cn002" {
		t.Fatalf("unrelated runtime did not reconcile: %#v", got)
	}
	assertOneSchedulerRound(t, log, "alpha")
}

func TestStoppingUnknownSubmissionUsesJobNameAndObservesState(t *testing.T) {
	service, log, _ := reconciliationService(t)
	runtime := stoppingRuntime("rt-111111111111", "alpha", "")
	t.Setenv("FAKE_CANCEL_ERRORS", "name:"+runtime.JobName+"|submission cancellation pending")
	t.Setenv("FAKE_STATUS_LINES", "777|PENDING||"+runtime.JobName)
	putRuntimes(t, service, runtime)

	listed, err := reconciledList(context.Background(), service)
	if err != nil {
		t.Fatal(err)
	}
	if listed[0].JobID != "777" || listed[0].State != "STOPPING" || listed[0].Error != "submission cancellation pending" {
		t.Fatalf("unknown stopping submission was not reconciled: %#v", listed[0])
	}
	assertOneSchedulerRound(t, log, "alpha")
	script := string(mustRead(t, os.Getenv("FAKE_STATUS_SCRIPT_LOG")))
	if !strings.Contains(script, "scancel --name='"+runtime.JobName+"'") {
		t.Fatalf("unknown submission was not cancelled by unique job name:\n%s", script)
	}
}

func assertOneSchedulerRound(t *testing.T, log, host string) {
	t.Helper()
	data := string(mustRead(t, log))
	if strings.Count(data, host+"|'sh' '-s' '--' 'csctl-runtime-status'") != 1 {
		t.Fatalf("scheduler calls were not one round for %s: %s", host, data)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestReconcileDoesNotHoldStoreLockDuringSSHAndDoesNotOverwriteStop(t *testing.T) {
	service, log, release := reconciliationService(t)
	started := filepath.Join(t.TempDir(), "started")
	t.Setenv("FAKE_STATUS_STARTED", started)
	t.Setenv("FAKE_STATUS_RELEASE", release)
	runtime := pendingRuntime("rt-111111111111", "alpha", "101")
	t.Setenv("FAKE_STATUS_LINES", "101|PENDING||"+runtime.JobName)
	putRuntimes(t, service, runtime)
	done := make(chan error, 1)
	go func() { _, err := reconciledList(context.Background(), service); done <- err }()
	waitForFile(t, log)

	lockAvailable := make(chan error, 1)
	go func() { lockAvailable <- service.Store.withLock(func(Store, *state) error { return nil }) }()
	select {
	case err := <-lockAvailable:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(300 * time.Millisecond):
		t.Fatal("state lock was held during blocked SSH")
	}
	if _, err := service.Stop(testTunnelContext(), runtime.ID); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(release, []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	got, err := reconciledGet(context.Background(), service, runtime.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != "STOPPING" && got.State != "STOPPED" {
		t.Fatalf("stale list overwrote stop intent: %#v", got)
	}
}

// An allocation that runs out its walltime has done what it was asked to do.
// Slurm reports that as TIMEOUT, which sits beside genuine faults in its
// vocabulary and read as a failed runtime to the owner.
func TestWalltimeExpiryStopsTheRuntimeRatherThanFailingIt(t *testing.T) {
	for raw, want := range map[string]string{
		"TIMEOUT":       "STOPPED",
		"COMPLETED":     "STOPPED",
		"CANCELLED":     "STOPPED",
		"NODE_FAIL":     "FAILED",
		"OUT_OF_MEMORY": "FAILED",
		"FAILED":        "FAILED",
		"BOOT_FAIL":     "FAILED",
		"PREEMPTED":     "FAILED",
	} {
		if got := nextState("READY", classifySchedulerState(raw)); got != want {
			t.Errorf("slurm %s left the runtime %s, want %s", raw, got, want)
		}
	}
	if classifySchedulerState("TIMEOUT") == classifySchedulerState("COMPLETED") {
		t.Error("a walltime expiry must stay distinguishable so the owner is told which stop it was")
	}
}

// startedRuntime builds an allocation Slurm has already begun running, which is
// what puts it under its own --time deadline.
func runningRuntime(id, host, jobID string, startedAt time.Time, wallMinutes int) Runtime {
	runtime := pendingRuntime(id, host, jobID)
	runtime.State = "READY"
	runtime.StartedAt = startedAt
	runtime.Resources.WallMinutes = wallMinutes
	return runtime
}

// A scheduler that answered and does not know the job is reporting that the
// allocation is over. Retaining the last state here is what left a finished
// runtime reading READY indefinitely.
func TestSchedulerThatDoesNotKnowTheJobRetiresTheRuntime(t *testing.T) {
	service, _, _ := reconciliationService(t)
	runtime := pendingRuntime("rt-111111111111", "alpha", "101")
	runtime.State = "READY"
	t.Setenv("FAKE_STATUS_LINES", "")
	putRuntimes(t, service, runtime)
	got := service.reconcileSnapshots(context.Background(), []Runtime{runtime})
	if got[0].State != "STOPPED" {
		t.Fatalf("a runtime the scheduler has no record of stayed %s, want STOPPED", got[0].State)
	}
}

// Slurm briefly omits a newly submitted job from squeue and sacct both, so
// absence inside that window says nothing about the allocation.
func TestFreshlySubmittedRuntimeSurvivesTheSchedulerPropagationWindow(t *testing.T) {
	service, _, _ := reconciliationService(t)
	runtime := pendingRuntime("rt-111111111111", "alpha", "101")
	// A card run again keeps a creation time whose window ran out during the run
	// it replaced, so the window has to belong to this submission.
	runtime.CreatedAt, runtime.UpdatedAt = time.Now().Add(-6*time.Hour).UTC(), time.Now().UTC()
	t.Setenv("FAKE_STATUS_LINES", "")
	putRuntimes(t, service, runtime)
	got := service.reconcileSnapshots(context.Background(), []Runtime{runtime})
	if got[0].State != "QUEUED" {
		t.Fatalf("a just-submitted runtime was retired as %s during the propagation window", got[0].State)
	}
}

// A login node we cannot reach must not pin a runtime to a state it left long
// ago: Slurm kills the job at its --time whether or not anyone can see it.
func TestUnreachableSchedulerRetiresAnAllocationPastItsWalltime(t *testing.T) {
	service, _, _ := reconciliationService(t)
	runtime := runningRuntime("rt-111111111111", "alpha", "101", time.Now().Add(-4*time.Hour), 60)
	putRuntimes(t, service, runtime)
	t.Setenv("FAKE_STATUS_FAIL", "1")
	got := service.reconcileSnapshots(context.Background(), []Runtime{runtime})
	if got[0].State != "STOPPED" {
		t.Fatalf("an allocation four hours past a one-hour walltime stayed %s, want STOPPED", got[0].State)
	}
	if got[0].Error != "" {
		t.Fatalf("a runtime the clock retired still carries a scheduler error: %q", got[0].Error)
	}
}

// Inside its walltime the allocation may well still be running, so an
// unreachable scheduler is a diagnostic rather than a verdict.
func TestUnreachableSchedulerKeepsAnAllocationInsideItsWalltime(t *testing.T) {
	service, _, _ := reconciliationService(t)
	runtime := runningRuntime("rt-111111111111", "alpha", "101", time.Now().Add(-5*time.Minute), 60)
	putRuntimes(t, service, runtime)
	t.Setenv("FAKE_STATUS_FAIL", "1")
	got := service.reconcileSnapshots(context.Background(), []Runtime{runtime})
	if got[0].State != "READY" {
		t.Fatalf("an allocation inside its walltime was retired as %s by an unreachable scheduler", got[0].State)
	}
	if got[0].Error == "" {
		t.Fatal("an unreachable scheduler left no diagnostic on the runtime")
	}
}

// sacct reports jobs from midnight today unless asked otherwise, which hid
// every allocation submitted before it.
func TestSchedulerQueryAsksSacctForJobsOlderThanToday(t *testing.T) {
	service, _, _ := reconciliationService(t)
	scripts := os.Getenv("FAKE_STATUS_SCRIPT_LOG")
	runtime := pendingRuntime("rt-111111111111", "alpha", "101")
	t.Setenv("FAKE_STATUS_LINES", "101|PENDING||"+runtime.JobName)
	putRuntimes(t, service, runtime)
	service.reconcileSnapshots(context.Background(), []Runtime{runtime})
	sent := string(mustRead(t, scripts))
	if !strings.Contains(sent, "sacct --noheader -X --starttime=") {
		t.Fatalf("sacct was asked without a start time, so anything older than today is invisible:\n%s", sent)
	}
	// Relative, not absolute: Slurm reads an absolute --starttime in the
	// cluster's timezone, so a stamp of ours can land in its future.
	if !strings.Contains(sent, "--starttime='now-") {
		t.Fatalf("the accounting window must be relative to the cluster's own clock:\n%s", sent)
	}
}

// The allocation may have been running long before anyone looked, so the
// wall-time countdown is anchored to Slurm's own elapsed figure rather than to
// the poll. cs-bridge anchors the same deadline the same way.
func TestStartedAtComesFromSlurmElapsedNotThePollTime(t *testing.T) {
	service, _, _ := reconciliationService(t)
	runtime := pendingRuntime("rt-111111111111", "alpha", "101")
	// squeue rows carry four fields; the sacct row carries the elapsed seconds.
	t.Setenv("FAKE_STATUS_LINES", "101|RUNNING|node1|"+runtime.JobName+"|7200")
	putRuntimes(t, service, runtime)
	got := service.reconcileSnapshots(context.Background(), []Runtime{runtime})
	elapsed := time.Since(got[0].StartedAt)
	if elapsed < 2*time.Hour-time.Minute || elapsed > 2*time.Hour+time.Minute {
		t.Fatalf("a job Slurm says ran for two hours was anchored %s ago, not ~2h", elapsed)
	}
}

// Slurm kills a running job at its --time, so an allocation anchored further
// back than that is over the moment it is seen. A queued one may wait for days
// under no such deadline: only the scheduler retires that, and only by answering.
func TestOnlyAStartedAllocationIsUnderAWalltimeDeadline(t *testing.T) {
	for _, test := range []struct {
		state string
		want  bool
	}{{"READY", true}, {"QUEUED", false}} {
		runtime := pendingRuntime("rt-111111111111", "alpha", "101")
		runtime.State = test.state
		runtime.Resources.WallMinutes = 60
		runtime.StartedAt = time.Now().Add(-4 * time.Hour)
		if got := outlivedAllocation(runtime, time.Now()); got != test.want {
			t.Errorf("a %s allocation four hours into a one-hour walltime = %v, want %v", test.state, got, test.want)
		}
	}
}

// A UTC stamp sent to a cluster west of UTC lands in that cluster's future, and
// sacct then refuses the whole range with "Start time ... is after end time",
// failing every status check. The window is therefore relative, always reaches
// back far enough to cover the oldest runtime, and is capped so it never becomes
// a scan of the cluster's whole accounting history.
func TestSchedulerLookbackIsRelativeBoundedAndReachesTheOldestRuntime(t *testing.T) {
	now := time.Now()
	longest := int64(schedulerLookbackMax.Seconds())
	for name, test := range map[string]struct {
		created  time.Time
		min, max int64
	}{
		"90 seconds old":    {now.Add(-90 * time.Second), 90, longest},
		"created now":       {now, 1, longest},
		"created in future": {now.Add(10 * time.Minute), 1, longest},
		"no creation time":  {time.Time{}, 1, longest},
		"created in 1970":   {time.Unix(1, 0), longest, longest},
	} {
		runtime := pendingRuntime("rt-111111111111", "alpha", "101")
		runtime.CreatedAt = test.created
		got := schedulerLookback([]Runtime{runtime}, now)
		if !strings.HasPrefix(got, "now-") || !strings.HasSuffix(got, "seconds") {
			t.Errorf("%s: lookback %q is not relative to the cluster's clock", name, got)
			continue
		}
		seconds, err := strconv.ParseInt(strings.TrimSuffix(strings.TrimPrefix(got, "now-"), "seconds"), 10, 64)
		if err != nil {
			t.Errorf("%s: lookback %q does not carry a count Slurm can read: %v", name, got, err)
			continue
		}
		if seconds < test.min || seconds > test.max {
			t.Errorf("%s: lookback of %d seconds is outside [%d, %d]", name, seconds, test.min, test.max)
		}
	}
}

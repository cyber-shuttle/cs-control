package control

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cyber-shuttle/cs-control/internal/sshexec"
)

func reconciliationService(t *testing.T) (Service, string, string) {
	t.Helper()
	dir := t.TempDir()
	log := filepath.Join(dir, "rounds")
	scripts := filepath.Join(dir, "scripts")
	logReads := filepath.Join(dir, "log-reads")
	release := filepath.Join(dir, "release")
	ssh := filepath.Join(dir, "ssh")
	script := `#!/bin/sh
set -eu
if [ "$1" = -G ]; then printf 'host %s\nhostname %s.example\nuser tester\nport 22\n' "$2" "$2"; exit 0; fi
while [ "$1" = -o ]; do shift 2; done
alias=$1; shift
wire=$1
printf '%s|%s\n' "$alias" "$wire" >> "$RECONCILE_LOG"
case "$wire" in
  *csctl-runtime-log-tail*)
    cat >/dev/null
    log_read_count=0; [ ! -f "$RECONCILE_LOG_READ_COUNT" ] || log_read_count=$(cat "$RECONCILE_LOG_READ_COUNT")
    log_read_count=$((log_read_count + 1)); printf '%s\n' "$log_read_count" > "$RECONCILE_LOG_READ_COUNT"
    [ "$log_read_count" -gt "${RECONCILE_LOG_READ_FAILURES:-0}" ] || { printf 'runtime logs unavailable\n' >&2; exit 1; }
    eval "set -- $wire"
    shift 4
    for runtime_id in "$@"; do
      printf '__CSCTL_RUNTIME_LOG__|%s|stdout|' "$runtime_id"
      printf 'startup-%s\n' "$runtime_id" | od -An -v -tx1 | tr -d ' \n'
      printf '\n__CSCTL_RUNTIME_LOG__|%s|stderr|\n' "$runtime_id"
    done
    ;;
  "'sh' '-s' '--' 'csctl-runtime-status'")
    payload=$(cat)
    printf '%s\n__CSCTL_SCRIPT_END__\n' "$payload" >> "$RECONCILE_SCRIPTS"
    [ -z "${RECONCILE_STARTED:-}" ] || : > "$RECONCILE_STARTED"
    while [ -n "${RECONCILE_RELEASE:-}" ] && [ ! -e "$RECONCILE_RELEASE" ]; do sleep .02; done
    [ "${RECONCILE_FAIL:-0}" = 0 ] || { printf 'scheduler unavailable\n' >&2; exit 1; }
    [ -z "${RECONCILE_CANCEL_ERRORS:-}" ] || printf '%b\n' "$RECONCILE_CANCEL_ERRORS"
    printf '__CSCTL_SQUEUE__\n%b\n__CSCTL_SACCT__\n%b\n' "$RECONCILE_LINES" "$RECONCILE_LINES"
    ;;
  "'squeue' '--noheader' '--jobs="*) printf 'PENDING|\n';;
  "'scancel' "*) :;;
  *) echo "unexpected command: $wire" >&2; exit 2;;
esac
`
	if err := os.WriteFile(ssh, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RECONCILE_LOG", log)
	t.Setenv("RECONCILE_SCRIPTS", scripts)
	t.Setenv("RECONCILE_LOG_READ_COUNT", logReads)
	t.Setenv("RECONCILE_RELEASE", "")
	service := Service{Runner: sshexec.Runner{SSHBin: ssh, Timeout: 5 * time.Second}, Store: Store{Dir: filepath.Join(dir, "state")}}
	configureTestTunnel(t, &service)
	return service, log, release
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
	t.Setenv("RECONCILE_LINES", "101|PENDING||"+one.JobName+"\\n202|PENDING||"+two.JobName)
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
	t.Setenv("RECONCILE_CANCEL_ERRORS", schedulerMarkerCancel+"|id:101|scheduler temporarily unavailable")
	t.Setenv("RECONCILE_LINES", "101|RUNNING|cn001|"+stopping.JobName+"\\n202|PENDING|cn002|"+unrelated.JobName)
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
	t.Setenv("RECONCILE_CANCEL_ERRORS", schedulerMarkerCancel+"|name:"+runtime.JobName+"|submission cancellation pending")
	t.Setenv("RECONCILE_LINES", "777|PENDING||"+runtime.JobName)
	putRuntimes(t, service, runtime)

	listed, err := reconciledList(context.Background(), service)
	if err != nil {
		t.Fatal(err)
	}
	if listed[0].JobID != "777" || listed[0].State != "STOPPING" || listed[0].Error != "submission cancellation pending" {
		t.Fatalf("unknown stopping submission was not reconciled: %#v", listed[0])
	}
	assertOneSchedulerRound(t, log, "alpha")
	script := string(mustRead(t, filepath.Join(filepath.Dir(log), "scripts")))
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
	t.Setenv("RECONCILE_STARTED", started)
	t.Setenv("RECONCILE_RELEASE", release)
	runtime := pendingRuntime("rt-111111111111", "alpha", "101")
	t.Setenv("RECONCILE_LINES", "101|PENDING||"+runtime.JobName)
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
	t.Setenv("RECONCILE_LINES", "")
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
	runtime.CreatedAt = time.Now().UTC()
	t.Setenv("RECONCILE_LINES", "")
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
	t.Setenv("RECONCILE_FAIL", "1")
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
	t.Setenv("RECONCILE_FAIL", "1")
	got := service.reconcileSnapshots(context.Background(), []Runtime{runtime})
	if got[0].State != "READY" {
		t.Fatalf("an allocation inside its walltime was retired as %s by an unreachable scheduler", got[0].State)
	}
	if got[0].Error == "" {
		t.Fatal("an unreachable scheduler left no diagnostic on the runtime")
	}
}

// A queued allocation may wait for days, so no clock retires it -- only the
// scheduler can, and only by answering.
func TestQueuedAllocationHasNoWalltimeDeadline(t *testing.T) {
	queued := pendingRuntime("rt-111111111111", "alpha", "101")
	queued.StartedAt = time.Now().Add(-30 * 24 * time.Hour)
	if outlivedAllocation(queued, time.Now()) {
		t.Fatal("a queued allocation was retired by a deadline it is not under")
	}
}

// sacct reports jobs from midnight today unless asked otherwise, which hid
// every allocation submitted before it.
func TestSchedulerQueryAsksSacctForJobsOlderThanToday(t *testing.T) {
	service, _, _ := reconciliationService(t)
	scripts := os.Getenv("RECONCILE_SCRIPTS")
	runtime := pendingRuntime("rt-111111111111", "alpha", "101")
	t.Setenv("RECONCILE_LINES", "101|PENDING||"+runtime.JobName)
	putRuntimes(t, service, runtime)
	service.reconcileSnapshots(context.Background(), []Runtime{runtime})
	sent := string(mustRead(t, scripts))
	if !strings.Contains(sent, "sacct --noheader -X --starttime=") {
		t.Fatalf("sacct was asked without a start time, so anything older than today is invisible:\n%s", sent)
	}
	if !strings.Contains(sent, "1969-12-31T23:00:01") {
		t.Fatalf("the accounting window did not reach back to the oldest runtime:\n%s", sent)
	}
}

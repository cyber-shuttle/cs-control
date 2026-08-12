package control

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fakeSSH(t *testing.T) (string, string, string) {
	t.Helper()
	dir := t.TempDir()
	status := filepath.Join(dir, "status")
	scriptLog := filepath.Join(dir, "script")
	commandLog := filepath.Join(dir, "commands")
	if err := os.WriteFile(status, []byte("RUNNING\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "ssh")
	script := `#!/bin/sh
set -eu
alias=$1
command=$2
printf '%s|%s\n' "$alias" "$command" >> "$FAKE_COMMAND_LOG"
if [ "$alias" = badhost ]; then
  echo 'host unavailable' >&2
  exit 2
fi
case "$command" in
  "sacctmgr show associations"*)
    printf 'Account|\nproject-a|\nproject-a|\nproject-b|\n'
    ;;
  "sinfo -h"*)
    printf 'cpu*|24+|191000+|(null)\ngpu|64|515000|gpu:a100:2(S:2,5)\n'
    ;;
  "echo "*)
    printf '/home/tester\n'
    ;;
  "sbatch --parsable")
    cat > "$FAKE_SCRIPT_LOG"
    if [ -n "${FAKE_SUBMIT_FAIL:-}" ]; then
      echo 'submit response lost' >&2
      exit 2
    fi
    if [ -n "${FAKE_BREAK_STATE_DIR:-}" ]; then chmod 500 "$FAKE_BREAK_STATE_DIR"; fi
    printf '12345;cluster\n'
    ;;
  "squeue --noheader --name="*)
    state=$(cat "$FAKE_STATUS")
    case "$state" in RUNNING|PENDING|CONFIGURING) printf '12345|%s\n' "$state";; esac
    ;;
  "squeue "*)
    state=$(cat "$FAKE_STATUS")
    case "$state" in RUNNING|PENDING|CONFIGURING) printf '%s\n' "$state";; esac
    ;;
  "sacct --noheader -X --name="*)
    if [ -z "${FAKE_SACCT_NO_RECORD:-}" ]; then
      printf '12345.batch|%s|cs-rt-012345abcdef|\n98765|%s|other-job|\n12345|%s|cs-rt-012345abcdef|\n' "$(cat "$FAKE_STATUS")" "$(cat "$FAKE_STATUS")" "$(cat "$FAKE_STATUS")"
    fi
    ;;
  "sacct "*)
    printf '%s|\n' "$(cat "$FAKE_STATUS")"
    ;;
  "scancel "*)
    if [ -n "${FAKE_CANCEL_FAIL:-}" ]; then
      echo 'cancel failed' >&2
      exit 2
    fi
    printf 'CANCELLED\n' > "$FAKE_STATUS"
    ;;
  *)
    echo "unexpected command: $command" >&2
    exit 2
    ;;
esac
`
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FAKE_STATUS", status)
	t.Setenv("FAKE_SCRIPT_LOG", scriptLog)
	t.Setenv("FAKE_COMMAND_LOG", commandLog)
	return path, status, scriptLog
}

func TestDiscover(t *testing.T) {
	ssh, _, _ := fakeSSH(t)
	resource, err := (Runner{SSHBin: ssh, Timeout: time.Second}).Discover(context.Background(), "delta")
	if err != nil {
		t.Fatal(err)
	}
	if resource.HomeDir != "/home/tester" || strings.Join(resource.Accounts, ",") != "project-a,project-b" {
		t.Fatalf("unexpected resource: %#v", resource)
	}
	if len(resource.Partitions) != 2 || resource.Partitions[1].GRES[0] != (GRES{Name: "gpu:a100", Count: 2}) {
		t.Fatalf("unexpected partitions: %#v", resource.Partitions)
	}
}

func TestRuntimeLifecycleAndStatePermissions(t *testing.T) {
	ssh, _, scriptLog := fakeSSH(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	stateDir := filepath.Join(home, ".cybershuttle", "control")
	service := Service{
		Runner: Runner{SSHBin: ssh, Timeout: time.Second},
		Store:  Store{},
		Now:    func() time.Time { return time.Unix(1, 0) },
	}
	request := CreateRequest{
		ID: "rt-012345abcdef", SSH: "delta", Partition: "cpu", Account: "project-a",
		CPUs: 4, MemoryMB: 4096, Walltime: "01:00:00",
		Linkspan: "/home/tester/.cybershuttle/bin/linkspan",
		Workflow: "/home/tester/.cybershuttle/runtime.yaml",
	}
	runtime, err := service.Create(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.JobID != "12345" || runtime.State != "PENDING" {
		t.Fatalf("unexpected runtime: %#v", runtime)
	}
	script, err := os.ReadFile(scriptLog)
	if err != nil {
		t.Fatal(err)
	}
	text := string(script)
	for _, expected := range []string{"#SBATCH --account=project-a", "--workflow '/home/tester/.cybershuttle/runtime.yaml'", "--runtime-id 'rt-012345abcdef'"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("script missing %q:\n%s", expected, text)
		}
	}

	listed, err := service.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 || listed[0].State != "RUNNING" {
		t.Fatalf("unexpected list: %#v", listed)
	}
	stopped, err := service.Stop(context.Background(), request.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stopped.State != "CANCELLED" {
		t.Fatalf("unexpected stop state: %s", stopped.State)
	}
	got, err := service.Get(context.Background(), request.ID)
	if err != nil || got.State != "CANCELLED" {
		t.Fatalf("unexpected get: %#v, %v", got, err)
	}

	info, err := os.Stat(filepath.Join(stateDir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("state permissions = %o", info.Mode().Perm())
	}
	stateBytes, err := os.ReadFile(filepath.Join(stateDir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"bearer", "token", "credential"} {
		if strings.Contains(strings.ToLower(string(stateBytes)), forbidden) {
			t.Fatalf("state contains forbidden field %q", forbidden)
		}
	}
}

func storedRuntime(id, alias, jobID, runtimeState string) *Runtime {
	now := time.Unix(1, 0).UTC()
	return &Runtime{
		ID: id, SSH: alias, JobID: jobID, JobName: jobName(id), State: runtimeState,
		Partition: "cpu", CPUs: 1, MemoryMB: 1024, Walltime: "01:00:00",
		Linkspan: "/bin/linkspan", Workflow: "/tmp/workflow.yaml", CreatedAt: now, UpdatedAt: now,
	}
}

func writeState(t *testing.T, dir string, runtimes map[string]*Runtime) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(state{Version: stateVersion, Runtimes: runtimes})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "state.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestSubmittingIntentReconcilesBySafeJobName(t *testing.T) {
	ssh, status, _ := fakeSSH(t)
	dir := t.TempDir()
	service := Service{Runner: Runner{SSHBin: ssh, Timeout: time.Second}, Store: Store{Dir: dir}}
	t.Setenv("FAKE_SUBMIT_FAIL", "1")
	request := CreateRequest{ID: "rt-012345abcdef", SSH: "delta", Partition: "cpu", CPUs: 1,
		MemoryMB: 1024, Walltime: "01:00:00", Linkspan: "/bin/linkspan", Workflow: "/tmp/workflow.yaml"}
	if _, err := service.Create(context.Background(), request); err == nil || !strings.Contains(err.Error(), "pending reconciliation") {
		t.Fatalf("expected pending reconciliation error, got %v", err)
	}
	t.Setenv("FAKE_SUBMIT_FAIL", "")
	if err := os.WriteFile(status, []byte("RUNNING\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	listed, err := service.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 || listed[0].JobID != "12345" || listed[0].State != "RUNNING" {
		t.Fatalf("intent was not reconciled: %#v", listed)
	}
	commands, err := os.ReadFile(os.Getenv("FAKE_COMMAND_LOG"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(commands), "squeue --noheader --name=cs-rt-012345abcdef --format=%i|%T") {
		t.Fatalf("missing job-name reconciliation: %s", commands)
	}
}

func TestSubmittingIntentReconcilesCompletedJobFromSacct(t *testing.T) {
	ssh, status, _ := fakeSSH(t)
	dir := t.TempDir()
	runtime := storedRuntime("rt-012345abcdef", "delta", "", "SUBMITTING")
	writeState(t, dir, map[string]*Runtime{runtime.ID: runtime})
	if err := os.WriteFile(status, []byte("COMPLETED\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	service := Service{Runner: Runner{SSHBin: ssh, Timeout: time.Second}, Store: Store{Dir: dir}}

	listed, err := service.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 || listed[0].JobID != "12345" || listed[0].State != "COMPLETED" || listed[0].ReconcileError != "" {
		t.Fatalf("completed intent was not recovered from sacct: %#v", listed)
	}
	commands, err := os.ReadFile(os.Getenv("FAKE_COMMAND_LOG"))
	if err != nil {
		t.Fatal(err)
	}
	expected := "sacct --noheader -X --name=cs-rt-012345abcdef --format=JobIDRaw,State,JobName --parsable2"
	if !strings.Contains(string(commands), expected) {
		t.Fatalf("missing sacct fallback %q: %s", expected, commands)
	}
}

func TestSubmittingIntentRetainsUnresolvedErrorWhenSchedulersHaveNoRecord(t *testing.T) {
	ssh, status, _ := fakeSSH(t)
	dir := t.TempDir()
	runtime := storedRuntime("rt-012345abcdef", "delta", "", "SUBMITTING")
	writeState(t, dir, map[string]*Runtime{runtime.ID: runtime})
	if err := os.WriteFile(status, []byte("MISSING\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FAKE_SACCT_NO_RECORD", "1")
	service := Service{Runner: Runner{SSHBin: ssh, Timeout: time.Second}, Store: Store{Dir: dir}}

	listed, err := service.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 || listed[0].State != "SUBMITTING" || listed[0].JobID != "" || !strings.Contains(listed[0].ReconcileError, "unresolved") {
		t.Fatalf("missing explicit unresolved reconciliation result: %#v", listed)
	}
}

func TestPersistFailureReportsCompensationFailure(t *testing.T) {
	ssh, _, _ := fakeSSH(t)
	dir := t.TempDir()
	t.Setenv("FAKE_BREAK_STATE_DIR", dir)
	t.Setenv("FAKE_CANCEL_FAIL", "1")
	defer os.Chmod(dir, 0o700) //nolint:errcheck
	service := Service{Runner: Runner{SSHBin: ssh, Timeout: time.Second}, Store: Store{Dir: dir}}
	_, err := service.Create(context.Background(), CreateRequest{ID: "rt-012345abcdef", SSH: "delta", Partition: "cpu", CPUs: 1,
		MemoryMB: 1024, Walltime: "01:00:00", Linkspan: "/bin/linkspan", Workflow: "/tmp/workflow.yaml"})
	if err == nil || !strings.Contains(err.Error(), "compensation scancel failed") {
		t.Fatalf("missing combined compensation error: %v", err)
	}
}

func TestMaliciousPersistedJobIDFailsBeforeSSH(t *testing.T) {
	ssh, _, _ := fakeSSH(t)
	dir := t.TempDir()
	runtime := storedRuntime("rt-012345abcdef", "delta", "1; touch /tmp/pwned", "RUNNING")
	writeState(t, dir, map[string]*Runtime{runtime.ID: runtime})
	service := Service{Runner: Runner{SSHBin: ssh, Timeout: time.Second}, Store: Store{Dir: dir}}
	if _, err := service.List(context.Background()); err == nil || !strings.Contains(err.Error(), "invalid stored runtime") {
		t.Fatalf("malicious state was accepted: %v", err)
	}
	if data, err := os.ReadFile(os.Getenv("FAKE_COMMAND_LOG")); err == nil && len(data) != 0 {
		t.Fatalf("SSH ran before state validation: %s", data)
	}
}

func TestListRetainsRuntimesWhenOneReconciliationFails(t *testing.T) {
	ssh, _, _ := fakeSSH(t)
	dir := t.TempDir()
	good := storedRuntime("rt-012345abcdef", "delta", "12345", "RUNNING")
	bad := storedRuntime("rt-fedcba654321", "badhost", "67890", "RUNNING")
	writeState(t, dir, map[string]*Runtime{good.ID: good, bad.ID: bad})
	service := Service{Runner: Runner{SSHBin: ssh, Timeout: time.Second}, Store: Store{Dir: dir}}
	listed, err := service.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 2 || listed[0].ReconcileError != "" || !strings.Contains(listed[1].ReconcileError, "host unavailable") {
		t.Fatalf("unexpected per-runtime results: %#v", listed)
	}
}

func TestGeneratedScriptUsesSupportedPrivateLinkspanContract(t *testing.T) {
	dir := t.TempDir()
	stub := filepath.Join(dir, "linkspan")
	result := filepath.Join(dir, "args")
	stubText := `#!/bin/sh
set -eu
: > "$STUB_RESULT"
while [ "$#" -gt 0 ]; do
  case "$1" in
    --host|--port|--socket|--workflow|--runtime-id|--remote-root)
      [ "$#" -ge 2 ] || exit 3
      printf '%s=%s\n' "$1" "$2" >> "$STUB_RESULT"
      shift 2
      ;;
    *) echo "unsupported flag: $1" >&2; exit 4;;
  esac
done
`
	if err := os.WriteFile(stub, []byte(stubText), 0o700); err != nil {
		t.Fatal(err)
	}
	request := CreateRequest{ID: "rt-012345abcdef", SSH: "delta", Partition: "cpu", CPUs: 1,
		MemoryMB: 1024, Walltime: "01:00:00", Linkspan: stub, Workflow: "/tmp/workflow.yaml", RemoteRoot: filepath.Join(dir, "remote-project")}
	command := exec.Command("bash")
	command.Stdin = strings.NewReader(buildScript(request))
	command.Env = append(os.Environ(), "HOME="+dir, "SLURM_TMPDIR="+dir, "STUB_RESULT="+result)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("script failed Linkspan contract: %v: %s", err, output)
	}
	args, err := os.ReadFile(result)
	if err != nil {
		t.Fatal(err)
	}
	text := string(args)
	for _, expected := range []string{
		"--host=127.0.0.1",
		"--port=0",
		"--socket=" + filepath.Join(dir, jobName(request.ID)+".sock"),
		"--workflow=/tmp/workflow.yaml",
		"--runtime-id=" + request.ID,
		"--remote-root=" + request.RemoteRoot,
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("missing %q in Linkspan args:\n%s", expected, text)
		}
	}
}

func TestNormalizeSlurmStates(t *testing.T) {
	for input, expected := range map[string]string{
		"CANCELLED by 1": "CANCELLED", "NODE_FAIL": "NODE_FAIL", "PREEMPTED": "PREEMPTED",
		"REQUEUE_HOLD": "REQUEUE_HOLD", "SUSPENDED": "SUSPENDED", "STOPPED": "SUSPENDED", "OUT_OF_MEMORY+": "OUT_OF_MEMORY",
	} {
		if actual := normalizeState(input); actual != expected {
			t.Errorf("normalizeState(%q) = %q, want %q", input, actual, expected)
		}
	}
}

func TestRejectsUnsafeInputs(t *testing.T) {
	ssh, _, _ := fakeSSH(t)
	service := Service{Runner: Runner{SSHBin: ssh}, Store: Store{Dir: t.TempDir()}}
	_, err := service.Create(context.Background(), CreateRequest{
		ID: "rt-012345abcdef", SSH: "delta; touch /tmp/x", Partition: "cpu", CPUs: 1,
		MemoryMB: 1024, Walltime: "01:00:00", Linkspan: "/bin/linkspan", Workflow: "/tmp/workflow.yaml",
	})
	if err == nil {
		t.Fatal("unsafe alias was accepted")
	}
}

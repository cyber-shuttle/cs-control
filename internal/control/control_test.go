package control

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cyber-shuttle/cs-control/internal/apierr"
	"github.com/cyber-shuttle/cs-control/internal/sshexec"
)

func fakeSSH(t *testing.T) (string, string, string, string) {
	t.Helper()
	dir := t.TempDir()
	status := filepath.Join(dir, "status")
	scriptLog := filepath.Join(dir, "script")
	validationScriptLog := filepath.Join(dir, "validation-script")
	commandLog := filepath.Join(dir, "commands")
	discoveryScriptLog := filepath.Join(dir, "discovery-script")
	discoveryExecCount := filepath.Join(dir, "discovery-exec-count")
	acceptedJobName := filepath.Join(dir, "accepted-job-name")
	schedulerQueryCount := filepath.Join(dir, "scheduler-query-count")
	if err := os.WriteFile(status, []byte("RUNNING\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "ssh")
	script := `#!/bin/sh
set -eu
if [ "$1" = "-G" ]; then
  printf 'host %s\nhostname %s.example\nuser tester\nport 22\n' "$2" "$2"
  exit 0
fi
while [ "$1" = "-o" ]; do shift 2; done
alias=$1; shift
[ "$#" -eq 1 ] || { echo "expected one OpenSSH remote command argument" >&2; exit 2; }
wire_command=$1
printf '%s|%s\n' "$alias" "$wire_command" >> "$FAKE_COMMAND_LOG"
if printf '%s' "$wire_command" | grep -q 'csctl-runtime-log-tail'; then
  [ -z "${FAKE_RUNTIME_LOG_SCRIPT:-}" ] || cat > "$FAKE_RUNTIME_LOG_SCRIPT"
  [ -n "${FAKE_RUNTIME_LOG_SCRIPT:-}" ] || cat >/dev/null
  eval "set -- $wire_command"
  shift 4
  for runtime_id in "$@"; do
    printf '__CSCTL_RUNTIME_LOG__|%s|stdout|' "$runtime_id"
    printf '%s' "${FAKE_RUNTIME_STDOUT:-}" | od -An -v -tx1 | tr -d ' \n'
    printf '\n__CSCTL_RUNTIME_LOG__|%s|stderr|' "$runtime_id"
    printf '%s' "${FAKE_RUNTIME_STDERR:-}" | od -An -v -tx1 | tr -d ' \n'
    printf '\n'
  done
  exit 0
fi
if [ "$wire_command" = "sh -s -- csctl-runtime-status" ] || [ "$wire_command" = "'sh' '-s' '--' 'csctl-runtime-status'" ]; then
  payload=$(cat)
  query_count=0; [ ! -f "$FAKE_SCHEDULER_QUERY_COUNT" ] || query_count=$(cat "$FAKE_SCHEDULER_QUERY_COUNT")
  query_count=$((query_count + 1)); printf '%s\n' "$query_count" > "$FAKE_SCHEDULER_QUERY_COUNT"
  job_id=12345
  if printf '%s' "$payload" | grep -q 'scancel '; then
    [ -z "${FAKE_SCANCEL_LOG:-}" ] || printf '%s' "$payload" | grep -o 'scancel [^)]*' | sed 's/ 2>&1$//' | tr -d "'" | sed 's/^/batch /' >> "$FAKE_SCANCEL_LOG"
    if [ "${FAKE_SCANCEL_FAIL:-0}" = 0 ]; then printf 'CANCELLED\n' > "$FAKE_STATUS"; fi
  fi
  state=$(cat "$FAKE_STATUS")
  accepted_name=; [ ! -f "$FAKE_ACCEPTED_JOB_NAME" ] || accepted_name=$(cat "$FAKE_ACCEPTED_JOB_NAME")
  printf '__CSCTL_SQUEUE__\n'
  if [ -n "$accepted_name" ] && { [ -z "${FAKE_SUBMIT_RELEASE:-}" ] || [ -e "$FAKE_SUBMIT_RELEASE" ]; }; then
    case "$state" in RUNNING|PENDING|CONFIGURING) printf '%s|%s|cn001|%s\n' "$job_id" "$state" "$accepted_name";; esac
  fi
  printf '__CSCTL_SACCT__\n'
  if [ -n "$accepted_name" ] && { [ -z "${FAKE_SUBMIT_RELEASE:-}" ] || [ -e "$FAKE_SUBMIT_RELEASE" ]; }; then
    printf '%s|%s|cn001|%s|\n' "$job_id" "$state" "$accepted_name"
  fi
  exit 0
fi
if [ "$wire_command" = "sh -s" ]; then
  cat > "$FAKE_DISCOVERY_SCRIPT_LOG"
  count=0; [ ! -f "$FAKE_DISCOVERY_EXEC_COUNT" ] || count=$(cat "$FAKE_DISCOVERY_EXEC_COUNT")
  printf '%s\n' $((count + 1)) > "$FAKE_DISCOVERY_EXEC_COUNT"
  printf 'REMOTE LOGIN BANNER\n' >&2
  user=${FAKE_REMOTE_USER:-tester}
  printf '%s\n' "$DISC_USER_BEGIN"
  case "$user" in ''|*[!A-Za-z0-9_.-]*|?????????????????????????????????????????????????????????????????*) printf '%s\n' "$DISC_ERROR_USER"; exit 72;; esac
  printf '%s\n%s\n' "$user" "$DISC_USER_END"
  printf '%s\n' "$DISC_ACCOUNTS_BEGIN"
  printf 'Account|\nproject-a|\nproject-a|\n%s\n' "$DISC_ACCOUNTS_END"
  printf '%s\n' "$DISC_PARTITIONS_BEGIN"
  printf 'cpu*|24+|191000+|(null)\ngpu|64|515000|gpu:a100:2(S:2,5)\n%s\n' "$DISC_PARTITIONS_END"
  printf '%s\n' "$DISC_HOME_BEGIN"
  printf '/home/tester\n%s\n%s\n' "$DISC_HOME_END" "$DISC_DONE"
  exit 0
fi
case "$wire_command" in
  *"'contract'"*)
    printf '%s' "${FAKE_LINKSPAN_CONTRACT_STDOUT:-}"
    exit "${FAKE_LINKSPAN_CONTRACT_EXIT:-0}";;
esac
eval "set -- $wire_command"
command="$*"
case "$command" in
  "sbatch --test-only")
    cat > "$FAKE_VALIDATION_SCRIPT_LOG"
    [ -z "${FAKE_VALIDATION_STDOUT:-}" ] || printf '%s\n' "$FAKE_VALIDATION_STDOUT"
    [ -z "${FAKE_VALIDATION_STDERR:-}" ] || printf '%s\n' "$FAKE_VALIDATION_STDERR" >&2
    [ "${FAKE_VALIDATION_FAIL:-0}" = 0 ] || exit "${FAKE_VALIDATION_FAIL}"
    ;;
  "sbatch --export=ALL,JUPYTER_TOKEN="*"CS_TUNNEL_HOST_TOKEN="*" --parsable")
    cat > "$FAKE_SCRIPT_LOG"
    [ -z "${FAKE_SUBMIT_STARTED:-}" ] || : > "$FAKE_SUBMIT_STARTED"
    while [ -n "${FAKE_SUBMIT_RELEASE:-}" ] && [ ! -e "$FAKE_SUBMIT_RELEASE" ]; do sleep .01; done
    sed -n 's/^#SBATCH --job-name=//p' "$FAKE_SCRIPT_LOG" | head -n 1 > "$FAKE_ACCEPTED_JOB_NAME"
    printf '12345;cluster\n'
    ;;
  "scancel "*)
    [ -z "${FAKE_SCANCEL_LOG:-}" ] || printf '%s\n' "$command" >> "$FAKE_SCANCEL_LOG"
    [ "${FAKE_SCANCEL_FAIL:-0}" = 0 ] || { echo 'scheduler temporarily unavailable' >&2; exit 1; }
    printf 'CANCELLED\n' > "$FAKE_STATUS"
    ;;
  "sh -c "*"csctl-runtime-workflow "*)
    cat > "${FAKE_WORKFLOW_LOG:-/dev/null}"
    ;;
  "sh -s -- csctl-provision "*)
    cat > "${FAKE_PROVISION_LOG:-/dev/null}"
    [ "${FAKE_PROVISION_FAIL:-0}" = 0 ] || { printf '%s\n' "${FAKE_PROVISION_REPORT:-error=jupyter}"; exit 75; }
    printf '%s\n' "${FAKE_PROVISION_REPORT:-uv=present}"
    printf 'linkspan=present\nprovision=complete\n'
    ;;
  "printenv WORKSPACE") printf '%s\n' "${FAKE_WORKSPACE_ENV:-/scratch/tester}";;
  "printenv EMPTY") exit 1;;
  "printenv RELATIVE") printf 'relative/path\n';;
  "printenv MULTILINE") printf '/scratch/one\n/scratch/two\n';;
  *) echo "unexpected command: $command" >&2; exit 2;;
esac
`
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FAKE_STATUS", status)
	t.Setenv("FAKE_SCRIPT_LOG", scriptLog)
	t.Setenv("FAKE_VALIDATION_SCRIPT_LOG", validationScriptLog)
	t.Setenv("FAKE_VALIDATION_STDOUT", "Job script accepted")
	t.Setenv("FAKE_VALIDATION_FAIL", "0")
	t.Setenv("FAKE_LINKSPAN_CONTRACT_STDOUT", "linkspan.allocation/v1\n")
	t.Setenv("FAKE_LINKSPAN_CONTRACT_EXIT", "0")
	t.Setenv("FAKE_COMMAND_LOG", commandLog)
	t.Setenv("FAKE_DISCOVERY_SCRIPT_LOG", discoveryScriptLog)
	t.Setenv("FAKE_DISCOVERY_EXEC_COUNT", discoveryExecCount)
	t.Setenv("FAKE_ACCEPTED_JOB_NAME", acceptedJobName)
	t.Setenv("FAKE_SCHEDULER_QUERY_COUNT", schedulerQueryCount)
	t.Setenv("DISC_USER_BEGIN", markerUserBegin)
	t.Setenv("DISC_USER_END", markerUserEnd)
	t.Setenv("DISC_ACCOUNTS_BEGIN", markerAccountsBegin)
	t.Setenv("DISC_ACCOUNTS_END", markerAccountsEnd)
	t.Setenv("DISC_PARTITIONS_BEGIN", markerPartitionsBegin)
	t.Setenv("DISC_PARTITIONS_END", markerPartitionsEnd)
	t.Setenv("DISC_HOME_BEGIN", markerHomeBegin)
	t.Setenv("DISC_HOME_END", markerHomeEnd)
	t.Setenv("DISC_DONE", markerDone)
	t.Setenv("DISC_ERROR_USER", markerErrorUser)
	t.Setenv("DISC_ERROR_ACCOUNTS", markerErrorAccounts)
	t.Setenv("DISC_ERROR_PARTITIONS", markerErrorPartitions)
	t.Setenv("DISC_ERROR_HOME", markerErrorHome)
	return path, status, scriptLog, commandLog
}

func testService(t *testing.T) Service {
	t.Helper()
	ssh, _, _, _ := fakeSSH(t)
	service := Service{Runner: sshexec.Runner{SSHBin: ssh, Timeout: 5 * time.Second}, Store: Store{Dir: t.TempDir()}, Config: Config{LinkspanPath: "/opt/cybershuttle/linkspan", RuntimeBase: ".cybershuttle/runtimes"}, Now: func() time.Time { return time.Unix(1, 0).UTC() }}
	configureTestTunnel(t, &service)
	return service
}

func createRequest() CreateRequest {
	return CreateRequest{ID: "rt-012345abcdef", IdempotencyKey: "request-one", SSHHost: "delta", Account: "project-a", Partition: "cpu", RootFolder: "projects/example", Resources: Resources{Cores: 4, MemoryMB: 4096, WallMinutes: 60}}
}

func TestDiscoverNormalizesSchedulerData(t *testing.T) {
	ssh, _, _, commandLog := fakeSSH(t)
	service := Service{Runner: sshexec.Runner{SSHBin: ssh, Timeout: 5 * time.Second}}
	resource, err := service.Discover(context.Background(), "delta")
	if err != nil {
		t.Fatal(err)
	}
	if resource.HomeDir != "/home/tester" || strings.Join(resource.Accounts, ",") != "project-a" || resource.Partitions[0].MemoryMB != 191000 {
		t.Fatalf("unexpected discovery: %#v", resource)
	}
	if got := resource.Partitions[1].GRES[0]; got != (GRES{Name: "gpu:a100", Count: 2}) {
		t.Fatalf("unexpected GRES: %#v", got)
	}
	commands, err := os.ReadFile(commandLog)
	if err != nil {
		t.Fatal(err)
	}
	wire := string(commands)
	if strings.Count(wire, "delta|sh -s") != 1 || strings.Count(strings.TrimSpace(wire), "\n") != 0 {
		t.Fatalf("discovery must use exactly one remote exec after ssh -G:\n%s", wire)
	}
	if count, err := os.ReadFile(os.Getenv("FAKE_DISCOVERY_EXEC_COUNT")); err != nil || strings.TrimSpace(string(count)) != "1" {
		t.Fatalf("discovery exec count = %q, %v", count, err)
	}
	script, err := os.ReadFile(os.Getenv("FAKE_DISCOVERY_SCRIPT_LOG"))
	if err != nil {
		t.Fatal(err)
	}
	if string(script) != discoveryScript || strings.Contains(string(script), "delta") || strings.Contains(string(script), "tester") {
		t.Fatalf("discovery script was not the constant trusted script:\n%s", script)
	}
}

func TestDiscoverRejectsUnsafeRemoteUsernameBeforeSacctmgr(t *testing.T) {
	for _, username := range []string{"bad;touch", "$USER", "two\nusers", strings.Repeat("a", 65)} {
		t.Run(fmt.Sprintf("%q", username), func(t *testing.T) {
			ssh, _, _, commandLog := fakeSSH(t)
			t.Setenv("FAKE_REMOTE_USER", username)
			service := Service{Runner: sshexec.Runner{SSHBin: ssh, Timeout: 5 * time.Second}}
			if _, err := service.Discover(context.Background(), "delta"); err == nil || !strings.Contains(err.Error(), "identify remote user") {
				t.Fatalf("expected unsafe username rejection, got %v", err)
			}
			commands, err := os.ReadFile(commandLog)
			if err != nil {
				t.Fatal(err)
			}
			wire := string(commands)
			if strings.Count(wire, "delta|sh -s") != 1 {
				t.Fatalf("unsafe username discovery used unexpected remote executions for %q:\n%s", username, wire)
			}
		})
	}
}

func TestWorkspaceExpressionsRejectUnsafeOrUnavailableValues(t *testing.T) {
	service := testService(t)
	for _, expression := range []string{"", " ", "/", "../x", "a/../b", "./x", "~/../x", "$HOME/../x", "${HOME}/../x", "$HOME/$USER", "$HOME/", "${WORKSPACE}/", "prefix/$HOME", "$(id)", "`id`", "$BAD-NAME/x", "${BAD-NAME}/x", "path\\x", "path\nother", "$EMPTY", "$RELATIVE", "$MULTILINE"} {
		t.Run(fmt.Sprintf("%q", expression), func(t *testing.T) {
			if _, err := service.resolveWorkspaceRoot(context.Background(), "delta", "/home/tester", expression); err == nil {
				t.Fatalf("accepted unsafe workspace expression %q", expression)
			}
		})
	}
}

func TestCreateRejectsWorkspaceInsidePrivateRuntime(t *testing.T) {
	request := createRequest()
	request.RootFolder = "/home/tester/.cybershuttle/runtimes/rt-012345abcdef/workspace"
	if _, err := testService(t).Create(testTunnelContext(), request); err == nil || apierr.For(err).Code != "invalid_root_folder" {
		t.Fatalf("private runtime overlap was not rejected: %v", err)
	}
}

func TestRuntimeLifecycleUsesManagedLinkspanAndSeparateRoots(t *testing.T) {
	ssh, _, scriptLog, _ := fakeSSH(t)
	service := Service{Runner: sshexec.Runner{SSHBin: ssh, Timeout: 5 * time.Second}, Store: Store{Dir: t.TempDir()}, Config: Config{LinkspanPath: "/opt/cybershuttle/linkspan"}}
	configureTestTunnel(t, &service)
	runtime, err := service.Create(testTunnelContext(), createRequest())
	if err != nil {
		t.Fatal(err)
	}
	if runtime.State != "QUEUED" || runtime.PrivateRoot != "/home/tester/.cybershuttle/runtimes/rt-012345abcdef" || runtime.WorkspaceRoot != "/home/tester/projects/example" {
		t.Fatalf("unexpected runtime: %#v", runtime)
	}
	script, err := os.ReadFile(scriptLog)
	if err != nil {
		t.Fatal(err)
	}
	text := string(script)
	// The allocation runs Linkspan against a workflow. What that workflow starts
	// is its own business, so the script names no service.
	for _, expected := range []string{`LINKSPAN_BIN='/opt/cybershuttle/linkspan'`, `exec "$LINKSPAN_BIN" --port`, "--workflow '/home/tester/.cybershuttle/runtimes/rt-012345abcdef/workflow.yaml'"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("script missing %q:\n%s", expected, text)
		}
	}
	for _, forbidden := range []string{"jupyter", "python", "--managed-jupyter", "--runtime-id", "--remote-root"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("script retained service-specific flag %q:\n%s", forbidden, text)
		}
	}
	listed, err := reconciledList(context.Background(), service)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 || listed[0].State != "READY" || listed[0].Node != "cn001" {
		t.Fatalf("unexpected list: %#v", listed)
	}
	stopped, err := service.Stop(testTunnelContext(), runtime.ID)
	if err != nil || stopped.State != "STOPPED" {
		t.Fatalf("unexpected stop: %#v %v", stopped, err)
	}
}

func TestCreateIsIdempotent(t *testing.T) {
	service := testService(t)
	first, err := service.Create(testTunnelContext(), CreateRequest{IdempotencyKey: "same", SSHHost: "delta", Account: "project-a", Partition: "cpu", RootFolder: "projects/a", Resources: Resources{Cores: 1, MemoryMB: 1024, WallMinutes: 10}})
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.Create(testTunnelContext(), CreateRequest{IdempotencyKey: "same", SSHHost: "delta", Account: "project-a", Partition: "cpu", RootFolder: "projects/a", Resources: Resources{Cores: 1, MemoryMB: 1024, WallMinutes: 10}})
	if err != nil || first.ID != second.ID || first.JobID != second.JobID {
		t.Fatalf("idempotency failed: %#v %#v %v", first, second, err)
	}
}

func TestStopSurvivesRequestCancellation(t *testing.T) {
	service := testService(t)
	runtime := pendingRuntime(runtimeLogIDOne, "delta", "12345")
	runtime.State = "READY"
	runtime.Account = "project-a"
	runtime.RootFolder = "projects/example"
	runtime.WorkspaceRoot = "/home/tester/projects/example"
	runtime.PrivateRoot = "/home/tester/.cybershuttle/runtimes/" + runtime.ID
	putRuntimes(t, service, runtime)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	stopped, err := service.Stop(testTunnelContextFrom(ctx), runtime.ID)
	if err != nil || stopped.State != "STOPPING" || strings.Contains(stopped.Error, "context canceled") {
		t.Fatalf("canceled request interrupted durable stop: %#v %v", stopped, err)
	}
}

func TestHTTPRequiresValidatedPrincipalForRuntimeInventory(t *testing.T) {
	service := testService(t)
	handler := NewHTTPHandler(service, nil)
	defer handler.Close()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/runtimes", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("request without validated principal status = %d", response.Code)
	}
	request = httptest.NewRequest(http.MethodGet, "/api/v1/runtimes", nil).WithContext(testTunnelContext())
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("validated principal status = %d: %s", response.Code, response.Body.String())
	}
	var list RuntimeList
	if err := json.Unmarshal(response.Body.Bytes(), &list); err != nil || list.Runtimes == nil {
		t.Fatalf("invalid runtime DTO: %#v %v", list, err)
	}
}

func TestStoredRuntimeRejectsNonHomeExpressionPrivateOverlap(t *testing.T) {
	now := time.Unix(1, 0).UTC()
	base := Runtime{
		RuntimeResponse: RuntimeResponse{ID: "rt-012345abcdef", State: "STOPPED", SSHHost: "delta", Partition: "cpu", Resources: Resources{Cores: 1, MemoryMB: 1024, WallMinutes: 60}, CreatedAt: now, UpdatedAt: now},
		JobName:         "cs-rt-012345abcdef",
	}
	setTestRuntimeMetadata(&base)
	for _, test := range []struct {
		expression, workspace string
	}{
		{"/scratch/tester", "/scratch/tester"},
		{"projects/example", "/home/tester/projects/example"},
	} {
		runtime := base
		runtime.RootFolder = test.expression
		runtime.WorkspaceRoot = test.workspace
		runtime.PrivateRoot = test.workspace + "/.cybershuttle/runtimes/" + runtime.ID
		if err := validateStoredRuntime(runtime.ID, &runtime); err == nil {
			t.Fatalf("stored non-home overlap %q accepted", test.expression)
		}
	}
}

func TestLoopbackListenValidation(t *testing.T) {
	for _, address := range []string{"127.0.0.1:8042", "127.0.0.1:0", "[::1]:0"} {
		if err := ValidateLoopbackListen(address); err != nil {
			t.Fatalf("loopback %s rejected: %v", address, err)
		}
	}
	for _, address := range []string{"0.0.0.0:8042", "0.0.0.0:0", "[::]:0"} {
		if err := ValidateLoopbackListen(address); err == nil {
			t.Fatalf("non-loopback %s accepted", address)
		}
	}
}

func TestDeleteRemovesATerminalRuntimeAndItsCredential(t *testing.T) {
	service := testService(t)
	runtime := pendingRuntime(runtimeLogIDOne, "delta", "12345")
	setTestRuntimeMetadata(&runtime)
	runtime.State = "FAILED"
	putRuntimes(t, service, runtime)
	if err := service.Credentials.Put(runtime.ID, runtime.Generation, testCredential()); err != nil {
		t.Fatal(err)
	}
	service.Logs.Append(runtime.ID, "status", "starting")

	deleted, err := service.Delete(testTunnelContext(), runtime.ID)
	if err != nil || deleted.ID != runtime.ID {
		t.Fatalf("delete failed: %#v %v", deleted, err)
	}
	runtimes, err := service.ListCached()
	if err != nil {
		t.Fatal(err)
	}
	for _, remaining := range runtimes {
		if remaining.ID == runtime.ID {
			t.Fatalf("deleted runtime is still listed: %#v", remaining)
		}
	}
	if _, err := service.Credentials.Get(runtime.ID, runtime.Generation); err == nil {
		t.Fatal("delete left the generation credential on disk")
	}
	if _, ok := service.Logs.Tail(runtime.ID); ok {
		t.Fatal("delete left the runtime log tail in memory")
	}
	if _, err := service.Delete(testTunnelContext(), runtime.ID); err == nil {
		t.Fatal("deleting an absent runtime should not succeed")
	}
}

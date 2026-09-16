// The end-to-end shape of a session's lifecycle against a fake SSH and scheduler.
// Covers discovery, create, idempotency, cancellation, ownership, and the loopback listen policy.
//
//	fakeSSH
//	testService
//	newTestCreateRequest
//	assertScriptRedirectsToTheSessionsGenerationLog
//	Test*
package control

import (
	"context"
	"encoding/json"
	"errors"
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
	"github.com/cyber-shuttle/cs-control/internal/testutil"
)

func fakeSSH(t *testing.T) (string, string, string) {
	t.Helper()
	dir := t.TempDir()
	status := filepath.Join(dir, "status")
	scriptLog := filepath.Join(dir, "script")
	validationScriptLog := filepath.Join(dir, "validation-script")
	commandLog := filepath.Join(dir, "commands")
	statusScriptLog := filepath.Join(dir, "status-script")
	discoveryScriptLog := filepath.Join(dir, "discovery-script")
	acceptedJobName := filepath.Join(dir, "accepted-job-name")
	schedulerQueryCount := filepath.Join(dir, "scheduler-query-count")
	acceptedJobID := filepath.Join(dir, "accepted-job-id")
	testutil.Check(t, os.WriteFile(status, []byte("RUNNING\n"), 0o600))
	path := filepath.Join(dir, "ssh")
	script := `#!/bin/sh
set -eu
if [ "$1" = "-G" ]; then
  shift
  while [ "$1" = "-o" ] || [ "$1" = "-F" ]; do shift 2; done
  printf 'host %s\nhostname %s.example\nuser tester\nport 22\n' "$1" "$1"
  exit 0
fi
while [ "$1" = "-o" ] || [ "$1" = "-F" ]; do shift 2; done
alias=$1; shift
[ "$#" -eq 1 ] || { echo "expected one OpenSSH remote command argument" >&2; exit 2; }
wire_command=$1
printf '%s|%s\n' "$alias" "$wire_command" >> "$FAKE_COMMAND_LOG"
if printf '%s' "$wire_command" | grep -q 'csctl-session-log-tail'; then
  cat > "${FAKE_SESSION_LOG_SCRIPT:-/dev/null}"
  eval "set -- $wire_command"
  shift 4
  [ -z "${FAKE_SESSION_LOG_BANNER:-}" ] || printf '%b\n' "$FAKE_SESSION_LOG_BANNER"
  while [ "$#" -gt 0 ]; do
    session_id=$1; shift 2
    printf '__CSCTL_SESSION_LOG__|%s|stdout\n' "$session_id"
    printf '%s' "${FAKE_SESSION_STDOUT:-}" | od -An -v -tx1 | tr -d ' \n'
    printf '\n__CSCTL_SESSION_LOG__|%s|stderr\n' "$session_id"
    printf '%s' "${FAKE_SESSION_STDERR:-}" | od -An -v -tx1 | tr -d ' \n'
    printf '\n'
  done
  exit 0
fi
if [ "$wire_command" = "'sh' '-s' '--' 'csctl-session-status'" ]; then
  payload=$(cat)
  printf '%s\n__CSCTL_SCRIPT_END__\n' "$payload" >> "$FAKE_STATUS_SCRIPT_LOG"
  query_count=0; [ ! -f "$FAKE_SCHEDULER_QUERY_COUNT" ] || query_count=$(cat "$FAKE_SCHEDULER_QUERY_COUNT")
  query_count=$((query_count + 1)); printf '%s\n' "$query_count" > "$FAKE_SCHEDULER_QUERY_COUNT"
  job_id=12345; [ ! -f "$FAKE_ACCEPTED_JOB_ID" ] || job_id=$(cat "$FAKE_ACCEPTED_JOB_ID")
  if printf '%s' "$payload" | grep -q 'scancel '; then
    [ -z "${FAKE_SCANCEL_LOG:-}" ] || printf '%s' "$payload" | grep -o 'scancel [^)]*' | sed 's/ 2>&1$//' | tr -d "'" | sed 's/^/batch /' >> "$FAKE_SCANCEL_LOG"
    if [ "${FAKE_SCANCEL_FAIL:-0}" = 0 ]; then printf 'CANCELLED\n' > "$FAKE_STATUS"; fi
  fi
  [ -z "${FAKE_STATUS_STARTED:-}" ] || : > "$FAKE_STATUS_STARTED"
  while [ -n "${FAKE_STATUS_RELEASE:-}" ] && [ ! -e "$FAKE_STATUS_RELEASE" ]; do sleep .02; done
  [ "${FAKE_STATUS_FAIL:-0}" = 0 ] || { printf 'scheduler unavailable\n' >&2; exit 1; }
  [ -z "${FAKE_STATUS_BANNER:-}" ] || printf '%b\n' "$FAKE_STATUS_BANNER"
  printf '__CSCTL_SCANCEL__\n'
  [ -z "${FAKE_CANCEL_ERRORS:-}" ] || printf '%b\n' "$FAKE_CANCEL_ERRORS"
  if [ -n "${FAKE_STATUS_LINES+x}" ]; then
    printf '__CSCTL_SQUEUE__\n%b\n__CSCTL_SACCT__\n%b\n' "${FAKE_QUEUE_LINES-$FAKE_STATUS_LINES}" "$FAKE_STATUS_LINES"
    exit 0
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
if [ "$wire_command" = "'sh' '-s'" ]; then
  cat > "$FAKE_DISCOVERY_SCRIPT_LOG"
  if [ -n "${FAKE_DISCOVERY_BLOCK_ALIAS:-}" ] && [ "$alias" = "$FAKE_DISCOVERY_BLOCK_ALIAS" ]; then
    [ -z "${FAKE_DISCOVERY_STARTED:-}" ] || printf '1' > "$FAKE_DISCOVERY_STARTED"
    while [ -n "${FAKE_DISCOVERY_RELEASE:-}" ] && [ ! -e "$FAKE_DISCOVERY_RELEASE" ]; do sleep .01; done
  fi
  if [ -n "${FAKE_DISCOVERY_FAIL:-}" ]; then printf '%s\n' "$FAKE_DISCOVERY_FAIL" >&2; exit 255; fi
  printf 'REMOTE LOGIN BANNER\n' >&2
  user=${FAKE_REMOTE_USER:-tester}
  printf '%s\n' "$DISC_USER"
  case "$user" in ''|*[!A-Za-z0-9_.-]*) printf '%s\n' "$DISC_ERROR_USER"; exit 72;; esac
  printf '%s\n%s\n' "$user" "$DISC_ACCOUNTS"
  printf 'Account|\nproject-a|\nproject-a|\n'
  if [ -n "${FAKE_DISCOVERY_PARTITIONS_FAIL:-}" ]; then printf '%s\n' "$DISC_ERROR_PARTITIONS"; exit 74; fi
  printf '%s\n' "$DISC_PARTITIONS"
  printf 'cpu*|24+|191000+|(null)\ngpu|64|515000|gpu:a100:2(S:2,5)\n%s\n' "$DISC_HOME"
  printf '/home/tester\n%s\n' "$DISC_DONE"
  exit 0
fi
eval "set -- $wire_command"
command="$*"
case "$command" in
  "sbatch --test-only")
    cat > "$FAKE_VALIDATION_SCRIPT_LOG"
    [ -z "${FAKE_VALIDATION_STDOUT:-}" ] || printf '%s\n' "$FAKE_VALIDATION_STDOUT"
    [ -z "${FAKE_VALIDATION_STDERR:-}" ] || printf '%s\n' "$FAKE_VALIDATION_STDERR" >&2
    [ "${FAKE_VALIDATION_FAIL:-0}" = 0 ] || exit "${FAKE_VALIDATION_FAIL}"
    ;;
  "sbatch --job-name="*" --export=ALL,JUPYTER_TOKEN="*"CS_TUNNEL_HOST_TOKEN="*" --parsable")
    cat > "$FAKE_SCRIPT_LOG"
    [ -z "${FAKE_SUBMIT_STARTED:-}" ] || : > "$FAKE_SUBMIT_STARTED"
    while [ -n "${FAKE_SUBMIT_RELEASE:-}" ] && [ ! -e "$FAKE_SUBMIT_RELEASE" ]; do sleep .01; done
    printf '%s\n' "${2#--job-name=}" > "$FAKE_ACCEPTED_JOB_NAME"
    printf '%s\n' "${FAKE_JOB_ID:-12345}" > "$FAKE_ACCEPTED_JOB_ID"
    printf '%s;cluster\n' "${FAKE_JOB_ID:-12345}"
    ;;
  "scancel "*)
    [ -z "${FAKE_SCANCEL_LOG:-}" ] || printf '%s\n' "$command" >> "$FAKE_SCANCEL_LOG"
    [ "${FAKE_SCANCEL_FAIL:-0}" = 0 ] || { echo 'scheduler temporarily unavailable' >&2; exit 1; }
    printf 'CANCELLED\n' > "$FAKE_STATUS"
    ;;
  "sh -s -- csctl-provision "*)
    cat > "${FAKE_PROVISION_LOG:-/dev/null}"
    [ -z "${FAKE_PROVISION_STARTED:-}" ] || : > "$FAKE_PROVISION_STARTED"
    while [ -n "${FAKE_PROVISION_RELEASE:-}" ] && [ ! -e "$FAKE_PROVISION_RELEASE" ]; do sleep .01; done
    [ "${FAKE_PROVISION_FAIL:-0}" = 0 ] || { printf '%s\n' "${FAKE_PROVISION_REPORT:-error=jupyter}"; exit 75; }
    printf '%s\n' "${FAKE_PROVISION_REPORT:-linkspan=present}"
    printf 'provision=complete\n'
    ;;
  "printenv WORKSPACE") printf '%s\n' "${FAKE_WORKSPACE_ENV:-/scratch/tester}";;
  "printenv EMPTY") exit 1;;
  "printenv RELATIVE") printf 'relative/path\n';;
  "printenv MULTILINE") printf '/scratch/one\n/scratch/two\n';;
  "sacct -P -n --units=K --starttime="*)
    [ -z "${FAKE_RUN_STATS_LOG:-}" ] || printf '%s\n' "$command" >> "$FAKE_RUN_STATS_LOG"
    if [ -n "${FAKE_RUN_STATS_SLEEP_ONCE:-}" ] && [ ! -e "$FAKE_RUN_STATS_SLEEP_ONCE" ]; then
      : > "$FAKE_RUN_STATS_SLEEP_ONCE"
      sleep "${FAKE_RUN_STATS_SLEEP_SECONDS:-0}"
    fi
    printf '%s\n' "${FAKE_RUN_STATS_OUTPUT:-}"
    ;;
  *) echo "unexpected command: $command" >&2; exit 2;;
esac
`
	writeScript(t, path, script)
	t.Setenv("FAKE_STATUS", status)
	t.Setenv("FAKE_SCRIPT_LOG", scriptLog)
	t.Setenv("FAKE_VALIDATION_SCRIPT_LOG", validationScriptLog)
	t.Setenv("FAKE_VALIDATION_STDOUT", "Job script accepted")
	t.Setenv("FAKE_VALIDATION_FAIL", "0")
	t.Setenv("FAKE_COMMAND_LOG", commandLog)
	t.Setenv("FAKE_STATUS_SCRIPT_LOG", statusScriptLog)
	t.Setenv("FAKE_DISCOVERY_SCRIPT_LOG", discoveryScriptLog)
	t.Setenv("FAKE_ACCEPTED_JOB_NAME", acceptedJobName)
	t.Setenv("FAKE_ACCEPTED_JOB_ID", acceptedJobID)
	t.Setenv("FAKE_SCHEDULER_QUERY_COUNT", schedulerQueryCount)
	t.Setenv("DISC_USER", markerUser)
	t.Setenv("DISC_ACCOUNTS", markerAccounts)
	t.Setenv("DISC_PARTITIONS", markerPartitions)
	t.Setenv("DISC_HOME", markerHome)
	t.Setenv("DISC_DONE", markerDone)
	t.Setenv("DISC_ERROR_USER", markerErrorUser)
	t.Setenv("DISC_ERROR_PARTITIONS", markerErrorPartitions)
	return path, scriptLog, commandLog
}

func testService(t *testing.T, now ...func() time.Time) Service {
	t.Helper()
	clock := func() time.Time { return time.Unix(1, 0).UTC() }
	if len(now) > 0 {
		clock = now[0]
	}
	ssh, _, _ := fakeSSH(t)
	service := Service{Runner: sshexec.Runner{SSHBin: ssh, Timeout: 5 * time.Second}, Store: Store{Dir: t.TempDir()}, Config: Config{LinkspanPath: "/opt/cybershuttle/linkspan"}, Now: clock, Logs: NewSessionLogs(), Metrics: NewSessionMetrics()}
	configureTestTunnel(t, &service)
	return service
}

func newTestCreateRequest() createRequest {
	return createRequest{ID: "s-012345abcdef", IdempotencyKey: "request-one", SSHHost: "delta", Account: "project-a", Partition: "cpu", RootFolder: "projects/example", Resources: resources{Cores: 4, MemoryMB: 4096, WallMinutes: 60}}
}

func assertScriptRedirectsToTheSessionsGenerationLog(t *testing.T, scriptLog string, session *Session) {
	t.Helper()
	if session.Generation == "" {
		t.Fatal("session has no generation")
	}
	script, err := os.ReadFile(scriptLog)
	testutil.Check(t, err)
	expected := `"$LOG_DIR/` + sessionLogBasename(session.ID, session.Generation) + `.out"`
	if !strings.Contains(string(script), expected) {
		t.Fatalf("submitted script does not redirect to %q, the basename the tail script later reads:\n%s", expected, script)
	}
}

func TestDiscoverNormalizesSchedulerData(t *testing.T) {
	ssh, _, commandLog := fakeSSH(t)
	service := Service{Runner: sshexec.Runner{SSHBin: ssh, Timeout: 5 * time.Second}, Logs: NewSessionLogs(), Metrics: NewSessionMetrics()}
	resource, err := service.discover(context.Background(), "delta")
	testutil.Check(t, err)
	if resource.HomeDir != "/home/tester" || strings.Join(resource.Accounts, ",") != "project-a" || resource.Partitions[0].MemoryMB != 191000 {
		t.Fatalf("unexpected discovery: %#v", resource)
	}
	if got := resource.Partitions[1].GRES[0]; got != (gres{Name: "gpu:a100", Count: 2}) {
		t.Fatalf("unexpected GRES: %#v", got)
	}
	wire := string(mustRead(t, commandLog))
	if strings.Count(wire, "delta|'sh' '-s'") != 1 || strings.Count(strings.TrimSpace(wire), "\n") != 0 {
		t.Fatalf("discovery must use exactly one remote exec after ssh -G:\n%s", wire)
	}
	script, err := os.ReadFile(os.Getenv("FAKE_DISCOVERY_SCRIPT_LOG"))
	testutil.Check(t, err)
	if string(script) != discoveryScript || strings.Contains(string(script), "delta") || strings.Contains(string(script), "tester") {
		t.Fatalf("discovery script was not the constant trusted script:\n%s", script)
	}
}

func TestDiscoverRejectsUnsafeRemoteUsernameBeforeSacctmgr(t *testing.T) {
	ssh, _, commandLog := fakeSSH(t)
	t.Setenv("FAKE_REMOTE_USER", "bad;touch")
	service := Service{Runner: sshexec.Runner{SSHBin: ssh, Timeout: 5 * time.Second}, Logs: NewSessionLogs(), Metrics: NewSessionMetrics()}
	if _, err := service.discover(context.Background(), "delta"); err == nil || !strings.Contains(err.Error(), "identify remote user") {
		t.Fatalf("expected unsafe username rejection, got %v", err)
	}
	wire := string(mustRead(t, commandLog))
	if strings.Count(wire, "delta|'sh' '-s'") != 1 {
		t.Fatalf("unsafe username discovery used unexpected remote executions:\n%s", wire)
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

func TestCreateRejectsWorkspaceInsidePrivateSession(t *testing.T) {
	request := newTestCreateRequest()
	request.RootFolder = "/home/tester/.cybershuttle/sessions/s-012345abcdef/workspace"
	service := testService(t)
	if _, err := service.create(testTunnelContext(), request); err == nil || apierr.For(err).Code != "invalid_root_folder" {
		t.Fatalf("private session overlap was not rejected: %v", err)
	}
}

func TestCreateRejectsSessionsBelowTheFloor(t *testing.T) {
	for _, below := range []resources{
		{Cores: minCores - 1, MemoryMB: minMemoryMB, WallMinutes: 60},
		{Cores: minCores, MemoryMB: minMemoryMB - 1, WallMinutes: 60},
	} {
		request := newTestCreateRequest()
		request.Resources = below
		service := testService(t)
		if _, err := service.create(testTunnelContext(), request); err == nil || apierr.For(err).Code != "invalid_resources" {
			t.Fatalf("%d cores / %d MB was not rejected: %v", below.Cores, below.MemoryMB, err)
		}
	}
	request := newTestCreateRequest()
	request.Resources = resources{Cores: minCores, MemoryMB: minMemoryMB, WallMinutes: 60}
	service := testService(t)
	if _, err := service.create(testTunnelContext(), request); err != nil {
		t.Fatalf("the floor itself was rejected: %v", err)
	}
}

func TestSessionLifecycleUsesManagedLinkspanAndSeparateRoots(t *testing.T) {
	ssh, scriptLog, _ := fakeSSH(t)
	cancellations := filepath.Join(t.TempDir(), "cancellations")
	t.Setenv("FAKE_SCANCEL_LOG", cancellations)
	service := Service{Runner: sshexec.Runner{SSHBin: ssh, Timeout: 5 * time.Second}, Store: Store{Dir: t.TempDir()}, Config: Config{LinkspanPath: "/opt/cybershuttle/linkspan"}, Logs: NewSessionLogs(), Metrics: NewSessionMetrics()}
	configureTestTunnel(t, &service)
	session, err := service.create(testTunnelContext(), newTestCreateRequest())
	testutil.Check(t, err)
	if session.State != "QUEUED" || session.PrivateRoot != "/home/tester/.cybershuttle/sessions/s-012345abcdef" || session.WorkspaceRoot != "/home/tester/projects/example" {
		t.Fatalf("unexpected session: %#v", session)
	}
	script, err := os.ReadFile(scriptLog)
	testutil.Check(t, err)
	text := string(script)
	for _, expected := range []string{`LINKSPAN_BIN='/opt/cybershuttle/linkspan'`, `exec "$LINKSPAN_BIN" --port`, "--workflow '/home/tester/.cybershuttle/sessions/s-012345abcdef/workflow.yaml'"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("script missing %q:\n%s", expected, text)
		}
	}
	for _, forbidden := range []string{"jupyter", "python", "--managed-jupyter", "--session-id", "--remote-root"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("script retained service-specific flag %q:\n%s", forbidden, text)
		}
	}
	t.Setenv("FAKE_SESSION_STDOUT", "Linkspan started\n")
	listed, err := reconciledList(context.Background(), service)
	testutil.Check(t, err)
	if len(listed) != 1 || listed[0].State != "READY" || listed[0].Node != "cn001" {
		t.Fatalf("unexpected list: %#v", listed)
	}
	stopped, err := service.stop(testTunnelContext(), session.ID)
	if err != nil || stopped.State != "STOPPED" {
		t.Fatalf("unexpected stop: %#v %v", stopped, err)
	}
	data, err := os.ReadFile(cancellations)
	if err != nil || !strings.Contains(string(data), "scancel 12345") {
		t.Fatalf("known job was not cancelled: %q %v", data, err)
	}
	runs, err := service.listRuns(testPrincipal)
	if err != nil || len(runs) != 1 || runs[0].SessionID != session.ID {
		t.Fatalf("stop did not freeze a run: %#v %v", runs, err)
	}
	if _, ok := service.Logs.Tail(session.ID); ok {
		t.Fatal("stop left the live log tail behind")
	}
}

func TestSubmittedScriptLogPathMatchesTheGenerationTheTailReads(t *testing.T) {
	ssh, scriptLog, _ := fakeSSH(t)
	t.Setenv("FAKE_SCANCEL_LOG", filepath.Join(t.TempDir(), "cancellations"))
	service := Service{Runner: sshexec.Runner{SSHBin: ssh, Timeout: 5 * time.Second}, Store: Store{Dir: t.TempDir()}, Config: Config{LinkspanPath: "/opt/cybershuttle/linkspan"}, Logs: NewSessionLogs(), Metrics: NewSessionMetrics()}
	configureTestTunnel(t, &service)

	session, err := service.create(testTunnelContext(), newTestCreateRequest())
	testutil.Check(t, err)
	assertScriptRedirectsToTheSessionsGenerationLog(t, scriptLog, session)

	t.Setenv("FAKE_SESSION_STDOUT", "Linkspan started\n")
	_, err = reconciledList(context.Background(), service)
	testutil.Check(t, err)
	_, err = service.stop(testTunnelContext(), session.ID)
	testutil.Check(t, err)
	relaunched, err := service.start(testTunnelContext(), session.ID)
	testutil.Check(t, err)
	if relaunched.Generation == session.Generation {
		t.Fatalf("relaunch reused the prior generation %q", relaunched.Generation)
	}
	assertScriptRedirectsToTheSessionsGenerationLog(t, scriptLog, relaunched)
}

func TestCreateIsIdempotent(t *testing.T) {
	service := testService(t)
	first, err := service.create(testTunnelContext(), createRequest{IdempotencyKey: "same", SSHHost: "delta", Account: "project-a", Partition: "cpu", RootFolder: "projects/a", Resources: resources{Cores: 2, MemoryMB: 4096, WallMinutes: 10}})
	testutil.Check(t, err)
	second, err := service.create(testTunnelContext(), createRequest{IdempotencyKey: "same", SSHHost: "delta", Account: "project-a", Partition: "cpu", RootFolder: "projects/a", Resources: resources{Cores: 2, MemoryMB: 4096, WallMinutes: 10}})
	if err != nil || first.ID != second.ID || first.JobID != second.JobID {
		t.Fatalf("idempotency failed: %#v %#v %v", first, second, err)
	}
}

func TestConcurrentMismatchedCreateInTheIdempotencyWindowAnswersConflict(t *testing.T) {
	ssh, _, _ := fakeSSH(t)
	started := filepath.Join(t.TempDir(), "discovery-started")
	release := filepath.Join(t.TempDir(), "discovery-release")
	t.Setenv("FAKE_DISCOVERY_BLOCK_ALIAS", "delta")
	t.Setenv("FAKE_DISCOVERY_STARTED", started)
	t.Setenv("FAKE_DISCOVERY_RELEASE", release)
	service := Service{Runner: sshexec.Runner{SSHBin: ssh, Timeout: 5 * time.Second}, Store: Store{Dir: t.TempDir()}, Config: Config{LinkspanPath: "/opt/cybershuttle/linkspan"}, Logs: NewSessionLogs(), Metrics: NewSessionMetrics()}
	configureTestTunnel(t, &service)

	requestA := createRequest{IdempotencyKey: "shared-key", SSHHost: "delta", Account: "project-a", Partition: "cpu", RootFolder: "projects/example", Resources: resources{Cores: 4, MemoryMB: 4096, WallMinutes: 60}}
	requestB := requestA
	requestB.SSHHost = "beta"

	errs := make(chan error, 1)
	go func() {
		_, err := service.create(testTunnelContext(), requestA)
		errs <- err
	}()
	waitForFile(t, started)

	// B completes fully while A is paused past its own idempotency check but before it re-checks under lock.
	_, err := service.create(testTunnelContext(), requestB)
	testutil.Check(t, err)
	testutil.Check(t, os.WriteFile(release, nil, 0o600))

	if err := <-errs; apierr.For(err).Code != "idempotency_conflict" {
		t.Fatalf("a mismatched create that landed in the idempotency window answered %v, not idempotency_conflict", err)
	}
}

func TestStopSurvivesRequestCancellation(t *testing.T) {
	service := testService(t)
	session := pendingSession(sessionLogIDOne, "delta", "12345")
	session.State = "READY"
	session.Account = "project-a"
	session.RootFolder = "projects/example"
	session.WorkspaceRoot = "/home/tester/projects/example"
	session.PrivateRoot = "/home/tester/.cybershuttle/sessions/" + session.ID
	putSessions(t, service, session)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	stopped, err := service.stop(testTunnelContextFrom(ctx), session.ID)
	if err != nil || stopped.State != "STOPPING" || strings.Contains(stopped.Error, "context canceled") {
		t.Fatalf("canceled request interrupted durable stop: %#v %v", stopped, err)
	}
}

func TestHTTPRequiresValidatedPrincipalForSessionInventory(t *testing.T) {
	service := testService(t)
	handler := NewHTTPHandler(service, noopAuth{})
	defer handler.Close()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	testutil.Equal(t, response.Code, http.StatusUnauthorized, "request without validated principal status")
	request = httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil).WithContext(testTunnelContext())
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("validated principal status = %d: %s", response.Code, response.Body.String())
	}
	var list sessionList
	if err := json.Unmarshal(response.Body.Bytes(), &list); err != nil {
		t.Fatalf("invalid session DTO: %#v %v", list, err)
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

func TestDeleteRemovesATerminalSessionAndItsCredential(t *testing.T) {
	service := testService(t)
	session := pendingSession(sessionLogIDOne, "delta", "12345")
	setTestSessionMetadata(&session)
	session.State = "FAILED"
	putSessions(t, service, session)
	testutil.Check(t, service.Credentials.Put(session.ID, session.Generation, credential()))
	service.Logs.Append(session.ID, "starting", service.now())

	deleted, err := service.delete(testTunnelContext(), session.ID)
	if err != nil || deleted.ID != session.ID {
		t.Fatalf("delete failed: %#v %v", deleted, err)
	}
	sessions, err := service.loadSessions()
	testutil.Check(t, err)
	for _, remaining := range sessions {
		if remaining.ID == session.ID {
			t.Fatalf("deleted session is still listed: %#v", remaining)
		}
	}
	if _, err := service.Credentials.Get(session.ID, session.Generation); err == nil {
		t.Fatal("delete left the generation credential on disk")
	}
	if _, ok := service.Logs.Tail(session.ID); ok {
		t.Fatal("delete left the session log tail in memory")
	}
	if _, err := service.delete(testTunnelContext(), session.ID); err == nil {
		t.Fatal("deleting an absent session should not succeed")
	}
}

func TestStopAndDeleteSurviveADevTunnelsReleaseFailure(t *testing.T) {
	ssh, _, _ := fakeSSH(t)
	service := Service{Runner: sshexec.Runner{SSHBin: ssh, Timeout: 5 * time.Second}, Store: Store{Dir: t.TempDir()}, Config: Config{LinkspanPath: "/opt/cybershuttle/linkspan"}, Logs: NewSessionLogs(), Metrics: NewSessionMetrics()}
	manager := configureTestTunnel(t, &service)
	created, err := service.create(testTunnelContext(), newTestCreateRequest())
	testutil.Check(t, err)
	manager.deleteErr = errors.New("Dev Tunnels outage")

	stopped, err := service.stop(testTunnelContext(), created.ID)
	if err != nil {
		t.Fatalf("a Dev Tunnels outage during stop answered an error instead of the record: %v", err)
	}
	if stopped.State != "STOPPED" {
		t.Fatalf("unexpected state after stop: %#v", stopped)
	}
	if !strings.Contains(stopped.Error, "Dev Tunnels outage") {
		t.Fatalf("the release failure was not recorded on the session: %#v", stopped)
	}

	deleted, err := service.delete(testTunnelContext(), created.ID)
	if err != nil {
		t.Fatalf("delete answered an error instead of removing the stopped session: %v", err)
	}
	if deleted.ID != created.ID {
		t.Fatalf("unexpected deleted session: %#v", deleted)
	}
}

func TestStopOnAnAlreadyStoppedSessionChangesNothing(t *testing.T) {
	current := time.Unix(1000, 0).UTC()
	clock := func() time.Time { return current }
	ssh, _, _ := fakeSSH(t)
	t.Setenv("FAKE_SCANCEL_LOG", filepath.Join(t.TempDir(), "cancellations"))
	service := Service{Runner: sshexec.Runner{SSHBin: ssh, Timeout: 5 * time.Second}, Store: Store{Dir: t.TempDir()}, Config: Config{LinkspanPath: "/opt/cybershuttle/linkspan"}, Now: clock, Logs: NewSessionLogs(), Metrics: NewSessionMetrics()}
	configureTestTunnel(t, &service)

	session, err := service.create(testTunnelContext(), newTestCreateRequest())
	testutil.Check(t, err)
	t.Setenv("FAKE_SESSION_STDOUT", "Linkspan started\n")
	_, err = reconciledList(context.Background(), service)
	testutil.Check(t, err)

	current = current.Add(time.Minute)
	first, err := service.stop(testTunnelContext(), session.ID)
	if err != nil || first.State != "STOPPED" {
		t.Fatalf("unexpected first stop: %#v %v", first, err)
	}

	current = current.Add(time.Minute)
	second, err := service.stop(testTunnelContext(), session.ID)
	testutil.Check(t, err)
	if !second.UpdatedAt.Equal(first.UpdatedAt) {
		t.Fatalf("a second stop on an already-stopped session changed UpdatedAt: %v -> %v", first.UpdatedAt, second.UpdatedAt)
	}
	if second.Error != first.Error {
		t.Fatalf("a second stop on an already-stopped session changed Error: %q -> %q", first.Error, second.Error)
	}
}

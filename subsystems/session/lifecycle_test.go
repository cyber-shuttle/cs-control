// Session lifecycle tests cover durable transitions, compensation, idempotency, and concurrency.
// One fake SSH boundary drives complete create, stop, delete, and relaunch flows.
// Races assert that persisted intent wins over delayed remote work.
// Detached work survives request cancellation and stops with the service.
package session

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/cyber-shuttle/cs-control/internal/devtunnel"
	"github.com/cyber-shuttle/cs-control/internal/security"
	"github.com/cyber-shuttle/cs-control/internal/ssh"
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
  "sbatch --job-name="*" --export=ALL,"*" --parsable")
    cat > "$FAKE_SCRIPT_LOG"
    [ -z "${FAKE_SUBMIT_STARTED:-}" ] || : > "$FAKE_SUBMIT_STARTED"
    while [ -n "${FAKE_SUBMIT_RELEASE:-}" ] && [ ! -e "$FAKE_SUBMIT_RELEASE" ]; do sleep .01; done
    printf '%s\n' "${2#--job-name=}" > "$FAKE_ACCEPTED_JOB_NAME"
    printf '%s\n' "${FAKE_JOB_ID:-12345}" > "$FAKE_ACCEPTED_JOB_ID"
    printf '%s;cluster\n' "${FAKE_JOB_ID:-12345}"
    ;;
  "scancel "*)
    [ -z "${FAKE_SCANCEL_LOG:-}" ] || printf '%s\n' "$command" >> "$FAKE_SCANCEL_LOG"
    [ -z "${FAKE_SCANCEL_STARTED:-}" ] || : > "$FAKE_SCANCEL_STARTED"
    while [ -n "${FAKE_SCANCEL_RELEASE:-}" ] && [ ! -e "$FAKE_SCANCEL_RELEASE" ]; do sleep .01; done
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
	testutil.WriteScript(t, path, script)
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
	const discoveryMarker = "__CSCTL_DSC_6f1c9a7e4b2d8053_"
	t.Setenv("DISC_USER", discoveryMarker+"USER__")
	t.Setenv("DISC_ACCOUNTS", discoveryMarker+"ACCOUNTS__")
	t.Setenv("DISC_PARTITIONS", discoveryMarker+"PARTITIONS__")
	t.Setenv("DISC_HOME", discoveryMarker+"HOME__")
	t.Setenv("DISC_DONE", discoveryMarker+"DONE__")
	t.Setenv("DISC_ERROR_USER", discoveryMarker+"ERROR_USER__")
	t.Setenv("DISC_ERROR_PARTITIONS", discoveryMarker+"ERROR_PARTITIONS__")
	return path, scriptLog, commandLog
}

// newTestService is NewService without the background reconciler and sampler; tests drive those directly.
func newTestService(t *testing.T, runner ssh.Runner, store Store) Service {
	t.Helper()
	service := Service{
		runner: runner, runners: testRunnerProvider{runner: runner}, store: store, linkspanExecutable: "/opt/cybershuttle/linkspan",
		logs: newSessionLogs(), metrics: newSessionMetrics(), tunnelTimeout: runner.EffectiveTimeout(),
		hostPreparations: &sync.Map{}, now: time.Now, runtime: newSessionRuntime(),
	}
	t.Cleanup(service.Close)
	return service
}

func fakeSSHService(t *testing.T, sshBin string) Service {
	t.Helper()
	return newTestService(t, ssh.Runner{SSHBin: sshBin, Timeout: 5 * time.Second}, testSessionStore(t))
}

func testService(t *testing.T) Service {
	t.Helper()
	sshBin, _, _ := fakeSSH(t)
	service := fakeSSHService(t, sshBin)
	service.now = func() time.Time { return time.Unix(1, 0).UTC() }
	configureTestTunnel(t, &service)
	return service
}

func newTestCreateRequest() createRequest {
	return createRequest{ID: "s-012345abcdef", IdempotencyKey: "request-one", SSHHost: "delta", Account: "project-a", Partition: "cpu", RootFolder: "projects/example", Resources: resources{Cores: 4, MemoryMB: 4096, WallMinutes: 60}}
}

func TestSessionLifecycleUsesManagedLinkspanAndSeparateRoots(t *testing.T) {
	sshBin, scriptLog, _ := fakeSSH(t)
	cancellations := filepath.Join(t.TempDir(), "cancellations")
	t.Setenv("FAKE_SCANCEL_LOG", cancellations)
	service := fakeSSHService(t, sshBin)
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
	runs, err := service.ListRuns(testPrincipal)
	if err != nil || len(runs) != 1 || runs[0].SessionID != session.ID {
		t.Fatalf("stop did not freeze a run: %#v %v", runs, err)
	}
	if _, ok := service.logs.tail(session.ID); ok {
		t.Fatal("stop left the live log tail behind")
	}
}

func TestCreateIdempotencyIsPrincipalScoped(t *testing.T) {
	request := createRequest{IdempotencyKey: "same", SSHHost: "delta", Account: "project-a", Partition: "cpu", RootFolder: "projects/a", Resources: resources{Cores: 2, MemoryMB: 4096, WallMinutes: 10}}
	service := testService(t)
	first, err := service.create(testTunnelContext(), request)
	testutil.Check(t, err)

	broker := service.tunnelCredentials.(*testLinkBroker)
	broker.mu.Lock()
	delete(broker.links, testPrincipal)
	broker.mu.Unlock()
	replayed, err := service.create(testTunnelContext(), request)
	if err != nil || first.ID != replayed.ID || first.JobID != replayed.JobID {
		t.Fatalf("same-principal replay = %#v, want %#v: %v", replayed, first, err)
	}

	broker.mu.Lock()
	broker.links[otherTestPrincipal] = devtunnel.Credential{Scheme: "Bearer", Token: "other-tunnel-link-token"}
	broker.mu.Unlock()
	otherContext := security.WithPrincipal(context.Background(), otherTestPrincipal)
	other, err := service.create(otherContext, request)
	if err != nil || other.ID == first.ID || other.Owner != otherTestPrincipal {
		t.Fatalf("cross-principal create = %#v, first = %#v: %v", other, first, err)
	}
}

func TestConcurrentMismatchedCreateInTheIdempotencyWindowAnswersConflict(t *testing.T) {
	sshBin, _, _ := fakeSSH(t)
	started := filepath.Join(t.TempDir(), "discovery-started")
	release := filepath.Join(t.TempDir(), "discovery-release")
	t.Setenv("FAKE_DISCOVERY_BLOCK_ALIAS", "delta")
	t.Setenv("FAKE_DISCOVERY_STARTED", started)
	t.Setenv("FAKE_DISCOVERY_RELEASE", release)
	service := fakeSSHService(t, sshBin)
	configureTestTunnel(t, &service)

	requestA := createRequest{IdempotencyKey: "shared-key", SSHHost: "delta", Account: "project-a", Partition: "cpu", RootFolder: "projects/example", Resources: resources{Cores: 4, MemoryMB: 4096, WallMinutes: 60}}
	requestB := requestA
	requestB.SSHHost = "beta"

	first := make(chan error, 1)
	go func() {
		_, err := service.create(testTunnelContext(), requestA)
		first <- err
	}()
	testutil.WaitForFile(t, started)

	second := make(chan error, 1)
	go func() {
		_, err := service.create(testTunnelContext(), requestB)
		second <- err
	}()
	testutil.RemainsBlocked(t, second, "a competing create bypassed the in-flight request")
	testutil.Check(t, os.WriteFile(release, nil, 0o600))
	testutil.Check(t, <-first)
	if err := <-second; security.For(err).Code != "idempotency_conflict" {
		t.Fatalf("a mismatched create that landed in the idempotency window answered %v, not idempotency_conflict", err)
	}
}

func TestStopOutlivesRequestAndStopsWithService(t *testing.T) {
	service := testService(t)
	manager := service.tunnelManager.(*testTunnelManager)
	manager.operationStarted, manager.operationBlock = make(chan struct{}), make(chan struct{})
	session := pendingSession(sessionLogIDOne, "delta", "12345")
	session.State = "READY"
	session.Account = "project-a"
	session.RootFolder = "projects/example"
	session.WorkspaceRoot = "/home/tester/projects/example"
	session.PrivateRoot = "/home/tester/.cybershuttle/sessions/" + session.ID
	putSessions(t, service, session)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var stopped *Session
	var stopErr error
	done := make(chan error, 1)
	go func() {
		stopped, stopErr = service.stop(security.WithPrincipal(ctx, testPrincipal), session.ID)
		done <- stopErr
	}()
	<-manager.operationStarted
	closed := make(chan error, 1)
	go func() { service.Close(); closed <- nil }()
	testutil.RemainsBlocked(t, closed, "service closed while a stop was still running")
	close(manager.operationBlock)
	testutil.Within(t, closed, time.Second, "service did not close after stop completed")
	testutil.Within(t, done, time.Second, "stop did not complete")
	if stopped.State != "STOPPING" || strings.Contains(stopped.Error, "context canceled") {
		t.Fatalf("canceled request interrupted durable stop: %#v", stopped)
	}
}

func TestDeleteRemovesATerminalSessionAndItsCredential(t *testing.T) {
	service := testService(t)
	session := pendingSession(sessionLogIDOne, "delta", "12345")
	setTestSessionMetadata(&session)
	session.State = "FAILED"
	putSessions(t, service, session)
	testutil.Check(t, putCapability(service.capabilityDir, session.ID, session.Seq, defaultSessionCapability()))
	service.logs.append(session.ID, "starting", service.utcNow())

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
	if _, err := getCapability(service.capabilityDir, session.ID, session.Seq); err == nil {
		t.Fatal("delete left the seq capability on disk")
	}
	if _, ok := service.logs.tail(session.ID); ok {
		t.Fatal("delete left the session log tail in memory")
	}
	if _, err := service.delete(testTunnelContext(), session.ID); err == nil {
		t.Fatal("deleting an absent session should not succeed")
	}
}

func TestStopAndDeleteSurviveADevTunnelsReleaseFailure(t *testing.T) {
	sshBin, _, _ := fakeSSH(t)
	service := fakeSSHService(t, sshBin)
	manager := configureTestTunnel(t, &service)
	created, err := service.create(testTunnelContext(), newTestCreateRequest())
	testutil.Check(t, err)
	manager.deleteErr = errors.New("Dev Tunnels outage")

	stopped, err := service.stop(testTunnelContext(), created.ID)
	testutil.Check(t, err)
	if stopped.State != "STOPPED" {
		t.Fatalf("unexpected state after stop: %#v", stopped)
	}
	if !strings.Contains(stopped.Error, "Dev Tunnels outage") {
		t.Fatalf("the release failure was not recorded on the session: %#v", stopped)
	}

	deleted, err := service.delete(testTunnelContext(), created.ID)
	testutil.Check(t, err)
	if deleted.ID != created.ID {
		t.Fatalf("unexpected deleted session: %#v", deleted)
	}
}

func TestCreateSerializesAcrossProcessesWithoutHoldingStoreLockDuringTunnelCreate(t *testing.T) {
	service := testService(t)
	manager := service.tunnelManager.(*testTunnelManager)
	manager.operationStarted = make(chan struct{})
	manager.operationBlock = make(chan struct{})
	request := newTestCreateRequest()
	sum := sha256.Sum256([]byte(request.ID))
	lockPath := filepath.Join(service.store.Dir, fmt.Sprintf(".session-create-%02x.lock", int(sum[0])%len(createLocks)))
	processLock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	testutil.Check(t, err)
	defer func() { _ = processLock.Close() }()
	testutil.Check(t, syscall.Flock(int(processLock.Fd()), syscall.LOCK_EX))

	done := make(chan error, 1)
	go func() {
		_, err := service.create(testTunnelContext(), request)
		done <- err
	}()
	testutil.RemainsBlocked(t, manager.operationStarted, "create bypassed the cross-process session lock")
	testutil.Check(t, syscall.Flock(int(processLock.Fd()), syscall.LOCK_UN))

	select {
	case <-manager.operationStarted:
	case <-time.After(time.Second):
		t.Fatal("tunnel create was never reached")
	}
	lockAvailable := make(chan error, 1)
	go func() { lockAvailable <- service.store.locked(func(*state) error { return nil }) }()
	testutil.Within(t, lockAvailable, 300*time.Millisecond, "state lock was held during blocked tunnel create")

	close(manager.operationBlock)
	testutil.Check(t, <-done)
}

const testConnectToken = "test-connect-token"

const testHostToken = "test-host-token"

const testJupyterToken = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

var testPrincipal = security.Principal{Subject: "test-owner", Tenant: "test-tenant"}

var otherTestPrincipal = security.Principal{Subject: "other-owner", Tenant: "test-tenant"}

type testLinkBroker struct {
	mu    sync.Mutex
	links map[security.Principal]devtunnel.Credential
}

func newTestLinkBroker() *testLinkBroker {
	return &testLinkBroker{links: map[security.Principal]devtunnel.Credential{testPrincipal: {Scheme: "Bearer", Token: "test-tunnel-link-token"}}}
}

func (b *testLinkBroker) Credential(_ context.Context, principal security.Principal) (devtunnel.Credential, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	link, ok := b.links[principal]
	if !ok {
		return devtunnel.Credential{}, security.New("tunnel_link_required", "a Dev Tunnels link is required", http.StatusConflict)
	}
	return link, nil
}

func reconciledList(ctx context.Context, service Service) ([]Session, error) {
	if err := service.reconcileAll(ctx); err != nil {
		return nil, err
	}
	return service.loadSessions()
}

type testTunnelManager struct {
	mu               sync.Mutex
	creates          []devtunnel.CreateRequest
	gets             []devtunnel.GetRequest
	deletes          []devtunnel.DeleteRequest
	createErr        error
	deleteErr        error
	getResponse      *devtunnel.Record
	expiresAt        time.Time
	operationStarted chan struct{}
	operationBlock   chan struct{}
}

func (m *testTunnelManager) Create(_ context.Context, request devtunnel.CreateRequest) (devtunnel.Record, error) {
	if m.operationStarted != nil {
		close(m.operationStarted)
	}
	if m.operationBlock != nil {
		<-m.operationBlock
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.creates = append(m.creates, request)
	if m.createErr != nil {
		return devtunnel.Record{}, m.createErr
	}
	m.expiresAt = time.Now().UTC().Add(time.Duration(request.DurationSeconds) * time.Second)
	return devtunnel.Record{ID: request.TunnelID, ClusterID: "use", ConnectToken: testConnectToken, HostToken: testHostToken, ExpiresAt: m.expiresAt}, nil
}

func (m *testTunnelManager) Get(_ context.Context, request devtunnel.GetRequest) (devtunnel.Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.gets = append(m.gets, request)
	if m.getResponse != nil {
		return *m.getResponse, nil
	}
	return devtunnel.Record{ID: request.TunnelID, ClusterID: request.ClusterID, ExpiresAt: m.expiresAt, Ports: []devtunnel.PortRecord{{PortNumber: 31001, Protocol: "http", PortForwardingURIs: []string{"https://31001.use.devtunnels.ms"}}}}, nil
}

func (m *testTunnelManager) Delete(_ context.Context, request devtunnel.DeleteRequest) error {
	if m.operationStarted != nil {
		close(m.operationStarted)
	}
	if m.operationBlock != nil {
		<-m.operationBlock
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deletes = append(m.deletes, request)
	return m.deleteErr
}

func testTunnelContext() context.Context {
	return security.WithPrincipal(context.Background(), testPrincipal)
}

type testRunnerProvider struct{ runner ssh.Runner }

func (h testRunnerProvider) Runner(security.Principal) ssh.Runner { return h.runner }

func configureTestTunnel(t *testing.T, service *Service) *testTunnelManager {
	t.Helper()
	testutil.Check(t, security.EnsurePrivateDir(service.store.Dir))
	manager := &testTunnelManager{}
	service.tunnelManager = manager
	service.tunnelCredentials = newTestLinkBroker()
	service.capabilityDir = t.TempDir() + "/session-capabilities"
	return manager
}

func setTestSessionMetadata(session *Session) {
	if session.Seq == 0 {
		session.Seq = 1
		session.Owner = testPrincipal
		session.Tunnel = tunnelMetadata{ID: session.ID + "-" + strconv.Itoa(session.Seq), ClusterID: "use", ExpiresAt: time.Now().Add(time.Hour)}
	}
}

func putSessions(t *testing.T, service Service, sessions ...Session) {
	t.Helper()
	testutil.Check(t, service.store.locked(func(current *state) error {
		for i := range sessions {
			copy := sessions[i]
			setTestSessionMetadata(&copy)
			current.Sessions[copy.ID] = &copy
		}
		return service.store.save(current)
	}))
}

func pendingSession(id, host, jobID string) Session {
	now := time.Unix(1, 0).UTC()
	return Session{
		sessionResponse: sessionResponse{ID: id, State: "QUEUED", SSHHost: host, Partition: "cpu", RootFolder: ".", Resources: resources{Cores: 1, MemoryMB: 1024, WallMinutes: 60}, CreatedAt: now, UpdatedAt: now},
		JobID:           jobID, JobName: jobName(id, 1), PrivateRoot: "/home/test/.cybershuttle/sessions/" + id, WorkspaceRoot: "/home/test", Owner: testPrincipal,
	}
}

func createStopRaceService(t *testing.T) (Service, string, string, string) {
	t.Helper()
	dir := t.TempDir()
	started := filepath.Join(dir, "submit-started")
	release := filepath.Join(dir, "submit-release")
	cancellations := filepath.Join(dir, "cancellations")
	t.Setenv("FAKE_SUBMIT_STARTED", started)
	t.Setenv("FAKE_SUBMIT_RELEASE", release)
	t.Setenv("FAKE_SCANCEL_LOG", cancellations)
	service := testService(t)
	return service, started, release, cancellations
}

// waitFor waits for the fake SSH marker file at path while create is still running.
func waitFor(t *testing.T, errs <-chan error, what, path string) {
	t.Helper()
	testutil.Eventually(t, 5*time.Second, what, func() bool {
		select {
		case err := <-errs:
			t.Fatalf("Create finished before %s: %v", what, err)
		default:
		}
		_, err := os.Stat(path)
		return err == nil
	})
}

func TestCreateCancelsJobWhenStopWinsBeforeSbatchReturns(t *testing.T) {
	service, started, release, cancellations := createStopRaceService(t)
	result := make(chan *Session, 1)
	errs := make(chan error, 1)
	go func() {
		session, err := service.create(testTunnelContext(), newTestCreateRequest())
		result <- session
		errs <- err
	}()
	waitFor(t, errs, "sbatch started", started)

	stopped, err := service.stop(testTunnelContext(), newTestCreateRequest().ID)
	if err != nil || stopped.State != "STOPPING" || stopped.JobID != "" {
		t.Fatalf("stop did not persist intent while sbatch was blocked: %#v %v", stopped, err)
	}
	testutil.Check(t, os.WriteFile(release, nil, 0o600))

	testutil.Within(t, errs, 5*time.Second, "Create did not finish after sbatch was released")
	created := <-result
	if created.State != "STOPPING" || created.JobID != "12345" || created.Error != "" {
		t.Fatalf("Create overwrote stop intent: %#v", created)
	}
	data, err := os.ReadFile(cancellations)
	if err != nil || strings.Count(string(data), "scancel 12345") != 1 {
		t.Fatalf("submitted job was not immediately cancelled exactly once: %q %v", data, err)
	}
	cached, err := service.loadSession(created.ID)
	if err != nil || cached.State != "STOPPING" || cached.JobID != "12345" {
		t.Fatalf("stored state lost stop/job identity: %#v %v", cached, err)
	}
}

func TestCreatePersistsCancelFailureAndLaterBatchRetries(t *testing.T) {
	service, started, release, cancellations := createStopRaceService(t)
	t.Setenv("FAKE_SCANCEL_FAIL", "1")
	result := make(chan *Session, 1)
	errs := make(chan error, 1)
	go func() {
		session, err := service.create(testTunnelContext(), newTestCreateRequest())
		result <- session
		errs <- err
	}()
	waitFor(t, errs, "sbatch started", started)
	_, err := service.stop(testTunnelContext(), newTestCreateRequest().ID)
	testutil.Check(t, err)
	testutil.Check(t, os.WriteFile(release, nil, 0o600))
	testutil.Check(t, <-errs)
	created := <-result
	if created.State != "STOPPING" || !strings.Contains(created.Error, "scheduler temporarily unavailable") {
		t.Fatalf("cancel failure was not persisted: %#v", created)
	}

	t.Setenv("FAKE_SCANCEL_FAIL", "0")
	listed, err := reconciledList(context.Background(), service)
	testutil.Check(t, err)
	if len(listed) != 1 || listed[0].State != "STOPPED" || listed[0].Error != "" {
		t.Fatalf("later reconciliation did not retry cancellation: %#v", listed)
	}
	data, err := os.ReadFile(cancellations)
	if err != nil || !strings.Contains(string(data), "batch scancel") {
		t.Fatalf("later batch did not retry cancellation: %q %v", data, err)
	}
}

func TestCreateCancelsUnsavedJobEvenWithACancelledRequestContext(t *testing.T) {
	service, started, release, cancellations := createStopRaceService(t)
	cancelStarted := filepath.Join(t.TempDir(), "scancel-started")
	cancelRelease := filepath.Join(t.TempDir(), "scancel-release")
	t.Setenv("FAKE_SCANCEL_STARTED", cancelStarted)
	t.Setenv("FAKE_SCANCEL_RELEASE", cancelRelease)
	ctx, cancel := context.WithCancel(testTunnelContext())
	request := newTestCreateRequest()
	errs := make(chan error, 1)
	go func() {
		_, err := service.create(ctx, request)
		errs <- err
	}()
	waitFor(t, errs, "sbatch started", started)
	testutil.Check(t, service.store.Database.Close())
	testutil.Check(t, os.WriteFile(release, nil, 0o600))
	waitFor(t, errs, "compensation scancel started", cancelStarted)
	cancel()
	testutil.Check(t, os.WriteFile(cancelRelease, nil, 0o600))

	err := <-errs
	if err == nil || !strings.Contains(err.Error(), "job was cancelled") {
		t.Fatalf("compensation did not report a successful cancel with a cancelled request context: %v", err)
	}
	data, err := os.ReadFile(cancellations)
	if err != nil || !strings.Contains(string(data), "12345") {
		t.Fatalf("submitted job was not cancelled: %q %v", data, err)
	}
}

func retire(t *testing.T, service Service, id string) Session {
	t.Helper()
	var terminal Session
	testutil.Check(t, service.store.locked(func(current *state) error {
		session := current.Sessions[id]
		session.State, session.Node = "STOPPED", "cn001"
		session.CreatedAt, session.UpdatedAt = time.Unix(0, 0).UTC(), time.Unix(0, 0).UTC()
		terminal = *session
		return service.store.save(current)
	}))
	return terminal
}

func TestStartRunsTheFinishedSessionOnTheSameSession(t *testing.T) {
	service := testService(t)
	tunnels := configureTestTunnel(t, &service)
	created, err := service.create(testTunnelContext(), newTestCreateRequest())
	testutil.Check(t, err)
	terminal := retire(t, service, created.ID)

	started, err := service.start(testTunnelContext(), created.ID)
	testutil.Check(t, err)
	if started.ID != created.ID {
		t.Fatalf("run again took a new identity: %s -> %s", created.ID, started.ID)
	}
	if started.State != "QUEUED" || started.Seq == terminal.Seq || started.Node != "" {
		t.Fatalf("unexpected relaunched session: %#v", started)
	}
	if !started.CreatedAt.Equal(terminal.CreatedAt) || !started.UpdatedAt.After(terminal.UpdatedAt) {
		t.Fatalf("relaunch must keep the session's creation time and move it forward: %#v", started.sessionResponse)
	}
	if len(tunnels.deletes) != 1 || tunnels.deletes[0].TunnelID != created.ID+"-"+strconv.Itoa(terminal.Seq) {
		t.Fatalf("the finished run's tunnel was not released: %#v", tunnels.deletes)
	}
	sessions, err := service.loadSessions()
	testutil.Check(t, err)
	if len(sessions) != 1 || sessions[0].RootFolder != terminal.RootFolder {
		t.Fatalf("run again must leave exactly the one session it ran: %#v", sessions)
	}
}

func TestStartRefusesSessionsItMayNotRun(t *testing.T) {
	service := testService(t)
	created, err := service.create(testTunnelContext(), newTestCreateRequest())
	testutil.Check(t, err)
	if _, err := service.start(testTunnelContext(), created.ID); err == nil || security.For(err).Code != "session_running" {
		t.Fatalf("a live session was run again: %v", err)
	}
	retire(t, service, created.ID)

	stranger := security.Principal{Subject: "other-owner", Tenant: "test-tenant"}
	ctx := security.WithPrincipal(context.Background(), stranger)
	if _, err := service.start(ctx, created.ID); err == nil || security.For(err).Code != "session_owner_mismatch" {
		t.Fatalf("another principal ran this session: %v", err)
	}
	if _, err := service.start(testTunnelContext(), "s-999999999999"); err == nil || security.For(err).Code != "session_not_found" {
		t.Fatalf("an unknown session was run: %v", err)
	}
}

func relaunchRaceService(t *testing.T) (Service, *atomic.Int64, string, string) {
	t.Helper()
	dir := t.TempDir()
	started := filepath.Join(dir, "provision-started")
	release := filepath.Join(dir, "provision-release")
	t.Setenv("FAKE_PROVISION_STARTED", started)
	clock := &atomic.Int64{}
	clock.Store(time.Date(2026, 8, 28, 10, 0, 0, 0, time.UTC).UnixNano())
	service := testService(t)
	service.now = func() time.Time { return time.Unix(0, clock.Load()).UTC() }
	return service, clock, started, release
}

func TestPostIntentWorkOutlivesRequestAndStopsWithService(t *testing.T) {
	sshBin, _, _ := fakeSSH(t)
	dir := t.TempDir()
	provisionStarted, provisionRelease := filepath.Join(dir, "provision-started"), filepath.Join(dir, "provision-release")
	submitStarted := filepath.Join(dir, "submit-started")
	t.Setenv("FAKE_PROVISION_STARTED", provisionStarted)
	t.Setenv("FAKE_PROVISION_RELEASE", provisionRelease)
	t.Setenv("FAKE_SUBMIT_STARTED", submitStarted)
	t.Setenv("FAKE_SUBMIT_RELEASE", filepath.Join(dir, "never-released"))
	service := fakeSSHService(t, sshBin)
	configureTestTunnel(t, &service)
	ctx, cancel := context.WithCancel(testTunnelContext())
	created := make(chan error, 1)
	go func() { _, err := service.create(ctx, newTestCreateRequest()); created <- err }()
	waitFor(t, created, "provisioning started", provisionStarted)
	cancel()
	testutil.Check(t, os.WriteFile(provisionRelease, nil, 0o600))
	waitFor(t, created, "submission started", submitStarted)

	closed := make(chan error, 1)
	go func() { service.Close(); closed <- nil }()
	testutil.Within(t, closed, time.Second, "Close did not cancel and wait for submission")
	if err := <-created; err == nil {
		t.Fatal("cancelled submission succeeded")
	}
	if _, _, ok := service.runtime.begin(); ok {
		t.Fatal("closed runtime accepted new work")
	}
}

func TestRunAgainSurvivesAReconciliationAgainstTheFinishedRun(t *testing.T) {
	service, clock, started, release := relaunchRaceService(t)
	ctx := testTunnelContext()
	created, err := service.create(ctx, newTestCreateRequest())
	testutil.Check(t, err)
	testutil.Check(t, os.WriteFile(os.Getenv("FAKE_STATUS"), []byte("TIMEOUT\n"), 0o600))
	finished := retire(t, service, created.ID)

	clock.Store(finished.CreatedAt.Add(time.Hour).UnixNano())
	t.Setenv("FAKE_PROVISION_RELEASE", release)
	t.Setenv("FAKE_JOB_ID", "67890")
	testutil.Check(t, os.Remove(started))
	result := make(chan *Session, 1)
	errs := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		session, err := service.start(ctx, created.ID)
		result <- session
		errs <- err
	}()
	t.Cleanup(func() {
		_ = os.WriteFile(release, nil, 0o600)
		<-done
	})
	waitFor(t, errs, "sbatch started", started)

	testutil.Check(t, service.reconcileAll(ctx))
	during, err := service.loadSession(created.ID)
	testutil.Check(t, err)
	if during.State != "SUBMITTING" {
		t.Fatalf("the finished run retired the relaunch: %s (job %q, node %q)", during.State, during.JobID, during.Node)
	}
	if during.JobID == finished.JobID || during.Node == finished.Node {
		t.Fatalf("the relaunch adopted the finished run's job: %#v", during)
	}

	testutil.Check(t, os.WriteFile(release, nil, 0o600))
	testutil.Check(t, <-errs)
	relaunched := <-result
	if relaunched.State != "QUEUED" || relaunched.JobID != "67890" {
		t.Fatalf("the submitted relaunch was not queued: %#v (job %q)", relaunched.sessionResponse, relaunched.JobID)
	}
}

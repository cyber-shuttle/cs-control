// Create revalidates the script it is about to submit, which is identical to validate's script except for
// the log redirect: validate has no seq yet, so it uses the placeholder-seq basename.
// A validation failure persists and submits nothing; no pre-persistence failure, including one from the
// tunnel provider, leaves a log buffer behind.
//
//	Test*
package control

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cyber-shuttle/cs-control/internal/apierr"
	"github.com/cyber-shuttle/cs-control/internal/sshexec"
	"github.com/cyber-shuttle/cs-control/internal/testutil"
)

func TestCreateRevalidatesExactScriptBeforeSubmit(t *testing.T) {
	ssh, scriptLog, commandLog := fakeSSH(t)
	service := Service{Runner: sshexec.Runner{SSHBin: ssh}, Store: Store{Dir: t.TempDir()}, Config: Config{LinkspanPath: "/opt/cybershuttle/linkspan"}, Logs: NewSessionLogs(), Metrics: NewSessionMetrics()}
	configureTestTunnel(t, &service)
	request := newTestCreateRequest()
	request.ID = ""
	validatedResult, err := service.validate(context.Background(), request)
	testutil.Check(t, err)
	created, err := service.create(testTunnelContext(), request)
	testutil.Check(t, err)
	testutil.Equal(t, created.ID, validatedResult.SessionID, "created session ID")
	submitted, err := os.ReadFile(scriptLog)
	testutil.Check(t, err)
	validated, err := os.ReadFile(filepath.Join(filepath.Dir(scriptLog), "validation-script"))
	if err != nil || string(validated) != validatedResult.Script {
		t.Fatalf("create revalidation differs from the original validation: %v", err)
	}
	submittedBasename := sessionLogBasename(created.ID, created.Seq)
	validatedBasename := sessionLogBasename(created.ID, 0)
	if !strings.Contains(string(submitted), submittedBasename) {
		t.Fatalf("submitted script does not redirect to the created session's seq log:\n%s", submitted)
	}
	if !strings.Contains(string(validated), validatedBasename) {
		t.Fatalf("validation script does not use the pre-seq placeholder log path:\n%s", validated)
	}
	if strings.ReplaceAll(string(submitted), submittedBasename, "placeholder") != strings.ReplaceAll(string(validated), validatedBasename, "placeholder") {
		t.Fatalf("submitted and validated scripts differ beyond the log path:\nsubmitted:\n%s\nvalidated:\n%s", submitted, validated)
	}
	commands, _ := os.ReadFile(commandLog)
	if strings.Count(string(commands), "'sbatch' '--test-only'") != 2 || strings.Count(string(commands), "'sbatch' '--job-name=") != 1 {
		t.Fatalf("expected validation, create revalidation, then one submit:\n%s", commands)
	}
}

func TestCreateValidationFailureDoesNotPersistOrSubmit(t *testing.T) {
	ssh, _, commandLog := fakeSSH(t)
	store := Store{Dir: t.TempDir()}
	service := Service{Runner: sshexec.Runner{SSHBin: ssh}, Store: store, Config: Config{LinkspanPath: "/opt/cybershuttle/linkspan"}, Logs: NewSessionLogs(), Metrics: NewSessionMetrics()}
	t.Setenv("FAKE_VALIDATION_FAIL", "1")
	t.Setenv("FAKE_VALIDATION_STDERR", "sbatch: error: rejected")
	_, err := service.create(testTunnelContext(), newTestCreateRequest())
	if apierr.For(err).Code != "slurm_validation_failed" {
		t.Fatalf("unexpected create error: %v", err)
	}
	if _, err := os.Stat(filepath.Join(store.Dir, "state.json")); !os.IsNotExist(err) {
		t.Fatalf("failed validation persisted state: %v", err)
	}
	commands, _ := os.ReadFile(commandLog)
	if strings.Contains(string(commands), "--parsable") {
		t.Fatalf("failed validation submitted a job:\n%s", commands)
	}
}

func TestRetriedCreateAfterValidationFailureStartsWithAnEmptyTail(t *testing.T) {
	ssh, _, _ := fakeSSH(t)
	t.Setenv("FAKE_VALIDATION_FAIL", "1")
	service := Service{Runner: sshexec.Runner{SSHBin: ssh}, Store: Store{Dir: t.TempDir()}, Config: Config{LinkspanPath: "/opt/cybershuttle/linkspan"}, Logs: NewSessionLogs(), Metrics: NewSessionMetrics()}
	configureTestTunnel(t, &service)
	request := newTestCreateRequest()
	if _, err := service.create(testTunnelContext(), request); err == nil {
		t.Fatal("expected the first create to fail")
	}

	t.Setenv("FAKE_VALIDATION_FAIL", "0")
	created, err := service.create(testTunnelContext(), request)
	testutil.Check(t, err)
	if joined := sessionLogText(t, service.Logs, created.ID); strings.Contains(joined, "Slurm validation failed") {
		t.Fatalf("retried create inherited the failed attempt's narration: %s", joined)
	}
}

func TestCreateFailingTunnelCreationLeavesNoLogBuffer(t *testing.T) {
	ssh, _, _ := fakeSSH(t)
	service := Service{Runner: sshexec.Runner{SSHBin: ssh}, Store: Store{Dir: t.TempDir()}, Config: Config{LinkspanPath: "/opt/cybershuttle/linkspan"}, Logs: NewSessionLogs(), Metrics: NewSessionMetrics()}
	manager := configureTestTunnel(t, &service)
	manager.createErr = errors.New("Dev Tunnels create failed")
	request := newTestCreateRequest()
	if _, err := service.create(testTunnelContext(), request); err == nil {
		t.Fatal("expected create to fail when the tunnel cannot be created")
	}
	if _, ok := service.Logs.Tail(request.ID); ok {
		t.Fatal("a create that failed before persisting a record kept its log tail")
	}
}

func TestLinkspanPathMayBeAnchoredAtHome(t *testing.T) {
	for _, value := range []string{"$HOME/.cybershuttle/bin/linkspan", "/usr/local/bin/linkspan"} {
		if !safeRemoteExecutable(value) {
			t.Fatalf("rejected %q", value)
		}
	}
	for _, value := range []string{"$HOME", "$HOME/../escape", "relative/linkspan", "$OTHER/linkspan"} {
		if safeRemoteExecutable(value) {
			t.Fatalf("accepted %q", value)
		}
	}
	if got := resolveRemoteExecutable("$HOME/.cybershuttle/bin/linkspan", "/u/someone"); got != "/u/someone/.cybershuttle/bin/linkspan" {
		t.Fatalf("anchor not resolved: %q", got)
	}
	if got := resolveRemoteExecutable("/usr/local/bin/linkspan", "/u/someone"); got != "/usr/local/bin/linkspan" {
		t.Fatalf("absolute path was rewritten: %q", got)
	}
}

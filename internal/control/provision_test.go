package control

import (
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

// A host that has never run a runtime has neither the interpreter the script
// starts nor the binary it execs, so creating one installs both first.
func TestCreateProvisionsABareHost(t *testing.T) {
	ssh, _, _, _ := fakeSSH(t)
	provisionLog := t.TempDir() + "/provision"
	t.Setenv("FAKE_PROVISION_LOG", provisionLog)
	t.Setenv("FAKE_PROVISION_REPORT", "jupyter=installed")
	service := Service{Runner: sshexec.Runner{SSHBin: ssh}, Store: Store{Dir: t.TempDir()}, Logs: NewRuntimeLogs()}
	configureTestTunnel(t, &service)
	created, err := service.Create(testTunnelContext(), createRequest())
	if err != nil {
		t.Fatal(err)
	}
	// The script the host received is the one this package ships, and it is
	// told where the workspace and the binary are rather than carrying them.
	script, err := os.ReadFile(provisionLog)
	if err != nil || string(script) != provisionScript {
		t.Fatalf("host did not receive the provisioning script: %v", err)
	}
	status := []string{}
	tail, _ := service.Logs.Tail(created.ID)
	for _, line := range tail.Lines {
		status = append(status, line.Text)
	}
	joined := strings.Join(status, "|")
	for _, expected := range []string{"Preparing the runtime environment", "Installed Jupyter environment", "Runtime environment ready"} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("status never reported %q: %s", expected, joined)
		}
	}
}

// A host that cannot be prepared is refused with the reason, and no job is ever
// submitted to it.
func TestCreateRefusesAHostItCannotProvision(t *testing.T) {
	ssh, _, scriptLog, _ := fakeSSH(t)
	t.Setenv("FAKE_PROVISION_FAIL", "1")
	t.Setenv("FAKE_PROVISION_REPORT", "error=linkspan-download")
	service := Service{Runner: sshexec.Runner{SSHBin: ssh}, Store: Store{Dir: t.TempDir()}, Logs: NewRuntimeLogs()}
	configureTestTunnel(t, &service)
	_, err := service.Create(testTunnelContext(), createRequest())
	failure := apierr.For(err)
	if failure.Code != "runtime_provisioning_failed" || !strings.Contains(failure.Message, "download the Linkspan release") {
		t.Fatalf("unexpected refusal: %#v", failure)
	}
	if _, statErr := os.Stat(scriptLog); statErr == nil {
		t.Fatal("a job was submitted to a host that could not be prepared")
	}
}

// A caller whose connection went away leaves an install running, so the next
// one is told to come back rather than made to wait behind work it cannot see
// or, worse, made to run a second uv against a half-built environment.
func TestSecondCreateIsRefusedWhileTheHostIsBeingPrepared(t *testing.T) {
	release, busy := hostPreparations.begin("delta")
	if busy {
		t.Fatal("host was already marked as being prepared")
	}
	ssh, _, scriptLog, _ := fakeSSH(t)
	service := Service{Runner: sshexec.Runner{SSHBin: ssh}, Store: Store{Dir: t.TempDir()}, Logs: NewRuntimeLogs()}
	configureTestTunnel(t, &service)
	_, err := service.Create(testTunnelContext(), createRequest())
	failure := apierr.For(err)
	if failure.Code != "runtime_provisioning_in_progress" || failure.Status != 409 {
		t.Fatalf("unexpected refusal: %#v", failure)
	}
	if _, statErr := os.Stat(scriptLog); statErr == nil {
		t.Fatal("a job was submitted while the host was still being prepared")
	}
	release()
	// Once the preparation finishes, the same request goes through.
	if _, err := service.Create(testTunnelContext(), createRequest()); err != nil {
		t.Fatalf("create was still refused after preparation ended: %v", err)
	}
}

// Choosing a host in the browser is the first moment anyone knows it will be
// used, so the install starts then rather than inside the request that submits.
func TestSelectingAHostPreparesItInTheBackground(t *testing.T) {
	ssh, _, _, _ := fakeSSH(t)
	provisionLog := filepath.Join(t.TempDir(), "provision")
	t.Setenv("FAKE_PROVISION_LOG", provisionLog)
	service := Service{Runner: sshexec.Runner{SSHBin: ssh}, Store: Store{Dir: t.TempDir()}, Logs: NewRuntimeLogs()}
	api := NewHTTPHandler(service, nil)
	t.Cleanup(api.Close)

	response := httptest.NewRecorder()
	api.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/v1/ssh/delta/slurm", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("discovery failed: %d %s", response.Code, response.Body.String())
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if script, err := os.ReadFile(provisionLog); err == nil && string(script) == provisionScript {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("selecting a host never prepared it")
}

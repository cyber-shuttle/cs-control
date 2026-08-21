package control

import (
	"os"
	"strings"
	"testing"

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

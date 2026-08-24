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
	ssh, _, _ := fakeSSH(t)
	dir := t.TempDir()
	provisionLog, workflowLog := dir+"/provision", dir+"/workflow"
	t.Setenv("FAKE_PROVISION_LOG", provisionLog)
	t.Setenv("FAKE_WORKFLOW_LOG", workflowLog)
	t.Setenv("FAKE_PROVISION_REPORT", "uv=installed")
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
	// The workflow install reads its document from standard input while the
	// script it runs travels as an argument, so what lands on the host is the
	// document rather than the script that writes it.
	document, err := os.ReadFile(workflowLog)
	if err != nil || string(document) != runtimeWorkflow(*created) {
		t.Fatalf("host did not receive the workflow document: %v\n%s", err, document)
	}
	status := []string{}
	tail, _ := service.Logs.Tail(created.ID)
	for _, line := range tail.Lines {
		status = append(status, line.Text)
	}
	joined := strings.Join(status, "|")
	for _, expected := range []string{"Preparing the runtime environment", "Installed uv", "Runtime environment ready"} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("status never reported %q: %s", expected, joined)
		}
	}
}

// A host that cannot be prepared is refused with the reason, and no job is ever
// submitted to it.
func TestCreateRefusesAHostItCannotProvision(t *testing.T) {
	ssh, scriptLog, _ := fakeSSH(t)
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
	ssh, scriptLog, _ := fakeSSH(t)
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

// The allocation hosts a tunnel the control plane created, so a Linkspan that
// predates host-scoped tokens cannot run one. It is refused while a runtime can
// still be refused, rather than by an allocation that dies on its first flag.
func TestCreateRefusesALinkspanThatCannotHostTheTunnel(t *testing.T) {
	ssh, scriptLog, _ := fakeSSH(t)
	t.Setenv("FAKE_PROVISION_FAIL", "1")
	t.Setenv("FAKE_PROVISION_REPORT", "error=linkspan-unsupported")
	service := Service{Runner: sshexec.Runner{SSHBin: ssh}, Store: Store{Dir: t.TempDir()}, Logs: NewRuntimeLogs()}
	configureTestTunnel(t, &service)
	_, err := service.Create(testTunnelContext(), createRequest())
	if failure := apierr.For(err); !strings.Contains(failure.Message, "tunnel-host-token") {
		t.Fatalf("refusal does not name what is missing: %#v", failure)
	}
	if _, statErr := os.Stat(scriptLog); statErr == nil {
		t.Fatal("a job was submitted to a host whose Linkspan cannot host the tunnel")
	}
}

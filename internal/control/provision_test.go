package control

import (
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cyber-shuttle/cs-control/internal/apierr"
	"github.com/cyber-shuttle/cs-control/internal/sshexec"
)

// A host that has never run a runtime has neither the interpreter the script
// starts nor the binary it execs, so creating one installs both first.
func TestCreateProvisionsABareHost(t *testing.T) {
	ssh, _, commandLog := fakeSSH(t)
	provisionLog := t.TempDir() + "/provision"
	t.Setenv("FAKE_PROVISION_LOG", provisionLog)
	t.Setenv("FAKE_PROVISION_REPORT", "uv=installed")
	service := Service{Runner: sshexec.Runner{SSHBin: ssh}, Store: Store{Dir: t.TempDir()}, Logs: NewRuntimeLogs()}
	configureTestTunnel(t, &service)
	created, err := service.Create(testTunnelContext(), createRequest())
	if err != nil {
		t.Fatal(err)
	}
	// The script the host received is the one this package ships, and it is
	// told where the workspace, the binary and the workflow are rather than
	// carrying them.
	script, err := os.ReadFile(provisionLog)
	if err != nil || string(script) != provisionScript {
		t.Fatalf("host did not receive the provisioning script: %v", err)
	}
	if document := provisionedWorkflow(t, commandLog); document != runtimeWorkflow(*created, "/home/tester") {
		t.Fatalf("host did not receive the workflow document:\n%s", document)
	}
	joined := runtimeLogText(t, service.Logs, created.ID, false)
	for _, expected := range []string{"Preparing the runtime environment", "Installed uv", "Runtime environment ready"} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("status never reported %q: %s", expected, joined)
		}
	}
}

// provisionedWorkflow recovers the document the host was handed from the
// provisioning command line, which is where it travels.
func provisionedWorkflow(t *testing.T, commandLog string) string {
	t.Helper()
	commands, err := os.ReadFile(commandLog)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(commands), "\n") {
		if !strings.Contains(line, "csctl-provision") {
			continue
		}
		arguments := strings.Split(strings.TrimSuffix(line, "'"), "'")
		document, err := base64.StdEncoding.DecodeString(arguments[len(arguments)-1])
		if err != nil {
			t.Fatalf("provisioning argument is not a base64 workflow: %v", err)
		}
		return string(document)
	}
	t.Fatal("host was never asked to provision")
	return ""
}

// A host that cannot be prepared is refused with the reason, and no job is ever
// submitted to it.
func TestCreateRefusesAHostItCannotProvision(t *testing.T) {
	for _, test := range []struct{ report, want string }{
		{"error=linkspan-download", "download the Linkspan release"},
		// The allocation hosts a tunnel the control plane created, so a Linkspan
		// that predates host-scoped tokens is refused while a runtime can still
		// be refused, rather than by an allocation that fails on its first flag.
		{"error=linkspan-unsupported", "tunnel-host-token"},
		{"error=workflow", "write the workflow"},
	} {
		t.Run(test.report, func(t *testing.T) {
			ssh, scriptLog, _ := fakeSSH(t)
			t.Setenv("FAKE_PROVISION_FAIL", "1")
			t.Setenv("FAKE_PROVISION_REPORT", test.report)
			service := Service{Runner: sshexec.Runner{SSHBin: ssh}, Store: Store{Dir: t.TempDir()}, Logs: NewRuntimeLogs()}
			configureTestTunnel(t, &service)
			_, err := service.Create(testTunnelContext(), createRequest())
			failure := apierr.For(err)
			if failure.Code != "runtime_provisioning_failed" || !strings.Contains(failure.Message, test.want) {
				t.Fatalf("unexpected refusal: %#v", failure)
			}
			if _, statErr := os.Stat(scriptLog); statErr == nil {
				t.Fatal("a job was submitted to a host that could not be prepared")
			}
		})
	}
}

// A caller whose connection went away leaves an install running, so the next
// one is told to come back rather than made to wait behind work it cannot see
// or, worse, made to run a second uv against a half-built environment.
func TestSecondCreateIsRefusedWhileTheHostIsBeingPrepared(t *testing.T) {
	if _, busy := hostPreparations.LoadOrStore("delta", true); busy {
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
	hostPreparations.Delete("delta")
	// Once the preparation finishes, the same request goes through.
	if _, err := service.Create(testTunnelContext(), createRequest()); err != nil {
		t.Fatalf("create was still refused after preparation ended: %v", err)
	}
}

// runProvisionScript runs the shipped script on this machine against stubs, so
// its own argument contract is exercised rather than described.
func runProvisionScript(t *testing.T, arguments ...string) (string, error) {
	t.Helper()
	// No release lookup: an unreachable curl leaves the installed binary in place.
	stubs := t.TempDir()
	if err := os.WriteFile(filepath.Join(stubs, "curl"), []byte("#!/bin/sh\nexit 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("/bin/sh", append([]string{"-s", "--"}, arguments...)...)
	command.Stdin = strings.NewReader(provisionScript)
	command.Env = append(os.Environ(), "PATH="+stubs+":"+os.Getenv("PATH"))
	output, err := command.CombinedOutput()
	return string(output), err
}

func TestProvisionScriptGuardsItsArgumentVector(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".local", "bin"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".local", "bin", "uv"), []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	linkspan := filepath.Join(home, ".local", "bin", "linkspan")
	if err := os.WriteFile(linkspan, []byte("#!/bin/sh\ncase \"$1\" in --version) echo v9.9.9;; --help) echo '  --tunnel-host-token string';; esac\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	workflow := filepath.Join(home, ".cybershuttle", "runtimes", "rt-012345abcdef", "workflow.yaml")
	document := base64.StdEncoding.EncodeToString([]byte("workflow: yes\n"))

	output, err := runProvisionScript(t, "csctl-provision", home, linkspan, workflow, document)
	if err != nil || !strings.Contains(output, "provision=complete") {
		t.Fatalf("the vector provisionRuntime sends was refused: %v\n%s", err, output)
	}

	// The guard must refuse rather than record a failed test and carry on.
	for _, wrong := range [][]string{
		{"csctl-provision", home, linkspan, workflow},
		{"not-csctl-provision", home, linkspan, workflow, document},
	} {
		output, err := runProvisionScript(t, wrong...)
		if err == nil || provisionOutcome(output)["error"] != "arguments" {
			t.Fatalf("wrong vector %v was not refused: %v\n%s", wrong, err, output)
		}
	}
}

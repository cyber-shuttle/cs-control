// The batch script and the workflow it points Linkspan at name no secret.
// A bare host is provisioned on its first create, and a failed preparation is refused with the reason; a
// second caller is refused rather than made to wait while preparation is in flight.
// The argument-vector test runs the shipped provisioning script against stub binaries on this machine.
//
//	provisionTestService
//	provisionedWorkflow
//	runProvisionScript
//	Test*
package control

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/cyber-shuttle/cs-control/internal/apierr"
	"github.com/cyber-shuttle/cs-control/internal/sshexec"
	"github.com/cyber-shuttle/cs-control/internal/testutil"
)

func provisionTestService(t *testing.T, ssh string) Service {
	t.Helper()
	service := Service{Runner: sshexec.Runner{SSHBin: ssh}, Store: Store{Dir: t.TempDir()}, Logs: NewSessionLogs(), Metrics: NewSessionMetrics()}
	configureTestTunnel(t, &service)
	return service
}

func provisionedWorkflow(t *testing.T, commandLog string) string {
	t.Helper()
	commands, err := os.ReadFile(commandLog)
	testutil.Check(t, err)
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

func runProvisionScript(t *testing.T, arguments ...string) (string, error) {
	t.Helper()
	stubs := t.TempDir()
	writeScript(t, filepath.Join(stubs, "curl"), "#!/bin/sh\nexit 1\n")
	command := exec.Command("/bin/sh", append([]string{"-s", "--"}, arguments...)...)
	command.Stdin = strings.NewReader(provisionScript)
	command.Env = append(os.Environ(), "PATH="+stubs+":"+os.Getenv("PATH"))
	output, err := command.CombinedOutput()
	return string(output), err
}

func TestSessionWorkflowStartsJupyterWithoutSecrets(t *testing.T) {
	session := Session{
		sessionResponse: sessionResponse{ID: "s-012345abcdef", Seq: 1},
		PrivateRoot:     "/home/test/.cybershuttle/sessions/s-012345abcdef", WorkspaceRoot: "/home/test/project",
	}
	document := sessionWorkflow(session)
	port := strconv.Itoa(int(sessionPorts(session.ID, session.Seq).jupyter))
	for _, required := range []string{
		"tasks:\n  - on: start",
		"    steps:\n      - name: Start Jupyter Server",
		"action: jupyter.sessions.start",
		`root_dir: "/home/test/project"`,
		`addr: "127.0.0.1:` + port + `"`,
	} {
		if !strings.Contains(document, required) {
			t.Fatalf("workflow is missing %q:\n%s", required, document)
		}
	}
	for _, forbidden := range []string{"token", "$", "shell.exec"} {
		if strings.Contains(document, forbidden) {
			t.Fatalf("workflow names %q, which it must not:\n%s", forbidden, document)
		}
	}
}

func TestSessionScriptExecsLinkspanWithTheSessionIdentity(t *testing.T) {
	dir := t.TempDir()
	linkspan := filepath.Join(dir, "linkspan")
	argsLog := filepath.Join(dir, "args")
	writeScript(t, linkspan, `#!/bin/sh
printf '%s\n' "$@" > "$ARGS_LOG"
printf '%s\n' "$JUPYTER_TOKEN" > "$ENV_LOG"
exit 7
`)
	session := Session{
		sessionResponse: sessionResponse{ID: "s-012345abcdef", Seq: 1, Partition: "cpu", Resources: resources{Cores: 1, MemoryMB: 128, WallMinutes: 1}},
		JobName:         jobName("s-012345abcdef", 1), PrivateRoot: dir + "/private", WorkspaceRoot: dir,
	}
	script := buildScript(session, linkspan)
	const jupyterToken, hostToken = "jupyter-secret", "host-secret"
	for _, secret := range []string{jupyterToken, hostToken} {
		if strings.Contains(script, secret) {
			t.Fatalf("session script contains a secret literal:\n%s", script)
		}
	}
	command := exec.Command("bash")
	command.Stdin = strings.NewReader(script)
	const tunnelID, tunnelCluster = "s-012345abcdef-g-0123456789abcdef", "usw3"
	ports := sessionPorts(session.ID, session.Seq)
	command.Env = append(os.Environ(), "HOME="+dir, "ARGS_LOG="+argsLog, "ENV_LOG="+filepath.Join(dir, "env"),
		"JUPYTER_TOKEN="+jupyterToken, "CS_TUNNEL_HOST_TOKEN="+hostToken,
		fmt.Sprintf("CS_CONTROL_PORT=%d", ports.control),
		"CS_TUNNEL_ID="+tunnelID, "CS_TUNNEL_CLUSTER="+tunnelCluster)
	var exitErr *exec.ExitError
	if err := command.Run(); err == nil || !errors.As(err, &exitErr) || exitErr.ExitCode() != 7 {
		t.Fatalf("script did not exec Linkspan or preserve status 7: %v", err)
	}
	for _, required := range []string{hostToken, tunnelID, tunnelCluster, strconv.Itoa(int(ports.control)), sessionWorkflowPath(session)} {
		if got := string(mustRead(t, argsLog)); !strings.Contains(got, required) {
			t.Fatalf("Linkspan argv missing %q: %q", required, got)
		}
	}
	if got := string(mustRead(t, filepath.Join(dir, "env"))); !strings.Contains(got, jupyterToken) {
		t.Fatalf("Linkspan did not inherit the Jupyter token: %q", got)
	}
}

func TestCreateProvisionsABareHost(t *testing.T) {
	ssh, _, commandLog := fakeSSH(t)
	provisionLog := t.TempDir() + "/provision"
	t.Setenv("FAKE_PROVISION_LOG", provisionLog)
	t.Setenv("FAKE_PROVISION_REPORT", "linkspan=installed")
	service := provisionTestService(t, ssh)
	created, err := service.create(testTunnelContext(), newTestCreateRequest())
	testutil.Check(t, err)
	script, err := os.ReadFile(provisionLog)
	if err != nil || string(script) != provisionScript {
		t.Fatalf("host did not receive the provisioning script: %v", err)
	}
	if document := provisionedWorkflow(t, commandLog); document != sessionWorkflow(*created) {
		t.Fatalf("host did not receive the workflow document:\n%s", document)
	}
	joined := sessionLogText(t, service.Logs, created.ID)
	for _, expected := range []string{"Preparing the session environment", "Installed Linkspan", "Session environment ready"} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("status never reported %q: %s", expected, joined)
		}
	}
}

func TestCreateRefusesAHostItCannotProvision(t *testing.T) {
	for _, test := range []struct{ report, want string }{
		{"error=linkspan-download", "download the Linkspan release"},
		{"error=workflow", "write the workflow"},
	} {
		t.Run(test.report, func(t *testing.T) {
			ssh, scriptLog, _ := fakeSSH(t)
			t.Setenv("FAKE_PROVISION_FAIL", "1")
			t.Setenv("FAKE_PROVISION_REPORT", test.report)
			service := provisionTestService(t, ssh)
			_, err := service.create(testTunnelContext(), newTestCreateRequest())
			failure := apierr.For(err)
			if failure.Code != "session_provisioning_failed" || !strings.Contains(failure.Message, test.want) {
				t.Fatalf("unexpected refusal: %#v", failure)
			}
			if _, statErr := os.Stat(scriptLog); statErr == nil {
				t.Fatal("a job was submitted to a host that could not be prepared")
			}
		})
	}
}

func TestRetriedCreateAfterProvisioningFailureStartsWithAnEmptyTail(t *testing.T) {
	ssh, _, _ := fakeSSH(t)
	t.Setenv("FAKE_PROVISION_FAIL", "1")
	t.Setenv("FAKE_PROVISION_REPORT", "error=workflow")
	service := provisionTestService(t, ssh)
	request := newTestCreateRequest()
	if _, err := service.create(testTunnelContext(), request); err == nil {
		t.Fatal("expected the first create to fail")
	}

	_ = os.Unsetenv("FAKE_PROVISION_FAIL")
	created, err := service.create(testTunnelContext(), request)
	testutil.Check(t, err)
	if joined := sessionLogText(t, service.Logs, created.ID); strings.Contains(joined, "preparation failed") {
		t.Fatalf("retried create inherited the failed attempt's narration: %s", joined)
	}
}

func TestSecondCreateIsRefusedWhileTheHostIsBeingPrepared(t *testing.T) {
	ssh, scriptLog, _ := fakeSSH(t)
	service := provisionTestService(t, ssh)
	key := service.Runner.Hosts.UserPath + "\x00" + "delta"
	if _, busy := service.HostPreparations.LoadOrStore(key, true); busy {
		t.Fatal("host was already marked as being prepared")
	}
	_, err := service.create(testTunnelContext(), newTestCreateRequest())
	failure := apierr.For(err)
	if failure.Code != "session_provisioning_in_progress" || failure.Status != 409 {
		t.Fatalf("unexpected refusal: %#v", failure)
	}
	if _, statErr := os.Stat(scriptLog); statErr == nil {
		t.Fatal("a job was submitted while the host was still being prepared")
	}
	service.HostPreparations.Delete(key)
	if _, err := service.create(testTunnelContext(), newTestCreateRequest()); err != nil {
		t.Fatalf("create was still refused after preparation ended: %v", err)
	}
}

func TestProvisionScriptGuardsItsArgumentVector(t *testing.T) {
	home := t.TempDir()
	testutil.Check(t, os.MkdirAll(filepath.Join(home, ".local", "bin"), 0o700))
	linkspan := filepath.Join(home, ".local", "bin", "linkspan")
	writeScript(t, linkspan, "#!/bin/sh\ncase \"$1\" in --version) echo v9.9.9;; esac\n")
	workflow := filepath.Join(home, ".cybershuttle", "sessions", "s-012345abcdef", "workflow.yaml")
	document := base64.StdEncoding.EncodeToString([]byte("workflow: yes\n"))

	output, err := runProvisionScript(t, "csctl-provision", home, linkspan, workflow, document)
	if err != nil || !strings.Contains(output, "provision=complete") {
		t.Fatalf("the vector provisionSession sends was refused: %v\n%s", err, output)
	}

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

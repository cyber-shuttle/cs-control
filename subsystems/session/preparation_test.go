// Session preparation tests defend request, path, resource, script, and side-effect boundaries.
// Remote identity and workspace expressions cannot escape their validated forms.
// The generated batch script carries identity but never embeds credentials.
// Failed validation leaves the database, tunnels, capabilities, and Slurm submission untouched.
package session

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cyber-shuttle/cs-plane/internal/security"
	"github.com/cyber-shuttle/cs-plane/internal/ssh"
	"github.com/cyber-shuttle/cs-plane/internal/testutil"
)

func TestDiscoverRejectsUnsafeRemoteUsernameBeforeSacctmgr(t *testing.T) {
	sshBin, _, commandLog := fakeSSH(t)
	t.Setenv("FAKE_REMOTE_USER", "bad;touch")
	service := newTestService(t, ssh.Runner{SSHBin: sshBin, Timeout: 5 * time.Second}, Store{})
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
	if _, err := service.create(testTunnelContext(), request); err == nil || security.For(err).Code != "invalid_root_folder" {
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
		if _, err := service.create(testTunnelContext(), request); err == nil || security.For(err).Code != "invalid_resources" {
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

func runProvisionScript(t *testing.T, arguments ...string) (string, error) {
	t.Helper()
	stubs := t.TempDir()
	testutil.WriteScript(t, filepath.Join(stubs, "curl"), "#!/bin/sh\nexit 1\n")
	command := exec.Command("/bin/sh", append([]string{"-s", "--"}, arguments...)...)
	command.Stdin = strings.NewReader(provisionScript)
	command.Env = append(os.Environ(), "PATH="+stubs+":"+os.Getenv("PATH"))
	output, err := command.CombinedOutput()
	return string(output), err
}

func TestSessionScriptExecsLinkspanWithTheSessionIdentity(t *testing.T) {
	dir := t.TempDir()
	linkspan := filepath.Join(dir, "linkspan")
	argsLog := filepath.Join(dir, "args")
	testutil.WriteScript(t, linkspan, `#!/bin/sh
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
	ports := ports(session.ID, session.Seq)
	command.Env = append(os.Environ(), "HOME="+dir, "ARGS_LOG="+argsLog, "ENV_LOG="+filepath.Join(dir, "env"),
		"JUPYTER_TOKEN="+jupyterToken, "CS_TUNNEL_HOST_TOKEN="+hostToken,
		fmt.Sprintf("CS_CONTROL_PORT=%d", ports.Control),
		"CS_TUNNEL_ID="+tunnelID, "CS_TUNNEL_CLUSTER="+tunnelCluster)
	err := command.Run()
	if exitErr, ok := errors.AsType[*exec.ExitError](err); !ok || exitErr.ExitCode() != 7 {
		t.Fatalf("script did not exec Linkspan or preserve status 7: %v", err)
	}
	for _, required := range []string{hostToken, tunnelID, tunnelCluster, strconv.Itoa(int(ports.Control)), sessionWorkflowPath(session)} {
		if got := string(mustRead(t, argsLog)); !strings.Contains(got, required) {
			t.Fatalf("Linkspan argv missing %q: %q", required, got)
		}
	}
	if got := string(mustRead(t, filepath.Join(dir, "env"))); !strings.Contains(got, jupyterToken) {
		t.Fatalf("Linkspan did not inherit the Jupyter token: %q", got)
	}
}

func TestProvisionScriptGuardsItsArgumentVector(t *testing.T) {
	home := t.TempDir()
	testutil.Check(t, os.MkdirAll(filepath.Join(home, ".local", "bin"), 0o700))
	linkspan := filepath.Join(home, ".local", "bin", "linkspan")
	testutil.WriteScript(t, linkspan, "#!/bin/sh\ncase \"$1\" in --version) echo v9.9.9;; esac\n")
	workflow := filepath.Join(home, ".cybershuttle", "sessions", "s-012345abcdef", "workflow.yaml")
	document := base64.StdEncoding.EncodeToString([]byte("workflow: yes\n"))

	output, err := runProvisionScript(t, "cs-provision", home, linkspan, workflow, document)
	if err != nil || !strings.Contains(output, "provision=complete") {
		t.Fatalf("the vector provisionSession sends was refused: %v\n%s", err, output)
	}

	for _, wrong := range [][]string{
		{"cs-provision", home, linkspan, workflow},
		{"not-cs-provision", home, linkspan, workflow, document},
	} {
		output, err := runProvisionScript(t, wrong...)
		if err == nil || provisionOutcome(output)["error"] != "arguments" {
			t.Fatalf("wrong vector %v was not refused: %v\n%s", wrong, err, output)
		}
	}
}

func TestCreateRevalidatesExactScriptBeforeSubmit(t *testing.T) {
	sshBin, scriptLog, commandLog := fakeSSH(t)
	service := fakeSSHService(t, sshBin)
	configureTestTunnel(t, &service)
	request := newTestCreateRequest()
	request.ID = ""
	validatedResult, err := service.validate(testTunnelContext(), request)
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
	submittedBasename := created.ID + "-" + strconv.Itoa(created.Seq)
	validatedBasename := created.ID + "-0"
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
	sshBin, _, commandLog := fakeSSH(t)
	service := fakeSSHService(t, sshBin)
	store := service.store
	manager := configureTestTunnel(t, &service)
	t.Setenv("FAKE_VALIDATION_FAIL", "1")
	t.Setenv("FAKE_VALIDATION_STDERR", "sbatch: error: rejected")
	_, err := service.create(testTunnelContext(), newTestCreateRequest())
	if security.For(err).Code != "slurm_validation_failed" {
		t.Fatalf("unexpected create error: %v", err)
	}
	testutil.Check(t, store.locked(func(current *state) error {
		if len(current.Sessions) != 0 || len(current.Runs) != 0 {
			t.Fatalf("failed validation persisted state: %#v", current)
		}
		return nil
	}))
	commands, _ := os.ReadFile(commandLog)
	if strings.Contains(string(commands), "--parsable") {
		t.Fatalf("failed validation submitted a job:\n%s", commands)
	}
	if len(manager.creates) != 0 {
		t.Fatalf("failed validation created a tunnel: %#v", manager.creates)
	}
	if entries, err := os.ReadDir(service.capabilityDir); err == nil && len(entries) != 0 {
		t.Fatalf("failed validation wrote capabilities: %#v", entries)
	} else if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
}

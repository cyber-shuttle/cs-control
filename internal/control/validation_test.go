package control

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/cyber-shuttle/cs-control/internal/apierr"
	"github.com/cyber-shuttle/cs-control/internal/sshexec"
)

func TestBuildScriptRunsLinkspanAndNamesNoApplication(t *testing.T) {
	runtime := Runtime{
		RuntimeResponse: RuntimeResponse{ID: "rt-012345abcdef", Partition: "cpu", Resources: Resources{Cores: 4, MemoryMB: 4096, WallMinutes: 60}},
		JobName:         "cs-rt-012345abcdef", PrivateRoot: "/home/test/.cybershuttle/runtimes/rt-012345abcdef", WorkspaceRoot: "/home/test/project",
	}
	script := buildScript(runtime, "/opt/linkspan")
	for _, required := range []string{
		"LINKSPAN_BIN='/opt/linkspan'",
		`exec "$LINKSPAN_BIN" --port`,
		"--workflow '/home/test/.cybershuttle/runtimes/rt-012345abcdef/workflow.yaml'",
	} {
		if !strings.Contains(script, required) {
			t.Errorf("allocation script is missing %q:\n%s", required, script)
		}
	}
	// The allocation runs Linkspan. What runs inside it is the workflow's
	// business, so nothing here knows an application by name.
	for _, forbidden := range []string{"jupyter", "python", "--managed-jupyter", "--runtime-id", "--ready-file", "--api-token-file"} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("allocation Slurm script names %q:\n%s", forbidden, script)
		}
	}
}

// The workflow asks Linkspan for the server on the port this control plane
// declared, and carries no secret: the token is the environment's to supply.
func TestRuntimeWorkflowStartsJupyterWithoutSecrets(t *testing.T) {
	runtime := Runtime{
		RuntimeResponse: RuntimeResponse{ID: "rt-012345abcdef", Generation: "g-0123456789abcdef"},
		PrivateRoot:     "/home/test/.cybershuttle/runtimes/rt-012345abcdef", WorkspaceRoot: "/home/test/project",
	}
	document := runtimeWorkflow(runtime)
	port := strconv.Itoa(int(allocationPorts(runtime.ID, runtime.Generation).jupyter))
	for _, required := range []string{
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

func TestCreateRevalidatesExactScriptBeforeSubmit(t *testing.T) {
	ssh, scriptLog, commandLog := fakeSSH(t)
	service := Service{Runner: sshexec.Runner{SSHBin: ssh}, Store: Store{Dir: t.TempDir()}, Config: Config{LinkspanPath: "/opt/cybershuttle/linkspan"}}
	configureTestTunnel(t, &service)
	request := createRequest()
	request.ID = ""
	validatedResult, err := service.Validate(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.Create(testTunnelContext(), request)
	if err != nil {
		t.Fatal(err)
	}
	if created.ID != validatedResult.RuntimeID {
		t.Fatalf("validated runtime ID %q differs from created ID %q", validatedResult.RuntimeID, created.ID)
	}
	submitted, err := os.ReadFile(scriptLog)
	if err != nil || string(submitted) != validatedResult.Script {
		t.Fatalf("submitted script differs from validation: %v", err)
	}
	validated, err := os.ReadFile(filepath.Join(filepath.Dir(scriptLog), "validation-script"))
	if err != nil || string(validated) != string(submitted) {
		t.Fatalf("create validation differs from submission: %v", err)
	}
	commands, _ := os.ReadFile(commandLog)
	if strings.Count(string(commands), "'sbatch' '--test-only'") != 2 || strings.Count(string(commands), "'sbatch' '--job-name=") != 1 {
		t.Fatalf("expected validation, create revalidation, then one submit:\n%s", commands)
	}
}

func TestCreateValidationFailureDoesNotPersistOrSubmit(t *testing.T) {
	ssh, _, commandLog := fakeSSH(t)
	store := Store{Dir: t.TempDir()}
	service := Service{Runner: sshexec.Runner{SSHBin: ssh}, Store: store, Config: Config{LinkspanPath: "/opt/cybershuttle/linkspan"}}
	t.Setenv("FAKE_VALIDATION_FAIL", "1")
	t.Setenv("FAKE_VALIDATION_STDERR", "sbatch: error: rejected")
	_, err := service.Create(testTunnelContext(), createRequest())
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

// One configured Linkspan path has to serve hosts whose accounts do not share a
// home, so an anchored path is accepted and resolved against the host's own.
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

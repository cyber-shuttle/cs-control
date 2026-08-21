package control

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cyber-shuttle/cs-control/internal/apierr"
	"github.com/cyber-shuttle/cs-control/internal/sshexec"
)

func TestBuildScriptStartsJupyterThenHostsTheTunnel(t *testing.T) {
	runtime := Runtime{
		RuntimeResponse: RuntimeResponse{ID: "rt-012345abcdef", Partition: "cpu", Resources: Resources{Cores: 4, MemoryMB: 4096, WallMinutes: 60}},
		JobName:         "cs-rt-012345abcdef", PrivateRoot: "/home/test/.cybershuttle/runtimes/rt-012345abcdef", WorkspaceRoot: "/home/test/project",
	}
	script := buildScript(runtime, "/opt/linkspan")
	for _, required := range []string{
		"LINKSPAN_BIN='/opt/linkspan'",
		"JUPYTER_PYTHON='/home/test/project/.cybershuttle/jupyter-env/bin/python'",
		`--ServerApp.root_dir='/home/test/project'`,
		`exec "$LINKSPAN_BIN" --port`,
	} {
		if !strings.Contains(script, required) {
			t.Errorf("allocation script is missing %q:\n%s", required, script)
		}
	}
	// Jupyter must be backgrounded before Linkspan takes over the shell, or the relay never starts.
	if strings.Index(script, "jupyter_server") > strings.Index(script, `exec "$LINKSPAN_BIN"`) {
		t.Fatalf("Jupyter must start before Linkspan execs:\n%s", script)
	}
	for _, forbidden := range []string{"allocation \"$CS_LINKSPAN_TRANSPORT\"", "--managed-jupyter", "--runtime-id", "--ready-file", "--api-token-file"} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("allocation Slurm script contains obsolete surface %q:\n%s", forbidden, script)
		}
	}
}

// The script a caller reads before validation is the one Slurm is then asked
// about, and asking for it runs no sbatch at all.
func TestScriptPreviewMatchesValidationAndRunsNoSbatch(t *testing.T) {
	ssh, _, _, commandLog := fakeSSH(t)
	service := Service{Runner: sshexec.Runner{SSHBin: ssh}, Store: Store{Dir: t.TempDir()}, Config: Config{LinkspanPath: "/opt/cybershuttle/linkspan"}}
	request := createRequest()
	preview, err := service.Script(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if commands, _ := os.ReadFile(commandLog); strings.Contains(string(commands), "sbatch") {
		t.Fatalf("script preview reached sbatch:\n%s", commands)
	}
	validated, err := service.Validate(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if preview.Script != validated.Script || preview.RuntimeID != validated.RuntimeID {
		t.Fatalf("preview differs from what was validated:\n%s\n%s", preview.Script, validated.Script)
	}
}

func TestCreateRevalidatesExactScriptBeforeSubmit(t *testing.T) {
	ssh, _, scriptLog, commandLog := fakeSSH(t)
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
	if strings.Count(string(commands), "'sbatch' '--test-only'") != 2 || strings.Count(string(commands), "'sbatch' '--export=ALL,CS_JUPYTER_TOKEN=") != 1 {
		t.Fatalf("expected validation, create revalidation, then one submit:\n%s", commands)
	}
}

func TestCreateValidationFailureDoesNotPersistOrSubmit(t *testing.T) {
	ssh, _, _, commandLog := fakeSSH(t)
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

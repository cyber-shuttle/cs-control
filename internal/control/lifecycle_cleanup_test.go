package control

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cyber-shuttle/cs-control/internal/sshexec"
)

func TestRuntimeScriptTakesBothCredentialsFromTheEnvironment(t *testing.T) {
	dir := t.TempDir()
	linkspan := filepath.Join(dir, "linkspan")
	argsLog := filepath.Join(dir, "args")
	// Wait for the backgrounded Jupyter stub so the assertions below are not racing it.
	if err := os.WriteFile(linkspan, []byte(`#!/bin/sh
printf '%s\n' "$@" > "$ARGS_LOG"
i=0; while [ ! -s "$JUPYTER_LOG" ] && [ $i -lt 200 ]; do sleep .01; i=$((i+1)); done
exit 7
`), 0o700); err != nil {
		t.Fatal(err)
	}
	python := filepath.Join(dir, "python")
	if err := os.WriteFile(python, []byte("#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$JUPYTER_LOG\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	runtime := Runtime{
		RuntimeResponse: RuntimeResponse{ID: "rt-012345abcdef", Generation: "g-0123456789abcdef", Partition: "cpu", Resources: Resources{Cores: 1, MemoryMB: 128, WallMinutes: 1}},
		JobName:         jobName("rt-012345abcdef"), WorkspaceRoot: dir,
	}
	script := buildScript(runtime, linkspan)
	const jupyterToken, hostToken = "jupyter-secret", "host-secret"
	for _, secret := range []string{jupyterToken, hostToken} {
		if strings.Contains(script, secret) {
			t.Fatalf("allocation script contains a secret literal:\n%s", script)
		}
	}
	// Point JUPYTER_PYTHON at the stub: the real path is derived, not injectable.
	script = strings.Replace(script, "JUPYTER_PYTHON="+sshexec.ShellQuote(jupyterPython(runtime)), "JUPYTER_PYTHON="+sshexec.ShellQuote(python), 1)
	command := exec.Command("bash")
	command.Stdin = strings.NewReader(script)
	command.Env = append(os.Environ(), "HOME="+dir, "ARGS_LOG="+argsLog,
		"JUPYTER_LOG="+filepath.Join(dir, "jupyter"), "CS_JUPYTER_TOKEN="+jupyterToken, "CS_TUNNEL_HOST_TOKEN="+hostToken)
	if err := command.Run(); err == nil || err.(*exec.ExitError).ExitCode() != 7 {
		t.Fatalf("script did not exec Linkspan or preserve status 7: %v", err)
	}
	if got := string(mustRead(t, argsLog)); !strings.Contains(got, hostToken) || strings.Contains(got, "allocation") {
		t.Fatalf("Linkspan argv = %q", got)
	}
	if got := string(mustRead(t, filepath.Join(dir, "jupyter"))); !strings.Contains(got, jupyterToken) {
		t.Fatalf("Jupyter argv did not receive the environment token: %q", got)
	}
}

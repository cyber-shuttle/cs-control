package control

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestRuntimeScriptExecsLinkspanWithTheAllocationIdentity(t *testing.T) {
	dir := t.TempDir()
	linkspan := filepath.Join(dir, "linkspan")
	argsLog := filepath.Join(dir, "args")
	if err := os.WriteFile(linkspan, []byte(`#!/bin/sh
printf '%s\n' "$@" > "$ARGS_LOG"
printf '%s\n' "$JUPYTER_TOKEN" "$JUPYTER_PORT" > "$ENV_LOG"
exit 7
`), 0o700); err != nil {
		t.Fatal(err)
	}
	runtime := Runtime{
		RuntimeResponse: RuntimeResponse{ID: "rt-012345abcdef", Generation: "g-0123456789abcdef", Partition: "cpu", Resources: Resources{Cores: 1, MemoryMB: 128, WallMinutes: 1}},
		JobName:         jobName("rt-012345abcdef"), PrivateRoot: dir + "/private", WorkspaceRoot: dir,
	}
	script := buildScript(runtime, linkspan)
	const jupyterToken, hostToken = "jupyter-secret", "host-secret"
	for _, secret := range []string{jupyterToken, hostToken} {
		if strings.Contains(script, secret) {
			t.Fatalf("allocation script contains a secret literal:\n%s", script)
		}
	}
	command := exec.Command("bash")
	command.Stdin = strings.NewReader(script)
	const tunnelID, tunnelCluster = "rt-012345abcdef-g-0123456789abcdef", "usw3"
	ports := allocationPorts(runtime.ID, runtime.Generation)
	command.Env = append(os.Environ(), "HOME="+dir, "ARGS_LOG="+argsLog, "ENV_LOG="+filepath.Join(dir, "env"),
		"JUPYTER_TOKEN="+jupyterToken, "CS_TUNNEL_HOST_TOKEN="+hostToken,
		fmt.Sprintf("JUPYTER_PORT=%d", ports.jupyter), fmt.Sprintf("CS_CONTROL_PORT=%d", ports.control),
		"CS_TUNNEL_ID="+tunnelID, "CS_TUNNEL_CLUSTER="+tunnelCluster)
	if err := command.Run(); err == nil || err.(*exec.ExitError).ExitCode() != 7 {
		t.Fatalf("script did not exec Linkspan or preserve status 7: %v", err)
	}
	// An empty --tunnel-id makes Linkspan refuse the host token and the job dies
	// on startup, so the identity has to survive the environment hand-off, and
	// the workflow it is told to run has to arrive with it.
	for _, required := range []string{hostToken, tunnelID, tunnelCluster, strconv.Itoa(int(ports.control)), runtimeWorkflowPath(runtime)} {
		if got := string(mustRead(t, argsLog)); !strings.Contains(got, required) {
			t.Fatalf("Linkspan argv missing %q: %q", required, got)
		}
	}
	// Linkspan inherits what Jupyter Server reads for itself, so the workflow
	// never names the token or the port.
	got := string(mustRead(t, filepath.Join(dir, "env")))
	if !strings.Contains(got, jupyterToken) || !strings.Contains(got, strconv.Itoa(int(ports.jupyter))) {
		t.Fatalf("Linkspan did not inherit the Jupyter environment: %q", got)
	}
}

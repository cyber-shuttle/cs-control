// The batch script and the workflow it points Linkspan at. Both name no secret.
//
//	Test*
package control

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestSessionWorkflowStartsJupyterWithoutSecrets(t *testing.T) {
	session := Session{
		sessionResponse: sessionResponse{ID: "s-012345abcdef", Generation: "g-0123456789abcdef"},
		PrivateRoot:     "/home/test/.cybershuttle/sessions/s-012345abcdef", WorkspaceRoot: "/home/test/project",
	}
	document := sessionWorkflow(session)
	port := strconv.Itoa(int(sessionPorts(session.ID, session.Generation).jupyter))
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
		sessionResponse: sessionResponse{ID: "s-012345abcdef", Generation: "g-0123456789abcdef", Partition: "cpu", Resources: resources{Cores: 1, MemoryMB: 128, WallMinutes: 1}},
		JobName:         jobName("s-012345abcdef", "g-0123456789abcdef"), PrivateRoot: dir + "/private", WorkspaceRoot: dir,
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
	ports := sessionPorts(session.ID, session.Generation)
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

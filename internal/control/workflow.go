package control

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/cyber-shuttle/cs-control/internal/apierr"
	"github.com/cyber-shuttle/cs-control/internal/sshexec"
)

// The allocation runs Linkspan; Linkspan runs this. Everything an allocation is
// for lives here rather than in the batch script, which names no application:
// the environment is built, its dependencies are installed, the server is
// started, and nothing calls the runtime usable until the server answers.
//
// shell.exec runs each command without a shell, splits it on whitespace, and
// expands nothing, so every path is a validated remote path, every port is the
// one this runtime was given, and the token Jupyter Server needs reaches it
// through the environment Linkspan inherits from the job.
func runtimeWorkflow(runtime Runtime) string {
	uv := strings.TrimSuffix(runtime.HomeDir, "/") + "/.local/bin/uv"
	env := jupyterEnvironment(runtime.HomeDir)
	python := jupyterPython(runtime)
	port := strconv.Itoa(int(allocationPorts(runtime.ID, runtime.Generation).jupyter))
	steps := []struct{ name, command string }{
		{"Create the Python environment", strings.Join([]string{
			uv, "venv", "--quiet", "--allow-existing", "--python", provisionPythonVersion, env}, " ")},
		{"Install the server", strings.Join([]string{
			uv, "pip", "install", "--quiet", "--python", python,
			"jupyter-server", "ipykernel", "jupyter-server-terminals"}, " ")},
		// setsid returns as soon as it has forked, so the server outlives this
		// step and the step after it can wait for the server rather than for it.
		{"Start Jupyter Server", strings.Join([]string{
			"setsid", "--fork", python, "-m", "jupyter_server",
			"--no-browser", "--ip=127.0.0.1",
			"--ServerApp.root_dir=" + runtime.WorkspaceRoot,
			"--ServerApp.allow_origin=*"}, " ")},
		// An answer of any kind means the server is listening; which answer it
		// is depends on a token this file is not allowed to hold.
		{"Wait for Jupyter Server", strings.Join([]string{
			"curl", "--silent", "--show-error", "--output", "/dev/null",
			"--retry", "90", "--retry-delay", "2", "--retry-connrefused",
			"--max-time", "10", "http://127.0.0.1:" + port + "/api/status"}, " ")},
	}
	document := []string{"name: cs-runtime", "steps:"}
	for _, step := range steps {
		document = append(document,
			"  - action: shell.exec",
			"    name: "+step.name,
			"    params:",
			"      command: "+fmt.Sprintf("%q", step.command))
	}
	return strings.Join(append(document, ""), "\n")
}

func runtimeWorkflowPath(runtime Runtime) string {
	return strings.TrimSuffix(runtime.PrivateRoot, "/") + "/workflow.yaml"
}

// workflowInstallScript is intentionally constant. The destination arrives as an
// argument and the document on standard input, so nothing is interpolated into
// the remote shell program.
const workflowInstallScript = `set -eu
[ "$#" -eq 2 ]
[ "$1" = csctl-runtime-workflow ]
shift
path=$1
case "$path" in /*) ;; *) exit 70 ;; esac
umask 077
install -d -m 700 "$(dirname "$path")"
staged="$path.staged"
cat > "$staged"
[ -s "$staged" ] || { rm -f "$staged"; exit 71; }
mv -f "$staged" "$path"
`

// installRuntimeWorkflow puts the workflow where the reviewed script says
// Linkspan will look for it. It carries no secret, so it is a file rather than
// an environment variable.
func (s Service) installRuntimeWorkflow(ctx context.Context, alias string, runtime Runtime) error {
	ctx, cancel := context.WithTimeout(ctx, s.Runner.EffectiveTimeout())
	defer cancel()
	remote := strings.Join([]string{
		sshexec.ShellQuote("sh"), sshexec.ShellQuote("-s"), sshexec.ShellQuote("--"),
		sshexec.ShellQuote("csctl-runtime-workflow"), sshexec.ShellQuote(runtimeWorkflowPath(runtime)),
	}, " ")
	cmd, err := s.Runner.Command(ctx, alias, remote)
	if err != nil {
		return err
	}
	cmd.Stdin = strings.NewReader(runtimeWorkflow(runtime))
	if _, errText, runErr := sshexec.RunBounded(ctx, cmd); runErr != nil {
		message := strings.TrimSpace(errText)
		if message == "" {
			message = runErr.Error()
		}
		return apierr.New("runtime_provisioning_failed", "Installing the runtime workflow on "+alias+" failed: "+message, http.StatusBadGateway)
	}
	return nil
}

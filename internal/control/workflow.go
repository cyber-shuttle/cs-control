package control

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/cyber-shuttle/cs-control/internal/apierr"
	"github.com/cyber-shuttle/cs-control/internal/sshexec"
)

// The allocation runs Linkspan; Linkspan runs this. Everything an allocation is
// for lives here rather than in the batch script, which names no application.
//
// Linkspan starts the workflow once its listener is bound, so the server below
// comes up behind a Linkspan that is already live. shell.exec runs without a
// shell and splits on whitespace, and it expands nothing: every path here is a
// validated remote path, and the token and port Jupyter Server needs reach it
// through the environment Linkspan inherits from the job.
func runtimeWorkflow(runtime Runtime) string {
	command := strings.Join([]string{
		jupyterPython(runtime), "-m", "jupyter_server",
		"--no-browser", "--ip=127.0.0.1",
		"--ServerApp.root_dir=" + runtime.WorkspaceRoot,
		"--ServerApp.allow_origin=*",
	}, " ")
	return strings.Join([]string{
		"name: cs-runtime",
		"steps:",
		"  - action: shell.exec",
		"    name: Start Jupyter Server",
		"    params:",
		"      command: " + fmt.Sprintf("%q", command),
		"",
	}, "\n")
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

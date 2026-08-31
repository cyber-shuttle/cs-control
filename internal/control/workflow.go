package control

import (
	"fmt"
	"strconv"
	"strings"
)

// The allocation runs Linkspan; Linkspan runs this. Everything an allocation is
// for lives here rather than in the batch script, which names no application.
//
// shell.exec runs each command without a shell, splits on whitespace and expands
// nothing, so every path here is a validated remote path and the token Jupyter
// Server needs reaches it through the environment Linkspan inherits.
func runtimeWorkflow(runtime Runtime, home string) string {
	uv := strings.TrimSuffix(home, "/") + "/.local/bin/uv"
	env := jupyterEnvironment(home)
	// One account, one environment, beside the binary the job execs: a workspace
	// chooses what a server opens, not what runs it.
	python := env + "/bin/python"
	port := strconv.Itoa(int(allocationPorts(runtime.ID, runtime.Generation).jupyter))
	steps := []struct{ name, command string }{
		{"Create the Python environment", strings.Join([]string{
			uv, "venv", "--quiet", "--allow-existing", "--python", provisionPythonVersion, env}, " ")},
		{"Install the server", strings.Join([]string{
			uv, "pip", "install", "--quiet", "--python", python,
			"jupyter-server", "ipykernel", "jupyter-server-terminals"}, " ")},
		// setsid returns once forked, so the server outlives this step and the
		// next step waits on the server rather than on this.
		{"Start Jupyter Server", strings.Join([]string{
			"setsid", "--fork", python, "-m", "jupyter_server",
			"--no-browser", "--ip=127.0.0.1",
			"--ServerApp.root_dir=" + runtime.WorkspaceRoot,
			"--ServerApp.allow_origin=*"}, " ")},
		// Any answer means the server is listening; which one depends on a token
		// this file may not hold.
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

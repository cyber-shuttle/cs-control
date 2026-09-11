package control

import (
	"fmt"
	"strconv"
	"strings"
)

// The allocation runs Linkspan; Linkspan runs this. Everything an allocation is
// for lives here rather than in the batch script, which names no application.
//
// One step: Linkspan builds its environment, starts Jupyter Server on the port
// this control plane declared on the tunnel, and publishes it. The token reaches
// the server through JUPYTER_TOKEN in the environment Linkspan inherits, so
// nothing secret is written down.
func runtimeWorkflow(runtime Runtime) string {
	port := strconv.Itoa(int(allocationPorts(runtime.ID, runtime.Generation).jupyter))
	return strings.Join([]string{
		"name: cs-runtime",
		"steps:",
		"  - action: jupyter.sessions.start",
		"    name: Start Jupyter Server",
		"    params:",
		"      root_dir: " + fmt.Sprintf("%q", runtime.WorkspaceRoot),
		"      addr: " + fmt.Sprintf("%q", "127.0.0.1:"+port),
		"",
	}, "\n")
}

func runtimeWorkflowPath(runtime Runtime) string {
	return strings.TrimSuffix(runtime.PrivateRoot, "/") + "/workflow.yaml"
}

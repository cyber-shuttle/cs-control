package control

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cyber-shuttle/cs-control/internal/sshconfig"
	"github.com/cyber-shuttle/cs-control/internal/sshexec"
)

// Runs the provisioning script on a real host. A fake ssh never executes it, so
// nothing else can catch what only a shell finds: argument order, quoting, or a
// release that does not extract. Off by default; LIVE_SSH_ALIAS names a host
// this machine can already reach and LIVE_PROVISION_ROOT an absolute directory
// the run may create and the caller may delete.
func TestLiveProvisionPreparesABareHost(t *testing.T) {
	alias, root := os.Getenv("LIVE_SSH_ALIAS"), os.Getenv("LIVE_PROVISION_ROOT")
	if alias == "" || root == "" {
		t.Skip("set LIVE_SSH_ALIAS and LIVE_PROVISION_ROOT to run")
	}
	home, _ := os.UserHomeDir()
	service := Service{
		Runner: sshexec.Runner{
			Hosts:      sshconfig.Config{UserPath: filepath.Join(home, ".ssh", "config"), SystemPath: "/etc/ssh/ssh_config"},
			ControlDir: t.TempDir(),
			Timeout:    30 * time.Second,
		},
		Logs: NewRuntimeLogs(),
	}
	runtime := Runtime{
		RuntimeResponse: RuntimeResponse{ID: "rt-0123456789ab", Generation: "g-0123456789abcdef"},
		PrivateRoot:     root + "/private", WorkspaceRoot: root,
	}
	linkspan := root + "/bin/linkspan"
	if err := service.provisionRuntime(context.Background(), alias, runtime, root, linkspan); err != nil {
		t.Fatalf("bare host was not prepared: %v", err)
	}
	// Again: what is already there is left alone rather than rebuilt.
	if err := service.provisionRuntime(context.Background(), alias, runtime, root, linkspan); err != nil {
		t.Fatalf("prepared host was not left alone: %v", err)
	}
	if said := runtimeLogText(t, service.Logs, runtime.ID, false); strings.Count(said, "Runtime environment ready") != 2 {
		t.Fatalf("status did not report readiness twice: %v", said)
	}
}

// Drives a real host, skipped unless LIVE_SSH_ALIAS and LIVE_PROVISION_ROOT opt in.
// Only a real shell can catch argument order, quoting, or a release that fails to extract.
//
//	Test*
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

func TestLiveProvisionPreparesABareHost(t *testing.T) {
	alias, root := os.Getenv("LIVE_SSH_ALIAS"), os.Getenv("LIVE_PROVISION_ROOT")
	if alias == "" || root == "" {
		t.Skip("set LIVE_SSH_ALIAS and LIVE_PROVISION_ROOT to run")
	}
	home, _ := os.UserHomeDir()
	service := Service{
		Runner: sshexec.Runner{
			Hosts:            sshconfig.Config{UserPath: filepath.Join(home, ".ssh", "config")},
			ControlNamespace: t.TempDir(),
			Timeout:          30 * time.Second,
		},
		Logs:    NewSessionLogs(),
		Metrics: NewSessionMetrics(),
	}
	session := Session{
		sessionResponse: sessionResponse{ID: "s-0123456789ab", Generation: "g-0123456789abcdef"},
		PrivateRoot:     root + "/private", WorkspaceRoot: root,
	}
	linkspan := root + "/bin/linkspan"
	if err := service.provisionSession(context.Background(), alias, session, root, linkspan); err != nil {
		t.Fatalf("bare host was not prepared: %v", err)
	}
	if err := service.provisionSession(context.Background(), alias, session, root, linkspan); err != nil {
		t.Fatalf("prepared host was not left alone: %v", err)
	}
	if said := sessionLogText(t, service.Logs, session.ID); strings.Count(said, "Session environment ready") != 2 {
		t.Fatalf("status did not report readiness twice: %v", said)
	}
}

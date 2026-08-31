package gateway

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cyber-shuttle/cs-control/internal/sshconfig"
	"github.com/cyber-shuttle/cs-control/internal/sshexec"
	"github.com/gorilla/websocket"
)

// Runs the real gateway against real OpenSSH. Off by default: it needs a host
// this machine can already reach.
func TestLiveRealOpenSSHReachesReady(t *testing.T) {
	alias := os.Getenv("LIVE_SSH_ALIAS")
	if alias == "" {
		t.Skip("set LIVE_SSH_ALIAS to run")
	}
	home, _ := os.UserHomeDir()
	runner := sshexec.Runner{
		Hosts:      sshconfig.Config{UserPath: home + "/.ssh/config", SystemPath: "/etc/ssh/ssh_config"},
		ControlDir: t.TempDir(),
		Timeout:    30 * time.Second,
	}
	manager := NewSSHAuthManager(runner)
	defer manager.Close()
	server := httptest.NewServer(serveSSHRoute(manager))
	defer server.Close()

	connection := dialAuthAlias(t, server.URL, alias)
	defer connection.Close()
	deadline := time.Now().Add(60 * time.Second)
	ready := false
	for time.Now().Before(deadline) {
		_ = connection.SetReadDeadline(deadline)
		frame := readAuthServerFrame(t, connection)
		t.Logf("frame: %#v", frame)
		if frame.Type == "ready" {
			ready = true
		}
		if frame.Type == "exit" {
			if !ready || frame.Code == nil || *frame.Code != 0 {
				t.Fatalf("live login failed: ready=%v frame=%#v", ready, frame)
			}
			return
		}
	}
	t.Fatal("no readiness before the deadline")
}

func dialAuthAlias(t *testing.T, serverURL, alias string) *websocket.Conn {
	t.Helper()
	header := http.Header{"Authorization": {"Bearer service-token-service-token-1234"}, "Origin": {serverURL}}
	url := "ws" + strings.TrimPrefix(serverURL, "http") + "/api/v1/ssh/" + alias + "/auth"
	connection, response, err := websocket.DefaultDialer.Dial(url, header)
	if err != nil {
		t.Fatalf("open auth websocket: %v (%v)", err, response)
	}
	return connection
}

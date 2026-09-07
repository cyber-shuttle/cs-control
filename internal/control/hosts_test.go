package control

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cyber-shuttle/cs-control/internal/sshexec"
)

func sshRefusingAuthentication(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "ssh")
	script := `#!/bin/sh
if [ "$1" = "-G" ]; then
  printf 'host %s\nhostname %s.example\nuser tester\nport 22\n' "$2" "$2"
  exit 0
fi
echo "tester@delta: Permission denied (publickey,keyboard-interactive)." >&2
exit 255
`
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestHostTestReportsAnOwedLoginAsOKFalseWithoutFailingTheCall(t *testing.T) {
	service := Service{Runner: sshexec.Runner{SSHBin: sshRefusingAuthentication(t), Timeout: 5 * time.Second}}

	result, err := service.TestHost(context.Background(), "delta")

	if err != nil {
		t.Fatalf("a host that only owes a login is a reportable state, not a failed call: %v", err)
	}
	if result.OK {
		t.Error("a host that refused authentication reported ok")
	}
	if !strings.Contains(result.Message, "interactive login") {
		t.Errorf("got %q, want the interactive-login guidance", result.Message)
	}
}

package sshexec

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRunRemoteArgsRejectsUnsafeArguments(t *testing.T) {
	runner := Runner{SSHBin: filepath.Join(t.TempDir(), "unused"), Timeout: time.Second}
	for _, argument := range []string{"", "line\nfeed", "carriage\rreturn", "nul\x00byte"} {
		if _, err := runner.Run(context.Background(), "delta", nil, "command", argument); err == nil {
			t.Fatalf("accepted unsafe argument %q", argument)
		}
	}
}

func TestRunRemoteArgsBoundsCombinedOutput(t *testing.T) {
	output := &Output{remaining: MaxOutput}
	stdout := &commandStream{output: output, name: "stdout"}
	stderr := &commandStream{output: output, name: "stderr"}
	if _, err := stdout.Write(make([]byte, MaxOutput)); err != nil {
		t.Fatal(err)
	}
	if _, err := stderr.Write([]byte("x")); err == nil || !strings.Contains(err.Error(), "output exceeded limit") {
		t.Fatalf("oversized combined remote output error = %v", err)
	}
}

// An interactive master must be the foreground process the gateway owns and
// reaps. ControlPersist backgrounds it instead: OpenSSH returns 0 as soon as it
// authenticates, which the gateway can only read as an exit before readiness.
func TestInteractiveMasterIsNotBackgrounded(t *testing.T) {
	runner := Runner{SSHBin: filepath.Join(t.TempDir(), "unused"), ControlDir: t.TempDir(), Timeout: time.Second}
	for _, test := range []struct {
		interactive bool
		persist     string
		batch       string
	}{{true, "ControlPersist=no", "BatchMode=no"}, {false, "ControlPersist=600", "BatchMode=yes"}} {
		args, err := runner.sshArgs("delta", test.interactive, "identity\n")
		if err != nil {
			t.Fatal(err)
		}
		joined := strings.Join(args, " ")
		if !strings.Contains(joined, test.persist) || !strings.Contains(joined, test.batch) {
			t.Fatalf("interactive=%v produced %q", test.interactive, joined)
		}
	}
}

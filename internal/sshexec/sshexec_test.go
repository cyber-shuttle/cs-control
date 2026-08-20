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

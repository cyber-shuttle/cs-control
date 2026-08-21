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

func TestReadRemoteRuntimeTailsUsesFixedArgumentsAndParsesStreams(t *testing.T) {
	ssh, _, _, commandLog := fakeSSH(t)
	scriptLog := filepath.Join(t.TempDir(), "runtime-tail-script")
	t.Setenv("FAKE_RUNTIME_LOG_SCRIPT", scriptLog)
	t.Setenv("FAKE_RUNTIME_STDOUT", "first\n\x1b[31msecond\x1b[0m\n")
	t.Setenv("FAKE_RUNTIME_STDERR", "warning\rnext\n")
	service := Service{
		Runner: sshexec.Runner{SSHBin: ssh, Timeout: 5 * time.Second, ControlDir: filepath.Join(t.TempDir(), "masters")},
		Logs:   NewRuntimeLogs(),
	}

	tails, err := service.readRemoteRuntimeTails(context.Background(), "alpha", []string{runtimeLogIDOne, runtimeLogIDTwo})
	if err != nil {
		t.Fatal(err)
	}
	if tails[runtimeLogIDOne].stdout != "first\n\x1b[31msecond\x1b[0m\n" || tails[runtimeLogIDTwo].stderr != "warning\rnext\n" {
		t.Fatalf("parsed tails = %#v", tails)
	}
	remoteScript, err := os.ReadFile(scriptLog)
	if err != nil {
		t.Fatal(err)
	}
	if string(remoteScript) != runtimeLogTailScript || strings.Contains(string(remoteScript), runtimeLogIDOne) {
		t.Fatal("remote script was not the constant runtime tail script")
	}
	commands, err := os.ReadFile(commandLog)
	if err != nil {
		t.Fatal(err)
	}
	command := string(commands)
	for _, want := range []string{"'sh' '-s' '--' 'csctl-runtime-log-tail'", "'" + runtimeLogIDOne + "'", "'" + runtimeLogIDTwo + "'"} {
		if !strings.Contains(command, want) {
			t.Errorf("fixed remote command missing %q: %s", want, command)
		}
	}
	args, err := service.Runner.Args(context.Background(), "alpha", false)
	if err != nil {
		t.Fatal(err)
	}
	joinedArgs := strings.Join(args, " ")
	for _, want := range []string{"ControlMaster=auto", "ControlPersist=600", "ControlPath="} {
		if !strings.Contains(joinedArgs, want) {
			t.Errorf("tail SSH arguments missing %q: %s", want, joinedArgs)
		}
	}
}

func TestCollectStartingRuntimeLogsOneReadPerHostFourRuntimeCapAndTerminalStop(t *testing.T) {
	ssh, _, _, commandLog := fakeSSH(t)
	t.Setenv("FAKE_RUNTIME_STDOUT", "hello\n")
	t.Setenv("FAKE_RUNTIME_STDERR", "\x1b[31mwarning\x1b[0m\n")
	service := Service{Runner: sshexec.Runner{SSHBin: ssh, Timeout: 5 * time.Second}, Logs: NewRuntimeLogs()}
	runtimes := []Runtime{
		{RuntimeResponse: RuntimeResponse{ID: "rt-000000000001", SSHHost: "alpha", State: "STARTING"}},
		{RuntimeResponse: RuntimeResponse{ID: "rt-000000000002", SSHHost: "alpha", State: "STARTING"}},
		{RuntimeResponse: RuntimeResponse{ID: "rt-000000000003", SSHHost: "alpha", State: "STARTING"}},
		{RuntimeResponse: RuntimeResponse{ID: "rt-000000000004", SSHHost: "alpha", State: "STARTING"}},
		{RuntimeResponse: RuntimeResponse{ID: "rt-000000000005", SSHHost: "alpha", State: "STARTING"}},
		{RuntimeResponse: RuntimeResponse{ID: "rt-000000000006", SSHHost: "alpha", State: "READY"}},
		{RuntimeResponse: RuntimeResponse{ID: "rt-000000000007", SSHHost: "alpha", State: "FAILED"}},
	}
	service.collectStartingRuntimeLogs(context.Background(), runtimes)

	commands, err := os.ReadFile(commandLog)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(commands)), "\n")
	if len(lines) != 1 || !strings.Contains(lines[0], "csctl-runtime-log-tail") {
		t.Fatalf("tail reads = %q, want one host read", lines)
	}
	for _, id := range []string{"rt-000000000001", "rt-000000000002", "rt-000000000003", "rt-000000000004"} {
		if !strings.Contains(lines[0], id) {
			t.Errorf("capped read missing %s: %s", id, lines[0])
		}
		tail, ok := service.Logs.Tail(id)
		if !ok || len(tail.Lines) != 2 || !sameLogLine(tail.Lines[0], "stdout", "hello") || !sameLogLine(tail.Lines[1], "stderr", "warning") {
			t.Errorf("merged sanitized tail for %s = %#v", id, tail)
		}
	}
	for _, id := range []string{"rt-000000000005", "rt-000000000006", "rt-000000000007"} {
		if strings.Contains(lines[0], id) {
			t.Errorf("ineligible runtime %s was tailed: %s", id, lines[0])
		}
	}

	before := string(commands)
	service.collectStartingRuntimeLogs(context.Background(), []Runtime{
		{RuntimeResponse: RuntimeResponse{ID: runtimeLogIDOne, SSHHost: "alpha", State: "READY"}},
		{RuntimeResponse: RuntimeResponse{ID: runtimeLogIDTwo, SSHHost: "alpha", State: "STOPPED"}},
	})
	after, err := os.ReadFile(commandLog)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != before {
		t.Fatalf("terminal collection issued SSH: before=%q after=%q", before, after)
	}
}

func TestRuntimeLogsMergeRemoteReplacesTheStoredTail(t *testing.T) {
	logs := NewRuntimeLogs()
	if err := logs.MergeRemote(runtimeLogIDOne, "one\ntwo\n", "warn\n"); err != nil {
		t.Fatal(err)
	}
	if err := logs.MergeRemote(runtimeLogIDOne, "one\ntwo\nthree\n", "warn\nnext\n"); err != nil {
		t.Fatal(err)
	}
	tail, ok := logs.Tail(runtimeLogIDOne)
	// The remote script returns the whole tail every time, so re-reading it must
	// leave one copy of each line rather than appending the overlap again.
	if !ok || len(tail.Lines) != 5 {
		t.Fatalf("replaced tail = %#v", tail)
	}
	if tail.Lines[2].Text != "three" || !sameLogLine(tail.Lines[4], "stderr", "next") {
		t.Fatalf("unexpected replaced tail: %#v", tail.Lines)
	}
}

func TestRuntimeLogsKeepsNarrationAheadOfTheRemoteTail(t *testing.T) {
	logs := NewRuntimeLogs()
	if err := logs.Append(runtimeLogIDOne, "status", "Runtime is queued"); err != nil {
		t.Fatal(err)
	}
	if err := logs.MergeRemote(runtimeLogIDOne, "job output\n", ""); err != nil {
		t.Fatal(err)
	}
	// Replacing the remote tail must not discard this process's own narration.
	if err := logs.MergeRemote(runtimeLogIDOne, "job output\nmore\n", ""); err != nil {
		t.Fatal(err)
	}
	tail, _ := logs.Tail(runtimeLogIDOne)
	if len(tail.Lines) != 3 || tail.Lines[0].Stream != "status" || tail.Lines[0].Text != "Runtime is queued" {
		t.Fatalf("narration lost after remote replacement: %#v", tail.Lines)
	}
}

func sameLogLine(line RuntimeLogLine, stream, text string) bool {
	return line.Stream == stream && line.Text == text && !line.At.IsZero()
}

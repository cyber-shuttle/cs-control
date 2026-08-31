package control

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cyber-shuttle/cs-control/internal/sshexec"
)

func TestReadRemoteRuntimeTailsUsesFixedArgumentsAndParsesStreams(t *testing.T) {
	ssh, _, commandLog := fakeSSH(t)
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
	remoteScript := string(mustRead(t, scriptLog))
	if remoteScript != runtimeLogTailScript || strings.Contains(remoteScript, runtimeLogIDOne) {
		t.Fatal("remote script was not the constant runtime tail script")
	}
	command := string(mustRead(t, commandLog))
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

func TestCollectStartingRuntimeLogsBatchesPerHostAndSkipsTerminalRuntimes(t *testing.T) {
	ssh, _, commandLog := fakeSSH(t)
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

	commands := string(mustRead(t, commandLog))
	lines := strings.Split(strings.TrimSpace(commands), "\n")
	// Five starting runtimes against a four-per-request script bound, so the host
	// takes two reads and no runtime waits for a later round.
	if len(lines) != 2 {
		t.Fatalf("tail reads = %q, want two batched host reads", lines)
	}
	for _, id := range []string{"rt-000000000001", "rt-000000000002", "rt-000000000003", "rt-000000000004", "rt-000000000005"} {
		if !strings.Contains(commands, id) {
			t.Errorf("batched read missing %s: %s", id, commands)
		}
		tail, ok := service.Logs.Tail(id)
		if !ok || len(tail.Lines) != 2 || !sameLogLine(tail.Lines[0], "stdout", "hello") || !sameLogLine(tail.Lines[1], "stderr", "warning") {
			t.Errorf("merged sanitized tail for %s = %#v", id, tail)
		}
	}
	for _, id := range []string{"rt-000000000006", "rt-000000000007"} {
		if strings.Contains(commands, id) {
			t.Errorf("ineligible runtime %s was tailed: %s", id, commands)
		}
	}

	service.collectStartingRuntimeLogs(context.Background(), []Runtime{
		{RuntimeResponse: RuntimeResponse{ID: runtimeLogIDOne, SSHHost: "alpha", State: "READY"}},
		{RuntimeResponse: RuntimeResponse{ID: runtimeLogIDTwo, SSHHost: "alpha", State: "STOPPED"}},
	})
	if after := string(mustRead(t, commandLog)); after != commands {
		t.Fatalf("terminal collection issued SSH: before=%q after=%q", commands, after)
	}
}

// The remote script returns the whole tail every time, so re-reading it replaces
// the stored copy rather than appending the overlap -- and never displaces this
// process's own narration, which is older than anything the allocation printed.
func TestRuntimeLogsMergeRemoteReplacesTheStoredTailAndKeepsNarration(t *testing.T) {
	logs := NewRuntimeLogs()
	logs.Append(runtimeLogIDOne, "Runtime is queued")
	logs.MergeRemote(runtimeLogIDOne, "one\ntwo\n", "warn\n")
	logs.MergeRemote(runtimeLogIDOne, "one\ntwo\nthree\n", "warn\nnext\n")
	tail, ok := logs.Tail(runtimeLogIDOne)
	if !ok || len(tail.Lines) != 6 {
		t.Fatalf("replaced tail = %#v", tail)
	}
	if !sameLogLine(tail.Lines[0], "status", "Runtime is queued") || tail.Lines[3].Text != "three" || !sameLogLine(tail.Lines[5], "stderr", "next") {
		t.Fatalf("unexpected replaced tail: %#v", tail.Lines)
	}
}

func sameLogLine(line RuntimeLogLine, stream, text string) bool {
	return line.Stream == stream && line.Text == text && !line.At.IsZero()
}

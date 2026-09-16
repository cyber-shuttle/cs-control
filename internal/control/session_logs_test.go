// Session logs' own contract: sanitized, bounded by line and byte, and redacted of sensitive text.
// An unchanged tail stays byte-identical for the poll's ETag.
// This file also covers remote tail collection, which replaces rather than appends on every read.
//
//	joinedLogText, runLogText, sessionLogText
//	assertNoSessionStatusSecrets
//	sameLogLine
//	remoteSessionLogTail
//	Test*
package control

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cyber-shuttle/cs-control/internal/authn"
	"github.com/cyber-shuttle/cs-control/internal/sshexec"
	"github.com/cyber-shuttle/cs-control/internal/testutil"
)

const (
	sessionLogIDOne = "s-111111111111"
	sessionLogIDTwo = "s-222222222222"
)

func joinedLogText(lines []sessionLogLine) string {
	texts := make([]string, 0, len(lines))
	for _, line := range lines {
		texts = append(texts, line.Text)
	}
	return strings.Join(texts, "\n")
}

func runLogText(t *testing.T, service Service, sessionID string) string {
	t.Helper()
	runs, err := service.listRuns(testPrincipal)
	testutil.Check(t, err)
	for _, run := range runs {
		if run.SessionID == sessionID {
			return joinedLogText(run.Logs)
		}
	}
	t.Fatal("session produced no run record")
	return ""
}

func sessionLogText(t *testing.T, logs *sessionLogs, sessionID string) string {
	t.Helper()
	tail, ok := logs.Tail(sessionID)
	if !ok {
		t.Fatal("session produced no log tail")
	}
	return joinedLogText(tail.Lines)
}

func assertNoSessionStatusSecrets(t *testing.T, joined string, values ...string) {
	t.Helper()
	values = append(values, "SENSITIVE_ENV_SENTINEL", "WORKSPACE_ROOT=", "sbatch", "--parsable")
	for _, sensitive := range values {
		if sensitive != "" && strings.Contains(joined, sensitive) {
			t.Errorf("sensitive value %q leaked into status tail:\n%s", sensitive, joined)
		}
	}
}

func sameLogLine(line sessionLogLine, stream, text string) bool {
	return line.Stream == stream && line.Text == text && !line.At.IsZero()
}

func remoteSessionLogTail(t *testing.T, home, id, generation string) string {
	t.Helper()
	cmd := exec.Command("sh", "-s", "--", "csctl-session-log-tail", id, generation)
	cmd.Stdin = strings.NewReader(sessionLogTailScript)
	cmd.Env = append(os.Environ(), "HOME="+home)
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("session log tail script failed: %v", err)
	}
	parsed, err := sections(string(output), sessionLogMarkerPrefix, []string{sessionLogMarker(id, "stdout"), sessionLogMarker(id, "stderr")})
	testutil.Check(t, err)
	stdout, err := decodeSessionLogTail(parsed[sessionLogMarker(id, "stdout")])
	testutil.Check(t, err)
	return stdout
}

func TestSessionLogsSanitizeAndSplit(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{name: "CR LF and CRLF", input: "one\rtwo\nthree\r\nfour\n", want: []string{"one", "two", "three", "four"}},
		{name: "interior blank", input: "one\n\ntwo", want: []string{"one", "", "two"}},
		{name: "ANSI CSI and OSC", input: "\x1b[31mred\x1b[0m \x1b]0;secret\x07plain", want: []string{"red plain"}},
		{name: "ESC designation and intermediates", input: "a\x1b(Bb\x1b%Gc\x1b#8d", want: []string{"abcd"}},
		{name: "7-bit string controls", input: "a\x1bPprivate-dcs\x1b\\b\x1b_hidden-apc\x1b\\c\x1b^hidden-pm\x1b\\d\x1bXhidden-sos\x1b\\e", want: []string{"abcde"}},
		{name: "C1 CSI and string controls", input: "a\u009b31mred\u009b0m b\u009dprivate-osc\u0007c\u0090private-dcs\u009cd\u009fprivate-apc\u009ce\u009eprivate-pm\u009cf\u0098private-sos\u009cg", want: []string{"ared bcdefg"}},
		{name: "OSC BEL and ST terminators", input: "a\x1b]private\x07b\x1b]private\x1b\\c\u009dprivate\u009cd", want: []string{"abcd"}},
		{name: "7-bit OSC ends at BEL across lines", input: "before\x1b]hidden\rhidden\nhidden\x07after", want: []string{"beforeafter"}},
		{name: "7-bit DCS ignores BEL through ESC ST", input: "before\x1bPhidden\rhidden\nhidden\x07must-not-leak\x1b\\after", want: []string{"beforeafter"}},
		{name: "incomplete CSI drops parameters", input: "safe\x1b[31", want: []string{"safe"}},
		{name: "malformed CSI drops payload", input: "safe\x1b[31\x00private", want: []string{"safe"}},
		{name: "incomplete ESC intermediates drop payload", input: "safe\x1b(", want: []string{"safe"}},
		{name: "UTF-8 around controls", input: "α\x1b(B界\u009b31mβ\u009b0m", want: []string{"α界β"}},
		{name: "split-looking literals are ordinary text", input: `literal \\x1b[31m and \\u009b31m`, want: []string{`literal \\x1b[31m and \\u009b31m`}},
		{name: "controls", input: "a\x00b\tc\x7fd\u0085e", want: []string{"abcde"}},
		{name: "invalid UTF-8", input: "a\xffb", want: []string{"a�b"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			logs := NewSessionLogs()
			logs.Append(sessionLogIDOne, test.input, time.Now())
			tail, ok := logs.Tail(sessionLogIDOne)
			if !ok || len(tail.Lines) != len(test.want) {
				t.Fatalf("tail = %#v, want %q", tail, test.want)
			}
			for i, want := range test.want {
				if !sameLogLine(tail.Lines[i], "status", want) {
					t.Fatalf("line %d = %#v, want %q", i, tail.Lines[i], want)
				}
			}
		})
	}
}

func TestSessionLogsEnforceLineAndByteLimits(t *testing.T) {
	t.Run("line limit", func(t *testing.T) {
		logs := NewSessionLogs()
		for i := 0; i < maxSessionLogLines+25; i++ {
			logs.Append(sessionLogIDOne, fmt.Sprintf("line-%03d", i), time.Now())
		}
		tail, _ := logs.Tail(sessionLogIDOne)
		if len(tail.Lines) != maxSessionLogLines || tail.Lines[0].Text != "line-025" || tail.Lines[len(tail.Lines)-1].Text != "line-124" {
			t.Fatalf("line eviction tail = first=%q last=%q count=%d", tail.Lines[0].Text, tail.Lines[len(tail.Lines)-1].Text, len(tail.Lines))
		}
	})

	t.Run("byte limit", func(t *testing.T) {
		logs := NewSessionLogs()
		for i := 0; i < 100; i++ {
			line := fmt.Sprintf("%04d", i) + strings.Repeat("x", 996)
			logs.Append(sessionLogIDOne, line, time.Now())
		}
		tail, _ := logs.Tail(sessionLogIDOne)
		bytes := 0
		for _, line := range tail.Lines {
			bytes += len(line.Text)
		}
		if len(tail.Lines) != 65 || bytes != 65000 || tail.Lines[0].Text[:4] != "0035" {
			t.Fatalf("byte eviction = count %d bytes %d first %q", len(tail.Lines), bytes, tail.Lines[0].Text[:4])
		}
	})
}

func TestSessionLogsRedactsSessionAndCredentialSecrets(t *testing.T) {
	logs := NewSessionLogs()
	logs.SetSessionSensitive(sessionLogIDOne,
		"/home/sentinel-user/.cybershuttle/sessions/"+sessionLogIDOne,
		"/scratch/sentinel-user/workspace",
		"/opt/private/linkspan-sentinel",
		"/opt/private/jupyter-sentinel/bin/python",
	)
	input := strings.Join([]string{
		"benign startup message",
		"workspace /scratch/sentinel-user/workspace/file.ipynb",
		"executables /opt/private/linkspan-sentinel /opt/private/jupyter-sentinel/bin/python",
		"authorization Bearer abcdefghijklmnopqrstuvwxyz012345",
		"token=token-shaped-secret-value-123456",
		"jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzZW50aW5lbCJ9.signature-value",
		"standalone generated tokens 0123456789abcdef0123456789abcdef and 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"tokenization for sentinel-user preserves 0123abcd and build 0123456789abcdefABCDEF_-0123456789abcdef",
	}, "\n")
	logs.Append(sessionLogIDOne, input, time.Now())
	joined := sessionLogText(t, logs, sessionLogIDOne)
	for _, secret := range []string{".cybershuttle/sessions", "linkspan-sentinel", "jupyter-sentinel", "abcdefghijklmnopqrstuvwxyz012345", "token-shaped-secret-value-123456", "eyJhbGciOiJIUzI1NiJ9", "0123456789abcdef0123456789abcdef"} {
		if strings.Contains(joined, secret) {
			t.Errorf("secret %q leaked in:\n%s", secret, joined)
		}
	}
	for _, benign := range []string{"benign startup message", "tokenization", "sentinel-user", "0123abcd", "0123456789abcdefABCDEF_-0123456789abcdef"} {
		if !strings.Contains(joined, benign) {
			t.Errorf("benign value %q was over-redacted in:\n%s", benign, joined)
		}
	}
	if !strings.Contains(joined, "[redacted]") {
		t.Fatalf("redaction omitted marker:\n%s", joined)
	}
}

func TestSessionPhaseStatusNeverStoresSensitiveValues(t *testing.T) {
	t.Run("successful readiness and stop", func(t *testing.T) {
		service := testService(t)
		t.Setenv("FAKE_WORKSPACE_ENV", "/scratch/SENSITIVE_ENV_SENTINEL")
		request := newTestCreateRequest()
		request.RootFolder = "$WORKSPACE/project"

		session, err := service.create(testTunnelContext(), request)
		testutil.Check(t, err)
		t.Setenv("FAKE_SESSION_STDOUT", "Linkspan started\n")
		testutil.Check(t, service.reconcileAll(context.Background()))
		_, err = service.stop(testTunnelContext(), session.ID)
		testutil.Check(t, err)

		joined := runLogText(t, service, session.ID)
		for _, want := range []string{"Preparing session", "Validating session with Slurm", "Submitting session to Slurm", "Session is queued", "Compute node assigned: cn001", "Session is running", "Stopping session"} {
			if !strings.Contains(joined, want) {
				t.Errorf("missing public phase %q in:\n%s", want, joined)
			}
		}
		assertNoSessionStatusSecrets(t, joined, service.Config.LinkspanPath, session.PrivateRoot, session.WorkspaceRoot)
	})

	t.Run("failure and cleanup", func(t *testing.T) {
		service := testService(t)
		session, err := service.create(testTunnelContext(), newTestCreateRequest())
		testutil.Check(t, err)
		_, err = service.stop(testTunnelContext(), session.ID)
		testutil.Check(t, err)
		testutil.Check(t, service.reconcileAll(context.Background()))
		runs, err := service.listRuns(testPrincipal)
		testutil.Check(t, err)
		var run *runRecord
		for i := range runs {
			if runs[i].SessionID == session.ID {
				run = &runs[i]
			}
		}
		if run == nil {
			t.Fatal("session produced no run record")
		}
		for _, line := range run.Logs {
			testutil.Equal(t, line.Stream, "status", "phase instrumentation stream")
		}
		joined := joinedLogText(run.Logs)
		if !strings.Contains(joined, "Session stopped") {
			t.Errorf("missing terminal phase %q in:\n%s", "Session stopped", joined)
		}
	})
}

func TestValidateNeverLeavesALogBuffer(t *testing.T) {
	t.Run("passed", func(t *testing.T) {
		service := testService(t)
		request := newTestCreateRequest()
		_, err := service.validate(testTunnelContext(), request)
		testutil.Check(t, err)
		if _, ok := service.Logs.Tail(request.ID); ok {
			t.Fatal("a passed validate left its log buffer behind")
		}
	})

	t.Run("rejected by Slurm", func(t *testing.T) {
		service := testService(t)
		t.Setenv("FAKE_VALIDATION_FAIL", "1")
		request := newTestCreateRequest()
		result, err := service.validate(testTunnelContext(), request)
		if err != nil || result.Status != "FAILED" {
			t.Fatalf("expected a FAILED validation result, got %#v %v", result, err)
		}
		if _, ok := service.Logs.Tail(request.ID); ok {
			t.Fatal("a rejected validate left its log buffer behind")
		}
	})

}

func TestSessionLogsUnchangedTailIsByteIdentical(t *testing.T) {
	logs := NewSessionLogs()
	tick := time.Unix(0, 0).UTC()
	next := func() time.Time { tick = tick.Add(time.Second); return tick }
	logs.Append(sessionLogIDOne, "same phase", next())
	logs.MergeRemote(sessionLogIDOne, "line one\nline two\n", "", next())
	first, ok := logs.Tail(sessionLogIDOne)
	if !ok {
		t.Fatal("no tail")
	}
	before, err := json.Marshal(first)
	testutil.Check(t, err)
	logs.Append(sessionLogIDOne, "same phase", next())
	logs.MergeRemote(sessionLogIDOne, "line one\nline two\n", "", next())
	second, _ := logs.Tail(sessionLogIDOne)
	after, err := json.Marshal(second)
	testutil.Check(t, err)
	if !bytes.Equal(before, after) {
		t.Fatalf("repeating an unchanged tail changed its body:\n%s\n%s", before, after)
	}
	if len(second.Lines) != 3 {
		t.Fatalf("lines = %#v", second.Lines)
	}
	logs.MergeRemote(sessionLogIDOne, "line one\nline three\n", "", next())
	changed, _ := logs.Tail(sessionLogIDOne)
	if !changed.Lines[1].At.Equal(second.Lines[1].At) || changed.Lines[2].At.Equal(second.Lines[2].At) {
		t.Fatalf("changed tail did not re-stamp exactly the changed line: %#v", changed.Lines)
	}
}

func TestReadRemoteSessionTailsUsesFixedArgumentsAndParsesStreams(t *testing.T) {
	ssh, _, commandLog := fakeSSH(t)
	scriptLog := filepath.Join(t.TempDir(), "session-tail-script")
	t.Setenv("FAKE_SESSION_LOG_SCRIPT", scriptLog)
	t.Setenv("FAKE_SESSION_STDOUT", "first\n\x1b[31msecond\x1b[0m\n")
	t.Setenv("FAKE_SESSION_STDERR", "warning\rnext\n")
	service := Service{
		Runner: sshexec.Runner{SSHBin: ssh, Timeout: 5 * time.Second, ControlNamespace: filepath.Join(t.TempDir(), "masters")},
		Logs:   NewSessionLogs(),
	}

	generationOne, generationTwo := "g-1111111111111111", "g-2222222222222222"
	tails, err := service.readRemoteSessionTails(context.Background(), "alpha", []sessionLogTarget{
		{id: sessionLogIDOne, generation: generationOne},
		{id: sessionLogIDTwo, generation: generationTwo},
	})
	testutil.Check(t, err)
	if tails[sessionLogIDOne].stdout != "first\n\x1b[31msecond\x1b[0m\n" || tails[sessionLogIDTwo].stderr != "warning\rnext\n" {
		t.Fatalf("parsed tails = %#v", tails)
	}
	remoteScript := string(mustRead(t, scriptLog))
	if remoteScript != sessionLogTailScript || strings.Contains(remoteScript, sessionLogIDOne) {
		t.Fatal("remote script was not the constant session tail script")
	}
	command := string(mustRead(t, commandLog))
	for _, want := range []string{"'sh' '-s' '--' 'csctl-session-log-tail'", "'" + sessionLogIDOne + "'", "'" + sessionLogIDTwo + "'"} {
		if !strings.Contains(command, want) {
			t.Errorf("fixed remote command missing %q: %s", want, command)
		}
	}
	args, err := service.Runner.Args(context.Background(), "alpha", false)
	testutil.Check(t, err)
	joinedArgs := strings.Join(args, " ")
	for _, want := range []string{"ControlMaster=auto", "ControlPersist=600", "ControlPath="} {
		if !strings.Contains(joinedArgs, want) {
			t.Errorf("tail SSH arguments missing %q: %s", want, joinedArgs)
		}
	}
}

func TestCollectStartingSessionLogsBatchesPerHostAndSkipsTerminalSessions(t *testing.T) {
	ssh, _, commandLog := fakeSSH(t)
	t.Setenv("FAKE_SESSION_STDOUT", "hello\n")
	t.Setenv("FAKE_SESSION_STDERR", "\x1b[31mwarning\x1b[0m\n")
	service := Service{Runner: sshexec.Runner{SSHBin: ssh, Timeout: 5 * time.Second}, Config: Config{HostsDir: filepath.Join(t.TempDir(), "hosts")}, Logs: NewSessionLogs()}
	registerTestHosts(t, service, authn.Principal{}, "alpha")
	sessions := []Session{
		{sessionResponse: sessionResponse{ID: "s-000000000001", Generation: "g-0000000000000001", SSHHost: "alpha", State: "STARTING"}},
		{sessionResponse: sessionResponse{ID: "s-000000000002", Generation: "g-0000000000000002", SSHHost: "alpha", State: "STARTING"}},
		{sessionResponse: sessionResponse{ID: "s-000000000003", Generation: "g-0000000000000003", SSHHost: "alpha", State: "STARTING"}},
		{sessionResponse: sessionResponse{ID: "s-000000000004", Generation: "g-0000000000000004", SSHHost: "alpha", State: "STARTING"}},
		{sessionResponse: sessionResponse{ID: "s-000000000005", Generation: "g-0000000000000005", SSHHost: "alpha", State: "STARTING"}},
		{sessionResponse: sessionResponse{ID: "s-000000000006", SSHHost: "alpha", State: "READY"}},
		{sessionResponse: sessionResponse{ID: "s-000000000007", SSHHost: "alpha", State: "FAILED"}},
	}
	service.collectStartingSessionLogs(context.Background(), sessions)

	commands := string(mustRead(t, commandLog))
	lines := strings.Split(strings.TrimSpace(commands), "\n")
	if len(lines) != 2 {
		t.Fatalf("tail reads = %q, want two batched host reads", lines)
	}
	for _, id := range []string{"s-000000000001", "s-000000000002", "s-000000000003", "s-000000000004", "s-000000000005"} {
		if !strings.Contains(commands, id) {
			t.Errorf("batched read missing %s: %s", id, commands)
		}
		tail, ok := service.Logs.Tail(id)
		if !ok || len(tail.Lines) != 2 || !sameLogLine(tail.Lines[0], "stdout", "hello") || !sameLogLine(tail.Lines[1], "stderr", "warning") {
			t.Errorf("merged sanitized tail for %s = %#v", id, tail)
		}
	}
	for _, id := range []string{"s-000000000006", "s-000000000007"} {
		if strings.Contains(commands, id) {
			t.Errorf("ineligible session %s was tailed: %s", id, commands)
		}
	}

	service.collectStartingSessionLogs(context.Background(), []Session{
		{sessionResponse: sessionResponse{ID: sessionLogIDOne, SSHHost: "alpha", State: "READY"}},
		{sessionResponse: sessionResponse{ID: sessionLogIDTwo, SSHHost: "alpha", State: "STOPPED"}},
	})
	if after := string(mustRead(t, commandLog)); after != commands {
		t.Fatalf("terminal collection issued SSH: before=%q after=%q", commands, after)
	}
}

func TestSessionLogsMergeRemoteReplacesTheStoredTailAndKeepsNarration(t *testing.T) {
	logs := NewSessionLogs()
	logs.Append(sessionLogIDOne, "Session is queued", time.Now())
	logs.MergeRemote(sessionLogIDOne, "one\ntwo\n", "warn\n", time.Now())
	logs.MergeRemote(sessionLogIDOne, "one\ntwo\nthree\n", "warn\nnext\n", time.Now())
	tail, ok := logs.Tail(sessionLogIDOne)
	if !ok || len(tail.Lines) != 6 {
		t.Fatalf("replaced tail = %#v", tail)
	}
	if !sameLogLine(tail.Lines[0], "status", "Session is queued") || tail.Lines[3].Text != "three" || !sameLogLine(tail.Lines[5], "stderr", "next") {
		t.Fatalf("unexpected replaced tail: %#v", tail.Lines)
	}
}

func TestSessionLogTailScriptIsScopedByGeneration(t *testing.T) {
	home := t.TempDir()
	logDir := filepath.Join(home, ".cybershuttle", "logs")
	testutil.Check(t, os.MkdirAll(logDir, 0o700))
	id, oldGeneration, newGeneration := "s-abcdefabcdef", "g-1111111111111111", "g-2222222222222222"
	testutil.Check(t, os.WriteFile(filepath.Join(logDir, sessionLogBasename(id, oldGeneration)+".out"), []byte("finished run output\n"), 0o600))

	if got := remoteSessionLogTail(t, home, id, newGeneration); got != "" {
		t.Fatalf("relaunch read the finished generation's log: %q", got)
	}

	testutil.Check(t, os.WriteFile(filepath.Join(logDir, sessionLogBasename(id, newGeneration)+".out"), []byte("new run output\n"), 0o600))
	if got := remoteSessionLogTail(t, home, id, newGeneration); got != "new run output\n" {
		t.Fatalf("new generation log = %q", got)
	}
}

func TestSessionLogTailScriptWorstCaseStaysUnderTheRemoteOutputCap(t *testing.T) {
	const sshexecMaxOutput = 1 << 20
	home := t.TempDir()
	logDir := filepath.Join(home, ".cybershuttle", "logs")
	testutil.Check(t, os.MkdirAll(logDir, 0o700))
	huge := bytes.Repeat([]byte("x"), sshexecMaxOutput)
	args := []string{"csctl-session-log-tail"}
	for i := 0; i < maxSessionLogCollections; i++ {
		id := fmt.Sprintf("s-%012x", i)
		generation := fmt.Sprintf("g-%016x", i)
		for _, suffix := range []string{"out", "err"} {
			path := filepath.Join(logDir, sessionLogBasename(id, generation)+"."+suffix)
			testutil.Check(t, os.WriteFile(path, huge, 0o600))
		}
		args = append(args, id, generation)
	}
	cmd := exec.Command("sh", append([]string{"-s", "--"}, args...)...)
	cmd.Stdin = strings.NewReader(sessionLogTailScript)
	cmd.Env = append(os.Environ(), "HOME="+home)
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("session log tail script failed: %v", err)
	}
	if len(output) >= sshexecMaxOutput {
		t.Fatalf("a full chunk of maximal tails produced %d bytes, at or over the sshexec output cap of %d", len(output), sshexecMaxOutput)
	}
}

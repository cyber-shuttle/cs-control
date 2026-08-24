package control

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

const (
	runtimeLogIDOne = "rt-111111111111"
	runtimeLogIDTwo = "rt-222222222222"
)

func TestRuntimeLogsSanitizeAndSplit(t *testing.T) {
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
		{name: "DCS ST terminators", input: "a\x1bPprivate\x1b\\b\u0090private\u009cc", want: []string{"abc"}},
		{name: "incomplete CSI drops parameters", input: "safe\x1b[31", want: []string{"safe"}},
		{name: "malformed CSI drops payload", input: "safe\x1b[31\x00private", want: []string{"safe"}},
		{name: "incomplete ESC intermediates drop payload", input: "safe\x1b(", want: []string{"safe"}},
		{name: "malformed strings consume payload", input: "safe\x1b]unterminated-private", want: []string{"safe"}},
		{name: "UTF-8 around controls", input: "α\x1b(B界\u009b31mβ\u009b0m", want: []string{"α界β"}},
		{name: "split-looking literals are ordinary text", input: `literal \\x1b[31m and \\u009b31m`, want: []string{`literal \\x1b[31m and \\u009b31m`}},
		{name: "controls", input: "a\x00b\tc\x7fd\u0085e", want: []string{"abcde"}},
		{name: "invalid UTF-8", input: "a\xffb", want: []string{"a�b"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			logs := NewRuntimeLogs()
			if err := logs.Append(runtimeLogIDOne, "stdout", test.input); err != nil {
				t.Fatalf("Append() = %v", err)
			}
			tail, ok := logs.Tail(runtimeLogIDOne)
			if !ok || len(tail.Lines) != len(test.want) {
				t.Fatalf("tail = %#v, want %q", tail, test.want)
			}
			for i, want := range test.want {
				if !sameLogLine(tail.Lines[i], "stdout", want) {
					t.Fatalf("line %d = %#v, want %q", i, tail.Lines[i], want)
				}
			}
		})
	}
}

func TestRuntimeLogStringControlsDoNotLeakAcrossLines(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "7-bit OSC BEL terminates before ST",
			input: "before\x1b]hidden\rhidden\nhidden\r\nhidden\x07after-bel\x1b\\after-st",
			want:  []string{"beforeafter-belafter-st"},
		},
		{
			name:  "C1 OSC BEL terminates before ST",
			input: "before\u009dhidden\rhidden\nhidden\r\nhidden\x07after-bel\u009cafter-st",
			want:  []string{"beforeafter-belafter-st"},
		},
		{
			name:  "7-bit DCS ignores BEL through ESC ST",
			input: "before\x1bPhidden\rhidden\nhidden\r\nhidden\x07must-not-leak\x1b\\after",
			want:  []string{"beforeafter"},
		},
		{
			name:  "C1 DCS ignores BEL through C1 ST",
			input: "before\u0090hidden\rhidden\nhidden\r\nhidden\x07must-not-leak\u009cafter",
			want:  []string{"beforeafter"},
		},
		{
			name:  "7-bit SOS ignores BEL through C1 ST",
			input: "before\x1bXhidden\rhidden\nhidden\r\nhidden\x07must-not-leak\u009cafter",
			want:  []string{"beforeafter"},
		},
		{
			name:  "C1 SOS ignores BEL through ESC ST",
			input: "before\u0098hidden\rhidden\nhidden\r\nhidden\x07must-not-leak\x1b\\after",
			want:  []string{"beforeafter"},
		},
		{
			name:  "7-bit PM ignores BEL through ESC ST",
			input: "before\x1b^hidden\rhidden\nhidden\r\nhidden\x07must-not-leak\x1b\\after",
			want:  []string{"beforeafter"},
		},
		{
			name:  "C1 PM ignores BEL through C1 ST",
			input: "before\u009ehidden\rhidden\nhidden\r\nhidden\x07must-not-leak\u009cafter",
			want:  []string{"beforeafter"},
		},
		{
			name:  "7-bit APC ignores BEL through C1 ST",
			input: "before\x1b_hidden\rhidden\nhidden\r\nhidden\x07must-not-leak\u009cafter",
			want:  []string{"beforeafter"},
		},
		{
			name:  "C1 APC ignores BEL through ESC ST",
			input: "before\u009fhidden\rhidden\nhidden\r\nhidden\x07must-not-leak\x1b\\after",
			want:  []string{"beforeafter"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := sanitizedRuntimeLogLines(test.input, nil); !slices.Equal(got, test.want) {
				t.Fatalf("sanitizedRuntimeLogLines() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestRuntimeLogsEnforceLineAndByteLimits(t *testing.T) {
	t.Run("line limit", func(t *testing.T) {
		logs := NewRuntimeLogs()
		for i := 0; i < maxRuntimeLogLines+25; i++ {
			if err := logs.Append(runtimeLogIDOne, "status", fmt.Sprintf("line-%03d", i)); err != nil {
				t.Fatal(err)
			}
		}
		tail, _ := logs.Tail(runtimeLogIDOne)
		if len(tail.Lines) != maxRuntimeLogLines || tail.Lines[0].Text != "line-025" || tail.Lines[len(tail.Lines)-1].Text != "line-124" {
			t.Fatalf("line eviction tail = first=%q last=%q count=%d", tail.Lines[0].Text, tail.Lines[len(tail.Lines)-1].Text, len(tail.Lines))
		}
	})

	t.Run("byte limit", func(t *testing.T) {
		logs := NewRuntimeLogs()
		for i := 0; i < 100; i++ {
			line := fmt.Sprintf("%04d", i) + strings.Repeat("x", 996)
			if err := logs.Append(runtimeLogIDOne, "stdout", line); err != nil {
				t.Fatal(err)
			}
		}
		tail, _ := logs.Tail(runtimeLogIDOne)
		bytes := 0
		for _, line := range tail.Lines {
			bytes += len(line.Text)
		}
		if len(tail.Lines) != 65 || bytes != 65000 || tail.Lines[0].Text[:4] != "0035" {
			t.Fatalf("byte eviction = count %d bytes %d first %q", len(tail.Lines), bytes, tail.Lines[0].Text[:4])
		}
	})
}

func TestRuntimeLogsRedactsRuntimeAndCredentialSecrets(t *testing.T) {
	logs := NewRuntimeLogs()
	logs.SetRuntimeSensitive(runtimeLogIDOne,
		"/home/sentinel-user/.cybershuttle/runtimes/"+runtimeLogIDOne,
		"/scratch/sentinel-user/workspace",
		"/opt/private/linkspan-sentinel",
		"/opt/private/jupyter-sentinel/bin/python",
	)
	input := strings.Join([]string{
		"benign startup message",
		"workspace /scratch/sentinel-user/workspace/file.ipynb",
		"socket /tmp/cs-" + runtimeLogIDOne + ".sock",
		"executables /opt/private/linkspan-sentinel /opt/private/jupyter-sentinel/bin/python",
		"authorization Bearer abcdefghijklmnopqrstuvwxyz012345",
		"token=token-shaped-secret-value-123456",
		"jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzZW50aW5lbCJ9.signature-value",
		"standalone generated tokens 0123456789abcdef0123456789abcdef and 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"tokenization for sentinel-user preserves 0123abcd and build 0123456789abcdefABCDEF_-0123456789abcdef",
	}, "\n")
	if err := logs.Append(runtimeLogIDOne, "stderr", input); err != nil {
		t.Fatalf("Append = %v", err)
	}
	joined := runtimeLogText(t, logs, runtimeLogIDOne, false)
	for _, secret := range []string{".cybershuttle/runtimes", "cs-" + runtimeLogIDOne + ".sock", "linkspan-sentinel", "jupyter-sentinel", "abcdefghijklmnopqrstuvwxyz012345", "token-shaped-secret-value-123456", "eyJhbGciOiJIUzI1NiJ9", "0123456789abcdef0123456789abcdef"} {
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

func TestRuntimePhaseStatusNeverStoresSensitiveValues(t *testing.T) {
	t.Run("successful readiness and stop", func(t *testing.T) {
		service := testService(t)
		service.Runner.Timeout = 5 * time.Second
		service.Logs = NewRuntimeLogs()
		t.Setenv("FAKE_WORKSPACE_ENV", "/scratch/SENSITIVE_ENV_SENTINEL")
		request := createRequest()
		request.RootFolder = "$WORKSPACE/project"

		runtime, err := service.Create(testTunnelContext(), request)
		if err != nil {
			t.Fatal(err)
		}
		if err := service.ReconcileAll(context.Background()); err != nil {
			t.Fatal(err)
		}
		if _, err := service.Stop(testTunnelContext(), runtime.ID); err != nil {
			t.Fatal(err)
		}

		joined := runtimeLogText(t, service.Logs, runtime.ID, true)
		for _, want := range []string{"Preparing runtime", "Validating runtime with Slurm", "Submitting runtime to Slurm", "Runtime is queued", "Compute node assigned: cn001", "Allocation is running", "Stopping runtime"} {
			if !strings.Contains(joined, want) {
				t.Errorf("missing public phase %q in:\n%s", want, joined)
			}
		}
		assertNoRuntimeStatusSecrets(t, joined, service.Config.LinkspanPath, runtime.PrivateRoot, runtime.WorkspaceRoot)
	})

	t.Run("failure and cleanup", func(t *testing.T) {
		service := testService(t)
		service.Runner.Timeout = 5 * time.Second
		service.Logs = NewRuntimeLogs()
		runtime, err := service.Create(testTunnelContext(), createRequest())
		if err != nil {
			t.Fatal(err)
		}
		// Stop changes the fake scheduler state to CANCELLED; the following
		// batched reconciliation then exercises terminal cleanup.
		if _, err := service.Stop(testTunnelContext(), runtime.ID); err != nil {
			t.Fatal(err)
		}
		if err := service.ReconcileAll(context.Background()); err != nil {
			t.Fatal(err)
		}
		joined := runtimeLogText(t, service.Logs, runtime.ID, true)
		for _, want := range []string{"Cleaning up runtime credentials", "Runtime credential cleanup complete", "Runtime stopped"} {
			if !strings.Contains(joined, want) {
				t.Errorf("missing terminal phase %q in:\n%s", want, joined)
			}
		}
	})

	t.Run("validation diagnostic", func(t *testing.T) {
		service := testService(t)
		service.Runner.Timeout = 5 * time.Second
		service.Logs = NewRuntimeLogs()
		t.Setenv("FAKE_VALIDATION_FAIL", "1")
		t.Setenv("FAKE_VALIDATION_STDERR", "SENSITIVE_TOKEN_SENTINEL /private/SENSITIVE_PATH_SENTINEL")
		if _, err := service.Create(testTunnelContext(), createRequest()); err == nil {
			t.Fatal("sensitive validation failure unexpectedly succeeded")
		}
		joined := runtimeLogText(t, service.Logs, createRequest().ID, true)
		if !strings.Contains(joined, "Slurm validation failed") {
			t.Fatalf("missing public validation failure in:\n%s", joined)
		}
		assertNoRuntimeStatusSecrets(t, joined, "SENSITIVE_TOKEN_SENTINEL", "SENSITIVE_PATH_SENTINEL")
	})
}

func runtimeLogText(t *testing.T, logs *RuntimeLogs, runtimeID string, statusOnly bool) string {
	t.Helper()
	tail, ok := logs.Tail(runtimeID)
	if !ok {
		t.Fatal("runtime produced no log tail")
	}
	texts := make([]string, 0, len(tail.Lines))
	for _, line := range tail.Lines {
		if statusOnly && line.Stream != "status" {
			t.Fatalf("phase instrumentation stored %q stream", line.Stream)
		}
		texts = append(texts, line.Text)
	}
	return strings.Join(texts, "\n")
}

func assertNoRuntimeStatusSecrets(t *testing.T, joined string, values ...string) {
	t.Helper()
	values = append(values, "SENSITIVE_ENV_SENTINEL", "WORKSPACE_ROOT=", "sbatch", "--parsable")
	for _, sensitive := range values {
		if sensitive != "" && strings.Contains(joined, sensitive) {
			t.Errorf("sensitive value %q leaked into status tail:\n%s", sensitive, joined)
		}
	}
}

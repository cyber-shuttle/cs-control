package sshexec

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
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

func TestChildEnvAsksForUTF8WhenTheServiceInheritedNoLocale(t *testing.T) {
	for _, name := range []string{"LC_ALL", "LC_CTYPE", "LANG"} {
		t.Setenv(name, "")
	}
	if !slices.Contains(ChildEnv(), "LC_ALL="+utf8Locale) {
		t.Fatal("a service with no locale must ask ssh for UTF-8, or remote text arrives octal-escaped")
	}
}

func TestChildEnvOverridesALocaleThatWouldEscapeRemoteText(t *testing.T) {
	t.Setenv("LC_ALL", "C")
	t.Setenv("LC_CTYPE", "")
	t.Setenv("LANG", "")
	if !slices.Contains(ChildEnv(), "LC_ALL="+utf8Locale) {
		t.Fatal("the C locale escapes every non-ASCII byte, so it must not stand for an ssh child")
	}
}

func TestChildEnvLeavesAUTF8LocaleAlone(t *testing.T) {
	for name, value := range map[string]string{"LC_ALL": "en_US.UTF-8", "LC_CTYPE": "en_GB.utf8", "LANG": "de_DE.UTF-8"} {
		for _, other := range []string{"LC_ALL", "LC_CTYPE", "LANG"} {
			t.Setenv(other, "")
		}
		t.Setenv(name, value)
		if slices.Contains(ChildEnv(), "LC_ALL="+utf8Locale) {
			t.Errorf("%s=%s already asks for UTF-8 and must be left alone", name, value)
		}
	}
}

// The unit tests above pin what we pass; only OpenSSH can say whether it honours
// it. It renders non-ASCII it does not trust through vis(3), so a hostname is
// enough to see which way it goes.
func TestOpenSSHDoesNotEscapeNonASCIIUnderChildEnv(t *testing.T) {
	ssh, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("no ssh on this machine")
	}
	host := "no-such-host-█▄.invalid"
	run := func(env []string) string {
		cmd := exec.Command(ssh, "-o", "ConnectTimeout=1", "-o", "BatchMode=yes", host, "true")
		cmd.Env = env
		out, _ := cmd.CombinedOutput()
		return string(out)
	}
	if escaped := run([]string{"PATH=" + os.Getenv("PATH"), "LC_ALL=C"}); !strings.Contains(escaped, `\342\226`) {
		t.Skip("this OpenSSH does not octal-escape under the C locale; nothing to prove")
	}
	for _, name := range []string{"LC_ALL", "LC_CTYPE", "LANG"} {
		t.Setenv(name, "")
	}
	if got := run(ChildEnv()); strings.Contains(got, `\342\226`) {
		t.Fatalf("ssh still octal-escaped non-ASCII under ChildEnv: %s", got)
	}
}

// A duplicate name reaches execve twice and the two libcs disagree about which
// copy wins, so exactly one must survive.
func TestChildEnvLeavesExactlyOneLocaleEntry(t *testing.T) {
	t.Setenv("LC_ALL", "C")
	t.Setenv("LC_CTYPE", "")
	t.Setenv("LANG", "")
	count := 0
	for _, entry := range ChildEnv() {
		if strings.HasPrefix(entry, "LC_ALL=") {
			count++
			if entry != "LC_ALL="+utf8Locale {
				t.Errorf("LC_ALL survived as %q", entry)
			}
		}
	}
	if count != 1 {
		t.Fatalf("ChildEnv returned %d LC_ALL entries, want exactly 1", count)
	}
}

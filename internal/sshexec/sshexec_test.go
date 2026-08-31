package sshexec

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestRunRemoteArgsBoundsCombinedOutput(t *testing.T) {
	captured := NewCapture()
	if _, err := captured.Stdout().Write(make([]byte, MaxOutput)); err != nil {
		t.Fatal(err)
	}
	if _, err := captured.Stderr().Write([]byte("x")); err == nil || !strings.Contains(err.Error(), "output exceeded limit") {
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
// it, and that depends on the build. OpenSSH escapes through strnvis: macOS
// supplies a locale-aware one, while portable OpenSSH bundles its own for Linux
// because glibc's is unusable, and the bundled copy escapes non-ASCII whatever
// the locale. A diagnostic is therefore only a usable probe where the platform
// varies by locale at all, so this measures that first and skips where it cannot
// tell the two apart.
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
	path := "PATH=" + os.Getenv("PATH")
	if !strings.Contains(run([]string{path, "LC_ALL=C"}), `\342\226`) {
		t.Skip("this OpenSSH does not octal-escape diagnostics under the C locale")
	}
	if strings.Contains(run([]string{path, "LC_ALL=" + utf8Locale}), `\342\226`) {
		t.Skip("this OpenSSH escapes diagnostics whatever the locale, so they cannot measure it")
	}
	for _, name := range []string{"LC_ALL", "LC_CTYPE", "LANG"} {
		t.Setenv(name, "")
	}
	if got := run(ChildEnv()); strings.Contains(got, `\342\226`) {
		t.Fatalf("ssh octal-escaped non-ASCII under ChildEnv on a build that honours the locale: %s", got)
	}
}

// A duplicate name reaches execve twice and the two libcs disagree about which
// copy wins -- glibc takes the first, macOS the last -- so exactly one survives.
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

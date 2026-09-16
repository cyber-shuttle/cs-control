// Tests the output bound, the interactive master's foreground ownership, ChildEnv's locale policy, and the
// private control socket.
//
//	listenUnix
//	TestRunRemoteArgsBoundsCombinedOutput, TestInteractiveMasterIsNotBackgrounded
//	TestChildEnvLeavesAUTF8LocaleAlone
//	TestOpenSSHDoesNotEscapeNonASCIIUnderChildEnv
//	TestChildEnvLeavesExactlyOneLocaleEntry, TestMasterHealthyRequiresAPrivateOwnedSocket
//	TestControlPathIsPerConfiguration, TestArgsNameTheCallersConfiguration
package sshexec

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cyber-shuttle/cs-control/internal/testutil"
)

func listenUnix(t *testing.T, path string) net.Listener {
	t.Helper()
	listener, err := net.Listen("unix", path)
	testutil.Check(t, err)
	return listener
}

func TestRunRemoteArgsBoundsCombinedOutput(t *testing.T) {
	captured := newCapture()
	_, err := captured.Stdout().Write(make([]byte, maxOutput))
	testutil.Check(t, err)
	if _, err := captured.Stderr().Write([]byte("x")); err == nil || !strings.Contains(err.Error(), "output exceeded limit") {
		t.Fatalf("oversized combined remote output error = %v", err)
	}
}

func TestInteractiveMasterIsNotBackgrounded(t *testing.T) {
	runner := Runner{SSHBin: filepath.Join(t.TempDir(), "unused"), ControlNamespace: t.TempDir(), Timeout: time.Second}
	for _, test := range []struct {
		interactive bool
		persist     string
		batch       string
	}{{true, "ControlPersist=no", "BatchMode=no"}, {false, "ControlPersist=600", "BatchMode=yes"}} {
		args, err := runner.sshArgs("delta", test.interactive, "identity\n")
		testutil.Check(t, err)
		joined := strings.Join(args, " ")
		if !strings.Contains(joined, test.persist) || !strings.Contains(joined, test.batch) {
			t.Fatalf("interactive=%v produced %q", test.interactive, joined)
		}
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
	testutil.Equal(t, count, 1, "ChildEnv LC_ALL entries")
}

func TestMasterHealthyRequiresAPrivateOwnedSocket(t *testing.T) {
	dir := t.TempDir()
	ssh := filepath.Join(dir, "ssh")
	testutil.Check(t, os.WriteFile(ssh, []byte("#!/bin/sh\nexit 0\n"), 0o700))
	runner := Runner{SSHBin: ssh}
	regular := filepath.Join(dir, "regular")
	testutil.Check(t, os.WriteFile(regular, nil, 0o600))
	link := filepath.Join(dir, "link")
	testutil.Check(t, os.Symlink(regular, link))
	sockets, err := os.MkdirTemp("", "cs")
	testutil.Check(t, err)
	defer func() { _ = os.RemoveAll(sockets) }()
	private, shared := filepath.Join(sockets, "private"), filepath.Join(sockets, "shared")
	privateListener, sharedListener := listenUnix(t, private), listenUnix(t, shared)
	defer func() { _ = privateListener.Close() }()
	defer func() { _ = sharedListener.Close() }()
	testutil.Check(t, os.Chmod(private, 0o600))
	testutil.Check(t, os.Chmod(shared, 0o777))
	for name, path := range map[string]string{"regular file": regular, "symlink": link, "world-accessible socket": shared} {
		if runner.MasterHealthy("delta", path) {
			t.Fatalf("%s was accepted as a control socket", name)
		}
	}
	if !runner.MasterHealthy("delta", private) {
		t.Fatal("a private socket this user owns was refused")
	}
}

func TestControlPathIsPerConfiguration(t *testing.T) {
	dir := t.TempDir()
	base := Runner{ControlNamespace: dir}
	mine := base
	mine.Hosts.UserPath = filepath.Join(dir, "a", "config")
	theirs := base
	theirs.Hosts.UserPath = filepath.Join(dir, "b", "config")

	minePath, err := mine.controlPath("delta", "identity")
	testutil.Check(t, err)
	theirsPath, err := theirs.controlPath("delta", "identity")
	testutil.Check(t, err)
	if minePath == theirsPath {
		t.Fatal("two configurations share one control master for the same alias")
	}
}

func TestArgsNameTheCallersConfiguration(t *testing.T) {
	runner := Runner{ControlNamespace: t.TempDir()}
	runner.Hosts.UserPath = "/tmp/some/caller/config"
	args, err := runner.sshArgs("delta", false, "identity")
	testutil.Check(t, err)
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "-F /tmp/some/caller/config") {
		t.Fatalf("ssh was not pointed at the caller's configuration: %s", joined)
	}
	bare, err := Runner{ControlNamespace: t.TempDir()}.sshArgs("delta", false, "identity")
	testutil.Check(t, err)
	if strings.Contains(strings.Join(bare, " "), "-F") {
		t.Fatalf("an unset configuration still produced -F: %v", bare)
	}
}

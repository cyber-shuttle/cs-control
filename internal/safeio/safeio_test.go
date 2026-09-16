// Tests the trust boundary every function here enforces against a planted symlink or an oversized file.
//
//	TestEnsurePrivateDirRefusesSymlinkWithoutChmoddingItsTarget, TestEnsurePrivateDirCreatesAndRepairsMode
//	TestReplaceFileRefusesSymlinkedTarget, TestReadPrivateFileRefusesSymlinkAndBoundsSize
package safeio

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cyber-shuttle/cs-control/internal/testutil"
)

func TestEnsurePrivateDirRefusesSymlinkWithoutChmoddingItsTarget(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "shared")
	testutil.Check(t, os.Mkdir(target, 0o755))
	link := filepath.Join(root, "state")
	testutil.Check(t, os.Symlink(target, link))
	if err := EnsurePrivateDir(link); err == nil {
		t.Fatal("a symlinked directory was accepted as private")
	}
	if info, err := os.Stat(target); err != nil || info.Mode().Perm() != 0o755 {
		t.Fatalf("chmod followed the symlink: mode = %v, %v", info.Mode(), err)
	}
}

func TestEnsurePrivateDirCreatesAndRepairsMode(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state", "nested")
	testutil.Check(t, EnsurePrivateDir(dir))
	testutil.Check(t, os.Chmod(dir, 0o755))
	testutil.Check(t, EnsurePrivateDir(dir))
	if info, err := os.Stat(dir); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("mode = %v, %v", info.Mode(), err)
	}
}

func TestReplaceFileRefusesSymlinkedTarget(t *testing.T) {
	root := t.TempDir()
	victim := filepath.Join(root, "victim.txt")
	testutil.Check(t, os.WriteFile(victim, []byte("ORIGINAL"), 0o600))
	link := filepath.Join(root, "state.json")
	testutil.Check(t, os.Symlink(victim, link))
	if err := ReplaceFile(link, []byte("NEW")); err == nil {
		t.Fatal("ReplaceFile silently converted a symlink into a regular file")
	}
	info, err := os.Lstat(link)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("symlink was destroyed: mode = %v, %v", info.Mode(), err)
	}
	if data, err := os.ReadFile(victim); err != nil || string(data) != "ORIGINAL" {
		t.Fatalf("link target = %q, %v", data, err)
	}
}

func TestReadPrivateFileRefusesSymlinkAndBoundsSize(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "record")
	testutil.Check(t, os.WriteFile(path, []byte("payload"), 0o600))
	if data, err := ReadPrivateFile(path, 64); err != nil || string(data) != "payload" {
		t.Fatalf("ReadPrivateFile = %q, %v", data, err)
	}
	if _, err := ReadPrivateFile(path, 3); err == nil {
		t.Fatal("a file larger than the limit was read")
	}
	link := filepath.Join(root, "link")
	testutil.Check(t, os.Symlink(path, link))
	if _, err := ReadPrivateFile(link, 64); err == nil {
		t.Fatal("ReadPrivateFile followed a symlink")
	}
}

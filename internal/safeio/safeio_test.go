package safeio

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEnsurePrivateDirRefusesSymlinkWithoutChmoddingItsTarget(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "shared")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "state")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := EnsurePrivateDir(link); err == nil {
		t.Fatal("a symlinked directory was accepted as private")
	}
	if info, err := os.Stat(target); err != nil || info.Mode().Perm() != 0o755 {
		t.Fatalf("chmod followed the symlink: mode = %v, %v", info.Mode(), err)
	}
}

func TestEnsurePrivateDirCreatesAndRepairsMode(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state", "nested")
	if err := EnsurePrivateDir(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := EnsurePrivateDir(dir); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(dir); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("mode = %v, %v", info.Mode(), err)
	}
}

func TestReplaceFileRefusesSymlinkedTarget(t *testing.T) {
	root := t.TempDir()
	victim := filepath.Join(root, "victim.txt")
	if err := os.WriteFile(victim, []byte("ORIGINAL"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "state.json")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	if err := ReplaceFile(link, []byte("NEW"), nil); err == nil {
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
	if err := os.WriteFile(path, []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	if data, err := ReadPrivateFile(path, 64); err != nil || string(data) != "payload" {
		t.Fatalf("ReadPrivateFile = %q, %v", data, err)
	}
	if _, err := ReadPrivateFile(path, 3); err == nil {
		t.Fatal("a file larger than the limit was read")
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPrivateFile(link, 64); err == nil {
		t.Fatal("ReadPrivateFile followed a symlink")
	}
}

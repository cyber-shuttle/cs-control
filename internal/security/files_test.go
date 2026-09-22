// Tests the trust boundary against planted symlinks and oversized files.
package security

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/cyber-shuttle/cs-plane/internal/testutil"
)

func TestSecretBoxPersistsKeyAndRejectsTampering(t *testing.T) {
	dir := t.TempDir()
	testutil.Check(t, os.Chmod(dir, 0o700))
	path := filepath.Join(dir, "sealing.key")
	box, err := LoadOrCreateSecretBox(path)
	testutil.Check(t, err)
	sealed, err := box.Seal([]byte("credential"))
	testutil.Check(t, err)
	reloaded, err := LoadOrCreateSecretBox(path)
	testutil.Check(t, err)
	plaintext, err := reloaded.Open(sealed)
	if err != nil || string(plaintext) != "credential" {
		t.Fatalf("opened secret = %q, %v", plaintext, err)
	}
	sealed[len(sealed)-1] ^= 1
	if _, err := reloaded.Open(sealed); err == nil {
		t.Fatal("tampered secret was accepted")
	}
}

func TestConcurrentSecretBoxCreationReturnsThePersistedKey(t *testing.T) {
	dir := t.TempDir()
	testutil.Check(t, os.Chmod(dir, 0o700))
	path := filepath.Join(dir, "sealing.key")
	const workers = 64
	start := make(chan struct{})
	results := make(chan *SecretBox, workers)
	errors := make(chan error, workers)
	var group sync.WaitGroup
	for range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			box, err := LoadOrCreateSecretBox(path)
			results <- box
			errors <- err
		}()
	}
	close(start)
	group.Wait()
	close(results)
	close(errors)
	persisted, err := LoadOrCreateSecretBox(path)
	testutil.Check(t, err)
	for err := range errors {
		testutil.Check(t, err)
	}
	for box := range results {
		if box == nil || *box != *persisted {
			t.Fatal("concurrent caller returned a key other than the persisted key")
		}
	}
}

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

func TestPrivateWritesRefuseSymlinkedTarget(t *testing.T) {
	root := t.TempDir()
	victim := filepath.Join(root, "victim.txt")
	testutil.Check(t, os.WriteFile(victim, []byte("ORIGINAL"), 0o600))
	link := filepath.Join(root, "state.json")
	testutil.Check(t, os.Symlink(victim, link))
	if err := ReplaceFile(link, []byte("NEW")); err == nil {
		t.Fatal("ReplaceFile silently converted a symlink into a regular file")
	}
	if err := WithFileLock(link, func() error { return nil }); err == nil {
		t.Fatal("WithFileLock followed a symlink")
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

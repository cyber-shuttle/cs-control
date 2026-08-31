// Package safeio holds the private-file primitives shared by every subsystem
// that persists state or secrets: the runtime store, the credential store and
// the SSH control directory. The daemon trusts what it wrote under its own
// state directory; only /tmp/csctl-<uid> and a state directory named on the
// command line can be created by anyone else, and those are verified once.
package safeio

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// EnsurePrivateDir creates dir with its parents and holds it at mode 0700.
func EnsurePrivateDir(dir string) (os.FileInfo, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	return os.Lstat(dir)
}

// PrivateDir accepts path only as a real directory this user owns at mode 0700,
// which is what a directory another user could have created first has to prove.
func PrivateDir(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsDir() || info.Mode().Perm() != 0o700 || int(stat.Uid) != os.Getuid() {
		return fmt.Errorf("%s is not a private directory owned by this user", path)
	}
	return nil
}

// SyncDir flushes a directory entry so a completed rename survives a crash.
func SyncDir(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("fsync directory: %w", err)
	}
	return nil
}

// WithFileLock holds an exclusive advisory lock on path for the duration of fn,
// serialising writers across every process that edits the same file.
func WithFileLock(path string, fn func() error) error {
	lock, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN) //nolint:errcheck
	return fn()
}

// ReplaceFile atomically installs data at path with mode 0600. beforeCommit,
// when set, runs after the payload is durable but before the rename.
func ReplaceFile(path string, data []byte, beforeCommit func() error) error {
	dir := filepath.Dir(path)
	temp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	name := temp.Name()
	committed := false
	defer func() {
		_ = temp.Close()
		if !committed {
			_ = os.Remove(name)
		}
	}()
	if err := temp.Chmod(0o600); err != nil {
		return err
	}
	if _, err := temp.Write(data); err != nil {
		return err
	}
	if err := temp.Sync(); err != nil {
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if beforeCommit != nil {
		if err := beforeCommit(); err != nil {
			return err
		}
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	committed = true
	return SyncDir(dir)
}

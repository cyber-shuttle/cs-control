// Package safeio holds the private-file primitives shared by every subsystem
// that persists state or secrets: the runtime store, the credential store and
// the SSH control directory. The daemon trusts what it wrote under its own
// state directory; only /tmp/csctl-<uid> and a state directory named on the
// command line can be created by anyone else, and those are verified once.
package safeio

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// EnsurePrivateDir creates dir with its parents, holds it at mode 0700, and
// returns PrivateDir's verdict, so no caller can proceed on an unverified path.
func EnsurePrivateDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	// chmod follows symlinks, so a swapped path must never reach it.
	if info.Mode().IsDir() && info.Mode().Perm() != 0o700 {
		if err := os.Chmod(dir, 0o700); err != nil {
			return err
		}
	}
	return PrivateDir(dir)
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

// ReadPrivateFile reads a regular file this user owns at mode 0600 or tighter,
// opened without following a final symlink and read no further than limit, so a
// planted link can neither redirect the read nor make it unbounded.
func ReadPrivateFile(path string, limit int64) ([]byte, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || int(stat.Uid) != os.Getuid() || info.Size() > limit {
		return nil, fmt.Errorf("%s is not a private file owned by this user", path)
	}
	return io.ReadAll(io.LimitReader(file, limit))
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
	// Renaming over a symlink destroys the link and orphans its target, so a
	// path that is not already a plain file is refused rather than converted.
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", path)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
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

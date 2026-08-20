// Package safeio holds the private-file primitives shared by every subsystem
// that persists state or secrets: the runtime store, the credential store and
// the SSH control directory.
package safeio

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// EnsurePrivateDir creates dir with its parents and returns it only once it is
// a mode-0700 directory this user owns, reached without traversing a symlink.
func EnsurePrivateDir(dir string) (os.FileInfo, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	// Repair a widened directory, but only once Lstat proves it is a real
	// directory rather than a link: chmod follows symlinks, so a swapped path
	// must never reach it.
	if info.Mode()&os.ModeSymlink == 0 && info.IsDir() && info.Mode().Perm() != 0o700 {
		if err := os.Chmod(dir, 0o700); err != nil {
			return nil, err
		}
	}
	return StatPrivate(dir, Dir, 0o700)
}

// Kind names the file shapes a private artifact is allowed to take.
type Kind uint8

const (
	Dir Kind = 1 << iota
	Regular
	Socket
)

func (k Kind) accepts(mode os.FileMode) bool {
	return mode.IsDir() && k&Dir != 0 ||
		mode.IsRegular() && k&Regular != 0 ||
		mode&os.ModeSocket != 0 && k&Socket != 0
}

// StatPrivate accepts path only when it has one of kinds, was not reached
// through a symlink, is owned by this user and grants nothing to group or
// other. A non-zero perm additionally requires exactly that mode. It is the one
// check every subsystem makes before it reads, replaces or removes a file it
// treats as its own.
func StatPrivate(path string, kinds Kind, perm os.FileMode) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	mode := info.Mode()
	if !ok || mode&os.ModeSymlink != 0 || !kinds.accepts(mode) || mode.Perm()&0o077 != 0 || int(stat.Uid) != os.Getuid() {
		return nil, fmt.Errorf("%s is not a private file owned by this user", path)
	}
	if perm != 0 && mode.Perm() != perm {
		return nil, fmt.Errorf("%s must have mode %o", path, perm)
	}
	return info, nil
}

// OpenNoFollow opens path for reading, refusing to traverse a final symlink.
func OpenNoFollow(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("create file handle")
	}
	return file, nil
}

// SyncDir flushes a directory entry so a completed rename survives a crash.
func SyncDir(path string) error {
	directory, err := OpenNoFollow(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	if info, err := directory.Stat(); err != nil || !info.IsDir() {
		return errors.New("sync target is not a directory")
	}
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

// ReplaceFile atomically installs data at path with mode 0600. Any file already
// there must be a regular file rather than a symlink, so a replaced path can
// never redirect the write. beforeCommit, when set, runs after the payload is
// durable but before the rename, which is where a caller re-checks that the
// directory it validated is still the one being written to.
func ReplaceFile(path string, data []byte, beforeCommit func() error) error {
	dir := filepath.Dir(path)
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("%s is not a regular file", path)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
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

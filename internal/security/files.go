// Private-file primitives shared by every subsystem that persists state or secrets. Directories must belong to
// this user at mode 0700; reads and process locks refuse links, loose modes, and foreign ownership. Replacement
// writes and syncs a mode-0600 temporary file before an atomic rename, then syncs the containing directory.
// Every path is verified when used, never trusted by its history.
package security

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/crypto/nacl/secretbox"
)

type SecretBox [32]byte

func LoadOrCreateSecretBox(path string) (*SecretBox, error) {
	read := func() (*SecretBox, error) {
		data, err := ReadPrivateFile(path, 32)
		if err != nil {
			return nil, err
		}
		if len(data) != 32 {
			return nil, errors.New("secretbox key file is invalid")
		}
		box := SecretBox(data)
		return &box, nil
	}
	box, err := read()
	if err == nil || !errors.Is(err, os.ErrNotExist) {
		return box, err
	}
	dir := filepath.Dir(path)
	if err := PrivateDir(dir); err != nil {
		return nil, err
	}
	var candidate SecretBox
	_, _ = rand.Read(candidate[:])
	name, err := writeTemp(dir, ".secretbox-*", candidate[:])
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.Remove(name) }()
	installed := false
	if err := os.Link(name, path); err == nil {
		installed = true
	} else if !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	if err := os.Remove(name); err != nil {
		return nil, err
	}
	if err := SyncDir(dir); err != nil {
		return nil, err
	}
	if installed {
		return &candidate, nil
	}
	return read()
}

// writeTemp writes data to a new mode-0600 file in dir, synced and closed, and returns its name.
func writeTemp(dir, pattern string, data []byte) (string, error) {
	temp, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return "", err
	}
	name := temp.Name()
	err = errors.Join(temp.Chmod(0o600), func() error { _, err := temp.Write(data); return err }(), temp.Sync(), temp.Close())
	if err != nil {
		_ = os.Remove(name)
		return "", err
	}
	return name, nil
}

// OwnedPrivate reports whether info describes an entry this user owns with no group or world permission bits.
func OwnedPrivate(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && info.Mode().Perm()&0o077 == 0 && int(stat.Uid) == os.Getuid()
}

func (b *SecretBox) Seal(plaintext []byte) ([]byte, error) {
	var nonce [24]byte
	_, _ = rand.Read(nonce[:])
	return secretbox.Seal(nonce[:], plaintext, &nonce, (*[32]byte)(b)), nil
}

func (b *SecretBox) Open(sealed []byte) ([]byte, error) {
	if len(sealed) < 24 {
		return nil, errors.New("sealed secret is truncated")
	}
	var nonce [24]byte
	copy(nonce[:], sealed[:24])
	plaintext, ok := secretbox.Open(nil, sealed[24:], &nonce, (*[32]byte)(b))
	if !ok {
		return nil, errors.New("sealed secret could not be opened")
	}
	return plaintext, nil
}

func PrivateDir(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsDir() || info.Mode().Perm() != 0o700 || !OwnedPrivate(info) {
		return fmt.Errorf("%s is not a private directory owned by this user", path)
	}
	return nil
}

func EnsurePrivateDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if info.Mode().IsDir() && info.Mode().Perm() != 0o700 {
		if err := os.Chmod(dir, 0o700); err != nil {
			return err
		}
	}
	return PrivateDir(dir)
}

func ReadPrivateFile(path string, limit int64) ([]byte, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || !OwnedPrivate(info) || info.Size() > limit {
		return nil, fmt.Errorf("%s is not a private file owned by this user", path)
	}
	return io.ReadAll(io.LimitReader(file, limit))
}

func SyncDir(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("fsync directory: %w", err)
	}
	return nil
}

// OpenLockFile opens or creates a private lock file without following links; the caller flocks its descriptor.
func OpenLockFile(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	lock := os.NewFile(uintptr(fd), path)
	info, err := lock.Stat()
	if err == nil && (!info.Mode().IsRegular() || !OwnedPrivate(info)) {
		err = fmt.Errorf("%s is not a private file owned by this user", path)
	}
	if err != nil {
		_ = lock.Close()
		return nil, err
	}
	return lock, nil
}

func WithFileLock(path string, fn func() error) error {
	lock, err := OpenLockFile(path)
	if err != nil {
		return err
	}
	defer func() { _ = lock.Close() }()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer func() { _ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN) }()
	return fn()
}

func RemoveFile(path string) error {
	if err := os.Remove(path); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	return SyncDir(filepath.Dir(path))
}

func ReplaceFile(path string, data []byte) error {
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", path)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	dir := filepath.Dir(path)
	name, err := writeTemp(dir, ".tmp-*", data)
	if err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		_ = os.Remove(name)
		return err
	}
	return SyncDir(dir)
}

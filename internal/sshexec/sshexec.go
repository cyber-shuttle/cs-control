// Package sshexec runs commands on a remote host over OpenSSH.
// Every entry point resolves the alias's configuration first, which also fingerprints the control socket.
// Under an interactive master, ControlPersist is off, since persist backgrounds the master on authentication.
//
//	Runner, capture, captureStream
//	killGroup, runCommand, newCapture
//	ensurePrivateControlDirectory, authenticationRequired, utf8Request
//	ChildEnv
//	ShellQuote, FailureMessage, AuthenticationFailure, ClassifyFailure
//	RunBounded, RemoveStaleControl, KillGroup, UnlockControl
package sshexec

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cyber-shuttle/cs-control/internal/apierr"
	"github.com/cyber-shuttle/cs-control/internal/safeio"
	"github.com/cyber-shuttle/cs-control/internal/sshconfig"
)

const (
	maxOutput                   = 1 << 20
	maxControlSocketPath        = 100
	openSSHControlSuffixReserve = 18
	controlSocketHashBytes      = 10
	utf8Locale                  = "C.UTF-8"
)

type Runner struct {
	SSHBin           string
	Timeout          time.Duration
	ControlNamespace string
	Hosts            sshconfig.Config
	ControlTempRoot  func() string
}

type capture struct {
	mu        sync.Mutex
	remaining int
	stdout    captureStream
	stderr    captureStream
}

type captureStream struct {
	capture *capture
	buf     bytes.Buffer
}

var authenticationMarkers = []string{
	"permission denied", "host key verification failed", "no supported authentication methods",
	"authentication failed", "keyboard-interactive", "too many authentication failures",
}

var sshTerminateGrace = 500 * time.Millisecond

func killGroup(cmd *exec.Cmd, exited <-chan struct{}) {
	select {
	case <-exited:
		return
	default:
	}
	if syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) != nil {
		_ = cmd.Process.Kill()
	}
	<-exited
}

func runCommand(ctx context.Context, cmd *exec.Cmd) error {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = sshTerminateGrace
	if err := cmd.Start(); err != nil {
		return err
	}
	var waitErr error
	done := make(chan struct{})
	go func() { waitErr = cmd.Wait(); close(done) }()
	select {
	case <-done:
		return waitErr
	case <-ctx.Done():
	}
	killGroup(cmd, done)
	return ctx.Err()
}

func newCapture() *capture {
	c := &capture{remaining: maxOutput}
	c.stdout.capture, c.stderr.capture = c, c
	return c
}

func (c *capture) Stdout() *captureStream { return &c.stdout }

func (c *capture) Stderr() *captureStream { return &c.stderr }

func (s *captureStream) Write(data []byte) (int, error) {
	s.capture.mu.Lock()
	defer s.capture.mu.Unlock()
	if len(data) > s.capture.remaining {
		return len(data), errors.New("command output exceeded limit")
	}
	s.capture.remaining -= len(data)
	return s.buf.Write(data)
}

func (s *captureStream) String() string {
	s.capture.mu.Lock()
	defer s.capture.mu.Unlock()
	return s.buf.String()
}

func ensurePrivateControlDirectory(path string) error {
	if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("create SSH control directory: %w", err)
	}
	if err := safeio.PrivateDir(path); err != nil {
		return fmt.Errorf("SSH control directory must be private: %w", err)
	}
	return nil
}

func authenticationRequired(alias string) error {
	return apierr.New("ssh_authentication_required", "SSH authentication is required for "+alias, 409)
}

func utf8Request(value string) bool {
	upper := strings.ToUpper(value)
	return strings.Contains(upper, "UTF-8") || strings.Contains(upper, "UTF8")
}

func (r Runner) Bin() string { return cmp.Or(r.SSHBin, "ssh") }

func (r Runner) EffectiveTimeout() time.Duration { return cmp.Or(r.Timeout, 20*time.Second) }

func ChildEnv() []string {
	environment := os.Environ()
	for _, name := range []string{"LC_ALL", "LC_CTYPE", "LANG"} {
		if utf8Request(os.Getenv(name)) {
			return environment
		}
	}
	kept := make([]string, 0, len(environment)+1)
	for _, entry := range environment {
		if !strings.HasPrefix(entry, "LC_ALL=") {
			kept = append(kept, entry)
		}
	}
	return append(kept, "LC_ALL="+utf8Locale)
}

func ShellQuote(value string) string { return "'" + strings.ReplaceAll(value, "'", `'"'"'`) + "'" }

func FailureMessage(stderr string, err error) string {
	if message := strings.TrimSpace(stderr); message != "" {
		return message
	}
	if err == nil {
		return ""
	}
	return err.Error()
}

func AuthenticationFailure(message string) bool {
	value := strings.ToLower(message)
	return slices.ContainsFunc(authenticationMarkers, func(marker string) bool { return strings.Contains(value, marker) })
}

func ClassifyFailure(alias, stderr string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("ssh command timed out: %w", err)
	}
	message := FailureMessage(stderr, err)
	if AuthenticationFailure(message) {
		return authenticationRequired(alias)
	}
	return fmt.Errorf("ssh command failed: %s", message)
}

func (r Runner) identity(ctx context.Context, alias string) (string, error) {
	if !sshconfig.ValidAlias(alias) {
		return "", sshconfig.ErrInvalidAlias
	}
	if r.Hosts.UserPath != "" {
		hosts, err := r.Hosts.List()
		if err != nil {
			return "", err
		}
		if !slices.ContainsFunc(hosts, func(host sshconfig.Host) bool { return host.Name == alias }) {
			return "", apierr.New("ssh_host_not_found", "SSH host alias is not configured", 404)
		}
	}

	ctx, cancel := context.WithTimeout(ctx, r.EffectiveTimeout())
	defer cancel()
	args := []string{"-G"}
	if r.Hosts.UserPath != "" {
		args = append(args, "-F", r.Hosts.UserPath)
	}
	cmd := exec.Command(r.Bin(), append(args, alias)...)
	cmd.Env = ChildEnv()
	captured := newCapture()
	cmd.Stdout, cmd.Stderr = captured.Stdout(), captured.Stderr()
	if err := runCommand(ctx, cmd); err != nil {
		if ctx.Err() != nil {
			return "", fmt.Errorf("resolve effective SSH configuration: %w", ctx.Err())
		}
		message := FailureMessage(captured.Stderr().String(), err)
		return "", fmt.Errorf("resolve effective SSH configuration: %s", message)
	}
	identity := strings.ReplaceAll(captured.Stdout().String(), "\r\n", "\n")
	identity = strings.TrimRight(identity, "\n") + "\n"
	if identity == "\n" {
		return "", errors.New("effective SSH configuration is empty")
	}
	return identity, nil
}

func (r Runner) privateControlDirectory(baseName string) (string, error) {
	tempRoot := r.ControlTempRoot
	if tempRoot == nil {
		tempRoot = os.TempDir
	}
	name := fmt.Sprintf("csctl-%d", os.Getuid())
	roots := []string{tempRoot()}
	if filepath.Clean(roots[0]) != "/tmp" {
		roots = append(roots, "/tmp")
	}
	var tooLong []string
	for _, root := range roots {
		if !filepath.IsAbs(root) {
			continue
		}
		directory := filepath.Join(root, name)
		candidate := filepath.Join(directory, baseName)
		if len(candidate)+openSSHControlSuffixReserve > maxControlSocketPath {
			tooLong = append(tooLong, candidate)
			continue
		}
		if err := ensurePrivateControlDirectory(directory); err != nil {
			return "", err
		}
		return directory, nil
	}
	return "", fmt.Errorf("no temporary directory can hold a safe SSH control path: %s", strings.Join(tooLong, ", "))
}

func (r Runner) controlPath(alias, identity string) (string, error) {
	if r.ControlNamespace == "" {
		return "", errors.New("SSH control namespace is not configured")
	}
	if !filepath.IsAbs(r.ControlNamespace) {
		return "", errors.New("SSH control namespace must be absolute")
	}
	if !sshconfig.ValidAlias(alias) {
		return "", sshconfig.ErrInvalidAlias
	}
	hash := sha256.Sum256([]byte(alias + "\x00" + identity + "\x00" + r.ControlNamespace + "\x00" + r.Bin() + "\x00" + r.Hosts.UserPath))
	baseName := "m-" + hex.EncodeToString(hash[:controlSocketHashBytes])
	directory, err := r.privateControlDirectory(baseName)
	if err != nil {
		return "", err
	}
	path := filepath.Join(directory, baseName)
	if len(path)+openSSHControlSuffixReserve > maxControlSocketPath {
		return "", fmt.Errorf("SSH control path is too long (%d > %d)", len(path)+openSSHControlSuffixReserve, maxControlSocketPath)
	}
	return path, nil
}

func (r Runner) sshArgs(alias string, interactive bool, identity string) ([]string, error) {
	batchMode, persist := "yes", "600"
	if interactive {
		batchMode, persist = "no", "no"
	}
	args := []string{
		"-o", "BatchMode=" + batchMode,
		"-o", "ConnectTimeout=10",
		"-o", "ServerAliveInterval=15",
		"-o", "ServerAliveCountMax=3",
	}
	if r.Hosts.UserPath != "" {
		args = append(args, "-F", r.Hosts.UserPath)
	}
	if r.ControlNamespace != "" {
		path, err := r.controlPath(alias, identity)
		if err != nil {
			return nil, err
		}
		args = append(args, "-o", "ControlMaster=auto", "-o", "ControlPersist="+persist, "-o", "ControlPath="+path)
	}
	return append(args, alias), nil
}

func (r Runner) run(ctx context.Context, alias, identity string, stdin io.Reader, remoteArgs ...string) (string, string, error) {
	if len(remoteArgs) == 0 {
		return "", "", errors.New("remote command is required")
	}
	quoted := make([]string, len(remoteArgs))
	for i, argument := range remoteArgs {
		quoted[i] = ShellQuote(argument)
	}
	ctx, cancel := context.WithTimeout(ctx, r.EffectiveTimeout())
	defer cancel()
	args, err := r.sshArgs(alias, false, identity)
	if err != nil {
		return "", "", err
	}
	cmd := exec.Command(r.Bin(), append(args, strings.Join(quoted, " "))...)
	cmd.Env = ChildEnv()
	cmd.Stdin = stdin
	captured := newCapture()
	cmd.Stdout, cmd.Stderr = captured.Stdout(), captured.Stderr()
	runErr := runCommand(ctx, cmd)
	if runErr != nil && ctx.Err() != nil {
		runErr = ctx.Err()
	}
	return captured.Stdout().String(), captured.Stderr().String(), runErr
}

func (r Runner) ControlPath(ctx context.Context, alias string) (string, error) {
	identity, err := r.identity(ctx, alias)
	if err != nil {
		return "", err
	}
	return r.controlPath(alias, identity)
}

func (r Runner) Args(ctx context.Context, alias string, interactive bool) ([]string, error) {
	identity, err := r.identity(ctx, alias)
	if err != nil {
		return nil, err
	}
	return r.sshArgs(alias, interactive, identity)
}

func (r Runner) RunOutput(ctx context.Context, alias string, stdin io.Reader, remoteArgs ...string) (string, string, error) {
	identity, err := r.identity(ctx, alias)
	if err != nil {
		return "", "", err
	}
	return r.run(ctx, alias, identity, stdin, remoteArgs...)
}

func (r Runner) Run(ctx context.Context, alias string, stdin io.Reader, remoteArgs ...string) (string, error) {
	stdout, stderr, err := r.RunOutput(ctx, alias, stdin, remoteArgs...)
	if err == nil {
		return stdout, nil
	}
	return stdout, ClassifyFailure(alias, stderr, err)
}

func (r Runner) Command(ctx context.Context, alias string, remote ...string) (*exec.Cmd, error) {
	identity, err := r.identity(ctx, alias)
	if err != nil {
		return nil, err
	}
	args, err := r.sshArgs(alias, false, identity)
	if err != nil {
		return nil, err
	}
	command := exec.Command(r.Bin(), append(args, remote...)...)
	command.Env = ChildEnv()
	return command, nil
}

func (r Runner) MasterHealthy(alias, path string) bool {
	info, err := os.Lstat(path)
	if err != nil {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm()&0o077 != 0 || int(stat.Uid) != os.Getuid() {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), r.EffectiveTimeout())
	defer cancel()
	args := []string{"-S", path, "-O", "check"}
	if r.Hosts.UserPath != "" {
		args = append(args, "-F", r.Hosts.UserPath)
	}
	cmd := exec.CommandContext(ctx, r.Bin(), append(args, alias)...)
	cmd.Env = ChildEnv()
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	return cmd.Run() == nil
}

func (r Runner) AcquireControlLock(ctx context.Context, alias, path string) (*os.File, bool, error) {
	lockPath := path + ".lock"
	fd, err := syscall.Open(lockPath, syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, false, err
	}
	lock := os.NewFile(uintptr(fd), lockPath)
	if lock == nil {
		_ = syscall.Close(fd)
		return nil, false, errors.New("open SSH control lock")
	}
	for {
		if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err == nil {
			return lock, r.MasterHealthy(alias, path), nil
		} else if !errors.Is(err, syscall.EWOULDBLOCK) {
			_ = lock.Close()
			return nil, false, err
		}
		if r.MasterHealthy(alias, path) {
			_ = lock.Close()
			return nil, true, nil
		}
		select {
		case <-ctx.Done():
			_ = lock.Close()
			return nil, false, ctx.Err()
		case <-time.After(25 * time.Millisecond):
		}
	}
}

func RunBounded(ctx context.Context, cmd *exec.Cmd) (string, string, error) {
	captured := newCapture()
	cmd.Stdout, cmd.Stderr = captured.Stdout(), captured.Stderr()
	err := runCommand(ctx, cmd)
	return captured.Stdout().String(), captured.Stderr().String(), err
}

func RemoveStaleControl(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func KillGroup(cmd *exec.Cmd, exited <-chan struct{}) { killGroup(cmd, exited) }

func UnlockControl(lock *os.File) {
	if lock != nil {
		_ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
		_ = lock.Close()
	}
}

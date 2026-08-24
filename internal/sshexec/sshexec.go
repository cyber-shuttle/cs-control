// Package sshexec runs commands on a remote host over OpenSSH. It owns the
// argument vectors, the multiplexed control socket and the bounded capture of
// remote output, so no subsystem above it ever builds an ssh command itself.
package sshexec

import (
	"bytes"
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
	"unicode/utf8"

	"github.com/cyber-shuttle/cs-control/internal/apierr"
	"github.com/cyber-shuttle/cs-control/internal/proc"
	"github.com/cyber-shuttle/cs-control/internal/safeio"
	"github.com/cyber-shuttle/cs-control/internal/sshconfig"
)

const (
	MaxOutput                   = 1 << 20
	maxControlSocketPath        = 100
	openSSHControlSuffixReserve = 18
	controlSocketHashBytes      = 10
)

// ControlTempRoot is replaced in tests that need a short, predictable control
// directory.
var ControlTempRoot = os.TempDir

// Runner executes commands on a remote host. Hosts supplies the alias lookup
// that rejects an alias the user has not configured.
type Runner struct {
	SSHBin     string
	Timeout    time.Duration
	ControlDir string
	Hosts      sshconfig.Config
}

type limitBuffer struct {
	buf bytes.Buffer
	n   int
}

func (r Runner) Bin() string {
	if r.SSHBin != "" {
		return r.SSHBin
	}
	return "ssh"
}

func (r Runner) EffectiveTimeout() time.Duration {
	if r.Timeout > 0 {
		return r.Timeout
	}
	return 20 * time.Second
}

func (r Runner) sshBaseArgs(batchMode string) []string {
	return []string{
		"-o", "BatchMode=" + batchMode,
		"-o", "ConnectTimeout=10",
		"-o", "ServerAliveInterval=15",
		"-o", "ServerAliveCountMax=3",
	}
}

func (r Runner) sshArgs(alias string, interactive bool, identity string) ([]string, error) {
	if !sshconfig.ValidAlias(alias) {
		return nil, sshconfig.ErrInvalidAlias
	}
	batchMode, persist := "yes", "600"
	if interactive {
		// An interactive master is owned by the process that starts it, and
		// ControlPersist takes that ownership away: OpenSSH backgrounds the
		// master the moment it authenticates and the foreground exits 0, which
		// reads as an exit before readiness and leaves a master nothing can
		// reap. Without it the foreground process is the master.
		batchMode, persist = "no", "no"
	}
	args := r.sshBaseArgs(batchMode)
	if r.ControlDir != "" {
		path, err := r.controlPath(alias, identity)
		if err != nil {
			return nil, err
		}
		args = append(args, "-o", "ControlMaster=auto", "-o", "ControlPersist="+persist, "-o", "ControlPath="+path)
	}
	return append(args, alias), nil
}

// RunCommand owns a process group so cancellation also terminates ProxyCommand
// and other descendants. WaitDelay closes inherited pipes held by descendants.
func RunCommand(ctx context.Context, cmd *exec.Cmd) error {
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
	proc.TerminateGroup(cmd, done, sshTerminateGrace)
	return ctx.Err()
}

// Every entry point lands here, so argument quoting, output bounding and
// failure classification exist in exactly one place.
func (r Runner) run(ctx context.Context, alias, identity string, stdin io.Reader, remoteArgs ...string) (string, error) {
	if len(remoteArgs) == 0 {
		return "", errors.New("remote command is required")
	}
	quoted := make([]string, len(remoteArgs))
	for i, argument := range remoteArgs {
		if argument == "" || strings.ContainsAny(argument, "\x00\r\n") {
			return "", errors.New("invalid remote command argument")
		}
		quoted[i] = ShellQuote(argument)
	}
	ctx, cancel := context.WithTimeout(ctx, r.EffectiveTimeout())
	defer cancel()
	args, err := r.sshArgs(alias, false, identity)
	if err != nil {
		return "", err
	}
	args = append(args, strings.Join(quoted, " "))
	cmd := exec.Command(r.Bin(), args...)
	cmd.Env = ChildEnv()
	cmd.Stdin = stdin
	captured := &Output{remaining: MaxOutput}
	cmd.Stdout = &commandStream{output: captured, name: "stdout"}
	cmd.Stderr = &commandStream{output: captured, name: "stderr"}
	runErr := RunCommand(ctx, cmd)
	stdout := captured.stdout.String()
	if runErr == nil {
		return stdout, nil
	}
	if ctx.Err() != nil {
		return stdout, fmt.Errorf("ssh command timed out: %w", ctx.Err())
	}
	message := strings.TrimSpace(captured.stderr.String())
	if message == "" {
		message = runErr.Error()
	}
	if AuthenticationFailure(message) {
		return stdout, AuthenticationRequired(alias)
	}
	return stdout, fmt.Errorf("ssh command failed: %s", message)
}

type Output struct {
	mu        sync.Mutex
	remaining int
	stdout    bytes.Buffer
	stderr    bytes.Buffer
}

type commandStream struct {
	output *Output
	name   string
}

func (r Runner) controlPath(alias, identity string) (string, error) {
	if r.ControlDir == "" {
		return "", errors.New("SSH control namespace is not configured")
	}
	if !filepath.IsAbs(r.ControlDir) {
		return "", errors.New("SSH control namespace must be absolute")
	}
	if !sshconfig.ValidAlias(alias) {
		return "", sshconfig.ErrInvalidAlias
	}
	// ControlDir is a stable namespace (normally the state directory), not the
	// socket location. OpenSSH appends a temporary suffix while binding, and
	// macOS has a particularly small AF_UNIX path limit.
	hash := sha256.Sum256([]byte(alias + "\x00" + identity + "\x00" + r.ControlDir + "\x00" + r.Bin()))
	baseName := "m-" + hex.EncodeToString(hash[:controlSocketHashBytes])
	directory, err := PrivateControlDirectory(baseName)
	if err != nil {
		return "", err
	}
	path := filepath.Join(directory, baseName)
	if len(path)+openSSHControlSuffixReserve > maxControlSocketPath {
		return "", fmt.Errorf("SSH control path is too long (%d > %d)", len(path)+openSSHControlSuffixReserve, maxControlSocketPath)
	}
	return path, nil
}

func PrivateControlDirectory(baseName string) (string, error) {
	name := fmt.Sprintf("csctl-%d", os.Getuid())
	roots := []string{ControlTempRoot()}
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

func ensurePrivateControlDirectory(path string) error {
	if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("create SSH control directory: %w", err)
	}
	if _, err := safeio.StatPrivate(path, safeio.Dir, 0o700); err != nil {
		return fmt.Errorf("SSH control directory must be private: %w", err)
	}
	return nil
}

// validateControlArtifact accepts a control path that is absent, or present as
// a private owned file or socket.
func validateControlArtifact(path string, allowSocket bool) error {
	kinds := safeio.Regular
	if allowSocket {
		kinds |= safeio.Socket
	}
	if _, err := safeio.StatPrivate(path, kinds, 0); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("SSH control artifact is not a private owned file or socket")
	}
	return nil
}

func RemoveStaleControl(path string) error {
	if err := validateControlArtifact(path, true); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// AuthenticationRequired is the refusal every subsystem returns when a remote
// host asks for interactive credentials, so the browser sees one code.
func AuthenticationRequired(alias string) error {
	return apierr.New("ssh_authentication_required", "SSH authentication is required for "+alias, 409)
}

func AuthenticationFailure(message string) bool {
	value := strings.ToLower(message)
	for _, marker := range []string{"permission denied", "host key verification failed", "no supported authentication methods", "authentication failed", "keyboard-interactive", "too many authentication failures"} {
		if strings.Contains(value, marker) {
			return true
		}
	}
	return false
}

func (runner Runner) MasterHealthy(alias, path string) bool {
	if _, err := safeio.StatPrivate(path, safeio.Socket, 0); err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, runner.Bin(), "-S", path, "-O", "check", alias)
	cmd.Env = ChildEnv()
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	return cmd.Run() == nil
}

func (runner Runner) AcquireControlLock(ctx context.Context, alias, path string) (*os.File, bool, error) {
	lockPath := path + ".lock"
	if err := validateControlArtifact(lockPath, false); err != nil {
		return nil, false, err
	}
	fd, err := syscall.Open(lockPath, syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, false, err
	}
	lock := os.NewFile(uintptr(fd), lockPath)
	if lock == nil {
		_ = syscall.Close(fd)
		return nil, false, errors.New("open SSH control lock")
	}
	if err := validateControlArtifact(lockPath, false); err != nil {
		_ = lock.Close()
		return nil, false, err
	}
	for {
		if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err == nil {
			return lock, runner.MasterHealthy(alias, path), nil
		} else if !errors.Is(err, syscall.EWOULDBLOCK) {
			_ = lock.Close()
			return nil, false, err
		}
		// Another process owns startup/lifecycle. Reuse its master once healthy,
		// but never claim or terminate it.
		if runner.MasterHealthy(alias, path) {
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

func UnlockControl(lock *os.File) {
	if lock != nil {
		_ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
		_ = lock.Close()
	}
}

func (b *limitBuffer) Write(p []byte) (int, error) {
	if b.buf.Len()+len(p) > b.n {
		remain := b.n - b.buf.Len()
		if remain > 0 {
			_, _ = b.buf.Write(p[:remain])
		}
		return len(p), errors.New("command output exceeded limit")
	}
	return b.buf.Write(p)
}

func (b *limitBuffer) String() string { return b.buf.String() }

func (s *commandStream) Write(data []byte) (int, error) {
	s.output.mu.Lock()
	if len(data) > s.output.remaining {
		s.output.mu.Unlock()
		return len(data), errors.New("command output exceeded limit")
	}
	s.output.remaining -= len(data)
	buffer := &s.output.stdout
	if s.name == "stderr" {
		buffer = &s.output.stderr
	}
	_, _ = buffer.Write(data)
	s.output.mu.Unlock()
	return len(data), nil
}

// Buffers one stream so a failure can be classified after the fact without
// retaining unbounded remote output.
func NewBoundedCapture(name string) *BoundedCapture {
	output := &Output{remaining: MaxOutput}
	return &BoundedCapture{stream: &commandStream{output: output, name: name}, output: output}
}

type BoundedCapture struct {
	stream *commandStream
	output *Output
}

func (c *BoundedCapture) Write(data []byte) (int, error) { return c.stream.Write(data) }

func (c *BoundedCapture) String() string {
	c.output.mu.Lock()
	defer c.output.mu.Unlock()
	if c.stream.name == "stderr" {
		return c.output.stderr.String()
	}
	return c.output.stdout.String()
}

var sshTerminateGrace = 500 * time.Millisecond

func ShellQuote(value string) string { return "'" + strings.ReplaceAll(value, "'", `'"'"'`) + "'" }

// Identity is the effective SSH configuration for alias, the fingerprint that
// keys its control socket. A hand-edited config therefore yields a new socket
// rather than reusing one pointed at the old host.
func (r Runner) Identity(ctx context.Context, alias string) (string, error) {
	if !sshconfig.ValidAlias(alias) {
		return "", sshconfig.ErrInvalidAlias
	}
	if r.Hosts.UserPath != "" || r.Hosts.SystemPath != "" {
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
	cmd := exec.Command(r.Bin(), "-G", alias)
	cmd.Env = ChildEnv()
	output := &Output{remaining: MaxOutput}
	// Effective configuration contains identity and socket paths. Buffer stdout
	// for the connection fingerprint but expose only diagnostics from stderr.
	cmd.Stdout = &commandStream{output: output, name: "stdout"}
	cmd.Stderr = &commandStream{output: output, name: "stderr"}
	if err := RunCommand(ctx, cmd); err != nil {
		if ctx.Err() != nil {
			return "", fmt.Errorf("resolve effective SSH configuration: %w", ctx.Err())
		}
		message := strings.TrimSpace(output.stderr.String())
		if message == "" {
			message = err.Error()
		}
		return "", fmt.Errorf("resolve effective SSH configuration: %s", message)
	}
	identity := strings.ReplaceAll(output.stdout.String(), "\r\n", "\n")
	identity = strings.TrimRight(identity, "\n") + "\n"
	if identity == "\n" || !utf8.ValidString(identity) || strings.ContainsRune(identity, '\x00') {
		return "", errors.New("effective SSH configuration is empty or unsafe")
	}
	return identity, nil
}

func (r Runner) ControlPath(ctx context.Context, alias string) (string, error) {
	identity, err := r.Identity(ctx, alias)
	if err != nil {
		return "", err
	}
	return r.controlPath(alias, identity)
}

func (r Runner) Args(ctx context.Context, alias string, interactive bool) ([]string, error) {
	identity, err := r.Identity(ctx, alias)
	if err != nil {
		return nil, err
	}
	return r.sshArgs(alias, interactive, identity)
}

// Arguments are passed as a fixed vector, never a shell string.
func (r Runner) Run(ctx context.Context, alias string, stdin io.Reader, remoteArgs ...string) (string, error) {
	identity, err := r.Identity(ctx, alias)
	if err != nil {
		return "", err
	}
	return r.run(ctx, alias, identity, stdin, remoteArgs...)
}

// How a subsystem that needs its own stdin or output sinks gets one without
// assembling an ssh command line of its own.
func (r Runner) Command(ctx context.Context, alias string, remote ...string) (*exec.Cmd, error) {
	identity, err := r.Identity(ctx, alias)
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

// Bounded so no remote host can exhaust memory through its output.
func RunBounded(ctx context.Context, cmd *exec.Cmd) (string, string, error) {
	stdout, stderr := &limitBuffer{n: MaxOutput}, &limitBuffer{n: MaxOutput}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	err := RunCommand(ctx, cmd)
	return stdout.String(), stderr.String(), err
}

// utf8Locale is a request for UTF-8 character classification and no language,
// which is what a service wants: it fixes what is legible without importing a
// language's collation or message catalogue.
const utf8Locale = "C.UTF-8"

// ChildEnv is the environment every ssh cs-control starts runs in.
//
// OpenSSH passes text a remote host sends -- keyboard-interactive prompts,
// banners, its own diagnostics about them -- through vis(3), which renders
// anything the current locale calls unprintable as an octal escape. A service
// inherits no locale at all: launchd and systemd both start one with an empty
// environment. Under the C locale that results, every non-ASCII byte becomes
// "\342\226\210", so a prompt drawn in UTF-8 block characters -- a QR code, a
// box-drawn banner -- reaches the browser as unreadable octal text.
//
// Control characters stay escaped whatever the locale, so this changes what is
// legible, not what is safe. A locale that already asks for UTF-8 is left alone.
func ChildEnv() []string {
	environment := os.Environ()
	for _, name := range []string{"LC_ALL", "LC_CTYPE", "LANG"} {
		if value := os.Getenv(name); value != "" {
			if strings.Contains(strings.ToUpper(value), "UTF-8") || strings.Contains(strings.ToUpper(value), "UTF8") {
				return environment
			}
		}
	}
	return append(environment, "LC_ALL="+utf8Locale)
}

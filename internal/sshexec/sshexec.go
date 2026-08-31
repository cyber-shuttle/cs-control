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

	"github.com/cyber-shuttle/cs-control/internal/apierr"
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
	KillGroup(cmd, done)
	return ctx.Err()
}

// KillGroup ends cmd's process group and returns once the caller's Wait has.
// exited must be closed by that Wait: a closed channel is what keeps an already
// reaped, reusable PID from being signalled.
//
// ponytail: SIGKILL the group outright -- OpenSSH forwards no signal to the
// remote command, so a TERM-first grace buys nothing; revisit if a killed client
// ever leaves remote state half-written.
func KillGroup(cmd *exec.Cmd, exited <-chan struct{}) {
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

// Every entry point lands here, so argument quoting and output bounding exist in
// exactly one place.
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
	captured := NewCapture()
	cmd.Stdout, cmd.Stderr = captured.Stdout(), captured.Stderr()
	runErr := RunCommand(ctx, cmd)
	if runErr != nil && ctx.Err() != nil {
		runErr = ctx.Err()
	}
	return captured.Stdout().String(), captured.Stderr().String(), runErr
}

// ClassifyFailure is the one reading every subsystem gives a failed ssh
// invocation: a timeout, an authentication demand, or what the host said.
func ClassifyFailure(alias, stderr string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("ssh command timed out: %w", err)
	}
	message := FailureMessage(stderr, err)
	if AuthenticationFailure(message) {
		return AuthenticationRequired(alias)
	}
	return fmt.Errorf("ssh command failed: %s", message)
}

// Capture bounds one command's output: its streams share a MaxOutput budget, so
// no remote host can exhaust memory through either.
type Capture struct {
	mu        sync.Mutex
	remaining int
	stdout    CaptureStream
	stderr    CaptureStream
}

// CaptureStream is one stream of a Capture: the sink a command writes through
// and what it accumulated.
type CaptureStream struct {
	capture *Capture
	buf     bytes.Buffer
}

func NewCapture() *Capture {
	capture := &Capture{remaining: MaxOutput}
	capture.stdout.capture, capture.stderr.capture = capture, capture
	return capture
}

func (c *Capture) Stdout() *CaptureStream { return &c.stdout }

func (c *Capture) Stderr() *CaptureStream { return &c.stderr }

func (s *CaptureStream) Write(data []byte) (int, error) {
	s.capture.mu.Lock()
	defer s.capture.mu.Unlock()
	if len(data) > s.capture.remaining {
		return len(data), errors.New("command output exceeded limit")
	}
	s.capture.remaining -= len(data)
	return s.buf.Write(data)
}

func (s *CaptureStream) String() string {
	s.capture.mu.Lock()
	defer s.capture.mu.Unlock()
	return s.buf.String()
}

// NewBoundedCapture buffers a single stream so a failure can be classified after
// the fact without retaining unbounded remote output.
func NewBoundedCapture(name string) *CaptureStream {
	if name == "stderr" {
		return NewCapture().Stderr()
	}
	return NewCapture().Stdout()
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
	if err := safeio.PrivateDir(path); err != nil {
		return fmt.Errorf("SSH control directory must be private: %w", err)
	}
	return nil
}

func RemoveStaleControl(path string) error {
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
	// ServeWebSocket polls this every 50 ms while a user authenticates, so the
	// stat keeps a missing socket from forking ssh on every tick.
	if _, err := os.Lstat(path); err != nil {
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
	captured := NewCapture()
	// Effective configuration contains identity and socket paths. Buffer stdout
	// for the connection fingerprint but expose only diagnostics from stderr.
	cmd.Stdout, cmd.Stderr = captured.Stdout(), captured.Stderr()
	if err := RunCommand(ctx, cmd); err != nil {
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
	stdout, stderr, err := r.RunOutput(ctx, alias, stdin, remoteArgs...)
	if err == nil {
		return stdout, nil
	}
	return stdout, ClassifyFailure(alias, stderr, err)
}

// RunOutput is Run for a caller that reads stderr or the exit status itself. It
// returns the process error unclassified; ClassifyFailure turns it into the
// refusal the browser sees.
func (r Runner) RunOutput(ctx context.Context, alias string, stdin io.Reader, remoteArgs ...string) (string, string, error) {
	identity, err := r.Identity(ctx, alias)
	if err != nil {
		return "", "", err
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
	captured := NewCapture()
	cmd.Stdout, cmd.Stderr = captured.Stdout(), captured.Stderr()
	err := RunCommand(ctx, cmd)
	return captured.Stdout().String(), captured.Stderr().String(), err
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
		if utf8Request(os.Getenv(name)) {
			return environment
		}
	}
	// LC_ALL has to replace what is there, not sit after it: a duplicate name
	// reaches execve twice, and glibc answers getenv with the first copy while
	// macOS answers with the last. Appending alone therefore fixes this on a Mac
	// and leaves it broken on the Linux hosts this actually runs on.
	kept := make([]string, 0, len(environment)+1)
	for _, entry := range environment {
		if !strings.HasPrefix(entry, "LC_ALL=") {
			kept = append(kept, entry)
		}
	}
	return append(kept, "LC_ALL="+utf8Locale)
}

// utf8Request reports whether a locale name asks for UTF-8 character
// classification, which is all this needs from it.
func utf8Request(value string) bool {
	upper := strings.ToUpper(value)
	return strings.Contains(upper, "UTF-8") || strings.Contains(upper, "UTF8")
}

// FailureMessage is what a failed remote command has to say for itself: its
// stderr, or the process error when stderr said nothing.
func FailureMessage(stderr string, err error) string {
	if message := strings.TrimSpace(stderr); message != "" {
		return message
	}
	if err == nil {
		return ""
	}
	return err.Error()
}

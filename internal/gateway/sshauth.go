// Package gateway serves the interactive SSH authentication WebSocket, whose
// prompt establishes a multiplexed control master. It runs commands only
// through sshexec and has no view of the runtime domain.
package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/creack/pty"
	"github.com/cyber-shuttle/cs-control/internal/apierr"
	"github.com/cyber-shuttle/cs-control/internal/authn"
	"github.com/cyber-shuttle/cs-control/internal/httpx"
	"github.com/cyber-shuttle/cs-control/internal/proc"
	"github.com/cyber-shuttle/cs-control/internal/sshexec"
	"github.com/gorilla/websocket"
)

// controlUpgrader serves both routes. Requests have already passed the
// exact-origin OAuth boundary.
var controlUpgrader = newUpgrader(authn.ControlWebSocketProtocol)

const (
	maxAuthFrame       = 64 << 10
	maxAuthInput       = 32 << 10
	maxQueuedAuthInput = 64 << 10

	ptyInitialCols = 100
	ptyInitialRows = 30
	ptyMinCols     = 20
	ptyMaxCols     = 500
	ptyMinRows     = 5
	ptyMaxRows     = 200
)

var (
	authWriteTimeout = 5 * time.Second
	// Answering a second factor leaves this connection with nothing to carry for
	// as long as the person takes, and an idle WebSocket is the first thing a
	// proxy between the browser and here closes. The keep-alive is what makes a
	// slow approval survive the wait.
	authKeepAlive = 20 * time.Second
)

type authInputOp struct {
	data   []byte
	resize *clientFrame
}

type authSession struct {
	alias       string
	controlPath string
	ctx         context.Context
	cancel      context.CancelFunc
	done        chan struct{}

	mu       sync.Mutex
	finished bool
	owned    bool
	cmd      *exec.Cmd
	master   *os.File
	conn     *websocket.Conn
	waitDone chan struct{}
	waitErr  error
	lock     *os.File
}

type ownedMaster struct {
	alias    string
	path     string
	lock     *os.File
	cmd      *exec.Cmd
	master   *os.File
	waitDone chan struct{}
}

type SSHAuthManager struct {
	runner sshexec.Runner
	ctx    context.Context
	cancel context.CancelFunc
	mu     sync.Mutex
	closed bool
	active map[string]*authSession
	owned  map[string]*ownedMaster
	wg     sync.WaitGroup
}

func NewSSHAuthManager(runner sshexec.Runner) *SSHAuthManager {
	ctx, cancel := context.WithCancel(context.Background())
	return &SSHAuthManager{runner: runner, ctx: ctx, cancel: cancel, active: map[string]*authSession{}, owned: map[string]*ownedMaster{}}
}

func (m *SSHAuthManager) admit(alias string) (*authSession, error) {
	// Reject a duplicate alias before resolving `ssh -G`. Resolution may invoke
	// helpers and take seconds; without this early guard a second WebSocket can
	// wait for teardown and then unexpectedly become a new authentication.
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil, apierr.New("service_stopping", "SSH authentication service is stopping", 503)
	}
	for _, active := range m.active {
		if active.alias == alias {
			m.mu.Unlock()
			return nil, apierr.New("ssh_authentication_in_progress", "SSH authentication is already in progress for "+alias, 409)
		}
	}
	m.mu.Unlock()

	path, err := m.runner.ControlPath(m.ctx, alias)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, apierr.New("service_stopping", "SSH authentication service is stopping", 503)
	}
	// Recheck after the unlocked effective-configuration lookup.
	for _, active := range m.active {
		if active.alias == alias || active.controlPath == path {
			return nil, apierr.New("ssh_authentication_in_progress", "SSH authentication is already in progress for "+alias, 409)
		}
	}
	ctx, cancel := context.WithCancel(m.ctx)
	session := &authSession{alias: alias, controlPath: path, ctx: ctx, cancel: cancel, done: make(chan struct{})}
	m.active[path] = session
	m.wg.Add(1)
	return session, nil
}

func (m *SSHAuthManager) finish(session *authSession, own bool) bool {
	m.mu.Lock()
	session.mu.Lock()
	if session.finished {
		owned := session.owned
		session.mu.Unlock()
		m.mu.Unlock()
		return owned
	}
	// A successful process may race with shutdown. Do not publish ownership
	// after Close; let the caller reap the exact process while retaining its lock.
	if own && (m.closed || session.cmd == nil || session.waitDone == nil) {
		session.mu.Unlock()
		m.mu.Unlock()
		return false
	}
	session.finished, session.owned = true, own
	if m.active[session.controlPath] == session {
		delete(m.active, session.controlPath)
	}
	if own {
		m.owned[session.controlPath] = &ownedMaster{
			alias: session.alias, path: session.controlPath, lock: session.lock,
			cmd: session.cmd, master: session.master, waitDone: session.waitDone,
		}
		session.lock = nil
	}
	session.mu.Unlock()
	m.mu.Unlock()
	sshexec.UnlockControl(session.lock)
	session.lock = nil
	close(session.done)
	m.wg.Done()
	return own
}

func (m *SSHAuthManager) command(session *authSession) (*exec.Cmd, bool, error) {
	// A manager keeps the lifecycle flock for masters it created. If OpenSSH's
	// ControlPersist process expires, that lock outlives the socket and would
	// otherwise make the next authentication wait forever on itself.
	if healthy, err := m.reclaimExpiredOwned(session.alias, session.controlPath); err != nil || healthy {
		return nil, healthy, err
	}
	lock, healthy, err := m.runner.AcquireControlLock(session.ctx, session.alias, session.controlPath)
	if err != nil {
		return nil, false, err
	}
	session.lock = lock
	if healthy {
		return nil, true, nil
	}
	if err := sshexec.RemoveStaleControl(session.controlPath); err != nil {
		return nil, false, err
	}
	args, err := m.runner.Args(session.ctx, session.alias, true)
	if err != nil {
		return nil, false, err
	}
	// Authenticate and persist only. Keeping every option before the host and
	// using -N/-T means OpenSSH never starts a remote shell, command, or PTY, so
	// shell startup files, MOTD, and module output cannot pollute this prompt.
	host := args[len(args)-1]
	options := []string{"-q", "-T", "-N", "-o", "LogLevel=ERROR"}
	args = append(args[:len(args)-1], append(options, host)...)
	cmd := exec.Command(m.runner.Bin(), args...)
	cmd.Env = os.Environ()
	return cmd, false, nil
}

func (s *authSession) assignConnection(conn *websocket.Conn) {
	s.mu.Lock()
	s.conn = conn
	s.mu.Unlock()
}

func (s *authSession) assign(cmd *exec.Cmd, master *os.File, waitDone chan struct{}) {
	s.mu.Lock()
	s.cmd, s.master, s.waitDone = cmd, master, waitDone
	s.mu.Unlock()
}

func (s *authSession) closeIO() {
	s.mu.Lock()
	conn, master := s.conn, s.master
	s.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
	if master != nil {
		_ = master.Close()
	}
}

var authTerminateGrace = 2 * time.Second

// stopAndReap ends a session that never became an owned master. A closed
// waitDone already tells TerminateGroup the process was reaped, so this needs no
// record of its own.
func stopAndReap(session *authSession) {
	session.mu.Lock()
	cmd, master, waitDone := session.cmd, session.master, session.waitDone
	session.mu.Unlock()
	if master != nil {
		_ = master.Close()
	}
	if cmd == nil || cmd.Process == nil || waitDone == nil {
		return
	}
	proc.TerminateGroup(cmd, waitDone, authTerminateGrace)
}

func closeMaster(master *ownedMaster) {
	if master == nil {
		return
	}
	// Server-owned authentication keeps the foreground OpenSSH process. Kill
	// and reap that exact process group; never address or unlink whatever may
	// currently occupy its former ControlPath.
	proc.TerminateGroup(master.cmd, master.waitDone, authTerminateGrace)
	if master.master != nil {
		_ = master.master.Close()
	}
	sshexec.UnlockControl(master.lock)
}

// reclaimExpiredOwned returns true while this manager's exact foreground
// master remains alive and its socket answers. A dead/unhealthy owned process
// is reaped and its lifecycle lock released before startup retries. The stale
// socket is deliberately left for locked startup cleanup; a foreign healthy
// socket is reused later but is never claimed or terminated by this manager.
func (m *SSHAuthManager) reclaimExpiredOwned(alias, path string) (bool, error) {
	m.mu.Lock()
	master := m.owned[path]
	if master == nil {
		m.mu.Unlock()
		return false, nil
	}
	if master.alias != alias {
		m.mu.Unlock()
		return false, errors.New("SSH control master identity mismatch")
	}
	select {
	case <-master.waitDone:
		delete(m.owned, path)
		m.mu.Unlock()
		if master.master != nil {
			_ = master.master.Close()
		}
		sshexec.UnlockControl(master.lock)
		return false, nil
	default:
	}
	if m.runner.MasterHealthy(alias, path) {
		m.mu.Unlock()
		return true, nil
	}
	delete(m.owned, path)
	m.mu.Unlock()
	closeMaster(master)
	return false, nil
}

func cleanupFailedSession(session *authSession) {
	stopAndReap(session)
	if session.lock != nil {
		// Failed startup owns no persistent process. Release the startup lock;
		// stale-path removal belongs only to the next exclusive startup.
		sshexec.UnlockControl(session.lock)
		session.lock = nil
	}
}

func (m *SSHAuthManager) ServeWebSocket(writer http.ResponseWriter, request *http.Request, alias string) {
	session, err := m.admit(alias)
	if err != nil {
		httpx.WriteError(writer, err)
		return
	}
	finished := false
	defer func() {
		if !finished {
			cleanupFailedSession(session)
			m.finish(session, false)
		}
	}()

	conn, err := controlUpgrader.Upgrade(writer, request, nil)
	if err != nil {
		return
	}
	session.assignConnection(conn)
	defer conn.Close()
	conn.SetReadLimit(maxAuthFrame)

	cmd, alreadyReady, err := m.command(session)
	if err != nil {
		_ = writeJSON(conn, authWriteTimeout, exitFrame(1, "failed to prepare SSH"))
		return
	}
	if alreadyReady {
		_ = writeJSON(conn, authWriteTimeout, serverFrame{Type: "ready"})
		_ = writeJSON(conn, authWriteTimeout, exitFrame(0, ""))
		finished = true
		m.finish(session, false)
		return
	}
	select {
	case <-session.ctx.Done():
		return
	default:
	}
	master, err := pty.StartWithSize(cmd, &pty.Winsize{Cols: ptyInitialCols, Rows: ptyInitialRows})
	if err != nil {
		_ = writeJSON(conn, authWriteTimeout, exitFrame(1, "failed to start SSH"))
		return
	}
	waitDone := make(chan struct{})
	go func() {
		err := cmd.Wait()
		session.mu.Lock()
		session.waitErr = err
		session.mu.Unlock()
		close(waitDone)
	}()
	session.assign(cmd, master, waitDone)

	output := make(chan []byte, 8)
	go pumpPTY(session.ctx, master, output, 16<<10)
	input := make(chan authInputOp, maxQueuedAuthInput/maxAuthInput)
	clientGone := make(chan struct{})
	go func() {
		defer close(clientGone)
		for {
			messageType, data, err := conn.ReadMessage()
			if err != nil {
				return
			}
			switch messageType {
			case websocket.BinaryMessage:
				if len(data) > maxAuthInput {
					session.cancel()
					return
				}
				select {
				case input <- authInputOp{data: data}:
				case <-session.ctx.Done():
					return
				default:
					// A client may not queue unbounded credentials or terminal input.
					session.cancel()
					return
				}
			case websocket.TextMessage:
				var frame clientFrame
				if err := json.Unmarshal(data, &frame); err != nil {
					return
				}
				if frame.Type != "resize" {
					continue
				}
				select {
				case input <- authInputOp{resize: &frame}:
				case <-session.ctx.Done():
					return
				default:
					session.cancel()
					return
				}
			default:
				session.cancel()
				return
			}
		}
	}()
	inputWriterDone := make(chan struct{})
	go func() {
		defer close(inputWriterDone)
		for {
			select {
			case operation := <-input:
				if operation.resize != nil {
					frame := operation.resize
					if frame.Cols >= ptyMinCols && frame.Cols <= ptyMaxCols && frame.Rows >= ptyMinRows && frame.Rows <= ptyMaxRows {
						_ = pty.Setsize(master, &pty.Winsize{Cols: frame.Cols, Rows: frame.Rows})
					}
					continue
				}
				if _, err := master.Write(operation.data); err != nil {
					return
				}
			case <-session.ctx.Done():
				return
			}
		}
	}()

	readiness := time.NewTicker(50 * time.Millisecond)
	defer readiness.Stop()
	keepAlive := time.NewTicker(authKeepAlive)
	defer keepAlive.Stop()
	for {
		select {
		case <-keepAlive.C:
			if err := conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(authWriteTimeout)); err != nil {
				return
			}
		case data := <-output:
			if err := writeBinary(conn, authWriteTimeout, data); err != nil {
				return
			}
		case <-readiness.C:
			if m.runner.MasterHealthy(alias, session.controlPath) {
				if m.finish(session, true) {
					_ = writeJSON(conn, authWriteTimeout, serverFrame{Type: "ready"})
					_ = writeJSON(conn, authWriteTimeout, exitFrame(0, ""))
					finished = true
					session.cancel() // stop browser I/O goroutines, not the owned process
					// The owned master keeps the PTY it authenticated on, and
					// nothing reads it once this loop ends. Drain it, so a full
					// buffer can never block the master it belongs to.
					go func() { _, _ = io.Copy(io.Discard, master) }()
					return
				}
				cleanupFailedSession(session)
				m.finish(session, false)
				finished = true
				_ = writeJSON(conn, authWriteTimeout, exitFrame(1, "SSH authentication service is stopping"))
				return
			}
		case <-waitDone:
			_ = master.Close()
			session.mu.Lock()
			err := session.waitErr
			session.mu.Unlock()
			code, message := exitDetails(err)
			if err == nil {
				code, message = 1, "SSH control master exited before becoming ready"
			}
			_ = writeJSON(conn, authWriteTimeout, exitFrame(code, message))
			return
		case <-clientGone:
			return
		case <-inputWriterDone:
			return
		case <-session.ctx.Done():
			return
		}
	}
}

func (m *SSHAuthManager) Close() {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	m.closed = true
	m.cancel()
	sessions := make([]*authSession, 0, len(m.active))
	for _, session := range m.active {
		session.cancel()
		sessions = append(sessions, session)
	}
	m.mu.Unlock()
	for _, session := range sessions {
		session.closeIO()
	}
	m.wg.Wait()
	m.mu.Lock()
	masters := make([]*ownedMaster, 0, len(m.owned))
	for _, master := range m.owned {
		masters = append(masters, master)
	}
	m.owned = map[string]*ownedMaster{}
	m.mu.Unlock()
	for _, master := range masters {
		closeMaster(master)
	}
}

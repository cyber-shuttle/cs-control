// Package gateway serves the interactive SSH authentication WebSocket, whose prompt establishes a control master.
// It runs commands only through sshexec and has no view of the session domain.
// The request that first sees the master turn healthy owns it, so shutdown reaps that exact process.
//
//	authInputOp, authAttempt, ownedMaster, SSHAuthManager
//	stopAndReap, closeMaster, cleanupFailedAttempt
//	writeReady, masterExitFrame, readClientFrames, negotiableWindow, writeClientInput
//	NewSSHAuthManager
package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/creack/pty"
	"github.com/cyber-shuttle/cs-control/internal/apierr"
	"github.com/cyber-shuttle/cs-control/internal/apihttp"
	"github.com/cyber-shuttle/cs-control/internal/authn"
	"github.com/cyber-shuttle/cs-control/internal/sshexec"
	"github.com/gorilla/websocket"
)

var controlUpgrader = websocket.Upgrader{Subprotocols: []string{authn.ControlWebSocketProtocol}, CheckOrigin: func(*http.Request) bool { return true }}

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
	authKeepAlive    = 20 * time.Second
)

type authInputOp struct {
	data   []byte
	resize *clientFrame
}

type authAttempt struct {
	alias       string
	runner      sshexec.Runner
	controlPath string
	ctx         context.Context
	cancel      context.CancelFunc

	mu       sync.Mutex
	cmd      *exec.Cmd
	master   *os.File
	conn     *websocket.Conn
	waitDone chan struct{}
	waitErr  error
	lock     *os.File
}

type ownedMaster struct {
	alias    string
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
	active map[string]*authAttempt
	owned  map[string]*ownedMaster
	wg     sync.WaitGroup
}

func (s *authAttempt) assignConnection(conn *websocket.Conn) {
	s.mu.Lock()
	s.conn = conn
	s.mu.Unlock()
}

func (s *authAttempt) assign(cmd *exec.Cmd, master *os.File, waitDone chan struct{}) {
	s.mu.Lock()
	s.cmd, s.master, s.waitDone = cmd, master, waitDone
	s.mu.Unlock()
}

func (s *authAttempt) closeIO() {
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

func stopAndReap(attempt *authAttempt) {
	attempt.mu.Lock()
	cmd, master, waitDone := attempt.cmd, attempt.master, attempt.waitDone
	attempt.mu.Unlock()
	if master != nil {
		_ = master.Close()
	}
	if cmd == nil || cmd.Process == nil || waitDone == nil {
		return
	}
	sshexec.KillGroup(cmd, waitDone)
}

func closeMaster(master *ownedMaster) {
	if master == nil {
		return
	}
	sshexec.KillGroup(master.cmd, master.waitDone)
	if master.master != nil {
		_ = master.master.Close()
	}
	sshexec.UnlockControl(master.lock)
}

func cleanupFailedAttempt(attempt *authAttempt) {
	attempt.cancel()
	stopAndReap(attempt)
	if attempt.lock != nil {
		sshexec.UnlockControl(attempt.lock)
		attempt.lock = nil
	}
}

func writeReady(conn *websocket.Conn) {
	_ = writeJSON(conn, authWriteTimeout, serverFrame{Type: "ready"})
	_ = writeJSON(conn, authWriteTimeout, exitFrame(0, ""))
}

func masterExitFrame(err error) serverFrame {
	var exit *exec.ExitError
	switch {
	case err == nil:
		return exitFrame(1, "SSH control master exited before becoming ready")
	case errors.As(err, &exit):
		return exitFrame(exit.ExitCode(), "SSH authentication failed")
	}
	return exitFrame(1, "SSH authentication failed")
}

func readClientFrames(attempt *authAttempt, conn *websocket.Conn, input chan<- authInputOp) <-chan struct{} {
	done := make(chan struct{})
	queue := func(operation authInputOp) bool {
		select {
		case input <- operation:
			return true
		case <-attempt.ctx.Done():
		default:
			attempt.cancel()
		}
		return false
	}
	go func() {
		defer close(done)
		for {
			messageType, data, err := conn.ReadMessage()
			if err != nil {
				return
			}
			switch messageType {
			case websocket.BinaryMessage:
				if len(data) > maxAuthInput {
					attempt.cancel()
					return
				}
				if !queue(authInputOp{data: data}) {
					return
				}
			case websocket.TextMessage:
				var frame clientFrame
				if err := json.Unmarshal(data, &frame); err != nil {
					return
				}
				if frame.Type == "resize" && !queue(authInputOp{resize: &frame}) {
					return
				}
			default:
				attempt.cancel()
				return
			}
		}
	}()
	return done
}

func negotiableWindow(frame clientFrame) bool {
	return frame.Cols >= ptyMinCols && frame.Cols <= ptyMaxCols && frame.Rows >= ptyMinRows && frame.Rows <= ptyMaxRows
}

func writeClientInput(attempt *authAttempt, master *os.File, input <-chan authInputOp) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case operation := <-input:
				switch {
				case operation.resize == nil:
					if _, err := master.Write(operation.data); err != nil {
						return
					}
				case negotiableWindow(*operation.resize):
					_ = pty.Setsize(master, &pty.Winsize{Cols: operation.resize.Cols, Rows: operation.resize.Rows})
				}
			case <-attempt.ctx.Done():
				return
			}
		}
	}()
	return done
}

func NewSSHAuthManager(runner sshexec.Runner) *SSHAuthManager {
	ctx, cancel := context.WithCancel(context.Background())
	return &SSHAuthManager{runner: runner, ctx: ctx, cancel: cancel, active: map[string]*authAttempt{}, owned: map[string]*ownedMaster{}}
}

func (m *SSHAuthManager) admit(alias string, runner sshexec.Runner) (*authAttempt, error) {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil, apierr.New("service_stopping", "SSH authentication service is stopping", 503)
	}
	for _, active := range m.active {
		if active.alias == alias && active.runner.Hosts.UserPath == runner.Hosts.UserPath {
			m.mu.Unlock()
			return nil, apierr.New("ssh_authentication_in_progress", "SSH authentication is already in progress for "+alias, 409)
		}
	}
	m.mu.Unlock()

	path, err := runner.ControlPath(m.ctx, alias)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, apierr.New("service_stopping", "SSH authentication service is stopping", 503)
	}
	for _, active := range m.active {
		if active.controlPath == path {
			return nil, apierr.New("ssh_authentication_in_progress", "SSH authentication is already in progress for "+alias, 409)
		}
	}
	ctx, cancel := context.WithCancel(m.ctx)
	attempt := &authAttempt{alias: alias, runner: runner, controlPath: path, ctx: ctx, cancel: cancel}
	m.active[path] = attempt
	m.wg.Add(1)
	return attempt, nil
}

func (m *SSHAuthManager) finish(attempt *authAttempt, own bool) bool {
	m.mu.Lock()
	attempt.mu.Lock()
	if own && (m.closed || attempt.cmd == nil || attempt.waitDone == nil) {
		attempt.mu.Unlock()
		m.mu.Unlock()
		return false
	}
	if m.active[attempt.controlPath] == attempt {
		delete(m.active, attempt.controlPath)
	}
	if own {
		m.owned[attempt.controlPath] = &ownedMaster{
			alias: attempt.alias, lock: attempt.lock,
			cmd: attempt.cmd, master: attempt.master, waitDone: attempt.waitDone,
		}
		attempt.lock = nil
	}
	attempt.mu.Unlock()
	m.mu.Unlock()
	sshexec.UnlockControl(attempt.lock)
	attempt.lock = nil
	m.wg.Done()
	return own
}

func (m *SSHAuthManager) reclaimExpiredOwned(runner sshexec.Runner, alias, path string) (bool, error) {
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
	if runner.MasterHealthy(alias, path) {
		m.mu.Unlock()
		return true, nil
	}
	delete(m.owned, path)
	m.mu.Unlock()
	closeMaster(master)
	return false, nil
}

func (m *SSHAuthManager) command(attempt *authAttempt) (*exec.Cmd, bool, error) {
	if healthy, err := m.reclaimExpiredOwned(attempt.runner, attempt.alias, attempt.controlPath); err != nil || healthy {
		return nil, healthy, err
	}
	lock, healthy, err := attempt.runner.AcquireControlLock(attempt.ctx, attempt.alias, attempt.controlPath)
	if err != nil {
		return nil, false, err
	}
	attempt.lock = lock
	if healthy {
		return nil, true, nil
	}
	if err := sshexec.RemoveStaleControl(attempt.controlPath); err != nil {
		return nil, false, err
	}
	args, err := attempt.runner.Args(attempt.ctx, attempt.alias, true)
	if err != nil {
		return nil, false, err
	}
	host := args[len(args)-1]
	options := make([]string, 0, 6)
	options = append(options, "-q", "-T", "-N", "-o", "LogLevel=ERROR", host)
	args = append(args[:len(args)-1], options...)
	cmd := exec.Command(attempt.runner.Bin(), args...)
	cmd.Env = sshexec.ChildEnv()
	return cmd, false, nil
}

func (m *SSHAuthManager) ServeWebSocket(writer http.ResponseWriter, request *http.Request, alias string, runner sshexec.Runner) {
	attempt, err := m.admit(alias, runner)
	if err != nil {
		apihttp.WriteError(writer, err)
		return
	}
	finished := false
	defer func() {
		if !finished {
			cleanupFailedAttempt(attempt)
			m.finish(attempt, false)
		}
	}()

	conn, err := controlUpgrader.Upgrade(writer, request, nil)
	if err != nil {
		return
	}
	attempt.assignConnection(conn)
	defer func() { _ = conn.Close() }()
	conn.SetReadLimit(maxAuthFrame)

	cmd, alreadyReady, err := m.command(attempt)
	if err != nil {
		_ = writeJSON(conn, authWriteTimeout, exitFrame(1, "failed to prepare SSH"))
		return
	}
	if alreadyReady {
		writeReady(conn)
		finished = true
		m.finish(attempt, false)
		attempt.cancel()
		return
	}
	master, err := pty.StartWithSize(cmd, &pty.Winsize{Cols: ptyInitialCols, Rows: ptyInitialRows})
	if err != nil {
		_ = writeJSON(conn, authWriteTimeout, exitFrame(1, "failed to start SSH"))
		return
	}
	waitDone := make(chan struct{})
	go func() {
		err := cmd.Wait()
		attempt.mu.Lock()
		attempt.waitErr = err
		attempt.mu.Unlock()
		close(waitDone)
	}()
	attempt.assign(cmd, master, waitDone)

	output := make(chan []byte, 8)
	go pumpPTY(attempt.ctx, master, output, 16<<10)
	input := make(chan authInputOp, maxQueuedAuthInput/maxAuthInput)
	clientGone := readClientFrames(attempt, conn, input)
	inputWriterDone := writeClientInput(attempt, master, input)

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
			if !attempt.runner.MasterHealthy(alias, attempt.controlPath) {
				continue
			}
			finished = true
			if !m.finish(attempt, true) {
				cleanupFailedAttempt(attempt)
				m.finish(attempt, false)
				_ = writeJSON(conn, authWriteTimeout, exitFrame(1, "SSH authentication service is stopping"))
				return
			}
			writeReady(conn)
			attempt.cancel()
			go func() {
				for range output {
				}
			}()
			return
		case <-waitDone:
			_ = master.Close()
			attempt.mu.Lock()
			err := attempt.waitErr
			attempt.mu.Unlock()
			_ = writeJSON(conn, authWriteTimeout, masterExitFrame(err))
			return
		case <-clientGone:
			return
		case <-inputWriterDone:
			return
		case <-attempt.ctx.Done():
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
	attempts := make([]*authAttempt, 0, len(m.active))
	for _, attempt := range m.active {
		attempt.cancel()
		attempts = append(attempts, attempt)
	}
	m.mu.Unlock()
	for _, attempt := range attempts {
		attempt.closeIO()
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

// Exercises SSHAuthManager end to end against a stub OpenSSH.
// Covers single-flight admission, prompt round-trip, keep-alive, master ownership, and rejected attacker paths.
// The stub re-execs this test binary as TestSSHAuthHelper to answer OpenSSH's own invocations.
//
//	pollUntil, waitForFile, waitProcessGone, authTestFrame, readAuthServerFrame, testIdentityToken,
//	testPrincipal, oauthValidatorFunc, serveSSHRoute, newAuthTestService, assertManagerCloseReaps, bindTestUnixSocket
//	TestSSHAuthWebSocketPromptReuseSingleFlightAndCleanup, TestSSHAuthHelper,
//	TestControlPathRejectsSymlinkAndInsecureTempArtifacts, TestControlPathChangesForEveryEffectiveConfigurationSource
//	TestPromptWaitKeepsTheConnectionAlive
//	TestOwnedForegroundMasterShutdownDoesNotTouchForeignReplacement
//	TestStopAndReapKillsStubbornProcess, TestConcurrentManagersSerializeControlPathStartup
//	TestCloseUnblocksFullPTYInputQueueAndReapsProcess
//	TestServeWebSocketAlreadyReadyCancelsAttemptContext
//	TestCleanupFailedAttemptCancelsContextAndDoesNotLeakGoroutines
package gateway

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"
	"github.com/gorilla/websocket"

	"github.com/cyber-shuttle/cs-control/internal/apierr"
	"github.com/cyber-shuttle/cs-control/internal/authn"
	"github.com/cyber-shuttle/cs-control/internal/sshconfig"
	"github.com/cyber-shuttle/cs-control/internal/sshexec"
	"github.com/cyber-shuttle/cs-control/internal/testutil"
)

func pollUntil(t *testing.T, timeout time.Duration, ready func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if ready() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal(msg)
}

func waitForFile(t *testing.T, path string) {
	t.Helper()
	pollUntil(t, 3*time.Second, func() bool {
		info, err := os.Stat(path)
		return err == nil && info.Size() > 0
	}, "timed out waiting for "+path)
}

func waitProcessGone(t *testing.T, pid int) {
	t.Helper()
	pollUntil(t, 3*time.Second, func() bool {
		return errors.Is(syscall.Kill(pid, 0), syscall.ESRCH)
	}, fmt.Sprintf("timed out waiting for process %d to exit", pid))
}

type authTestFrame struct {
	serverFrame
	Output []byte
}

func readAuthServerFrame(t *testing.T, connection *websocket.Conn) authTestFrame {
	t.Helper()
	_ = connection.SetReadDeadline(time.Now().Add(5 * time.Second))
	messageType, data, err := connection.ReadMessage()
	testutil.Check(t, err)
	if messageType == websocket.BinaryMessage {
		return authTestFrame{serverFrame: serverFrame{Type: "output"}, Output: data}
	}
	testutil.Equal(t, messageType, websocket.TextMessage, "auth WebSocket message type")
	var frame serverFrame
	testutil.Check(t, json.Unmarshal(data, &frame))
	if frame.Type == "output" {
		t.Fatal("auth output must use binary WebSocket messages")
	}
	return authTestFrame{serverFrame: frame}
}

const testIdentityToken = "signed-test-identity-token"

var testPrincipal = authn.Principal{Subject: "test-owner", Tenant: "test-tenant"}

type oauthValidatorFunc func(context.Context, string) (authn.Principal, error)

func (f oauthValidatorFunc) Validate(ctx context.Context, credentials authn.OAuthCredentials) (authn.Principal, error) {
	return f(ctx, credentials.IDToken)
}

func serveSSHRoute(auth *SSHAuthManager) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		segments := strings.Split(strings.Trim(strings.TrimPrefix(request.URL.Path, "/api/v1/"), "/"), "/")
		if len(segments) != 3 || segments[0] != "ssh" {
			apierr.WriteError(writer, apierr.New("not_found", "route not found", 404))
			return
		}
		switch segments[2] {
		case "auth":
			if request.Method != http.MethodGet || request.Header.Get("Upgrade") == "" {
				apierr.WriteError(writer, apierr.New("upgrade_required", "SSH authentication requires a WebSocket", 426))
				return
			}
			if auth == nil {
				apierr.WriteError(writer, apierr.New("service_stopping", "SSH authentication service is stopping", 503))
				return
			}
			auth.ServeWebSocket(writer, request, segments[1], auth.runner)
		default:
			apierr.WriteError(writer, apierr.New("not_found", "route not found", 404))
		}
	})
}

func newAuthTestService(t *testing.T) sshexec.Runner {
	t.Helper()
	dir := t.TempDir()
	wrapper := filepath.Join(dir, "ssh")
	testutil.Check(t, os.WriteFile(wrapper, []byte("#!/bin/sh\nexec \"$TEST_BINARY\" -test.run=TestSSHAuthHelper -- \"$@\"\n"), 0o700))
	user := filepath.Join(dir, "config")
	included := filepath.Join(dir, "included.conf")
	testutil.Check(t, os.WriteFile(included, []byte("Host *\n  ServerAliveInterval 30\n"), 0o600))
	testutil.Check(t, os.WriteFile(user, []byte("Include "+included+"\nHost delta\n  HostName one.example\n  User tester\n"), 0o600))
	system := filepath.Join(dir, "system")
	testutil.Check(t, os.WriteFile(system, nil, 0o600))
	t.Setenv("GO_WANT_SSH_AUTH_HELPER", "1")
	t.Setenv("TEST_BINARY", os.Args[0])
	t.Setenv("AUTH_HELPER_LOG", filepath.Join(dir, "ssh.log"))
	t.Setenv("AUTH_HELPER_EFFECTIVE_FILES", strings.Join([]string{user, system, included}, string(os.PathListSeparator)))
	return sshexec.Runner{SSHBin: wrapper, Timeout: 10 * time.Second, ControlNamespace: filepath.Join(dir, "control"), Hosts: sshconfig.Config{UserPath: user}}
}

func assertManagerCloseReaps(t *testing.T, manager *SSHAuthManager, pidFile string) {
	t.Helper()
	data, err := os.ReadFile(pidFile)
	testutil.Check(t, err)
	var pid int
	_, err = fmt.Sscanf(string(data), "%d", &pid)
	testutil.Check(t, err)
	closed := make(chan struct{})
	started := time.Now()
	go func() { manager.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("SSHAuthManager.Close blocked on slow client or PTY")
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("Close took %s", elapsed)
	}
	waitProcessGone(t, pid)
}

func bindTestUnixSocket(path string) error {
	_ = os.Remove(path)
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return err
	}
	defer func() { _ = syscall.Close(fd) }()
	if err := syscall.Bind(fd, &syscall.SockaddrUnix{Name: path}); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

func TestSSHAuthWebSocketPromptReuseSingleFlightAndCleanup(t *testing.T) {
	service := newAuthTestService(t)
	t.Setenv("AUTH_HELPER_REMOTE_NOISE", "1")
	logPath := os.Getenv("AUTH_HELPER_LOG")
	auth := NewSSHAuthManager(service)
	api := serveSSHRoute(auth)
	defer auth.Close()
	server := httptest.NewUnstartedServer(nil)
	const approvedOrigin = "https://workspace.example.edu"
	handler, err := authn.NewOAuthBoundary(api, oauthValidatorFunc(func(_ context.Context, token string) (authn.Principal, error) {
		if token != testIdentityToken {
			return authn.Principal{}, errors.New("invalid delegated token")
		}
		return testPrincipal, nil
	}), []string{approvedOrigin})
	testutil.Check(t, err)
	server.Config.Handler = handler
	server.Start()
	defer server.Close()

	unauthorized, err := http.Get(server.URL + "/api/v1/ssh/delta/auth")
	testutil.Check(t, err)
	testutil.Equal(t, unauthorized.StatusCode, http.StatusUnauthorized, "unauthorized auth")
	_ = unauthorized.Body.Close()

	url := "ws" + strings.TrimPrefix(server.URL, "http") + "/api/v1/ssh/delta/auth"
	dialer := *websocket.DefaultDialer
	dialer.Subprotocols = []string{authn.ControlWebSocketProtocol, authn.WebSocketBearerPrefix + base64.RawURLEncoding.EncodeToString([]byte(testIdentityToken))}
	hostile := http.Header{"Origin": {"https://evil.example"}}
	if connection, response, dialErr := dialer.Dial(url, hostile); dialErr == nil || response == nil || response.StatusCode != http.StatusForbidden {
		if connection != nil {
			_ = connection.Close()
		}
		t.Fatalf("hostile origin response=%v error=%v, want 403", response, dialErr)
	} else {
		_ = response.Body.Close()
	}

	header := http.Header{"Origin": {approvedOrigin}}
	connection, response, err := dialer.Dial(url, header)
	if err != nil {
		t.Fatalf("open auth websocket: %v (%v)", err, response)
	}
	defer func() { _ = connection.Close() }()
	defer func() { _ = response.Body.Close() }()
	if connection.Subprotocol() != authn.ControlWebSocketProtocol || response.Header.Get("Sec-WebSocket-Protocol") != authn.ControlWebSocketProtocol || strings.Contains(response.Header.Get("Sec-WebSocket-Protocol"), authn.WebSocketBearerPrefix) {
		t.Fatalf("authentication subprotocol = %q response=%q", connection.Subprotocol(), response.Header.Get("Sec-WebSocket-Protocol"))
	}

	var output strings.Builder
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(output.String(), "Password:") && time.Now().Before(deadline) {
		frame := readAuthServerFrame(t, connection)
		if frame.Type == "output" {
			output.Write(frame.Output)
		}
	}
	if !strings.Contains(output.String(), "Password:") {
		t.Fatalf("prompt not received: %q", output.String())
	}

	_, secondResponse, secondErr := dialer.Dial(url, header)
	if secondErr == nil || secondResponse == nil || secondResponse.StatusCode != http.StatusConflict {
		t.Fatalf("parallel authentication was not rejected: response=%v error=%v", secondResponse, secondErr)
	}
	_ = secondResponse.Body.Close()

	testutil.Check(t, connection.WriteJSON(clientFrame{Type: "resize", Cols: 120, Rows: 40}))
	secret := []byte("correct horse battery staple\n")
	testutil.Check(t, connection.WriteMessage(websocket.BinaryMessage, secret))
	ready, exited := false, false
	for !exited {
		frame := readAuthServerFrame(t, connection)
		switch frame.Type {
		case "output":
			output.Write(frame.Output)
		case "ready":
			ready = true
		case "exit":
			if frame.Code == nil || *frame.Code != 0 {
				t.Fatalf("authentication exited %v: %s output=%q", frame.Code, frame.Message, output.String())
			}
			exited = true
		}
	}
	if !ready || !strings.Contains(output.String(), "Authenticated") || !strings.Contains(output.String(), "SIZE=120x40") {
		t.Fatalf("missing ready/output/resize evidence: ready=%v output=%q", ready, output.String())
	}
	if strings.Contains(output.String(), "MOTD") || strings.Contains(output.String(), "Lmod") {
		t.Fatalf("remote login noise reached authentication output: %q", output.String())
	}

	_, err = service.Run(context.Background(), "delta", nil, "true")
	testutil.Check(t, err)
	logData, err := os.ReadFile(logPath)
	testutil.Check(t, err)
	if !strings.Contains(string(logData), "BATCH_REUSED") {
		t.Fatalf("batch operations did not reuse control path: %s", logData)
	}
	if strings.Contains(string(logData), strings.TrimSpace(string(secret))) {
		t.Fatal("interactive credential leaked into logs")
	}

	controlPath, err := service.ControlPath(context.Background(), "delta")
	testutil.Check(t, err)
	if _, err := os.Stat(controlPath); err != nil {
		t.Fatalf("control path did not persist: %v", err)
	}
	auth.mu.Lock()
	owned := auth.owned[controlPath]
	auth.mu.Unlock()
	if owned == nil || owned.cmd == nil || owned.cmd.Process == nil {
		t.Fatal("ready master was not process-owned")
	}
	ownedPID := owned.cmd.Process.Pid
	auth.Close()
	waitProcessGone(t, ownedPID)
}

func TestSSHAuthHelper(t *testing.T) {
	if os.Getenv("GO_WANT_SSH_AUTH_HELPER") != "1" {
		return
	}
	separator := 0
	for i, arg := range os.Args {
		if arg == "--" {
			separator = i + 1
			break
		}
	}
	args := os.Args[separator:]
	log := func(value string) {
		file, _ := os.OpenFile(os.Getenv("AUTH_HELPER_LOG"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		defer func() { _ = file.Close() }()
		_, _ = fmt.Fprintln(file, value)
	}
	if args[0] == "-G" {
		rest := args[1:]
		if len(rest) >= 2 && rest[0] == "-F" {
			log("G -F " + rest[1])
			rest = rest[2:]
		}
		fmt.Println("host", rest[0])
		for _, path := range strings.Split(os.Getenv("AUTH_HELPER_EFFECTIVE_FILES"), string(os.PathListSeparator)) {
			if path == "" {
				continue
			}
			data, err := os.ReadFile(path)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			fmt.Printf("config %s\n%s\n", filepath.Base(path), data)
		}
		os.Exit(0)
	}
	if len(args) >= 5 && args[0] == "-S" && args[2] == "-O" {
		path, operation := args[1], args[3]
		switch operation {
		case "check":
			if _, err := os.Stat(path); err != nil {
				os.Exit(1)
			}
		case "exit":
			_ = os.Remove(path)
			log("MASTER_EXIT")
		}
		os.Exit(0)
	}
	controlPath, batch := "", ""
	for i, arg := range args {
		if arg == "-o" && i+1 < len(args) {
			option := args[i+1]
			if strings.HasPrefix(option, "ControlPath=") {
				controlPath = strings.TrimPrefix(option, "ControlPath=")
			}
			if strings.HasPrefix(option, "BatchMode=") {
				batch = strings.TrimPrefix(option, "BatchMode=")
			}
		}
	}
	if batch == "no" {
		hostIndex := -1
		for i, arg := range args {
			if arg == "delta" {
				hostIndex = i
			}
		}
		if os.Getenv("AUTH_HELPER_REMOTE_NOISE") == "1" && hostIndex >= 0 && hostIndex < len(args)-1 {
			fmt.Println("MOTD: remote shell started")
			fmt.Println("Lmod: module startup warning")
		}
		if pidFile := os.Getenv("AUTH_HELPER_PID_FILE"); pidFile != "" {
			_ = os.WriteFile(pidFile, []byte(fmt.Sprint(os.Getpid())), 0o600)
		}
		if os.Getenv("AUTH_HELPER_NO_READ") == "1" {
			fmt.Println("NOT_READING")
			select {}
		}
		if os.Getenv("AUTH_HELPER_START_DELAY") != "" {
			delay, _ := time.ParseDuration(os.Getenv("AUTH_HELPER_START_DELAY"))
			time.Sleep(delay)
		}
		if os.Getenv("AUTH_HELPER_AUTO") != "1" {
			fmt.Print("Password: ")
			line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
			if strings.TrimSpace(line) != "correct horse battery staple" {
				os.Exit(1)
			}
		}
		rows, cols, _ := pty.Getsize(os.Stdin)
		_ = os.MkdirAll(filepath.Dir(controlPath), 0o700)
		if err := bindTestUnixSocket(controlPath); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		fmt.Printf("\r\nAuthenticated\r\nSIZE=%dx%d\r\n", cols, rows)
		log("MASTER_READY")
		stopping := make(chan os.Signal, 1)
		signal.Notify(stopping, syscall.SIGTERM, syscall.SIGINT)
		<-stopping
		os.Exit(0)
	}
	if batch == "yes" {
		if _, err := os.Stat(controlPath); err != nil {
			fmt.Fprintln(os.Stderr, "Permission denied (publickey,password).")
			os.Exit(255)
		}
		log("BATCH_REUSED")
		os.Exit(0)
	}
	os.Exit(2)
}

func TestControlPathRejectsSymlinkAndInsecureTempArtifacts(t *testing.T) {
	for _, test := range []struct {
		name  string
		setup func(t *testing.T, root string, service sshexec.Runner)
		run   func(service sshexec.Runner) error
	}{
		{
			name: "symlink directory",
			setup: func(t *testing.T, root string, _ sshexec.Runner) {
				target := t.TempDir()
				testutil.Check(t, os.Symlink(target, filepath.Join(root, fmt.Sprintf("csctl-%d", os.Getuid()))))
			},
			run: func(service sshexec.Runner) error {
				_, err := service.ControlPath(context.Background(), "delta")
				return err
			},
		},
		{
			name: "insecure directory",
			setup: func(t *testing.T, root string, _ sshexec.Runner) {
				testutil.Check(t, os.Mkdir(filepath.Join(root, fmt.Sprintf("csctl-%d", os.Getuid())), 0o755))
			},
			run: func(service sshexec.Runner) error {
				_, err := service.ControlPath(context.Background(), "delta")
				return err
			},
		},
		{
			name: "symlink lock",
			setup: func(t *testing.T, _ string, service sshexec.Runner) {
				path, err := service.ControlPath(context.Background(), "delta")
				testutil.Check(t, err)
				testutil.Check(t, os.Symlink(filepath.Join(t.TempDir(), "target"), path+".lock"))
			},
			run: func(service sshexec.Runner) error {
				path, err := service.ControlPath(context.Background(), "delta")
				if err != nil {
					return err
				}
				_, _, err = service.AcquireControlLock(context.Background(), "delta", path)
				return err
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			root, err := os.MkdirTemp("/tmp", "csctl-control-attack-")
			testutil.Check(t, err)
			defer func() { _ = os.RemoveAll(root) }()
			service := newAuthTestService(t)
			service.ControlTempRoot = func() string { return root }
			test.setup(t, root, service)
			if err := test.run(service); err == nil {
				t.Fatal("unsafe control artifact was accepted")
			}
		})
	}
}

func TestControlPathChangesForEveryEffectiveConfigurationSource(t *testing.T) {
	service := newAuthTestService(t)
	before, err := service.ControlPath(context.Background(), "delta")
	testutil.Check(t, err)
	logData, err := os.ReadFile(os.Getenv("AUTH_HELPER_LOG"))
	testutil.Check(t, err)
	if !strings.Contains(string(logData), "G -F "+service.Hosts.UserPath) {
		t.Fatalf("-G was not resolved against the caller's own configuration: %s", logData)
	}
	original, err := os.ReadFile(service.Hosts.UserPath)
	testutil.Check(t, err)
	retargeted := strings.Replace(string(original), "Host delta\n  HostName one.example\n  User tester\n",
		"Host delta\n  HostName two.example\n  User other\n  Port 2222\n  IdentityFile ~/.ssh/other\n  ProxyJump bastion\n", 1)
	testutil.Check(t, os.WriteFile(service.Hosts.UserPath, []byte(retargeted), 0o600))
	concrete, err := service.ControlPath(context.Background(), "delta")
	testutil.Check(t, err)
	if before == concrete {
		t.Fatal("concrete alias retarget reused its old ControlPath")
	}

	paths := strings.Split(os.Getenv("AUTH_HELPER_EFFECTIVE_FILES"), string(os.PathListSeparator))
	system := paths[1]
	systemOriginal, err := os.ReadFile(system)
	testutil.Check(t, err)
	testutil.Check(t, os.WriteFile(system, append(systemOriginal, "Host *\n  ProxyJump new-bastion\n"...), 0o600))
	outsideStanza, err := service.ControlPath(context.Background(), "delta")
	testutil.Check(t, err)
	if concrete == outsideStanza {
		t.Fatal("a wildcard change outside the alias's own stanza reused ControlPath")
	}
}

func TestPromptWaitKeepsTheConnectionAlive(t *testing.T) {
	oldKeepAlive := authKeepAlive
	authKeepAlive = 20 * time.Millisecond
	defer func() { authKeepAlive = oldKeepAlive }()
	service := newAuthTestService(t)
	manager := NewSSHAuthManager(service)
	defer manager.Close()
	server := httptest.NewServer(serveSSHRoute(manager))
	defer server.Close()

	connection := dialAuthAlias(t, server.URL, "delta")
	defer func() { _ = connection.Close() }()
	pings := make(chan struct{}, 4)
	connection.SetPingHandler(func(string) error {
		select {
		case pings <- struct{}{}:
		default:
		}
		return nil
	})
	go func() {
		for {
			if _, _, err := connection.ReadMessage(); err != nil {
				return
			}
		}
	}()
	select {
	case <-pings:
	case <-time.After(5 * time.Second):
		t.Fatal("an idle prompt received no keep-alive")
	}
}

func TestOwnedForegroundMasterShutdownDoesNotTouchForeignReplacement(t *testing.T) {
	service := newAuthTestService(t)
	t.Setenv("AUTH_HELPER_AUTO", "1")
	manager := NewSSHAuthManager(service)
	server := httptest.NewServer(serveSSHRoute(manager))
	defer server.Close()

	connection := dialAuthAlias(t, server.URL, "delta")
	ready := false
	for {
		frame := readAuthServerFrame(t, connection)
		if frame.Type == "ready" {
			ready = true
		}
		if frame.Type == "exit" {
			if !ready || frame.Code == nil || *frame.Code != 0 {
				t.Fatalf("foreground master failed: ready=%v frame=%#v", ready, frame)
			}
			break
		}
	}
	_ = connection.Close()
	path, err := service.ControlPath(context.Background(), "delta")
	testutil.Check(t, err)
	manager.mu.Lock()
	owned := manager.owned[path]
	manager.mu.Unlock()
	if owned == nil || owned.cmd == nil || owned.cmd.Process == nil {
		t.Fatalf("ready was not backed by an owned process: %#v", owned)
	}
	pid := owned.cmd.Process.Pid
	if err := syscall.Kill(pid, 0); err != nil {
		t.Fatalf("ready was emitted after the owned process exited: %v", err)
	}

	testutil.Check(t, os.Remove(path))
	testutil.Check(t, bindTestUnixSocket(path))
	manager.Close()
	waitProcessGone(t, pid)
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("foreign replacement socket was touched: info=%v err=%v", info, err)
	}
	logData, _ := os.ReadFile(os.Getenv("AUTH_HELPER_LOG"))
	if strings.Contains(string(logData), "MASTER_EXIT") {
		t.Fatalf("shutdown addressed replacement by ControlPath: %s", logData)
	}
}

func TestStopAndReapKillsStubbornProcess(t *testing.T) {
	cmd := exec.Command("sh", "-c", "trap '' TERM; while :; do sleep 1; done")
	testutil.Check(t, cmd.Start())
	waitDone := make(chan struct{})
	go func() { _ = cmd.Wait(); close(waitDone) }()
	attempt := &authAttempt{}
	attempt.assign(cmd, nil, waitDone)
	time.Sleep(100 * time.Millisecond)
	stopAndReap(attempt)
	if cmd.ProcessState == nil || cmd.ProcessState.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
		t.Fatalf("stubborn authentication process was not killed and reaped: %v", cmd.ProcessState)
	}
}

func TestConcurrentManagersSerializeControlPathStartup(t *testing.T) {
	service := newAuthTestService(t)
	path, err := service.ControlPath(context.Background(), "delta")
	testutil.Check(t, err)
	check := filepath.Join(t.TempDir(), "ssh-check")
	testutil.Check(t, os.WriteFile(check, []byte("#!/bin/sh\n[ -e \"$2\" ]\n"), 0o700))
	service.SSHBin = check
	first, healthy, err := service.AcquireControlLock(context.Background(), "delta", path)
	if err != nil || healthy {
		t.Fatalf("first lock: healthy=%v err=%v", healthy, err)
	}
	type result struct {
		lock    *os.File
		healthy bool
		err     error
	}
	second := make(chan result, 1)
	go func() {
		lock, healthy, err := service.AcquireControlLock(context.Background(), "delta", path)
		second <- result{lock, healthy, err}
	}()
	select {
	case <-second:
		t.Fatal("second manager bypassed the inter-process lock")
	case <-time.After(100 * time.Millisecond):
	}
	testutil.Check(t, os.MkdirAll(filepath.Dir(path), 0o700))
	testutil.Check(t, bindTestUnixSocket(path))
	select {
	case got := <-second:
		if got.err != nil || !got.healthy || got.lock != nil {
			t.Fatalf("second manager did not reuse without ownership: %#v", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("second manager did not observe the healthy master")
	}
	sshexec.UnlockControl(first)
}

func TestCloseUnblocksFullPTYInputQueueAndReapsProcess(t *testing.T) {
	service := newAuthTestService(t)
	t.Setenv("AUTH_HELPER_NO_READ", "1")
	pidFile := filepath.Join(t.TempDir(), "pid")
	t.Setenv("AUTH_HELPER_PID_FILE", pidFile)
	manager := NewSSHAuthManager(service)
	server := httptest.NewServer(serveSSHRoute(manager))
	defer server.Close()
	connection := dialAuthAlias(t, server.URL, "delta")
	defer func() { _ = connection.Close() }()
	waitForFile(t, pidFile)
	payload := make([]byte, maxAuthInput)
	for i := 0; i < 8; i++ {
		_ = connection.WriteMessage(websocket.BinaryMessage, payload)
	}
	assertManagerCloseReaps(t, manager, pidFile)
}

func TestServeWebSocketAlreadyReadyCancelsAttemptContext(t *testing.T) {
	service := newAuthTestService(t)
	t.Setenv("AUTH_HELPER_AUTO", "1")
	manager := NewSSHAuthManager(service)
	defer manager.Close()
	server := httptest.NewServer(serveSSHRoute(manager))
	defer server.Close()

	first := dialAuthAlias(t, server.URL, "delta")
	defer func() { _ = first.Close() }()
	for readAuthServerFrame(t, first).Type != "ready" {
	}

	path, err := service.ControlPath(context.Background(), "delta")
	testutil.Check(t, err)
	captured := make(chan *authAttempt, 1)
	go func() {
		for {
			manager.mu.Lock()
			attempt := manager.active[path]
			manager.mu.Unlock()
			if attempt != nil {
				captured <- attempt
				return
			}
		}
	}()

	second := dialAuthAlias(t, server.URL, "delta")
	defer func() { _ = second.Close() }()
	for readAuthServerFrame(t, second).Type != "ready" {
	}

	var attempt *authAttempt
	select {
	case attempt = <-captured:
	case <-time.After(2 * time.Second):
		t.Fatal("did not observe the reused attempt")
	}
	pollUntil(t, time.Second, func() bool { return attempt.ctx.Err() != nil },
		"reusing a ready control master did not cancel the attempt context")
}

func TestCleanupFailedAttemptCancelsContextAndDoesNotLeakGoroutines(t *testing.T) {
	service := newAuthTestService(t)
	t.Setenv("AUTH_HELPER_NO_READ", "1")
	manager := NewSSHAuthManager(service)
	defer manager.Close()
	server := httptest.NewServer(serveSSHRoute(manager))
	defer server.Close()

	runtime.GC()
	baseline := runtime.NumGoroutine()

	const attempts = 8
	for i := 0; i < attempts; i++ {
		pidFile := filepath.Join(t.TempDir(), "pid")
		t.Setenv("AUTH_HELPER_PID_FILE", pidFile)
		connection := dialAuthAlias(t, server.URL, "delta")
		waitForFile(t, pidFile)
		data, err := os.ReadFile(pidFile)
		testutil.Check(t, err)
		var pid int
		_, err = fmt.Sscanf(string(data), "%d", &pid)
		testutil.Check(t, err)
		_ = connection.Close()
		waitProcessGone(t, pid)
	}

	pollUntil(t, 3*time.Second, func() bool {
		runtime.GC()
		return runtime.NumGoroutine() <= baseline+2
	}, fmt.Sprintf("goroutine count did not return to baseline after %d aborted authentications: have %d, want <= %d", attempts, runtime.NumGoroutine(), baseline+2))
}

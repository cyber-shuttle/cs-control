package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/cyber-shuttle/cs-control/internal/control"
)

func TestServeValidatesOriginsBeforeListening(t *testing.T) {
	for _, args := range [][]string{
		{"--oauth-authority", "https://login.microsoftonline.com/tenant/"},
		{"--oauth-authority", "https://login.microsoftonline.com/tenant/", "--allowed-origin", "*"},
		{"--oauth-authority", "https://login.microsoftonline.com/tenant/", "--allowed-origin", "http://workspace.example"},
		{"--listen", "0.0.0.0:8045", "--oauth-authority", "https://login.microsoftonline.com/tenant/", "--allowed-origin", "https://workspace.example"},
	} {
		listened := false
		listen := func(string, string) (net.Listener, error) {
			listened = true
			return nil, errors.New("unexpected listen")
		}
		if err := runServe(context.Background(), control.Service{}, args, listen); err == nil {
			t.Fatalf("invalid serve configuration accepted: %q", args)
		}
		if listened {
			t.Fatalf("serve listened before validating %q", args)
		}
	}
}

func TestServeComponentsAlwaysApplyOAuthBoundary(t *testing.T) {
	const allowedOrigin = "https://workspace.example.edu"
	service := control.Service{Store: control.Store{Dir: t.TempDir()}, Logs: control.NewRuntimeLogs()}
	components, err := newServeComponents(service, []string{allowedOrigin}, "https://login.microsoftonline.com/tenant/")
	if err != nil {
		t.Fatal(err)
	}
	defer components.close()

	missing := httptest.NewRequest(http.MethodGet, "/api/v1/ssh/delta/auth", nil)
	missing.Header.Set("Origin", allowedOrigin)
	missing.Header.Set("Connection", "Upgrade")
	missing.Header.Set("Upgrade", "websocket")
	missing.Header.Set("Sec-WebSocket-Protocol", "cybershuttle.v1")
	missingResponse := httptest.NewRecorder()
	components.handler.ServeHTTP(missingResponse, missing)
	if missingResponse.Code != http.StatusBadRequest {
		t.Fatalf("production handler without bearer = %d", missingResponse.Code)
	}

	hostile := httptest.NewRequest(http.MethodGet, "/api/v1/ssh/delta/auth", nil)
	hostile.Header.Set("Origin", "https://evil.example")
	hostile.Header.Set("Connection", "Upgrade")
	hostile.Header.Set("Upgrade", "websocket")
	hostile.Header.Set("Sec-WebSocket-Protocol", "cybershuttle.v1, cybershuttle.bearer.not-valid***")
	hostileResponse := httptest.NewRecorder()
	components.handler.ServeHTTP(hostileResponse, hostile)
	if hostileResponse.Code != http.StatusForbidden {
		t.Fatalf("production handler hostile origin = %d", hostileResponse.Code)
	}
}

func captureOutput(fn func() error) ([]byte, []byte, error) {
	oldStdout, oldStderr := os.Stdout, os.Stderr
	stdoutReader, stdoutWriter, err := os.Pipe()
	if err != nil {
		return nil, nil, err
	}
	stderrReader, stderrWriter, err := os.Pipe()
	if err != nil {
		_ = stdoutReader.Close()
		_ = stdoutWriter.Close()
		return nil, nil, err
	}
	os.Stdout, os.Stderr = stdoutWriter, stderrWriter
	defer func() { os.Stdout, os.Stderr = oldStdout, oldStderr }()
	runErr := fn()
	_ = stdoutWriter.Close()
	_ = stderrWriter.Close()
	stdout, stdoutErr := io.ReadAll(stdoutReader)
	stderr, stderrErr := io.ReadAll(stderrReader)
	_ = stdoutReader.Close()
	_ = stderrReader.Close()
	if stdoutErr != nil {
		return stdout, stderr, stdoutErr
	}
	if stderrErr != nil {
		return stdout, stderr, stderrErr
	}
	return stdout, stderr, runErr
}

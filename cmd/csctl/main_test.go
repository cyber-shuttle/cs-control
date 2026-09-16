// Tests that serve validates before it listens, stays behind the OAuth boundary, and parses its flags correctly.
//
//	TestServeValidatesOriginsBeforeListening, TestServeComponentsAlwaysApplyOAuthBoundary
//	TestCLIAcceptsOnlyServeHelpAndVersion
package main

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cyber-shuttle/cs-control/internal/control"
	"github.com/cyber-shuttle/cs-control/internal/testutil"
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
		service := control.Service{Store: control.Store{Dir: t.TempDir()}}
		if err := runServe(context.Background(), service, args, listen); err == nil {
			t.Fatalf("invalid serve configuration accepted: %q", args)
		}
		if listened {
			t.Fatalf("serve listened before validating %q", args)
		}
	}
}

func TestServeComponentsAlwaysApplyOAuthBoundary(t *testing.T) {
	const allowedOrigin = "https://workspace.example.edu"
	service := control.Service{Store: control.Store{Dir: t.TempDir()}, Logs: control.NewSessionLogs()}
	components, err := newServeComponents(service, []string{allowedOrigin}, "https://login.microsoftonline.com/tenant/")
	testutil.Check(t, err)
	defer components.close()

	missing := httptest.NewRequest(http.MethodGet, "/api/v1/ssh/delta/auth", nil)
	missing.Header.Set("Origin", allowedOrigin)
	missing.Header.Set("Connection", "Upgrade")
	missing.Header.Set("Upgrade", "websocket")
	missing.Header.Set("Sec-WebSocket-Protocol", "cybershuttle.v1")
	missingResponse := httptest.NewRecorder()
	components.handler.ServeHTTP(missingResponse, missing)
	testutil.Equal(t, missingResponse.Code, http.StatusBadRequest, "production handler without bearer")

	hostile := httptest.NewRequest(http.MethodGet, "/api/v1/ssh/delta/auth", nil)
	hostile.Header.Set("Origin", "https://evil.example")
	hostile.Header.Set("Connection", "Upgrade")
	hostile.Header.Set("Upgrade", "websocket")
	hostile.Header.Set("Sec-WebSocket-Protocol", "cybershuttle.v1")
	hostileResponse := httptest.NewRecorder()
	components.handler.ServeHTTP(hostileResponse, hostile)
	if hostileResponse.Code != http.StatusForbidden {
		t.Fatalf("a disallowed origin was not refused before the subprotocol was even read: %d", hostileResponse.Code)
	}

	access := base64.RawURLEncoding.EncodeToString([]byte("not-a-real-access-token"))
	identity := base64.RawURLEncoding.EncodeToString([]byte("not-a-real-identity-token"))
	invalidToken := httptest.NewRequest(http.MethodGet, "/api/v1/ssh/delta/auth", nil)
	invalidToken.Header.Set("Origin", allowedOrigin)
	invalidToken.Header.Set("Connection", "Upgrade")
	invalidToken.Header.Set("Upgrade", "websocket")
	invalidToken.Header.Set("Sec-WebSocket-Protocol", "cybershuttle.v1, bearer."+access+", identity."+identity)
	invalidTokenResponse := httptest.NewRecorder()
	components.handler.ServeHTTP(invalidTokenResponse, invalidToken)
	if invalidTokenResponse.Code != http.StatusUnauthorized {
		t.Fatalf("a well-formed but bogus bearer protocol = %d, want 401 from the subprotocol path", invalidTokenResponse.Code)
	}
}

func TestCLIAcceptsOnlyServeHelpAndVersion(t *testing.T) {
	for _, command := range []string{"version", "help", "-h", "--help"} {
		if err := run(context.Background(), []string{command}); err != nil {
			t.Errorf("%q is part of the CLI but was refused: %v", command, err)
		}
	}
	for _, command := range []string{"status", "session", "login", "ssh"} {
		if err := run(context.Background(), []string{command}); err == nil {
			t.Errorf("%q was accepted; session and SSH operations go through the API, not argv", command)
		}
	}
}

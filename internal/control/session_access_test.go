// The one route that returns a secret, only to the owner of a READY session with a live, unexpired tunnel.
// The seq credential itself never leaves the private credential store.
//
//	readyAccessSession
//	accessTestService
//	Test*
package control

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cyber-shuttle/cs-control/internal/authn"
	"github.com/cyber-shuttle/cs-control/internal/credentialstore"
	"github.com/cyber-shuttle/cs-control/internal/devtunnel"
	"github.com/cyber-shuttle/cs-control/internal/sshexec"
	"github.com/cyber-shuttle/cs-control/internal/testutil"
)

func readyAccessSession(now time.Time) Session {
	session := pendingSession("s-012345abcdef", "delta", "123")
	setTestSessionMetadata(&session)
	session.State = "READY"
	session.Tunnel.ExpiresAt = now.Add(time.Hour).Truncate(time.Second)
	return session
}

func accessTestService(t *testing.T, manager devtunnel.Manager, now time.Time) Service {
	t.Helper()
	return Service{Store: Store{Dir: t.TempDir()}, Tunnels: manager, Credentials: credentialstore.Store{Dir: t.TempDir() + "/credentials"}, Now: func() time.Time { return now }, Logs: NewSessionLogs(), Metrics: NewSessionMetrics()}
}

func TestCreateSessionTunnelPersistsCapabilityOnlyInPrivateCredential(t *testing.T) {
	manager := &testTunnelManager{}
	service := Service{Tunnels: manager, Credentials: credentialstore.Store{Dir: t.TempDir() + "/credentials"}, Logs: NewSessionLogs(), Metrics: NewSessionMetrics()}
	session := pendingSession("s-012345abcdef", "delta", "")
	record, jupyterToken, err := service.createSessionTunnel(context.Background(), &session, authn.TunnelAuthorization{OAuthToken: "oauth-token", Principal: testPrincipal}, 1)
	testutil.Check(t, err)
	stored, err := service.Credentials.Get(session.ID, session.Seq)
	if err != nil || stored.ConnectToken != record.ConnectToken {
		t.Fatalf("private credential = %#v, %v", stored, err)
	}
	if jupyterToken != stored.JupyterToken {
		t.Fatalf("returned Jupyter token does not match the stored credential")
	}
	persistedSession, err := json.Marshal(session)
	testutil.Check(t, err)
	for _, secret := range []string{stored.ConnectToken, stored.JupyterToken, record.HostToken} {
		if strings.Contains(string(persistedSession), secret) {
			t.Fatalf("session state contains seq secret: %s", persistedSession)
		}
	}
}

func TestSessionAccessDiscoversOwnerJupyterWithoutCallingTheSession(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	session := readyAccessSession(now)
	manager := &testTunnelManager{getResponse: &devtunnel.Record{
		ID: session.Tunnel.ID, ClusterID: session.Tunnel.ClusterID, ExpiresAt: session.Tunnel.ExpiresAt,
		Ports: []devtunnel.PortRecord{{PortNumber: sessionPorts(session.ID, session.Seq).jupyter, Protocol: "http", PortForwardingURIs: []string{"https://31001.use.devtunnels.ms/"}}},
	}}
	service := accessTestService(t, manager, now)
	testutil.Check(t, service.Credentials.Put(session.ID, session.Seq, credential()))
	putSessions(t, service, session)
	api := NewHTTPHandler(service, noopAuth{})
	defer api.Close()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/sessions/"+session.ID+"/access", nil).WithContext(testTunnelContext())
	response := httptest.NewRecorder()
	api.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("access status = %d: %s", response.Code, response.Body.String())
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(response.Body.Bytes(), &raw); err != nil || len(raw) != 4 || raw["sessionId"] == nil || raw["seq"] == nil || raw["expiresAt"] == nil || raw["jupyter"] == nil {
		t.Fatalf("access JSON is not narrow: %s (%v)", response.Body.String(), err)
	}
	var jupyter map[string]json.RawMessage
	if err := json.Unmarshal(raw["jupyter"], &jupyter); err != nil || len(jupyter) != 2 || jupyter["uri"] == nil || jupyter["token"] == nil {
		t.Fatalf("Jupyter access JSON is not narrow: %s (%v)", raw["jupyter"], err)
	}
	var access sessionAccessResponse
	testutil.Check(t, json.Unmarshal(response.Body.Bytes(), &access))
	if access.SessionID != session.ID || access.Seq != session.Seq || access.ExpiresAt != session.Tunnel.ExpiresAt || access.Jupyter.URI != "https://31001.use.devtunnels.ms" || access.Jupyter.Token != testJupyterToken {
		t.Fatalf("access = %#v", access)
	}
	manager.mu.Lock()
	gets := append([]devtunnel.GetRequest(nil), manager.gets...)
	manager.mu.Unlock()
	if len(gets) != 1 || gets[0].AccessToken != testConnectToken || gets[0].TunnelID != session.Tunnel.ID || gets[0].ClusterID != session.Tunnel.ClusterID {
		t.Fatalf("management discovery = %#v", gets)
	}
}

func TestSessionAccessIsOwnerOnly(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	session := readyAccessSession(now)
	manager := &testTunnelManager{getResponse: &devtunnel.Record{ID: session.Tunnel.ID, ClusterID: session.Tunnel.ClusterID, ExpiresAt: session.Tunnel.ExpiresAt, Ports: []devtunnel.PortRecord{{PortNumber: sessionPorts(session.ID, session.Seq).jupyter, Protocol: "http", PortForwardingURIs: []string{"https://31001.use.devtunnels.ms"}}}}}
	service := accessTestService(t, manager, now)
	testutil.Check(t, service.Credentials.Put(session.ID, session.Seq, credential()))
	putSessions(t, service, session)
	api := NewHTTPHandler(service, noopAuth{})
	defer api.Close()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/sessions/"+session.ID+"/access", nil)
	request = request.WithContext(authn.WithTunnelAuthorization(request.Context(), authn.TunnelAuthorization{OAuthToken: "test-oauth-token", Principal: authn.Principal{Subject: "other", Tenant: testPrincipal.Tenant}}))
	response := httptest.NewRecorder()
	api.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || strings.Contains(response.Body.String(), testJupyterToken) {
		t.Fatalf("owner mismatch = %d %s", response.Code, response.Body.String())
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if len(manager.gets) != 0 {
		t.Fatalf("owner mismatch reached discovery: %#v", manager.gets)
	}
}

func TestSessionAccessFollowsTheLiveTunnelExpiration(t *testing.T) {
	for name, test := range map[string]struct {
		liveExpiresAt func(sessionExpiresAt time.Time) time.Time
		check         func(t *testing.T, expiresAt time.Time, err error)
	}{
		"extended": {
			liveExpiresAt: func(sessionExpiresAt time.Time) time.Time { return sessionExpiresAt.Add(17 * time.Minute) },
			check: func(t *testing.T, expiresAt time.Time, err error) {
				if err != nil {
					t.Fatalf("extended tunnel expiration refused session access: %v", err)
				}
			},
		},
		"expired": {
			liveExpiresAt: func(time.Time) time.Time { return time.Now().UTC().Add(-time.Second) },
			check: func(t *testing.T, _ time.Time, err error) {
				if err == nil || !strings.Contains(err.Error(), "expired") {
					t.Fatalf("expected an expiry-specific refusal, got %v", err)
				}
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Second)
			session := readyAccessSession(now)
			live := test.liveExpiresAt(session.Tunnel.ExpiresAt)
			manager := &testTunnelManager{getResponse: &devtunnel.Record{
				ID: session.Tunnel.ID, ClusterID: session.Tunnel.ClusterID, ExpiresAt: live,
				Ports: []devtunnel.PortRecord{{PortNumber: sessionPorts(session.ID, session.Seq).jupyter, Protocol: "http", PortForwardingURIs: []string{"https://31001.use.devtunnels.ms/"}}},
			}}
			service := accessTestService(t, manager, now)
			testutil.Check(t, service.Credentials.Put(session.ID, session.Seq, credential()))
			access, err := service.sessionAccess(context.Background(), session)
			var expiresAt time.Time
			if err == nil {
				expiresAt = access.ExpiresAt
				if !expiresAt.Equal(live) {
					t.Fatalf("session access reported %s, want the live expiration %s", expiresAt, live)
				}
			}
			test.check(t, expiresAt, err)
		})
	}
}

func TestCreateSessionTunnelCompensatesUncertainCreateError(t *testing.T) {
	const oauth = "oauth-token-must-not-leak"
	manager := &testTunnelManager{
		createErr: errors.New("create response was ambiguous"),
		deleteErr: errors.New("delete failed with " + oauth),
	}
	session := pendingSession("s-012345abcdef", "delta", "")
	before := session
	credentialDir := t.TempDir()
	testutil.Check(t, os.Chmod(credentialDir, 0o700))
	service := Service{
		Runner: sshexec.Runner{Timeout: 5 * time.Second}, Tunnels: manager,
		Credentials: credentialstore.Store{Dir: credentialDir},
	}
	_, _, err := service.createSessionTunnel(context.Background(), &session, authn.TunnelAuthorization{OAuthToken: oauth, Principal: authn.Principal{Subject: "owner", Tenant: "tenant"}}, 1)
	if err == nil || strings.Contains(err.Error(), oauth) || !strings.Contains(err.Error(), "[redacted]") {
		t.Fatalf("create/cleanup error = %v", err)
	}
	if !reflect.DeepEqual(session, before) {
		t.Fatalf("session mutated after uncertain create: before=%#v after=%#v", before, session)
	}
	if len(manager.deletes) != 1 || manager.deletes[0].TunnelID != manager.creates[0].TunnelID || manager.deletes[0].ClusterID != "" || manager.deletes[0].OAuthToken != oauth {
		t.Fatalf("uncertain create compensation = %#v, create=%#v", manager.deletes, manager.creates)
	}
	entries, readErr := os.ReadDir(credentialDir)
	if readErr != nil || len(entries) != 0 {
		t.Fatalf("credential directory after uncertain create = %#v, %v", entries, readErr)
	}
}

func TestSessionTunnelDurationFloorAndCap(t *testing.T) {
	for _, test := range []struct {
		name        string
		wallMinutes int
		want        uint32
	}{
		{name: "one hour floor", wallMinutes: 1, want: devtunnel.MinDurationSeconds},
		{name: "walltime plus grace", wallMinutes: 60, want: 75 * 60},
		{name: "thirty day cap", wallMinutes: 525600, want: devtunnel.MaxDurationSeconds},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := sessionTunnelDurationSeconds(test.wallMinutes); got != test.want {
				t.Fatalf("duration = %d, want %d", got, test.want)
			}
		})
	}
}

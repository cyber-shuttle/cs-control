package control

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cyber-shuttle/cs-control/internal/authn"
	"github.com/cyber-shuttle/cs-control/internal/devtunnel"
)

func TestCreateAllocationTunnelPersistsCapabilityOnlyInPrivateCredential(t *testing.T) {
	manager := &testTunnelManager{}
	service := Service{Tunnels: manager, Credentials: CredentialStore{Dir: t.TempDir() + "/credentials"}}
	runtime := pendingRuntime("rt-012345abcdef", "delta", "")
	record, jupyterToken, err := service.createAllocationTunnel(context.Background(), &runtime, authn.TunnelAuthorization{OAuthToken: "oauth-token", Principal: testPrincipal})
	if err != nil {
		t.Fatal(err)
	}
	stored, err := service.Credentials.Get(runtime.ID, runtime.Generation)
	if err != nil || stored.ConnectToken != record.ConnectToken || !validJupyterToken(stored.JupyterToken) {
		t.Fatalf("private credential = %#v, %v", stored, err)
	}
	if jupyterToken != stored.JupyterToken {
		t.Fatalf("returned Jupyter token does not match the stored credential")
	}
	persistedRuntime, err := json.Marshal(runtime)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{stored.ConnectToken, stored.JupyterToken, record.HostToken} {
		if strings.Contains(string(persistedRuntime), secret) {
			t.Fatalf("runtime state contains generation secret: %s", persistedRuntime)
		}
	}
}

func readyAccessRuntime(now time.Time) Runtime {
	runtime := pendingRuntime("rt-012345abcdef", "delta", "123")
	setTestRuntimeMetadata(&runtime)
	runtime.State = "READY"
	runtime.Tunnel.ExpiresAt = now.Add(time.Hour).Truncate(time.Second)
	return runtime
}

func TestRuntimeAccessDiscoversOwnerJupyterWithoutCallingTheAllocation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	runtime := readyAccessRuntime(now)
	manager := &testTunnelManager{getResponse: &devtunnel.Record{
		ID: runtime.Tunnel.ID, ClusterID: runtime.Tunnel.ClusterID, ExpiresAt: runtime.Tunnel.ExpiresAt,
		Ports: []devtunnel.PortRecord{{PortNumber: 31001, Protocol: "http", Description: "cybershuttle-jupyter", PortForwardingURIs: []string{"https://31001.use.devtunnels.ms/"}}},
	}}
	service := Service{Store: Store{Dir: t.TempDir()}, Tunnels: manager, Credentials: CredentialStore{Dir: t.TempDir() + "/credentials"}, Now: func() time.Time { return now }}
	if err := service.Credentials.Put(runtime.ID, runtime.Generation, testCredential()); err != nil {
		t.Fatal(err)
	}
	putRuntimes(t, service, runtime)
	api := NewHTTPHandler(service, nil)
	defer api.Close()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/runtimes/"+runtime.ID+"/access", nil).WithContext(authn.WithPrincipal(context.Background(), testPrincipal))
	response := httptest.NewRecorder()
	api.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("access status = %d: %s", response.Code, response.Body.String())
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(response.Body.Bytes(), &raw); err != nil || len(raw) != 4 || raw["runtimeId"] == nil || raw["generation"] == nil || raw["expiresAt"] == nil || raw["jupyter"] == nil {
		t.Fatalf("access JSON is not narrow: %s (%v)", response.Body.String(), err)
	}
	var jupyter map[string]json.RawMessage
	if err := json.Unmarshal(raw["jupyter"], &jupyter); err != nil || len(jupyter) != 2 || jupyter["uri"] == nil || jupyter["token"] == nil {
		t.Fatalf("Jupyter access JSON is not narrow: %s (%v)", raw["jupyter"], err)
	}
	var access RuntimeAccessResponse
	if err := json.Unmarshal(response.Body.Bytes(), &access); err != nil {
		t.Fatal(err)
	}
	if access.RuntimeID != runtime.ID || access.Generation != runtime.Generation || access.ExpiresAt != runtime.Tunnel.ExpiresAt || access.Jupyter.URI != "https://31001.use.devtunnels.ms" || access.Jupyter.Token != testJupyterToken {
		t.Fatalf("access = %#v", access)
	}
	manager.mu.Lock()
	gets := append([]devtunnel.GetRequest(nil), manager.gets...)
	manager.mu.Unlock()
	if len(gets) != 1 || gets[0].AccessToken != testConnectToken || gets[0].TunnelID != runtime.Tunnel.ID || gets[0].ClusterID != runtime.Tunnel.ClusterID {
		t.Fatalf("management discovery = %#v", gets)
	}
}

func TestRuntimeAccessIsOwnerOnly(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	runtime := readyAccessRuntime(now)
	manager := &testTunnelManager{getResponse: &devtunnel.Record{ID: runtime.Tunnel.ID, ClusterID: runtime.Tunnel.ClusterID, ExpiresAt: runtime.Tunnel.ExpiresAt, Ports: []devtunnel.PortRecord{{PortNumber: 31001, Protocol: "http", Description: "cybershuttle-jupyter", PortForwardingURIs: []string{"https://31001.use.devtunnels.ms"}}}}}
	service := Service{Store: Store{Dir: t.TempDir()}, Tunnels: manager, Credentials: CredentialStore{Dir: t.TempDir() + "/credentials"}, Now: func() time.Time { return now }}
	if err := service.Credentials.Put(runtime.ID, runtime.Generation, testCredential()); err != nil {
		t.Fatal(err)
	}
	putRuntimes(t, service, runtime)
	api := NewHTTPHandler(service, nil)
	defer api.Close()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/runtimes/"+runtime.ID+"/access", nil)
	request = request.WithContext(authn.WithPrincipal(request.Context(), authn.Principal{Subject: "other", Tenant: testPrincipal.Tenant}))
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

// The management service slides a hosted tunnel's expiration forward, so the
// value stored at creation goes stale the moment Linkspan serves traffic.
// Comparing the two refused every healthy allocation.
func TestRuntimeAccessAcceptsATunnelWhoseExpirationTheServiceExtended(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	runtime := readyAccessRuntime(now)
	extended := runtime.Tunnel.ExpiresAt.Add(17 * time.Minute)
	manager := &testTunnelManager{getResponse: &devtunnel.Record{
		ID: runtime.Tunnel.ID, ClusterID: runtime.Tunnel.ClusterID, ExpiresAt: extended,
		Ports: []devtunnel.PortRecord{{PortNumber: 31001, Protocol: "http", Description: "cybershuttle-jupyter", PortForwardingURIs: []string{"https://31001.use.devtunnels.ms/"}}},
	}}
	service := Service{Store: Store{Dir: t.TempDir()}, Tunnels: manager, Credentials: CredentialStore{Dir: t.TempDir() + "/credentials"}, Now: func() time.Time { return now }}
	if err := service.Credentials.Put(runtime.ID, runtime.Generation, testCredential()); err != nil {
		t.Fatal(err)
	}
	access, err := service.RuntimeAccess(context.Background(), runtime)
	if err != nil {
		t.Fatalf("extended tunnel expiration refused runtime access: %v", err)
	}
	if !access.ExpiresAt.Equal(extended) {
		t.Fatalf("runtime access reported %s, want the live expiration %s", access.ExpiresAt, extended)
	}
}

func TestRuntimeAccessRefusesAnExpiredTunnelAndNamesTheReason(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	runtime := readyAccessRuntime(now)
	manager := &testTunnelManager{getResponse: &devtunnel.Record{
		ID: runtime.Tunnel.ID, ClusterID: runtime.Tunnel.ClusterID, ExpiresAt: now.Add(-time.Second),
		Ports: []devtunnel.PortRecord{{PortNumber: 31001, Protocol: "http", Description: "cybershuttle-jupyter", PortForwardingURIs: []string{"https://31001.use.devtunnels.ms/"}}},
	}}
	service := Service{Store: Store{Dir: t.TempDir()}, Tunnels: manager, Credentials: CredentialStore{Dir: t.TempDir() + "/credentials"}, Now: func() time.Time { return now }}
	if err := service.Credentials.Put(runtime.ID, runtime.Generation, testCredential()); err != nil {
		t.Fatal(err)
	}
	_, err := service.RuntimeAccess(context.Background(), runtime)
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected an expiry-specific refusal, got %v", err)
	}
}

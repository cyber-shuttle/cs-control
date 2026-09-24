// Public session routes preserve authentication, ownership, caching, and JSON contracts.
// Discovery retains classified failures; inventory remains principal-filtered and conditionally cacheable.
// Access responses expose only the live Jupyter endpoint and its short-lived capability.
package session

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cyber-shuttle/cs-plane/internal/devtunnel"
	"github.com/cyber-shuttle/cs-plane/internal/router"
	"github.com/cyber-shuttle/cs-plane/internal/security"
	"github.com/cyber-shuttle/cs-plane/internal/testutil"
)

func serviceHandler(t *testing.T, service *Service) http.Handler {
	t.Helper()
	handler, err := router.New(service.Routes())
	testutil.Check(t, err)
	return handler
}

func readyAccessScenario(t *testing.T, jupyterURI string) (Session, *testTunnelManager, Service) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	session := readyAccessSession(now)
	manager := &testTunnelManager{getResponse: &devtunnel.Record{
		ID: session.Tunnel.ID, ClusterID: session.Tunnel.ClusterID, ExpiresAt: session.Tunnel.ExpiresAt,
		Ports: []devtunnel.PortRecord{{PortNumber: ports(session.ID, session.Seq).Jupyter, Protocol: "http", PortForwardingURIs: []string{jupyterURI}}},
	}}
	service := accessTestService(t, manager, now)
	testutil.Check(t, putCapability(service.capabilityDir, session.ID, session.Seq, defaultSessionCapability()))
	putSessions(t, service, session)
	return session, manager, service
}

func mixedOwnerSession(id string, owner security.Principal) Session {
	session := pendingSession(id, "alpha", "101")
	session.State = "FAILED"
	setTestSessionMetadata(&session)
	session.Owner = owner
	return session
}

func requestAs(principal security.Principal, method, path string, body []byte) *http.Request {
	request := httptest.NewRequest(method, path, bytes.NewReader(body))
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	return request.WithContext(security.WithPrincipal(request.Context(), principal))
}

func TestHTTPRequiresValidatedPrincipalForSessionInventory(t *testing.T) {
	handler := serviceHandler(t, &Service{})
	response := testutil.Serve(handler, httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil))
	testutil.Equal(t, response.Code, http.StatusUnauthorized, "request without validated principal status")
}

func TestDiscoveryFailureReachesTheHandlerAsItsOwnCode(t *testing.T) {
	service := testService(t)
	t.Setenv("FAKE_DISCOVERY_PARTITIONS_FAIL", "1")
	handler := serviceHandler(t, &service)

	body, err := json.Marshal(newTestCreateRequest())
	testutil.Check(t, err)
	response := testutil.Serve(handler, requestAs(testPrincipal, http.MethodPost, "/api/v1/sessions/validate", body))

	if response.Code != http.StatusBadGateway {
		t.Fatalf("a login node missing sinfo answered %d, want %d: %s", response.Code, http.StatusBadGateway, response.Body.String())
	}
	var envelope security.Envelope
	testutil.Check(t, json.Unmarshal(response.Body.Bytes(), &envelope))
	if envelope.Error.Code != "slurm_discovery_failed" || !strings.Contains(envelope.Error.Message, "query Slurm partitions") {
		t.Fatalf("discovery failure lost its code and operation: %#v", envelope.Error)
	}
}

func TestHTTPSessionListReturnsCachedStateWhileRefreshBlocks(t *testing.T) {
	service, logPath, release := reconciliationService(t)
	session := pendingSession("s-111111111111", "alpha", "101")
	t.Setenv("FAKE_STATUS_RELEASE", release)
	t.Setenv("FAKE_STATUS_LINES", "101|FAILED||"+session.JobName)
	putSessions(t, service, session)
	handler := serviceHandler(t, &service)
	service.triggerRefresh()

	list := func() *httptest.ResponseRecorder {
		return testutil.Serve(handler, requestAs(testPrincipal, http.MethodGet, "/api/v1/sessions", nil))
	}
	response := list()
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"state":"QUEUED"`) {
		t.Fatalf("unexpected cached response: %d %s", response.Code, response.Body.String())
	}
	testutil.WaitForFile(t, logPath)
	for range 20 {
		if response = list(); response.Code != http.StatusOK {
			t.Fatal(response.Code)
		}
	}
	if data, _ := os.ReadFile(logPath); strings.Count(string(data), "cs-session-status") != 1 {
		t.Fatalf("polling launched SSH refreshes: %s", data)
	}
	testutil.Check(t, os.WriteFile(release, []byte("ok"), 0o600))
	testutil.Eventually(t, 3*time.Second, "the merged update to be visible", func() bool {
		return strings.Contains(list().Body.String(), `"state":"FAILED"`)
	})
}

func TestSessionAccessDiscoversOwnerJupyterWithoutCallingTheSession(t *testing.T) {
	session, manager, service := readyAccessScenario(t, "https://31001.use.devtunnels.ms/")
	handler := serviceHandler(t, &service)
	response := testutil.Serve(handler, requestAs(testPrincipal, http.MethodGet, "/api/v1/sessions/"+session.ID+"/access", nil))
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
	session, manager, service := readyAccessScenario(t, "https://31001.use.devtunnels.ms")
	handler := serviceHandler(t, &service)
	response := testutil.Serve(handler, requestAs(security.Principal{Subject: "other", Tenant: testPrincipal.Tenant}, http.MethodGet, "/api/v1/sessions/"+session.ID+"/access", nil))
	if response.Code != http.StatusForbidden || strings.Contains(response.Body.String(), testJupyterToken) {
		t.Fatalf("owner mismatch = %d %s", response.Code, response.Body.String())
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if len(manager.gets) != 0 {
		t.Fatalf("owner mismatch reached discovery: %#v", manager.gets)
	}
}

func TestSessionListDropsAnotherOwnersSessionsAndLogs(t *testing.T) {
	service := testService(t)
	owned := mixedOwnerSession("s-111111111111", testPrincipal)
	other := mixedOwnerSession("s-222222222222", otherTestPrincipal)
	putSessions(t, service, owned, other)
	service.logs.append(owned.ID, "owned-log-line", service.now())
	service.logs.append(other.ID, "other-owner-log-line", service.now())
	handler := serviceHandler(t, &service)

	response := testutil.Serve(handler, requestAs(testPrincipal, http.MethodGet, "/api/v1/sessions", nil))
	body := response.Body.String()
	var list sessionList
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &list) != nil {
		t.Fatalf("session list = %d %s", response.Code, body)
	}
	if len(list.Sessions) != 1 || list.Sessions[0].ID != owned.ID {
		t.Fatalf("session list did not narrow to the owner: %s", body)
	}
	if len(list.Logs) != 1 || list.Logs[0].SessionID != owned.ID {
		t.Fatalf("log tails did not narrow to the owner: %s", body)
	}
	for _, expected := range []string{owned.ID, "owned-log-line"} {
		if !strings.Contains(body, expected) {
			t.Errorf("owner poll omitted %q: %s", expected, body)
		}
	}
	for _, forbidden := range []string{other.ID, "other-owner-log-line"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("owner poll exposed %q: %s", forbidden, body)
		}
	}
	repeat := requestAs(testPrincipal, http.MethodGet, "/api/v1/sessions", nil)
	repeat.Header.Set("If-None-Match", response.Header().Get("ETag"))
	repeatResponse := testutil.Serve(handler, repeat)
	if repeatResponse.Code != http.StatusNotModified || repeatResponse.Body.Len() != 0 {
		t.Fatalf("unchanged poll = %d %s", repeatResponse.Code, repeatResponse.Body.String())
	}

	otherItem := testutil.Serve(handler, requestAs(testPrincipal, http.MethodGet, "/api/v1/sessions/"+other.ID, nil))
	if otherItem.Code != http.StatusForbidden || !strings.Contains(otherItem.Body.String(), `"code":"session_owner_mismatch"`) {
		t.Fatalf("other-owner item = %d %s", otherItem.Code, otherItem.Body.String())
	}
	missingItem := testutil.Serve(handler, requestAs(testPrincipal, http.MethodGet, "/api/v1/sessions/s-333333333333", nil))
	if missingItem.Code != http.StatusNotFound || !strings.Contains(missingItem.Body.String(), `"code":"session_not_found"`) {
		t.Fatalf("missing item = %d %s", missingItem.Code, missingItem.Body.String())
	}
}

func TestSessionPublicJSONContractIsNarrow(t *testing.T) {
	value := sessionResponse{
		ID: "s-012345abcdef", Seq: 1,
		State: "READY", SSHHost: "delta", Account: "project-a", Partition: "cpu",
		RootFolder: "$HOME/project", Resources: resources{Cores: 2, MemoryMB: 4096, WallMinutes: 60},
		CreatedAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), StartedAt: time.Date(2030, 1, 1, 0, 0, 30, 0, time.UTC), UpdatedAt: time.Date(2030, 1, 1, 0, 1, 0, 0, time.UTC),
	}
	encoded, err := json.MarshalIndent(value, "", "  ")
	testutil.Check(t, err)
	encoded = append(encoded, '\n')
	fixture, err := os.ReadFile("testdata/session-contract.json")
	testutil.Check(t, err)
	if !bytes.Equal(encoded, fixture) {
		t.Fatalf("contract fixture differs from actual JSON\nactual:\n%s\nfixture:\n%s", encoded, fixture)
	}
	for _, forbidden := range []string{"owner", "tunnel", "token", "privateRoot", "workspaceRoot", "jupyter", "jobId", "jobName", "node"} {
		if strings.Contains(strings.ToLower(string(fixture)), strings.ToLower(forbidden)) {
			t.Fatalf("public session fixture contains private field %q: %s", forbidden, fixture)
		}
	}
}

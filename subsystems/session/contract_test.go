// Public session routes preserve authentication, ownership, caching, and JSON contracts.
// Discovery retains classified failures; inventory remains principal-filtered and conditionally cacheable.
// Access responses expose only the live Jupyter endpoint and its short-lived capability. Define records a session
// only; a finished history is adopted once, scoped to the caller.
package session

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

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

func readyAccessScenario(t *testing.T) (Session, Service) {
	t.Helper()
	session := pendingSession("s-012345abcdef", "delta", "123")
	setTestSessionMetadata(&session)
	session.State = "READY"
	service := accessTestService(t, &testTunnelManager{})
	testutil.Check(t, putCapability(service.CapabilityDir, session.ID, session.Seq, defaultSessionCapability()))
	putSessions(t, service, session)
	return session, service
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

func TestSessionAccessNamesTheJupyterProxyWithoutCallingTheSession(t *testing.T) {
	session, service := readyAccessScenario(t)
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
	var access SessionAccessResponse
	testutil.Check(t, json.Unmarshal(response.Body.Bytes(), &access))
	if access.SessionID != session.ID || access.Seq != session.Seq || !access.ExpiresAt.After(time.Now()) || access.Jupyter.URI != "https://plane.example.edu/api/v1/sessions/"+session.ID+"/jupyter/" || access.Jupyter.Token != testJupyterToken {
		t.Fatalf("access = %#v", access)
	}
}

func TestSessionAccessIsOwnerOnly(t *testing.T) {
	session, service := readyAccessScenario(t)
	handler := serviceHandler(t, &service)
	response := testutil.Serve(handler, requestAs(security.Principal{Subject: "other", Tenant: testPrincipal.Tenant}, http.MethodGet, "/api/v1/sessions/"+session.ID+"/access", nil))
	if response.Code != http.StatusForbidden || strings.Contains(response.Body.String(), testJupyterToken) {
		t.Fatalf("owner mismatch = %d %s", response.Code, response.Body.String())
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
	var list SessionList
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
	value := SessionResponse{
		ID: "s-012345abcdef", Seq: 1,
		State: "READY", Launcher: launcherPlane, SSHHost: "delta", Account: "project-a", Partition: "cpu",
		RootFolder: "$HOME/project", Resources: Resources{Cores: 2, MemoryMB: 4096, WallMinutes: 60}, TunnelModes: []string{modeWebsocket},
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
	for _, forbidden := range []string{"owner", `"tunnel"`, "token", "privateRoot", "workspaceRoot", "jupyter", "jobId", "jobName", "node"} {
		if strings.Contains(strings.ToLower(string(fixture)), strings.ToLower(forbidden)) {
			t.Fatalf("public session fixture contains private field %q: %s", forbidden, fixture)
		}
	}
}

func TestDefineRecordsAStoppedSessionOnce(t *testing.T) {
	service := testService(t)
	handler := serviceHandler(t, &service)
	defined := newTestCreateRequest()
	post := func(body string) (SessionResponse, *httptest.ResponseRecorder) {
		response := testutil.Serve(handler, requestAs(testPrincipal, http.MethodPost, "/api/v1/sessions", []byte(body)))
		var session SessionResponse
		_ = json.Unmarshal(response.Body.Bytes(), &session)
		return session, response
	}
	encoded, err := json.Marshal(defined)
	testutil.Check(t, err)
	first, response := post(string(encoded))
	if response.Code != http.StatusCreated || response.Header().Get("Location") != "/api/v1/sessions/"+first.ID || first.State != "STOPPED" || first.Seq != 0 {
		t.Fatalf("first define = %d %s", response.Code, response.Body.String())
	}
	if replay, response := post(string(encoded)); response.Code != http.StatusOK || replay.ID != first.ID {
		t.Fatalf("replayed define = %d %s", response.Code, response.Body.String())
	}
	if other, isNew, err := service.Define(otherTestPrincipal, defined); err != nil || !isNew || other.ID == first.ID {
		t.Fatalf("another principal's define with the same key = %#v: %v", other, err)
	}
	if _, response := post(strings.Replace(string(encoded), `"partition":"cpu"`, `"partition":"gpu"`, 1)); response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "idempotency_conflict") {
		t.Fatalf("a changed replay = %d %s", response.Code, response.Body.String())
	}
	if _, response := post(strings.Replace(string(encoded), "{", `{"runs":[],`, 1)); response.Code != http.StatusBadRequest {
		t.Fatalf("a define carrying runs = %d %s", response.Code, response.Body.String())
	}
}

func TestAdoptRunsAttachesAFinishedHistoryOnce(t *testing.T) {
	service := testService(t)
	handler := serviceHandler(t, &service)
	defined, _, err := service.Define(testPrincipal, newTestCreateRequest())
	testutil.Check(t, err)
	adopt := func(principal security.Principal, history SessionHistory) *httptest.ResponseRecorder {
		body, err := json.Marshal(history)
		testutil.Check(t, err)
		return testutil.Serve(handler, requestAs(principal, http.MethodPost, "/api/v1/sessions/"+defined.ID+"/runs", body))
	}
	history := SessionHistory{CreatedAt: time.Unix(50, 0), Runs: []FinishedRun{
		{FinalState: "STOPPED", EndedAt: time.Unix(100, 0), Stats: &RunStats{CPUEfficiencyPct: 9.5}, Samples: []MetricSample{{At: time.Unix(90, 0).UTC()}}},
		{FinalState: "FAILED", Error: "node failure", StartedAt: time.Unix(150, 0), EndedAt: time.Unix(200, 0)},
	}}
	for _, invalid := range [][]FinishedRun{nil, {{FinalState: "READY", EndedAt: time.Unix(1, 0)}}} {
		if response := adopt(testPrincipal, SessionHistory{Runs: invalid}); response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "invalid_runs") {
			t.Fatalf("invalid runs %v = %d %s", invalid, response.Code, response.Body.String())
		}
	}
	if response := adopt(otherTestPrincipal, history); response.Code != http.StatusForbidden {
		t.Fatalf("another principal's adopt = %d %s", response.Code, response.Body.String())
	}
	response := adopt(testPrincipal, history)
	var adopted SessionResponse
	_ = json.Unmarshal(response.Body.Bytes(), &adopted)
	if response.Code != http.StatusOK || adopted.State != "FAILED" || adopted.Seq != 2 || adopted.Error != "node failure" || !adopted.CreatedAt.Equal(time.Unix(50, 0)) {
		t.Fatalf("adopt = %d %s", response.Code, response.Body.String())
	}
	if response := adopt(testPrincipal, history); response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "session_has_history") {
		t.Fatalf("second adopt = %d %s", response.Code, response.Body.String())
	}
	runs := func() []Run {
		runs, err := service.Runs(testPrincipal)
		testutil.Check(t, err)
		return runs
	}
	if got := runs(); len(got) != 2 || got[0].Seq != 2 || got[0].FinalState != "FAILED" || got[1].Seq != 1 || got[1].Stats.CPUEfficiencyPct != 9.5 || len(got[1].Samples) != 1 {
		t.Fatalf("adopted runs = %#v", got)
	}
	started, err := service.Start(context.Background(), testPrincipal, defined.ID)
	testutil.Check(t, err)
	if started.State != "QUEUED" || started.Seq != 3 || len(runs()) != 2 {
		t.Fatalf("start after adopt = %#v with %d runs", started.SessionResponse, len(runs()))
	}
}

// The HTTP surface's own tests: every route the mux must dispatch, and the shared strict JSON body decoding.
//
//	mixedOwnerOrigin, otherTestPrincipal, mixedOwnerSession
//	Test*
package control

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cyber-shuttle/cs-control/internal/apierr"
	"github.com/cyber-shuttle/cs-control/internal/authn"
	"github.com/cyber-shuttle/cs-control/internal/sshconfig"
	"github.com/cyber-shuttle/cs-control/internal/sshexec"
	"github.com/cyber-shuttle/cs-control/internal/testutil"
)

const mixedOwnerOrigin = "https://workspace.example.edu"

var otherTestPrincipal = authn.Principal{Subject: "other-owner", Tenant: "test-tenant"}

func mixedOwnerSession(id string, owner authn.Principal) Session {
	session := pendingSession(id, "alpha", "101")
	session.State = "FAILED"
	setTestSessionMetadata(&session)
	session.Owner = owner
	return session
}

func TestHTTPRouteSurfaceRetainsRequiredControlOperations(t *testing.T) {
	configDir := t.TempDir()
	service := Service{
		Store: Store{Dir: t.TempDir()}, Logs: NewSessionLogs(), Metrics: NewSessionMetrics(),
		Runner: sshexec.Runner{Hosts: sshconfig.Config{UserPath: filepath.Join(configDir, "user_ssh_config")}},
	}
	api := NewHTTPHandler(service, noopAuth{})
	t.Cleanup(api.Close)

	// Every route is reached with a tunnel-authorized caller and an otherwise empty service, so the
	// status below is what an unknown session or unmanaged host alias produces, not a routing failure.
	for _, test := range []struct {
		method string
		path   string
		status int
	}{
		{http.MethodPost, "/api/v1/sessions/validate", http.StatusBadRequest},
		{http.MethodPost, "/api/v1/sessions", http.StatusBadRequest},
		{http.MethodGet, "/api/v1/sessions", http.StatusOK},
		{http.MethodGet, "/api/v1/sessions/s-012345abcdef", http.StatusNotFound},
		{http.MethodDelete, "/api/v1/sessions/s-012345abcdef", http.StatusNotFound},
		{http.MethodGet, "/api/v1/sessions/s-012345abcdef/access", http.StatusNotFound},
		{http.MethodGet, "/api/v1/sessions/s-012345abcdef/metrics", http.StatusNotFound},
		{http.MethodGet, "/api/v1/sessions/history", http.StatusOK},
		{http.MethodPost, "/api/v1/sessions/s-012345abcdef/start", http.StatusNotFound},
		{http.MethodPost, "/api/v1/sessions/s-012345abcdef/stop", http.StatusNotFound},
		{http.MethodGet, "/api/v1/ssh", http.StatusOK},
		{http.MethodPost, "/api/v1/ssh", http.StatusBadRequest},
		{http.MethodPut, "/api/v1/ssh/delta", http.StatusBadRequest},
		{http.MethodDelete, "/api/v1/ssh/delta", http.StatusConflict},
		{http.MethodPost, "/api/v1/ssh/delta/test", http.StatusOK},
		{http.MethodGet, "/api/v1/ssh/delta/auth", http.StatusUpgradeRequired},
		{http.MethodGet, "/api/v1/ssh/delta/slurm", http.StatusNotFound},
		{http.MethodGet, "/api/v1/keys", http.StatusOK},
		{http.MethodPost, "/api/v1/keys", http.StatusBadRequest},
		{http.MethodDelete, "/api/v1/keys/delta-key", http.StatusNotFound},
	} {
		t.Run(test.method+" "+test.path, func(t *testing.T) {
			request := httptest.NewRequest(test.method, test.path, nil).WithContext(testTunnelContext())
			response := httptest.NewRecorder()
			api.ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("route %s %s = %d, want %d: %s", test.method, test.path, response.Code, test.status, response.Body.String())
			}
			if strings.Contains(response.Body.String(), `"code":"not_found"`) {
				t.Fatalf("retained route %s %s was not dispatched: %d %s", test.method, test.path, response.Code, response.Body.String())
			}
			if cookies := response.Header().Values("Set-Cookie"); len(cookies) != 0 {
				t.Fatalf("route %s %s emitted cookies: %q", test.method, test.path, cookies)
			}
		})
	}
}

func TestRequestBodiesRefuseUnknownFieldsTrailingDataAndOversizeBodies(t *testing.T) {
	type payload struct {
		Name string `json:"name"`
	}
	refused := map[string]string{
		"an unknown field": `{"name":"a","surprise":1}`,
		"trailing data":    `{"name":"a"}{}`,
		"over 64 KiB":      `{"name":"` + strings.Repeat("a", maxRequestBody) + `"}`,
	}
	for what, body := range refused {
		var target payload
		err := decodeJSON(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)), &target)

		var api *apierr.APIError
		if !errors.As(err, &api) || api.Code != "invalid_json" || api.Status != 400 {
			t.Errorf("%s was accepted; got %v, want 400 invalid_json", what, err)
		}
	}

	var target payload
	if err := decodeJSON(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"a"}`)), &target); err != nil || target.Name != "a" {
		t.Errorf("a well-formed body was refused: %v", err)
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

func TestSessionListDropsAnotherOwnersSessionsAndLogs(t *testing.T) {
	service := testService(t)
	owned := mixedOwnerSession("s-111111111111", testPrincipal)
	other := mixedOwnerSession("s-222222222222", otherTestPrincipal)
	putSessions(t, service, owned, other)
	service.Logs.Append(owned.ID, "owned-log-line", service.now())
	service.Logs.Append(other.ID, "other-owner-log-line", service.now())

	handler := handlerAs(t, service, testPrincipal)

	response := hostRequest(t, handler, http.MethodGet, "/api/v1/sessions", "")
	if got := response.Header().Get("Access-Control-Allow-Origin"); got != mixedOwnerOrigin {
		t.Fatalf("allowed origin = %q, want %q", got, mixedOwnerOrigin)
	}
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
	repeat := hostRequest(t, handler, http.MethodGet, "/api/v1/sessions", "", response.Header().Get("ETag"))
	if repeat.Code != http.StatusNotModified || repeat.Body.Len() != 0 {
		t.Fatalf("unchanged poll = %d %s", repeat.Code, repeat.Body.String())
	}

	otherItem := hostRequest(t, handler, http.MethodGet, "/api/v1/sessions/"+other.ID, "")
	if otherItem.Code != http.StatusForbidden || !strings.Contains(otherItem.Body.String(), `"code":"session_owner_mismatch"`) {
		t.Fatalf("other-owner item = %d %s", otherItem.Code, otherItem.Body.String())
	}
	missingItem := hostRequest(t, handler, http.MethodGet, "/api/v1/sessions/s-333333333333", "")
	if missingItem.Code != http.StatusNotFound || !strings.Contains(missingItem.Body.String(), `"code":"session_not_found"`) {
		t.Fatalf("missing item = %d %s", missingItem.Code, missingItem.Body.String())
	}
}

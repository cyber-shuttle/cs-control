// The session poll and item routes, filtered to the caller who owns the session.
// Another owner's sessions and log tails must never appear.
//
//	mixedOwnerSession
//	Test*
package control

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/cyber-shuttle/cs-control/internal/authn"
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

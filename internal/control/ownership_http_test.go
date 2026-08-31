package control

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cyber-shuttle/cs-control/internal/authn"
)

const mixedOwnerOrigin = "https://workspace.example.edu"

var otherTestPrincipal = authn.Principal{Subject: "other-owner", Tenant: "test-tenant"}

func mixedOwnerRuntime(id string, owner authn.Principal) Runtime {
	runtime := pendingRuntime(id, "alpha", "101")
	runtime.State = "FAILED"
	setTestRuntimeMetadata(&runtime)
	runtime.Owner = owner
	return runtime
}

func mixedOwnerHandler(t *testing.T, service Service) (*HTTPAPI, http.Handler) {
	t.Helper()
	api := NewHTTPHandler(service, nil)
	handler, err := authn.NewOAuthBoundary(api, oauthValidatorFunc(func(context.Context, string) (authn.Principal, error) {
		return testPrincipal, nil
	}), []string{mixedOwnerOrigin})
	if err != nil {
		api.Close()
		t.Fatal(err)
	}
	return api, handler
}

func serveMixedOwnerRequest(t *testing.T, handler http.Handler, path string, ifNoneMatch ...string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, path, nil)
	for _, etag := range ifNoneMatch {
		request.Header.Set("If-None-Match", etag)
	}
	request.Header.Set("Origin", mixedOwnerOrigin)
	request.Header.Set("Authorization", "Bearer delegated-token")
	request.Header.Set(authn.ControlIdentityHeader, testIdentityToken)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if got := response.Header().Get("Access-Control-Allow-Origin"); got != mixedOwnerOrigin {
		t.Fatalf("allowed origin = %q, want %q", got, mixedOwnerOrigin)
	}
	return response
}

func TestRuntimeListDropsAnotherOwnersRuntimesAndLogs(t *testing.T) {
	service := testService(t)
	owned := mixedOwnerRuntime("rt-111111111111", testPrincipal)
	other := mixedOwnerRuntime("rt-222222222222", otherTestPrincipal)
	putRuntimes(t, service, owned, other)
	service.Logs.Append(owned.ID, "owned-log-line")
	service.Logs.Append(other.ID, "other-owner-log-line")

	api, handler := mixedOwnerHandler(t, service)
	defer api.Close()

	response := serveMixedOwnerRequest(t, handler, "/api/v1/runtimes")
	body := response.Body.String()
	var list RuntimeList
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &list) != nil {
		t.Fatalf("runtime list = %d %s", response.Code, body)
	}
	// A tail is as private as the runtime that produced it: the poll carries
	// both, so both must be filtered to the same owned set.
	if len(list.Runtimes) != 1 || list.Runtimes[0].ID != owned.ID {
		t.Fatalf("runtime list did not narrow to the owner: %s", body)
	}
	if len(list.Logs) != 1 || list.Logs[0].RuntimeID != owned.ID {
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
	// An unchanged inventory answers the next poll without repeating any of it.
	repeat := serveMixedOwnerRequest(t, handler, "/api/v1/runtimes", response.Header().Get("ETag"))
	if repeat.Code != http.StatusNotModified || repeat.Body.Len() != 0 {
		t.Fatalf("unchanged poll = %d %s", repeat.Code, repeat.Body.String())
	}

	otherItem := serveMixedOwnerRequest(t, handler, "/api/v1/runtimes/"+other.ID)
	if otherItem.Code != http.StatusForbidden || !strings.Contains(otherItem.Body.String(), `"code":"runtime_owner_mismatch"`) {
		t.Fatalf("other-owner item = %d %s", otherItem.Code, otherItem.Body.String())
	}
	missingItem := serveMixedOwnerRequest(t, handler, "/api/v1/runtimes/rt-333333333333")
	if missingItem.Code != http.StatusNotFound || !strings.Contains(missingItem.Body.String(), `"code":"runtime_not_found"`) {
		t.Fatalf("missing item = %d %s", missingItem.Code, missingItem.Body.String())
	}
}

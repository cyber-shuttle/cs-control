// GuardedClient's redirect discipline: an allowed hop is followed, anything else stops at the last response.
//
//	Test*
package httpx

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cyber-shuttle/cs-control/internal/testutil"
)

func TestGuardedClientFollowsASameOriginRedirect(t *testing.T) {
	var finalAuthorization string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "/end", http.StatusFound)
			return
		}
		finalAuthorization = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := GuardedClient(nil, time.Second, SameOriginRedirect)
	request, err := http.NewRequest(http.MethodGet, server.URL+"/start", nil)
	testutil.Check(t, err)
	request.Header.Set("Authorization", "Bearer secret")
	response, err := client.Do(request)
	testutil.Check(t, err)
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("same-origin redirect was not followed: %d", response.StatusCode)
	}
	if finalAuthorization != "Bearer secret" {
		t.Fatalf("Authorization did not survive the same-origin redirect: %q", finalAuthorization)
	}
}

func TestGuardedClientRefusesACrossOriginRedirect(t *testing.T) {
	var otherSawAuthorization bool
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		otherSawAuthorization = r.Header.Get("Authorization") != ""
		w.WriteHeader(http.StatusOK)
	}))
	defer other.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/steal", http.StatusFound)
	}))
	defer origin.Close()

	client := GuardedClient(nil, time.Second, SameOriginRedirect)
	request, err := http.NewRequest(http.MethodGet, origin.URL, nil)
	testutil.Check(t, err)
	request.Header.Set("Authorization", "Bearer secret")
	response, err := client.Do(request)
	testutil.Check(t, err)
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusFound {
		t.Fatalf("cross-origin redirect was followed instead of stopped at the last response: %d", response.StatusCode)
	}
	if otherSawAuthorization {
		t.Fatal("Authorization followed the cross-origin redirect")
	}
}

func TestGuardedClientCapsRedirectHops(t *testing.T) {
	var hops int
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hops++
		http.Redirect(w, r, server.URL+"/next", http.StatusFound)
	}))
	defer server.Close()

	client := GuardedClient(nil, time.Second, SameOriginRedirect)
	response, err := client.Get(server.URL)
	testutil.Check(t, err)
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusFound {
		t.Fatalf("hop cap did not stop the chain at the last response: %d", response.StatusCode)
	}
	testutil.Equal(t, hops, 5, "hop cap")
}

// Tests Custos identity resolution: a linked user, identity_not_linked, and the five-minute cache.
package identity

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cyber-shuttle/cs-control/internal/testutil"
)

func TestCustosResolverCachesALinkedUser(t *testing.T) {
	calls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/me" || r.Header.Get("Authorization") != "Bearer the-id-token" {
			t.Fatalf("request = %s %s headers=%v", r.Method, r.URL, r.Header)
		}
		writeTestJSON(t, w, map[string]any{"user": map[string]string{"id": "custos-user-1"}})
	}))
	defer server.Close()
	resolver, err := NewCustos(server.URL, server.Client())
	testutil.Check(t, err)
	fixed := time.Unix(1_700_000_000, 0)
	resolver.now = func() time.Time { return fixed }

	userID, err := resolver.Resolve(context.Background(), "the-id-token")
	testutil.Check(t, err)
	if userID != "custos-user-1" {
		t.Fatalf("user ID = %q", userID)
	}

	resolver.now = func() time.Time { return fixed.Add(4 * time.Minute) }
	if _, err := resolver.Resolve(context.Background(), "the-id-token"); err != nil {
		t.Fatal(err)
	}
	testutil.Equal(t, calls, 1, "Custos calls before expiry")

	resolver.now = func() time.Time { return fixed.Add(6 * time.Minute) }
	if _, err := resolver.Resolve(context.Background(), "the-id-token"); err != nil {
		t.Fatal(err)
	}
	testutil.Equal(t, calls, 2, "Custos calls after the cache expires")
}

func TestCustosRequiresAnHTTPSBaseURL(t *testing.T) {
	if _, err := NewCustos("http://127.0.0.1:8100", nil); err != nil {
		t.Fatalf("rejected loopback HTTP Custos URL: %v", err)
	}
	for _, raw := range []string{"", "http://custos.example", "http://localhost:8100", "https://user@custos.example", "https://custos.example?query=1", "https://custos.example#fragment"} {
		if _, err := NewCustos(raw, nil); err == nil {
			t.Fatalf("accepted Custos URL %q", raw)
		}
	}
}

func TestCustosResolverMapsIdentityNotLinked(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"code":"identity_not_linked","message":"OIDC identity is not linked to a portal user"}`))
	}))
	defer server.Close()
	resolver, err := NewCustos(server.URL, server.Client())
	testutil.Check(t, err)

	_, err = resolver.Resolve(context.Background(), "unlinked-token")
	if !errors.Is(err, ErrIdentityNotLinked) {
		t.Fatalf("error = %v", err)
	}
}

// The GitHub validator reads the user once per token and serves the principal from memory until it expires.
//
//	TestGitHubValidatorCachesThePrincipalPerToken
package authn

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cyber-shuttle/cs-control/internal/testutil"
)

func TestGitHubValidatorCachesThePrincipalPerToken(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		switch r.Header.Get("Authorization") {
		case "Bearer gho_first":
			_, _ = w.Write([]byte(`{"id":17297498,"login":"yasithdev"}`))
		case "Bearer gho_second":
			_, _ = w.Write([]byte(`{"id":42,"login":"other"}`))
		default:
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"message":"Bad credentials"}`))
		}
	}))
	t.Cleanup(server.Close)
	validator := newGitHubValidator(server.URL, server.Client())
	now := time.Unix(2_000_000_000, 0)
	validator.now = func() time.Time { return now }

	for range 3 {
		principal, err := validator.Validate(context.Background(), "gho_first")
		testutil.Check(t, err)
		testutil.Equal(t, principal, Principal{Subject: "17297498", Tenant: "github"}, "principal")
	}
	second, err := validator.Validate(context.Background(), "gho_second")
	testutil.Check(t, err)
	testutil.Equal(t, second.Subject, "42", "second principal")
	if _, err := validator.Validate(context.Background(), "gho_revoked"); err == nil {
		t.Fatal("a rejected token produced a principal")
	}
	testutil.Equal(t, calls.Load(), int32(3), "upstream reads")

	now = now.Add(githubPrincipalTTL + time.Second)
	_, err = validator.Validate(context.Background(), "gho_first")
	testutil.Check(t, err)
	testutil.Equal(t, calls.Load(), int32(4), "upstream reads after expiry")
}

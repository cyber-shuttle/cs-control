// Tests the OIDC validator: signature and claim rejection, key refresh, discovery, and issuer policy.
//
//	writeTestJSON, testRSAKey, testJWK, testJWKS, signIDToken, changedClaim, withoutClaim
//	testDiscoveryRoutes, oidcServer, jwksRoute, testBaseURL
//	TestOIDCValidatorAcceptsAValidIDToken, TestOIDCValidatorAcceptsATokenWithNoNotBeforeClaim
//	TestOIDCValidatorRejectsInvalidIdentityTokensWithoutLeaks
//	TestOIDCUnknownKIDFloodCoalescesRefreshWithoutBlockingKnownKey
//	TestOIDCValidatorRejectsWrongJWKAlgorithmAndEncryptionUse, TestOIDCIssuerMustBeHTTPS
//	TestOIDCDiscoveryExposesAuthorizationAndTokenEndpoints
package authn

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cyber-shuttle/cs-control/internal/testutil"
)

func writeTestJSON(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Fatal(fmt.Errorf("write test JSON: %w", err))
	}
}
func testRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	testutil.Check(t, err)
	return key
}

func testJWK(kid string, key *rsa.PublicKey) map[string]string {
	exponent := big.NewInt(int64(key.E)).Bytes()
	return map[string]string{
		"kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid,
		"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(exponent),
	}
}

func testJWKS(kid string, key *rsa.PublicKey) map[string]any {
	return map[string]any{"keys": []map[string]string{testJWK(kid, key)}}
}

func signIDToken(t *testing.T, key *rsa.PrivateKey, claims, header map[string]any) string {
	t.Helper()
	encode := func(value any) string {
		encoded, err := json.Marshal(value)
		testutil.Check(t, err)
		return base64.RawURLEncoding.EncodeToString(encoded)
	}
	signingInput := encode(header) + "." + encode(claims)
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	testutil.Check(t, err)
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func changedClaim(source map[string]any, key string, value any) map[string]any {
	claims := maps.Clone(source)
	claims[key] = value
	return claims
}

func withoutClaim(source map[string]any, key string) map[string]any {
	claims := maps.Clone(source)
	delete(claims, key)
	return claims
}

func testDiscoveryRoutes(server **httptest.Server) map[string]http.HandlerFunc {
	return map[string]http.HandlerFunc{
		"/.well-known/openid-configuration": func(w http.ResponseWriter, _ *http.Request) {
			base := (*server).URL
			_, _ = fmt.Fprintf(w, `{"issuer":%q,"jwks_uri":%q,"authorization_endpoint":%q,"token_endpoint":%q}`, base+"/issuer", base+"/keys", base+"/authorize", base+"/token")
		},
	}
}

func oidcServer(t *testing.T, routes map[string]http.HandlerFunc) *httptest.Server {
	t.Helper()
	var server *httptest.Server
	merged := map[string]http.HandlerFunc{}
	for path, handler := range testDiscoveryRoutes(&server) {
		merged[path] = handler
	}
	for path, handler := range routes {
		merged[path] = handler
	}
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if handler, ok := merged[r.URL.Path]; ok {
			handler(w, r)
			return
		}
		t.Errorf("unexpected OIDC request %s", r.URL)
	}))
	t.Cleanup(server.Close)
	return server
}

func jwksRoute(t *testing.T, kid string, public *rsa.PublicKey) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) { writeTestJSON(t, w, testJWKS(kid, public)) }
}

func testBaseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	testutil.Check(t, err)
	return parsed
}

func TestOIDCValidatorAcceptsAValidIDToken(t *testing.T) {
	key := testRSAKey(t)
	const kid = "identity-key"
	server := oidcServer(t, map[string]http.HandlerFunc{"/keys": jwksRoute(t, kid, &key.PublicKey)})

	validator, err := makeOIDCValidator(testBaseURL(t, server.URL), "client-id", server.Client())
	testutil.Check(t, err)
	now := time.Now().Unix()
	idToken := signIDToken(t, key, map[string]any{
		"iss": server.URL + "/issuer", "aud": "client-id", "exp": now + 300, "nbf": now - 1,
		"sub": "11111111-1111-1111-1111-111111111111",
	}, map[string]any{"alg": "RS256", "kid": kid, "typ": "JWT"})
	testutil.Check(t, validator.Validate(context.Background(), idToken))
}

func TestOIDCValidatorAcceptsATokenWithNoNotBeforeClaim(t *testing.T) {
	key := testRSAKey(t)
	const kid = "identity-key"
	server := oidcServer(t, map[string]http.HandlerFunc{"/keys": jwksRoute(t, kid, &key.PublicKey)})
	validator, err := makeOIDCValidator(testBaseURL(t, server.URL), "client-id", server.Client())
	testutil.Check(t, err)
	now := time.Now().Unix()
	idToken := signIDToken(t, key, map[string]any{
		"iss": server.URL + "/issuer", "aud": "client-id", "exp": now + 300, "sub": "owner-id",
	}, map[string]any{"alg": "RS256", "kid": kid})
	testutil.Check(t, validator.Validate(context.Background(), idToken))
}

func TestOIDCValidatorRejectsInvalidIdentityTokensWithoutLeaks(t *testing.T) {
	key := testRSAKey(t)
	other := testRSAKey(t)
	const kid = "identity-key"
	server := oidcServer(t, map[string]http.HandlerFunc{"/keys": jwksRoute(t, kid, &key.PublicKey)})
	validator, err := makeOIDCValidator(testBaseURL(t, server.URL), "client-id", server.Client())
	testutil.Check(t, err)
	fixed := time.Unix(2_000_000_000, 0)
	validator.now = func() time.Time { return fixed }
	valid := map[string]any{
		"iss": server.URL + "/issuer", "aud": "client-id", "exp": fixed.Unix() + 60, "nbf": fixed.Unix() - 1,
		"sub": "owner-id",
	}
	tests := []struct {
		name   string
		claims map[string]any
		header map[string]any
		key    *rsa.PrivateKey
	}{
		{"issuer", changedClaim(valid, "iss", server.URL+"/other"), map[string]any{"alg": "RS256", "kid": kid}, key},
		{"audience", changedClaim(valid, "aud", "other-client"), map[string]any{"alg": "RS256", "kid": kid}, key},
		{"expired", changedClaim(valid, "exp", fixed.Unix()), map[string]any{"alg": "RS256", "kid": kid}, key},
		{"missing expiration", withoutClaim(valid, "exp"), map[string]any{"alg": "RS256", "kid": kid}, key},
		{"not before", changedClaim(valid, "nbf", fixed.Unix()+1), map[string]any{"alg": "RS256", "kid": kid}, key},
		{"missing subject", changedClaim(valid, "sub", ""), map[string]any{"alg": "RS256", "kid": kid}, key},
		{"algorithm", valid, map[string]any{"alg": "RS512", "kid": kid}, key},
		{"unknown kid", valid, map[string]any{"alg": "RS256", "kid": "unknown-key"}, key},
		{"signature", valid, map[string]any{"alg": "RS256", "kid": kid}, other},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			token := signIDToken(t, test.key, test.claims, test.header)
			err := validator.Validate(context.Background(), token)
			if err == nil || strings.Contains(err.Error(), token) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestOIDCUnknownKIDFloodCoalescesRefreshWithoutBlockingKnownKey(t *testing.T) {
	key := testRSAKey(t)
	const knownKID = "known-key"
	var metadataRequests, keyRequests int
	var requestMu sync.Mutex
	refreshStarted := make(chan struct{})
	releaseRefresh := make(chan struct{})
	var startOnce sync.Once
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			requestMu.Lock()
			metadataRequests++
			requestMu.Unlock()
			_, _ = fmt.Fprintf(w, `{"issuer":%q,"jwks_uri":%q,"authorization_endpoint":%q,"token_endpoint":%q}`, server.URL+"/issuer", server.URL+"/keys", server.URL+"/authorize", server.URL+"/token")
		case "/keys":
			requestMu.Lock()
			keyRequests++
			request := keyRequests
			requestMu.Unlock()
			if request == 2 {
				startOnce.Do(func() { close(refreshStarted) })
				<-releaseRefresh
			}
			writeTestJSON(t, w, testJWKS(knownKID, &key.PublicKey))
		}
	}))
	defer server.Close()
	validator, err := makeOIDCValidator(testBaseURL(t, server.URL), "client-id", server.Client())
	testutil.Check(t, err)
	now := time.Now().Unix()
	claims := map[string]any{"iss": server.URL + "/issuer", "aud": "client-id", "exp": now + 300, "nbf": now - 1, "sub": "owner"}
	known := signIDToken(t, key, claims, map[string]any{"alg": "RS256", "kid": knownKID})
	testutil.Check(t, validator.Validate(context.Background(), known))

	const flood = 512
	start := make(chan struct{})
	errors := make(chan error, flood)
	var workers sync.WaitGroup
	workers.Add(flood)
	for i := 0; i < flood; i++ {
		token := signIDToken(t, key, claims, map[string]any{"alg": "RS256", "kid": fmt.Sprintf("random-%d", i)})
		go func() {
			defer workers.Done()
			<-start
			errors <- validator.Validate(context.Background(), token)
		}()
	}
	close(start)
	select {
	case <-refreshStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("unknown-kid refresh did not start")
	}

	knownDone := make(chan error, 1)
	go func() { knownDone <- validator.Validate(context.Background(), known) }()
	select {
	case err := <-knownDone:
		testutil.Check(t, err)
	case <-time.After(200 * time.Millisecond):
		t.Fatal("known-key validation was serialized behind OIDC refresh")
	}
	close(releaseRefresh)
	workers.Wait()
	close(errors)
	for err := range errors {
		if err == nil {
			t.Fatal("random kid was accepted")
		}
	}
	requestMu.Lock()
	if metadataRequests != 2 || keyRequests != 2 {
		t.Fatalf("OIDC requests metadata=%d keys=%d, want one initial load and one coalesced refresh", metadataRequests, keyRequests)
	}
	requestMu.Unlock()

	cooldownToken := signIDToken(t, key, claims, map[string]any{"alg": "RS256", "kid": "random-after-flood"})
	if err := validator.Validate(context.Background(), cooldownToken); err == nil {
		t.Fatal("unknown kid during cooldown was accepted")
	}
	requestMu.Lock()
	defer requestMu.Unlock()
	if metadataRequests != 2 || keyRequests != 2 {
		t.Fatalf("cooldown triggered network requests metadata=%d keys=%d", metadataRequests, keyRequests)
	}
}

func TestOIDCValidatorRejectsWrongJWKAlgorithmAndEncryptionUse(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(map[string]string)
	}{
		{"wrong algorithm", func(jwk map[string]string) { jwk["alg"] = "RS512" }},
		{"encryption use", func(jwk map[string]string) { delete(jwk, "alg"); jwk["use"] = "enc" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			key := testRSAKey(t)
			jwk := testJWK("rejected-key", &key.PublicKey)
			test.mutate(jwk)
			server := oidcServer(t, map[string]http.HandlerFunc{
				"/keys": func(w http.ResponseWriter, _ *http.Request) {
					writeTestJSON(t, w, map[string]any{"keys": []map[string]string{jwk}})
				},
			})
			validator, err := makeOIDCValidator(testBaseURL(t, server.URL), "client-id", server.Client())
			testutil.Check(t, err)
			now := time.Now().Unix()
			claims := map[string]any{"iss": server.URL + "/issuer", "aud": "client-id", "exp": now + 300, "nbf": now - 1, "sub": "owner"}
			token := signIDToken(t, key, claims, map[string]any{"alg": "RS256", "kid": "rejected-key"})
			if err := validator.Validate(context.Background(), token); err == nil {
				t.Fatalf("invalid JWK was accepted: %#v", jwk)
			}
		})
	}
}

func TestOIDCIssuerMustBeHTTPS(t *testing.T) {
	for _, issuer := range []string{
		"http://cilogon.org",
		"https://user@cilogon.org",
		"not a url",
		"",
	} {
		if _, err := newOIDCValidator(issuer, "client-id", nil); err == nil {
			t.Fatalf("issuer accepted: %q", issuer)
		}
	}
	validator, err := newOIDCValidator("https://cilogon.org", "client-id", nil)
	testutil.Check(t, err)
	if validator.authority.String() != "https://cilogon.org" {
		t.Fatalf("authority = %q", validator.authority)
	}
}

func TestOIDCDiscoveryExposesAuthorizationAndTokenEndpoints(t *testing.T) {
	key := testRSAKey(t)
	server := oidcServer(t, map[string]http.HandlerFunc{"/keys": jwksRoute(t, "kid", &key.PublicKey)})
	validator, err := makeOIDCValidator(testBaseURL(t, server.URL), "client-id", server.Client())
	testutil.Check(t, err)
	metadata, err := validator.Discovery(context.Background())
	testutil.Check(t, err)
	testutil.Equal(t, metadata.AuthorizationEndpoint, server.URL+"/authorize", "authorization endpoint")
	testutil.Equal(t, metadata.TokenEndpoint, server.URL+"/token", "token endpoint")
}

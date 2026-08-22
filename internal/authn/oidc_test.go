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
	"strings"
	"sync"
	"testing"
	"time"
)

func TestMicrosoftOAuthValidatorAcceptsIndependentCapabilityAndIdentityBearers(t *testing.T) {
	key := testRSAKey(t)
	const kid = "identity-key"
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/userlimits":
			// The opaque JWE is independently accepted as a Dev Tunnels
			// capability; it has no locally asserted subject to bind to the ID token.
			if r.Header.Get("Authorization") != "Bearer protected.encrypted-key.iv.ciphertext.tag" {
				t.Fatalf("access authorization = %q", r.Header.Get("Authorization"))
			}
			_, _ = w.Write([]byte(`[]`))
		case "/.well-known/openid-configuration":
			writeTestJSON(t, w, map[string]string{"issuer": server.URL + "/issuer", "jwks_uri": server.URL + "/keys"})
		case "/keys":
			writeTestJSON(t, w, testJWKS(kid, &key.PublicKey))
		default:
			t.Fatalf("unexpected OIDC request %s", r.URL)
		}
	}))
	defer server.Close()

	validator, err := newMicrosoftOAuthValidator(server.URL, server.URL, "client-id", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	// The signed ID token is independently valid and is the sole source of
	// Principal. No at_hash or subject-binding claim is required.
	idToken := signIDToken(t, key, map[string]any{
		"iss": server.URL + "/issuer", "aud": "client-id", "exp": now + 300, "nbf": now - 1,
		"oid": "11111111-1111-1111-1111-111111111111", "tid": "22222222-2222-2222-2222-222222222222",
	}, map[string]any{"alg": "RS256", "kid": kid, "typ": "JWT"})
	principal, err := validator.Validate(context.Background(), OAuthCredentials{AccessToken: "protected.encrypted-key.iv.ciphertext.tag", IDToken: idToken})
	if err != nil {
		t.Fatal(err)
	}
	if principal != (Principal{Subject: "11111111-1111-1111-1111-111111111111", Tenant: "22222222-2222-2222-2222-222222222222"}) {
		t.Fatalf("principal = %#v", principal)
	}
}

func TestOIDCValidatorRejectsInvalidIdentityTokensWithoutLeaks(t *testing.T) {
	key := testRSAKey(t)
	other := testRSAKey(t)
	const kid = "identity-key"
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			writeTestJSON(t, w, map[string]string{"issuer": server.URL + "/issuer", "jwks_uri": server.URL + "/keys"})
		case "/keys":
			writeTestJSON(t, w, testJWKS(kid, &key.PublicKey))
		default:
			t.Fatalf("unexpected request %s", r.URL)
		}
	}))
	defer server.Close()
	validator, err := newOIDCValidator(server.URL, "client-id", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	fixed := time.Unix(2_000_000_000, 0)
	validator.now = func() time.Time { return fixed }
	valid := map[string]any{
		"iss": server.URL + "/issuer", "aud": "client-id", "exp": fixed.Unix() + 60, "nbf": fixed.Unix() - 1,
		"oid": "owner-id", "tid": "tenant-id",
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
		{"missing not before", withoutClaim(valid, "nbf"), map[string]any{"alg": "RS256", "kid": kid}, key},
		{"missing oid", changedClaim(valid, "oid", ""), map[string]any{"alg": "RS256", "kid": kid}, key},
		{"missing tid", changedClaim(valid, "tid", ""), map[string]any{"alg": "RS256", "kid": kid}, key},
		{"algorithm", valid, map[string]any{"alg": "RS512", "kid": kid}, key},
		{"unknown kid", valid, map[string]any{"alg": "RS256", "kid": "unknown-key"}, key},
		{"signature", valid, map[string]any{"alg": "RS256", "kid": kid}, other},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			token := signIDToken(t, test.key, test.claims, test.header)
			_, err := validator.Validate(context.Background(), token)
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
			writeTestJSON(t, w, map[string]string{"issuer": server.URL + "/issuer", "jwks_uri": server.URL + "/keys"})
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
	validator, err := newOIDCValidator(server.URL, "client-id", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	claims := map[string]any{"iss": server.URL + "/issuer", "aud": "client-id", "exp": now + 300, "nbf": now - 1, "oid": "owner", "tid": "tenant"}
	known := signIDToken(t, key, claims, map[string]any{"alg": "RS256", "kid": knownKID})
	if _, err := validator.Validate(context.Background(), known); err != nil {
		t.Fatal(err)
	}

	const flood = maxOIDCNegativeKIDs * 2
	start := make(chan struct{})
	errors := make(chan error, flood)
	var workers sync.WaitGroup
	workers.Add(flood)
	for i := 0; i < flood; i++ {
		token := signIDToken(t, key, claims, map[string]any{"alg": "RS256", "kid": fmt.Sprintf("random-%d", i)})
		go func() {
			defer workers.Done()
			<-start
			_, err := validator.Validate(context.Background(), token)
			errors <- err
		}()
	}
	close(start)
	select {
	case <-refreshStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("unknown-kid refresh did not start")
	}

	// A valid token using a cached known key must not wait behind the blocked
	// refresh, even though all unknown-kid callers are coalesced on it.
	knownDone := make(chan error, 1)
	go func() {
		_, err := validator.Validate(context.Background(), known)
		knownDone <- err
	}()
	select {
	case err := <-knownDone:
		if err != nil {
			t.Fatal(err)
		}
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
	validator.mu.Lock()
	negativeCount := len(validator.negativeKIDs)
	validator.mu.Unlock()
	if negativeCount > maxOIDCNegativeKIDs {
		t.Fatalf("negative-kid cache size = %d, maximum %d", negativeCount, maxOIDCNegativeKIDs)
	}
	requestMu.Lock()
	if metadataRequests != 2 || keyRequests != 2 {
		t.Fatalf("OIDC requests metadata=%d keys=%d, want one initial load and one coalesced refresh", metadataRequests, keyRequests)
	}
	requestMu.Unlock()

	// The global cooldown and bounded negative cache prevent a new random kid
	// from immediately causing another network refresh.
	cooldownToken := signIDToken(t, key, claims, map[string]any{"alg": "RS256", "kid": "random-after-flood"})
	if _, err := validator.Validate(context.Background(), cooldownToken); err == nil {
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
			var server *httptest.Server
			server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/.well-known/openid-configuration":
					writeTestJSON(t, w, map[string]string{"issuer": server.URL + "/issuer", "jwks_uri": server.URL + "/keys"})
				case "/keys":
					writeTestJSON(t, w, map[string]any{"keys": []map[string]string{jwk}})
				}
			}))
			defer server.Close()
			validator, err := newOIDCValidator(server.URL, "client-id", server.Client())
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now().Unix()
			claims := map[string]any{"iss": server.URL + "/issuer", "aud": "client-id", "exp": now + 300, "nbf": now - 1, "oid": "owner", "tid": "tenant"}
			token := signIDToken(t, key, claims, map[string]any{"alg": "RS256", "kid": "rejected-key"})
			if _, err := validator.Validate(context.Background(), token); err == nil {
				t.Fatalf("invalid JWK was accepted: %#v", jwk)
			}
		})
	}
}

func TestProductionOIDCAuthorityIsRestricted(t *testing.T) {
	for _, authority := range []string{
		"http://login.microsoftonline.com/contoso/",
		"https://login.microsoftonline.com.evil/contoso/",
		"https://login.microsoftonline.com/contoso/extra/",
		"https://user@login.microsoftonline.com/contoso/",
		// Runtime ownership is a tenant-scoped subject, so an authority that
		// accepts every tenant must not be configurable at any entry point.
		"https://login.microsoftonline.com/common/",
		"https://login.microsoftonline.com/consumers/",
		"https://login.microsoftonline.com/organizations/",
	} {
		if _, err := NewOIDCValidator(authority, "client-id", nil); err == nil {
			t.Fatalf("authority accepted: %q", authority)
		}
	}
	validator, err := NewOIDCValidator("https://login.microsoftonline.com/contoso/", "client-id", nil)
	if err != nil {
		t.Fatal(err)
	}
	if validator.authority.String() != "https://login.microsoftonline.com/contoso/v2.0" {
		t.Fatalf("normalized authority = %q", validator.authority)
	}
}

func testRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
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
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(encoded)
	}
	signingInput := encode(header) + "." + encode(claims)
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
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

func writeTestJSON(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Fatal(fmt.Errorf("write test JSON: %w", err))
	}
}

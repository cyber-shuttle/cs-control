// OIDC token validation, layered under Validator, backed by discovery and JWKS.
// A signature failure against a known key is hostile input, not evidence of rotation.
// Only an unknown kid inside its cooldown earns a key refresh. Discovery is also where Validator's sign-in
// relay reads the authorization and token endpoints, so both share one cache and one refresh.
//
//	oidcMetadata, oidcKeySet, cachedOIDCKeys, oidcRefreshCall, oidcValidator, idTokenHeader, idTokenClaims
//	makeOIDCValidator, newOIDCValidator, parseSignedIDToken, verifyIDTokenSignature
//	Discovery
package authn

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/cyber-shuttle/cs-control/internal/devtunnel"
	"github.com/cyber-shuttle/cs-control/internal/httpx"
)

const (
	maxOIDCResponse        = 256 << 10
	oidcCacheTTL           = 5 * time.Minute
	oidcUnknownKIDCooldown = 30 * time.Second
)

type oidcMetadata struct {
	Issuer                string `json:"issuer"`
	JWKSURI               string `json:"jwks_uri"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
}

type oidcKeySet struct {
	Keys []struct {
		Kty string `json:"kty"`
		Use string `json:"use"`
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		N   string `json:"n"`
		E   string `json:"e"`
	} `json:"keys"`
}

type cachedOIDCKeys struct {
	metadata oidcMetadata
	keys     map[string]*rsa.PublicKey
	expires  time.Time
}

type oidcRefreshCall struct {
	done chan struct{}
	err  error
}

type oidcValidator struct {
	authority          *url.URL
	clientID           string
	client             *http.Client
	now                clock
	mu                 sync.Mutex
	cache              cachedOIDCKeys
	refresh            *oidcRefreshCall
	nextUnknownRefresh time.Time
}

type idTokenHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

type idTokenClaims struct {
	Issuer    string `json:"iss"`
	Audience  string `json:"aud"`
	Expires   *int64 `json:"exp"`
	NotBefore *int64 `json:"nbf"`
	Subject   string `json:"sub"`
}

func makeOIDCValidator(authority *url.URL, clientID string, client *http.Client) (*oidcValidator, error) {
	if !validIdentityValue(clientID) {
		return nil, errors.New("OIDC client ID is invalid")
	}
	bounded := httpx.GuardedClient(client, oauthRequestTimeout, httpx.SameOriginRedirect)
	return &oidcValidator{authority: authority, clientID: clientID, client: bounded, now: time.Now}, nil
}

func newOIDCValidator(issuer, clientID string, client *http.Client) (*oidcValidator, error) {
	parsed, err := url.Parse(issuer)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("OIDC issuer must be an HTTPS URL")
	}
	return makeOIDCValidator(parsed, clientID, client)
}

func parseSignedIDToken(token string) (idTokenHeader, idTokenClaims, string, []byte, error) {
	var header idTokenHeader
	var claims idTokenClaims
	parts := strings.Split(token, ".")
	if len(parts) != 3 || !validOAuthToken(token) || len(parts[0]) > devtunnel.MaxToken || len(parts[1]) > devtunnel.MaxToken || len(parts[2]) > devtunnel.MaxToken {
		return header, claims, "", nil, errors.New("token format")
	}
	decodeJSON := func(encoded string, destination any) error {
		decoded, ok := canonicalBase64URL(encoded)
		if !ok {
			return errors.New("token encoding")
		}
		if err := json.Unmarshal(decoded, destination); err != nil {
			return errors.New("token JSON")
		}
		return nil
	}
	if err := decodeJSON(parts[0], &header); err != nil || header.Alg != "RS256" || !validIdentityValue(header.Kid) || header.Typ != "" && header.Typ != "JWT" {
		return header, claims, "", nil, errors.New("token header")
	}
	if err := decodeJSON(parts[1], &claims); err != nil {
		return header, claims, "", nil, err
	}
	signature, ok := canonicalBase64URL(parts[2])
	if !ok || len(signature) == 0 {
		return header, claims, "", nil, errors.New("token signature")
	}
	return header, claims, parts[0] + "." + parts[1], signature, nil
}

func verifyIDTokenSignature(key *rsa.PublicKey, signingInput string, signature []byte) error {
	digest := sha256.Sum256([]byte(signingInput))
	return rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature)
}

func (v *oidcValidator) Validate(ctx context.Context, token string) error {
	header, claims, signingInput, signature, err := parseSignedIDToken(token)
	if err != nil {
		return errors.New("ID token is invalid")
	}
	cache, err := v.loadKeys(ctx)
	if err != nil {
		return err
	}
	key := cache.keys[header.Kid]
	if key == nil {
		cache, err = v.refreshUnknownKID(ctx, header.Kid)
		if err != nil {
			return err
		}
		key = cache.keys[header.Kid]
		if key == nil {
			return errors.New("ID token signing key is unknown")
		}
	}
	if err := verifyIDTokenSignature(key, signingInput, signature); err != nil {
		return errors.New("ID token signature is invalid")
	}
	return v.validateClaims(claims, cache.metadata.Issuer)
}

func (v *oidcValidator) validateClaims(claims idTokenClaims, configuredIssuer string) error {
	if claims.Issuer != configuredIssuer || claims.Audience != v.clientID || claims.Expires == nil || !validIdentityValue(claims.Subject) {
		return errors.New("ID token claims are invalid")
	}
	now := v.now().Unix()
	if *claims.Expires <= now {
		return errors.New("ID token is outside its validity period")
	}
	if claims.NotBefore != nil && *claims.NotBefore > now {
		return errors.New("ID token is outside its validity period")
	}
	return nil
}

func (v *oidcValidator) refreshCallLocked() (*oidcRefreshCall, bool) {
	if v.refresh != nil {
		return v.refresh, false
	}
	call := &oidcRefreshCall{done: make(chan struct{})}
	v.refresh = call
	return call, true
}

func (v *oidcValidator) awaitRefresh(ctx context.Context, call *oidcRefreshCall, start bool) (cachedOIDCKeys, error) {
	if start {
		go v.runRefresh(call)
	}
	select {
	case <-ctx.Done():
		return cachedOIDCKeys{}, errors.New("OIDC signing-key refresh was canceled")
	case <-call.done:
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if call.err != nil {
		return cachedOIDCKeys{}, call.err
	}
	return v.cache, nil
}

func (v *oidcValidator) loadKeys(ctx context.Context) (cachedOIDCKeys, error) {
	v.mu.Lock()
	if v.cache.keys != nil && v.now().Before(v.cache.expires) {
		cache := v.cache
		v.mu.Unlock()
		return cache, nil
	}
	call, start := v.refreshCallLocked()
	v.mu.Unlock()
	return v.awaitRefresh(ctx, call, start)
}

func (v *oidcValidator) refreshUnknownKID(ctx context.Context, kid string) (cachedOIDCKeys, error) {
	v.mu.Lock()
	now := v.now()
	if v.cache.keys[kid] != nil || v.refresh == nil && now.Before(v.nextUnknownRefresh) {
		cache := v.cache
		v.mu.Unlock()
		return cache, nil
	}
	call, start := v.refreshCallLocked()
	if start {
		v.nextUnknownRefresh = now.Add(oidcUnknownKIDCooldown)
	}
	v.mu.Unlock()
	return v.awaitRefresh(ctx, call, start)
}

func (v *oidcValidator) runRefresh(call *oidcRefreshCall) {
	metadata, err := v.fetchMetadata(context.Background())
	var keys map[string]*rsa.PublicKey
	if err == nil {
		keys, err = v.fetchKeys(context.Background(), metadata.JWKSURI)
	}
	v.mu.Lock()
	if err == nil {
		v.cache = cachedOIDCKeys{metadata: metadata, keys: keys, expires: v.now().Add(oidcCacheTTL)}
	}
	call.err = err
	if v.refresh == call {
		v.refresh = nil
	}
	close(call.done)
	v.mu.Unlock()
}

func (v *oidcValidator) fetchMetadata(ctx context.Context) (oidcMetadata, error) {
	endpoint := *v.authority
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + "/.well-known/openid-configuration"
	var metadata oidcMetadata
	if err := httpx.GetJSON(ctx, v.client, endpoint.String(), "", maxOIDCResponse, &metadata); err != nil {
		return metadata, errors.New("fetch OIDC discovery metadata")
	}
	issuer, issuerErr := url.Parse(metadata.Issuer)
	jwks, jwksErr := url.Parse(metadata.JWKSURI)
	authorization, authErr := url.Parse(metadata.AuthorizationEndpoint)
	token, tokenErr := url.Parse(metadata.TokenEndpoint)
	if issuerErr != nil || jwksErr != nil || authErr != nil || tokenErr != nil ||
		metadata.Issuer == "" || metadata.JWKSURI == "" || metadata.AuthorizationEndpoint == "" || metadata.TokenEndpoint == "" ||
		issuer.User != nil || jwks.User != nil || authorization.User != nil || token.User != nil {
		return metadata, errors.New("OIDC discovery metadata is invalid")
	}
	sameOrigin := func(candidate *url.URL) bool {
		return candidate.Scheme == v.authority.Scheme && candidate.Host == v.authority.Host
	}
	if !sameOrigin(issuer) || !sameOrigin(jwks) || !sameOrigin(authorization) || !sameOrigin(token) {
		return metadata, errors.New("OIDC discovery endpoints do not match the configured issuer")
	}
	return metadata, nil
}

func (v *oidcValidator) fetchKeys(ctx context.Context, endpoint string) (map[string]*rsa.PublicKey, error) {
	var set oidcKeySet
	if err := httpx.GetJSON(ctx, v.client, endpoint, "", maxOIDCResponse, &set); err != nil {
		return nil, errors.New("fetch OIDC signing keys")
	}
	keys := make(map[string]*rsa.PublicKey, len(set.Keys))
	for _, jwk := range set.Keys {
		if jwk.Kty != "RSA" || (jwk.Use != "" && jwk.Use != "sig") || (jwk.Alg != "" && jwk.Alg != "RS256") {
			continue
		}
		if !validIdentityValue(jwk.Kid) || keys[jwk.Kid] != nil {
			return nil, errors.New("OIDC signing key is invalid")
		}
		n, errN := base64.RawURLEncoding.Strict().DecodeString(jwk.N)
		e, errE := base64.RawURLEncoding.Strict().DecodeString(jwk.E)
		if errN != nil || errE != nil || len(n) < 256 || len(e) == 0 || len(e) > 4 {
			return nil, errors.New("OIDC RSA key is invalid")
		}
		exponent := 0
		for _, value := range e {
			exponent = exponent<<8 | int(value)
		}
		modulus := new(big.Int).SetBytes(n)
		if modulus.BitLen() < 2048 || exponent < 3 || exponent%2 == 0 {
			return nil, errors.New("OIDC RSA key is invalid")
		}
		keys[jwk.Kid] = &rsa.PublicKey{N: modulus, E: exponent}
	}
	if len(keys) == 0 {
		return nil, errors.New("OIDC signing keys are empty")
	}
	return keys, nil
}

// Discovery answers the cached authorization and token endpoints the sign-in relay redeems codes against.
func (v *oidcValidator) Discovery(ctx context.Context) (oidcMetadata, error) {
	cache, err := v.loadKeys(ctx)
	return cache.metadata, err
}

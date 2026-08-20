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
	oidcNegativeKIDTTL     = 5 * time.Minute
	maxOIDCNegativeKIDs    = 256
)

// MicrosoftOAuthValidator validates two independent bearers: the Dev Tunnels
// access token is a capability accepted by the Dev Tunnels API, while the ID
// token is the sole identity bearer. There is intentionally no subject or
// at_hash binding between them.
type MicrosoftOAuthValidator struct {
	access   *DevTunnelOAuthValidator
	identity *OIDCValidator
}

func NewMicrosoftOAuthValidator(devTunnelBaseURL, authority, clientID string, client *http.Client) (*MicrosoftOAuthValidator, error) {
	access, err := NewDevTunnelOAuthValidator(devTunnelBaseURL, client)
	if err != nil {
		return nil, err
	}
	identity, err := NewOIDCValidator(authority, clientID, client)
	if err != nil {
		return nil, err
	}
	return &MicrosoftOAuthValidator{access: access, identity: identity}, nil
}

// newMicrosoftOAuthValidator is the httptest seam. Production callers must use
// NewMicrosoftOAuthValidator so neither credential can be sent to an
// unrecognized authority.
func newMicrosoftOAuthValidator(devTunnelBaseURL, authority, clientID string, client *http.Client) (*MicrosoftOAuthValidator, error) {
	access, err := newDevTunnelOAuthValidator(devTunnelBaseURL, client)
	if err != nil {
		return nil, err
	}
	identity, err := newOIDCValidator(authority, clientID, client)
	if err != nil {
		return nil, err
	}
	return &MicrosoftOAuthValidator{access: access, identity: identity}, nil
}

func (v *MicrosoftOAuthValidator) Validate(ctx context.Context, credentials OAuthCredentials) (Principal, error) {
	if v == nil || v.access == nil || v.identity == nil || !validOAuthToken(credentials.AccessToken) || !validOAuthToken(credentials.IDToken) {
		return Principal{}, errors.New("OAuth credentials are invalid")
	}
	if err := v.access.ValidateAccess(ctx, credentials.AccessToken); err != nil {
		return Principal{}, err
	}
	return v.identity.Validate(ctx, credentials.IDToken)
}

type oidcMetadata struct {
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwks_uri"`
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
	metadata   oidcMetadata
	keys       map[string]*rsa.PublicKey
	expires    time.Time
	generation uint64
}

type oidcRefreshCall struct {
	done chan struct{}
	err  error
}

// OIDCValidator is a bounded RS256 validator backed by OIDC discovery and
// JWKS. Its cache is process-memory only.
type OIDCValidator struct {
	authority          *url.URL
	clientID           string
	client             *http.Client
	production         bool
	now                func() time.Time
	mu                 sync.Mutex
	cache              cachedOIDCKeys
	refresh            *oidcRefreshCall
	nextUnknownRefresh time.Time
	negativeKIDs       map[string]time.Time
}

func NewOIDCValidator(authority, clientID string, client *http.Client) (*OIDCValidator, error) {
	parsed, err := parseProductionOIDCAuthority(authority)
	if err != nil {
		return nil, err
	}
	return makeOIDCValidator(parsed, clientID, client, true)
}

func newOIDCValidator(authority, clientID string, client *http.Client) (*OIDCValidator, error) {
	parsed, err := httpx.ParseBaseURL(authority, "OAuth authority")
	if err != nil {
		return nil, err
	}
	return makeOIDCValidator(parsed, clientID, client, false)
}

func makeOIDCValidator(authority *url.URL, clientID string, client *http.Client, production bool) (*OIDCValidator, error) {
	if !ValidIdentityValue(clientID) {
		return nil, errors.New("OAuth client ID is invalid")
	}
	bounded := httpx.BoundedClient(client, defaultOAuthTimeout)
	bounded.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &OIDCValidator{authority: authority, clientID: clientID, client: bounded, production: production, now: time.Now, negativeKIDs: make(map[string]time.Time)}, nil
}

func parseProductionOIDCAuthority(raw string) (*url.URL, error) {
	parsed, tenant, err := parseTenantAuthority(raw)
	if err != nil {
		return nil, err
	}
	parsed.Path = "/" + tenant + "/v2.0"
	return parsed, nil
}

func (v *OIDCValidator) Validate(ctx context.Context, token string) (Principal, error) {
	header, claims, signingInput, signature, err := parseSignedIDToken(token)
	if err != nil {
		return Principal{}, errors.New("ID token is invalid")
	}
	cache, err := v.loadKeys(ctx)
	if err != nil {
		return Principal{}, err
	}
	key := cache.keys[header.Kid]
	if key == nil {
		cache, err = v.refreshUnknownKID(ctx, header.Kid, cache.generation)
		if err != nil {
			return Principal{}, err
		}
		key = cache.keys[header.Kid]
		if key == nil {
			return Principal{}, errors.New("ID token signing key is unknown")
		}
	}
	// A signature failure for a known kid is hostile input, not evidence of key
	// rotation. Same-kid rotation is picked up by the bounded cache TTL.
	if err := verifyIDTokenSignature(key, signingInput, signature); err != nil {
		return Principal{}, errors.New("ID token signature is invalid")
	}
	if err := v.validateClaims(claims, cache.metadata.Issuer); err != nil {
		return Principal{}, err
	}
	return Principal{Subject: claims.Subject, Tenant: claims.Tenant}, nil
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
	Subject   string `json:"oid"`
	Tenant    string `json:"tid"`
}

func parseSignedIDToken(token string) (idTokenHeader, idTokenClaims, string, []byte, error) {
	var header idTokenHeader
	var claims idTokenClaims
	parts := strings.Split(token, ".")
	if len(parts) != 3 || !validOAuthToken(token) || len(parts[0]) > devtunnel.MaxToken || len(parts[1]) > devtunnel.MaxToken || len(parts[2]) > devtunnel.MaxToken {
		return header, claims, "", nil, errors.New("token format")
	}
	decodeJSON := func(encoded string, destination any) error {
		decoded, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
		if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != encoded {
			return errors.New("token encoding")
		}
		if err := json.Unmarshal(decoded, destination); err != nil {
			return errors.New("token JSON")
		}
		return nil
	}
	if err := decodeJSON(parts[0], &header); err != nil || header.Alg != "RS256" || !ValidIdentityValue(header.Kid) || header.Typ != "" && header.Typ != "JWT" {
		return header, claims, "", nil, errors.New("token header")
	}
	if err := decodeJSON(parts[1], &claims); err != nil {
		return header, claims, "", nil, err
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err != nil || base64.RawURLEncoding.EncodeToString(signature) != parts[2] || len(signature) == 0 {
		return header, claims, "", nil, errors.New("token signature")
	}
	return header, claims, parts[0] + "." + parts[1], signature, nil
}

func (v *OIDCValidator) validateClaims(claims idTokenClaims, configuredIssuer string) error {
	if claims.Audience != v.clientID || claims.Expires == nil || claims.NotBefore == nil || !ValidIdentityValue(claims.Subject) || !ValidIdentityValue(claims.Tenant) {
		return errors.New("ID token claims are invalid")
	}
	expectedIssuer := strings.ReplaceAll(configuredIssuer, "{tenantid}", claims.Tenant)
	if claims.Issuer != expectedIssuer {
		return errors.New("ID token issuer is invalid")
	}
	now := v.now().Unix()
	if *claims.Expires <= now || *claims.NotBefore > now {
		return errors.New("ID token is outside its validity period")
	}
	return nil
}

func verifyIDTokenSignature(key *rsa.PublicKey, signingInput string, signature []byte) error {
	digest := sha256.Sum256([]byte(signingInput))
	return rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature)
}

func (v *OIDCValidator) loadKeys(ctx context.Context) (cachedOIDCKeys, error) {
	v.mu.Lock()
	if v.cache.keys != nil && v.now().Before(v.cache.expires) {
		cache := v.cache
		v.mu.Unlock()
		return cache, nil
	}
	call, start := v.refreshCallLocked()
	v.mu.Unlock()
	if start {
		go v.runRefresh(call)
	}
	if err := waitOIDCRefresh(ctx, call); err != nil {
		return cachedOIDCKeys{}, err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if call.err != nil {
		return cachedOIDCKeys{}, call.err
	}
	return v.cache, nil
}

func (v *OIDCValidator) refreshUnknownKID(ctx context.Context, kid string, observedGeneration uint64) (cachedOIDCKeys, error) {
	v.mu.Lock()
	now := v.now()
	if v.cache.keys[kid] != nil {
		cache := v.cache
		v.mu.Unlock()
		return cache, nil
	}
	if v.cache.generation != observedGeneration {
		v.rememberUnknownKIDLocked(kid, now)
		cache := v.cache
		v.mu.Unlock()
		return cache, nil
	}
	if expires, ok := v.negativeKIDs[kid]; ok && now.Before(expires) {
		cache := v.cache
		v.mu.Unlock()
		return cache, nil
	}
	if v.refresh != nil {
		call := v.refresh
		v.mu.Unlock()
		if err := waitOIDCRefresh(ctx, call); err != nil {
			return cachedOIDCKeys{}, err
		}
		return v.cacheAfterUnknownRefresh(kid, call)
	}
	if now.Before(v.nextUnknownRefresh) {
		v.rememberUnknownKIDLocked(kid, now)
		cache := v.cache
		v.mu.Unlock()
		return cache, nil
	}
	call, _ := v.refreshCallLocked()
	v.nextUnknownRefresh = now.Add(oidcUnknownKIDCooldown)
	v.mu.Unlock()
	go v.runRefresh(call)
	if err := waitOIDCRefresh(ctx, call); err != nil {
		return cachedOIDCKeys{}, err
	}
	return v.cacheAfterUnknownRefresh(kid, call)
}

func (v *OIDCValidator) cacheAfterUnknownRefresh(kid string, call *oidcRefreshCall) (cachedOIDCKeys, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if call.err != nil {
		return cachedOIDCKeys{}, call.err
	}
	if v.cache.keys[kid] == nil {
		v.rememberUnknownKIDLocked(kid, v.now())
	}
	return v.cache, nil
}

func (v *OIDCValidator) refreshCallLocked() (*oidcRefreshCall, bool) {
	if v.refresh != nil {
		return v.refresh, false
	}
	call := &oidcRefreshCall{done: make(chan struct{})}
	v.refresh = call
	return call, true
}

func (v *OIDCValidator) runRefresh(call *oidcRefreshCall) {
	metadata, err := v.fetchMetadata(context.Background())
	var keys map[string]*rsa.PublicKey
	if err == nil {
		keys, err = v.fetchKeys(context.Background(), metadata.JWKSURI)
	}
	v.mu.Lock()
	if err == nil {
		v.cache = cachedOIDCKeys{
			metadata:   metadata,
			keys:       keys,
			expires:    v.now().Add(oidcCacheTTL),
			generation: v.cache.generation + 1,
		}
		for kid := range keys {
			delete(v.negativeKIDs, kid)
		}
	}
	call.err = err
	if v.refresh == call {
		v.refresh = nil
	}
	close(call.done)
	v.mu.Unlock()
}

func waitOIDCRefresh(ctx context.Context, call *oidcRefreshCall) error {
	select {
	case <-ctx.Done():
		return errors.New("OIDC signing-key refresh was canceled")
	case <-call.done:
		return nil
	}
}

func (v *OIDCValidator) rememberUnknownKIDLocked(kid string, now time.Time) {
	for cached, expires := range v.negativeKIDs {
		if !now.Before(expires) {
			delete(v.negativeKIDs, cached)
		}
	}
	if len(v.negativeKIDs) >= maxOIDCNegativeKIDs {
		for cached := range v.negativeKIDs {
			delete(v.negativeKIDs, cached)
			break
		}
	}
	v.negativeKIDs[kid] = now.Add(oidcNegativeKIDTTL)
}

func (v *OIDCValidator) fetchMetadata(ctx context.Context) (oidcMetadata, error) {
	endpoint := *v.authority
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + "/.well-known/openid-configuration"
	var metadata oidcMetadata
	if err := httpx.GetJSON(ctx, v.client, endpoint.String(), "", maxOIDCResponse, &metadata); err != nil {
		return metadata, errors.New("fetch OIDC discovery metadata")
	}
	issuer, issuerErr := url.Parse(metadata.Issuer)
	jwks, jwksErr := url.Parse(metadata.JWKSURI)
	if issuerErr != nil || jwksErr != nil || metadata.Issuer == "" || metadata.JWKSURI == "" || issuer.User != nil || jwks.User != nil {
		return metadata, errors.New("OIDC discovery metadata is invalid")
	}
	if v.production {
		if issuer.Scheme != "https" || issuer.Host != "login.microsoftonline.com" || jwks.Scheme != "https" || jwks.Host != "login.microsoftonline.com" {
			return metadata, errors.New("OIDC discovery endpoints are not recognized")
		}
	} else if issuer.Scheme != v.authority.Scheme || issuer.Host != v.authority.Host || jwks.Scheme != v.authority.Scheme || jwks.Host != v.authority.Host {
		return metadata, errors.New("OIDC discovery endpoints do not match the test authority")
	}
	return metadata, nil
}

func (v *OIDCValidator) fetchKeys(ctx context.Context, endpoint string) (map[string]*rsa.PublicKey, error) {
	var set oidcKeySet
	if err := httpx.GetJSON(ctx, v.client, endpoint, "", maxOIDCResponse, &set); err != nil {
		return nil, errors.New("fetch OIDC signing keys")
	}
	keys := make(map[string]*rsa.PublicKey, len(set.Keys))
	for _, jwk := range set.Keys {
		if jwk.Kty != "RSA" || (jwk.Use != "" && jwk.Use != "sig") || (jwk.Alg != "" && jwk.Alg != "RS256") || !ValidIdentityValue(jwk.Kid) || keys[jwk.Kid] != nil {
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

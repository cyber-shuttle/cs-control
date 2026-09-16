// Package authn is the identity boundary.
// It validates the Dev Tunnels access capability and the Microsoft ID token, and brokers the device-code flow.
// Every request carries both tokens, and the WebSocket route folds its own into a subprotocol handshake.
//
//	Principal, clock, OAuthCredentials, oAuthValidator, oauthBoundary
//	devTunnelOAuthValidator, TunnelAuthorization, tunnelAuthorizationContextKey, tenantSegment
//	canonicalBase64URL, validOAuthToken, validateControlOrigin, validatedOriginSet, allowOrigin
//	preflightHeadersAllowed, validPreflight, writePreflightAllow, bearerToken
//	controlWebSocketRoute, controlWebSocketProtocols, decodeWebSocketCredential, controlWebSocketAuthorization
//	httpOAuthCredentials, withTunnelAuthorization, newDevTunnelOAuthValidatorForBase, newDevTunnelOAuthValidator
//	parseTenantAuthority
//	validIdentityValue, NewOAuthBoundary, WithTunnelAuthorization, TunnelAuthorizationFromContext
package authn

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/cyber-shuttle/cs-control/internal/apierr"
	"github.com/cyber-shuttle/cs-control/internal/devtunnel"
	"github.com/cyber-shuttle/cs-control/internal/httpx"
	"github.com/cyber-shuttle/cs-control/internal/sshconfig"
	"github.com/gorilla/websocket"
)

const (
	maxOAuthResponse                    = 64 << 10
	oauthRequestTimeout                 = 15 * time.Second
	ControlIdentityHeader               = "X-CyberShuttle-Identity"
	ControlWebSocketProtocol            = "cybershuttle.v1"
	WebSocketBearerPrefix               = "bearer."
	WebSocketIdentityPrefix             = "identity."
	maxWebSocketCredentialProtocolBytes = (devtunnel.MaxToken*8 + 5) / 6
)

type Principal struct {
	Subject string `json:"subject"`
	Tenant  string `json:"tenant"`
}

type clock func() time.Time

type OAuthCredentials struct {
	AccessToken string
	IDToken     string
}

type oAuthValidator interface {
	Validate(context.Context, OAuthCredentials) (Principal, error)
}

type oauthBoundary struct {
	next      http.Handler
	validator oAuthValidator
	originSet map[string]struct{}
}

type devTunnelOAuthValidator struct {
	baseURL string
	client  *http.Client
}

type TunnelAuthorization struct {
	OAuthToken string
	Principal  Principal
}

type tunnelAuthorizationContextKey struct{}

var tenantSegment = regexp.MustCompile(`^[A-Za-z0-9.-]{1,256}$`)

func canonicalBase64URL(encoded string) ([]byte, bool) {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != encoded {
		return nil, false
	}
	return decoded, true
}

func validOAuthToken(token string) bool {
	if token == "" || len(token) > devtunnel.MaxToken || !utf8.ValidString(token) {
		return false
	}
	for _, char := range token {
		if unicode.IsControl(char) || unicode.IsSpace(char) {
			return false
		}
	}
	return true
}

func validateControlOrigin(origin string) error {
	if origin == "" || origin == "*" || strings.TrimSpace(origin) != origin {
		return errors.New("control origin is invalid")
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed.User != nil || parsed.Host == "" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("control origin is invalid")
	}
	if parsed.Scheme == "https" {
		return nil
	}
	host := parsed.Hostname()
	ip := net.ParseIP(host)
	if parsed.Scheme == "http" && (host == "localhost" || ip != nil && ip.IsLoopback()) {
		return nil
	}
	return errors.New("control origin must use HTTPS or loopback HTTP")
}

func validatedOriginSet(allowedOrigins []string) (map[string]struct{}, error) {
	origins := make(map[string]struct{}, len(allowedOrigins))
	for _, origin := range allowedOrigins {
		if err := validateControlOrigin(origin); err != nil {
			return nil, err
		}
		origins[origin] = struct{}{}
	}
	if len(origins) == 0 {
		return nil, errors.New("at least one control origin is required")
	}
	return origins, nil
}

func allowOrigin(w http.ResponseWriter, origin string, origins map[string]struct{}) bool {
	if _, ok := origins[origin]; !ok {
		return false
	}
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Add("Vary", "Origin")
	return true
}

func preflightHeadersAllowed(raw string, allowed ...string) bool {
	for _, header := range strings.Split(raw, ",") {
		header = strings.TrimSpace(header)
		if header == "" {
			continue
		}
		if !slices.ContainsFunc(allowed, func(candidate string) bool { return strings.EqualFold(header, candidate) }) {
			return false
		}
	}
	return true
}

func validPreflight(r *http.Request) bool {
	switch r.Header.Get("Access-Control-Request-Method") {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodOptions:
	default:
		return false
	}
	return preflightHeadersAllowed(r.Header.Get("Access-Control-Request-Headers"), "authorization", "content-type", "if-none-match", ControlIdentityHeader)
}

func writePreflightAllow(w http.ResponseWriter, methods, headers string) {
	w.Header().Set("Access-Control-Allow-Methods", methods)
	w.Header().Set("Access-Control-Allow-Headers", headers)
	w.WriteHeader(http.StatusNoContent)
}

func bearerToken(header string) (string, bool) {
	fields := strings.Fields(header)
	if len(fields) != 2 || !strings.EqualFold(fields[0], "Bearer") || !validOAuthToken(fields[1]) {
		return "", false
	}
	return fields[1], true
}

func controlWebSocketRoute(request *http.Request) bool {
	if request.Method != http.MethodGet || request.URL.EscapedPath() != request.URL.Path {
		return false
	}
	const prefix = "/api/v1/ssh/"
	if !strings.HasPrefix(request.URL.Path, prefix) {
		return false
	}
	segments := strings.Split(strings.TrimPrefix(request.URL.Path, prefix), "/")
	return len(segments) == 2 && segments[1] == "auth" && sshconfig.ValidAlias(segments[0])
}

func controlWebSocketProtocols(header http.Header) ([]string, bool) {
	values := header.Values("Sec-WebSocket-Protocol")
	protocols := make([]string, 0, len(values)*2)
	for _, value := range values {
		for _, candidate := range strings.Split(value, ",") {
			candidate = strings.TrimSpace(candidate)
			if candidate == "" {
				return nil, false
			}
			protocols = append(protocols, candidate)
		}
	}
	return protocols, true
}

func decodeWebSocketCredential(encoded string) (string, bool) {
	if encoded == "" || len(encoded) > maxWebSocketCredentialProtocolBytes {
		return "", false
	}
	decoded, ok := canonicalBase64URL(encoded)
	if !ok || !validOAuthToken(string(decoded)) {
		return "", false
	}
	return string(decoded), true
}

func controlWebSocketAuthorization(request *http.Request) (OAuthCredentials, *http.Request, int) {
	protocols, valid := controlWebSocketProtocols(request.Header)
	if !valid {
		return OAuthCredentials{}, request, http.StatusBadRequest
	}
	versionCount, bearerCount, identityCount := 0, 0, 0
	var encodedAccess, encodedIdentity string
	for _, protocol := range protocols {
		switch {
		case protocol == ControlWebSocketProtocol:
			versionCount++
		case strings.HasPrefix(protocol, WebSocketBearerPrefix):
			bearerCount++
			encodedAccess = strings.TrimPrefix(protocol, WebSocketBearerPrefix)
		case strings.HasPrefix(protocol, WebSocketIdentityPrefix):
			identityCount++
			encodedIdentity = strings.TrimPrefix(protocol, WebSocketIdentityPrefix)
		default:
			return OAuthCredentials{}, request, http.StatusBadRequest
		}
	}
	if versionCount != 1 || len(protocols) != 3 {
		return OAuthCredentials{}, request, http.StatusBadRequest
	}
	if bearerCount != 1 || identityCount != 1 {
		return OAuthCredentials{}, request, http.StatusUnauthorized
	}
	accessToken, ok := decodeWebSocketCredential(encodedAccess)
	if !ok {
		return OAuthCredentials{}, request, http.StatusUnauthorized
	}
	identityToken, ok := decodeWebSocketCredential(encodedIdentity)
	if !ok {
		return OAuthCredentials{}, request, http.StatusUnauthorized
	}
	clean := request.Clone(request.Context())
	clean.Header = request.Header.Clone()
	clean.Header.Del("Authorization")
	clean.Header.Del(ControlIdentityHeader)
	clean.Header.Set("Sec-WebSocket-Protocol", ControlWebSocketProtocol)
	return OAuthCredentials{AccessToken: accessToken, IDToken: identityToken}, clean, 0
}

func httpOAuthCredentials(header http.Header) (OAuthCredentials, bool) {
	if len(header.Values("Authorization")) != 1 || len(header.Values(ControlIdentityHeader)) != 1 {
		return OAuthCredentials{}, false
	}
	accessToken, ok := bearerToken(header.Get("Authorization"))
	identityToken := header.Get(ControlIdentityHeader)
	if !ok || !validOAuthToken(identityToken) {
		return OAuthCredentials{}, false
	}
	return OAuthCredentials{AccessToken: accessToken, IDToken: identityToken}, true
}

func withTunnelAuthorization(ctx context.Context, auth TunnelAuthorization) context.Context {
	return context.WithValue(ctx, tunnelAuthorizationContextKey{}, auth)
}

func (b *oauthBoundary) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if origin != "" {
		if !allowOrigin(w, origin, b.originSet) {
			http.Error(w, "origin is not allowed", http.StatusForbidden)
			return
		}
		w.Header().Set("Access-Control-Expose-Headers", "ETag")
	}
	if r.Method == http.MethodOptions && origin != "" && r.Header.Get("Access-Control-Request-Method") != "" {
		if !validPreflight(r) {
			http.Error(w, "preflight is not allowed", http.StatusForbidden)
			return
		}
		writePreflightAllow(w, "GET, POST, PUT, DELETE, OPTIONS", "Authorization, Content-Type, If-None-Match, "+ControlIdentityHeader)
		return
	}
	request := r
	var credentials OAuthCredentials
	var ok bool
	if websocket.IsWebSocketUpgrade(r) && controlWebSocketRoute(r) {
		var status int
		credentials, request, status = controlWebSocketAuthorization(r)
		if status != 0 {
			if status == http.StatusUnauthorized {
				w.Header().Set("WWW-Authenticate", "Bearer")
			}
			http.Error(w, http.StatusText(status), status)
			return
		}
		ok = true
	} else {
		credentials, ok = httpOAuthCredentials(r.Header)
	}
	if !ok {
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	principal, err := b.validator.Validate(request.Context(), credentials)
	if err != nil || principal.Subject == "" || principal.Tenant == "" {
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	ctx := withTunnelAuthorization(request.Context(), TunnelAuthorization{OAuthToken: credentials.AccessToken, Principal: principal})
	b.next.ServeHTTP(w, request.WithContext(ctx))
}

func newDevTunnelOAuthValidatorForBase(base *url.URL, client *http.Client) *devTunnelOAuthValidator {
	bounded := devtunnel.GuardedClient(client, oauthRequestTimeout)
	return &devTunnelOAuthValidator{baseURL: base.String(), client: bounded}
}

func newDevTunnelOAuthValidator(baseURL string, client *http.Client) (*devTunnelOAuthValidator, error) {
	base, err := devtunnel.ParseProductionBaseURL(baseURL)
	if err != nil {
		return nil, err
	}
	return newDevTunnelOAuthValidatorForBase(base, client), nil
}

func (v *devTunnelOAuthValidator) ValidateAccess(ctx context.Context, token string) error {
	if _, ok := bearerToken("Bearer " + token); !ok {
		return errors.New("delegated token is invalid")
	}
	endpoint, _ := url.Parse(v.baseURL)
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + "/userlimits"
	query := endpoint.Query()
	query.Set("api-version", devtunnel.APIVersion)
	endpoint.RawQuery = query.Encode()

	var limits []json.RawMessage
	if err := httpx.GetJSON(ctx, v.client, endpoint.String(), token, maxOAuthResponse, &limits); err != nil {
		return fmt.Errorf("validate delegated token with Dev Tunnels: %w", err)
	}
	return nil
}

func parseTenantAuthority(raw string) (*url.URL, string, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() != "login.microsoftonline.com" ||
		parsed.Host != parsed.Hostname() || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, "", errors.New("OAuth authority must be a pinned tenant-specific Microsoft authority")
	}
	segments := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	if len(segments) != 1 || !tenantSegment.MatchString(segments[0]) {
		return nil, "", errors.New("OAuth authority must identify exactly one Microsoft tenant")
	}
	switch strings.ToLower(segments[0]) {
	case "common", "consumers", "organizations":
		return nil, "", errors.New("OAuth authority must be tenant-specific")
	}
	return parsed, segments[0], nil
}

func validIdentityValue(value string) bool {
	if value == "" || len(value) > 256 {
		return false
	}
	for _, char := range value {
		allowed := (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || strings.ContainsRune("-._:@", char)
		if !allowed {
			return false
		}
	}
	return true
}

func NewOAuthBoundary(next http.Handler, validator oAuthValidator, allowedOrigins []string) (http.Handler, error) {
	if next == nil || validator == nil {
		return nil, errors.New("OAuth boundary dependencies are required")
	}
	origins, err := validatedOriginSet(allowedOrigins)
	if err != nil {
		return nil, err
	}
	return &oauthBoundary{next: next, validator: validator, originSet: origins}, nil
}

func WithTunnelAuthorization(ctx context.Context, auth TunnelAuthorization) context.Context {
	return withTunnelAuthorization(ctx, auth)
}

func TunnelAuthorizationFromContext(ctx context.Context) (TunnelAuthorization, error) {
	auth, ok := ctx.Value(tunnelAuthorizationContextKey{}).(TunnelAuthorization)
	if !ok || auth.OAuthToken == "" || len(auth.OAuthToken) > devtunnel.MaxToken || strings.ContainsAny(auth.OAuthToken, "\x00\r\n") || !validIdentityValue(auth.Principal.Subject) || !validIdentityValue(auth.Principal.Tenant) {
		return TunnelAuthorization{}, apierr.New("tunnel_authorization_required", "fresh delegated Dev Tunnel authorization is required", 401)
	}
	return auth, nil
}

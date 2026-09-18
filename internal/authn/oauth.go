// Package authn is the identity boundary.
// Every request carries one bearer ID token, cryptographically validated against a configured OIDC issuer and
// then resolved to a Custos user, which is the sole identity claim. The WebSocket route folds the same bearer
// into a subprotocol handshake, since a browser cannot send headers to it.
//
//	Principal, clock, OAuthCredentials, oAuthValidator, oauthBoundary, principalContextKey
//	canonicalBase64URL, validOAuthToken, validateControlOrigin, validatedOriginSet, allowOrigin
//	preflightHeadersAllowed, validPreflight, writePreflightAllow, authorizationToken
//	controlWebSocketRoute, controlWebSocketProtocols, decodeWebSocketCredential, controlWebSocketAuthorization
//	httpOAuthCredentials
//	validIdentityValue, PrincipalDirName, NewOAuthBoundary, WithPrincipal, PrincipalFromContext
package authn

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/cyber-shuttle/cs-control/internal/apierr"
	"github.com/cyber-shuttle/cs-control/internal/devtunnel"
	"github.com/cyber-shuttle/cs-control/internal/sshconfig"
	"github.com/gorilla/websocket"
)

const (
	maxOAuthResponse                    = 64 << 10
	oauthRequestTimeout                 = 15 * time.Second
	ControlWebSocketProtocol            = "cybershuttle.v1"
	WebSocketBearerPrefix               = "bearer."
	SchemeBearer                        = "Bearer"
	maxWebSocketCredentialProtocolBytes = (devtunnel.MaxToken*8 + 5) / 6
)

type Principal struct {
	Subject string `json:"subject"`
	Tenant  string `json:"tenant"`
}

type clock func() time.Time

type OAuthCredentials struct {
	IDToken string
}

type oAuthValidator interface {
	Validate(context.Context, OAuthCredentials) (Principal, error)
}

type oauthBoundary struct {
	next      http.Handler
	validator oAuthValidator
	originSet map[string]struct{}
}

type principalContextKey struct{}

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
	methods := []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodOptions}
	return slices.Contains(methods, r.Header.Get("Access-Control-Request-Method")) &&
		preflightHeadersAllowed(r.Header.Get("Access-Control-Request-Headers"), "authorization", "content-type", "if-none-match")
}

func writePreflightAllow(w http.ResponseWriter, methods, headers string) {
	w.Header().Set("Access-Control-Allow-Methods", methods)
	w.Header().Set("Access-Control-Allow-Headers", headers)
	w.WriteHeader(http.StatusNoContent)
}

func authorizationToken(header string) (string, bool) {
	fields := strings.Fields(header)
	if len(fields) != 2 || !strings.EqualFold(fields[0], SchemeBearer) || !validOAuthToken(fields[1]) {
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
	versionCount, bearerCount := 0, 0
	var encoded string
	for _, protocol := range protocols {
		switch {
		case protocol == ControlWebSocketProtocol:
			versionCount++
		case strings.HasPrefix(protocol, WebSocketBearerPrefix):
			bearerCount++
			encoded = strings.TrimPrefix(protocol, WebSocketBearerPrefix)
		default:
			return OAuthCredentials{}, request, http.StatusBadRequest
		}
	}
	if versionCount != 1 || bearerCount != 1 || len(protocols) != 2 {
		return OAuthCredentials{}, request, http.StatusBadRequest
	}
	token, ok := decodeWebSocketCredential(encoded)
	if !ok {
		return OAuthCredentials{}, request, http.StatusUnauthorized
	}
	clean := request.Clone(request.Context())
	clean.Header = request.Header.Clone()
	clean.Header.Del("Authorization")
	clean.Header.Set("Sec-WebSocket-Protocol", ControlWebSocketProtocol)
	return OAuthCredentials{IDToken: token}, clean, 0
}

func httpOAuthCredentials(header http.Header) (OAuthCredentials, bool) {
	if len(header.Values("Authorization")) != 1 {
		return OAuthCredentials{}, false
	}
	token, ok := authorizationToken(header.Get("Authorization"))
	return OAuthCredentials{IDToken: token}, ok
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
		writePreflightAllow(w, "GET, POST, PUT, DELETE, OPTIONS", "Authorization, Content-Type, If-None-Match")
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
	ctx := context.WithValue(request.Context(), principalContextKey{}, principal)
	b.next.ServeHTTP(w, request.WithContext(ctx))
}

func validIdentityValue(value string) bool {
	if value == "" || len(value) > 256 {
		return false
	}
	for _, char := range value {
		allowed := (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || strings.ContainsRune("-._:@/,", char)
		if !allowed {
			return false
		}
	}
	return true
}

func PrincipalDirName(principal Principal) string {
	sum := sha256.Sum256([]byte(principal.Subject + "\x00" + principal.Tenant))
	return hex.EncodeToString(sum[:16])
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

func WithPrincipal(ctx context.Context, principal Principal) context.Context {
	return context.WithValue(ctx, principalContextKey{}, principal)
}

func PrincipalFromContext(ctx context.Context) (Principal, error) {
	principal, ok := ctx.Value(principalContextKey{}).(Principal)
	if !ok || !validIdentityValue(principal.Subject) || !validIdentityValue(principal.Tenant) {
		return Principal{}, apierr.New("tunnel_authorization_required", "an authenticated principal is required", 401)
	}
	return principal, nil
}

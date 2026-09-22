// OAuth middleware applies the API's exact-origin CORS policy and establishes caller identity from one bearer
// channel. Preflight and dispatch read methods from the same route registry. Browser WebSockets carry the same token
// through the versioned subprotocol because their API cannot set Authorization; classified identity failures retain
// their wire meaning rather than being flattened into generic authentication errors.
package oauth

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/cyber-shuttle/cs-control/internal/identity"
	"github.com/cyber-shuttle/cs-control/internal/router"
	"github.com/cyber-shuttle/cs-control/internal/security"
	"github.com/cyber-shuttle/cs-control/internal/ssh"
	"github.com/gorilla/websocket"
)

const (
	webSocketBearerPrefix               = "bearer."
	maxWebSocketCredentialProtocolBytes = (security.MaxCredentialBytes*8 + 5) / 6
)

type oauthBoundary struct {
	next        *router.Registry
	validate    func(context.Context, string) (security.Principal, error)
	originSet   map[string]struct{}
	publicPaths map[string]struct{}
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
		if header != "" && !slices.ContainsFunc(allowed, func(candidate string) bool { return strings.EqualFold(header, candidate) }) {
			return false
		}
	}
	return true
}

func controlWebSocketRoute(request *http.Request) bool {
	if request.Method != http.MethodGet || request.URL.EscapedPath() != request.URL.Path {
		return false
	}
	const prefix = "/api/v1/ssh/hosts/"
	if !strings.HasPrefix(request.URL.Path, prefix) {
		return false
	}
	segments := strings.Split(strings.TrimPrefix(request.URL.Path, prefix), "/")
	return len(segments) == 2 && segments[1] == "auth" && ssh.ValidAlias(segments[0])
}

func controlWebSocketAuthorization(request *http.Request) (string, *http.Request, int) {
	values := request.Header.Values("Sec-WebSocket-Protocol")
	protocols := make([]string, 0, len(values)*2)
	for _, value := range values {
		for _, candidate := range strings.Split(value, ",") {
			candidate = strings.TrimSpace(candidate)
			if candidate == "" {
				return "", request, http.StatusBadRequest
			}
			protocols = append(protocols, candidate)
		}
	}
	versionCount, bearerCount := 0, 0
	var encoded string
	for _, protocol := range protocols {
		switch {
		case protocol == ssh.ControlWebSocketProtocol:
			versionCount++
		case strings.HasPrefix(protocol, webSocketBearerPrefix):
			bearerCount++
			encoded = strings.TrimPrefix(protocol, webSocketBearerPrefix)
		default:
			return "", request, http.StatusBadRequest
		}
	}
	if versionCount != 1 || bearerCount != 1 || len(protocols) != 2 {
		return "", request, http.StatusBadRequest
	}
	if encoded == "" || len(encoded) > maxWebSocketCredentialProtocolBytes {
		return "", request, http.StatusUnauthorized
	}
	decoded, ok := security.DecodeBase64URL(encoded)
	token := string(decoded)
	if !ok || !security.ValidCredential(token) {
		return "", request, http.StatusUnauthorized
	}
	clean := request.Clone(request.Context())
	clean.Header = request.Header.Clone()
	clean.Header.Del("Authorization")
	clean.Header.Set("Sec-WebSocket-Protocol", ssh.ControlWebSocketProtocol)
	return token, clean, 0
}

func httpOAuthCredentials(header http.Header) (string, bool) {
	if len(header.Values("Authorization")) != 1 {
		return "", false
	}
	fields := strings.Fields(header.Get("Authorization"))
	if len(fields) != 2 || !strings.EqualFold(fields[0], "Bearer") || !security.ValidCredential(fields[1]) {
		return "", false
	}
	return fields[1], true
}

func writeUnauthorized(writer http.ResponseWriter) {
	writer.Header().Set("WWW-Authenticate", "Bearer")
	security.WriteError(writer, security.New("unauthorized", "unauthorized", http.StatusUnauthorized))
}

func (b *oauthBoundary) preflight(writer http.ResponseWriter, request *http.Request, public bool) {
	writer.Header().Add("Vary", "Access-Control-Request-Method")
	writer.Header().Add("Vary", "Access-Control-Request-Headers")
	methods, found := b.next.Methods(request)
	if !found {
		security.WriteError(writer, router.ErrNotFound)
		return
	}
	if !slices.Contains(methods, request.Header.Get("Access-Control-Request-Method")) {
		router.MethodNotAllowed(writer, methods)
		return
	}
	allowed := []string{"authorization", "content-type", "if-none-match"}
	responseHeaders := "Authorization, Content-Type, If-None-Match"
	if public {
		allowed = []string{"content-type"}
		responseHeaders = "Content-Type"
	}
	if !preflightHeadersAllowed(request.Header.Get("Access-Control-Request-Headers"), allowed...) {
		security.WriteError(writer, security.New("preflight_not_allowed", "preflight is not allowed", http.StatusForbidden))
		return
	}
	writer.Header().Set("Access-Control-Allow-Methods", strings.Join(methods, ", "))
	writer.Header().Set("Access-Control-Allow-Headers", responseHeaders)
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(http.StatusNoContent)
}

func (b *oauthBoundary) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	_, public := b.publicPaths[request.URL.EscapedPath()]
	origin := request.Header.Get("Origin")
	if origin != "" {
		if !allowOrigin(writer, origin, b.originSet) {
			security.WriteError(writer, security.New("origin_not_allowed", "origin is not allowed", http.StatusForbidden))
			return
		}
		writer.Header().Set("Access-Control-Expose-Headers", "ETag, Location")
	} else if public {
		security.WriteError(writer, security.New("origin_required", "browser origin is required", http.StatusForbidden))
		return
	}
	if request.Method == http.MethodOptions && origin != "" && request.Header.Get("Access-Control-Request-Method") != "" {
		b.preflight(writer, request, public)
		return
	}
	if public {
		b.next.ServeHTTP(writer, request)
		return
	}

	authenticated := request
	var token string
	var ok bool
	if websocket.IsWebSocketUpgrade(request) && controlWebSocketRoute(request) {
		var status int
		token, authenticated, status = controlWebSocketAuthorization(request)
		if status != 0 {
			if status == http.StatusUnauthorized {
				writeUnauthorized(writer)
			} else {
				security.WriteError(writer, security.New("invalid_websocket_auth", "WebSocket authentication is invalid", status))
			}
			return
		}
		ok = true
	} else {
		token, ok = httpOAuthCredentials(request.Header)
	}
	if !ok {
		writeUnauthorized(writer)
		return
	}
	principal, err := b.validate(authenticated.Context(), token)
	if err != nil {
		if classified := security.For(err); classified.Code != "internal_error" {
			if classified.Status == http.StatusUnauthorized {
				writer.Header().Set("WWW-Authenticate", "Bearer")
			}
			security.WriteError(writer, classified)
		} else {
			writeUnauthorized(writer)
		}
		return
	}
	ctx := security.WithPrincipal(authenticated.Context(), principal)
	b.next.ServeHTTP(writer, authenticated.WithContext(ctx))
}

const custosTenant = "custos"

// validate resolves a bearer both channels have already checked for credential shape to its Custos principal.
func (s *Service) validate(ctx context.Context, token string) (security.Principal, error) {
	if err := s.oidc.Validate(ctx, token); err != nil {
		return security.Principal{}, err
	}
	userID, err := s.custos.Resolve(ctx, token)
	if errors.Is(err, identity.ErrIdentityNotLinked) {
		return security.Principal{}, security.New("identity_not_linked", "OIDC identity is not linked to a Custos user", http.StatusUnauthorized)
	}
	if errors.Is(err, identity.ErrIdentityUnrecognized) {
		return security.Principal{}, security.New("identity_not_linked", "Custos did not recognize this identity", http.StatusUnauthorized)
	}
	return security.Principal{Subject: userID, Tenant: custosTenant}, err
}

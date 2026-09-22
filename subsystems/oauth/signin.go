// The sign-in relay finishes the browser's CILogon authorization-code flow with PKCE while keeping the client
// secret server-side. Its three canonical OAuth routes enforce the same exact-origin policy as authenticated API
// requests and share OIDC discovery with bearer validation. Upstream failures are classified without returning
// provider details or tokens.
package oauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/cyber-shuttle/cs-control/internal/identity"
	"github.com/cyber-shuttle/cs-control/internal/router"
	"github.com/cyber-shuttle/cs-control/internal/security"
)

const (
	signInScope        = "openid email profile offline_access"
	maxDeviceEntries   = 256
	deviceSlowDownStep = 5 * time.Second
)

var deviceHandlePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

type oauthConfigResponse struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorizationEndpoint"`
	ClientID              string `json:"clientId"`
	Scope                 string `json:"scope"`
}

type exchangeRequest struct {
	Code         string `json:"code"`
	CodeVerifier string `json:"codeVerifier"`
	RedirectURI  string `json:"redirectUri"`
}

type refreshRequest struct {
	RefreshToken string `json:"refreshToken"`
}

type deviceStart struct {
	Handle           string `json:"handle"`
	UserCode         string `json:"userCode"`
	VerificationURI  string `json:"verificationUri"`
	CompleteURI      string `json:"verificationUriComplete"`
	ExpiresInSeconds int64  `json:"expiresInSeconds"`
	IntervalSeconds  int64  `json:"intervalSeconds"`
}

type pendingAuthorization struct {
	Status          string `json:"status"`
	IntervalSeconds int64  `json:"intervalSeconds"`
}

// deviceEntry keeps the upstream device code server-side; a client only ever holds the opaque handle.
type deviceEntry struct {
	deviceCode string
	expiresAt  time.Time
	interval   time.Duration
	nextPoll   time.Time
}

type tokenResponse struct {
	IDToken          string `json:"idToken"`
	RefreshToken     string `json:"refreshToken,omitempty"`
	ExpiresInSeconds int64  `json:"expiresInSeconds"`
}

type Service struct {
	oidc         *identity.OIDC
	custos       *identity.Custos
	clientID     string
	clientSecret string
	origins      map[string]struct{}
	// validator is s.validate in production; tests substitute a fake.
	validator func(context.Context, string) (security.Principal, error)
	mu        sync.Mutex
	devices   map[string]*deviceEntry
	now       func() time.Time
}

func redirectOriginAllowed(redirectURI string, origins map[string]struct{}) bool {
	parsed, err := url.Parse(redirectURI)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil {
		return false
	}
	_, ok := origins[parsed.Scheme+"://"+parsed.Host]
	return ok
}

func (s *Service) handleConfig(writer http.ResponseWriter, request *http.Request) {
	metadata, err := s.oidc.Discovery(request.Context())
	if err != nil {
		security.WriteError(writer, security.New("upstream_unavailable", "the identity provider is unavailable", http.StatusBadGateway))
		return
	}
	security.WriteJSON(writer, http.StatusOK, oauthConfigResponse{Issuer: metadata.Issuer, AuthorizationEndpoint: metadata.AuthorizationEndpoint, ClientID: s.clientID, Scope: signInScope})
}

func (s *Service) handleExchange(writer http.ResponseWriter, request *http.Request) {
	var body exchangeRequest
	if err := security.DecodeJSON(request, &body); err != nil {
		security.WriteError(writer, err)
		return
	}
	if body.Code == "" || body.CodeVerifier == "" || !redirectOriginAllowed(body.RedirectURI, s.origins) {
		security.WriteError(writer, security.New("invalid_grant", "the request is invalid", http.StatusBadRequest))
		return
	}
	tokens, err := s.oidc.Exchange(request.Context(), s.clientSecret, body.Code, body.CodeVerifier, body.RedirectURI)
	s.writeTokens(writer, tokens, err)
}

func (s *Service) handleRefresh(writer http.ResponseWriter, request *http.Request) {
	var body refreshRequest
	if err := security.DecodeJSON(request, &body); err != nil {
		security.WriteError(writer, err)
		return
	}
	if body.RefreshToken == "" {
		security.WriteError(writer, security.New("invalid_json", "request body is invalid", http.StatusBadRequest))
		return
	}
	tokens, err := s.oidc.Refresh(request.Context(), s.clientSecret, body.RefreshToken)
	s.writeTokens(writer, tokens, err)
}

// upstreamError classifies an identity-provider outcome for every sign-in route, so one grant failure reads the
// same whether it came from an authorization code, a refresh token or a device code.
func upstreamError(err error) error {
	switch {
	case errors.Is(err, identity.ErrGrantRejected):
		return security.New("invalid_grant", "the grant was rejected", http.StatusBadRequest)
	case errors.Is(err, identity.ErrDeviceUnsupported):
		return security.New("device_unsupported", "the identity provider does not offer device sign-in", http.StatusNotImplemented)
	case errors.Is(err, identity.ErrTokenInvalid):
		return security.New("upstream_invalid", "the identity provider returned an invalid response", http.StatusBadGateway)
	default:
		return security.New("upstream_unavailable", "the identity provider is unavailable", http.StatusBadGateway)
	}
}

func (s *Service) writeTokens(writer http.ResponseWriter, tokens identity.Tokens, err error) {
	if err != nil {
		security.WriteError(writer, upstreamError(err))
		return
	}
	security.WriteJSON(writer, http.StatusOK, tokenResponse{IDToken: tokens.IDToken, RefreshToken: tokens.RefreshToken, ExpiresInSeconds: tokens.ExpiresIn})
}

// handleAuthorize starts the device grant for a client that cannot receive a redirect, such as an editor extension.
func (s *Service) handleAuthorize(writer http.ResponseWriter, request *http.Request) {
	s.mu.Lock()
	full := len(s.devices) >= maxDeviceEntries
	s.mu.Unlock()
	if full {
		security.WriteError(writer, security.New("broker_capacity", "authorization service is busy", http.StatusServiceUnavailable))
		return
	}
	authorization, err := s.oidc.DeviceAuthorize(request.Context(), s.clientSecret, signInScope)
	if err != nil {
		security.WriteError(writer, upstreamError(err))
		return
	}
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	handle := base64.RawURLEncoding.EncodeToString(raw)
	now := s.now()
	s.mu.Lock()
	if len(s.devices) >= maxDeviceEntries {
		s.mu.Unlock()
		security.WriteError(writer, security.New("broker_capacity", "authorization service is busy", http.StatusServiceUnavailable))
		return
	}
	s.devices[handle] = &deviceEntry{
		deviceCode: authorization.DeviceCode, expiresAt: now.Add(authorization.ExpiresIn),
		interval: authorization.Interval, nextPoll: now,
	}
	s.mu.Unlock()
	security.WriteJSON(writer, http.StatusOK, deviceStart{
		Handle: handle, UserCode: authorization.UserCode,
		VerificationURI: authorization.VerificationURI, CompleteURI: authorization.CompleteURI,
		ExpiresInSeconds: int64(authorization.ExpiresIn / time.Second),
		IntervalSeconds:  int64(authorization.Interval / time.Second),
	})
}

func (s *Service) handlePoll(writer http.ResponseWriter, request *http.Request) {
	handle := request.PathValue("handle")
	deviceCode, err := s.claimPoll(handle)
	if err != nil {
		security.WriteError(writer, err)
		return
	}
	tokens, err := s.oidc.RedeemDevice(request.Context(), s.clientSecret, deviceCode)
	switch {
	case errors.Is(err, identity.ErrAuthorizationPending), errors.Is(err, identity.ErrSlowDown):
		interval := s.deferPoll(handle, errors.Is(err, identity.ErrSlowDown))
		security.WriteJSON(writer, http.StatusOK, pendingAuthorization{Status: "pending", IntervalSeconds: interval})
	default:
		s.forget(handle)
		s.writeTokens(writer, tokens, err)
	}
}

// claimPoll validates the handle and reserves the next upstream call, so a caller cannot poll faster than the
// interval the provider asked for.
func (s *Service) claimPoll(handle string) (string, error) {
	if !deviceHandlePattern.MatchString(handle) {
		return "", security.New("not_found", "authorization was not found", http.StatusNotFound)
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.devices[handle]
	if !ok {
		return "", security.New("not_found", "authorization was not found", http.StatusNotFound)
	}
	if !now.Before(entry.expiresAt) {
		delete(s.devices, handle)
		return "", security.New("authorization_expired", "authorization expired", http.StatusGone)
	}
	if now.Before(entry.nextPoll) {
		return "", security.New("rate_limited", "polling too quickly", http.StatusTooManyRequests)
	}
	entry.nextPoll = now.Add(entry.interval)
	return entry.deviceCode, nil
}

func (s *Service) deferPoll(handle string, slowDown bool) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.devices[handle]
	if !ok {
		return int64(deviceSlowDownStep / time.Second)
	}
	if slowDown {
		entry.interval += deviceSlowDownStep
		entry.nextPoll = s.now().Add(entry.interval)
	}
	return int64(entry.interval / time.Second)
}

func (s *Service) forget(handle string) {
	s.mu.Lock()
	delete(s.devices, handle)
	s.mu.Unlock()
}

func NewService(custosURL, issuer, clientID, clientSecret string, allowedOrigins []string, client *http.Client) (*Service, error) {
	if strings.TrimSpace(clientSecret) == "" {
		return nil, errors.New("auth service dependencies are required")
	}
	origins, err := validatedOriginSet(allowedOrigins)
	if err != nil {
		return nil, err
	}
	oidc, err := identity.NewOIDC(issuer, clientID, client)
	if err != nil {
		return nil, err
	}
	custos, err := identity.NewCustos(custosURL, client)
	if err != nil {
		return nil, err
	}
	service := &Service{
		oidc: oidc, custos: custos, clientID: clientID, clientSecret: clientSecret, origins: origins,
		devices: map[string]*deviceEntry{}, now: time.Now,
	}
	service.validator = service.validate
	return service, nil
}

func (s *Service) Routes() router.Routes {
	return router.Routes{
		"/api/v1/oauth/config":                       {http.MethodGet: s.handleConfig},
		"/api/v1/oauth/exchange":                     {http.MethodPost: s.handleExchange},
		"/api/v1/oauth/refresh":                      {http.MethodPost: s.handleRefresh},
		"/api/v1/oauth/authorizations":               {http.MethodPost: s.handleAuthorize},
		"/api/v1/oauth/authorizations/{handle}/poll": {http.MethodPost: s.handlePoll},
	}
}

// Protect wraps the registry so that only this service's own routes are public.
func (s *Service) Protect(next *router.Registry) http.Handler {
	public := map[string]struct{}{}
	for path := range s.Routes() {
		public[path] = struct{}{}
	}
	return &oauthBoundary{next: next, validate: s.validator, originSet: s.origins, publicPaths: public}
}

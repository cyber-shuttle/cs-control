// The sign-in relay finishes the browser's CILogon authorization-code flow with PKCE while keeping the client
// secret server-side. Its three canonical OAuth routes enforce the same exact-origin policy as authenticated API
// requests and share OIDC discovery with bearer validation. Upstream failures are classified without returning
// provider details or tokens.
package oauth

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/cyber-shuttle/cs-control/internal/identity"
	"github.com/cyber-shuttle/cs-control/internal/router"
	"github.com/cyber-shuttle/cs-control/internal/security"
)

const signInScope = "openid email profile offline_access"

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

func (s *Service) writeTokens(writer http.ResponseWriter, tokens identity.Tokens, err error) {
	switch {
	case errors.Is(err, identity.ErrGrantRejected):
		security.WriteError(writer, security.New("invalid_grant", "the authorization code or refresh token was rejected", http.StatusBadRequest))
	case errors.Is(err, identity.ErrTokenInvalid):
		security.WriteError(writer, security.New("upstream_invalid", "the identity provider returned an invalid response", http.StatusBadGateway))
	case err != nil:
		security.WriteError(writer, security.New("upstream_unavailable", "the identity provider is unavailable", http.StatusBadGateway))
	default:
		security.WriteJSON(writer, http.StatusOK, tokenResponse{IDToken: tokens.IDToken, RefreshToken: tokens.RefreshToken, ExpiresInSeconds: tokens.ExpiresIn})
	}
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
	service := &Service{oidc: oidc, custos: custos, clientID: clientID, clientSecret: clientSecret, origins: origins}
	service.validator = service.validate
	return service, nil
}

func (s *Service) Routes() router.Routes {
	return router.Routes{
		"/api/v1/oauth/config":   {http.MethodGet: s.handleConfig},
		"/api/v1/oauth/exchange": {http.MethodPost: s.handleExchange},
		"/api/v1/oauth/refresh":  {http.MethodPost: s.handleRefresh},
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

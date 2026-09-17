// The sign-in relay finishes the browser's own CILogon authorization-code flow with PKCE: it holds the client
// secret CILogon's token endpoint requires, which the browser cannot. It sits in front of the OAuth boundary,
// origin-gated the same way the identity broker used to be, and shares Validator's OIDC discovery cache rather
// than fetching its own.
//
//	signInScope
//	signInRelay
//	oauthConfigResponse, exchangeRequest, refreshRequest, tokenResponse
//	writeSignInError, redirectOriginAllowed, postForm
//	NewSignInRoutes
package authn

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/cyber-shuttle/cs-control/internal/apierr"
	"github.com/cyber-shuttle/cs-control/internal/httpx"
)

const signInScope = "openid email profile offline_access"

type signInRelay struct {
	identity     *oidcValidator
	clientID     string
	clientSecret string
	origins      map[string]struct{}
	client       *http.Client
}

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

func writeSignInError(w http.ResponseWriter, status int, code, message string) {
	apierr.WriteError(w, apierr.New(code, message, status))
}

func redirectOriginAllowed(redirectURI string, origins map[string]struct{}) bool {
	parsed, err := url.Parse(redirectURI)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil {
		return false
	}
	_, ok := origins[parsed.Scheme+"://"+parsed.Host]
	return ok
}

func postForm(parent context.Context, client *http.Client, endpoint string, form url.Values, timeout time.Duration) ([]byte, int, error) {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	request, err := httpx.NewRequest(ctx, http.MethodPost, endpoint, "", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, 0, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return httpx.Do(client, request, maxOAuthResponse)
}

func (s *signInRelay) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if origin == "" {
		writeSignInError(w, http.StatusForbidden, "origin_required", "browser origin is required")
		return
	}
	if !allowOrigin(w, origin, s.origins) {
		writeSignInError(w, http.StatusForbidden, "origin_not_allowed", "origin is not allowed")
		return
	}
	if r.URL.RawQuery != "" || r.URL.EscapedPath() != r.URL.Path {
		writeSignInError(w, http.StatusNotFound, "not_found", "route not found")
		return
	}
	method := http.MethodPost
	if r.URL.Path == "/api/v1/oauth/config" {
		method = http.MethodGet
	}
	if r.Method == http.MethodOptions {
		if r.Header.Get("Access-Control-Request-Method") != method || !preflightHeadersAllowed(r.Header.Get("Access-Control-Request-Headers"), "content-type") {
			writeSignInError(w, http.StatusForbidden, "preflight_not_allowed", "preflight is not allowed")
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writePreflightAllow(w, method+", OPTIONS", "Content-Type")
		return
	}
	if r.Method != method {
		writeSignInError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	switch r.URL.Path {
	case "/api/v1/oauth/config":
		s.handleConfig(w, r)
	case "/api/v1/oauth/exchange":
		s.handleExchange(w, r)
	case "/api/v1/oauth/refresh":
		s.handleRefresh(w, r)
	default:
		writeSignInError(w, http.StatusNotFound, "not_found", "route not found")
	}
}

func (s *signInRelay) handleConfig(w http.ResponseWriter, r *http.Request) {
	metadata, err := s.identity.Discovery(r.Context())
	if err != nil {
		writeSignInError(w, http.StatusBadGateway, "upstream_unavailable", "the identity provider is unavailable")
		return
	}
	apierr.WriteJSON(w, http.StatusOK, oauthConfigResponse{Issuer: metadata.Issuer, AuthorizationEndpoint: metadata.AuthorizationEndpoint, ClientID: s.clientID, Scope: signInScope})
}

func (s *signInRelay) handleExchange(w http.ResponseWriter, r *http.Request) {
	var request exchangeRequest
	if apierr.DecodeStrict(io.LimitReader(r.Body, maxOAuthResponse+1), &request) != nil {
		writeSignInError(w, http.StatusBadRequest, "invalid_json", "request body is invalid")
		return
	}
	if request.Code == "" || request.CodeVerifier == "" || !redirectOriginAllowed(request.RedirectURI, s.origins) {
		writeSignInError(w, http.StatusBadRequest, "invalid_grant", "the request is invalid")
		return
	}
	metadata, err := s.identity.Discovery(r.Context())
	if err != nil {
		writeSignInError(w, http.StatusBadGateway, "upstream_unavailable", "the identity provider is unavailable")
		return
	}
	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {request.Code}, "redirect_uri": {request.RedirectURI},
		"code_verifier": {request.CodeVerifier}, "client_id": {s.clientID}, "client_secret": {s.clientSecret},
	}
	s.redeem(r.Context(), w, metadata.TokenEndpoint, form)
}

func (s *signInRelay) handleRefresh(w http.ResponseWriter, r *http.Request) {
	var request refreshRequest
	if apierr.DecodeStrict(io.LimitReader(r.Body, maxOAuthResponse+1), &request) != nil || request.RefreshToken == "" {
		writeSignInError(w, http.StatusBadRequest, "invalid_json", "request body is invalid")
		return
	}
	metadata, err := s.identity.Discovery(r.Context())
	if err != nil {
		writeSignInError(w, http.StatusBadGateway, "upstream_unavailable", "the identity provider is unavailable")
		return
	}
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {request.RefreshToken}, "client_id": {s.clientID}, "client_secret": {s.clientSecret}}
	s.redeem(r.Context(), w, metadata.TokenEndpoint, form)
}

func (s *signInRelay) redeem(ctx context.Context, w http.ResponseWriter, tokenEndpoint string, form url.Values) {
	body, status, err := postForm(ctx, s.client, tokenEndpoint, form, oauthRequestTimeout)
	if err != nil {
		writeSignInError(w, http.StatusBadGateway, "upstream_unavailable", "the identity provider is unavailable")
		return
	}
	var oauthError struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(body, &oauthError)
	if status < 200 || status >= 300 || oauthError.Error != "" {
		if oauthError.Error == "invalid_grant" {
			writeSignInError(w, http.StatusBadRequest, "invalid_grant", "the authorization code or refresh token was rejected")
		} else {
			writeSignInError(w, http.StatusBadGateway, "upstream_unavailable", "the identity provider is unavailable")
		}
		return
	}
	var tokens struct {
		IDToken      string `json:"id_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
	}
	if json.Unmarshal(body, &tokens) != nil || !validOAuthToken(tokens.IDToken) || tokens.ExpiresIn <= 0 || tokens.ExpiresIn > 86400 || tokens.RefreshToken != "" && !validOAuthToken(tokens.RefreshToken) {
		writeSignInError(w, http.StatusBadGateway, "upstream_invalid", "the identity provider returned an invalid response")
		return
	}
	apierr.WriteJSON(w, http.StatusOK, tokenResponse{IDToken: tokens.IDToken, RefreshToken: tokens.RefreshToken, ExpiresInSeconds: tokens.ExpiresIn})
}

func NewSignInRoutes(next http.Handler, validator *Validator, clientSecret string, allowedOrigins []string) (http.Handler, error) {
	if next == nil || validator == nil || validator.identity == nil || strings.TrimSpace(clientSecret) == "" {
		return nil, errors.New("sign-in relay dependencies are required")
	}
	origins, err := validatedOriginSet(allowedOrigins)
	if err != nil {
		return nil, err
	}
	relay := &signInRelay{identity: validator.identity, clientID: validator.identity.clientID, clientSecret: clientSecret, origins: origins, client: httpx.BoundedClient(nil, oauthRequestTimeout)}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.EscapedPath() {
		case "/api/v1/oauth/config", "/api/v1/oauth/exchange", "/api/v1/oauth/refresh":
			relay.ServeHTTP(w, r)
		default:
			next.ServeHTTP(w, r)
		}
	}), nil
}

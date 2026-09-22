// Tests the sign-in relay: config discovery, code exchange, refresh, and redirect-origin refusal.
package oauth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cyber-shuttle/cs-control/internal/router"
	"github.com/cyber-shuttle/cs-control/internal/testutil"
)

func newTestSignInRelay(t *testing.T, tokenRoute http.HandlerFunc) (http.Handler, *httptest.Server) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	testutil.Check(t, err)
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_, _ = w.Write([]byte(`{"issuer":"` + server.URL + `","jwks_uri":"` + server.URL + `/keys","authorization_endpoint":"` + server.URL + `/authorize","token_endpoint":"` + server.URL + `/token"}`))
		case "/keys":
			exponent := big.NewInt(int64(key.E)).Bytes()
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
				"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "relay-key",
				"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(exponent),
			}}})
		case "/token":
			tokenRoute(w, r)
		default:
			t.Errorf("unexpected relay request %s", r.URL)
		}
	}))
	t.Cleanup(server.Close)
	service, err := NewService(server.URL, server.URL, "the-client-id", "the-client-secret", []string{"https://workspace.example.edu"}, server.Client())
	testutil.Check(t, err)
	routes, err := router.New(service.Routes())
	testutil.Check(t, err)
	return service.Protect(routes), server
}

func TestSignInConfigAnswersCanonicalRoute(t *testing.T) {
	handler, server := newTestSignInRelay(t, nil)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/oauth/config", nil)
	request.Header.Set("Origin", "https://workspace.example.edu")
	response := testutil.Serve(handler, request)
	testutil.Equal(t, response.Code, http.StatusOK, "config status")
	var body oauthConfigResponse
	testutil.Check(t, json.Unmarshal(response.Body.Bytes(), &body))
	testutil.Equal(t, body.Issuer, server.URL, "issuer")
	testutil.Equal(t, body.AuthorizationEndpoint, server.URL+"/authorize", "authorization endpoint")
	testutil.Equal(t, body.ClientID, "the-client-id", "client id")

	for path, method := range map[string]string{"/api/v1/oauth/config": http.MethodGet, "/api/v1/oauth/exchange": http.MethodPost} {
		request := httptest.NewRequest(http.MethodOptions, path, nil)
		request.Header.Set("Origin", "https://workspace.example.edu")
		request.Header.Set("Access-Control-Request-Method", method)
		request.Header.Set("Access-Control-Request-Headers", "content-type")
		if response := testutil.Serve(handler, request); response.Code != http.StatusNoContent {
			t.Fatalf("%s preflight = %d %s", path, response.Code, response.Body.String())
		}
	}
}

func TestSignInExchangeRedeemsACode(t *testing.T) {
	handler, _ := newTestSignInRelay(t, func(w http.ResponseWriter, r *http.Request) {
		testutil.Check(t, r.ParseForm())
		if r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("code") != "the-code" ||
			r.Form.Get("code_verifier") != "the-verifier" || r.Form.Get("client_secret") != "the-client-secret" ||
			r.Form.Get("redirect_uri") != "https://workspace.example.edu/callback" {
			t.Fatalf("token request = %v", r.Form)
		}
		_, _ = w.Write([]byte(`{"id_token":"header.payload.signature","refresh_token":"a-refresh-token","expires_in":900}`))
	})
	body := strings.NewReader(`{"code":"the-code","codeVerifier":"the-verifier","redirectUri":"https://workspace.example.edu/callback"}`)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/exchange", body)
	request.Header.Set("Origin", "https://workspace.example.edu")
	response := testutil.Serve(handler, request)
	testutil.Equal(t, response.Code, http.StatusOK, "exchange status")
	var tokens tokenResponse
	testutil.Check(t, json.Unmarshal(response.Body.Bytes(), &tokens))
	testutil.Equal(t, tokens.IDToken, "header.payload.signature", "id token")
	testutil.Equal(t, tokens.RefreshToken, "a-refresh-token", "refresh token")
	testutil.Equal(t, tokens.ExpiresInSeconds, int64(900), "expires in")
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q", response.Header().Get("Cache-Control"))
	}

	t.Run("foreign redirect", func(t *testing.T) {
		body := strings.NewReader(`{"code":"the-code","codeVerifier":"the-verifier","redirectUri":"https://evil.example/callback"}`)
		request := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/exchange", body)
		request.Header.Set("Origin", "https://workspace.example.edu")
		response := testutil.Serve(handler, request)
		testutil.Equal(t, response.Code, http.StatusBadRequest, "foreign redirect status")
	})
}

func TestSignInRefreshRotatesTokens(t *testing.T) {
	handler, _ := newTestSignInRelay(t, func(w http.ResponseWriter, r *http.Request) {
		testutil.Check(t, r.ParseForm())
		if r.Form.Get("grant_type") != "refresh_token" || r.Form.Get("refresh_token") != "old-refresh-token" {
			t.Fatalf("refresh request = %v", r.Form)
		}
		_, _ = w.Write([]byte(`{"id_token":"header.payload.signature","refresh_token":"new-refresh-token","expires_in":900}`))
	})
	body := strings.NewReader(`{"refreshToken":"old-refresh-token"}`)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/refresh", body)
	request.Header.Set("Origin", "https://workspace.example.edu")
	response := testutil.Serve(handler, request)
	testutil.Equal(t, response.Code, http.StatusOK, "refresh status")
	var tokens tokenResponse
	testutil.Check(t, json.Unmarshal(response.Body.Bytes(), &tokens))
	testutil.Equal(t, tokens.RefreshToken, "new-refresh-token", "rotated refresh token")
}

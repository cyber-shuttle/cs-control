// Tests the OAuth boundary's origins, its two credential channels, redirect and claim rejection, and poll headers.
//
//	testIdentityToken, testPrincipal, oauthValidatorFunc, oauthCredentialsValidatorFunc, testBaseURL
//	browserWebSocketProtocols, browserUpgradeRequest
//	TestOAuthBoundaryExactOriginsBearerAndNative, TestOAuthBoundaryWebSocketSubprotocolBearer
//	TestOAuthBoundaryWebSocketRejectsHeaderCredentialChannels, TestOAuthValidatorAcceptsEncryptedDevTunnelsAccessToken
//	TestOAuthValidatorDoesNotFollowBearerToUntrustedRedirect, TestOAuthValidatorRejectsUnvalidatedClaimsAndRedacts
//	TestOAuthBoundaryConditionalPollHeaders, TestOAuthBoundaryAcceptsAGitHubTokenAloneOverHeadersAndSubprotocol
package authn

import (
	"bytes"
	"context"
	"encoding/base64"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/cyber-shuttle/cs-control/internal/devtunnel"
	"github.com/cyber-shuttle/cs-control/internal/testutil"
)

const testIdentityToken = "signed-test-identity-token"

var testPrincipal = Principal{Subject: "test-owner", Tenant: "test-tenant"}

type oauthValidatorFunc func(context.Context, string) (Principal, error)

type oauthCredentialsValidatorFunc func(context.Context, OAuthCredentials) (Principal, error)

func testBaseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	base, err := devtunnel.ParseBaseURL(raw, "test base URL")
	testutil.Check(t, err)
	return base
}

func (f oauthValidatorFunc) Validate(ctx context.Context, credentials OAuthCredentials) (Principal, error) {
	return f(ctx, credentials.AccessToken)
}

func (f oauthCredentialsValidatorFunc) Validate(ctx context.Context, credentials OAuthCredentials) (Principal, error) {
	return f(ctx, credentials)
}

func browserWebSocketProtocols(token string) string {
	return ControlWebSocketProtocol + ", " + WebSocketBearerPrefix + base64.RawURLEncoding.EncodeToString([]byte(token)) + ", " + WebSocketIdentityPrefix + base64.RawURLEncoding.EncodeToString([]byte(testIdentityToken))
}

func browserUpgradeRequest(token string) *http.Request {
	request := httptest.NewRequest(http.MethodGet, "http://control.example/api/v1/ssh/delta/auth", nil)
	for name, value := range map[string]string{
		"Origin":                 "https://workspace.example.edu",
		"Connection":             "Upgrade",
		"Upgrade":                "websocket",
		"Sec-WebSocket-Version":  "13",
		"Sec-WebSocket-Protocol": browserWebSocketProtocols(token),
	} {
		request.Header.Set(name, value)
	}
	return request
}

func TestOAuthBoundaryExactOriginsBearerAndNative(t *testing.T) {
	const token = "delegated-secret-token"
	validator := oauthCredentialsValidatorFunc(func(_ context.Context, got OAuthCredentials) (Principal, error) {
		if got != (OAuthCredentials{Scheme: SchemeBearer, AccessToken: token, IDToken: testIdentityToken}) {
			t.Fatalf("credentials were not passed exactly")
		}
		return Principal{Subject: "owner", Tenant: "tenant"}, nil
	})
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth, err := TunnelAuthorizationFromContext(r.Context())
		if err != nil || auth.OAuthToken != token || auth.Principal != (Principal{Subject: "owner", Tenant: "tenant"}) {
			t.Fatalf("tunnel authorization = %#v, %v", auth, err)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	handler, err := NewOAuthBoundary(next, validator, []string{"https://workspace.example.edu", "http://127.0.0.1:8045"})
	testutil.Check(t, err)

	for _, origin := range []string{"https://workspace.example.edu", "http://127.0.0.1:8045"} {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions", nil)
		req.Header.Set("Origin", origin)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set(ControlIdentityHeader, testIdentityToken)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusNoContent || rr.Header().Get("Access-Control-Allow-Origin") != origin || rr.Header().Get("Access-Control-Allow-Credentials") != "" {
			t.Fatalf("origin %q: code=%d headers=%v", origin, rr.Code, rr.Header())
		}
	}

	native := httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)
	native.Header.Set("Authorization", "Bearer "+token)
	native.Header.Set(ControlIdentityHeader, testIdentityToken)
	native.AddCookie(&http.Cookie{Name: "cs_session", Value: "ignored"})
	native.Header.Set("X-XSRFToken", "ignored")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, native)
	if rr.Code != http.StatusNoContent || rr.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("native code=%d headers=%v", rr.Code, rr.Header())
	}
}

func TestOAuthBoundaryWebSocketSubprotocolBearer(t *testing.T) {
	const token = "delegated-websocket-token"
	var logs bytes.Buffer
	previousLogOutput := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(previousLogOutput)
	validatorCalls := 0
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Fatal("subprotocol bearer was copied into Authorization")
		}
		if got := r.Header.Get("Sec-WebSocket-Protocol"); got != ControlWebSocketProtocol {
			t.Fatalf("inner protocols = %q", got)
		}
		if strings.Contains(r.URL.String(), token) || strings.Contains(r.URL.String(), base64.RawURLEncoding.EncodeToString([]byte(token))) {
			t.Fatalf("request URL exposed token: %s", r.URL)
		}
		auth, err := TunnelAuthorizationFromContext(r.Context())
		if err != nil || auth.OAuthToken != token || auth.Principal != testPrincipal {
			t.Fatalf("context authorization = %#v, %v", auth, err)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	handler, err := NewOAuthBoundary(next, oauthValidatorFunc(func(_ context.Context, got string) (Principal, error) {
		validatorCalls++
		testutil.Equal(t, got, token, "validated token")
		return testPrincipal, nil
	}), []string{"https://workspace.example.edu"})
	testutil.Check(t, err)
	request := browserUpgradeRequest(token)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || validatorCalls != 1 {
		t.Fatalf("websocket OAuth response = %d calls=%d body=%q", response.Code, validatorCalls, response.Body.String())
	}
	for _, secret := range []string{token, base64.RawURLEncoding.EncodeToString([]byte(token))} {
		if strings.Contains(response.Body.String(), secret) || strings.Contains(response.Header().Get("Sec-WebSocket-Protocol"), secret) || strings.Contains(logs.String(), secret) {
			t.Fatalf("boundary exposed %q: headers=%v body=%q logs=%q", secret, response.Header(), response.Body.String(), logs.String())
		}
	}
}

func TestOAuthBoundaryWebSocketRejectsHeaderCredentialChannels(t *testing.T) {
	const token = "native-websocket-token"
	calls := 0
	handler, err := NewOAuthBoundary(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "" || request.Header.Get(ControlIdentityHeader) != "" || request.Header.Get("Sec-WebSocket-Protocol") != ControlWebSocketProtocol {
			t.Fatalf("secret WebSocket protocols were not stripped: %v", request.Header)
		}
		w.WriteHeader(http.StatusNoContent)
	}), oauthValidatorFunc(func(context.Context, string) (Principal, error) {
		calls++
		return testPrincipal, nil
	}), []string{"https://workspace.example.edu"})
	testutil.Check(t, err)
	request := browserUpgradeRequest(token)
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set(ControlIdentityHeader, testIdentityToken)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || calls != 1 {
		t.Fatalf("protocol-authenticated WebSocket response = %d calls=%d %q", response.Code, calls, response.Body.String())
	}
}

func TestOAuthValidatorAcceptsEncryptedDevTunnelsAccessToken(t *testing.T) {
	token := "protected.encrypted-key.iv.ciphertext.tag"
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if r.Method != http.MethodGet || r.URL.Path != "/userlimits" || r.URL.Query().Get("api-version") != devtunnel.APIVersion || r.Header.Get("Authorization") != "Bearer "+token {
			t.Fatalf("request = %s %s headers=%v", r.Method, r.URL, r.Header)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	}))
	defer server.Close()
	validator := newDevTunnelOAuthValidatorForBase(testBaseURL(t, server.URL), server.Client())
	testutil.Check(t, validator.ValidateAccess(context.Background(), SchemeBearer, token))
	if !called {
		t.Fatal("Dev Tunnels validation endpoint was not called")
	}
}

func TestOAuthValidatorDoesNotFollowBearerToUntrustedRedirect(t *testing.T) {
	const token = "header.payload.signature-secret"
	hostileCalled := false
	hostile := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hostileCalled = true
		if r.Header.Get("Authorization") != "" {
			t.Fatalf("bearer leaked to hostile redirect: %q", r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer hostile.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, hostile.URL, http.StatusTemporaryRedirect)
	}))
	defer origin.Close()
	validator := newDevTunnelOAuthValidatorForBase(testBaseURL(t, origin.URL), origin.Client())
	if err := validator.ValidateAccess(context.Background(), SchemeBearer, token); err == nil {
		t.Fatal("redirect response accepted")
	}
	if hostileCalled {
		t.Fatal("untrusted redirect was followed")
	}
}

func TestOAuthValidatorRejectsUnvalidatedClaimsAndRedacts(t *testing.T) {
	const secret = "header.payload.signature-secret"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "rejected "+r.Header.Get("Authorization"), http.StatusUnauthorized)
	}))
	defer server.Close()
	validator := newDevTunnelOAuthValidatorForBase(testBaseURL(t, server.URL), server.Client())
	err := validator.ValidateAccess(context.Background(), SchemeBearer, secret)
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("error = %v", err)
	}
}

func TestOAuthBoundaryConditionalPollHeaders(t *testing.T) {
	const origin = "https://workspace.example.edu"
	validator := oauthValidatorFunc(func(context.Context, string) (Principal, error) { return testPrincipal, nil })
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("ETag", `"abc"`)
		w.WriteHeader(http.StatusNotModified)
	})
	handler, err := NewOAuthBoundary(next, validator, []string{origin})
	testutil.Check(t, err)

	preflight := httptest.NewRequest(http.MethodOptions, "/api/v1/sessions", nil)
	preflight.Header.Set("Origin", origin)
	preflight.Header.Set("Access-Control-Request-Method", http.MethodGet)
	preflight.Header.Set("Access-Control-Request-Headers", "authorization,if-none-match,"+strings.ToLower(ControlIdentityHeader))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, preflight)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("preflight code=%d body=%q", rr.Code, rr.Body.String())
	}
	if !strings.Contains(strings.ToLower(rr.Header().Get("Access-Control-Allow-Headers")), "if-none-match") {
		t.Fatalf("Allow-Headers = %q", rr.Header().Get("Access-Control-Allow-Headers"))
	}

	actual := httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)
	actual.Header.Set("Origin", origin)
	actual.Header.Set("Authorization", "Bearer token-value")
	actual.Header.Set(ControlIdentityHeader, testIdentityToken)
	actual.Header.Set("If-None-Match", `"abc"`)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, actual)
	if rr.Code != http.StatusNotModified || rr.Header().Get("Access-Control-Expose-Headers") != "ETag" {
		t.Fatalf("code=%d headers=%v", rr.Code, rr.Header())
	}
}

func TestOAuthBoundaryAcceptsAGitHubTokenAloneOverHeadersAndSubprotocol(t *testing.T) {
	const token = "gho_github_secret_token"
	validator := oauthCredentialsValidatorFunc(func(_ context.Context, got OAuthCredentials) (Principal, error) {
		if got != (OAuthCredentials{Scheme: SchemeGitHub, AccessToken: token}) {
			t.Fatalf("credentials = %#v", got)
		}
		return Principal{Subject: "17297498", Tenant: SchemeGitHub}, nil
	})
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth, err := TunnelAuthorizationFromContext(r.Context())
		if err != nil || auth.Authorization() != "github "+token || auth.Principal.Tenant != SchemeGitHub {
			t.Fatalf("tunnel authorization = %#v, %v", auth, err)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	handler, err := NewOAuthBoundary(next, validator, []string{"https://workspace.example.edu"})
	testutil.Check(t, err)

	request := httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)
	request.Header.Set("Authorization", "github "+token)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	testutil.Equal(t, response.Code, http.StatusNoContent, "github header")

	request.Header.Set(ControlIdentityHeader, testIdentityToken)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	testutil.Equal(t, response.Code, http.StatusUnauthorized, "github token with a stray identity header")

	upgrade := browserUpgradeRequest(token)
	upgrade.Header.Set("Sec-WebSocket-Protocol", ControlWebSocketProtocol+", "+WebSocketGitHubPrefix+base64.RawURLEncoding.EncodeToString([]byte(token)))
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, upgrade)
	testutil.Equal(t, response.Code, http.StatusNoContent, "github subprotocol")

	upgrade.Header.Set("Sec-WebSocket-Protocol", browserWebSocketProtocols(token)+", "+WebSocketGitHubPrefix+base64.RawURLEncoding.EncodeToString([]byte(token)))
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, upgrade)
	testutil.Equal(t, response.Code, http.StatusUnauthorized, "both credential shapes at once")
}

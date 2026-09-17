// Tests the OAuth boundary's origins, its one bearer credential channel over headers and over a subprotocol,
// and its conditional poll headers.
//
//	testPrincipal, oauthValidatorFunc
//	browserWebSocketProtocols, browserUpgradeRequest
//	TestOAuthBoundaryExactOriginsBearerAndNative, TestOAuthBoundaryWebSocketSubprotocolBearer
//	TestOAuthBoundaryWebSocketRejectsHeaderCredentialChannels, TestOAuthBoundaryConditionalPollHeaders
//	TestOAuthBoundaryRejectsMalformedCredentials
package authn

import (
	"bytes"
	"context"
	"encoding/base64"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cyber-shuttle/cs-control/internal/testutil"
)

var testPrincipal = Principal{Subject: "test-owner", Tenant: "test-tenant"}

type oauthValidatorFunc func(context.Context, OAuthCredentials) (Principal, error)

func (f oauthValidatorFunc) Validate(ctx context.Context, credentials OAuthCredentials) (Principal, error) {
	return f(ctx, credentials)
}

func browserWebSocketProtocols(token string) string {
	return ControlWebSocketProtocol + ", " + WebSocketBearerPrefix + base64.RawURLEncoding.EncodeToString([]byte(token))
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
	validator := oauthValidatorFunc(func(_ context.Context, got OAuthCredentials) (Principal, error) {
		if got != (OAuthCredentials{IDToken: token}) {
			t.Fatalf("credentials were not passed exactly: %#v", got)
		}
		return Principal{Subject: "owner", Tenant: "tenant"}, nil
	})
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, err := PrincipalFromContext(r.Context())
		if err != nil || principal != (Principal{Subject: "owner", Tenant: "tenant"}) {
			t.Fatalf("tunnel authorization = %#v, %v", principal, err)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	handler, err := NewOAuthBoundary(next, validator, []string{"https://workspace.example.edu", "http://127.0.0.1:8045"})
	testutil.Check(t, err)

	for _, origin := range []string{"https://workspace.example.edu", "http://127.0.0.1:8045"} {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions", nil)
		req.Header.Set("Origin", origin)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusNoContent || rr.Header().Get("Access-Control-Allow-Origin") != origin || rr.Header().Get("Access-Control-Allow-Credentials") != "" {
			t.Fatalf("origin %q: code=%d headers=%v", origin, rr.Code, rr.Header())
		}
	}

	native := httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)
	native.Header.Set("Authorization", "Bearer "+token)
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
		principal, err := PrincipalFromContext(r.Context())
		if err != nil || principal != testPrincipal {
			t.Fatalf("context authorization = %#v, %v", principal, err)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	handler, err := NewOAuthBoundary(next, oauthValidatorFunc(func(_ context.Context, got OAuthCredentials) (Principal, error) {
		validatorCalls++
		testutil.Equal(t, got.IDToken, token, "validated token")
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
		if request.Header.Get("Authorization") != "" || request.Header.Get("Sec-WebSocket-Protocol") != ControlWebSocketProtocol {
			t.Fatalf("secret WebSocket protocols were not stripped: %v", request.Header)
		}
		w.WriteHeader(http.StatusNoContent)
	}), oauthValidatorFunc(func(context.Context, OAuthCredentials) (Principal, error) {
		calls++
		return testPrincipal, nil
	}), []string{"https://workspace.example.edu"})
	testutil.Check(t, err)
	request := browserUpgradeRequest(token)
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || calls != 1 {
		t.Fatalf("protocol-authenticated WebSocket response = %d calls=%d %q", response.Code, calls, response.Body.String())
	}
}

func TestOAuthBoundaryConditionalPollHeaders(t *testing.T) {
	const origin = "https://workspace.example.edu"
	validator := oauthValidatorFunc(func(context.Context, OAuthCredentials) (Principal, error) { return testPrincipal, nil })
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("ETag", `"abc"`)
		w.WriteHeader(http.StatusNotModified)
	})
	handler, err := NewOAuthBoundary(next, validator, []string{origin})
	testutil.Check(t, err)

	preflight := httptest.NewRequest(http.MethodOptions, "/api/v1/sessions", nil)
	preflight.Header.Set("Origin", origin)
	preflight.Header.Set("Access-Control-Request-Method", http.MethodGet)
	preflight.Header.Set("Access-Control-Request-Headers", "authorization,if-none-match")
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
	actual.Header.Set("If-None-Match", `"abc"`)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, actual)
	if rr.Code != http.StatusNotModified || rr.Header().Get("Access-Control-Expose-Headers") != "ETag" {
		t.Fatalf("code=%d headers=%v", rr.Code, rr.Header())
	}
}

func TestOAuthBoundaryRejectsMalformedCredentials(t *testing.T) {
	validator := oauthValidatorFunc(func(context.Context, OAuthCredentials) (Principal, error) { return testPrincipal, nil })
	handler, err := NewOAuthBoundary(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), validator, []string{"https://workspace.example.edu"})
	testutil.Check(t, err)

	for name, request := range map[string]*http.Request{
		"no credential": httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil),
		"github scheme gone": func() *http.Request {
			r := httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)
			r.Header.Set("Authorization", "github some-token")
			return r
		}(),
		"two authorizations": func() *http.Request {
			r := httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)
			r.Header.Add("Authorization", "Bearer a")
			r.Header.Add("Authorization", "Bearer b")
			return r
		}(),
		"websocket github": func() *http.Request {
			r := browserUpgradeRequest("t")
			r.Header.Set("Sec-WebSocket-Protocol", ControlWebSocketProtocol+", github."+base64.RawURLEncoding.EncodeToString([]byte("t")))
			return r
		}(),
		"websocket identity": func() *http.Request {
			r := browserUpgradeRequest("t")
			r.Header.Set("Sec-WebSocket-Protocol", browserWebSocketProtocols("t")+", identity."+base64.RawURLEncoding.EncodeToString([]byte("t")))
			return r
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusUnauthorized && response.Code != http.StatusBadRequest {
				t.Fatalf("code = %d, want 400 or 401", response.Code)
			}
		})
	}
}

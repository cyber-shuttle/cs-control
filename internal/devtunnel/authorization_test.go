package devtunnel

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cyber-shuttle/cs-plane/internal/security"
	"github.com/cyber-shuttle/cs-plane/internal/testutil"
)

func localAuthorizer(server *httptest.Server, provider authorizationProvider) *Authorizer {
	provider.deviceEndpoint = server.URL + "/device"
	provider.tokenEndpoint = server.URL + "/token"
	if provider.name == "github" {
		provider.userEndpoint = server.URL + "/user"
	}
	return &Authorizer{providers: map[string]authorizationProvider{provider.name: provider}, client: security.GuardedClient(server.Client(), authorizationTimeout)}
}

func TestGitHubAuthorizationStartPendingAndSuccess(t *testing.T) {
	polls := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/device":
			_, _ = writer.Write([]byte(`{"device_code":"device-secret","user_code":"ABCD-EFGH","verification_uri":"https://github.com/login/device","expires_in":900,"interval":1,"extra":true}`))
		case "/token":
			polls++
			if polls == 1 {
				writer.WriteHeader(http.StatusBadRequest)
				_, _ = writer.Write([]byte(`{"error":"authorization_pending"}`))
				return
			}
			_, _ = writer.Write([]byte(`{"access_token":"access-secret","scope":"extra"}`))
		case "/user":
			if request.Header.Get("Authorization") != "Bearer access-secret" {
				t.Fatalf("authorization = %q", request.Header.Get("Authorization"))
			}
			_, _ = writer.Write([]byte(`{"login":"octocat"}`))
		}
	}))
	defer server.Close()
	provider := authorizationProvider{name: "github", scheme: "github", clientID: "client"}
	authorizer := localAuthorizer(server, provider)
	authorization, err := authorizer.Start(context.Background(), "github")
	if err != nil || authorization.UserCode != "ABCD-EFGH" || authorization.Interval != time.Second {
		t.Fatalf("Start = %#v, %v", authorization, err)
	}
	pending, err := authorizer.Poll(context.Background(), authorization, time.Second)
	if err != nil || !pending.Pending || len(authorization.deviceCode) == 0 {
		t.Fatalf("pending = %#v, %v", pending, err)
	}
	result, err := authorizer.Poll(context.Background(), authorization, time.Second)
	if err != nil || result.Tokens.Account != "octocat" || result.Tokens.AccessToken != "access-secret" || result.Tokens.ExpiresIn != 0 {
		t.Fatalf("success = %#v, %v", result, err)
	}
	if len(authorization.deviceCode) != 0 {
		t.Fatal("terminal authorization retained its device code")
	}
}

func TestAuthorizationRefusesCrossOriginRedirects(t *testing.T) {
	calls := 0
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls++ }))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", target.URL)
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	authorizer := localAuthorizer(source, authorizationProvider{name: "microsoft", scheme: "Bearer", clientID: "client"})
	if _, err := authorizer.Start(context.Background(), "microsoft"); !errors.Is(err, ErrAuthorizationUnavailable) {
		t.Fatalf("Start error = %v", err)
	}
	if calls != 0 {
		t.Fatal("authorization request followed a cross-origin redirect")
	}
}

func TestAuthorizationRejectsMalformedCredentials(t *testing.T) {
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"preferred_username":"researcher@example.edu"}`))
	for _, response := range []string{
		`{"access_token":"bad token","refresh_token":"refresh","expires_in":3600,"id_token":"x.` + payload + `.y"}`,
		`{"access_token":"access","refresh_token":"bad\nrefresh","expires_in":3600,"id_token":"x.` + payload + `.y"}`,
		`{"access_token":"access","refresh_token":"refresh","expires_in":0,"id_token":"x.` + payload + `.y"}`,
		`{"access_token":"access","refresh_token":"refresh","expires_in":86401,"id_token":"x.` + payload + `.y"}`,
		`{"access_token":"access","refresh_token":"refresh","expires_in":3600,"id_token":"x.e30.y"}`,
	} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(response)) }))
		authorizer := localAuthorizer(server, authorizationProvider{name: "microsoft", scheme: "Bearer", clientID: "client"})
		authorization := &DeviceAuthorization{provider: authorizer.providers["microsoft"], deviceCode: []byte("secret")}
		if _, err := authorizer.Poll(context.Background(), authorization, time.Second); !errors.Is(err, ErrAuthorizationInvalid) {
			t.Errorf("Poll accepted %s: %v", response, err)
		}
		server.Close()
	}
}

func TestAuthorizationTerminalErrorsClearDeviceCode(t *testing.T) {
	for providerError, want := range map[string]error{
		"access_denied": ErrAuthorizationDenied,
		"expired_token": ErrAuthorizationExpired,
		"invalid_grant": ErrAuthorizationRejected,
	} {
		t.Run(providerError, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				if request.URL.Path == "/device" {
					_, _ = writer.Write([]byte(`{"device_code":"secret","user_code":"CODE","verification_uri":"https://example.test/device","expires_in":60,"interval":1}`))
					return
				}
				writer.WriteHeader(http.StatusBadRequest)
				_, _ = fmt.Fprintf(writer, `{"error":%q}`, providerError)
			}))
			defer server.Close()
			authorizer := localAuthorizer(server, authorizationProvider{name: "microsoft", scheme: "Bearer", clientID: "client"})
			authorization, err := authorizer.Start(context.Background(), "microsoft")
			testutil.Check(t, err)
			if _, err := authorizer.Poll(context.Background(), authorization, time.Second); !errors.Is(err, want) {
				t.Fatalf("Poll error = %v, want %v", err, want)
			}
			if len(authorization.deviceCode) != 0 {
				t.Fatal("terminal error retained the device code")
			}
		})
	}
}

func TestAuthorizationCanBeClearedDuringPoll(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
		writer.WriteHeader(http.StatusBadRequest)
		_, _ = writer.Write([]byte(`{"error":"authorization_pending"}`))
	}))
	defer server.Close()
	authorizer := localAuthorizer(server, authorizationProvider{name: "microsoft", scheme: "Bearer", clientID: "client"})
	authorization := &DeviceAuthorization{provider: authorizer.providers["microsoft"], deviceCode: []byte("secret")}
	done := make(chan error, 1)
	go func() {
		_, err := authorizer.Poll(context.Background(), authorization, time.Second)
		done <- err
	}()
	<-started
	authorization.Clear()
	close(release)
	testutil.Check(t, <-done)
	if _, err := authorizer.Poll(context.Background(), authorization, time.Second); !errors.Is(err, ErrAuthorizationInvalid) {
		t.Fatalf("Poll after Clear error = %v", err)
	}
}

func TestMicrosoftAuthorizationNameAndRefreshRotation(t *testing.T) {
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"preferred_username":"researcher@example.edu"}`))
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls++
		if calls == 1 {
			_, _ = writer.Write([]byte(`{"device_code":"secret","user_code":"CODE","verification_uri":"https://example.test/device","expires_in":60,"interval":1}`))
			return
		}
		testutil.Check(t, request.ParseForm())
		switch request.Form.Get("grant_type") {
		case deviceGrantType:
			_, _ = fmt.Fprintf(writer, `{"access_token":"access","refresh_token":"refresh","expires_in":60,"id_token":"x.%s.y"}`, payload)
		case "refresh_token":
			if request.Form.Get("refresh_token") != "refresh" || !strings.Contains(request.Form.Get("scope"), "offline_access") {
				t.Fatalf("refresh form = %v", request.Form)
			}
			_, _ = writer.Write([]byte(`{"access_token":"new-access","expires_in":3600}`))
		}
	}))
	defer server.Close()
	provider := authorizationProvider{name: "microsoft", scheme: "Bearer", clientID: "client", scope: deviceScope}
	authorizer := localAuthorizer(server, provider)
	authorization, err := authorizer.Start(context.Background(), "microsoft")
	testutil.Check(t, err)
	result, err := authorizer.Poll(context.Background(), authorization, time.Second)
	if err != nil || result.Tokens.Account != "researcher@example.edu" {
		t.Fatalf("Poll = %#v, %v", result, err)
	}
	refreshed, err := authorizer.Refresh(context.Background(), "microsoft", result.Tokens.RefreshToken)
	if err != nil || refreshed.AccessToken != "new-access" || refreshed.RefreshToken != "refresh" {
		t.Fatalf("Refresh = %#v, %v", refreshed, err)
	}
}

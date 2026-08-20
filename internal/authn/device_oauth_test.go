package authn

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

const deviceTestOrigin = "https://workspace.example.edu"

type deviceRoundTripFunc func(*http.Request) (*http.Response, error)

func (fn deviceRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func deviceJSONResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}
}

func newTestDeviceBroker(t *testing.T, transport http.RoundTripper) (*DeviceCodeBroker, *time.Time) {
	t.Helper()
	broker, err := NewDeviceCodeBroker("https://login.microsoftonline.com/tenant/", []string{deviceTestOrigin}, &http.Client{Transport: transport})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(2_000_000_000, 0)
	broker.now = func() time.Time { return now }
	t.Cleanup(broker.Close)
	return broker, &now
}

func deviceRequest(method, path, origin string) *http.Request {
	request := httptest.NewRequest(method, path, nil)
	if origin != "" {
		request.Header.Set("Origin", origin)
	}
	return request
}

func startDeviceAuthorization(t *testing.T, broker *DeviceCodeBroker) deviceStartResponse {
	t.Helper()
	response := httptest.NewRecorder()
	broker.ServeHTTP(response, deviceRequest(http.MethodPost, "/api/v1/oauth/device/start", deviceTestOrigin))
	if response.Code != http.StatusOK {
		t.Fatalf("start status = %d body=%s", response.Code, response.Body.String())
	}
	var result deviceStartResponse
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestDeviceBrokerExactCORSAndPinnedAuthority(t *testing.T) {
	requests := 0
	broker, _ := newTestDeviceBroker(t, deviceRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		if request.URL.Scheme != "https" || request.URL.Host != "login.microsoftonline.com" || request.URL.Path != "/tenant/oauth2/v2.0/devicecode" {
			t.Fatalf("unpinned request URL = %s", request.URL)
		}
		body, _ := io.ReadAll(request.Body)
		form, _ := url.ParseQuery(string(body))
		if form.Get("client_id") != DevTunnelsNativeClientID || form.Get("scope") != devTunnelsDeviceScope {
			t.Fatalf("device form = %v", form)
		}
		return deviceJSONResponse(200, `{"device_code":"private-device-code","user_code":"ABCD-EFGH","verification_uri":"https://microsoft.com/devicelogin","expires_in":900,"interval":5}`), nil
	}))

	for name, request := range map[string]*http.Request{
		"missing origin": deviceRequest(http.MethodPost, "/api/v1/oauth/device/start", ""),
		"wrong origin":   deviceRequest(http.MethodPost, "/api/v1/oauth/device/start", "https://evil.example"),
		"nearby route":   deviceRequest(http.MethodPost, "/api/v1/oauth/device/start/", deviceTestOrigin),
	} {
		t.Run(name, func(t *testing.T) {
			response := httptest.NewRecorder()
			broker.ServeHTTP(response, request)
			if response.Code != http.StatusForbidden && response.Code != http.StatusNotFound {
				t.Fatalf("status = %d", response.Code)
			}
			if response.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("error was cacheable")
			}
		})
	}
	preflight := deviceRequest(http.MethodOptions, "/api/v1/oauth/device/start", deviceTestOrigin)
	preflight.Header.Set("Access-Control-Request-Method", http.MethodPost)
	preflight.Header.Set("Access-Control-Request-Headers", "content-type")
	preflightResponse := httptest.NewRecorder()
	broker.ServeHTTP(preflightResponse, preflight)
	if preflightResponse.Code != http.StatusNoContent || preflightResponse.Header().Get("Access-Control-Allow-Origin") != deviceTestOrigin || preflightResponse.Header().Get("Access-Control-Allow-Credentials") != "" {
		t.Fatalf("preflight = %d %v", preflightResponse.Code, preflightResponse.Header())
	}
	badPreflight := deviceRequest(http.MethodOptions, "/api/v1/oauth/device/start", deviceTestOrigin)
	badPreflight.Header.Set("Access-Control-Request-Method", http.MethodGet)
	badResponse := httptest.NewRecorder()
	broker.ServeHTTP(badResponse, badPreflight)
	if badResponse.Code != http.StatusForbidden {
		t.Fatalf("bad preflight = %d", badResponse.Code)
	}

	result := startDeviceAuthorization(t, broker)
	if !deviceHandlePattern.MatchString(result.Handle) || result.UserCode != "ABCD-EFGH" || requests != 1 {
		t.Fatalf("result = %#v requests=%d", result, requests)
	}
	for _, authority := range []string{
		"https://login.microsoftonline.com/common/",
		"https://login.microsoftonline.com/tenant/extra/",
		"https://login.microsoftonline.com:443/tenant/",
		"https://evil.example/tenant/",
		"http://login.microsoftonline.com/tenant/",
	} {
		if _, err := NewDeviceCodeBroker(authority, []string{deviceTestOrigin}, nil); err == nil {
			t.Fatalf("unsafe authority accepted: %s", authority)
		}
	}
}

func TestDeviceBrokerPendingSlowDownSuccessAndSecretHandling(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	var requestBodies []string
	transport := deviceRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		mu.Lock()
		defer mu.Unlock()
		body, _ := io.ReadAll(request.Body)
		requestBodies = append(requestBodies, string(body))
		calls++
		switch calls {
		case 1:
			return deviceJSONResponse(200, `{"device_code":"private-device-code","user_code":"ABCD-EFGH","verification_uri":"https://microsoft.com/devicelogin","expires_in":900,"interval":1}`), nil
		case 2:
			return deviceJSONResponse(400, `{"error":"authorization_pending"}`), nil
		case 3:
			return deviceJSONResponse(400, `{"error":"slow_down"}`), nil
		default:
			return deviceJSONResponse(200, `{"access_token":"access-secret","id_token":"identity-secret","refresh_token":"refresh-must-be-discarded","expires_in":60}`), nil
		}
	})
	broker, now := newTestDeviceBroker(t, transport)
	var logs bytes.Buffer
	oldWriter := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(oldWriter)
	start := startDeviceAuthorization(t, broker)

	poll := func() *httptest.ResponseRecorder {
		response := httptest.NewRecorder()
		broker.ServeHTTP(response, deviceRequest(http.MethodPost, "/api/v1/oauth/device/poll/"+start.Handle, deviceTestOrigin))
		return response
	}
	tooFast := poll()
	if tooFast.Code != http.StatusTooManyRequests || calls != 1 {
		t.Fatalf("early poll = %d calls=%d", tooFast.Code, calls)
	}
	*now = now.Add(time.Second)
	pending := poll()
	if pending.Code != http.StatusAccepted || !strings.Contains(pending.Body.String(), `"intervalSeconds":1`) {
		t.Fatalf("pending = %d %s", pending.Code, pending.Body.String())
	}
	*now = now.Add(time.Second)
	slow := poll()
	if slow.Code != http.StatusAccepted || !strings.Contains(slow.Body.String(), `"intervalSeconds":6`) {
		t.Fatalf("slow = %d %s", slow.Code, slow.Body.String())
	}
	*now = now.Add(6 * time.Second)
	complete := poll()
	if complete.Code != http.StatusOK || !strings.Contains(complete.Body.String(), `"accessToken":"access-secret"`) || strings.Contains(complete.Body.String(), "refresh") {
		t.Fatalf("complete = %d %s", complete.Code, complete.Body.String())
	}
	if len(broker.entries) != 0 {
		t.Fatal("successful authorization state was retained")
	}
	if strings.Contains(logs.String(), "secret") {
		t.Fatalf("secret logged: %s", logs.String())
	}
	if len(requestBodies) != 4 || !strings.Contains(requestBodies[1], "private-device-code") {
		t.Fatalf("outbound forms = %q", requestBodies)
	}
}

func TestDeviceBrokerExpiryGuessOriginBindingAndCleanup(t *testing.T) {
	transport := deviceRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return deviceJSONResponse(200, `{"device_code":"code-to-zero","user_code":"CODE","verification_uri":"https://microsoft.com/devicelogin","expires_in":2,"interval":1}`), nil
	})
	broker, now := newTestDeviceBroker(t, transport)
	start := startDeviceAuthorization(t, broker)
	entry := broker.entries[start.Handle]
	guess := httptest.NewRecorder()
	broker.ServeHTTP(guess, deviceRequest(http.MethodPost, "/api/v1/oauth/device/poll/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", deviceTestOrigin))
	if guess.Code != http.StatusNotFound {
		t.Fatalf("guess status = %d", guess.Code)
	}
	wrongOrigin := httptest.NewRecorder()
	wrong := deviceRequest(http.MethodPost, "/api/v1/oauth/device/poll/"+start.Handle, "https://evil.example")
	broker.ServeHTTP(wrongOrigin, wrong)
	if wrongOrigin.Code != http.StatusForbidden {
		t.Fatalf("wrong origin = %d", wrongOrigin.Code)
	}
	*now = now.Add(2 * time.Second)
	expired := httptest.NewRecorder()
	broker.ServeHTTP(expired, deviceRequest(http.MethodPost, "/api/v1/oauth/device/poll/"+start.Handle, deviceTestOrigin))
	if expired.Code != http.StatusGone || len(broker.entries) != 0 {
		t.Fatalf("expired = %d entries=%d", expired.Code, len(broker.entries))
	}
	for _, value := range entry.deviceCode {
		if value != 0 {
			t.Fatal("expired device code was not zeroed")
		}
	}

	*now = now.Add(deviceStartInterval)
	second := startDeviceAuthorization(t, broker)
	secondEntry := broker.entries[second.Handle]
	broker.Close()
	if len(broker.entries) != 0 {
		t.Fatal("close retained entries")
	}
	for _, value := range secondEntry.deviceCode {
		if value != 0 {
			t.Fatal("close did not zero device code")
		}
	}
}

func TestDeviceBrokerStartRateAndGlobalBound(t *testing.T) {
	broker, now := newTestDeviceBroker(t, deviceRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return deviceJSONResponse(200, `{"device_code":"private-device-code","user_code":"CODE","verification_uri":"https://microsoft.com/devicelogin","expires_in":900,"interval":5}`), nil
	}))
	startDeviceAuthorization(t, broker)
	rate := httptest.NewRecorder()
	broker.ServeHTTP(rate, deviceRequest(http.MethodPost, "/api/v1/oauth/device/start", deviceTestOrigin))
	if rate.Code != http.StatusTooManyRequests {
		t.Fatalf("start rate = %d", rate.Code)
	}
	*now = now.Add(deviceStartInterval)
	broker.mu.Lock()
	for len(broker.entries) < maxDeviceBrokerEntries {
		handle := fmt.Sprintf("%043d", len(broker.entries))
		broker.entries[handle] = &deviceBrokerEntry{deviceCode: []byte("code"), origin: deviceTestOrigin, expiresAt: now.Add(time.Hour)}
	}
	broker.mu.Unlock()
	capacity := httptest.NewRecorder()
	broker.ServeHTTP(capacity, deviceRequest(http.MethodPost, "/api/v1/oauth/device/start", deviceTestOrigin))
	if capacity.Code != http.StatusServiceUnavailable {
		t.Fatalf("capacity status = %d", capacity.Code)
	}
}

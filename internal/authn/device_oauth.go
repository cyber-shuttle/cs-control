package authn

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cyber-shuttle/cs-control/internal/apierr"
	"github.com/cyber-shuttle/cs-control/internal/httpx"
)

const (
	DevTunnelsNativeClientID = "c0df98ca-23b4-4bce-bb9f-72039b28d3a5"
	devTunnelsDeviceScope    = "openid profile offline_access 46da2f7e-b5ef-422a-88d4-2a7f9de6a0b2/.default"
	deviceGrantType          = "urn:ietf:params:oauth:grant-type:device_code"
	maxDeviceBrokerEntries   = 256
	maxDeviceResponse        = 64 << 10
	deviceRequestTimeout     = 15 * time.Second
	deviceStartInterval      = time.Second
	maxDevicePollInterval    = 60 * time.Second
)

var deviceHandlePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

type deviceBrokerEntry struct {
	deviceCode []byte
	origin     string
	expiresAt  time.Time
	interval   time.Duration
	nextPoll   time.Time
	inFlight   bool
}

type DeviceCodeBroker struct {
	mu              sync.Mutex
	entries         map[string]*deviceBrokerEntry
	nextOriginStart map[string]time.Time
	deviceEndpoint  string
	tokenEndpoint   string
	origins         map[string]struct{}
	client          *http.Client
	now             func() time.Time
	ctx             context.Context
	cancel          context.CancelFunc
}

type deviceStartResponse struct {
	Handle           string `json:"handle"`
	UserCode         string `json:"userCode"`
	VerificationURI  string `json:"verificationUri"`
	ExpiresInSeconds int64  `json:"expiresInSeconds"`
	IntervalSeconds  int64  `json:"intervalSeconds"`
}

type devicePollResponse struct {
	Status           string `json:"status"`
	IntervalSeconds  int64  `json:"intervalSeconds,omitempty"`
	AccessToken      string `json:"accessToken,omitempty"`
	IDToken          string `json:"idToken,omitempty"`
	ExpiresInSeconds int64  `json:"expiresInSeconds,omitempty"`
}

// Microsoft endpoints are derived only from a pinned, tenant-specific authority.
func NewDeviceCodeBroker(authority string, allowedOrigins []string, client *http.Client) (*DeviceCodeBroker, error) {
	base, tenant, err := parseTenantAuthority(authority)
	if err != nil {
		return nil, err
	}
	base.Path = "/" + tenant + "/"
	origins, err := validatedOriginSet(allowedOrigins)
	if err != nil {
		return nil, err
	}
	bounded := httpx.BoundedClient(client, deviceRequestTimeout)
	bounded.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	ctx, cancel := context.WithCancel(context.Background())
	broker := &DeviceCodeBroker{
		entries:         make(map[string]*deviceBrokerEntry),
		nextOriginStart: make(map[string]time.Time),
		deviceEndpoint:  base.ResolveReference(&url.URL{Path: "oauth2/v2.0/devicecode"}).String(),
		tokenEndpoint:   base.ResolveReference(&url.URL{Path: "oauth2/v2.0/token"}).String(),
		origins:         origins,
		client:          bounded,
		now:             time.Now,
		ctx:             ctx,
		cancel:          cancel,
	}
	go broker.cleanupLoop()
	return broker, nil
}

// Only the two broker routes sit before the OAuth boundary; every other request
// is delegated unchanged.
func NewDeviceCodeRoutes(next http.Handler, broker *DeviceCodeBroker) (http.Handler, error) {
	if next == nil || broker == nil {
		return nil, errors.New("device-code route dependencies are required")
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.EscapedPath()
		if path == "/api/v1/oauth/device/start" || strings.HasPrefix(path, "/api/v1/oauth/device/poll/") {
			broker.ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(w, r)
	}), nil
}

func writeDeviceError(w http.ResponseWriter, status int, code, message string) {
	httpx.WriteError(w, apierr.New(code, message, status))
}

// ponytail: a body on a bodyless route is ignored, not refused; revisit only if
// a body ever gains meaning here.
func (b *DeviceCodeBroker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if origin == "" {
		writeDeviceError(w, http.StatusForbidden, "origin_required", "browser origin is required")
		return
	}
	if !allowOrigin(w, origin, b.origins) {
		writeDeviceError(w, http.StatusForbidden, "origin_not_allowed", "origin is not allowed")
		return
	}
	if r.Method == http.MethodOptions {
		if r.Header.Get("Access-Control-Request-Method") != http.MethodPost || !preflightHeadersAllowed(r.Header.Get("Access-Control-Request-Headers"), "content-type") {
			writeDeviceError(w, http.StatusForbidden, "preflight_not_allowed", "preflight is not allowed")
			return
		}
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost {
		writeDeviceError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	if r.URL.RawQuery != "" || r.URL.EscapedPath() != r.URL.Path {
		writeDeviceError(w, http.StatusNotFound, "not_found", "route not found")
		return
	}
	switch {
	case r.URL.Path == "/api/v1/oauth/device/start":
		b.handleStart(w, r, origin)
	case strings.HasPrefix(r.URL.Path, "/api/v1/oauth/device/poll/"):
		handle := strings.TrimPrefix(r.URL.Path, "/api/v1/oauth/device/poll/")
		if !deviceHandlePattern.MatchString(handle) {
			writeDeviceError(w, http.StatusNotFound, "not_found", "authorization was not found")
			return
		}
		b.handlePoll(w, r, origin, handle)
	default:
		writeDeviceError(w, http.StatusNotFound, "not_found", "route not found")
	}
}

func (b *DeviceCodeBroker) handleStart(w http.ResponseWriter, r *http.Request, origin string) {
	now := b.now()
	b.mu.Lock()
	b.cleanupLocked(now)
	if now.Before(b.nextOriginStart[origin]) {
		b.mu.Unlock()
		writeDeviceError(w, http.StatusTooManyRequests, "rate_limited", "request rate exceeded")
		return
	}
	if len(b.entries) >= maxDeviceBrokerEntries {
		b.mu.Unlock()
		writeDeviceError(w, http.StatusServiceUnavailable, "broker_capacity", "authorization service is busy")
		return
	}
	b.nextOriginStart[origin] = now.Add(deviceStartInterval)
	b.mu.Unlock()

	form := url.Values{"client_id": {DevTunnelsNativeClientID}, "scope": {devTunnelsDeviceScope}}
	value, status, err := b.postForm(r.Context(), b.deviceEndpoint, form, deviceRequestTimeout)
	if err != nil || status < 200 || status >= 300 {
		writeDeviceError(w, http.StatusBadGateway, "upstream_unavailable", "authorization service is unavailable")
		return
	}
	var result struct {
		DeviceCode      string `json:"device_code"`
		UserCode        string `json:"user_code"`
		VerificationURI string `json:"verification_uri"`
		ExpiresIn       int64  `json:"expires_in"`
		Interval        int64  `json:"interval"`
	}
	if json.Unmarshal(value, &result) != nil || !validDeviceAuthorization(result.DeviceCode, result.UserCode, result.VerificationURI, result.ExpiresIn, result.Interval) {
		writeDeviceError(w, http.StatusBadGateway, "upstream_invalid", "authorization service returned an invalid response")
		return
	}
	if result.Interval == 0 {
		result.Interval = 5
	}
	handle, err := newDeviceHandle()
	if err != nil {
		writeDeviceError(w, http.StatusInternalServerError, "broker_unavailable", "authorization service is unavailable")
		return
	}
	now = b.now()
	entry := &deviceBrokerEntry{deviceCode: []byte(result.DeviceCode), origin: origin, expiresAt: now.Add(time.Duration(result.ExpiresIn) * time.Second), interval: time.Duration(result.Interval) * time.Second, nextPoll: now.Add(time.Duration(result.Interval) * time.Second)}
	b.mu.Lock()
	if len(b.entries) >= maxDeviceBrokerEntries {
		b.mu.Unlock()
		clear(entry.deviceCode)
		writeDeviceError(w, http.StatusServiceUnavailable, "broker_capacity", "authorization service is busy")
		return
	}
	b.entries[handle] = entry
	b.mu.Unlock()
	httpx.WriteJSON(w, http.StatusOK, deviceStartResponse{Handle: handle, UserCode: result.UserCode, VerificationURI: result.VerificationURI, ExpiresInSeconds: result.ExpiresIn, IntervalSeconds: result.Interval})
}

func validDeviceAuthorization(deviceCode, userCode, verificationURI string, expiresIn, interval int64) bool {
	if deviceCode == "" || len(deviceCode) > 4096 || userCode == "" || len(userCode) > 128 || expiresIn <= 0 || expiresIn > 3600 || interval < 0 || interval > 60 {
		return false
	}
	uri, err := url.Parse(verificationURI)
	return err == nil && uri.Scheme == "https" && uri.Host != "" && uri.User == nil && uri.Fragment == "" && len(verificationURI) <= 2048
}

func (b *DeviceCodeBroker) handlePoll(w http.ResponseWriter, r *http.Request, origin, handle string) {
	now := b.now()
	b.mu.Lock()
	entry, ok := b.entries[handle]
	if !ok || entry.origin != origin {
		b.mu.Unlock()
		writeDeviceError(w, http.StatusNotFound, "not_found", "authorization was not found")
		return
	}
	if !now.Before(entry.expiresAt) {
		b.deleteLocked(handle)
		b.mu.Unlock()
		writeDeviceError(w, http.StatusGone, "authorization_expired", "authorization expired")
		return
	}
	if entry.inFlight || now.Before(entry.nextPoll) {
		retry := entry.nextPoll.Sub(now)
		if retry < time.Second {
			retry = time.Second
		}
		w.Header().Set("Retry-After", strconv.FormatInt(int64((retry+time.Second-1)/time.Second), 10))
		b.mu.Unlock()
		writeDeviceError(w, http.StatusTooManyRequests, "rate_limited", "polling too quickly")
		return
	}
	entry.inFlight = true
	entry.nextPoll = now.Add(entry.interval)
	deviceCode := string(entry.deviceCode)
	remaining := entry.expiresAt.Sub(now)
	b.mu.Unlock()

	value, status, err := b.postForm(r.Context(), b.tokenEndpoint, url.Values{"grant_type": {deviceGrantType}, "client_id": {DevTunnelsNativeClientID}, "device_code": {deviceCode}}, remaining)
	if err != nil {
		b.settle(w, handle, pollOutcome{status: http.StatusBadGateway, code: "upstream_unavailable", message: "authorization service is unavailable"})
		return
	}
	var oauthError struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(value, &oauthError)
	if status < 200 || status >= 300 || oauthError.Error != "" {
		outcome, known := devicePollOutcomes[oauthError.Error]
		if !known {
			outcome = pollOutcome{remove: true, status: http.StatusBadGateway, code: "upstream_failure", message: "authorization service rejected the request"}
		}
		b.settle(w, handle, outcome)
		return
	}
	var tokens struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if json.Unmarshal(value, &tokens) != nil || !validOAuthToken(tokens.AccessToken) || !validOAuthToken(tokens.IDToken) || tokens.ExpiresIn <= 0 || tokens.ExpiresIn > 86400 {
		b.settle(w, handle, pollOutcome{remove: true, status: http.StatusBadGateway, code: "upstream_invalid", message: "authorization service returned an invalid response"})
		return
	}
	b.deliverTokens(w, handle, tokens.AccessToken, tokens.IDToken, tokens.ExpiresIn)
}

// pollOutcome is how one upstream token response ends: whether the entry is
// discarded, how far its interval backs off, and what the browser is told. An
// empty code means the authorization is still pending.
type pollOutcome struct {
	remove   bool
	slowDown time.Duration
	status   int
	code     string
	message  string
}

// devicePollOutcomes maps the OAuth device-flow errors the broker understands.
// Anything else is an upstream failure.
var devicePollOutcomes = map[string]pollOutcome{
	"authorization_pending": {},
	"slow_down":             {slowDown: 5 * time.Second},
	"access_denied":         {remove: true, status: http.StatusForbidden, code: "authorization_denied", message: "authorization was denied"},
	"expired_token":         {remove: true, status: http.StatusGone, code: "authorization_expired", message: "authorization expired"},
}

// settle applies one outcome to the entry and writes the single response it
// implies, so every poll result reaches the browser through one path.
func (b *DeviceCodeBroker) settle(w http.ResponseWriter, handle string, outcome pollOutcome) {
	interval := b.finishPoll(handle, outcome.remove, outcome.slowDown)
	if outcome.code == "" {
		httpx.WriteJSON(w, http.StatusAccepted, devicePollResponse{Status: "pending", IntervalSeconds: int64(interval / time.Second)})
		return
	}
	writeDeviceError(w, outcome.status, outcome.code, outcome.message)
}

func (b *DeviceCodeBroker) postForm(parent context.Context, endpoint string, form url.Values, maximum time.Duration) ([]byte, int, error) {
	if maximum <= 0 {
		return nil, 0, context.DeadlineExceeded
	}
	if maximum > deviceRequestTimeout {
		maximum = deviceRequestTimeout
	}
	ctx, cancel := context.WithTimeout(parent, maximum)
	defer cancel()
	request, err := httpx.NewRequest(ctx, http.MethodPost, endpoint, "", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, 0, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return httpx.Do(b.client, request, maxDeviceResponse)
}

func newDeviceHandle() (string, error) {
	bytes := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

// ponytail: a failed loopback response write loses the tokens and the user signs
// in again; revisit (store-and-redeliver) if that is ever observed.
func (b *DeviceCodeBroker) deliverTokens(w http.ResponseWriter, handle, accessToken, idToken string, expiresIn int64) {
	httpx.WriteJSON(w, http.StatusOK, devicePollResponse{Status: "complete", AccessToken: accessToken, IDToken: idToken, ExpiresInSeconds: expiresIn})
	b.finishPoll(handle, true, 0)
}

func (b *DeviceCodeBroker) finishPoll(handle string, remove bool, slowDown time.Duration) time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()
	entry := b.entries[handle]
	if entry == nil {
		return 0
	}
	if remove {
		b.deleteLocked(handle)
		return 0
	}
	entry.inFlight = false
	entry.interval = min(entry.interval+slowDown, maxDevicePollInterval)
	entry.nextPoll = b.now().Add(entry.interval)
	return entry.interval
}

func (b *DeviceCodeBroker) deleteLocked(handle string) {
	if entry := b.entries[handle]; entry != nil {
		clear(entry.deviceCode)
		delete(b.entries, handle)
	}
}

func (b *DeviceCodeBroker) cleanupLocked(now time.Time) {
	for handle, entry := range b.entries {
		if !now.Before(entry.expiresAt) {
			b.deleteLocked(handle)
		}
	}
	for origin, next := range b.nextOriginStart {
		if !now.Before(next) {
			delete(b.nextOriginStart, origin)
		}
	}
}

func (b *DeviceCodeBroker) cleanupLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			b.mu.Lock()
			b.cleanupLocked(b.now())
			b.mu.Unlock()
		case <-b.ctx.Done():
			return
		}
	}
}

func (b *DeviceCodeBroker) Close() {
	b.cancel()
	b.mu.Lock()
	defer b.mu.Unlock()
	for handle := range b.entries {
		b.deleteLocked(handle)
	}
	clear(b.nextOriginStart)
}

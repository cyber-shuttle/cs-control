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
	DevTunnelsNativeClientID   = "c0df98ca-23b4-4bce-bb9f-72039b28d3a5"
	devTunnelsDeviceScope      = "openid profile offline_access 46da2f7e-b5ef-422a-88d4-2a7f9de6a0b2/.default"
	deviceGrantType            = "urn:ietf:params:oauth:grant-type:device_code"
	maxDeviceBrokerEntries     = 256
	maxDeviceResponse          = 64 << 10
	deviceRequestTimeout       = 15 * time.Second
	deviceResponseWriteTimeout = 5 * time.Second
	deviceStartInterval        = time.Second
	maxDevicePollInterval      = 60 * time.Second
)

var deviceHandlePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

type deviceBrokerEntry struct {
	deviceCode     []byte
	accessToken    []byte
	idToken        []byte
	origin         string
	expiresAt      time.Time
	tokenExpiresAt time.Time
	interval       time.Duration
	nextPoll       time.Time
	inFlight       bool
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
	random          io.Reader
	writeTimeout    time.Duration
	ctx             context.Context
	cancel          context.CancelFunc
	closed          bool
	active          sync.WaitGroup
	closeOnce       sync.Once
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
	base, err := parseDeviceAuthority(authority)
	if err != nil {
		return nil, err
	}
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
		random:          rand.Reader,
		writeTimeout:    deviceResponseWriteTimeout,
		ctx:             ctx,
		cancel:          cancel,
	}
	broker.active.Add(1)
	go broker.cleanupLoop()
	return broker, nil
}

func parseDeviceAuthority(raw string) (*url.URL, error) {
	parsed, tenant, err := parseTenantAuthority(raw)
	if err != nil {
		return nil, err
	}
	parsed.Path = "/" + tenant + "/"
	return parsed, nil
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

// enterLocked takes the broker lock and keeps it, or answers the request and
// reports false. It is how every entry point refuses work started after Close.
func (b *DeviceCodeBroker) enterLocked(w http.ResponseWriter) bool {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		b.writeClosed(w)
		return false
	}
	return true
}

func (b *DeviceCodeBroker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !b.enterLocked(w) {
		return
	}
	b.active.Add(1)
	b.mu.Unlock()
	defer b.active.Done()

	origin := r.Header.Get("Origin")
	if origin == "" {
		b.writeError(w, http.StatusForbidden, "origin_required", "browser origin is required")
		return
	}
	if !allowOrigin(w, origin, b.origins) {
		b.writeError(w, http.StatusForbidden, "origin_not_allowed", "origin is not allowed")
		return
	}
	if r.Method == http.MethodOptions {
		if r.Header.Get("Access-Control-Request-Method") != http.MethodPost || !preflightHeadersAllowed(r.Header.Get("Access-Control-Request-Headers"), "content-type") {
			b.writeError(w, http.StatusForbidden, "preflight_not_allowed", "preflight is not allowed")
			return
		}
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		_ = b.writeDeviceJSON(w, http.StatusNoContent, nil)
		return
	}
	if r.Method != http.MethodPost {
		b.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	if r.ContentLength != 0 {
		b.writeError(w, http.StatusBadRequest, "invalid_request", "request body must be empty")
		return
	}
	if r.URL.RawQuery != "" || r.URL.EscapedPath() != r.URL.Path {
		b.writeError(w, http.StatusNotFound, "not_found", "route not found")
		return
	}
	switch {
	case r.URL.Path == "/api/v1/oauth/device/start":
		b.handleStart(w, r, origin)
	case strings.HasPrefix(r.URL.Path, "/api/v1/oauth/device/poll/"):
		handle := strings.TrimPrefix(r.URL.Path, "/api/v1/oauth/device/poll/")
		if !deviceHandlePattern.MatchString(handle) {
			b.writeError(w, http.StatusNotFound, "not_found", "authorization was not found")
			return
		}
		b.handlePoll(w, r, origin, handle)
	default:
		b.writeError(w, http.StatusNotFound, "not_found", "route not found")
	}
}

func (b *DeviceCodeBroker) handleStart(w http.ResponseWriter, r *http.Request, origin string) {
	now := b.now()
	if !b.enterLocked(w) {
		return
	}
	b.cleanupLocked(now)
	if now.Before(b.nextOriginStart[origin]) {
		b.mu.Unlock()
		b.writeError(w, http.StatusTooManyRequests, "rate_limited", "request rate exceeded")
		return
	}
	if len(b.entries) >= maxDeviceBrokerEntries {
		b.mu.Unlock()
		b.writeError(w, http.StatusServiceUnavailable, "broker_capacity", "authorization service is busy")
		return
	}
	b.nextOriginStart[origin] = now.Add(deviceStartInterval)
	b.mu.Unlock()

	form := url.Values{"client_id": {DevTunnelsNativeClientID}, "scope": {devTunnelsDeviceScope}}
	value, status, err := b.postForm(r.Context(), b.deviceEndpoint, form, deviceRequestTimeout)
	if err != nil || status < 200 || status >= 300 {
		if b.isClosed() {
			b.writeClosed(w)
		} else {
			b.writeError(w, http.StatusBadGateway, "upstream_unavailable", "authorization service is unavailable")
		}
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
		b.writeError(w, http.StatusBadGateway, "upstream_invalid", "authorization service returned an invalid response")
		return
	}
	if result.Interval == 0 {
		result.Interval = 5
	}
	handle, err := b.newHandle()
	if err != nil {
		b.writeError(w, http.StatusInternalServerError, "broker_unavailable", "authorization service is unavailable")
		return
	}
	now = b.now()
	entry := &deviceBrokerEntry{deviceCode: []byte(result.DeviceCode), origin: origin, expiresAt: now.Add(time.Duration(result.ExpiresIn) * time.Second), interval: time.Duration(result.Interval) * time.Second, nextPoll: now.Add(time.Duration(result.Interval) * time.Second)}
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		clear(entry.deviceCode)
		b.writeClosed(w)
		return
	}
	if len(b.entries) >= maxDeviceBrokerEntries {
		b.mu.Unlock()
		clear(entry.deviceCode)
		b.writeError(w, http.StatusServiceUnavailable, "broker_capacity", "authorization service is busy")
		return
	}
	b.entries[handle] = entry
	b.mu.Unlock()
	if err := b.writeDeviceJSON(w, http.StatusOK, deviceStartResponse{Handle: handle, UserCode: result.UserCode, VerificationURI: result.VerificationURI, ExpiresInSeconds: result.ExpiresIn, IntervalSeconds: result.Interval}); err != nil {
		b.mu.Lock()
		b.deleteLocked(handle)
		b.mu.Unlock()
	}
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
	if !b.enterLocked(w) {
		return
	}
	entry, ok := b.entries[handle]
	if !ok || entry.origin != origin {
		b.mu.Unlock()
		b.writeError(w, http.StatusNotFound, "not_found", "authorization was not found")
		return
	}
	if !now.Before(entry.expiresAt) || len(entry.accessToken) != 0 && !now.Before(entry.tokenExpiresAt) {
		b.deleteLocked(handle)
		b.mu.Unlock()
		b.writeError(w, http.StatusGone, "authorization_expired", "authorization expired")
		return
	}
	if entry.inFlight || now.Before(entry.nextPoll) {
		retry := entry.nextPoll.Sub(now)
		if retry < time.Second {
			retry = time.Second
		}
		w.Header().Set("Retry-After", strconv.FormatInt(int64((retry+time.Second-1)/time.Second), 10))
		b.mu.Unlock()
		b.writeError(w, http.StatusTooManyRequests, "rate_limited", "polling too quickly")
		return
	}
	entry.inFlight = true
	entry.nextPoll = now.Add(entry.interval)
	deviceCode := string(entry.deviceCode)
	expiresAt := entry.expiresAt
	accessToken := string(entry.accessToken)
	idToken := string(entry.idToken)
	tokenExpiresIn := int64((entry.tokenExpiresAt.Sub(now) + time.Second - 1) / time.Second)
	b.mu.Unlock()

	if accessToken != "" && idToken != "" {
		deviceCode = ""
		b.deliverTokens(w, handle, accessToken, idToken, tokenExpiresIn)
		return
	}

	remaining := expiresAt.Sub(now)
	value, status, err := b.postForm(r.Context(), b.tokenEndpoint, url.Values{"grant_type": {deviceGrantType}, "client_id": {DevTunnelsNativeClientID}, "device_code": {deviceCode}}, remaining)
	deviceCode = ""
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
	if !b.storeTokens(handle, tokens.AccessToken, tokens.IDToken, tokens.ExpiresIn) {
		tokens.AccessToken = ""
		tokens.IDToken = ""
		b.writeClosed(w)
		return
	}
	b.deliverTokens(w, handle, tokens.AccessToken, tokens.IDToken, tokens.ExpiresIn)
	tokens.AccessToken = ""
	tokens.IDToken = ""
}

// pollOutcome is how one upstream token response ends: whether the broker entry
// is discarded, how far its interval backs off, and what the browser is told. An
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
// implies, so every poll result reaches the browser through one path and a
// broker that closed mid-poll is reported the same way everywhere.
func (b *DeviceCodeBroker) settle(w http.ResponseWriter, handle string, outcome pollOutcome) {
	interval, open := b.finishPoll(handle, outcome.remove, outcome.slowDown)
	switch {
	case !open:
		b.writeClosed(w)
	case outcome.code == "":
		_ = b.writeDeviceJSON(w, http.StatusAccepted, devicePollResponse{Status: "pending", IntervalSeconds: int64(interval / time.Second)})
	default:
		b.writeError(w, outcome.status, outcome.code, outcome.message)
	}
}

func (b *DeviceCodeBroker) postForm(parent context.Context, endpoint string, form url.Values, maximum time.Duration) ([]byte, int, error) {
	if maximum <= 0 {
		return nil, 0, context.DeadlineExceeded
	}
	if maximum > deviceRequestTimeout {
		maximum = deviceRequestTimeout
	}
	ctx, cancel := context.WithTimeout(parent, maximum)
	stopBrokerCancel := context.AfterFunc(b.ctx, cancel)
	defer func() {
		stopBrokerCancel()
		cancel()
	}()
	request, err := httpx.NewRequest(ctx, http.MethodPost, endpoint, "", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, 0, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return httpx.Do(b.client, request, maxDeviceResponse)
}

func (b *DeviceCodeBroker) newHandle() (string, error) {
	for range 4 {
		bytes := make([]byte, 32)
		if _, err := io.ReadFull(b.random, bytes); err != nil {
			clear(bytes)
			return "", err
		}
		handle := base64.RawURLEncoding.EncodeToString(bytes)
		clear(bytes)
		b.mu.Lock()
		_, exists := b.entries[handle]
		b.mu.Unlock()
		if !exists {
			return handle, nil
		}
	}
	return "", errors.New("generate unique device authorization handle")
}

func (b *DeviceCodeBroker) storeTokens(handle, accessToken, idToken string, expiresIn int64) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	entry := b.entries[handle]
	if b.closed || entry == nil {
		return false
	}
	entry.accessToken = []byte(accessToken)
	entry.idToken = []byte(idToken)
	entry.tokenExpiresAt = b.now().Add(time.Duration(expiresIn) * time.Second)
	return true
}

func (b *DeviceCodeBroker) deliverTokens(w http.ResponseWriter, handle, accessToken, idToken string, expiresIn int64) {
	err := b.writeDeviceJSON(w, http.StatusOK, devicePollResponse{Status: "complete", AccessToken: accessToken, IDToken: idToken, ExpiresInSeconds: expiresIn})
	accessToken = ""
	idToken = ""
	b.finishPoll(handle, err == nil, 0)
}

func (b *DeviceCodeBroker) finishPoll(handle string, remove bool, slowDown time.Duration) (time.Duration, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		if remove {
			b.deleteLocked(handle)
		}
		return 0, false
	}
	entry := b.entries[handle]
	if entry == nil {
		return 0, true
	}
	if remove {
		b.deleteLocked(handle)
		return 0, true
	}
	entry.inFlight = false
	entry.interval = min(entry.interval+slowDown, maxDevicePollInterval)
	entry.nextPoll = b.now().Add(entry.interval)
	return entry.interval, true
}

func (b *DeviceCodeBroker) deleteLocked(handle string) {
	if entry := b.entries[handle]; entry != nil {
		clear(entry.deviceCode)
		clear(entry.accessToken)
		clear(entry.idToken)
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
	defer b.active.Done()
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
	b.closeOnce.Do(func() {
		b.mu.Lock()
		b.closed = true
		b.cancel()
		b.mu.Unlock()

		b.active.Wait()

		b.mu.Lock()
		for handle := range b.entries {
			b.deleteLocked(handle)
		}
		clear(b.nextOriginStart)
		b.mu.Unlock()
	})
}

func (b *DeviceCodeBroker) isClosed() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.closed
}

func (b *DeviceCodeBroker) writeDeviceJSON(w http.ResponseWriter, status int, value any) error {
	controller := http.NewResponseController(w)
	if err := controller.SetWriteDeadline(time.Now().Add(b.writeTimeout)); err != nil && !errors.Is(err, http.ErrNotSupported) {
		return err
	}
	w.Header().Set("Cache-Control", "no-store")
	if value != nil {
		w.Header().Set("Content-Type", "application/json")
	}
	w.WriteHeader(status)
	if value != nil {
		if err := json.NewEncoder(w).Encode(value); err != nil {
			return err
		}
	}
	if err := controller.Flush(); err != nil {
		return err
	}
	_ = controller.SetWriteDeadline(time.Time{})
	return nil
}

func (b *DeviceCodeBroker) writeError(w http.ResponseWriter, status int, code, message string) {
	_ = b.writeDeviceJSON(w, status, apierr.Envelope{Error: apierr.For(apierr.New(code, message, status))})
}

func (b *DeviceCodeBroker) writeClosed(w http.ResponseWriter) {
	b.writeError(w, http.StatusServiceUnavailable, "broker_closed", "authorization service is unavailable")
}

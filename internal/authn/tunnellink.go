// The Dev Tunnels link: a Microsoft or GitHub device-code authorization, brokered per principal and sealed to
// disk once, so sessions run over the caller's own Dev Tunnels account without this daemon ever returning the
// token that grants it. The broker keeps the device code only in bounded process memory; Poll answers what
// GET /api/v1/tunnel/link would once linked, never the tokens. A Microsoft link is refreshed on use within two
// minutes of expiry; a GitHub token does not expire. The sealing key lives beside the state at mode 0600.
//
//	devTunnelsNativeClientID, devTunnelsGitHubClientID, tunnelLinkDeviceScope, tunnelLinkGrantType
//	githubDeviceEndpoint, githubTokenEndpoint, githubUserAPI, microsoftDeviceEndpoint, microsoftTokenEndpoint
//	tunnelLinkRefreshWindow, maxLinkBrokerEntries, linkStartInterval, maxLinkPollInterval
//	tunnelLinkFileName, TunnelLinkKeyFileName
//	linkHandlePattern
//	tunnelLinkProvider, tunnelLink, TunnelLinkStatus, TunnelLinkStart, TunnelLinkPoll, TunnelCredential, linkBrokerEntry
//	LinkBroker
//	validDeviceAuthorization, newLinkHandle, sealSecret, openSealed, decodeUnverifiedPreferredUsername
//	LoadOrCreateTunnelLinkKey, NewLinkBroker
package authn

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/cyber-shuttle/cs-control/internal/apierr"
	"github.com/cyber-shuttle/cs-control/internal/httpx"
	"github.com/cyber-shuttle/cs-control/internal/safeio"
	"golang.org/x/crypto/nacl/secretbox"
)

const (
	devTunnelsNativeClientID = "c0df98ca-23b4-4bce-bb9f-72039b28d3a5"
	devTunnelsGitHubClientID = "Iv1.e7b89e013f801f03"
	tunnelLinkDeviceScope    = "openid profile offline_access 46da2f7e-b5ef-422a-88d4-2a7f9de6a0b2/.default"
	tunnelLinkGrantType      = "urn:ietf:params:oauth:grant-type:device_code"
	githubDeviceEndpoint     = "https://github.com/login/device/code"
	githubTokenEndpoint      = "https://github.com/login/oauth/access_token"
	githubUserAPI            = "https://api.github.com/user"
	microsoftDeviceEndpoint  = "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode"
	microsoftTokenEndpoint   = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
	tunnelLinkRefreshWindow  = 2 * time.Minute
	maxLinkBrokerEntries     = 256
	linkStartInterval        = time.Second
	maxLinkPollInterval      = 60 * time.Second
	tunnelLinkFileName       = "tunnel-link"

	TunnelLinkKeyFileName = "tunnel-link.key"
)

var linkHandlePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

type tunnelLinkProvider struct {
	name, scheme, deviceEndpoint, tokenEndpoint, userEndpoint, clientID, scope string
}

type tunnelLink struct {
	Provider     string    `json:"provider"`
	Scheme       string    `json:"scheme"`
	AccessToken  string    `json:"accessToken"`
	RefreshToken string    `json:"refreshToken,omitempty"`
	ExpiresAt    time.Time `json:"expiresAt,omitzero"`
	Account      string    `json:"account"`
	LinkedAt     time.Time `json:"linkedAt"`
}

type TunnelLinkStatus struct {
	Linked   bool      `json:"linked"`
	Provider string    `json:"provider,omitempty"`
	Account  string    `json:"account,omitempty"`
	LinkedAt time.Time `json:"linkedAt,omitzero"`
}

type TunnelLinkStart struct {
	Handle           string `json:"handle"`
	UserCode         string `json:"userCode"`
	VerificationURI  string `json:"verificationUri"`
	ExpiresInSeconds int64  `json:"expiresInSeconds"`
	IntervalSeconds  int64  `json:"intervalSeconds"`
}

type TunnelLinkPoll struct {
	Pending         bool
	IntervalSeconds int64
	Status          TunnelLinkStatus
}

type TunnelCredential struct {
	Scheme, Token string
}

type linkBrokerEntry struct {
	provider   tunnelLinkProvider
	principal  Principal
	deviceCode []byte
	expiresAt  time.Time
	interval   time.Duration
	nextPoll   time.Time
	inFlight   bool
}

type LinkBroker struct {
	mu                 sync.Mutex
	entries            map[string]*linkBrokerEntry
	nextPrincipalStart map[Principal]time.Time
	providers          map[string]tunnelLinkProvider
	hostsDir           string
	key                *[32]byte
	client             *http.Client
	now                clock
}

func (l tunnelLink) status() TunnelLinkStatus {
	return TunnelLinkStatus{Linked: true, Provider: l.Provider, Account: l.Account, LinkedAt: l.LinkedAt}
}

func validDeviceAuthorization(deviceCode, userCode, verificationURI string, expiresIn, interval int64) bool {
	if deviceCode == "" || len(deviceCode) > 4096 || userCode == "" || len(userCode) > 128 || expiresIn <= 0 || expiresIn > 3600 || interval < 0 || interval > 60 {
		return false
	}
	uri, err := url.Parse(verificationURI)
	return err == nil && uri.Scheme == "https" && uri.Host != "" && uri.User == nil && uri.Fragment == "" && len(verificationURI) <= 2048
}

func newLinkHandle() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func sealSecret(key *[32]byte, plaintext []byte) ([]byte, error) {
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	return secretbox.Seal(nonce[:], plaintext, &nonce, key), nil
}

func openSealed(key *[32]byte, sealed []byte) ([]byte, error) {
	if len(sealed) < 24 {
		return nil, errors.New("sealed tunnel link is truncated")
	}
	var nonce [24]byte
	copy(nonce[:], sealed[:24])
	plaintext, ok := secretbox.Open(nil, sealed[24:], &nonce, key)
	if !ok {
		return nil, errors.New("sealed tunnel link could not be opened")
	}
	return plaintext, nil
}

func decodeUnverifiedPreferredUsername(idToken string) string {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return ""
	}
	decoded, ok := canonicalBase64URL(parts[1])
	if !ok {
		return ""
	}
	var claims struct {
		PreferredUsername string `json:"preferred_username"`
	}
	if json.Unmarshal(decoded, &claims) != nil {
		return ""
	}
	return claims.PreferredUsername
}

func (b *LinkBroker) linkPath(principal Principal) string {
	return filepath.Join(b.hostsDir, PrincipalDirName(principal), tunnelLinkFileName)
}

func (b *LinkBroker) loadLink(principal Principal) (tunnelLink, bool, error) {
	path := b.linkPath(principal)
	if err := safeio.PrivateDir(filepath.Dir(path)); err != nil {
		if os.IsNotExist(err) {
			return tunnelLink{}, false, nil
		}
		return tunnelLink{}, false, err
	}
	sealed, err := safeio.ReadPrivateFile(path, maxOAuthResponse)
	if err != nil {
		if os.IsNotExist(err) {
			return tunnelLink{}, false, nil
		}
		return tunnelLink{}, false, err
	}
	plaintext, err := openSealed(b.key, sealed)
	if err != nil {
		return tunnelLink{}, false, err
	}
	var link tunnelLink
	if json.Unmarshal(plaintext, &link) != nil {
		return tunnelLink{}, false, errors.New("stored tunnel link is invalid")
	}
	return link, true, nil
}

func (b *LinkBroker) saveLink(principal Principal, link tunnelLink) error {
	path := b.linkPath(principal)
	if err := safeio.EnsurePrivateDir(filepath.Dir(path)); err != nil {
		return err
	}
	plaintext, err := json.Marshal(link)
	if err != nil {
		return err
	}
	sealed, err := sealSecret(b.key, plaintext)
	if err != nil {
		return err
	}
	return safeio.ReplaceFile(path, sealed)
}

func (b *LinkBroker) cleanupLocked(now time.Time) {
	for handle, entry := range b.entries {
		if !now.Before(entry.expiresAt) {
			b.deleteLocked(handle)
		}
	}
	for principal, next := range b.nextPrincipalStart {
		if !now.Before(next) {
			delete(b.nextPrincipalStart, principal)
		}
	}
}

func (b *LinkBroker) deleteLocked(handle string) {
	if entry := b.entries[handle]; entry != nil {
		clear(entry.deviceCode)
		delete(b.entries, handle)
	}
}

func (b *LinkBroker) finishPoll(handle string, remove bool, slowDown time.Duration) time.Duration {
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
	entry.interval = min(entry.interval+slowDown, maxLinkPollInterval)
	entry.nextPoll = b.now().Add(entry.interval)
	return entry.interval
}

func (b *LinkBroker) resolveAccount(ctx context.Context, provider tunnelLinkProvider, accessToken, idToken string) (string, error) {
	if provider.name == "github" {
		var user struct {
			Login string `json:"login"`
		}
		if err := httpx.GetJSON(ctx, b.client, provider.userEndpoint, SchemeBearer+" "+accessToken, maxOAuthResponse, &user); err != nil || user.Login == "" {
			return "", errors.New("resolve GitHub account")
		}
		return user.Login, nil
	}
	return decodeUnverifiedPreferredUsername(idToken), nil
}

func (b *LinkBroker) completeLink(ctx context.Context, principal Principal, provider tunnelLinkProvider, accessToken, refreshToken, idToken string, expiresIn int64) (TunnelLinkStatus, error) {
	account, err := b.resolveAccount(ctx, provider, accessToken, idToken)
	if err != nil {
		return TunnelLinkStatus{}, apierr.New("upstream_invalid", "authorization service returned an invalid response", http.StatusBadGateway)
	}
	now := b.now()
	link := tunnelLink{Provider: provider.name, Scheme: provider.scheme, AccessToken: accessToken, RefreshToken: refreshToken, Account: account, LinkedAt: now}
	if provider.name == "microsoft" {
		if expiresIn <= 0 {
			expiresIn = 3600
		}
		link.ExpiresAt = now.Add(time.Duration(expiresIn) * time.Second)
	}
	if err := b.saveLink(principal, link); err != nil {
		return TunnelLinkStatus{}, err
	}
	return link.status(), nil
}

func (b *LinkBroker) refreshMicrosoft(ctx context.Context, principal Principal, link tunnelLink) (tunnelLink, error) {
	provider := b.providers["microsoft"]
	body, status, err := postForm(ctx, b.client, provider.tokenEndpoint, url.Values{"grant_type": {"refresh_token"}, "client_id": {provider.clientID}, "refresh_token": {link.RefreshToken}, "scope": {provider.scope}}, oauthRequestTimeout)
	if err != nil || status < 200 || status >= 300 {
		return tunnelLink{}, apierr.New("upstream_unavailable", "the Dev Tunnels link could not be refreshed", http.StatusBadGateway)
	}
	var tokens struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
	}
	if json.Unmarshal(body, &tokens) != nil || tokens.AccessToken == "" {
		return tunnelLink{}, apierr.New("upstream_invalid", "the Dev Tunnels link could not be refreshed", http.StatusBadGateway)
	}
	if tokens.RefreshToken == "" {
		tokens.RefreshToken = link.RefreshToken
	}
	if tokens.ExpiresIn <= 0 {
		tokens.ExpiresIn = 3600
	}
	link.AccessToken, link.RefreshToken, link.ExpiresAt = tokens.AccessToken, tokens.RefreshToken, b.now().Add(time.Duration(tokens.ExpiresIn)*time.Second)
	if err := b.saveLink(principal, link); err != nil {
		return tunnelLink{}, err
	}
	return link, nil
}

func (b *LinkBroker) Status(principal Principal) (TunnelLinkStatus, error) {
	link, ok, err := b.loadLink(principal)
	if err != nil || !ok {
		return TunnelLinkStatus{}, err
	}
	return link.status(), nil
}

func (b *LinkBroker) Start(ctx context.Context, principal Principal, providerName string) (TunnelLinkStart, error) {
	provider, known := b.providers[providerName]
	if !known {
		return TunnelLinkStart{}, apierr.New("unknown_provider", "sign-in provider is not offered", http.StatusBadRequest)
	}
	now := b.now()
	b.mu.Lock()
	b.cleanupLocked(now)
	if now.Before(b.nextPrincipalStart[principal]) {
		b.mu.Unlock()
		return TunnelLinkStart{}, apierr.New("rate_limited", "request rate exceeded", http.StatusTooManyRequests)
	}
	if len(b.entries) >= maxLinkBrokerEntries {
		b.mu.Unlock()
		return TunnelLinkStart{}, apierr.New("broker_capacity", "authorization service is busy", http.StatusServiceUnavailable)
	}
	b.nextPrincipalStart[principal] = now.Add(linkStartInterval)
	b.mu.Unlock()

	form := url.Values{"client_id": {provider.clientID}}
	if provider.scope != "" {
		form.Set("scope", provider.scope)
	}
	body, status, err := postForm(ctx, b.client, provider.deviceEndpoint, form, oauthRequestTimeout)
	if err != nil || status < 200 || status >= 300 {
		return TunnelLinkStart{}, apierr.New("upstream_unavailable", "authorization service is unavailable", http.StatusBadGateway)
	}
	var result struct {
		DeviceCode      string `json:"device_code"`
		UserCode        string `json:"user_code"`
		VerificationURI string `json:"verification_uri"`
		ExpiresIn       int64  `json:"expires_in"`
		Interval        int64  `json:"interval"`
	}
	if json.Unmarshal(body, &result) != nil || !validDeviceAuthorization(result.DeviceCode, result.UserCode, result.VerificationURI, result.ExpiresIn, result.Interval) {
		return TunnelLinkStart{}, apierr.New("upstream_invalid", "authorization service returned an invalid response", http.StatusBadGateway)
	}
	if result.Interval == 0 {
		result.Interval = 5
	}
	handle, err := newLinkHandle()
	if err != nil {
		return TunnelLinkStart{}, apierr.New("broker_unavailable", "authorization service is unavailable", http.StatusInternalServerError)
	}
	now = b.now()
	entry := &linkBrokerEntry{
		provider: provider, principal: principal, deviceCode: []byte(result.DeviceCode),
		expiresAt: now.Add(time.Duration(result.ExpiresIn) * time.Second),
		interval:  time.Duration(result.Interval) * time.Second, nextPoll: now.Add(time.Duration(result.Interval) * time.Second),
	}
	b.mu.Lock()
	if len(b.entries) >= maxLinkBrokerEntries {
		b.mu.Unlock()
		clear(entry.deviceCode)
		return TunnelLinkStart{}, apierr.New("broker_capacity", "authorization service is busy", http.StatusServiceUnavailable)
	}
	b.entries[handle] = entry
	b.mu.Unlock()
	return TunnelLinkStart{Handle: handle, UserCode: result.UserCode, VerificationURI: result.VerificationURI, ExpiresInSeconds: result.ExpiresIn, IntervalSeconds: result.Interval}, nil
}

func (b *LinkBroker) Poll(ctx context.Context, principal Principal, handle string) (TunnelLinkPoll, error) {
	if !linkHandlePattern.MatchString(handle) {
		return TunnelLinkPoll{}, apierr.New("not_found", "authorization was not found", http.StatusNotFound)
	}
	now := b.now()
	b.mu.Lock()
	entry, ok := b.entries[handle]
	if !ok || entry.principal != principal {
		b.mu.Unlock()
		return TunnelLinkPoll{}, apierr.New("not_found", "authorization was not found", http.StatusNotFound)
	}
	if !now.Before(entry.expiresAt) {
		b.deleteLocked(handle)
		b.mu.Unlock()
		return TunnelLinkPoll{}, apierr.New("authorization_expired", "authorization expired", http.StatusGone)
	}
	if entry.inFlight || now.Before(entry.nextPoll) {
		b.mu.Unlock()
		return TunnelLinkPoll{}, apierr.New("rate_limited", "polling too quickly", http.StatusTooManyRequests)
	}
	entry.inFlight = true
	entry.nextPoll = now.Add(entry.interval)
	provider := entry.provider
	deviceCode := string(entry.deviceCode)
	remaining := entry.expiresAt.Sub(now)
	b.mu.Unlock()

	timeout := remaining
	if timeout <= 0 || timeout > oauthRequestTimeout {
		timeout = oauthRequestTimeout
	}
	body, status, err := postForm(ctx, b.client, provider.tokenEndpoint, url.Values{"grant_type": {tunnelLinkGrantType}, "client_id": {provider.clientID}, "device_code": {deviceCode}}, timeout)
	if err != nil {
		b.finishPoll(handle, true, 0)
		return TunnelLinkPoll{}, apierr.New("upstream_unavailable", "authorization service is unavailable", http.StatusBadGateway)
	}
	var oauthError struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(body, &oauthError)
	if status < 200 || status >= 300 || oauthError.Error != "" {
		switch oauthError.Error {
		case "authorization_pending":
			interval := b.finishPoll(handle, false, 0)
			return TunnelLinkPoll{Pending: true, IntervalSeconds: int64(interval / time.Second)}, nil
		case "slow_down":
			interval := b.finishPoll(handle, false, 5*time.Second)
			return TunnelLinkPoll{Pending: true, IntervalSeconds: int64(interval / time.Second)}, nil
		case "access_denied":
			b.finishPoll(handle, true, 0)
			return TunnelLinkPoll{}, apierr.New("authorization_denied", "authorization was denied", http.StatusForbidden)
		case "expired_token":
			b.finishPoll(handle, true, 0)
			return TunnelLinkPoll{}, apierr.New("authorization_expired", "authorization expired", http.StatusGone)
		default:
			b.finishPoll(handle, true, 0)
			return TunnelLinkPoll{}, apierr.New("upstream_failure", "authorization service rejected the request", http.StatusBadGateway)
		}
	}
	var tokens struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
		ExpiresIn    int64  `json:"expires_in"`
	}
	if json.Unmarshal(body, &tokens) != nil || tokens.AccessToken == "" {
		b.finishPoll(handle, true, 0)
		return TunnelLinkPoll{}, apierr.New("upstream_invalid", "authorization service returned an invalid response", http.StatusBadGateway)
	}
	linkStatus, err := b.completeLink(ctx, principal, provider, tokens.AccessToken, tokens.RefreshToken, tokens.IDToken, tokens.ExpiresIn)
	b.finishPoll(handle, true, 0)
	if err != nil {
		return TunnelLinkPoll{}, err
	}
	return TunnelLinkPoll{Status: linkStatus}, nil
}

func (b *LinkBroker) Credential(ctx context.Context, principal Principal) (TunnelCredential, error) {
	link, ok, err := b.loadLink(principal)
	if err != nil {
		return TunnelCredential{}, err
	}
	if !ok {
		return TunnelCredential{}, apierr.New("tunnel_link_required", "a Dev Tunnels link is required", http.StatusConflict)
	}
	if link.Provider == "microsoft" && !link.ExpiresAt.IsZero() && b.now().Add(tunnelLinkRefreshWindow).After(link.ExpiresAt) {
		refreshed, err := b.refreshMicrosoft(ctx, principal, link)
		if err != nil {
			return TunnelCredential{}, err
		}
		link = refreshed
	}
	return TunnelCredential{Scheme: link.Scheme, Token: link.AccessToken}, nil
}

func (b *LinkBroker) Delete(principal Principal) error {
	if err := os.Remove(b.linkPath(principal)); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (b *LinkBroker) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	for handle := range b.entries {
		b.deleteLocked(handle)
	}
	clear(b.nextPrincipalStart)
}

func LoadOrCreateTunnelLinkKey(path string) (*[32]byte, error) {
	data, err := safeio.ReadPrivateFile(path, 32)
	if err == nil {
		if len(data) != 32 {
			return nil, errors.New("tunnel-link key file is invalid")
		}
		var key [32]byte
		copy(key[:], data)
		return &key, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		return nil, err
	}
	if err := safeio.ReplaceFile(path, key[:]); err != nil {
		return nil, err
	}
	return &key, nil
}

func NewLinkBroker(hostsDir string, key *[32]byte, client *http.Client) (*LinkBroker, error) {
	if hostsDir == "" || key == nil {
		return nil, errors.New("tunnel-link broker dependencies are required")
	}
	return &LinkBroker{
		entries:            map[string]*linkBrokerEntry{},
		nextPrincipalStart: map[Principal]time.Time{},
		providers: map[string]tunnelLinkProvider{
			"microsoft": {name: "microsoft", scheme: SchemeBearer, deviceEndpoint: microsoftDeviceEndpoint, tokenEndpoint: microsoftTokenEndpoint, clientID: devTunnelsNativeClientID, scope: tunnelLinkDeviceScope},
			"github":    {name: "github", scheme: "github", deviceEndpoint: githubDeviceEndpoint, tokenEndpoint: githubTokenEndpoint, userEndpoint: githubUserAPI, clientID: devTunnelsGitHubClientID},
		},
		hostsDir: hostsDir, key: key, client: httpx.BoundedClient(client, oauthRequestTimeout), now: time.Now,
	}, nil
}

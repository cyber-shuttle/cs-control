// Package tunnel owns Dev Tunnels account linking and its HTTP surface. The broker binds device authorizations to
// principals, bounds pending work, and seals linked Microsoft or GitHub tokens in protected principal files. Provider
// protocol and cryptography remain internal; routes and stored metadata never expose tokens.
package tunnel

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"github.com/cyber-shuttle/cs-plane/internal/devtunnel"
	"github.com/cyber-shuttle/cs-plane/internal/router"
	"github.com/cyber-shuttle/cs-plane/internal/security"
)

const (
	maxStoredCredential     = 64 << 10
	tunnelLinkRefreshWindow = 2 * time.Minute
	maxLinkBrokerEntries    = 256
	linkStartInterval       = time.Second
	maxLinkPollInterval     = 60 * time.Second
	tunnelLinkFileName      = "tunnel-link"
	tunnelLinkKeyFileName   = "tunnel-link.key"
)

var linkHandlePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

type tunnelAuthorizer interface {
	Supports(string) bool
	Start(context.Context, string) (*devtunnel.DeviceAuthorization, error)
	Poll(context.Context, *devtunnel.DeviceAuthorization, time.Duration) (devtunnel.PollResult, error)
	Refresh(context.Context, string, string) (devtunnel.AuthorizationTokens, error)
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

type tunnelLinkStatus struct {
	Linked   bool      `json:"linked"`
	Provider string    `json:"provider,omitempty"`
	Account  string    `json:"account,omitempty"`
	LinkedAt time.Time `json:"linkedAt,omitzero"`
}

type tunnelLinkStart struct {
	Handle           string `json:"handle"`
	UserCode         string `json:"userCode"`
	VerificationURI  string `json:"verificationUri"`
	ExpiresInSeconds int64  `json:"expiresInSeconds"`
	IntervalSeconds  int64  `json:"intervalSeconds"`
}

type tunnelLinkPoll struct {
	Pending         bool
	IntervalSeconds int64
	Status          tunnelLinkStatus
}

type startLinkRequest struct {
	Provider string `json:"provider"`
}

type pendingLink struct {
	Status          string `json:"status"`
	IntervalSeconds int64  `json:"intervalSeconds"`
}

type linkBrokerEntry struct {
	principal     security.Principal
	authorization *devtunnel.DeviceAuthorization
	expiresAt     time.Time
	interval      time.Duration
	nextPoll      time.Time
}

type Service struct {
	mu                 sync.Mutex
	entries            map[string]*linkBrokerEntry
	nextPrincipalStart map[security.Principal]time.Time
	stateDir           string
	principalDir       string
	box                *security.SecretBox
	authorizer         tunnelAuthorizer
	now                func() time.Time
}

func (l tunnelLink) status() tunnelLinkStatus {
	return tunnelLinkStatus{Linked: true, Provider: l.Provider, Account: l.Account, LinkedAt: l.LinkedAt}
}

func (s *Service) withCredentialLock(principal security.Principal, fn func() error) error {
	path := filepath.Join(s.stateDir, ".tunnel-link-"+security.PrincipalDirName(principal)+".lock")
	return security.WithFileLock(path, fn)
}

func (s *Service) linkPath(principal security.Principal) string {
	return filepath.Join(s.principalDir, security.PrincipalDirName(principal), tunnelLinkFileName)
}

func (s *Service) loadLink(principal security.Principal) (tunnelLink, bool, error) {
	path := s.linkPath(principal)
	if err := security.PrivateDir(filepath.Dir(path)); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return tunnelLink{}, false, nil
		}
		return tunnelLink{}, false, err
	}
	sealed, err := security.ReadPrivateFile(path, maxStoredCredential)
	if errors.Is(err, os.ErrNotExist) {
		return tunnelLink{}, false, nil
	}
	if err != nil {
		return tunnelLink{}, false, err
	}
	plaintext, err := s.box.Open(sealed)
	if err != nil {
		return tunnelLink{}, false, err
	}
	var link tunnelLink
	if json.Unmarshal(plaintext, &link) != nil {
		return tunnelLink{}, false, errors.New("stored tunnel link is invalid")
	}
	return link, true, nil
}

func (s *Service) saveLink(principal security.Principal, link tunnelLink) error {
	path := s.linkPath(principal)
	if err := security.EnsurePrivateDir(filepath.Dir(path)); err != nil {
		return err
	}
	plaintext, err := json.Marshal(link)
	if err != nil {
		return err
	}
	sealed, err := s.box.Seal(plaintext)
	if err != nil {
		return err
	}
	return security.ReplaceFile(path, sealed)
}

func (s *Service) cleanupLocked(now time.Time) {
	for handle, entry := range s.entries {
		if !now.Before(entry.expiresAt) {
			s.deleteLocked(handle)
		}
	}
	for principal, next := range s.nextPrincipalStart {
		if !now.Before(next) {
			delete(s.nextPrincipalStart, principal)
		}
	}
}

func (s *Service) deleteLocked(handle string) {
	if entry := s.entries[handle]; entry != nil {
		entry.authorization.Clear()
		delete(s.entries, handle)
	}
}

func (s *Service) finishPoll(handle string, remove bool, slowDown time.Duration) time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry := s.entries[handle]
	if entry == nil {
		return 0
	}
	if remove {
		s.deleteLocked(handle)
		return 0
	}
	entry.interval = min(entry.interval+slowDown, maxLinkPollInterval)
	entry.nextPoll = s.now().Add(entry.interval)
	return entry.interval
}

func authorizationError(err error) error {
	switch {
	case errors.Is(err, devtunnel.ErrUnknownProvider):
		return security.New("unknown_provider", "sign-in provider is not offered", http.StatusBadRequest)
	case errors.Is(err, devtunnel.ErrAuthorizationDenied):
		return security.New("authorization_denied", "authorization was denied", http.StatusForbidden)
	case errors.Is(err, devtunnel.ErrAuthorizationExpired):
		return security.New("authorization_expired", "authorization expired", http.StatusGone)
	case errors.Is(err, devtunnel.ErrAuthorizationUnavailable):
		return security.New("upstream_unavailable", "authorization service is unavailable", http.StatusBadGateway)
	case errors.Is(err, devtunnel.ErrAuthorizationRejected):
		return security.New("upstream_failure", "authorization service rejected the request", http.StatusBadGateway)
	default:
		return security.New("upstream_invalid", "authorization service returned an invalid response", http.StatusBadGateway)
	}
}

func (s *Service) status(principal security.Principal) (tunnelLinkStatus, error) {
	link, ok, err := s.loadLink(principal)
	if err != nil || !ok {
		return tunnelLinkStatus{}, err
	}
	return link.status(), nil
}

func (s *Service) start(ctx context.Context, principal security.Principal, providerName string) (tunnelLinkStart, error) {
	if !s.authorizer.Supports(providerName) {
		return tunnelLinkStart{}, authorizationError(devtunnel.ErrUnknownProvider)
	}
	now := s.now()
	s.mu.Lock()
	s.cleanupLocked(now)
	if now.Before(s.nextPrincipalStart[principal]) {
		s.mu.Unlock()
		return tunnelLinkStart{}, security.New("rate_limited", "request rate exceeded", http.StatusTooManyRequests)
	}
	if len(s.entries) >= maxLinkBrokerEntries {
		s.mu.Unlock()
		return tunnelLinkStart{}, security.New("broker_capacity", "authorization service is busy", http.StatusServiceUnavailable)
	}
	s.nextPrincipalStart[principal] = now.Add(linkStartInterval)
	s.mu.Unlock()

	authorization, err := s.authorizer.Start(ctx, providerName)
	if err != nil {
		return tunnelLinkStart{}, authorizationError(err)
	}
	rawHandle := make([]byte, 32)
	_, _ = rand.Read(rawHandle)
	handle := base64.RawURLEncoding.EncodeToString(rawHandle)
	now = s.now()
	entry := &linkBrokerEntry{
		principal: principal, authorization: authorization, expiresAt: now.Add(authorization.ExpiresIn),
		interval: authorization.Interval, nextPoll: now.Add(authorization.Interval),
	}
	s.mu.Lock()
	if len(s.entries) >= maxLinkBrokerEntries {
		s.mu.Unlock()
		authorization.Clear()
		return tunnelLinkStart{}, security.New("broker_capacity", "authorization service is busy", http.StatusServiceUnavailable)
	}
	s.entries[handle] = entry
	s.mu.Unlock()
	return tunnelLinkStart{
		Handle: handle, UserCode: authorization.UserCode, VerificationURI: authorization.VerificationURI,
		ExpiresInSeconds: int64(authorization.ExpiresIn / time.Second), IntervalSeconds: int64(authorization.Interval / time.Second),
	}, nil
}

func (s *Service) poll(ctx context.Context, principal security.Principal, handle string) (result tunnelLinkPoll, err error) {
	if !linkHandlePattern.MatchString(handle) {
		return tunnelLinkPoll{}, security.New("not_found", "authorization was not found", http.StatusNotFound)
	}
	err = s.withCredentialLock(principal, func() error {
		result, err = s.pollCredentialLocked(ctx, principal, handle)
		return err
	})
	return result, err
}

func (s *Service) pollCredentialLocked(ctx context.Context, principal security.Principal, handle string) (tunnelLinkPoll, error) {
	now := s.now()
	s.mu.Lock()
	entry, ok := s.entries[handle]
	if !ok || entry.principal != principal {
		s.mu.Unlock()
		return tunnelLinkPoll{}, security.New("not_found", "authorization was not found", http.StatusNotFound)
	}
	if !now.Before(entry.expiresAt) {
		s.deleteLocked(handle)
		s.mu.Unlock()
		return tunnelLinkPoll{}, security.New("authorization_expired", "authorization expired", http.StatusGone)
	}
	if now.Before(entry.nextPoll) {
		s.mu.Unlock()
		return tunnelLinkPoll{}, security.New("rate_limited", "polling too quickly", http.StatusTooManyRequests)
	}
	authorization, remaining := entry.authorization, entry.expiresAt.Sub(now)
	s.mu.Unlock()

	result, err := s.authorizer.Poll(ctx, authorization, remaining)
	if err != nil {
		s.finishPoll(handle, true, 0)
		return tunnelLinkPoll{}, authorizationError(err)
	}
	if result.Pending {
		interval := s.finishPoll(handle, false, result.SlowDown)
		return tunnelLinkPoll{Pending: true, IntervalSeconds: int64(interval / time.Second)}, nil
	}
	s.finishPoll(handle, true, 0)
	now = s.now()
	link := tunnelLink{
		Provider: result.Tokens.Provider, Scheme: result.Tokens.Scheme, AccessToken: result.Tokens.AccessToken,
		RefreshToken: result.Tokens.RefreshToken, Account: result.Tokens.Account, LinkedAt: now,
	}
	if result.Tokens.ExpiresIn > 0 {
		link.ExpiresAt = now.Add(result.Tokens.ExpiresIn)
	}
	if err = s.saveLink(principal, link); err != nil {
		return tunnelLinkPoll{}, err
	}
	return tunnelLinkPoll{Status: link.status()}, nil
}

func (s *Service) Credential(ctx context.Context, principal security.Principal) (result devtunnel.Credential, err error) {
	err = s.withCredentialLock(principal, func() error {
		link, ok, err := s.loadLink(principal)
		if err != nil {
			return err
		}
		if !ok {
			return security.New("tunnel_link_required", "a Dev Tunnels link is required", http.StatusConflict)
		}
		if link.RefreshToken != "" && !link.ExpiresAt.IsZero() && s.now().Add(tunnelLinkRefreshWindow).After(link.ExpiresAt) {
			tokens, err := s.authorizer.Refresh(ctx, link.Provider, link.RefreshToken)
			if err != nil {
				return security.New("upstream_unavailable", "the Dev Tunnels link could not be refreshed", http.StatusBadGateway)
			}
			link.AccessToken, link.RefreshToken, link.ExpiresAt = tokens.AccessToken, tokens.RefreshToken, s.now().Add(tokens.ExpiresIn)
			if err := s.saveLink(principal, link); err != nil {
				return err
			}
		}
		result = devtunnel.Credential{Scheme: link.Scheme, Token: link.AccessToken}
		return nil
	})
	return result, err
}

func (s *Service) delete(principal security.Principal) error {
	return s.withCredentialLock(principal, func() error {
		path := s.linkPath(principal)
		if err := security.PrivateDir(filepath.Dir(path)); errors.Is(err, os.ErrNotExist) {
			return nil
		} else if err != nil {
			return err
		}
		return security.RemoveFile(path)
	})
}

func (s *Service) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for handle := range s.entries {
		s.deleteLocked(handle)
	}
	clear(s.nextPrincipalStart)
}

func NewService(stateDir, principalDir string, client *http.Client) (*Service, error) {
	if stateDir == "" || principalDir == "" {
		return nil, errors.New("tunnel broker directories are required")
	}
	if err := security.EnsurePrivateDir(stateDir); err != nil {
		return nil, err
	}
	if err := security.EnsurePrivateDir(principalDir); err != nil {
		return nil, err
	}
	box, err := security.LoadOrCreateSecretBox(filepath.Join(stateDir, tunnelLinkKeyFileName))
	if err != nil {
		return nil, err
	}
	return newService(stateDir, principalDir, box, devtunnel.NewAuthorizer(client)), nil
}

func newService(stateDir, principalDir string, box *security.SecretBox, authorizer tunnelAuthorizer) *Service {
	return &Service{
		entries: map[string]*linkBrokerEntry{}, nextPrincipalStart: map[security.Principal]time.Time{},
		stateDir: stateDir, principalDir: principalDir, box: box, authorizer: authorizer, now: time.Now,
	}
}

func (s *Service) Routes() router.Routes {
	return router.Routes{
		"/api/v1/tunnel": {
			http.MethodGet: security.AnswerAsPrincipal(http.StatusOK, func(principal security.Principal, _ *http.Request) (tunnelLinkStatus, error) {
				return s.status(principal)
			}),
			http.MethodDelete: security.NoContentAsPrincipal(func(principal security.Principal, _ *http.Request) error {
				return s.delete(principal)
			}),
		},
		"/api/v1/tunnel/authorizations": {
			http.MethodPost: security.AnswerAsPrincipal(http.StatusOK, func(principal security.Principal, request *http.Request) (tunnelLinkStart, error) {
				var body startLinkRequest
				if err := security.DecodeJSON(request, &body); err != nil {
					return tunnelLinkStart{}, err
				}
				return s.start(request.Context(), principal, body.Provider)
			}),
		},
		"/api/v1/tunnel/authorizations/{handle}/poll": {
			http.MethodPost: security.AnswerAsPrincipal(http.StatusOK, func(principal security.Principal, request *http.Request) (any, error) {
				result, err := s.poll(request.Context(), principal, request.PathValue("handle"))
				if err != nil || !result.Pending {
					return result.Status, err
				}
				return pendingLink{Status: "pending", IntervalSeconds: result.IntervalSeconds}, nil
			}),
		},
	}
}

// Custos resolves a validated identity token to its linked user. Successful resolutions are cached by token hash
// so a polling client does not call Custos on every request; authorization failures remain distinct so the auth
// subsystem can own their public meaning.
package identity

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/cyber-shuttle/cs-control/internal/security"
)

const (
	custosUserTTL  = 5 * time.Minute
	maxCustosUsers = 1024
)

type custosMeResponse struct {
	User struct {
		ID string `json:"id"`
	} `json:"user"`
	Code string `json:"code"`
}

type cachedCustosUser struct {
	id        string
	expiresAt time.Time
}

type Custos struct {
	mu       sync.Mutex
	cache    map[[sha256.Size]byte]cachedCustosUser
	endpoint string
	client   *http.Client
	now      func() time.Time
}

func NewCustos(baseURL string, client *http.Client) (*Custos, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil || baseURL != strings.TrimSpace(baseURL) || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Opaque != "" {
		return nil, errors.New("Custos URL must be an HTTPS URL")
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/") + "/me"
	return &Custos{
		cache:    map[[sha256.Size]byte]cachedCustosUser{},
		endpoint: parsed.String(),
		client:   security.GuardedClient(client, oauthRequestTimeout),
		now:      time.Now,
	}, nil
}

func (r *Custos) Resolve(ctx context.Context, idToken string) (string, error) {
	if !security.ValidCredential(idToken) {
		return "", errors.New("Custos identity token is invalid")
	}
	key := sha256.Sum256([]byte(idToken))
	now := r.now()
	r.mu.Lock()
	cached, ok := r.cache[key]
	r.mu.Unlock()
	if ok && now.Before(cached.expiresAt) {
		return cached.id, nil
	}
	request, err := security.NewRequest(ctx, http.MethodGet, r.endpoint, "Bearer "+idToken, nil)
	if err != nil {
		return "", err
	}
	body, status, err := security.Do(r.client, request, maxOAuthResponse)
	if err != nil {
		return "", fmt.Errorf("resolve Custos identity: %w", err)
	}
	var response custosMeResponse
	_ = json.Unmarshal(body, &response)
	if status == http.StatusUnauthorized {
		if response.Code == "identity_not_linked" {
			return "", ErrIdentityNotLinked
		}
		return "", ErrIdentityUnrecognized
	}
	if status < 200 || status >= 300 || !security.ValidIdentityValue(response.User.ID) {
		return "", errors.New("Custos identity resolution failed")
	}
	r.mu.Lock()
	if len(r.cache) >= maxCustosUsers {
		clear(r.cache)
	}
	r.cache[key] = cachedCustosUser{id: response.User.ID, expiresAt: now.Add(custosUserTTL)}
	r.mu.Unlock()
	return response.User.ID, nil
}

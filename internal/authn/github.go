// A GitHub token is the Dev Tunnels capability under the github scheme and the identity at once. The principal
// is the GitHub user id, read once per token and held, since the browser polls sessions every second and
// GitHub meters the user endpoint per token.
//
//	githubUserEndpoint, githubPrincipalTTL, maxGitHubPrincipals
//	githubPrincipal, githubValidator
//	newGitHubValidator
package authn

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/cyber-shuttle/cs-control/internal/httpx"
)

const (
	githubUserEndpoint  = "https://api.github.com/user"
	githubPrincipalTTL  = 5 * time.Minute
	maxGitHubPrincipals = 1024
)

type githubPrincipal struct {
	principal Principal
	expiresAt time.Time
}

type githubValidator struct {
	mu       sync.Mutex
	cache    map[[sha256.Size]byte]githubPrincipal
	endpoint string
	client   *http.Client
	now      clock
}

func newGitHubValidator(endpoint string, client *http.Client) *githubValidator {
	return &githubValidator{cache: map[[sha256.Size]byte]githubPrincipal{}, endpoint: endpoint, client: httpx.BoundedClient(client, oauthRequestTimeout), now: time.Now}
}

func (v *githubValidator) Validate(ctx context.Context, token string) (Principal, error) {
	key := sha256.Sum256([]byte(token))
	now := v.now()
	v.mu.Lock()
	cached, ok := v.cache[key]
	v.mu.Unlock()
	if ok && now.Before(cached.expiresAt) {
		return cached.principal, nil
	}
	var user struct {
		ID int64 `json:"id"`
	}
	if err := httpx.GetJSON(ctx, v.client, v.endpoint, SchemeBearer+" "+token, maxOAuthResponse, &user); err != nil {
		return Principal{}, fmt.Errorf("validate GitHub token: %w", err)
	}
	if user.ID <= 0 {
		return Principal{}, errors.New("GitHub user is invalid")
	}
	principal := Principal{Subject: strconv.FormatInt(user.ID, 10), Tenant: SchemeGitHub}
	v.mu.Lock()
	if len(v.cache) >= maxGitHubPrincipals {
		clear(v.cache)
	}
	v.cache[key] = githubPrincipal{principal: principal, expiresAt: now.Add(githubPrincipalTTL)}
	v.mu.Unlock()
	return principal, nil
}

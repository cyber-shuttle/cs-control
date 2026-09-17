// Custos identity resolution, layered above OIDC validation. A token that verifies against the issuer still
// answers as no one until Custos names the user it belongs to; that user id, under the fixed tenant custos,
// is the only principal this daemon ever grants. The result is cached per token hash so the poll every second
// does not call Custos every second.
//
//	custosPrincipalTTL, maxCustosPrincipals, custosTenant
//	custosMeResponse, cachedCustosPrincipal, custosResolver
//	newCustosResolver
//	Validator
//	NewValidator
package authn

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/cyber-shuttle/cs-control/internal/apierr"
	"github.com/cyber-shuttle/cs-control/internal/httpx"
)

const (
	custosPrincipalTTL  = 5 * time.Minute
	maxCustosPrincipals = 1024
	custosTenant        = "custos"
)

type custosMeResponse struct {
	User struct {
		ID string `json:"id"`
	} `json:"user"`
	Code string `json:"code"`
}

type cachedCustosPrincipal struct {
	principal Principal
	expiresAt time.Time
}

type custosResolver struct {
	mu       sync.Mutex
	cache    map[[sha256.Size]byte]cachedCustosPrincipal
	endpoint string
	client   *http.Client
	now      clock
}

func newCustosResolver(baseURL string, client *http.Client) (*custosResolver, error) {
	trimmed := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if trimmed == "" {
		return nil, errors.New("Custos URL is required")
	}
	return &custosResolver{
		cache:    map[[sha256.Size]byte]cachedCustosPrincipal{},
		endpoint: trimmed + "/me",
		client:   httpx.BoundedClient(client, oauthRequestTimeout),
		now:      time.Now,
	}, nil
}

func (r *custosResolver) Resolve(ctx context.Context, idToken string) (Principal, error) {
	key := sha256.Sum256([]byte(idToken))
	now := r.now()
	r.mu.Lock()
	cached, ok := r.cache[key]
	r.mu.Unlock()
	if ok && now.Before(cached.expiresAt) {
		return cached.principal, nil
	}
	request, err := httpx.NewRequest(ctx, http.MethodGet, r.endpoint, SchemeBearer+" "+idToken, nil)
	if err != nil {
		return Principal{}, err
	}
	body, status, err := httpx.Do(r.client, request, maxOAuthResponse)
	if err != nil {
		return Principal{}, fmt.Errorf("resolve Custos identity: %w", err)
	}
	var response custosMeResponse
	_ = json.Unmarshal(body, &response)
	if status == http.StatusUnauthorized {
		message := "Custos did not recognize this identity"
		if response.Code == "identity_not_linked" {
			message = "OIDC identity is not linked to a Custos user"
		}
		return Principal{}, apierr.New("identity_not_linked", message, http.StatusUnauthorized)
	}
	if status < 200 || status >= 300 || !validIdentityValue(response.User.ID) {
		return Principal{}, errors.New("Custos identity resolution failed")
	}
	principal := Principal{Subject: response.User.ID, Tenant: custosTenant}
	r.mu.Lock()
	if len(r.cache) >= maxCustosPrincipals {
		clear(r.cache)
	}
	r.cache[key] = cachedCustosPrincipal{principal: principal, expiresAt: now.Add(custosPrincipalTTL)}
	r.mu.Unlock()
	return principal, nil
}

type Validator struct {
	identity *oidcValidator
	custos   *custosResolver
}

func (v *Validator) Validate(ctx context.Context, credentials OAuthCredentials) (Principal, error) {
	if v == nil || v.identity == nil || v.custos == nil || !validOAuthToken(credentials.IDToken) {
		return Principal{}, errors.New("OAuth credentials are invalid")
	}
	if err := v.identity.Validate(ctx, credentials.IDToken); err != nil {
		return Principal{}, err
	}
	return v.custos.Resolve(ctx, credentials.IDToken)
}

func NewValidator(custosURL, issuer, clientID string, client *http.Client) (*Validator, error) {
	identity, err := newOIDCValidator(issuer, clientID, client)
	if err != nil {
		return nil, err
	}
	custos, err := newCustosResolver(custosURL, client)
	if err != nil {
		return nil, err
	}
	return &Validator{identity: identity, custos: custos}, nil
}

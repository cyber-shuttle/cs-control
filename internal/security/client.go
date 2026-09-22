// Outbound HTTP primitives shared by external-service callers.
// UserAgent identifies the binary to the services it calls; the composition root sets it once at startup.
// A GuardedClient follows only same-origin redirects, so the Authorization header Go preserves across such a hop
// never reaches another host.
package security

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var UserAgent = "cs-plane"

func BoundedClient(client *http.Client, fallback time.Duration) *http.Client {
	if client == nil {
		client = http.DefaultClient
	}
	bounded := *client
	if bounded.Timeout <= 0 || bounded.Timeout > fallback {
		bounded.Timeout = fallback
	}
	return &bounded
}

func SameOriginRedirect(from, to *url.URL) bool {
	return from != nil && to != nil && to.User == nil && from.Scheme == to.Scheme && from.Host == to.Host
}

func GuardedClient(client *http.Client, fallback time.Duration) *http.Client {
	bounded := BoundedClient(client, fallback)
	bounded.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if len(via) >= 5 || len(via) == 0 || !SameOriginRedirect(via[0].URL, request.URL) {
			return http.ErrUseLastResponse
		}
		return nil
	}
	return bounded
}

func Do(client *http.Client, request *http.Request, limit int64) ([]byte, int, error) {
	response, err := client.Do(request)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, response.StatusCode, err
	}
	if int64(len(body)) > limit {
		return nil, response.StatusCode, errors.New("response body exceeds limit")
	}
	return body, response.StatusCode, nil
}

func NewRequest(ctx context.Context, method, endpoint, authorization string, body io.Reader) (*http.Request, error) {
	request, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", UserAgent)
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}
	return request, nil
}

func PostForm(parent context.Context, client *http.Client, endpoint string, form url.Values, timeout time.Duration, limit int64) ([]byte, int, error) {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	request, err := NewRequest(ctx, http.MethodPost, endpoint, "", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, 0, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return Do(client, request, limit)
}

func GetJSON(ctx context.Context, client *http.Client, endpoint, authorization string, limit int64, destination any) error {
	request, err := NewRequest(ctx, http.MethodGet, endpoint, authorization, nil)
	if err != nil {
		return err
	}
	body, status, err := Do(client, request, limit)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("HTTP %d", status)
	}
	return json.Unmarshal(body, destination)
}

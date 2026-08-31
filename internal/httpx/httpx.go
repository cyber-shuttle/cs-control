// Package httpx holds the outbound-HTTP primitives every subsystem that talks
// to an external identity or tunnel service needs: a bounded client, a bounded
// body read, and the URL policy those services' base URLs must satisfy.
package httpx

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

	"github.com/cyber-shuttle/cs-control/internal/apierr"
)

const userAgent = "cs-control/0.1.0"

// ParseBaseURL accepts only a bare http(s) origin with an optional path -- no
// credentials, query or fragment -- so a base URL cannot smuggle parameters into
// every request built from it. subject names it in errors.
func ParseBaseURL(raw, subject string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Scheme != "https" && parsed.Scheme != "http") {
		return nil, fmt.Errorf("%s is invalid", subject)
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	return parsed, nil
}

// BoundedClient copies client with a timeout no longer than fallback, so a
// hung external service can never hold a request goroutine open indefinitely.
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

// Do sends request and returns its body alongside the status, leaving status
// interpretation to the caller. An oversized body is rejected rather than
// truncated, so a partial response is never parsed as a whole one.
func Do(client *http.Client, request *http.Request, limit int64) ([]byte, int, error) {
	response, err := client.Do(request)
	if err != nil {
		return nil, 0, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, response.StatusCode, err
	}
	if int64(len(body)) > limit {
		return nil, response.StatusCode, errors.New("response body exceeds limit")
	}
	return body, response.StatusCode, nil
}

// NewRequest builds an outbound request with this process's standard headers and
// its bearer when one is supplied, so the user agent and the Accept and
// Authorization policy exist in one place.
func NewRequest(ctx context.Context, method, endpoint, bearer string, body io.Reader) (*http.Request, error) {
	request, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", userAgent)
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	return request, nil
}

// GetJSON decodes a bounded successful JSON response into destination.
func GetJSON(ctx context.Context, client *http.Client, endpoint, bearer string, limit int64, destination any) error {
	request, err := NewRequest(ctx, http.MethodGet, endpoint, bearer, nil)
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

// WriteJSON renders value as the whole response body. Every control response is
// no-store: a browser or proxy must never retain runtime state or a token.
func WriteJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

// WriteError renders err as the classified envelope clients parse, so an
// unclassified error surfaces as an opaque 500 rather than its own text.
func WriteError(writer http.ResponseWriter, err error) {
	api := apierr.For(err)
	WriteJSON(writer, api.Status, apierr.Envelope{Error: api})
}

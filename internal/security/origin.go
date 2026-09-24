// Origins is the one browser-origin policy the OAuth boundary and the session routes apply. An origin is an exact
// HTTPS or loopback HTTP scheme and host. A request without Origin is a native client and passes; a present Origin
// must be allowlisted. Routes that serve only browsers additionally require Origin, which is the caller's decision,
// not this policy's.
package security

import (
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
)

type Origins map[string]struct{}

func validOrigin(origin string) error {
	if origin == "" || origin == "*" || strings.TrimSpace(origin) != origin {
		return errors.New("control origin is invalid")
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed.User != nil || parsed.Host == "" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("control origin is invalid")
	}
	if parsed.Scheme == "https" {
		return nil
	}
	host := parsed.Hostname()
	ip := net.ParseIP(host)
	if parsed.Scheme == "http" && (host == "localhost" || ip != nil && ip.IsLoopback()) {
		return nil
	}
	return errors.New("control origin must use HTTPS or loopback HTTP")
}

func NewOrigins(allowed []string) (Origins, error) {
	origins := make(Origins, len(allowed))
	for _, origin := range allowed {
		if err := validOrigin(origin); err != nil {
			return nil, err
		}
		origins[origin] = struct{}{}
	}
	if len(origins) == 0 {
		return nil, errors.New("at least one control origin is required")
	}
	return origins, nil
}

func (o Origins) Allowed(origin string) bool {
	_, ok := o[origin]
	return ok
}

func (o Origins) Admits(request *http.Request) bool {
	origin := request.Header.Get("Origin")
	return origin == "" || o.Allowed(origin)
}

var ErrOriginNotAllowed = New("origin_not_allowed", "origin is not allowed", http.StatusForbidden)

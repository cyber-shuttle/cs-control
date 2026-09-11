package control

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cyber-shuttle/cs-control/internal/authn"
	"github.com/cyber-shuttle/cs-control/internal/sshconfig"
)

// handlerAs serves requests whose caller is always principal.
func handlerAs(t *testing.T, service Service, principal authn.Principal) (*HTTPAPI, http.Handler) {
	t.Helper()
	api := NewHTTPHandler(service, nil)
	handler, err := authn.NewOAuthBoundary(api, oauthValidatorFunc(func(context.Context, string) (authn.Principal, error) {
		return principal, nil
	}), []string{mixedOwnerOrigin})
	if err != nil {
		api.Close()
		t.Fatal(err)
	}
	t.Cleanup(api.Close)
	return api, handler
}

func hostRequest(t *testing.T, handler http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var reader *strings.Reader = strings.NewReader(body)
	request := httptest.NewRequest(method, path, reader)
	request.Header.Set("Origin", mixedOwnerOrigin)
	request.Header.Set("Authorization", "Bearer delegated-token")
	request.Header.Set(authn.ControlIdentityHeader, testIdentityToken)
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func hostNames(t *testing.T, handler http.Handler) []string {
	t.Helper()
	response := hostRequest(t, handler, http.MethodGet, "/api/v1/ssh", "")
	if response.Code != http.StatusOK {
		t.Fatalf("host list = %d %s", response.Code, response.Body.String())
	}
	var list sshconfig.HostList
	if err := json.Unmarshal(response.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(list.Hosts))
	for _, host := range list.Hosts {
		names = append(names, host.Name)
	}
	return names
}

func isolatedHostService(t *testing.T) Service {
	t.Helper()
	service := testService(t)
	service.Config.HostsDir = filepath.Join(t.TempDir(), "hosts")
	return service
}

// The whole point of the per-caller host store: an alias one principal adds is
// invisible to every other, and the account this daemon runs as has no standing.
func TestSSHHostsAreIsolatedPerPrincipal(t *testing.T) {
	service := isolatedHostService(t)
	_, mine := handlerAs(t, service, testPrincipal)
	_, theirs := handlerAs(t, service, otherTestPrincipal)

	if got := hostNames(t, mine); len(got) != 0 {
		t.Fatalf("a caller with no hosts of their own was shown %v", got)
	}
	created := hostRequest(t, mine, http.MethodPost, "/api/v1/ssh", `{"name":"delta","command":"ssh me@login.example.edu"}`)
	if created.Code != http.StatusCreated {
		t.Fatalf("add = %d %s", created.Code, created.Body.String())
	}

	if got := hostNames(t, mine); len(got) != 1 || got[0] != "delta" {
		t.Fatalf("the caller cannot see the host they added: %v", got)
	}
	if got := hostNames(t, theirs); len(got) != 0 {
		t.Fatalf("another principal was shown a host that is not theirs: %v", got)
	}

	// The same alias name is free for another caller, and editing or deleting it
	// reaches only their own entry.
	if code := hostRequest(t, theirs, http.MethodPost, "/api/v1/ssh", `{"name":"delta","command":"ssh you@other.example.edu"}`).Code; code != http.StatusCreated {
		t.Fatalf("a name another principal already used was refused: %d", code)
	}
	if code := hostRequest(t, theirs, http.MethodDelete, "/api/v1/ssh/delta", "").Code; code != http.StatusOK {
		t.Fatalf("delete = %d", code)
	}
	if got := hostNames(t, mine); len(got) != 1 {
		t.Fatalf("another principal's delete reached this caller's host: %v", got)
	}
}

// Each caller's configuration is a private file of its own, and ssh is pointed
// at it by name so an alias cannot resolve through anyone else's.
func TestEachPrincipalGetsItsOwnPrivateConfigFile(t *testing.T) {
	service := isolatedHostService(t)
	_, mine := handlerAs(t, service, testPrincipal)
	if code := hostRequest(t, mine, http.MethodPost, "/api/v1/ssh", `{"name":"delta","command":"ssh me@login.example.edu"}`).Code; code != http.StatusCreated {
		t.Fatal("add failed")
	}
	path := service.hostConfigPath(testPrincipal)
	if path == "" || !strings.HasPrefix(path, service.Config.HostsDir) {
		t.Fatalf("host configuration is not inside the per-caller store: %q", path)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the caller's own configuration was not written: %v", err)
	}
	// The subject is an identifier from another system and never becomes a path.
	if strings.Contains(path, testPrincipal.Subject) {
		t.Fatalf("the principal's subject leaked into the path: %q", path)
	}
	if service.forPrincipal(testPrincipal).Runner.Hosts.UserPath != path {
		t.Fatal("the scoped runner does not name the caller's own configuration")
	}
	// Two principals never share a file, and so never share a control master.
	if service.hostConfigPath(otherTestPrincipal) == path {
		t.Fatal("two principals resolved to one configuration")
	}
}

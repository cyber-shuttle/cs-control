// Every caller has their own host configuration and nothing else.
// One principal's aliases are invisible to another, and each gets its own private config file.
//
//	handlerAs
//	hostRequest
//	hostNames
//	isolatedHostService
//	Test*
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
	"time"

	"github.com/cyber-shuttle/cs-control/internal/apierr"
	"github.com/cyber-shuttle/cs-control/internal/authn"
	"github.com/cyber-shuttle/cs-control/internal/sshconfig"
	"github.com/cyber-shuttle/cs-control/internal/sshexec"
	"github.com/cyber-shuttle/cs-control/internal/testutil"
)

func handlerAs(t *testing.T, service Service, principal authn.Principal) http.Handler {
	t.Helper()
	api := NewHTTPHandler(service, noopAuth{})
	handler, err := authn.NewOAuthBoundary(api, oauthValidatorFunc(func(context.Context, string) (authn.Principal, error) {
		return principal, nil
	}), []string{mixedOwnerOrigin})
	if err != nil {
		api.Close()
		t.Fatal(err)
	}
	t.Cleanup(api.Close)
	return handler
}

func hostRequest(t *testing.T, handler http.Handler, method, path, body string, ifNoneMatch ...string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	for _, etag := range ifNoneMatch {
		request.Header.Set("If-None-Match", etag)
	}
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
	testutil.Check(t, json.Unmarshal(response.Body.Bytes(), &list))
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

func TestSSHHostsAreIsolatedPerPrincipal(t *testing.T) {
	service := isolatedHostService(t)
	mine := handlerAs(t, service, testPrincipal)
	theirs := handlerAs(t, service, otherTestPrincipal)

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

func TestEachPrincipalGetsItsOwnPrivateConfigFile(t *testing.T) {
	service := isolatedHostService(t)
	mine := handlerAs(t, service, testPrincipal)
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
	if strings.Contains(path, testPrincipal.Subject) {
		t.Fatalf("the principal's subject leaked into the path: %q", path)
	}
	if service.forPrincipal(testPrincipal).Runner.Hosts.UserPath != path {
		t.Fatal("the scoped runner does not name the caller's own configuration")
	}
	if service.hostConfigPath(otherTestPrincipal) == path {
		t.Fatal("two principals resolved to one configuration")
	}
}

func TestForPrincipalFailsClosedWithoutAHostsDirectory(t *testing.T) {
	ssh, _, commandLog := fakeSSH(t)
	service := Service{Runner: sshexec.Runner{SSHBin: ssh, Timeout: 5 * time.Second}, Logs: NewSessionLogs(), Metrics: NewSessionMetrics()}
	if service.Config.HostsDir != "" {
		t.Fatal("test assumes an unconfigured HostsDir")
	}
	scoped := service.forPrincipal(testPrincipal)
	if _, _, err := scoped.Runner.RunOutput(context.Background(), "delta", nil, "true"); apierr.For(err).Code != "ssh_host_not_found" {
		t.Fatalf("an unconfigured HostsDir did not fail closed: %v", err)
	}
	if _, statErr := os.Stat(commandLog); statErr == nil {
		t.Fatal("a scoped runner without isolation ran a remote command")
	}
}

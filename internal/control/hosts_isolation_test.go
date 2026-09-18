// Every caller has their own host configuration and nothing else.
// One principal's aliases and login keys are invisible to another, and each gets its own private config file.
//
//	handlerAs
//	hostRequest
//	hostNames
//	isolatedHostService
//	sshRefusingAuthentication
//	uploadedKey
//	Test*
package control

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
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
	"golang.org/x/crypto/ssh"
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
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	response := testutil.Serve(handler, request)
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

func sshRefusingAuthentication(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "ssh")
	script := `#!/bin/sh
if [ "$1" = "-G" ]; then
  printf 'host %s\nhostname %s.example\nuser tester\nport 22\n' "$2" "$2"
  exit 0
fi
echo "tester@delta: Permission denied (publickey,keyboard-interactive)." >&2
exit 255
`
	writeScript(t, path, script)
	return path
}

func uploadedKey(t *testing.T, handler http.Handler, name string) sshconfig.Key {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	testutil.Check(t, err)
	block, err := ssh.MarshalPrivateKey(private, "")
	testutil.Check(t, err)
	body, err := json.Marshal(addKeyRequest{Name: name, PrivateKey: string(pem.EncodeToMemory(block))})
	testutil.Check(t, err)
	response := hostRequest(t, handler, http.MethodPost, "/api/v1/keys", string(body))
	if response.Code != http.StatusCreated {
		t.Fatalf("upload = %d %s", response.Code, response.Body.String())
	}
	var key sshconfig.Key
	testutil.Check(t, json.Unmarshal(response.Body.Bytes(), &key))
	return key
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

func TestLoginKeysAreOwnedPerPrincipalAndFollowTheHost(t *testing.T) {
	service := isolatedHostService(t)
	mine := handlerAs(t, service, testPrincipal)
	theirs := handlerAs(t, service, otherTestPrincipal)
	key := uploadedKey(t, mine, "delta-key")
	if key.Type != "ssh-ed25519" || !strings.HasPrefix(key.Fingerprint, "SHA256:") {
		t.Fatalf("upload did not describe the key: %+v", key)
	}
	if body := hostRequest(t, theirs, http.MethodGet, "/api/v1/keys", "").Body.String(); strings.Contains(body, "delta-key") {
		t.Fatalf("another principal was shown this caller's key: %s", body)
	}
	if code := hostRequest(t, theirs, http.MethodPost, "/api/v1/ssh", `{"name":"delta","command":"ssh me@login.example.edu","key":"delta-key"}`).Code; code != http.StatusNotFound {
		t.Fatalf("another principal assigned a key that is not theirs: %d", code)
	}

	created := hostRequest(t, mine, http.MethodPost, "/api/v1/ssh", `{"name":"delta","command":"ssh me@login.example.edu","key":"delta-key"}`)
	if created.Code != http.StatusCreated {
		t.Fatalf("add with key = %d %s", created.Code, created.Body.String())
	}
	var host sshconfig.Host
	testutil.Check(t, json.Unmarshal(created.Body.Bytes(), &host))
	keyDir := service.forPrincipal(testPrincipal).Runner.Hosts.KeyDir
	if host.Key != "delta-key" || host.IdentityFile != filepath.Join(keyDir, "delta-key") || !strings.Contains(strings.Join(host.ExtraDirectives, "\n"), "IdentitiesOnly yes") {
		t.Fatalf("the host does not carry its key: %+v", host)
	}
	if info, err := os.Stat(host.IdentityFile); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("stored key is not private: %v %v", info, err)
	}

	updated := hostRequest(t, mine, http.MethodPut, "/api/v1/ssh/delta", `{"command":"ssh me@login.example.edu","key":""}`)
	var edited sshconfig.Host
	testutil.Check(t, json.Unmarshal(updated.Body.Bytes(), &edited))
	if updated.Code != http.StatusOK || edited.Key != "" || edited.IdentityFile != "" || len(edited.ExtraDirectives) != 0 {
		t.Fatalf("an update without a key kept the old one: %d %+v", updated.Code, edited)
	}
	if code := hostRequest(t, mine, http.MethodPut, "/api/v1/ssh/delta", `{"command":"ssh me@login.example.edu","key":"delta-key"}`).Code; code != http.StatusOK {
		t.Fatalf("reassign = %d", code)
	}
	if code := hostRequest(t, mine, http.MethodDelete, "/api/v1/keys/delta-key", "").Code; code != http.StatusOK {
		t.Fatalf("delete key = %d", code)
	}
	list := hostRequest(t, mine, http.MethodGet, "/api/v1/ssh", "")
	if strings.Contains(list.Body.String(), "delta-key") || strings.Contains(list.Body.String(), "Identit") {
		t.Fatalf("deleting the key left the host naming it: %s", list.Body.String())
	}
	if body := hostRequest(t, mine, http.MethodGet, "/api/v1/keys", "").Body.String(); body != `{"keys":[]}`+"\n" && body != `{"keys":[]}` {
		t.Fatalf("keys after delete = %s", body)
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

func TestHostTestReportsAnOwedLoginAsOKFalseWithoutFailingTheCall(t *testing.T) {
	service := Service{Runner: sshexec.Runner{SSHBin: sshRefusingAuthentication(t), Timeout: 5 * time.Second}, Logs: NewSessionLogs(), Metrics: NewSessionMetrics()}

	result, err := service.testHost(context.Background(), "delta")

	if err != nil {
		t.Fatalf("a host that only owes a login is a reportable state, not a failed call: %v", err)
	}
	if result.OK {
		t.Error("a host that refused authentication reported ok")
	}
	if !strings.Contains(result.Message, "interactive login") {
		t.Errorf("got %q, want the interactive-login guidance", result.Message)
	}
}

// SSH service tests protect the canonical route surface, principal isolation, key secrecy, host/key atomicity,
// and sanitized live-probe responses. Lower-level OpenSSH execution and credential-file durability are tested by
// their internal packages; these cases exercise only the feature composition.
package ssh

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cyber-shuttle/cs-control/internal/db"
	"github.com/cyber-shuttle/cs-control/internal/router"
	"github.com/cyber-shuttle/cs-control/internal/security"
	internalssh "github.com/cyber-shuttle/cs-control/internal/ssh"
	"github.com/cyber-shuttle/cs-control/internal/testutil"
	cryptossh "golang.org/x/crypto/ssh"
)

var (
	testPrincipal      = security.Principal{Subject: "test-owner", Tenant: "test-tenant"}
	otherTestPrincipal = security.Principal{Subject: "other-owner", Tenant: "test-tenant"}
)

func testKey(t *testing.T, passphrase string) []byte {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	testutil.Check(t, err)
	var block *pem.Block
	if passphrase == "" {
		block, err = cryptossh.MarshalPrivateKey(private, "test")
	} else {
		block, err = cryptossh.MarshalPrivateKeyWithPassphrase(private, "test", []byte(passphrase))
	}
	testutil.Check(t, err)
	return pem.EncodeToMemory(block)
}

func isolatedService(t *testing.T) *Service {
	t.Helper()
	dir := t.TempDir()
	principalDir := filepath.Join(dir, "hosts")
	database, err := db.Open(testutil.Database(t), dir, Schema)
	testutil.Check(t, err)
	service, err := NewService(database, internalssh.Configurations{Dir: principalDir}, internalssh.NewControlManager())
	testutil.Check(t, err)
	t.Cleanup(func() {
		service.Control.Close()
		testutil.Check(t, database.Close())
	})
	return service
}

func serviceHandler(t *testing.T, service *Service) http.Handler {
	t.Helper()
	handler, err := router.New(service.Routes())
	testutil.Check(t, err)
	return handler
}

func requestAs(principal security.Principal, method, path string, body []byte) *http.Request {
	request := httptest.NewRequest(method, path, bytes.NewReader(body))
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	return request.WithContext(security.WithPrincipal(request.Context(), principal))
}

func TestSSHResourcesArePrincipalScopedAndNeverReturnPrivateKeys(t *testing.T) {
	service := isolatedService(t)
	handler := serviceHandler(t, service)
	private := testKey(t, "secret")
	keyBody, err := json.Marshal(sshKeyRequest{Name: "delta-key", PrivateKey: string(private)})
	testutil.Check(t, err)
	createdKey := testutil.Serve(handler, requestAs(testPrincipal, http.MethodPost, "/api/v1/ssh/keys", keyBody))
	if createdKey.Code != http.StatusCreated || strings.Contains(createdKey.Body.String(), "PRIVATE KEY") || !strings.Contains(createdKey.Body.String(), `"fingerprint":"SHA256:`) {
		t.Fatalf("key create = %d %s", createdKey.Code, createdKey.Body.String())
	}
	replacement, err := json.Marshal(sshKeyRequest{Name: "delta-key", PrivateKey: string(testKey(t, ""))})
	testutil.Check(t, err)
	if response := testutil.Serve(handler, requestAs(testPrincipal, http.MethodPost, "/api/v1/ssh/keys", replacement)); response.Code != http.StatusConflict {
		t.Fatalf("key replacement = %d %s", response.Code, response.Body.String())
	}
	if response := testutil.Serve(handler, requestAs(otherTestPrincipal, http.MethodGet, "/api/v1/ssh/keys", nil)); strings.Contains(response.Body.String(), "delta-key") {
		t.Fatalf("another principal saw the key: %s", response.Body.String())
	}
	if response := testutil.Serve(handler, requestAs(otherTestPrincipal, http.MethodPost, "/api/v1/ssh/hosts", []byte(`{"name":"delta","command":"ssh me@login.example.edu","key":"delta-key"}`))); response.Code != http.StatusNotFound {
		t.Fatalf("another principal assigned the key: %d %s", response.Code, response.Body.String())
	}

	createdHost := testutil.Serve(handler, requestAs(testPrincipal, http.MethodPost, "/api/v1/ssh/hosts", []byte(`{"name":"delta","command":"ssh me@login.example.edu","key":"delta-key"}`)))
	if createdHost.Code != http.StatusCreated || !strings.Contains(createdHost.Body.String(), `"managed":true`) {
		t.Fatalf("host create = %d %s", createdHost.Code, createdHost.Body.String())
	}
	if response := testutil.Serve(handler, requestAs(otherTestPrincipal, http.MethodGet, "/api/v1/ssh/hosts", nil)); strings.Contains(response.Body.String(), "delta") {
		t.Fatalf("another principal saw the host: %s", response.Body.String())
	}
	updated := testutil.Serve(handler, requestAs(testPrincipal, http.MethodPut, "/api/v1/ssh/hosts/delta", []byte(`{"command":"ssh -p 2222 me@login2.example.edu","key":"delta-key"}`)))
	if updated.Code != http.StatusOK || !strings.Contains(updated.Body.String(), `"hostname":"login2.example.edu"`) || !strings.Contains(updated.Body.String(), `"port":2222`) {
		t.Fatalf("host update = %d %s", updated.Code, updated.Body.String())
	}
	deleted := testutil.Serve(handler, requestAs(testPrincipal, http.MethodDelete, "/api/v1/ssh/keys/delta-key", nil))
	if deleted.Code != http.StatusNoContent || deleted.Body.Len() != 0 {
		t.Fatalf("key delete = %d %s", deleted.Code, deleted.Body.String())
	}
	listed := testutil.Serve(handler, requestAs(testPrincipal, http.MethodGet, "/api/v1/ssh/hosts", nil))
	if strings.Contains(listed.Body.String(), "delta-key") || strings.Contains(listed.Body.String(), "identityFile") {
		t.Fatalf("key deletion left a host reference: %s", listed.Body.String())
	}
	if _, err := os.Stat(service.Store.sshPath(security.PrincipalDirName(testPrincipal), "delta-key")); !os.IsNotExist(err) {
		t.Fatalf("key file survived deletion: %v", err)
	}
	if response := testutil.Serve(handler, requestAs(testPrincipal, http.MethodDelete, "/api/v1/ssh/hosts/delta", nil)); response.Code != http.StatusNoContent || response.Body.Len() != 0 {
		t.Fatalf("host delete = %d %s", response.Code, response.Body.String())
	}
	if response := testutil.Serve(handler, requestAs(testPrincipal, http.MethodGet, "/api/v1/ssh/hosts", nil)); strings.Contains(response.Body.String(), `"name":"delta"`) {
		t.Fatalf("deleted host remains: %s", response.Body.String())
	}

	const identity = "~/.ssh/id_ed25519"
	createdHost = testutil.Serve(handler, requestAs(testPrincipal, http.MethodPost, "/api/v1/ssh/hosts", []byte(`{"name":"raw","command":"ssh -i ~/.ssh/id_ed25519 me@raw.example.edu"}`)))
	listed = testutil.Serve(handler, requestAs(testPrincipal, http.MethodGet, "/api/v1/ssh/hosts", nil))
	hosts, err := service.Store.loadHosts(security.PrincipalDirName(testPrincipal))
	testutil.Check(t, err)
	config, err := os.ReadFile(service.Configs.ConfigPath(testPrincipal))
	testutil.Check(t, err)
	if createdHost.Code != http.StatusCreated || !strings.Contains(createdHost.Body.String(), identity) || !strings.Contains(listed.Body.String(), identity) || len(hosts) != 1 || hosts[0].IdentityFile != identity || !strings.Contains(string(config), "identityfile "+identity) {
		t.Fatalf("raw identity did not survive host persistence: create=%d %s list=%s hosts=%+v config=%s", createdHost.Code, createdHost.Body.String(), listed.Body.String(), hosts, config)
	}
}

func TestConcurrentHostAssignmentAndKeyDeletionLeaveNoReference(t *testing.T) {
	service := isolatedService(t)
	private := testKey(t, "")
	for index := range 10 {
		name := "key-" + string(rune('a'+index))
		_, err := service.writeSSHKey(testPrincipal, name, private)
		testutil.Check(t, err)
		start := make(chan struct{})
		var assigned hostEntry
		var assignedErr, deletedErr error
		var wait sync.WaitGroup
		wait.Add(2)
		go func() {
			defer wait.Done()
			<-start
			assigned, assignedErr = service.addHost(testPrincipal, addHostRequest{Name: name, Command: "ssh login.example.edu", Key: name})
		}()
		go func() {
			defer wait.Done()
			<-start
			deletedErr = service.deleteSSHKey(testPrincipal, name)
		}()
		close(start)
		wait.Wait()
		testutil.Check(t, deletedErr)
		if assignedErr != nil && !errors.Is(assignedErr, errSSHKeyNotFound) {
			t.Fatalf("host assignment = %v", assignedErr)
		}
		if assignedErr == nil && (assigned.Key != "" && assigned.Key != name) {
			t.Fatalf("unexpected assigned host: %+v", assigned)
		}
		hosts, err := service.Store.loadHosts(security.PrincipalDirName(testPrincipal))
		testutil.Check(t, err)
		for _, host := range hosts {
			if host.Name == name && (host.Key != "" || host.IdentityFile != "") {
				t.Fatalf("deleted %s remains assigned: %+v", name, host)
			}
		}
	}
}

func TestSSHAuthAndProbeExposeOnlyCanonicalSanitizedResponses(t *testing.T) {
	service := isolatedService(t)
	handler := serviceHandler(t, service)
	if response := testutil.Serve(handler, httptest.NewRequest(http.MethodGet, "/api/v1/ssh/hosts/delta/auth", nil)); response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated auth = %d", response.Code)
	}
	if response := testutil.Serve(handler, requestAs(testPrincipal, http.MethodGet, "/api/v1/ssh/hosts/delta/auth", nil)); response.Code != http.StatusUpgradeRequired {
		t.Fatalf("non-WebSocket auth = %d", response.Code)
	}
	dir := t.TempDir()
	configPath := service.Configs.ConfigPath(testPrincipal)
	testutil.Check(t, security.EnsurePrivateDir(filepath.Dir(configPath)))
	testutil.Check(t, os.WriteFile(configPath, []byte("Host delta broken\n"), 0o600))
	sshBin := filepath.Join(dir, "ssh")
	testutil.WriteScript(t, sshBin, `#!/bin/sh
case " $* " in
  *" -G "*)
    for alias do :; done
    printf 'host %s\nhostname %s.example\n' "$alias" "$alias"
    exit 0
    ;;
esac
case " $* " in
  *" broken "*) echo 'secret remote diagnostic' >&2; exit 1 ;;
esac
echo 'Permission denied (publickey,keyboard-interactive).' >&2
exit 255
`)
	service.Configs.Template = internalssh.Runner{SSHBin: sshBin, Timeout: time.Second}
	handler = serviceHandler(t, service)
	interactive := testutil.Serve(handler, requestAs(testPrincipal, http.MethodPost, "/api/v1/ssh/hosts/delta/test", nil))
	if interactive.Code != http.StatusOK || !strings.Contains(interactive.Body.String(), "interactive login") {
		t.Fatalf("interactive probe = %d %s", interactive.Code, interactive.Body.String())
	}
	failed := testutil.Serve(handler, requestAs(testPrincipal, http.MethodPost, "/api/v1/ssh/hosts/broken/test", nil))
	if failed.Code != http.StatusOK || !strings.Contains(failed.Body.String(), "The SSH connection failed.") || strings.Contains(failed.Body.String(), "secret remote diagnostic") {
		t.Fatalf("failed probe leaked output: %d %s", failed.Code, failed.Body.String())
	}
}

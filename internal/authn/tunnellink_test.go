// Tests the Dev Tunnels link: the full device-flow start/poll cycle, the sealed file on disk, Microsoft
// refresh on use, and tunnel_link_required with nothing linked.
//
//	newTestLinkBroker
//	TestLinkBrokerGitHubStartPollLinksAndTheFileIsSealed
//	TestLinkBrokerCredentialRequiresALink, TestLinkBrokerRefreshesAnExpiringMicrosoftLinkOnUse
package authn

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cyber-shuttle/cs-control/internal/apierr"
	"github.com/cyber-shuttle/cs-control/internal/testutil"
)

func newTestLinkBroker(t *testing.T) (*LinkBroker, string) {
	t.Helper()
	dir := t.TempDir()
	hostsDir := filepath.Join(dir, "hosts")
	var key [32]byte
	copy(key[:], strings.Repeat("k", 32))
	broker, err := NewLinkBroker(hostsDir, &key, nil)
	testutil.Check(t, err)
	return broker, hostsDir
}

func TestLinkBrokerGitHubStartPollLinksAndTheFileIsSealed(t *testing.T) {
	broker, hostsDir := newTestLinkBroker(t)
	principal := Principal{Subject: "owner", Tenant: "custos"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login/device/code":
			_, _ = w.Write([]byte(`{"device_code":"the-device-code","user_code":"ABCD-EFGH","verification_uri":"https://github.com/login/device","expires_in":900,"interval":0}`))
		case "/login/oauth/access_token":
			_, _ = w.Write([]byte(`{"access_token":"gho_the_token"}`))
		case "/user":
			writeTestJSON(t, w, map[string]string{"login": "octocat"})
		default:
			t.Errorf("unexpected request %s", r.URL)
		}
	}))
	defer server.Close()
	broker.providers["github"] = tunnelLinkProvider{name: "github", scheme: "github", deviceEndpoint: server.URL + "/login/device/code", tokenEndpoint: server.URL + "/login/oauth/access_token", userEndpoint: server.URL + "/user", clientID: devTunnelsGitHubClientID}
	broker.client = server.Client()
	now := time.Now()
	broker.now = func() time.Time { return now }

	start, err := broker.Start(context.Background(), principal, "github")
	testutil.Check(t, err)
	testutil.Equal(t, start.UserCode, "ABCD-EFGH", "user code")

	now = now.Add(10 * time.Second)
	poll, err := broker.Poll(context.Background(), principal, start.Handle)
	testutil.Check(t, err)
	if !poll.Status.Linked || poll.Status.Provider != "github" || poll.Status.Account != "octocat" {
		t.Fatalf("poll = %#v", poll)
	}

	path := filepath.Join(hostsDir, PrincipalDirName(principal), tunnelLinkFileName)
	sealed, err := os.ReadFile(path)
	testutil.Check(t, err)
	if strings.Contains(string(sealed), "gho_the_token") {
		t.Fatal("the sealed file holds the access token in the clear")
	}

	status, err := broker.Status(principal)
	testutil.Check(t, err)
	if !status.Linked || status.Account != "octocat" {
		t.Fatalf("status = %#v", status)
	}

	testutil.Check(t, broker.Delete(principal))
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("sealed file survived Delete: %v", err)
	}
}

func TestLinkBrokerCredentialRequiresALink(t *testing.T) {
	broker, _ := newTestLinkBroker(t)
	principal := Principal{Subject: "owner", Tenant: "custos"}
	_, err := broker.Credential(context.Background(), principal)
	api := apierr.For(err)
	if err == nil || api.Code != "tunnel_link_required" || api.Status != http.StatusConflict {
		t.Fatalf("error = %v", err)
	}
}

func TestLinkBrokerRefreshesAnExpiringMicrosoftLinkOnUse(t *testing.T) {
	broker, _ := newTestLinkBroker(t)
	principal := Principal{Subject: "owner", Tenant: "custos"}
	refreshCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		refreshCalls++
		testutil.Check(t, r.ParseForm())
		if r.Form.Get("grant_type") != "refresh_token" || r.Form.Get("refresh_token") != "old-refresh" {
			t.Fatalf("refresh request = %v", r.Form)
		}
		_, _ = w.Write([]byte(`{"access_token":"new-access","refresh_token":"new-refresh","expires_in":3600}`))
	}))
	defer server.Close()
	broker.providers["microsoft"] = tunnelLinkProvider{name: "microsoft", scheme: SchemeBearer, tokenEndpoint: server.URL, clientID: devTunnelsNativeClientID, scope: tunnelLinkDeviceScope}
	broker.client = server.Client()
	fixed := time.Now()
	broker.now = func() time.Time { return fixed }
	testutil.Check(t, broker.saveLink(principal, tunnelLink{
		Provider: "microsoft", Scheme: SchemeBearer, AccessToken: "old-access", RefreshToken: "old-refresh",
		ExpiresAt: fixed.Add(time.Minute), Account: "someone@outlook.com", LinkedAt: fixed,
	}))

	credential, err := broker.Credential(context.Background(), principal)
	testutil.Check(t, err)
	testutil.Equal(t, credential, TunnelCredential{Scheme: SchemeBearer, Token: "new-access"}, "refreshed credential")
	testutil.Equal(t, refreshCalls, 1, "refresh calls")

	link, ok, err := broker.loadLink(principal)
	testutil.Check(t, err)
	if !ok || link.RefreshToken != "new-refresh" {
		t.Fatalf("stored link after refresh = %#v", link)
	}
}

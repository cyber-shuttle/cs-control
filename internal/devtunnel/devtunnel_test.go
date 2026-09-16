// Tests Create, Get, and the URL and redirect policy against a fake Dev Tunnels management service.
//
//	realisticTunnelResponse, testClient
//	TestDevTunnelCreateRequestsScopedTokensAndAcceptsAdditiveFields, TestDevTunnelRejectsMalformedUsedFields,
//	TestDevTunnelURLAndRedirectValidation, TestSafeErrorTruncatesWithoutSplittingARune
package devtunnel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/cyber-shuttle/cs-control/internal/testutil"
)

func realisticTunnelResponse(id, hostToken, connectToken string) string {
	created := time.Now().UTC().Truncate(time.Second)
	expires := created.Add(time.Hour)
	return fmt.Sprintf(`{
		"tunnelId":%q,
		"clusterId":"use",
		"accessTokens":{"host manage:ports":%q,"connect":%q},
		"created":%q,
		"expiration":%q,
		"customExpiration":3600,
		"endpoints":[{"connectionMode":"TunnelRelay","hostId":"session-host","portUriFormat":"https://{port}.use.devtunnels.ms/","portSshCommandFormat":"ssh tunnel@{port}.use.devtunnels.ms","sshGatewayPublicKey":"ignored additive field"}],
		"ports":[],
		"futureField":"ignored"
	}`, id, hostToken, connectToken, created.Format(time.RFC3339), expires.Format(time.RFC3339))
}

func testClient(t *testing.T, baseURL string, client *http.Client) *client {
	t.Helper()
	base, err := ParseBaseURL(baseURL, "Dev Tunnels base URL")
	testutil.Check(t, err)
	return newClientForBase(base, client)
}

func TestDevTunnelCreateRequestsScopedTokensAndAcceptsAdditiveFields(t *testing.T) {
	const id = "s-123456789abc-g-0123456789abcdef"
	var body map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.Header.Get("Authorization") != "Bearer oauth" || r.Header.Get("If-None-Match") != "*" {
			t.Fatalf("request = %s headers=%v", r.Method, r.Header)
		}
		if got := r.URL.Query()["tokenScopes"]; len(got) != 2 || got[0] != "host manage:ports" || got[1] != "connect" {
			t.Fatalf("token scopes = %#v", got)
		}
		testutil.Check(t, json.NewDecoder(r.Body).Decode(&body))
		_, _ = io.WriteString(w, realisticTunnelResponse(id, "host-secret", "connect-secret"))
	}))
	defer server.Close()
	record, err := testClient(t, server.URL, server.Client()).Create(context.Background(), CreateRequest{OAuthToken: "oauth", TunnelID: id, DurationSeconds: 3600})
	testutil.Check(t, err)
	if record.ID != id || record.ClusterID != "use" || record.HostToken != "host-secret" || record.ConnectToken != "connect-secret" || record.ExpiresAt.IsZero() {
		t.Fatalf("record = %#v", record)
	}
	if body["tunnelId"] != id || body["customExpiration"] != float64(3600) {
		t.Fatalf("body = %#v", body)
	}
}

func TestDevTunnelRejectsMalformedUsedFields(t *testing.T) {
	expires := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	cases := map[string]string{
		"wrong identity":         `{"tunnelId":"other-tunnel","clusterId":"use","expiration":"` + expires + `"}`,
		"missing expiration":     `{"tunnelId":"tunnel-123","clusterId":"use"}`,
		"duplicate port":         `{"tunnelId":"tunnel-123","clusterId":"use","expiration":"` + expires + `","ports":[{"portNumber":31001,"protocol":"http"},{"portNumber":31001,"protocol":"http"}]}`,
		"invalid forwarding URI": `{"tunnelId":"tunnel-123","clusterId":"use","expiration":"` + expires + `","ports":[{"portNumber":31001,"protocol":"http","description":"cybershuttle-control","portForwardingUris":["https://evil.example/"]}]}`,
	}
	for name, response := range cases {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, response) }))
			defer server.Close()
			if _, err := testClient(t, server.URL, server.Client()).Get(context.Background(), GetRequest{AccessToken: "connect", TunnelID: "tunnel-123", ClusterID: "use"}); err == nil {
				t.Fatal("malformed response accepted")
			}
		})
	}
}

func TestDevTunnelURLAndRedirectValidation(t *testing.T) {
	manager, err := NewClient("https://global.rel.tunnels.api.visualstudio.com/", nil)
	testutil.Check(t, err)
	got := manager.tunnelURL("tunnel-123", "use", false, true)
	if got.Host != "use.rel.tunnels.api.visualstudio.com" || got.Query().Get("includePorts") != "true" {
		t.Fatalf("URL = %s", got)
	}
	from, _ := url.Parse("https://global.rel.tunnels.api.visualstudio.com/tunnels/x")
	to, _ := url.Parse("https://use.rel.tunnels.api.visualstudio.com/tunnels/x")
	if !safeRedirect(from, to) {
		t.Fatal("safe cluster redirect rejected")
	}
	to, _ = url.Parse("https://evil.example/tunnels/x")
	if safeRedirect(from, to) {
		t.Fatal("hostile redirect accepted")
	}
}

func TestSafeErrorTruncatesWithoutSplittingARune(t *testing.T) {
	// Place a multi-byte rune straddling the truncation boundary, one byte before it.
	filler := strings.Repeat("a", maxDevTunnelError-len(": ")-1)
	err := safeError("", errors.New(filler+"€"))
	if !utf8.ValidString(err.Error()) {
		t.Fatalf("truncated error message split a rune: %q", err.Error())
	}
}

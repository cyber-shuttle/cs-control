package devtunnel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/cyber-shuttle/cs-control/internal/httpx"
)

func testClient(t *testing.T, baseURL string, client *http.Client) *Client {
	t.Helper()
	base, err := httpx.ParseBaseURL(baseURL, "Dev Tunnels base URL")
	if err != nil {
		t.Fatal(err)
	}
	return newClientForBase(base, client)
}

func TestDevTunnelCreateRequestsScopedTokensAndAcceptsAdditiveFields(t *testing.T) {
	const id = "rt-123456789abc-g-0123456789abcdef"
	var body map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.Header.Get("Authorization") != "Bearer oauth" || r.Header.Get("If-Not-Match") != "*" {
			t.Fatalf("request = %s headers=%v", r.Method, r.Header)
		}
		if got := r.URL.Query()["tokenScopes"]; len(got) != 2 || got[0] != "host manage:ports" || got[1] != "connect" {
			t.Fatalf("token scopes = %#v", got)
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		_, _ = io.WriteString(w, realisticTunnelResponse(id, "host-secret", "connect-secret"))
	}))
	defer server.Close()
	record, err := testClient(t, server.URL, server.Client()).Create(context.Background(), CreateRequest{OAuthToken: "oauth", TunnelID: id, DurationSeconds: 3600})
	if err != nil {
		t.Fatal(err)
	}
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
	if err != nil {
		t.Fatal(err)
	}
	got := manager.tunnelURL("tunnel-123", "use", false, true)
	if got.Host != "use.rel.tunnels.api.visualstudio.com" || got.Query().Get("includePorts") != "true" {
		t.Fatalf("URL = %s", got)
	}
	from, _ := url.Parse("https://global.rel.tunnels.api.visualstudio.com/tunnels/x")
	to, _ := url.Parse("https://use.rel.tunnels.api.visualstudio.com/tunnels/x")
	if !SafeRedirect(from, to) {
		t.Fatal("safe cluster redirect rejected")
	}
	to, _ = url.Parse("https://evil.example/tunnels/x")
	if SafeRedirect(from, to) {
		t.Fatal("hostile redirect accepted")
	}
}

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
		"endpoints":[{"connectionMode":"TunnelRelay","hostId":"allocation-host","portUriFormat":"https://{port}.use.devtunnels.ms/","portSshCommandFormat":"ssh tunnel@{port}.use.devtunnels.ms","sshGatewayPublicKey":"ignored additive field"}],
		"ports":[],
		"futureField":"ignored"
	}`, id, hostToken, connectToken, created.Format(time.RFC3339), expires.Format(time.RFC3339))
}

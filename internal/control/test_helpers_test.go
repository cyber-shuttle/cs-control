package control

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cyber-shuttle/cs-control/internal/authn"
	"github.com/cyber-shuttle/cs-control/internal/devtunnel"
)

const testConnectToken = "test-connect-token"
const testHostToken = "test-host-token"
const testJupyterToken = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

var testPrincipal = authn.Principal{Subject: "test-owner", Tenant: "test-tenant"}

const testIdentityToken = "signed-test-identity-token"

// browserWebSocketProtocols is the subprotocol list a browser sends on a
// control WebSocket: the protocol name plus both credential channels.

type oauthValidatorFunc func(context.Context, string) (authn.Principal, error)

func (f oauthValidatorFunc) Validate(ctx context.Context, credentials authn.OAuthCredentials) (authn.Principal, error) {
	return f(ctx, credentials.AccessToken)
}

func reconciledList(ctx context.Context, service Service) ([]Runtime, error) {
	if err := service.ReconcileAll(ctx); err != nil {
		return nil, err
	}
	return service.ListCached()
}

func reconciledGet(ctx context.Context, service Service, id string) (*Runtime, error) {
	if err := service.ReconcileAll(ctx); err != nil {
		return nil, err
	}
	return service.GetCached(id)
}

type testTunnelManager struct {
	mu          sync.Mutex
	creates     []devtunnel.CreateRequest
	gets        []devtunnel.GetRequest
	deletes     []devtunnel.DeleteRequest
	generation  string
	createErr   error
	getResponse *devtunnel.Record
	expiresAt   time.Time
}

func (m *testTunnelManager) Create(_ context.Context, request devtunnel.CreateRequest) (devtunnel.Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.creates = append(m.creates, request)
	if m.createErr != nil {
		return devtunnel.Record{}, m.createErr
	}
	if marker := strings.LastIndex(request.TunnelID, "-g-"); marker >= 0 {
		m.generation = request.TunnelID[marker+1:]
	}
	m.expiresAt = time.Now().UTC().Add(time.Duration(request.DurationSeconds) * time.Second)
	return devtunnel.Record{ID: request.TunnelID, ClusterID: "use", ConnectToken: testConnectToken, HostToken: testHostToken, ExpiresAt: m.expiresAt}, nil
}

func (m *testTunnelManager) Get(_ context.Context, request devtunnel.GetRequest) (devtunnel.Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.gets = append(m.gets, request)
	if m.getResponse != nil {
		return *m.getResponse, nil
	}
	return devtunnel.Record{ID: request.TunnelID, ClusterID: request.ClusterID, ExpiresAt: m.expiresAt, Ports: []devtunnel.PortRecord{{PortNumber: 31001, Protocol: "http", Description: "cybershuttle-control", PortForwardingURIs: []string{"https://31001.use.devtunnels.ms"}}}}, nil
}

func (m *testTunnelManager) Delete(_ context.Context, request devtunnel.DeleteRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deletes = append(m.deletes, request)
	return nil
}

func testTunnelContext() context.Context {
	return testTunnelContextFrom(context.Background())
}

func testTunnelContextFrom(ctx context.Context) context.Context {
	ctx = authn.WithPrincipal(ctx, testPrincipal)
	return authn.WithTunnelAuthorization(ctx, authn.TunnelAuthorization{OAuthToken: "test-oauth-token", Principal: testPrincipal})
}

func configureTestTunnel(t *testing.T, service *Service) *testTunnelManager {
	t.Helper()
	if service.Logs == nil {
		service.Logs = NewRuntimeLogs()
	}
	manager := &testTunnelManager{}
	service.Tunnels = manager
	service.Credentials = CredentialStore{Dir: t.TempDir() + "/credentials"}
	return manager
}

func testCredential() GenerationCredential {
	return GenerationCredential{ConnectToken: testConnectToken, JupyterToken: testJupyterToken}
}

// eventually polls cond until it holds or the timeout expires. One helper for every
// wait-for-a-side-effect test, so the polling shape is written once.
func eventually(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// nonEmptyFile is the condition almost every such test waits on: a fake wrote its marker.
func nonEmptyFile(path string) func() bool {
	return func() bool {
		data, err := os.ReadFile(path)
		return err == nil && len(data) > 0
	}
}

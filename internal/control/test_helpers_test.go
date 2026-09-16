// Shared fixtures every test in this package draws on: test tokens and a fake Dev Tunnels manager.
// It also holds the tunnel-authorized context every request needs.
// The rest are small polling and stub-script helpers.
//
//	testConnectToken, testHostToken, testJupyterToken, testPrincipal, testIdentityToken
//	noopAuth, ServeWebSocket
//	oauthValidatorFunc, Validate
//	reconciledList
//	reconciledGet
//	testTunnelManager, Create, Get, Delete
//	testTunnelContextFrom
//	testTunnelContext
//	registerTestHosts
//	configureTestTunnel
//	eventually
//	waitForFile
//	writeScript
//	credential
//	setTestSessionMetadata
//	putSessions
//	pendingSession
package control

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/cyber-shuttle/cs-control/internal/authn"
	"github.com/cyber-shuttle/cs-control/internal/credentialstore"
	"github.com/cyber-shuttle/cs-control/internal/devtunnel"
	"github.com/cyber-shuttle/cs-control/internal/safeio"
	"github.com/cyber-shuttle/cs-control/internal/sshexec"
	"github.com/cyber-shuttle/cs-control/internal/testutil"
)

const testConnectToken = "test-connect-token"
const testHostToken = "test-host-token"
const testJupyterToken = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

var testPrincipal = authn.Principal{Subject: "test-owner", Tenant: "test-tenant"}

const testIdentityToken = "signed-test-identity-token"

type noopAuth struct{}

func (noopAuth) ServeWebSocket(http.ResponseWriter, *http.Request, string, sshexec.Runner) {}

type oauthValidatorFunc func(context.Context, string) (authn.Principal, error)

func (f oauthValidatorFunc) Validate(ctx context.Context, credentials authn.OAuthCredentials) (authn.Principal, error) {
	return f(ctx, credentials.AccessToken)
}

func reconciledList(ctx context.Context, service Service) ([]Session, error) {
	if err := service.reconcileAll(ctx); err != nil {
		return nil, err
	}
	return service.loadSessions()
}

func reconciledGet(ctx context.Context, service Service, id string) (*Session, error) {
	if err := service.reconcileAll(ctx); err != nil {
		return nil, err
	}
	return service.loadSession(id)
}

type testTunnelManager struct {
	mu            sync.Mutex
	creates       []devtunnel.CreateRequest
	gets          []devtunnel.GetRequest
	deletes       []devtunnel.DeleteRequest
	createErr     error
	deleteErr     error
	getResponse   *devtunnel.Record
	expiresAt     time.Time
	createStarted chan struct{}
	createBlock   chan struct{}
}

func (m *testTunnelManager) Create(_ context.Context, request devtunnel.CreateRequest) (devtunnel.Record, error) {
	if m.createStarted != nil {
		close(m.createStarted)
	}
	if m.createBlock != nil {
		<-m.createBlock
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.creates = append(m.creates, request)
	if m.createErr != nil {
		return devtunnel.Record{}, m.createErr
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
	return devtunnel.Record{ID: request.TunnelID, ClusterID: request.ClusterID, ExpiresAt: m.expiresAt, Ports: []devtunnel.PortRecord{{PortNumber: 31001, Protocol: "http", PortForwardingURIs: []string{"https://31001.use.devtunnels.ms"}}}}, nil
}

func (m *testTunnelManager) Delete(_ context.Context, request devtunnel.DeleteRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deletes = append(m.deletes, request)
	return m.deleteErr
}

func testTunnelContextFrom(ctx context.Context) context.Context {
	return authn.WithTunnelAuthorization(ctx, authn.TunnelAuthorization{OAuthToken: "test-oauth-token", Principal: testPrincipal})
}

func testTunnelContext() context.Context {
	return testTunnelContextFrom(context.Background())
}

func registerTestHosts(t *testing.T, service Service, principal authn.Principal, aliases ...string) {
	t.Helper()
	scoped := service.forPrincipal(principal)
	for _, alias := range aliases {
		_, err := scoped.addHost(addHostRequest{Name: alias, Command: "ssh " + alias + ".example.edu"})
		testutil.Check(t, err)
	}
}

func configureTestTunnel(t *testing.T, service *Service) *testTunnelManager {
	t.Helper()
	if service.Logs == nil {
		service.Logs = NewSessionLogs()
	}
	if service.Config.HostsDir == "" {
		service.Config.HostsDir = filepath.Join(t.TempDir(), "hosts")
		registerTestHosts(t, *service, testPrincipal, "delta", "alpha", "beta", "gamma")
	}
	if service.Store.Dir != "" {
		testutil.Check(t, safeio.EnsurePrivateDir(service.Store.Dir))
	}
	manager := &testTunnelManager{}
	service.Tunnels = manager
	service.Credentials = credentialstore.Store{Dir: t.TempDir() + "/credentials"}
	if service.HostPreparations == nil {
		service.HostPreparations = &sync.Map{}
	}
	return manager
}

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

func waitForFile(t *testing.T, path string) {
	t.Helper()
	eventually(t, 3*time.Second, path, func() bool {
		data, err := os.ReadFile(path)
		return err == nil && len(data) > 0
	})
}

func writeScript(t *testing.T, path, body string) {
	t.Helper()
	testutil.Check(t, os.WriteFile(path, []byte(body), 0o700))
}

func credential() credentialstore.Credential {
	return credentialstore.Credential{ConnectToken: testConnectToken, JupyterToken: testJupyterToken}
}

func setTestSessionMetadata(session *Session) {
	if session.Seq == 0 {
		session.Seq = 1
		session.Owner = testPrincipal
		session.Tunnel = tunnelMetadata{ID: session.ID + "-" + strconv.Itoa(session.Seq), ClusterID: "use", ExpiresAt: time.Now().Add(time.Hour)}
	}
}

func putSessions(t *testing.T, service Service, sessions ...Session) {
	t.Helper()
	testutil.Check(t, service.Store.withLock(func(current *state) error {
		for i := range sessions {
			copy := sessions[i]
			setTestSessionMetadata(&copy)
			current.Sessions[copy.ID] = &copy
		}
		return service.Store.save(current)
	}))
}

func pendingSession(id, host, jobID string) Session {
	now := time.Unix(1, 0).UTC()
	return Session{
		sessionResponse: sessionResponse{ID: id, State: "QUEUED", SSHHost: host, Partition: "cpu", RootFolder: ".", Resources: resources{Cores: 1, MemoryMB: 1024, WallMinutes: 60}, CreatedAt: now, UpdatedAt: now},
		JobID:           jobID, JobName: jobName(id, 1), PrivateRoot: "/home/test/.cybershuttle/sessions/" + id, WorkspaceRoot: "/home/test", Owner: testPrincipal,
	}
}

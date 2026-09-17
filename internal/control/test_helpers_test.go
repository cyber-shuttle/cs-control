// Shared fixtures every test in this package draws on: test tokens and a fake Dev Tunnels manager.
// It also holds the tunnel-authorized context every request needs.
// The rest are small polling and stub-script helpers.
//
//	testConnectToken, testHostToken, testJupyterToken, testPrincipal
//	noopAuth, ServeWebSocket
//	oauthValidatorFunc, Validate
//	testLinkBroker, newTestLinkBroker, Status, Start, Poll, Credential, Delete
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

	"github.com/cyber-shuttle/cs-control/internal/apierr"
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

type noopAuth struct{}

func (noopAuth) ServeWebSocket(http.ResponseWriter, *http.Request, string, sshexec.Runner) {}

type oauthValidatorFunc func(context.Context, string) (authn.Principal, error)

func (f oauthValidatorFunc) Validate(ctx context.Context, credentials authn.OAuthCredentials) (authn.Principal, error) {
	return f(ctx, credentials.IDToken)
}

type testLinkBroker struct {
	mu    sync.Mutex
	links map[authn.Principal]authn.TunnelCredential
}

func newTestLinkBroker() *testLinkBroker {
	return &testLinkBroker{links: map[authn.Principal]authn.TunnelCredential{testPrincipal: {Scheme: authn.SchemeBearer, Token: "test-tunnel-link-token"}}}
}

func (b *testLinkBroker) Status(authn.Principal) (authn.TunnelLinkStatus, error) {
	return authn.TunnelLinkStatus{}, nil
}

func (b *testLinkBroker) Start(context.Context, authn.Principal, string) (authn.TunnelLinkStart, error) {
	return authn.TunnelLinkStart{}, nil
}

func (b *testLinkBroker) Poll(_ context.Context, _ authn.Principal, handle string) (authn.TunnelLinkPoll, error) {
	if handle == "pending" {
		return authn.TunnelLinkPoll{Pending: true, IntervalSeconds: 5}, nil
	}
	return authn.TunnelLinkPoll{Status: authn.TunnelLinkStatus{Linked: true, Provider: "github", Account: "octocat"}}, nil
}

func (b *testLinkBroker) Credential(_ context.Context, principal authn.Principal) (authn.TunnelCredential, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	link, ok := b.links[principal]
	if !ok {
		return authn.TunnelCredential{}, apierr.New("tunnel_link_required", "a Dev Tunnels link is required", http.StatusConflict)
	}
	return link, nil
}

func (b *testLinkBroker) Delete(principal authn.Principal) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.links, principal)
	return nil
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
	return authn.WithPrincipal(ctx, testPrincipal)
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
	if service.TunnelLinks == nil {
		service.TunnelLinks = newTestLinkBroker()
	}
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

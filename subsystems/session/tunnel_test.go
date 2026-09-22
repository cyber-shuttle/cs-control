// Session tunnel tests protect capability files, secret separation, live access, and compensation.
// Capabilities remain strict private files and reject malformed data or symlink traversal.
// Persisted session payloads never contain connection, host, or Jupyter tokens.
// An uncertain provider create is deleted without exposing its credential in errors.
package session

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cyber-shuttle/cs-plane/internal/devtunnel"
	"github.com/cyber-shuttle/cs-plane/internal/security"
	"github.com/cyber-shuttle/cs-plane/internal/ssh"
	"github.com/cyber-shuttle/cs-plane/internal/testutil"
)

func defaultSessionCapability() sessionCapability {
	return sessionCapability{ConnectToken: testConnectToken, JupyterToken: testJupyterToken}
}

func TestSessionCapabilityStorage(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "session-capabilities")
	const sessionID, seq = "s-123456789abc", 1
	first := sessionCapability{ConnectToken: "first-connect-token", JupyterToken: strings.Repeat("A", 43)}
	testutil.Check(t, putCapability(dir, sessionID, seq, first))
	if got, err := getCapability(dir, sessionID, seq); err != nil || got != first {
		t.Fatalf("getCapability = %#v, %v", got, err)
	}
	if info, err := os.Stat(dir); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("directory mode = %v, %v", info.Mode(), err)
	}
	path, _ := capabilityPath(dir, sessionID, seq)
	if info, err := os.Stat(path); err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("file mode = %v, %v", info.Mode(), err)
	}
	replacement := sessionCapability{ConnectToken: "replacement-connect-token", JupyterToken: strings.Repeat("B", 42) + "A"}
	testutil.Check(t, putCapability(dir, sessionID, seq, replacement))
	if got, err := getCapability(dir, sessionID, seq); err != nil || got != replacement {
		t.Fatalf("replacement = %#v, %v", got, err)
	}
	testutil.Check(t, deleteCapability(dir, sessionID, seq))
	if _, err := getCapability(dir, sessionID, seq); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("after delete = %v", err)
	}
}

func TestSessionCapabilityRefusesInvalidRecordsAndSymlinks(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "session-capabilities")
	const sessionID, seq = "s-123456789abc", 1
	if err := putCapability(dir, sessionID, seq, sessionCapability{ConnectToken: "connect"}); err == nil {
		t.Fatal("invalid capability accepted")
	}
	testutil.Check(t, os.Mkdir(dir, 0o700))
	path, _ := capabilityPath(dir, sessionID, seq)
	for _, raw := range []string{
		`{"connectToken":"connect"}`,
		`{"connectToken":"connect","jupyterToken":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","extra":true}`,
		`{"connectToken":"connect","jupyterToken":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}{}`,
	} {
		testutil.Check(t, os.WriteFile(path, []byte(raw), 0o600))
		if _, err := getCapability(dir, sessionID, seq); err == nil {
			t.Fatalf("invalid record accepted: %s", raw)
		}
	}
	foreign := filepath.Join(root, "foreign.token")
	testutil.Check(t, os.WriteFile(foreign, []byte(`{"connectToken":"planted","jupyterToken":"`+strings.Repeat("A", 43)+`"}`), 0o600))
	testutil.Check(t, os.Remove(path))
	testutil.Check(t, os.Symlink(foreign, path))
	if _, err := getCapability(dir, sessionID, seq); err == nil {
		t.Fatal("capability read followed a symlink")
	}

	linkedDir, target := filepath.Join(root, "linked"), filepath.Join(root, "target")
	testutil.Check(t, os.Mkdir(target, 0o755))
	testutil.Check(t, os.Symlink(target, linkedDir))
	if err := putCapability(linkedDir, sessionID, seq, defaultSessionCapability()); err == nil {
		t.Fatal("capability write followed a directory symlink")
	}
	if entries, err := os.ReadDir(target); err != nil || len(entries) != 0 {
		t.Fatalf("symlink target entries = %#v, %v", entries, err)
	}
}

func readyAccessSession(now time.Time) Session {
	session := pendingSession("s-012345abcdef", "delta", "123")
	setTestSessionMetadata(&session)
	session.State = "READY"
	session.Tunnel.ExpiresAt = now.Add(time.Hour).Truncate(time.Second)
	return session
}

func accessTestService(t *testing.T, manager TunnelManager, now time.Time) Service {
	t.Helper()
	service := newTestService(t, ssh.Runner{}, testSessionStore(t))
	service.tunnelManager, service.capabilityDir, service.now = manager, t.TempDir()+"/credentials", func() time.Time { return now }
	return service
}

func TestCreateSessionTunnelPersistsCapabilityOnlyInPrivateCredential(t *testing.T) {
	manager := &testTunnelManager{}
	service := accessTestService(t, manager, time.Now())
	session := pendingSession("s-012345abcdef", "delta", "")
	record, jupyterToken, err := service.createSessionTunnel(context.Background(), &session, testPrincipal, devtunnel.Credential{Scheme: "Bearer", Token: "oauth-token"}, 1)
	testutil.Check(t, err)
	stored, err := getCapability(service.capabilityDir, session.ID, session.Seq)
	if err != nil || stored.ConnectToken != record.ConnectToken {
		t.Fatalf("private capability = %#v, %v", stored, err)
	}
	if jupyterToken != stored.JupyterToken {
		t.Fatalf("returned Jupyter token does not match the stored capability")
	}
	persistedSession, err := json.Marshal(session)
	testutil.Check(t, err)
	for _, secret := range []string{stored.ConnectToken, stored.JupyterToken, record.HostToken} {
		if strings.Contains(string(persistedSession), secret) {
			t.Fatalf("session state contains seq secret: %s", persistedSession)
		}
	}
}

func TestSessionAccessFollowsTheLiveTunnelExpiration(t *testing.T) {
	for name, test := range map[string]struct {
		liveExpiresAt func(sessionExpiresAt time.Time) time.Time
		check         func(t *testing.T, expiresAt time.Time, err error)
	}{
		"extended": {
			liveExpiresAt: func(sessionExpiresAt time.Time) time.Time { return sessionExpiresAt.Add(17 * time.Minute) },
			check: func(t *testing.T, expiresAt time.Time, err error) {
				if err != nil {
					t.Fatalf("extended tunnel expiration refused session access: %v", err)
				}
			},
		},
		"expired": {
			liveExpiresAt: func(time.Time) time.Time { return time.Now().UTC().Add(-time.Second) },
			check: func(t *testing.T, _ time.Time, err error) {
				if err == nil || !strings.Contains(err.Error(), "expired") {
					t.Fatalf("expected an expiry-specific refusal, got %v", err)
				}
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Second)
			session := readyAccessSession(now)
			live := test.liveExpiresAt(session.Tunnel.ExpiresAt)
			manager := &testTunnelManager{getResponse: &devtunnel.Record{
				ID: session.Tunnel.ID, ClusterID: session.Tunnel.ClusterID, ExpiresAt: live,
				Ports: []devtunnel.PortRecord{{PortNumber: ports(session.ID, session.Seq).Jupyter, Protocol: "http", PortForwardingURIs: []string{"https://31001.use.devtunnels.ms/"}}},
			}}
			service := accessTestService(t, manager, now)
			testutil.Check(t, putCapability(service.capabilityDir, session.ID, session.Seq, defaultSessionCapability()))
			access, err := service.sessionAccess(context.Background(), session)
			var expiresAt time.Time
			if err == nil {
				expiresAt = access.ExpiresAt
				if !expiresAt.Equal(live) {
					t.Fatalf("session access reported %s, want the live expiration %s", expiresAt, live)
				}
			}
			test.check(t, expiresAt, err)
		})
	}
}

func TestCreateSessionTunnelCompensatesUncertainCreateError(t *testing.T) {
	const oauth = "oauth-token-must-not-leak"
	manager := &testTunnelManager{
		createErr: errors.New("create response was ambiguous"),
		deleteErr: errors.New("delete failed with " + oauth),
	}
	session := pendingSession("s-012345abcdef", "delta", "")
	before := session
	credentialDir := t.TempDir()
	testutil.Check(t, os.Chmod(credentialDir, 0o700))
	service := accessTestService(t, manager, time.Now())
	service.capabilityDir = credentialDir
	_, _, err := service.createSessionTunnel(context.Background(), &session, security.Principal{Subject: "owner", Tenant: "tenant"}, devtunnel.Credential{Scheme: "Bearer", Token: oauth}, 1)
	if err == nil || strings.Contains(err.Error(), oauth) || !strings.Contains(err.Error(), "[redacted]") {
		t.Fatalf("create/cleanup error = %v", err)
	}
	if !reflect.DeepEqual(session, before) {
		t.Fatalf("session mutated after uncertain create: before=%#v after=%#v", before, session)
	}
	if len(manager.deletes) != 1 || manager.deletes[0].TunnelID != manager.creates[0].TunnelID || manager.deletes[0].ClusterID != "" || manager.deletes[0].OAuthToken != oauth {
		t.Fatalf("uncertain create compensation = %#v, create=%#v", manager.deletes, manager.creates)
	}
	entries, readErr := os.ReadDir(credentialDir)
	if readErr != nil || len(entries) != 0 {
		t.Fatalf("capability directory after uncertain create = %#v, %v", entries, readErr)
	}
}

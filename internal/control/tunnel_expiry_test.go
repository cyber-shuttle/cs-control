package control

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cyber-shuttle/cs-control/internal/authn"
	"github.com/cyber-shuttle/cs-control/internal/devtunnel"
	"github.com/cyber-shuttle/cs-control/internal/sshexec"
)

type expiryTunnelManager struct {
	createdAt  time.Time
	expiration func(devtunnel.CreateRequest) time.Time
	createErr  error
	deleteErr  error
	create     devtunnel.CreateRequest
	deletes    []devtunnel.DeleteRequest
}

func (m *expiryTunnelManager) Create(_ context.Context, request devtunnel.CreateRequest) (devtunnel.Record, error) {
	m.create = request
	if m.createErr != nil {
		return devtunnel.Record{}, m.createErr
	}
	createdAt := m.createdAt
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}
	expires := createdAt.Add(time.Duration(request.DurationSeconds) * time.Second)
	if m.expiration != nil {
		expires = m.expiration(request)
	}
	return devtunnel.Record{
		ID: request.TunnelID, ClusterID: "use", HostToken: "host-token", ConnectToken: "connect-token", ExpiresAt: expires,
	}, nil
}

func (m *expiryTunnelManager) Get(context.Context, devtunnel.GetRequest) (devtunnel.Record, error) {
	return devtunnel.Record{}, nil
}

func (m *expiryTunnelManager) Delete(_ context.Context, request devtunnel.DeleteRequest) error {
	m.deletes = append(m.deletes, request)
	return m.deleteErr
}

func TestCreateAllocationTunnelCompensatesUncertainCreateError(t *testing.T) {
	const oauth = "oauth-token-must-not-leak"
	manager := &expiryTunnelManager{
		createErr: errors.New("create response was ambiguous"),
		deleteErr: errors.New("delete failed with " + oauth),
	}
	runtime := pendingRuntime("rt-012345abcdef", "delta", "")
	before := runtime
	credentialDir := t.TempDir()
	if err := os.Chmod(credentialDir, 0o700); err != nil {
		t.Fatal(err)
	}
	service := Service{
		Runner: sshexec.Runner{Timeout: 5 * time.Second}, Tunnels: manager,
		Credentials: CredentialStore{Dir: credentialDir},
	}
	_, _, err := service.createAllocationTunnel(context.Background(), &runtime, authn.TunnelAuthorization{OAuthToken: oauth, Principal: authn.Principal{Subject: "owner", Tenant: "tenant"}})
	if err == nil || strings.Contains(err.Error(), oauth) || !strings.Contains(err.Error(), "[redacted]") {
		t.Fatalf("create/cleanup error = %v", err)
	}
	if !reflect.DeepEqual(runtime, before) {
		t.Fatalf("runtime mutated after uncertain create: before=%#v after=%#v", before, runtime)
	}
	if len(manager.deletes) != 1 || manager.deletes[0].TunnelID != manager.create.TunnelID || manager.deletes[0].ClusterID != "" || manager.deletes[0].OAuthToken != oauth {
		t.Fatalf("uncertain create compensation = %#v, create=%#v", manager.deletes, manager.create)
	}
	entries, readErr := os.ReadDir(credentialDir)
	if readErr != nil || len(entries) != 0 {
		t.Fatalf("credential directory after uncertain create = %#v, %v", entries, readErr)
	}
}

func TestAllocationTunnelDurationFloorAndCap(t *testing.T) {
	for _, test := range []struct {
		name        string
		wallMinutes int
		want        uint32
	}{
		{name: "one hour floor", wallMinutes: 1, want: devtunnel.MinDurationSeconds},
		{name: "walltime plus grace", wallMinutes: 60, want: 75 * 60},
		{name: "thirty day cap", wallMinutes: 525600, want: devtunnel.MaxDurationSeconds},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := allocationTunnelDurationSeconds(test.wallMinutes); got != test.want {
				t.Fatalf("duration = %d, want %d", got, test.want)
			}
		})
	}
}

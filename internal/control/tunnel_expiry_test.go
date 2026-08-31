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

func TestCreateAllocationTunnelCompensatesUncertainCreateError(t *testing.T) {
	const oauth = "oauth-token-must-not-leak"
	manager := &testTunnelManager{
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
	if len(manager.deletes) != 1 || manager.deletes[0].TunnelID != manager.creates[0].TunnelID || manager.deletes[0].ClusterID != "" || manager.deletes[0].OAuthToken != oauth {
		t.Fatalf("uncertain create compensation = %#v, create=%#v", manager.deletes, manager.creates)
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

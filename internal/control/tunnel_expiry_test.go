// Tunnel lifecycle edges. An uncertain create compensates by idempotently deleting the deterministic tunnel ID.
//
//	Test*
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
	"github.com/cyber-shuttle/cs-control/internal/credentialstore"
	"github.com/cyber-shuttle/cs-control/internal/devtunnel"
	"github.com/cyber-shuttle/cs-control/internal/sshexec"
	"github.com/cyber-shuttle/cs-control/internal/testutil"
)

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
	service := Service{
		Runner: sshexec.Runner{Timeout: 5 * time.Second}, Tunnels: manager,
		Credentials: credentialstore.Store{Dir: credentialDir},
	}
	_, _, err := service.createSessionTunnel(context.Background(), &session, authn.TunnelAuthorization{OAuthToken: oauth, Principal: authn.Principal{Subject: "owner", Tenant: "tenant"}})
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
		t.Fatalf("credential directory after uncertain create = %#v, %v", entries, readErr)
	}
}

func TestSessionTunnelDurationFloorAndCap(t *testing.T) {
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
			if got := sessionTunnelDurationSeconds(test.wallMinutes); got != test.want {
				t.Fatalf("duration = %d, want %d", got, test.want)
			}
		})
	}
}

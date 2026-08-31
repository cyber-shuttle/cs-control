package control

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cyber-shuttle/cs-control/internal/authn"
)

func runtimeContractValue() Runtime {
	return Runtime{
		RuntimeResponse: RuntimeResponse{
			ID: "rt-012345abcdef", Generation: "g-0123456789abcdef",
			State: "READY", SSHHost: "delta", Account: "project-a", Partition: "cpu",
			RootFolder: "$HOME/project", Resources: Resources{Cores: 2, MemoryMB: 2048, WallMinutes: 60},
			CreatedAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), UpdatedAt: time.Date(2030, 1, 1, 0, 1, 0, 0, time.UTC),
		},
		Owner:  authn.Principal{Subject: "owner-subject", Tenant: "owner-tenant"},
		Tunnel: TunnelMetadata{ID: "rt-012345abcdef-g-0123456789abcdef", ClusterID: "use", ExpiresAt: time.Date(2030, 1, 1, 1, 0, 0, 0, time.UTC)},
		JobID:  "12345", JobName: "cs-rt-012345abcdef", Node: "compute-1",
		PrivateRoot: "/home/alice/.cybershuttle/runtimes/rt-012345abcdef", WorkspaceRoot: "/home/alice/project",
	}
}

func assertJSONContractFixture(t *testing.T, value any, path string) []byte {
	t.Helper()
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, '\n')
	fixture, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, fixture) {
		t.Fatalf("contract fixture differs from actual JSON\nactual:\n%s\nfixture:\n%s", encoded, fixture)
	}
	return fixture
}

func TestRuntimePublicJSONContractIsNarrow(t *testing.T) {
	fixture := assertJSONContractFixture(t, runtimeContractValue().RuntimeResponse, "testdata/runtime-contract.json")
	for _, forbidden := range []string{"owner", "tunnel", "capability", "token", "privateRoot", "workspaceRoot", "services", "jupyter", "jobId", "jobName", "node", "linkspanSpec", "portUriFormat", "portSshCommandFormat"} {
		if strings.Contains(strings.ToLower(string(fixture)), strings.ToLower(forbidden)) {
			t.Fatalf("public runtime fixture contains private field %q: %s", forbidden, fixture)
		}
	}
}

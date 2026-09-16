// The published session JSON is narrow. Owner, tunnel, job ID, job name, node, and remote paths are never returned.
//
//	Test*
package control

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cyber-shuttle/cs-control/internal/testutil"
)

func TestSessionPublicJSONContractIsNarrow(t *testing.T) {
	value := sessionResponse{
		ID: "s-012345abcdef", Generation: "g-0123456789abcdef",
		State: "READY", SSHHost: "delta", Account: "project-a", Partition: "cpu",
		RootFolder: "$HOME/project", Resources: resources{Cores: 2, MemoryMB: 4096, WallMinutes: 60},
		CreatedAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), StartedAt: time.Date(2030, 1, 1, 0, 0, 30, 0, time.UTC), UpdatedAt: time.Date(2030, 1, 1, 0, 1, 0, 0, time.UTC),
	}
	encoded, err := json.MarshalIndent(value, "", "  ")
	testutil.Check(t, err)
	encoded = append(encoded, '\n')
	fixture, err := os.ReadFile("testdata/session-contract.json")
	testutil.Check(t, err)
	if !bytes.Equal(encoded, fixture) {
		t.Fatalf("contract fixture differs from actual JSON\nactual:\n%s\nfixture:\n%s", encoded, fixture)
	}
	for _, forbidden := range []string{"owner", "tunnel", "token", "privateRoot", "workspaceRoot", "jupyter", "jobId", "jobName", "node"} {
		if strings.Contains(strings.ToLower(string(fixture)), strings.ToLower(forbidden)) {
			t.Fatalf("public session fixture contains private field %q: %s", forbidden, fixture)
		}
	}
}

package control

import (
	"strings"
	"testing"
	"time"
)

func discoveryOutput(lines ...string) string {
	return strings.Join(lines, "\n") + "\n"
}

func TestDiscoveryFramingRejectsMalformedOutput(t *testing.T) {
	valid := []string{
		markerUser, "tester",
		markerAccounts, "Account|", "project-a|",
		markerPartitions, "cpu|8|64000|(null)",
		markerHome, "/home/tester",
		markerDone,
	}
	tests := map[string][]string{
		"missing section":       valid[:len(valid)-2],
		"duplicate marker":      append([]string{markerUser}, valid...),
		"out of order":          append([]string{markerPartitions}, valid[2:]...),
		"unknown marker":        append([]string{discoveryMarkerPrefix + "INJECTED__"}, valid...),
		"data before a section": append([]string{"stray"}, valid...),
		"data past the end":     append(append([]string{}, valid...), "stray"),
		"unsafe username":       {markerUser, "two users", markerAccounts, markerPartitions, markerHome, "/home/tester", markerDone},
		"unsafe home":           {markerUser, "tester", markerAccounts, markerPartitions, markerHome, "../../etc", markerDone},
		"malformed sinfo":       {markerUser, "tester", markerAccounts, markerPartitions, "cpu|8", markerHome, "/home/tester", markerDone},
		"malformed GRES":        {markerUser, "tester", markerAccounts, markerPartitions, "cpu|8|64000|gpu", markerHome, "/home/tester", markerDone},
		"failed command":        {markerUser, markerErrorUser},
	}
	for name, lines := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := discoveryResult("delta", discoveryOutput(lines...)); err == nil {
				t.Fatalf("accepted malformed output: %q", lines)
			}
		})
	}
	if _, err := discoveryResult("delta", discoveryOutput(valid...)); err != nil {
		t.Fatalf("well-formed output was rejected: %v", err)
	}
	if _, err := discoveryResult("delta", strings.TrimSuffix(discoveryOutput(valid...), "\n")); err == nil {
		t.Fatal("output truncated mid-line was accepted")
	}
}

// The remote username reaches Go only when the remote program's own guard let it
// through, so both refusals stand between a host and a shell command.
func TestDiscoveryRejectsUnsafeRemoteUsernames(t *testing.T) {
	for _, username := range []string{"", "bad;touch", "$USER", "two users", strings.Repeat("a", 65)} {
		if _, err := discoveryResult("delta", discoveryOutput(markerUser, username, markerAccounts, markerPartitions, markerHome, "/home/tester", markerDone)); err == nil {
			t.Errorf("accepted unsafe remote username %q", username)
		}
	}
}

func waitForFile(t *testing.T, path string) {
	t.Helper()
	eventually(t, 3*time.Second, path, nonEmptyFile(path))
}

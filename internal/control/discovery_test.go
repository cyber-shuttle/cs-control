package control

import (
	"strings"
	"testing"
	"time"
)

func TestDiscoveryFramingRejectsMalformedOutput(t *testing.T) {
	valid := []string{
		markerUserBegin, "tester", markerUserEnd,
		markerAccountsBegin, "Account|", "project-a|", markerAccountsEnd,
		markerPartitionsBegin, "cpu|8|64000|(null)", markerPartitionsEnd,
		markerHomeBegin, "/home/tester", markerHomeEnd,
		markerDone,
	}
	tests := map[string][]string{
		"missing section":       valid[:len(valid)-2],
		"duplicate marker":      append(append([]string{}, valid[:3]...), append([]string{markerUserEnd}, valid[3:]...)...),
		"out of order":          append(append([]string{}, valid[:3]...), append([]string{markerPartitionsBegin}, valid[3:]...)...),
		"marker collision data": append(append([]string{}, valid[:4]...), append([]string{markerDone}, valid[4:]...)...),
		"unknown marker":        append(append([]string{}, valid[:4]...), append([]string{discoveryMarkerPrefix + "INJECTED__"}, valid[4:]...)...),
	}
	for name, lines := range tests {
		t.Run(name, func(t *testing.T) {
			output := newDiscoveryFramedOutput()
			if _, err := output.Write([]byte(strings.Join(lines, "\n") + "\n")); err != nil {
				t.Fatal(err)
			}
			if _, err := output.result("delta"); err == nil {
				t.Fatalf("accepted malformed output: %q", lines)
			}
		})
	}
}

func waitForFile(t *testing.T, path string) {
	t.Helper()
	eventually(t, 3*time.Second, path, nonEmptyFile(path))
}

package main

import (
	"os/exec"
	"slices"
	"strings"
	"testing"
)

const modulePrefix = "github.com/cyber-shuttle/cs-control/"

var lowestToHighest = []string{
	"internal/apierr",
	"internal/safeio",
	"internal/framed",
	"internal/httpx",
	"internal/sshconfig",
	"internal/sshexec",
	"internal/devtunnel",
	"internal/authn",
	"internal/gateway",
	"internal/control",
	"cmd/csctl",
}

func TestNoPackageImportsUpward(t *testing.T) {
	listed, err := exec.Command("go", "list", "-f", `{{.ImportPath}} {{join .Imports " "}}`, modulePrefix+"...").Output()
	if err != nil {
		t.Fatal(err)
	}

	for _, line := range strings.Split(strings.TrimSpace(string(listed)), "\n") {
		fields := strings.Fields(line)
		importer := strings.TrimPrefix(fields[0], modulePrefix)
		level := slices.Index(lowestToHighest, importer)
		if level < 0 {
			t.Errorf("%s is in no layer; place it in lowestToHighest", importer)
			continue
		}
		for _, imported := range fields[1:] {
			if !strings.HasPrefix(imported, modulePrefix) {
				continue
			}
			name := strings.TrimPrefix(imported, modulePrefix)
			if slices.Index(lowestToHighest, name) >= level {
				t.Errorf("%s imports %s, which is not below it", importer, name)
			}
		}
	}
}

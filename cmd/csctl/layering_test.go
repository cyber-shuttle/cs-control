// Enforces docs/ARCHITECTURE.md's package order. Every import must name a strictly lower layer.
//
//	modulePrefix, lowestToHighest
//	TestNoPackageImportsUpward
package main

import (
	"os/exec"
	"slices"
	"strings"
	"testing"

	"github.com/cyber-shuttle/cs-control/internal/testutil"
)

const modulePrefix = "github.com/cyber-shuttle/cs-control/"

var lowestToHighest = []string{
	"internal/testutil",
	"internal/apierr",
	"internal/apihttp",
	"internal/safeio",
	"internal/httpx",
	"internal/sshconfig",
	"internal/sshexec",
	"internal/devtunnel",
	"internal/credentialstore",
	"internal/authn",
	"internal/control",
	"internal/gateway",
	"cmd/csctl",
}

func TestNoPackageImportsUpward(t *testing.T) {
	listed, err := exec.Command("go", "list", "-f",
		`{{.ImportPath}} {{join .Imports " "}} {{join .TestImports " "}} {{join .XTestImports " "}}`,
		modulePrefix+"...").Output()
	testutil.Check(t, err)

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

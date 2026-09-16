// Discovery's own framing and safety checks. Malformed output and an unsafe remote username are both refused.
//
//	discoveryOutput, validDiscoveryOutput
//	Test*
package control

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cyber-shuttle/cs-control/internal/apierr"
	"github.com/cyber-shuttle/cs-control/internal/sshconfig"
	"github.com/cyber-shuttle/cs-control/internal/sshexec"
	"github.com/cyber-shuttle/cs-control/internal/testutil"
)

func discoveryOutput(lines ...string) string {
	return strings.Join(lines, "\n") + "\n"
}

func validDiscoveryOutput() []string {
	return []string{
		markerUser, "tester",
		markerAccounts, "Account|", "project-a|",
		markerPartitions, "cpu|8|64000|(null)",
		markerHome, "/home/tester",
		markerDone,
	}
}

func TestDiscoveryFramingRejectsMalformedOutput(t *testing.T) {
	valid := validDiscoveryOutput()
	tests := map[string][]string{
		"missing section":              valid[:len(valid)-2],
		"duplicate marker":             append([]string{markerUser}, valid...),
		"out of order":                 append([]string{markerPartitions}, valid[2:]...),
		"unknown marker":               append([]string{discoveryMarkerPrefix + "INJECTED__"}, valid...),
		"data past the end":            append(append([]string{}, valid...), "stray"),
		"unsafe username: shell chars": {markerUser, "bad;touch", markerAccounts, markerPartitions, markerHome, "/home/tester", markerDone},
		"unsafe username: too long":    {markerUser, strings.Repeat("a", 65), markerAccounts, markerPartitions, markerHome, "/home/tester", markerDone},
		"unsafe home":                  {markerUser, "tester", markerAccounts, markerPartitions, markerHome, "../../etc", markerDone},
		"malformed sinfo":              {markerUser, "tester", markerAccounts, markerPartitions, "cpu|8", markerHome, "/home/tester", markerDone},
		"malformed GRES":               {markerUser, "tester", markerAccounts, markerPartitions, "cpu|8|64000|gpu", markerHome, "/home/tester", markerDone},
		"failed command":               {markerUser, markerErrorUser},
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
}

func TestDiscoveryToleratesALoginBanner(t *testing.T) {
	banner := append([]string{"Last login: Mon Jan  1 00:00:00 2026 from 10.0.0.1", "Warning: unattended access is logged"}, validDiscoveryOutput()...)
	if _, err := discoveryResult("delta", discoveryOutput(banner...)); err != nil {
		t.Fatalf("login banner ahead of the first marker was rejected: %v", err)
	}
}

func TestDiscoveryOfAnUnresolvableAliasKeepsItsClassifiedCode(t *testing.T) {
	service := Service{Runner: sshexec.Runner{Hosts: sshconfig.Config{UserPath: filepath.Join(t.TempDir(), "user_ssh_config")}}}
	_, err := service.discover(context.Background(), "delta")
	if apierr.For(err).Code != "ssh_host_not_found" {
		t.Fatalf("an unresolvable alias lost its classified code: %v", err)
	}
}

func TestDiscoveryFailureReachesTheHandlerAsItsOwnCode(t *testing.T) {
	service := testService(t)
	t.Setenv("FAKE_DISCOVERY_PARTITIONS_FAIL", "1")
	handler := NewHTTPHandler(service, noopAuth{})
	t.Cleanup(handler.Close)

	body, err := json.Marshal(newTestCreateRequest())
	testutil.Check(t, err)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/sessions/validate", bytes.NewReader(body)).WithContext(testTunnelContext())
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusBadGateway {
		t.Fatalf("a login node missing sinfo answered %d, want %d: %s", response.Code, http.StatusBadGateway, response.Body.String())
	}
	var envelope apierr.Envelope
	testutil.Check(t, json.Unmarshal(response.Body.Bytes(), &envelope))
	if envelope.Error.Code != "slurm_discovery_failed" || !strings.Contains(envelope.Error.Message, "query Slurm partitions") {
		t.Fatalf("discovery failure lost its code and operation: %#v", envelope.Error)
	}
}

func TestDiscoverBoundsBothSSHInvocationsTogether(t *testing.T) {
	ssh := filepath.Join(t.TempDir(), "ssh")
	script := "#!/bin/sh\nif [ \"$1\" = -G ]; then sleep 0.6; printf 'host %s\\nuser tester\\n' \"$2\"; exit 0; fi\nwhile :; do sleep 1; done\n"
	writeScript(t, ssh, script)
	const timeout = time.Second
	service := Service{Runner: sshexec.Runner{SSHBin: ssh, Timeout: timeout}, Logs: NewSessionLogs(), Metrics: NewSessionMetrics()}
	started := time.Now()
	if _, err := service.discover(context.Background(), "delta"); err == nil {
		t.Fatal("a hanging host was discovered")
	}
	if elapsed := time.Since(started); elapsed > timeout+300*time.Millisecond {
		t.Fatalf("discovery took %s, which is both timeouts rather than one", elapsed)
	}
}

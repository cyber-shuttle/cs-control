// Start runs a finished session again under the same session, only from a terminal state.
// A relaunch that fails to provision must end FAILED with the failure narrated in its tail.
//
//	retire
//	Test*
package control

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/cyber-shuttle/cs-control/internal/apierr"
	"github.com/cyber-shuttle/cs-control/internal/authn"
	"github.com/cyber-shuttle/cs-control/internal/testutil"
)

func retire(t *testing.T, service Service, id string) Session {
	t.Helper()
	var terminal Session
	if err := service.Store.withLock(func(current *state) error {
		session := current.Sessions[id]
		session.State, session.Node = "STOPPED", "cn001"
		session.CreatedAt, session.UpdatedAt = time.Unix(0, 0).UTC(), time.Unix(0, 0).UTC()
		terminal = *session
		return service.Store.save(current)
	}); err != nil {
		t.Fatal(err)
	}
	return terminal
}

func TestStartRunsTheFinishedSessionOnTheSameSession(t *testing.T) {
	service := testService(t)
	tunnels := configureTestTunnel(t, &service)
	created, err := service.create(testTunnelContext(), newTestCreateRequest())
	testutil.Check(t, err)
	terminal := retire(t, service, created.ID)

	started, err := service.start(testTunnelContext(), created.ID)
	testutil.Check(t, err)
	if started.ID != created.ID {
		t.Fatalf("run again took a new identity: %s -> %s", created.ID, started.ID)
	}
	if started.State != "QUEUED" || started.Generation == terminal.Generation || started.Node != "" {
		t.Fatalf("unexpected relaunched session: %#v", started)
	}
	if !started.CreatedAt.Equal(terminal.CreatedAt) || !started.UpdatedAt.After(terminal.UpdatedAt) {
		t.Fatalf("relaunch must keep the session's creation time and move it forward: %#v", started.sessionResponse)
	}
	if len(tunnels.deletes) != 1 || tunnels.deletes[0].TunnelID != created.ID+"-"+terminal.Generation {
		t.Fatalf("the finished run's tunnel was not released: %#v", tunnels.deletes)
	}
	sessions, err := service.loadSessions()
	testutil.Check(t, err)
	if len(sessions) != 1 || sessions[0].RootFolder != terminal.RootFolder {
		t.Fatalf("run again must leave exactly the one session it ran: %#v", sessions)
	}
}

func TestStartRefusesSessionsItMayNotRun(t *testing.T) {
	service := testService(t)
	created, err := service.create(testTunnelContext(), newTestCreateRequest())
	testutil.Check(t, err)
	if _, err := service.start(testTunnelContext(), created.ID); err == nil || apierr.For(err).Code != "session_running" {
		t.Fatalf("a live session was run again: %v", err)
	}
	retire(t, service, created.ID)

	stranger := authn.Principal{Subject: "other-owner", Tenant: "test-tenant"}
	ctx := authn.WithTunnelAuthorization(context.Background(), authn.TunnelAuthorization{OAuthToken: "other-token", Principal: stranger})
	if _, err := service.start(ctx, created.ID); err == nil || apierr.For(err).Code != "session_owner_mismatch" {
		t.Fatalf("another principal ran this session: %v", err)
	}
	if _, err := service.start(testTunnelContext(), "s-999999999999"); err == nil || apierr.For(err).Code != "session_not_found" {
		t.Fatalf("an unknown session was run: %v", err)
	}
}

func TestRelaunchProvisioningFailureKeepsItsTail(t *testing.T) {
	service := testService(t)
	created, err := service.create(testTunnelContext(), newTestCreateRequest())
	testutil.Check(t, err)
	retire(t, service, created.ID)

	t.Setenv("FAKE_PROVISION_FAIL", "1")
	t.Setenv("FAKE_PROVISION_REPORT", "error=workflow")
	if _, err := service.start(testTunnelContext(), created.ID); err == nil {
		t.Fatal("expected the relaunch to fail")
	}

	session, err := service.loadSession(created.ID)
	testutil.Check(t, err)
	if session.State != "FAILED" {
		t.Fatalf("relaunch did not end FAILED: %#v", session)
	}
	if joined := sessionLogText(t, service.Logs, created.ID); !strings.Contains(joined, "preparation failed") {
		t.Fatalf("a FAILED relaunch's tail did not outlive it: %s", joined)
	}
}

func TestStartReportsCredentialCleanupFailureInsteadOfRelaunching(t *testing.T) {
	service := testService(t)
	created, err := service.create(testTunnelContext(), newTestCreateRequest())
	testutil.Check(t, err)
	retire(t, service, created.ID)
	if err := service.Store.withLock(func(current *state) error {
		stored := current.Sessions[created.ID]
		stored.Generation, stored.Tunnel = "not-a-generation", tunnelMetadata{}
		return service.Store.save(current)
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := service.start(testTunnelContext(), created.ID); err == nil {
		t.Fatal("start relaunched despite a failed credential cleanup")
	}

	sessions, err := service.loadSessions()
	testutil.Check(t, err)
	if len(sessions) != 1 || sessions[0].Generation != "not-a-generation" {
		t.Fatalf("start silently dropped the unfrozen run and relaunched: %#v", sessions)
	}
}

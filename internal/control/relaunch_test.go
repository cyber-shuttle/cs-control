package control

import (
	"context"
	"testing"
	"time"

	"github.com/cyber-shuttle/cs-control/internal/apierr"
	"github.com/cyber-shuttle/cs-control/internal/authn"
)

// retire drives a created runtime to a terminal state the way a finished
// allocation reaches one, leaving the scheduler facts of that run behind.
func retire(t *testing.T, service Service, id string) Runtime {
	t.Helper()
	var terminal Runtime
	if err := service.Store.withLock(func(store Store, current *state) error {
		runtime := current.Runtimes[id]
		runtime.State, runtime.Node = "STOPPED", "cn001"
		runtime.CreatedAt, runtime.UpdatedAt = time.Unix(0, 0).UTC(), time.Unix(0, 0).UTC()
		terminal = *runtime
		return store.save(current)
	}); err != nil {
		t.Fatal(err)
	}
	return terminal
}

func TestStartRunsTheFinishedAllocationOnTheSameCard(t *testing.T) {
	service := testService(t)
	tunnels := configureTestTunnel(t, &service)
	created, err := service.Create(testTunnelContext(), createRequest())
	if err != nil {
		t.Fatal(err)
	}
	terminal := retire(t, service, created.ID)

	started, err := service.Start(testTunnelContext(), created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if started.ID != created.ID {
		t.Fatalf("run again took a new identity: %s -> %s", created.ID, started.ID)
	}
	if started.State != "QUEUED" || started.Generation == terminal.Generation || started.Node != "" {
		t.Fatalf("unexpected relaunched runtime: %#v", started)
	}
	if !started.CreatedAt.Equal(terminal.CreatedAt) || !started.UpdatedAt.After(terminal.UpdatedAt) {
		t.Fatalf("relaunch must keep the card's creation time and move it forward: %#v", started.RuntimeResponse)
	}
	if len(tunnels.deletes) != 1 || tunnels.deletes[0].TunnelID != created.ID+"-"+terminal.Generation {
		t.Fatalf("the finished run's tunnel was not released: %#v", tunnels.deletes)
	}
	runtimes, err := service.ListCached()
	if err != nil {
		t.Fatal(err)
	}
	if len(runtimes) != 1 || runtimes[0].RootFolder != terminal.RootFolder {
		t.Fatalf("run again must leave exactly the one card it ran: %#v", runtimes)
	}
}

func TestStartRefusesRuntimesItMayNotRun(t *testing.T) {
	service := testService(t)
	created, err := service.Create(testTunnelContext(), createRequest())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Start(testTunnelContext(), created.ID); err == nil || apierr.For(err).Code != "runtime_running" {
		t.Fatalf("a live allocation was run again: %v", err)
	}
	retire(t, service, created.ID)

	stranger := authn.Principal{Subject: "other-owner", Tenant: "test-tenant"}
	ctx := authn.WithTunnelAuthorization(authn.WithPrincipal(context.Background(), stranger), authn.TunnelAuthorization{OAuthToken: "other-token", Principal: stranger})
	if _, err := service.Start(ctx, created.ID); err == nil || apierr.For(err).Code != "runtime_owner_mismatch" {
		t.Fatalf("another principal ran this card: %v", err)
	}
	if _, err := service.Start(testTunnelContext(), "rt-999999999999"); err == nil || apierr.For(err).Code != "runtime_not_found" {
		t.Fatalf("an unknown runtime was run: %v", err)
	}
}

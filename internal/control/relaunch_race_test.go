// A relaunch races the reconciliation of the run it replaces.
// A login that stopped accepting sessions must refuse cleanly rather than half-provision.
//
//	relaunchRaceService
//	Test*
package control

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cyber-shuttle/cs-control/internal/apierr"
	"github.com/cyber-shuttle/cs-control/internal/testutil"
)

func relaunchRaceService(t *testing.T) (Service, *atomic.Int64, string, string) {
	t.Helper()
	dir := t.TempDir()
	started := filepath.Join(dir, "provision-started")
	release := filepath.Join(dir, "provision-release")
	t.Setenv("FAKE_PROVISION_STARTED", started)
	clock := &atomic.Int64{}
	clock.Store(time.Date(2026, 8, 28, 10, 0, 0, 0, time.UTC).UnixNano())
	service := testService(t, func() time.Time { return time.Unix(0, clock.Load()).UTC() })
	return service, clock, started, release
}

func TestRunAgainSurvivesAReconciliationAgainstTheFinishedRun(t *testing.T) {
	service, clock, started, release := relaunchRaceService(t)
	ctx := testTunnelContext()
	created, err := service.create(ctx, newTestCreateRequest())
	testutil.Check(t, err)
	testutil.Check(t, os.WriteFile(os.Getenv("FAKE_STATUS"), []byte("TIMEOUT\n"), 0o600))
	finished := retire(t, service, created.ID)

	clock.Store(finished.CreatedAt.Add(time.Hour).UnixNano())
	t.Setenv("FAKE_PROVISION_RELEASE", release)
	t.Setenv("FAKE_JOB_ID", "67890")
	testutil.Check(t, os.Remove(started))
	result := make(chan *Session, 1)
	errs := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		session, err := service.start(ctx, created.ID)
		result <- session
		errs <- err
	}()
	t.Cleanup(func() {
		_ = os.WriteFile(release, nil, 0o600)
		<-done
	})
	waitFor(t, errs, "sbatch started", func() bool { _, err := os.Stat(started); return err == nil })

	testutil.Check(t, service.reconcileAll(ctx))
	during, err := service.loadSession(created.ID)
	testutil.Check(t, err)
	if during.State != "SUBMITTING" {
		t.Fatalf("the finished run retired the relaunch: %s (job %q, node %q)", during.State, during.JobID, during.Node)
	}
	if during.JobID == finished.JobID || during.Node == finished.Node {
		t.Fatalf("the relaunch adopted the finished run's job: %#v", during)
	}

	testutil.Check(t, os.WriteFile(release, nil, 0o600))
	testutil.Check(t, <-errs)
	relaunched := <-result
	if relaunched.State != "QUEUED" || relaunched.JobID != "67890" {
		t.Fatalf("the submitted relaunch was not queued: %#v (job %q)", relaunched.sessionResponse, relaunched.JobID)
	}
}

func TestPreparationRefusedForALoginSaysSo(t *testing.T) {
	service := testService(t)
	t.Setenv("FAKE_DISCOVERY_FAIL", "Permission denied (publickey,keyboard-interactive).")
	_, err := service.create(testTunnelContext(), newTestCreateRequest())
	if apierr.For(err).Code != "ssh_authentication_required" {
		t.Fatalf("a host asking for a login was not reported as such: %v", err)
	}
	if _, ok := service.Logs.Tail(newTestCreateRequest().ID); ok {
		t.Fatal("a create that never persisted a record kept its log tail")
	}
}

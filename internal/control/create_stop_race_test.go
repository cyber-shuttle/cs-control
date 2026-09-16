// A job that arrives after must be cancelled immediately.
// A cancel failure persists for a later batch to retry.
// A client that disconnects mid-create must not leave the job running either.
//
//	createStopRaceService
//	waitFor
//	Test*
package control

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cyber-shuttle/cs-control/internal/testutil"
)

func createStopRaceService(t *testing.T) (Service, string, string, string) {
	t.Helper()
	dir := t.TempDir()
	started := filepath.Join(dir, "submit-started")
	release := filepath.Join(dir, "submit-release")
	cancellations := filepath.Join(dir, "cancellations")
	t.Setenv("FAKE_SUBMIT_STARTED", started)
	t.Setenv("FAKE_SUBMIT_RELEASE", release)
	t.Setenv("FAKE_SCANCEL_LOG", cancellations)
	service := testService(t)
	return service, started, release, cancellations
}

func waitFor(t *testing.T, errs <-chan error, what string, ready func() bool) {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case err := <-errs:
			t.Fatalf("Create finished before %s: %v", what, err)
		case <-ticker.C:
			if ready() {
				return
			}
		case <-deadline.C:
			t.Fatalf("timed out waiting for %s", what)
		}
	}
}

func TestCreateCancelsJobWhenStopWinsBeforeSbatchReturns(t *testing.T) {
	service, started, release, cancellations := createStopRaceService(t)
	result := make(chan *Session, 1)
	errs := make(chan error, 1)
	go func() {
		session, err := service.create(testTunnelContext(), newTestCreateRequest())
		result <- session
		errs <- err
	}()
	waitFor(t, errs, "sbatch started", func() bool { _, err := os.Stat(started); return err == nil })

	stopped, err := service.stop(testTunnelContext(), newTestCreateRequest().ID)
	if err != nil || stopped.State != "STOPPING" || stopped.JobID != "" {
		t.Fatalf("stop did not persist intent while sbatch was blocked: %#v %v", stopped, err)
	}
	testutil.Check(t, os.WriteFile(release, nil, 0o600))

	select {
	case err := <-errs:
		testutil.Check(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("Create did not finish after sbatch was released")
	}
	created := <-result
	if created.State != "STOPPING" || created.JobID != "12345" || created.Error != "" {
		t.Fatalf("Create overwrote stop intent: %#v", created)
	}
	data, err := os.ReadFile(cancellations)
	if err != nil || strings.Count(string(data), "scancel 12345") != 1 {
		t.Fatalf("submitted job was not immediately cancelled exactly once: %q %v", data, err)
	}
	cached, err := service.loadSession(created.ID)
	if err != nil || cached.State != "STOPPING" || cached.JobID != "12345" {
		t.Fatalf("stored state lost stop/job identity: %#v %v", cached, err)
	}
}

func TestCreatePersistsCancelFailureAndLaterBatchRetries(t *testing.T) {
	service, started, release, cancellations := createStopRaceService(t)
	t.Setenv("FAKE_SCANCEL_FAIL", "1")
	result := make(chan *Session, 1)
	errs := make(chan error, 1)
	go func() {
		session, err := service.create(testTunnelContext(), newTestCreateRequest())
		result <- session
		errs <- err
	}()
	waitFor(t, errs, "sbatch started", func() bool { _, err := os.Stat(started); return err == nil })
	_, err := service.stop(testTunnelContext(), newTestCreateRequest().ID)
	testutil.Check(t, err)
	testutil.Check(t, os.WriteFile(release, nil, 0o600))
	testutil.Check(t, <-errs)
	created := <-result
	if created.State != "STOPPING" || !strings.Contains(created.Error, "scheduler temporarily unavailable") {
		t.Fatalf("cancel failure was not persisted: %#v", created)
	}

	t.Setenv("FAKE_SCANCEL_FAIL", "0")
	listed, err := reconciledList(context.Background(), service)
	testutil.Check(t, err)
	if len(listed) != 1 || listed[0].State != "STOPPED" || listed[0].Error != "" {
		t.Fatalf("later reconciliation did not retry cancellation: %#v", listed)
	}
	data, err := os.ReadFile(cancellations)
	if err != nil || !strings.Contains(string(data), "batch scancel") {
		t.Fatalf("later batch did not retry cancellation: %q %v", data, err)
	}
}

func TestCreateCancelsUnsavedJobEvenWithACancelledRequestContext(t *testing.T) {
	service, started, release, cancellations := createStopRaceService(t)
	cancelStarted := filepath.Join(t.TempDir(), "scancel-started")
	cancelRelease := filepath.Join(t.TempDir(), "scancel-release")
	t.Setenv("FAKE_SCANCEL_STARTED", cancelStarted)
	t.Setenv("FAKE_SCANCEL_RELEASE", cancelRelease)
	ctx, cancel := context.WithCancel(testTunnelContext())
	request := newTestCreateRequest()
	errs := make(chan error, 1)
	go func() {
		_, err := service.create(ctx, request)
		errs <- err
	}()
	waitFor(t, errs, "sbatch started", func() bool { _, err := os.Stat(started); return err == nil })
	testutil.Check(t, os.Chmod(service.Store.Dir, 0o500))
	t.Cleanup(func() { _ = os.Chmod(service.Store.Dir, 0o700) })
	testutil.Check(t, os.WriteFile(release, nil, 0o600))
	waitFor(t, errs, "compensation scancel started", func() bool { _, err := os.Stat(cancelStarted); return err == nil })
	cancel()
	testutil.Check(t, os.WriteFile(cancelRelease, nil, 0o600))

	err := <-errs
	if err == nil || !strings.Contains(err.Error(), "job was cancelled") {
		t.Fatalf("compensation did not report a successful cancel with a cancelled request context: %v", err)
	}
	data, err := os.ReadFile(cancellations)
	if err != nil || !strings.Contains(string(data), "12345") {
		t.Fatalf("submitted job was not cancelled: %q %v", data, err)
	}
}

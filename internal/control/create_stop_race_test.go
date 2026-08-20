package control

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cyber-shuttle/cs-control/internal/sshexec"
)

func createStopRaceService(t *testing.T) (Service, string, string, string) {
	t.Helper()
	ssh, _, _, _ := fakeSSH(t)
	dir := t.TempDir()
	started := filepath.Join(dir, "submit-started")
	release := filepath.Join(dir, "submit-release")
	cancellations := filepath.Join(dir, "cancellations")
	t.Setenv("FAKE_SUBMIT_STARTED", started)
	t.Setenv("FAKE_SUBMIT_RELEASE", release)
	t.Setenv("FAKE_SCANCEL_LOG", cancellations)
	service := Service{
		Runner: sshexec.Runner{SSHBin: ssh, Timeout: 5 * time.Second},
		Store:  Store{Dir: filepath.Join(dir, "state")},
		Config: Config{LinkspanPath: "/opt/cybershuttle/linkspan"},
	}
	configureTestTunnel(t, &service)
	return service, started, release, cancellations
}

func TestCreateCancelsJobWhenStopWinsBeforeSbatchReturns(t *testing.T) {
	service, started, release, cancellations := createStopRaceService(t)
	result := make(chan *Runtime, 1)
	errs := make(chan error, 1)
	go func() {
		runtime, err := service.Create(testTunnelContext(), createRequest())
		result <- runtime
		errs <- err
	}()
	waitForSubmitStart(t, started, errs)

	stopped, err := service.Stop(testTunnelContext(), createRequest().ID)
	if err != nil || stopped.State != "STOPPING" || stopped.JobID != "" {
		t.Fatalf("stop did not persist intent while sbatch was blocked: %#v %v", stopped, err)
	}
	if err := os.WriteFile(release, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-errs:
		if err != nil {
			t.Fatal(err)
		}
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
	cached, err := service.GetCached(created.ID)
	if err != nil || cached.State != "STOPPING" || cached.JobID != "12345" {
		t.Fatalf("stored state lost stop/job identity: %#v %v", cached, err)
	}
}

func TestCreatePersistsCancelFailureAndLaterBatchRetries(t *testing.T) {
	service, started, release, cancellations := createStopRaceService(t)
	t.Setenv("FAKE_SCANCEL_FAIL", "1")
	result := make(chan *Runtime, 1)
	errs := make(chan error, 1)
	go func() {
		runtime, err := service.Create(testTunnelContext(), createRequest())
		result <- runtime
		errs <- err
	}()
	waitForSubmitStart(t, started, errs)
	if _, err := service.Stop(testTunnelContext(), createRequest().ID); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(release, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := <-errs; err != nil {
		t.Fatal(err)
	}
	created := <-result
	if created.State != "STOPPING" || !strings.Contains(created.Error, "scheduler temporarily unavailable") {
		t.Fatalf("cancel failure was not persisted: %#v", created)
	}

	t.Setenv("FAKE_SCANCEL_FAIL", "0")
	listed, err := reconciledList(context.Background(), service)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 || listed[0].State != "STOPPED" || listed[0].Error != "" {
		t.Fatalf("later reconciliation did not retry cancellation: %#v", listed)
	}
	data, err := os.ReadFile(cancellations)
	if err != nil || !strings.Contains(string(data), "batch scancel") {
		t.Fatalf("later batch did not retry cancellation: %q %v", data, err)
	}
}

func TestStopAfterSubmittedJobIDDoesNotAllowCreateOverwrite(t *testing.T) {
	service, _, _, cancellations := createStopRaceService(t)
	t.Setenv("FAKE_SUBMIT_STARTED", "")
	t.Setenv("FAKE_SUBMIT_RELEASE", "")
	created, err := service.Create(testTunnelContext(), createRequest())
	if err != nil || created.State != "QUEUED" || created.JobID != "12345" {
		t.Fatalf("create failed: %#v %v", created, err)
	}
	stopped, err := service.Stop(testTunnelContext(), created.ID)
	if err != nil || stopped.State != "STOPPED" {
		t.Fatalf("stop after job ID failed: %#v %v", stopped, err)
	}
	data, err := os.ReadFile(cancellations)
	if err != nil || !strings.Contains(string(data), "scancel 12345") {
		t.Fatalf("known job was not cancelled: %q %v", data, err)
	}
	cached, err := service.GetCached(created.ID)
	if err != nil || cached.State != "STOPPED" {
		t.Fatalf("stop state was overwritten: %#v %v", cached, err)
	}
}

func waitForSubmitStart(t *testing.T, path string, errs <-chan error) {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case err := <-errs:
			t.Fatalf("Create failed before sbatch started: %v", err)
		case <-ticker.C:
			if _, err := os.Stat(path); err == nil {
				return
			}
		case <-deadline.C:
			t.Fatalf("timed out waiting for %s", path)
		}
	}
}

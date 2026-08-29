package control

import (
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cyber-shuttle/cs-control/internal/apierr"
	"github.com/cyber-shuttle/cs-control/internal/sshexec"
)

// relaunchRaceService holds provisioning open -- the window a relaunch spends
// SUBMITTING with no job of its own -- and hands the test the clock.
func relaunchRaceService(t *testing.T) (Service, *atomic.Int64, string, string) {
	t.Helper()
	ssh, _, _ := fakeSSH(t)
	dir := t.TempDir()
	started := filepath.Join(dir, "provision-started")
	release := filepath.Join(dir, "provision-release")
	t.Setenv("FAKE_PROVISION_STARTED", started)
	clock := &atomic.Int64{}
	clock.Store(time.Date(2026, 8, 28, 10, 0, 0, 0, time.UTC).UnixNano())
	service := Service{
		Runner: sshexec.Runner{SSHBin: ssh, Timeout: 5 * time.Second},
		Store:  Store{Dir: filepath.Join(dir, "state")},
		Config: Config{LinkspanPath: "/opt/cybershuttle/linkspan", RuntimeBase: ".cybershuttle/runtimes"},
		Now:    func() time.Time { return time.Unix(0, clock.Load()).UTC() },
	}
	configureTestTunnel(t, &service)
	return service, clock, started, release
}

// A reconciliation landing while the next allocation is still being prepared
// used to read the finished run's record as this one's outcome, leaving the
// card STOPPED for good while its job ran on unattended.
func TestRunAgainSurvivesAReconciliationAgainstTheFinishedRun(t *testing.T) {
	service, clock, started, release := relaunchRaceService(t)
	ctx := testTunnelContext()
	created, err := service.Create(ctx, createRequest())
	if err != nil {
		t.Fatal(err)
	}
	// End the card the way Slurm ends one, through the reconciler.
	if err := os.WriteFile(os.Getenv("FAKE_STATUS"), []byte("TIMEOUT\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := service.ReconcileAll(ctx); err != nil {
		t.Fatal(err)
	}
	finished, err := service.GetCached(created.ID)
	if err != nil || finished.State != "STOPPED" {
		t.Fatalf("allocation did not finish: %#v %v", finished, err)
	}

	// The card is older than the window that lets a just-submitted job be
	// missing from the scheduler, which is true of every card worth running again.
	clock.Store(finished.CreatedAt.Add(time.Hour).UnixNano())
	t.Setenv("FAKE_PROVISION_RELEASE", release)
	t.Setenv("FAKE_JOB_ID", "67890")
	if err := os.Remove(started); err != nil {
		t.Fatal(err)
	}
	result := make(chan *Runtime, 1)
	errs := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		runtime, err := service.Start(ctx, created.ID)
		result <- runtime
		errs <- err
	}()
	// Preparation is one host at a time process-wide, so a failed assertion must
	// still let the blocked relaunch finish or it holds delta for the package.
	t.Cleanup(func() {
		_ = os.WriteFile(release, nil, 0o600)
		<-done
	})
	waitForSubmitStart(t, started, errs)

	before, err := service.GetCached(created.ID)
	if err != nil || before.State != "SUBMITTING" {
		t.Fatalf("relaunch did not persist a submit intent: %#v %v", before, err)
	}
	if err := service.ReconcileAll(ctx); err != nil {
		t.Fatal(err)
	}
	during, err := service.GetCached(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if during.State != "SUBMITTING" {
		t.Fatalf("the finished run retired the relaunch: %s (job %q, node %q)", during.State, during.JobID, during.Node)
	}
	if during.JobID == finished.JobID || during.Node == finished.Node {
		t.Fatalf("the relaunch adopted the finished run's job: %#v", during)
	}

	if err := os.WriteFile(release, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := <-errs; err != nil {
		t.Fatal(err)
	}
	relaunched := <-result
	if relaunched.State != "QUEUED" || relaunched.JobID != "67890" {
		t.Fatalf("the submitted relaunch was not queued: %#v (job %q)", relaunched.RuntimeResponse, relaunched.JobID)
	}
	cached, err := service.GetCached(created.ID)
	if err != nil || cached.State != "QUEUED" || cached.JobID != "67890" {
		t.Fatalf("stored state lost the relaunch: %#v %v", cached, err)
	}
}

// A host wanting a login refused the runtime; the tail should name the remedy.
func TestPreparationRefusedForALoginSaysSo(t *testing.T) {
	service := testService(t)
	t.Setenv("FAKE_DISCOVERY_FAIL", "Permission denied (publickey,keyboard-interactive).")
	_, err := service.Create(testTunnelContext(), createRequest())
	if apierr.For(err).Code != "ssh_authentication_required" {
		t.Fatalf("a host asking for a login was not reported as such: %v", err)
	}
	tail, _ := service.Logs.Tail(createRequest().ID)
	joined := ""
	for _, line := range tail.Lines {
		joined += line.Text + "|"
	}
	if !strings.Contains(joined, "Interactive SSH login required") {
		t.Fatalf("the tail did not name the remedy: %s", joined)
	}
	if strings.Contains(joined, "Runtime preparation failed") {
		t.Fatalf("a login refusal was reported as a failure: %s", joined)
	}
}

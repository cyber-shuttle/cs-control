// Reconciliation's own contract against a fake scheduler.
// Covers batched SSH rounds, terminal and stopping sessions, lock discipline, walltime retirement, and lookback.
// A session gets no scheduler observation until its walltime or the propagation window says otherwise.
//
//	reconciliationService
//	stoppingSession
//	mustRead
//	assertOneSchedulerRound
//	runningSession
//	Test*
package control

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cyber-shuttle/cs-control/internal/testutil"
)

func reconciliationService(t *testing.T) (Service, string, string) {
	t.Helper()
	service := testService(t, time.Now)
	return service, os.Getenv("FAKE_COMMAND_LOG"), filepath.Join(service.Store.Dir, "release")
}

func stoppingSession(id, host, jobID string) Session {
	session := pendingSession(id, host, jobID)
	session.State = "STOPPING"
	return session
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	testutil.Check(t, err)
	return data
}

func assertOneSchedulerRound(t *testing.T, log, host string) {
	t.Helper()
	data := string(mustRead(t, log))
	if strings.Count(data, host+"|'sh' '-s' '--' 'csctl-session-status'") != 1 {
		t.Fatalf("scheduler calls were not one round for %s: %s", host, data)
	}
}

func runningSession(startedAt time.Time) Session {
	session := pendingSession("s-111111111111", "alpha", "101")
	session.State = "READY"
	session.StartedAt = startedAt
	session.Resources.WallMinutes = 60
	return session
}

func TestCancelledReconciliationPreservesLastGoodSession(t *testing.T) {
	service, _, _ := reconciliationService(t)
	session := pendingSession("s-111111111111", "alpha", "101")
	session.State = "READY"
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, _ := service.reconcileSnapshots(ctx, []Session{session})
	if !reflect.DeepEqual(got, []Session{session}) {
		t.Fatalf("cancelled refresh changed persisted presentation state: %#v", got)
	}
}

func TestReconcileUsesOneRoundPerMixedHostAndNoneForTerminal(t *testing.T) {
	service, log, _ := reconciliationService(t)
	one := pendingSession("s-111111111111", "alpha", "101")
	two := pendingSession("s-222222222222", "beta", "202")
	terminal := pendingSession("s-333333333333", "gamma", "303")
	terminal.State = "FAILED"
	t.Setenv("FAKE_STATUS_LINES", "101|PENDING||"+one.JobName+"\\n202|PENDING||"+two.JobName)
	putSessions(t, service, one, two, terminal)
	_, err := reconciledList(context.Background(), service)
	testutil.Check(t, err)
	data, _ := os.ReadFile(log)
	if got := strings.Count(string(data), "csctl-session-status"); got != 2 || strings.Contains(string(data), "gamma|") {
		t.Fatalf("unexpected scheduler rounds: %s", data)
	}
}

func TestStoppingFailedCancelKeepsActiveStateAndDiagnostic(t *testing.T) {
	service, log, _ := reconciliationService(t)
	stopping := stoppingSession("s-111111111111", "alpha", "101")
	unrelated := pendingSession("s-222222222222", "alpha", "202")
	t.Setenv("FAKE_CANCEL_ERRORS", "id:101|scheduler temporarily unavailable")
	t.Setenv("FAKE_STATUS_LINES", "101|RUNNING|cn001|"+stopping.JobName+"\\n202|PENDING|cn002|"+unrelated.JobName)
	putSessions(t, service, stopping, unrelated)

	listed, err := reconciledList(context.Background(), service)
	testutil.Check(t, err)
	byID := map[string]Session{}
	for _, session := range listed {
		byID[session.ID] = session
	}
	if got := byID[stopping.ID]; got.State != "STOPPING" || got.Error != "scheduler temporarily unavailable" {
		t.Fatalf("active stopping session lost cancellation diagnostic: %#v", got)
	}
	if got := byID[unrelated.ID]; got.State != "QUEUED" || got.Error != "" || got.Node != "cn002" {
		t.Fatalf("unrelated session did not reconcile: %#v", got)
	}
	assertOneSchedulerRound(t, log, "alpha")
}

func TestStoppingUnknownSubmissionUsesJobNameAndObservesState(t *testing.T) {
	service, log, _ := reconciliationService(t)
	session := stoppingSession("s-111111111111", "alpha", "")
	t.Setenv("FAKE_CANCEL_ERRORS", "name:"+session.JobName+"|submission cancellation pending")
	t.Setenv("FAKE_STATUS_LINES", "777|PENDING||"+session.JobName)
	putSessions(t, service, session)

	listed, err := reconciledList(context.Background(), service)
	testutil.Check(t, err)
	if listed[0].JobID != "777" || listed[0].State != "STOPPING" || listed[0].Error != "submission cancellation pending" {
		t.Fatalf("unknown stopping submission was not reconciled: %#v", listed[0])
	}
	assertOneSchedulerRound(t, log, "alpha")
	script := string(mustRead(t, os.Getenv("FAKE_STATUS_SCRIPT_LOG")))
	if !strings.Contains(script, "scancel --name='"+session.JobName+"'") {
		t.Fatalf("unknown submission was not cancelled by unique job name:\n%s", script)
	}
}

func TestReconcileDoesNotHoldStoreLockDuringSSHAndDoesNotOverwriteStop(t *testing.T) {
	service, log, release := reconciliationService(t)
	started := filepath.Join(t.TempDir(), "started")
	t.Setenv("FAKE_STATUS_STARTED", started)
	t.Setenv("FAKE_STATUS_RELEASE", release)
	session := pendingSession("s-111111111111", "alpha", "101")
	t.Setenv("FAKE_STATUS_LINES", "101|PENDING||"+session.JobName)
	putSessions(t, service, session)
	done := make(chan error, 1)
	go func() { _, err := reconciledList(context.Background(), service); done <- err }()
	waitForFile(t, log)

	lockAvailable := make(chan error, 1)
	go func() { lockAvailable <- service.Store.withLock(func(*state) error { return nil }) }()
	testutil.Within(t, lockAvailable, 300*time.Millisecond, "state lock was held during blocked SSH")
	_, err := service.stop(testTunnelContext(), session.ID)
	testutil.Check(t, err)
	testutil.Check(t, os.WriteFile(release, []byte("ok"), 0o600))
	testutil.Check(t, <-done)
	got, err := reconciledGet(context.Background(), service, session.ID)
	testutil.Check(t, err)
	if got.State != "STOPPING" && got.State != "STOPPED" {
		t.Fatalf("stale list overwrote stop intent: %#v", got)
	}
}

func TestSchedulerTerminalWordsClassifyIntoStoppedOrFailed(t *testing.T) {
	for raw, want := range map[string]string{
		"TIMEOUT":   "STOPPED",
		"COMPLETED": "STOPPED",
		"FAILED":    "FAILED",
	} {
		if got := nextState("READY", classifySchedulerState(raw)); got != want {
			t.Errorf("Slurm %s left the session %s, want %s", raw, got, want)
		}
	}
	if classifySchedulerState("BOGUS_STATE") != schedulerUnknown {
		t.Error("an unrecognised scheduler word classified as something, so it would move the session")
	}
}

func TestSchedulerThatDoesNotKnowTheJobRetiresTheSession(t *testing.T) {
	service, _, _ := reconciliationService(t)
	session := pendingSession("s-111111111111", "alpha", "101")
	session.State = "READY"
	t.Setenv("FAKE_STATUS_LINES", "")
	putSessions(t, service, session)
	got, _ := service.reconcileSnapshots(context.Background(), []Session{session})
	if got[0].State != "STOPPED" {
		t.Fatalf("a session the scheduler has no record of stayed %s, want STOPPED", got[0].State)
	}
}

func TestFreshlySubmittedSessionSurvivesTheSchedulerPropagationWindow(t *testing.T) {
	service, _, _ := reconciliationService(t)
	session := pendingSession("s-111111111111", "alpha", "101")
	session.CreatedAt, session.UpdatedAt = time.Now().Add(-6*time.Hour).UTC(), time.Now().UTC()
	t.Setenv("FAKE_STATUS_LINES", "")
	putSessions(t, service, session)
	got, _ := service.reconcileSnapshots(context.Background(), []Session{session})
	if got[0].State != "QUEUED" {
		t.Fatalf("a just-submitted session was retired as %s during the propagation window", got[0].State)
	}
}

func TestSubmittingSessionWithNoJobIDSurvivesThePropagationWindow(t *testing.T) {
	service, _, _ := reconciliationService(t)
	session := pendingSession("s-111111111111", "alpha", "")
	session.State = "SUBMITTING"
	session.UpdatedAt = time.Now().Add(-provisionTimeout / 2).UTC()
	t.Setenv("FAKE_STATUS_LINES", "")
	putSessions(t, service, session)
	got, _ := service.reconcileSnapshots(context.Background(), []Session{session})
	if got[0].State != "SUBMITTING" {
		t.Fatalf("a submitting session with no job ID was retired as %s, want SUBMITTING", got[0].State)
	}

	session.UpdatedAt = time.Now().Add(-provisionTimeout - time.Minute).UTC()
	putSessions(t, service, session)
	got, _ = service.reconcileSnapshots(context.Background(), []Session{session})
	if got[0].State != "STOPPED" {
		t.Fatalf("a submitting session with no job ID past provisionTimeout stayed %s, want STOPPED", got[0].State)
	}
}

func TestUnreachableSchedulerRetiresASessionPastItsWalltime(t *testing.T) {
	service, _, _ := reconciliationService(t)
	session := runningSession(time.Now().Add(-4 * time.Hour))
	putSessions(t, service, session)
	t.Setenv("FAKE_STATUS_FAIL", "1")
	got, _ := service.reconcileSnapshots(context.Background(), []Session{session})
	if got[0].State != "STOPPED" {
		t.Fatalf("a session four hours past a one-hour walltime stayed %s, want STOPPED", got[0].State)
	}
	if got[0].Error != "" {
		t.Fatalf("a session the clock retired still carries a scheduler error: %q", got[0].Error)
	}
}

func TestWalltimeExpiryWithNoObservationDeletesTheCredential(t *testing.T) {
	service, _, _ := reconciliationService(t)
	session := runningSession(time.Now().Add(-4 * time.Hour))
	setTestSessionMetadata(&session)
	testutil.Check(t, service.Credentials.Put(session.ID, session.Seq, credential()))
	putSessions(t, service, session)
	t.Setenv("FAKE_STATUS_FAIL", "1")
	testutil.Check(t, service.reconcileAll(context.Background()))
	if _, err := service.Credentials.Get(session.ID, session.Seq); err == nil {
		t.Fatal("a session retired past its walltime with no observation kept its seq credential")
	}
}

func TestUnreachableSchedulerDiagnosticIsBounded(t *testing.T) {
	session := runningSession(time.Now())
	oversized := errors.New(strings.Repeat("x", maxSessionError*4))
	unreachableScheduler(&session, oversized, time.Now())
	if len(session.Error) > maxSessionError {
		t.Fatalf("an oversized scheduler failure text was stored unbounded: %d bytes", len(session.Error))
	}
}

func TestUnreachableSchedulerKeepsASessionInsideItsWalltime(t *testing.T) {
	service, _, _ := reconciliationService(t)
	session := runningSession(time.Now().Add(-5 * time.Minute))
	putSessions(t, service, session)
	t.Setenv("FAKE_STATUS_FAIL", "1")
	got, _ := service.reconcileSnapshots(context.Background(), []Session{session})
	if got[0].State != "READY" {
		t.Fatalf("a session inside its walltime was retired as %s by an unreachable scheduler", got[0].State)
	}
	if got[0].Error == "" {
		t.Fatal("an unreachable scheduler left no diagnostic on the session")
	}
}

func TestSchedulerQueryAsksSacctForJobsOlderThanToday(t *testing.T) {
	service, _, _ := reconciliationService(t)
	scripts := os.Getenv("FAKE_STATUS_SCRIPT_LOG")
	session := pendingSession("s-111111111111", "alpha", "101")
	t.Setenv("FAKE_STATUS_LINES", "101|PENDING||"+session.JobName)
	putSessions(t, service, session)
	service.reconcileSnapshots(context.Background(), []Session{session})
	sent := string(mustRead(t, scripts))
	if !strings.Contains(sent, "sacct --noheader -X --starttime=") {
		t.Fatalf("sacct was asked without a start time, so anything older than today is invisible:\n%s", sent)
	}
	if !strings.Contains(sent, "--starttime='now-") {
		t.Fatalf("the accounting window must be relative to the cluster's own clock:\n%s", sent)
	}
}

func TestStartedAtComesFromSlurmElapsedNotThePollTime(t *testing.T) {
	service, _, _ := reconciliationService(t)
	session := pendingSession("s-111111111111", "alpha", "101")
	t.Setenv("FAKE_STATUS_LINES", "101|RUNNING|node1|"+session.JobName+"|7200")
	putSessions(t, service, session)
	got, _ := service.reconcileSnapshots(context.Background(), []Session{session})
	elapsed := time.Since(got[0].StartedAt)
	if elapsed < 2*time.Hour-time.Minute || elapsed > 2*time.Hour+time.Minute {
		t.Fatalf("a job Slurm says ran for two hours was anchored %s ago, not ~2h", elapsed)
	}
}

func TestQueueRowDoesNotResetTheAccountingElapsedAnchor(t *testing.T) {
	service, _, _ := reconciliationService(t)
	session := pendingSession("s-111111111111", "alpha", "101")
	t.Setenv("FAKE_QUEUE_LINES", "101|RUNNING|node1|"+session.JobName)
	t.Setenv("FAKE_STATUS_LINES", "101|RUNNING|node1|"+session.JobName+"|7200")
	putSessions(t, service, session)
	got, _ := service.reconcileSnapshots(context.Background(), []Session{session})
	if elapsed := time.Since(got[0].StartedAt); elapsed < 2*time.Hour-time.Minute {
		t.Fatalf("a two-hour-old job was anchored %s ago: the queue row reset it", elapsed)
	}
}

func TestOnlyAStartedSessionIsUnderAWalltimeDeadline(t *testing.T) {
	session := pendingSession("s-111111111111", "alpha", "101")
	session.State = "QUEUED"
	session.Resources.WallMinutes = 60
	session.StartedAt = time.Now().Add(-4 * time.Hour)
	if outlivedWalltime(session, time.Now()) {
		t.Error("a queued session past its nominal walltime was retired")
	}
}

func TestSchedulerLookbackIsRelativeBoundedAndReachesTheOldestSession(t *testing.T) {
	now := time.Now()
	longest := int64(schedulerLookbackMax.Seconds())
	for name, test := range map[string]struct {
		created  time.Time
		min, max int64
	}{
		"90 seconds old":   {now.Add(-90 * time.Second), 90, longest},
		"no creation time": {time.Time{}, 1, longest},
		"created in 1970":  {time.Unix(1, 0), longest, longest},
	} {
		session := pendingSession("s-111111111111", "alpha", "101")
		session.CreatedAt = test.created
		got := schedulerLookback([]Session{session}, now)
		if !strings.HasPrefix(got, "now-") || !strings.HasSuffix(got, "seconds") {
			t.Errorf("%s: lookback %q is not relative to the cluster's clock", name, got)
			continue
		}
		seconds, err := strconv.ParseInt(strings.TrimSuffix(strings.TrimPrefix(got, "now-"), "seconds"), 10, 64)
		if err != nil {
			t.Errorf("%s: lookback %q does not carry a count Slurm can read: %v", name, got, err)
			continue
		}
		if seconds < test.min || seconds > test.max {
			t.Errorf("%s: lookback of %d seconds is outside [%d, %d]", name, seconds, test.min, test.max)
		}
	}
}

func TestSchedulerRoundToleratesRemoteLoginBanner(t *testing.T) {
	service, _, _ := reconciliationService(t)
	session := pendingSession("s-111111111111", "alpha", "101")
	t.Setenv("FAKE_STATUS_BANNER", "Welcome to Delta. Scheduled maintenance Friday.")
	t.Setenv("FAKE_STATUS_LINES", "101|RUNNING|cn001|"+session.JobName)
	putSessions(t, service, session)

	listed, err := reconciledList(context.Background(), service)
	testutil.Check(t, err)
	if listed[0].State == "QUEUED" || listed[0].Error != "" || listed[0].Node != "cn001" {
		t.Fatalf("a banner ahead of the first marker discarded the round: %#v", listed[0])
	}
}

func TestRunningSessionStaysStartingUntilItsTailHasContent(t *testing.T) {
	service, _, _ := reconciliationService(t)
	session := pendingSession("s-111111111111", "alpha", "101")
	t.Setenv("FAKE_STATUS_LINES", "101|RUNNING|cn001|"+session.JobName)
	putSessions(t, service, session)

	listed, err := reconciledList(context.Background(), service)
	testutil.Check(t, err)
	if listed[0].State != "STARTING" {
		t.Fatalf("a running job with an empty tail was promoted early: %#v", listed[0])
	}

	t.Setenv("FAKE_SESSION_STDOUT", "Jupyter Server started\n")
	listed, err = reconciledList(context.Background(), service)
	testutil.Check(t, err)
	if listed[0].State != "READY" {
		t.Fatalf("a running job with a non-empty tail was not promoted: %#v", listed[0])
	}
}

func TestSessionLogTailRoundToleratesRemoteLoginBanner(t *testing.T) {
	service, _, _ := reconciliationService(t)
	session := pendingSession("s-111111111111", "alpha", "101")
	t.Setenv("FAKE_STATUS_LINES", "101|RUNNING|cn001|"+session.JobName)
	t.Setenv("FAKE_SESSION_LOG_BANNER", "Welcome to Delta. Scheduled maintenance Friday.")
	t.Setenv("FAKE_SESSION_STDOUT", "Jupyter Server started\n")
	putSessions(t, service, session)

	listed, err := reconciledList(context.Background(), service)
	testutil.Check(t, err)
	if listed[0].State != "READY" {
		t.Fatalf("a banner ahead of the first marker blocked the merge and promotion: %#v", listed[0])
	}
}

func TestStaleReconciliationRoundDoesNotNarrateARelaunchedSession(t *testing.T) {
	service, commandLog, release := reconciliationService(t)
	t.Setenv("FAKE_STATUS_RELEASE", release)
	session := pendingSession("s-111111111111", "alpha", "101")
	session.State = "READY"
	t.Setenv("FAKE_STATUS_LINES", "101|COMPLETED|cn001|"+session.JobName)
	putSessions(t, service, session)

	done := make(chan error, 1)
	go func() { done <- service.reconcileAll(context.Background()) }()
	waitForFile(t, commandLog)

	service.Logs.Forget(session.ID)
	relaunched := session
	relaunched.State, relaunched.JobID, relaunched.UpdatedAt = "SUBMITTING", "", time.Now().UTC()
	putSessions(t, service, relaunched)

	testutil.Check(t, os.WriteFile(release, []byte("ok"), 0o600))
	testutil.Check(t, <-done)
	if tail, ok := service.Logs.Tail(session.ID); ok {
		t.Fatalf("a superseded round narrated the relaunched session: %#v", tail.Lines)
	}
}

func TestStoppingATerminalSessionTwiceLeavesNoLiveTail(t *testing.T) {
	service, _, _ := reconciliationService(t)
	session := pendingSession("s-111111111111", "alpha", "101")
	session.State = "READY"
	t.Setenv("FAKE_STATUS_LINES", "101|CANCELLED||"+session.JobName)
	putSessions(t, service, session)

	_, err := service.stop(testTunnelContext(), session.ID)
	testutil.Check(t, err)
	if _, ok := service.Logs.Tail(session.ID); ok {
		t.Fatal("first stop left a live log tail behind")
	}
	_, err = service.stop(testTunnelContext(), session.ID)
	testutil.Check(t, err)
	if _, ok := service.Logs.Tail(session.ID); ok {
		t.Fatal("stopping an already-stopped session rebuilt the log tail")
	}
}

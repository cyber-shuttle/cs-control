// The refresher's own cadence: at most one reconciliation per interval, never overlapping, no failure latches.
// The poll route it drives is cached while SSH blocks, and reconciles in the background once nobody is reading.
//
//	sessionListRequest
//	refreshing
//	waitRefresh
//	Test*
package control

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cyber-shuttle/cs-control/internal/testutil"
)

func sessionListRequest(t *testing.T, api *httpAPI, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, path, nil).WithContext(testTunnelContext())
	response := httptest.NewRecorder()
	api.ServeHTTP(response, request)
	return response
}

func refreshing(refresher *sessionRefresher) bool {
	refresher.mu.Lock()
	defer refresher.mu.Unlock()
	return refresher.running
}

func waitRefresh(t *testing.T, refresher *sessionRefresher) {
	t.Helper()
	eventually(t, 3*time.Second, "the session refresh to finish", func() bool { return !refreshing(refresher) })
}

func TestTriggerStartsOneReconciliationPerIntervalAndNeverOverlaps(t *testing.T) {
	var running, total atomic.Int32
	release := make(chan struct{})
	started := make(chan struct{}, 1)
	refresher := newSessionRefresher(func(context.Context) error {
		total.Add(1)
		if running.Add(1) != 1 {
			t.Error("reconciliations overlapped")
		}
		started <- struct{}{}
		<-release
		running.Add(-1)
		return nil
	}, 50*time.Millisecond, backgroundInterval)

	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() { defer wg.Done(); refresher.Trigger() }()
	}
	wg.Wait()
	<-started
	if got := total.Load(); got != 1 {
		t.Fatalf("concurrent triggers started %d reconciliations, want 1", got)
	}
	if !refreshing(refresher) {
		t.Fatal("refresher did not report the in-flight reconciliation")
	}

	close(release)
	refresher.Close()

	refresher.Trigger()
	if refreshing(refresher) {
		t.Fatal("a trigger after close started a reconciliation")
	}
	if got := total.Load(); got != 1 {
		t.Fatalf("interval cap allowed %d reconciliations, want 1", got)
	}
}

func TestTriggerReportsFailureWithoutBlockingTheNextOne(t *testing.T) {
	var calls atomic.Int32
	reconcile := func(context.Context) error {
		calls.Add(1)
		return errors.New("scheduler unreachable")
	}
	refresher := newSessionRefresher(reconcile, 0, backgroundInterval)
	defer refresher.Close()
	refresher.Trigger()
	waitRefresh(t, refresher)
	refresher.Trigger()
	waitRefresh(t, refresher)
	if got := calls.Load(); got != 2 {
		t.Fatalf("a failed reconciliation blocked the next: %d calls", got)
	}
}

func TestHTTPSessionListReturnsCachedWhileSSHBlocksAndSingleFlights(t *testing.T) {
	service, logPath, release := reconciliationService(t)
	session := pendingSession("s-111111111111", "alpha", "101")
	t.Setenv("FAKE_STATUS_RELEASE", release)
	t.Setenv("FAKE_STATUS_LINES", "101|FAILED||"+session.JobName)
	putSessions(t, service, session)
	api := NewHTTPHandler(service, noopAuth{})
	defer api.Close()

	response := sessionListRequest(t, api, http.MethodGet, "/api/v1/sessions")
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"state":"QUEUED"`) {
		t.Fatalf("unexpected cached response: %d %s", response.Code, response.Body.String())
	}
	waitForFile(t, logPath)
	for range 20 {
		if response = sessionListRequest(t, api, http.MethodGet, "/api/v1/sessions"); response.Code != http.StatusOK {
			t.Fatal(response.Code)
		}
	}
	if data, _ := os.ReadFile(logPath); strings.Count(string(data), "csctl-session-status") != 1 {
		t.Fatalf("polling launched overlapping SSH refreshes: %s", data)
	}
	testutil.Check(t, os.WriteFile(release, []byte("ok"), 0o600))
	waitRefresh(t, api.Refresher)
	response = sessionListRequest(t, api, http.MethodGet, "/api/v1/sessions")
	if !strings.Contains(response.Body.String(), `"state":"FAILED"`) {
		t.Fatalf("merged update was not visible on next GET: %s", response.Body.String())
	}
}

func TestBackgroundTickReconcilesWithNobodyReading(t *testing.T) {
	reconciled := make(chan struct{}, 8)
	refresher := newSessionRefresher(func(context.Context) error { reconciled <- struct{}{}; return nil }, 0, time.Millisecond)
	defer refresher.Close()

	select {
	case <-reconciled:
	case <-time.After(5 * time.Second):
		t.Fatal("no reconciliation ran without a read")
	}
}

func TestCloseCancelsAnInFlightReconciliationInsteadOfWaitingOutItsTimeout(t *testing.T) {
	started := make(chan struct{})
	refresher := newSessionRefresher(func(ctx context.Context) error {
		close(started)
		<-ctx.Done()
		return ctx.Err()
	}, 0, backgroundInterval)
	refresher.Trigger()
	<-started

	closed := make(chan struct{})
	go func() { refresher.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close waited out the reconciliation's own timeout instead of cancelling it")
	}
}

func TestCloseStopsTheBackgroundTick(t *testing.T) {
	var count atomic.Int64
	refresher := newSessionRefresher(func(context.Context) error { count.Add(1); return nil }, 0, time.Millisecond)
	for start := time.Now(); count.Load() == 0 && time.Since(start) < 5*time.Second; {
		time.Sleep(time.Millisecond)
	}
	refresher.Close()
	settled := count.Load()
	time.Sleep(50 * time.Millisecond)
	if count.Load() != settled {
		t.Fatalf("the tick kept reconciling after Close: %d -> %d", settled, count.Load())
	}
}

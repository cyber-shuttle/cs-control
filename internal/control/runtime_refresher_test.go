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
)

const refresherTestToken = "runtime-refresher-test-token-123456"

func runtimeListRequest(t *testing.T, api *HTTPAPI, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, path, nil).WithContext(testTunnelContext())
	request.Header.Set("Authorization", "Bearer "+refresherTestToken)
	response := httptest.NewRecorder()
	api.ServeHTTP(response, request)
	return response
}

func waitRefresh(t *testing.T, refresher *RuntimeRefresher) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for refresher.Running() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if refresher.Running() {
		t.Fatal("runtime refresh did not finish")
	}
}

// The interval is the only thing standing between a polling browser and one SSH
// round per poll, so it is worth pinning directly.
func TestTriggerStartsOneReconciliationPerIntervalAndNeverOverlaps(t *testing.T) {
	var running, total atomic.Int32
	release := make(chan struct{})
	started := make(chan struct{}, 1)
	refresher := &RuntimeRefresher{
		interval: 50 * time.Millisecond,
		timeout:  time.Minute,
		now:      time.Now,
		reconcile: func(context.Context) error {
			total.Add(1)
			if running.Add(1) != 1 {
				t.Error("reconciliations overlapped")
			}
			started <- struct{}{}
			<-release
			running.Add(-1)
			return nil
		},
	}

	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() { defer wg.Done(); refresher.Trigger() }()
	}
	wg.Wait()
	// Trigger returns as soon as it spawns, so wait for the reconciliation it
	// spawned to actually be running before counting.
	<-started
	if got := total.Load(); got != 1 {
		t.Fatalf("concurrent triggers started %d reconciliations, want 1", got)
	}
	if !refresher.Running() {
		t.Fatal("refresher did not report the in-flight reconciliation")
	}

	close(release)
	refresher.Close()

	// Still inside the interval, so another trigger must not start SSH work.
	if refresher.Trigger() {
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
	refresher := &RuntimeRefresher{interval: 0, timeout: time.Minute, now: time.Now, reconcile: reconcile}
	refresher.Trigger()
	refresher.Close()
	// A failure must leave nothing latched, so an identically configured
	// refresher reconciles again rather than refusing.
	next := &RuntimeRefresher{interval: 0, timeout: time.Minute, now: time.Now, reconcile: reconcile}
	next.Trigger()
	next.Close()
	if got := calls.Load(); got != 2 {
		t.Fatalf("a failed reconciliation blocked the next: %d calls", got)
	}
}

func TestHTTPRuntimeListReturnsCachedWhileSSHBlocksAndSingleFlights(t *testing.T) {
	service, logPath, release := reconciliationService(t)
	runtime := pendingRuntime("rt-111111111111", "alpha", "101")
	t.Setenv("RECONCILE_RELEASE", release)
	t.Setenv("RECONCILE_LINES", "101|FAILED||"+runtime.JobName)
	putRuntimes(t, service, runtime)
	api := NewHTTPHandler(service, nil)
	defer api.Close()

	before := time.Now()
	response := runtimeListRequest(t, api, http.MethodGet, "/api/v1/runtimes")
	if elapsed := time.Since(before); elapsed > 100*time.Millisecond {
		t.Fatalf("cached GET blocked for %v", elapsed)
	}
	if response.Code != http.StatusOK ||
		!strings.Contains(response.Body.String(), `"refreshing":true`) ||
		!strings.Contains(response.Body.String(), `"state":"QUEUED"`) {
		t.Fatalf("unexpected cached response: %d %s", response.Code, response.Body.String())
	}
	waitForFile(t, logPath)
	for range 20 {
		if response = runtimeListRequest(t, api, http.MethodGet, "/api/v1/runtimes"); response.Code != http.StatusOK {
			t.Fatal(response.Code)
		}
	}
	if data, _ := os.ReadFile(logPath); strings.Count(string(data), "csctl-runtime-status") != 1 {
		t.Fatalf("polling launched overlapping SSH refreshes: %s", data)
	}
	if err := os.WriteFile(release, []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}
	waitRefresh(t, api.Refresher)
	response = runtimeListRequest(t, api, http.MethodGet, "/api/v1/runtimes")
	if !strings.Contains(response.Body.String(), `"state":"FAILED"`) {
		t.Fatalf("merged update was not visible on next GET: %s", response.Body.String())
	}
}

// Nothing reads runtime state except a request, so without a tick a runtime
// whose owner closed the tab would keep whatever state it was last seen in.
func TestBackgroundTickReconcilesWithNobodyReading(t *testing.T) {
	reconciled := make(chan struct{}, 8)
	refresher := &RuntimeRefresher{
		interval: 0, timeout: time.Minute, now: time.Now, stop: make(chan struct{}),
		reconcile: func(context.Context) error { reconciled <- struct{}{}; return nil },
	}
	refresher.wg.Add(1)
	go refresher.tick(time.Millisecond)
	defer refresher.Close()

	select {
	case <-reconciled:
	case <-time.After(5 * time.Second):
		t.Fatal("no reconciliation ran without a read")
	}
}

func TestCloseStopsTheBackgroundTick(t *testing.T) {
	var count atomic.Int64
	refresher := &RuntimeRefresher{
		interval: 0, timeout: time.Minute, now: time.Now, stop: make(chan struct{}),
		reconcile: func(context.Context) error { count.Add(1); return nil },
	}
	refresher.wg.Add(1)
	go refresher.tick(time.Millisecond)
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

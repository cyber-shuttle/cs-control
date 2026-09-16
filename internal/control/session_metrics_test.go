// The sample window's own discipline: bounded, newest-last, and copied so it shares no memory with the store.
//
//	sampleFrom
//	Test*
package control

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cyber-shuttle/cs-control/internal/credentialstore"
	"github.com/cyber-shuttle/cs-control/internal/sshexec"
	"github.com/cyber-shuttle/cs-control/internal/testutil"
)

func sampleFrom(t *testing.T, uri string) (metricSample, error) {
	t.Helper()
	service := Service{Runner: sshexec.Runner{Timeout: 2 * time.Second}, Logs: NewSessionLogs(), Metrics: NewSessionMetrics()}
	return service.sampleEndpoint(context.Background(), tunnelEndpoint{
		uri:        uri,
		credential: credentialstore.Credential{ConnectToken: "connect-token"},
	})
}

func TestSampleWindowIsBoundedAndNewestLast(t *testing.T) {
	metrics := NewSessionMetrics()
	for index := 0; index < maxSessionMetricSamples+5; index++ {
		used := int64(index)
		metrics.Append("s-111111111111", metricSample{At: time.Unix(int64(index), 0), MemBytes: &used})
	}
	series := metrics.Series("s-111111111111")
	testutil.Equal(t, len(series), maxSessionMetricSamples, "window sample count")
	if *series[len(series)-1].MemBytes != int64(maxSessionMetricSamples+4) {
		t.Fatalf("the newest sample is not last: %+v", series[len(series)-1])
	}
	metrics.Forget("s-111111111111")
	if got := metrics.Series("s-111111111111"); len(got) != 0 {
		t.Fatalf("a forgotten session kept %d samples", len(got))
	}
}

func TestSeriesDoesNotShareMemoryWithTheStore(t *testing.T) {
	metrics := NewSessionMetrics()
	used := int64(1)
	metrics.Append("s-111111111111", metricSample{MemBytes: &used})
	series := metrics.Series("s-111111111111")
	series[0] = metricSample{}
	if got := metrics.Series("s-111111111111"); got[0].MemBytes == nil {
		t.Fatal("a caller's edit reached the stored window")
	}
}

func TestSampleRefusesAnythingThatIsNotASample(t *testing.T) {
	for name, handler := range map[string]http.HandlerFunc{
		"an HTML interstitial": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("<html>tunnel offline</html>"))
		},
		"a refusal": func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusForbidden) },
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(handler)
			defer server.Close()
			if _, err := sampleFrom(t, server.URL); err == nil {
				t.Fatal("an unusable answer was read as a sample")
			}
		})
	}
}

func TestSamplerTickDoesNotPileUpRunStatsAndCloseWaitsForOneInFlight(t *testing.T) {
	ssh, _, _ := fakeSSH(t)
	runStatsLog := filepath.Join(t.TempDir(), "run-stats")
	t.Setenv("FAKE_RUN_STATS_LOG", runStatsLog)
	t.Setenv("FAKE_RUN_STATS_SLEEP_ONCE", filepath.Join(t.TempDir(), "sacct-slept-once"))
	t.Setenv("FAKE_RUN_STATS_SLEEP_SECONDS", "0.15")
	t.Setenv("FAKE_RUN_STATS_OUTPUT", sacctRows)
	service := Service{Runner: sshexec.Runner{SSHBin: ssh, Timeout: 5 * time.Second}, Store: Store{Dir: t.TempDir()}, Config: Config{HostsDir: filepath.Join(t.TempDir(), "hosts")}, Logs: NewSessionLogs(), Metrics: NewSessionMetrics()}
	registerTestHosts(t, service, testPrincipal, "delta")
	run := runRecord{runResponse: runResponse{SessionID: "s-111111111111", Seq: 1, SSHHost: "delta", EndedAt: service.now()}, Owner: testPrincipal}
	if err := service.Store.withLock(func(current *state) error {
		current.Runs = []runRecord{run}
		return service.Store.save(current)
	}); err != nil {
		t.Fatal(err)
	}

	sampler := &sessionSampler{service: service, interval: 5 * time.Millisecond, stop: make(chan struct{})}
	sampler.wg.Add(1)
	go sampler.tick()

	// Many ticks fire while the one slow sacct call is in flight; without the guard each would pile on its own call.
	time.Sleep(120 * time.Millisecond)
	sampler.Close()

	if calls := strings.Count(string(mustRead(t, runStatsLog)), "\n"); calls != 1 {
		t.Fatalf("a slow run in flight was piled on by later ticks: %d sacct calls", calls)
	}
	runs := runsIn(t, service)
	if len(runs) != 1 || runs[0].Stats == nil {
		t.Fatal("Close returned before the in-flight run stats call finished")
	}
}

func TestSampleCarriesTheTunnelAuthorizationAndIsStampedHere(t *testing.T) {
	var authorization string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorization = r.Header.Get(tunnelAuthorizationHeader)
		used, cpu := int64(2048), int64(500)
		_ = json.NewEncoder(w).Encode(metricSample{MemBytes: &used, CPUUsageUsec: &cpu,
			GPUs: []gpuSample{{Index: 0, UtilPct: 40, MemUsedMiB: 1024, MemTotalMiB: 40960}}})
	}))
	defer server.Close()
	sample, err := sampleFrom(t, server.URL)
	testutil.Check(t, err)
	if authorization != "tunnel connect-token" {
		t.Fatalf("Linkspan was asked without the tunnel credential: %q", authorization)
	}
	if sample.At.IsZero() {
		t.Fatal("the sample was not stamped when it was observed")
	}
}

func TestSampleNeverCarriesTheTunnelAuthorizationAcrossARedirect(t *testing.T) {
	var otherSawAuthorization bool
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		otherSawAuthorization = r.Header.Get(tunnelAuthorizationHeader) != ""
		w.WriteHeader(http.StatusForbidden)
	}))
	defer other.Close()
	tunnel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/steal", http.StatusFound)
	}))
	defer tunnel.Close()

	if _, err := sampleFrom(t, tunnel.URL); err == nil {
		t.Fatal("a cross-origin redirect was read as a sample")
	}
	if otherSawAuthorization {
		t.Fatal("the tunnel authorization header followed a cross-origin redirect")
	}
}

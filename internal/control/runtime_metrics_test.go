package control

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cyber-shuttle/cs-control/internal/sshexec"
)

func TestSampleWindowIsBoundedAndNewestLast(t *testing.T) {
	metrics := NewRuntimeMetrics()
	for index := 0; index < maxRuntimeMetricSamples+5; index++ {
		used := int64(index)
		metrics.Append("rt-111111111111", MetricSample{At: time.Unix(int64(index), 0), MemBytes: &used})
	}
	series := metrics.Series("rt-111111111111")
	if len(series) != maxRuntimeMetricSamples {
		t.Fatalf("window holds %d samples, want %d", len(series), maxRuntimeMetricSamples)
	}
	if *series[len(series)-1].MemBytes != int64(maxRuntimeMetricSamples+4) {
		t.Fatalf("the newest sample is not last: %+v", series[len(series)-1])
	}
	// A generation that ended is a different allocation from its replacement.
	metrics.Forget("rt-111111111111")
	if got := metrics.Series("rt-111111111111"); len(got) != 0 {
		t.Fatalf("a forgotten runtime kept %d samples", len(got))
	}
}

// Series answers with a copy, so a reader cannot mutate the store behind its lock.
func TestSeriesDoesNotShareMemoryWithTheStore(t *testing.T) {
	metrics := NewRuntimeMetrics()
	used := int64(1)
	metrics.Append("rt-111111111111", MetricSample{MemBytes: &used})
	series := metrics.Series("rt-111111111111")
	series[0] = MetricSample{}
	if got := metrics.Series("rt-111111111111"); got[0].MemBytes == nil {
		t.Fatal("a caller's edit reached the stored window")
	}
}

// The tunnel edge answers 200 with an interstitial page once the host is gone,
// so a body that parses is the liveness signal, not the status.
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

func TestSampleCarriesTheTunnelAuthorizationAndIsStampedHere(t *testing.T) {
	var authorization string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorization = r.Header.Get(tunnelAuthorizationHeader)
		used, cpu := int64(2048), int64(500)
		_ = json.NewEncoder(w).Encode(MetricSample{MemBytes: &used, CPUUsageUsec: &cpu,
			GPUs: []GPUSample{{Index: 0, UtilPct: 40, MemUsedMiB: 1024, MemTotalMiB: 40960}}})
	}))
	defer server.Close()
	sample, err := sampleFrom(t, server.URL)
	if err != nil {
		t.Fatal(err)
	}
	// Dev Tunnels authorizes a non-anonymous port with its own header, not with
	// the Authorization the allocation's Jupyter token uses.
	if authorization != "tunnel connect-token" {
		t.Fatalf("Linkspan was asked without the tunnel credential: %q", authorization)
	}
	if *sample.MemBytes != 2048 || *sample.CPUUsageUsec != 500 || len(sample.GPUs) != 1 {
		t.Fatalf("the sample lost figures in transit: %+v", sample)
	}
	// Linkspan does not stamp its own reading, and a rate needs the local clock.
	if sample.At.IsZero() {
		t.Fatal("the sample was not stamped when it was observed")
	}
}

// The transport is exercised on its own: a Dev Tunnel URI is required to be a
// devtunnels.ms host, which a local test server can never be.
func sampleFrom(t *testing.T, uri string) (MetricSample, error) {
	t.Helper()
	service := Service{Runner: sshexec.Runner{Timeout: 2 * time.Second}}
	return service.sampleEndpoint(context.Background(), tunnelEndpoint{
		uri:        uri,
		credential: GenerationCredential{ConnectToken: "connect-token"},
	})
}

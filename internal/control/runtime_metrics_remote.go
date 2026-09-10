package control

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/cyber-shuttle/cs-control/internal/httpx"
)

// A sample is three small numbers and a short GPU list; anything larger is not
// one, and reading it would be the tunnel edge's interstitial page.
const maxMetricBodyBytes = 64 << 10

// Dev Tunnels authorizes a non-anonymous port with its own header rather than
// with Authorization, which the allocation's Jupyter identity token uses.
const tunnelAuthorizationHeader = "X-Tunnel-Authorization"

// sampleRuntime reads one live sample from the Linkspan the allocation is
// running, over the control port already declared on its tunnel.
func (s Service) sampleRuntime(ctx context.Context, runtime Runtime) (MetricSample, error) {
	endpoint, err := s.allocationEndpoint(ctx, runtime, allocationPorts(runtime.ID, runtime.Generation).control)
	if err != nil {
		return MetricSample{}, err
	}
	return s.sampleEndpoint(ctx, endpoint)
}

// sampleEndpoint is the read itself, once the allocation has been resolved to a
// reachable Linkspan.
func (s Service) sampleEndpoint(ctx context.Context, endpoint tunnelEndpoint) (MetricSample, error) {
	request, err := httpx.NewRequest(ctx, http.MethodGet, endpoint.uri+"/api/v1/metrics", "", nil)
	if err != nil {
		return MetricSample{}, err
	}
	request.Header.Set(tunnelAuthorizationHeader, "tunnel "+endpoint.credential.ConnectToken)
	body, status, err := httpx.Do(httpx.BoundedClient(nil, s.Runner.EffectiveTimeout()), request, maxMetricBodyBytes)
	if err != nil {
		return MetricSample{}, err
	}
	if status != http.StatusOK {
		return MetricSample{}, errors.New("Linkspan did not answer with a sample")
	}
	// The tunnel edge answers 200 with an HTML page once the host is gone, so a
	// body that parses is the real liveness signal, not the status.
	var sample MetricSample
	if err := json.Unmarshal(body, &sample); err != nil {
		return MetricSample{}, errors.New("Linkspan returned no sample")
	}
	sample.At = s.now()
	return sample, nil
}

// RuntimeSampler keeps a window of live resource samples for every allocation
// that is running. It is separate from RuntimeRefresher because that batches one
// SSH round per host, while this is one HTTPS call per runtime to the node
// itself: neither cadence nor failure of one belongs to the other.
type RuntimeSampler struct {
	service  Service
	metrics  *RuntimeMetrics
	interval time.Duration

	wg   sync.WaitGroup
	stop chan struct{}
	once sync.Once
}

func NewRuntimeSampler(service Service, metrics *RuntimeMetrics) *RuntimeSampler {
	sampler := &RuntimeSampler{service: service, metrics: metrics, interval: metricSampleInterval, stop: make(chan struct{})}
	sampler.wg.Add(1)
	go sampler.tick()
	return sampler
}

func (r *RuntimeSampler) tick() {
	defer r.wg.Done()
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	for {
		select {
		case <-r.stop:
			return
		case <-ticker.C:
			r.sampleOnce()
			r.completeRunStats()
		}
	}
}

// sampleOnce reads every running allocation concurrently: they are independent
// hosts, and one that has stopped answering must not hold up the rest.
func (r *RuntimeSampler) sampleOnce() {
	runtimes, err := r.service.ListCached()
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), r.interval)
	defer cancel()
	var group sync.WaitGroup
	for _, runtime := range runtimes {
		if runtime.State != "READY" || runtime.Tunnel.ID == "" {
			continue
		}
		group.Add(1)
		go func(runtime Runtime) {
			defer group.Done()
			sample, err := r.service.sampleRuntime(ctx, runtime)
			if err != nil {
				// A missed sample is a gap in a window, not a fault: the allocation
				// may be between states or the node briefly unreachable.
				return
			}
			r.metrics.Append(runtime.ID, sample)
		}(runtime)
	}
	group.Wait()
}

// completeRunStats rides the same tick: Slurm's accounting for a just-finished
// run lands a beat after the job does, so the read is retried until it does.
// Bounded like a sample, so a login node that stopped answering does not stall
// the next one.
func (r *RuntimeSampler) completeRunStats() {
	ctx, cancel := context.WithTimeout(context.Background(), r.interval)
	defer cancel()
	r.service.completeRunStats(ctx)
}

func (r *RuntimeSampler) Close() {
	r.once.Do(func() { close(r.stop) })
	r.wg.Wait()
}

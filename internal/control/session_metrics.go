// A resource sample is read from the session's own Linkspan over its tunnel's control port, every five seconds.
// sessionMetrics keeps a bounded window per session, apart from persisted state.
// The sampler runs on its own cadence, so one dead node's HTTP timeout never holds up the rest.
//
//	maxSessionMetricSamples, metricSampleInterval
//	gpuSample, metricSample, sessionSeries
//	sessionMetrics, Append, Series, Forget
//	maxMetricBodyBytes, tunnelAuthorizationHeader
//	sessionSampler, newSessionSampler
//	tick, sampleOnce, Close
//	NewSessionMetrics
//	Service
//	sampleSession, sampleEndpoint
package control

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cyber-shuttle/cs-control/internal/httpx"
)

const (
	maxSessionMetricSamples = 20
	metricSampleInterval    = 5 * time.Second
)

type gpuSample struct {
	Index       int `json:"index"`
	UtilPct     int `json:"utilPct"`
	MemUsedMiB  int `json:"memUsedMiB"`
	MemTotalMiB int `json:"memTotalMiB"`
}

type metricSample struct {
	At           time.Time   `json:"at"`
	MemBytes     *int64      `json:"memBytes,omitempty"`
	CPUUsageUsec *int64      `json:"cpuUsageUsec,omitempty"`
	GPUs         []gpuSample `json:"gpus,omitempty"`
}

type sessionSeries struct {
	SessionID string         `json:"sessionId"`
	Samples   []metricSample `json:"samples"`
}

type sessionMetrics struct {
	mu     sync.RWMutex
	series map[string][]metricSample
}

func (m *sessionMetrics) Append(sessionID string, sample metricSample) {
	m.mu.Lock()
	defer m.mu.Unlock()
	kept := append(append([]metricSample(nil), m.series[sessionID]...), sample)
	if len(kept) > maxSessionMetricSamples {
		kept = append([]metricSample(nil), kept[len(kept)-maxSessionMetricSamples:]...)
	}
	m.series[sessionID] = kept
}

func (m *sessionMetrics) Series(sessionID string) []metricSample {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append(make([]metricSample, 0, len(m.series[sessionID])), m.series[sessionID]...)
}

func (m *sessionMetrics) Forget(sessionID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.series, sessionID)
}

const maxMetricBodyBytes = 64 << 10

const tunnelAuthorizationHeader = "X-Tunnel-Authorization"

type sessionSampler struct {
	service  Service
	interval time.Duration

	wg            sync.WaitGroup
	stop          chan struct{}
	once          sync.Once
	statsInFlight atomic.Bool
}

func newSessionSampler(service Service) *sessionSampler {
	sampler := &sessionSampler{service: service, interval: metricSampleInterval, stop: make(chan struct{})}
	sampler.wg.Add(1)
	go sampler.tick()
	return sampler
}

func (r *sessionSampler) tick() {
	defer r.wg.Done()
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	for {
		select {
		case <-r.stop:
			return
		case <-ticker.C:
			r.sampleOnce()
			if r.statsInFlight.CompareAndSwap(false, true) {
				r.wg.Add(1)
				go func() {
					defer r.wg.Done()
					defer r.statsInFlight.Store(false)
					r.service.completeRunStats()
				}()
			}
		}
	}
}

func (r *sessionSampler) sampleOnce() {
	sessions, err := r.service.loadSessions()
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), r.interval)
	defer cancel()
	var group sync.WaitGroup
	for _, session := range sessions {
		if session.State != "READY" || session.Tunnel.ID == "" {
			continue
		}
		group.Add(1)
		go func(session Session) {
			defer group.Done()
			sample, err := r.service.sampleSession(ctx, session)
			if err != nil {
				return
			}
			r.service.Metrics.Append(session.ID, sample)
		}(session)
	}
	group.Wait()
}

func (r *sessionSampler) Close() {
	r.once.Do(func() { close(r.stop) })
	r.wg.Wait()
}

func NewSessionMetrics() *sessionMetrics {
	return &sessionMetrics{series: make(map[string][]metricSample)}
}

func (s Service) sampleSession(ctx context.Context, session Session) (metricSample, error) {
	endpoint, err := s.sessionEndpoint(ctx, session, sessionPorts(session.ID, session.Seq).control)
	if err != nil {
		return metricSample{}, err
	}
	return s.sampleEndpoint(ctx, endpoint)
}

func (s Service) sampleEndpoint(ctx context.Context, endpoint tunnelEndpoint) (metricSample, error) {
	request, err := httpx.NewRequest(ctx, http.MethodGet, endpoint.uri+"/api/v1/metrics", "", nil)
	if err != nil {
		return metricSample{}, err
	}
	request.Header.Set(tunnelAuthorizationHeader, "tunnel "+endpoint.credential.ConnectToken)
	body, status, err := httpx.Do(httpx.GuardedClient(nil, s.Runner.EffectiveTimeout(), httpx.SameOriginRedirect), request, maxMetricBodyBytes)
	if err != nil {
		return metricSample{}, err
	}
	if status != http.StatusOK {
		return metricSample{}, errors.New("Linkspan did not answer with a sample")
	}
	var sample metricSample
	if err := json.Unmarshal(body, &sample); err != nil {
		return metricSample{}, errors.New("Linkspan returned no sample")
	}
	sample.At = s.now()
	return sample, nil
}

package control

import (
	"sync"
	"time"
)

// Twenty samples five seconds apart: the window cs-bridge shows, and enough of
// one to differentiate a cumulative CPU counter into a rate that means anything.
const (
	maxRuntimeMetricSamples = 20
	metricSampleInterval    = 5 * time.Second
)

// GPUSample is one device as the allocation's node reported it.
type GPUSample struct {
	Index       int `json:"index"`
	UtilPct     int `json:"utilPct"`
	MemUsedMiB  int `json:"memUsedMiB"`
	MemTotalMiB int `json:"memTotalMiB"`
}

// MetricSample is one reading of what an allocation is actually using, stamped
// when it was observed here. Every figure is optional: a host has no GPUs to
// report, and a cgroup file that cannot be read is absent rather than zero,
// which for a cumulative counter is a different claim entirely.
type MetricSample struct {
	At           time.Time   `json:"at"`
	MemBytes     *int64      `json:"memBytes,omitempty"`
	CPUUsageUsec *int64      `json:"cpuUsageUsec,omitempty"`
	GPUs         []GPUSample `json:"gpus,omitempty"`
}

// RuntimeSeries is one runtime's complete current window.
type RuntimeSeries struct {
	RuntimeID string         `json:"runtimeId"`
	Samples   []MetricSample `json:"samples"`
}

// RuntimeMetrics is a bounded process-local store of resource samples, held
// apart from persisted state for the reason RuntimeLogs is: a window on a
// running allocation is not a fact about it, and rewriting state.json every
// five seconds to hold one would be the wrong store.
type RuntimeMetrics struct {
	mu     sync.RWMutex
	series map[string][]MetricSample
}

func NewRuntimeMetrics() *RuntimeMetrics {
	return &RuntimeMetrics{series: make(map[string][]MetricSample)}
}

func (m *RuntimeMetrics) Append(runtimeID string, sample MetricSample) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	kept := append(m.series[runtimeID], sample)
	if len(kept) > maxRuntimeMetricSamples {
		kept = append([]MetricSample(nil), kept[len(kept)-maxRuntimeMetricSamples:]...)
	}
	m.series[runtimeID] = kept
}

// Series answers with a copy, so no reader shares memory with the lock.
func (m *RuntimeMetrics) Series(runtimeID string) []MetricSample {
	if m == nil {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]MetricSample(nil), m.series[runtimeID]...)
}

// Forget drops a runtime's window. A generation that ended is a different
// allocation from the one that replaces it, so its samples never carry over.
func (m *RuntimeMetrics) Forget(runtimeID string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.series, runtimeID)
}

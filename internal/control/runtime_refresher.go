package control

import (
	"context"
	"log"
	"sync"
	"time"
)

// RuntimeRefresher runs at most one scheduler reconciliation at a time, and no
// more often than once a second. Every read triggers it, and that is the whole
// schedule: nothing observes runtime state except a request, so there is no
// background cadence to keep in step with one. Tunnel expiry remains the
// cleanup backstop for a runtime nobody ever asks about again.
type RuntimeRefresher struct {
	reconcile func(context.Context) error
	interval  time.Duration
	timeout   time.Duration
	now       func() time.Time

	mu        sync.Mutex
	running   bool
	completed time.Time
	closed    bool
	wg        sync.WaitGroup
}

func NewRuntimeRefresher(service Service) *RuntimeRefresher {
	return &RuntimeRefresher{
		reconcile: service.ReconcileAll,
		interval:  time.Second,
		timeout:   60 * time.Second,
		now:       time.Now,
	}
}

// Trigger starts a reconciliation unless one is already running or the last one
// finished less than interval ago, and reports whether one is now in flight.
// The interval is login-node load protection and nothing bypasses it.
func (r *RuntimeRefresher) Trigger() bool {
	r.mu.Lock()
	switch {
	case r.closed:
		r.mu.Unlock()
		return false
	case r.running:
		r.mu.Unlock()
		return true
	case r.now().Sub(r.completed) < r.interval:
		r.mu.Unlock()
		return false
	}
	r.running = true
	r.wg.Add(1)
	r.mu.Unlock()
	go func() {
		defer r.wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
		defer cancel()
		if err := r.reconcile(ctx); err != nil {
			log.Printf("runtime reconciliation failed: %v", err)
		}
		r.mu.Lock()
		r.running, r.completed = false, r.now()
		r.mu.Unlock()
	}()
	return true
}

func (r *RuntimeRefresher) Running() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.running
}

func (r *RuntimeRefresher) Close() {
	r.mu.Lock()
	r.closed = true
	r.mu.Unlock()
	r.wg.Wait()
}

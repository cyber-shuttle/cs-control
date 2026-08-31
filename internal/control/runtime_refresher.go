package control

import (
	"context"
	"log"
	"sync"
	"time"
)

// backgroundInterval is how often a runtime nobody is watching is reconciled.
// Slow on purpose: a viewer polls far more often, so this tick only matters once
// the owner has closed the tab, at one batched SSH round per host.
const backgroundInterval = 30 * time.Second

// RuntimeRefresher runs at most one scheduler reconciliation at a time and no
// more often than once a second. Every read triggers one, so a viewer converges
// at its own polling rate, and a background tick reconciles for an owner who has
// closed the tab.
type RuntimeRefresher struct {
	reconcile func(context.Context) error
	interval  time.Duration
	timeout   time.Duration

	mu        sync.Mutex
	running   bool
	completed time.Time
	closed    bool
	wg        sync.WaitGroup
	stop      chan struct{}
}

func NewRuntimeRefresher(service Service) *RuntimeRefresher {
	refresher := &RuntimeRefresher{
		reconcile: service.ReconcileAll,
		interval:  time.Second,
		timeout:   60 * time.Second,
		stop:      make(chan struct{}),
	}
	refresher.wg.Add(1)
	go refresher.tick(backgroundInterval)
	return refresher
}

// tick reconciles on a slow cadence whether or not anyone is reading. Trigger
// collapses a tick landing on a viewer's poll, and reconciliation makes no SSH
// call when nothing is worth observing, so an idle control plane stays idle.
func (r *RuntimeRefresher) tick(every time.Duration) {
	defer r.wg.Done()
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-r.stop:
			return
		case <-ticker.C:
			r.Trigger()
		}
	}
}

// Trigger starts a reconciliation unless one is running or the last finished
// less than interval ago, and reports whether one is now in flight. The interval
// is login-node load protection and nothing bypasses it.
func (r *RuntimeRefresher) Trigger() bool {
	r.mu.Lock()
	switch {
	case r.closed:
		r.mu.Unlock()
		return false
	case r.running:
		r.mu.Unlock()
		return true
	case time.Since(r.completed) < r.interval:
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
		r.running, r.completed = false, time.Now()
		r.mu.Unlock()
	}()
	return true
}

func (r *RuntimeRefresher) Close() {
	r.mu.Lock()
	alreadyClosed := r.closed
	r.closed = true
	r.mu.Unlock()
	// A refresher a test built as a struct literal has no tick to stop.
	if !alreadyClosed && r.stop != nil {
		close(r.stop)
	}
	r.wg.Wait()
}

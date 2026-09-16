// The scheduler poll cadence: at most one reconciliation in flight, no more often than once a second.
// Every read triggers one, plus a slow background tick covers an owner who has closed the tab.
//
//	backgroundInterval, refreshTimeout
//	sessionRefresher, newSessionRefresher
//	tick
//	Trigger
//	Close
package control

import (
	"context"
	"log"
	"sync"
	"time"
)

const (
	backgroundInterval = 30 * time.Second
	refreshTimeout     = 60 * time.Second
)

type sessionRefresher struct {
	reconcile func(context.Context) error
	interval  time.Duration
	timeout   time.Duration
	ctx       context.Context
	cancel    context.CancelFunc

	mu        sync.Mutex
	running   bool
	completed time.Time
	wg        sync.WaitGroup
}

func newSessionRefresher(reconcile func(context.Context) error, interval, background time.Duration) *sessionRefresher {
	ctx, cancel := context.WithCancel(context.Background())
	refresher := &sessionRefresher{reconcile: reconcile, interval: interval, timeout: refreshTimeout, ctx: ctx, cancel: cancel}
	refresher.wg.Add(1)
	go refresher.tick(background)
	return refresher
}

func (r *sessionRefresher) tick(every time.Duration) {
	defer r.wg.Done()
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-r.ctx.Done():
			return
		case <-ticker.C:
			r.Trigger()
		}
	}
}

func (r *sessionRefresher) Trigger() {
	r.mu.Lock()
	switch {
	case r.ctx.Err() != nil, r.running, time.Since(r.completed) < r.interval:
		r.mu.Unlock()
		return
	}
	r.running = true
	r.wg.Add(1)
	r.mu.Unlock()
	go func() {
		defer r.wg.Done()
		ctx, cancel := context.WithTimeout(r.ctx, r.timeout)
		defer cancel()
		if err := r.reconcile(ctx); err != nil {
			log.Printf("session reconciliation failed: %v", err)
		}
		r.mu.Lock()
		r.running, r.completed = false, time.Now()
		r.mu.Unlock()
	}()
}

func (r *sessionRefresher) Close() {
	r.cancel()
	r.wg.Wait()
}

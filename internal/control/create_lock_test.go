// Create's own lock discipline. The store lock must not be held across the slow Dev Tunnels create call.
//
//	Test*
package control

import (
	"testing"
	"time"

	"github.com/cyber-shuttle/cs-control/internal/testutil"
)

func TestCreateDoesNotHoldStoreLockDuringTunnelCreate(t *testing.T) {
	service := testService(t)
	manager := service.Tunnels.(*testTunnelManager)
	manager.createStarted = make(chan struct{})
	manager.createBlock = make(chan struct{})

	done := make(chan error, 1)
	go func() {
		_, err := service.create(testTunnelContext(), newTestCreateRequest())
		done <- err
	}()

	select {
	case <-manager.createStarted:
	case <-time.After(time.Second):
		t.Fatal("tunnel create was never reached")
	}

	lockAvailable := make(chan error, 1)
	go func() { lockAvailable <- service.Store.withLock(func(*state) error { return nil }) }()
	select {
	case err := <-lockAvailable:
		testutil.Check(t, err)
	case <-time.After(300 * time.Millisecond):
		t.Fatal("state lock was held during blocked tunnel create")
	}

	close(manager.createBlock)
	testutil.Check(t, <-done)
}

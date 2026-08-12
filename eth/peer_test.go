package eth

import (
	"crypto/rand"
	"sync"
	"testing"
	"time"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/p2p"
	"github.com/XinFinOrg/XDPoSChain/p2p/enode"
)

func TestPeerSetRegisterRejectsDuplicateID(t *testing.T) {
	peers := newPeerSet()
	first := &peer{id: "dup"}
	second := &peer{id: "dup"}

	if err := peers.Register(first); err != nil {
		t.Fatalf("first register failed: %v", err)
	}
	if err := peers.Register(second); err != errAlreadyRegistered {
		t.Fatalf("second register error mismatch: got %v want %v", err, errAlreadyRegistered)
	}
	if peers.Len() != 1 {
		t.Fatalf("peer set size mismatch: got %d want 1", peers.Len())
	}
	if got := peers.Peer("dup"); got != first {
		t.Fatalf("registered peer replaced: got %p want %p", got, first)
	}
}

// TestPeerSetUnregisterTerminatesBroadcasters ensures that Unregister closes
// p.term, so the peer's broadcast goroutines wind down when the peer is removed.
// The loops only exit via p.term (or a send error), so without this the
// goroutines leak and retain the peer for the lifetime of the process.
func TestPeerSetUnregisterTerminatesBroadcasters(t *testing.T) {
	peers := newPeerSet()

	app, net := p2p.MsgPipe()
	defer app.Close()
	defer net.Close()
	var id enode.ID
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatalf("failed to generate random peer id: %v", err)
	}
	// Use xdc165 so Register also starts the transaction announcer; the wait
	// below then covers all three broadcast goroutines, not just two.
	p := newPeer(xdc165, p2p.NewPeer(id, "unregister", nil), net, func(common.Hash) *types.Transaction { return nil })
	if err := peers.Register(p); err != nil {
		t.Fatalf("first register failed: %v", err)
	}
	if err := peers.Unregister(p.id); err != nil {
		t.Fatalf("unregister failed: %v", err)
	}
	// Unregister only closes term to signal the broadcasters; wait until the
	// goroutines have actually exited so the leak this guards against is
	// detected, not merely the close of the channel.
	waitBroadcasters(t, &p.broadcastWg)
	// A second unregister must fail cleanly and must not close term again.
	if err := peers.Unregister(p.id); err != errNotRegistered {
		t.Fatalf("second unregister error mismatch: got %v want %v", err, errNotRegistered)
	}
}

// waitBroadcasters blocks until the peer's broadcast goroutines have exited,
// or fails the test if they are still running after the grace period.
func waitBroadcasters(t *testing.T, wg *sync.WaitGroup) {
	t.Helper()
	const gracePeriod = 2 * time.Second

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(gracePeriod):
		t.Fatalf("waitBroadcasters: broadcast goroutines still running after %v, want them to terminate", gracePeriod)
	}
}

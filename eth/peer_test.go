package eth

import (
	"crypto/rand"
	"math/big"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/crypto"
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

// countingMsgWriter wraps a p2p.MsgReadWriter and counts every write attempt,
// allowing tests to assert that a peer stops sending after a network error.
type countingMsgWriter struct {
	p2p.MsgReadWriter
	writes atomic.Int32
}

func (c *countingMsgWriter) WriteMsg(msg p2p.Msg) error {
	c.writes.Add(1)
	return c.MsgReadWriter.WriteMsg(msg)
}

// newBroadcastTestPeer assembles a peer whose network connection is already
// broken, so the first send from any broadcast loop fails. The returned
// terminate function closes the peer exactly once and is safe to call from
// anywhere, including t.Cleanup and the test body itself.
func newBroadcastTestPeer(t *testing.T, name string) (*peer, *types.Transaction, *countingMsgWriter, func()) {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}
	tx, err := types.SignTx(types.NewTransaction(0, common.Address{}, big.NewInt(1), 100000, big.NewInt(1), nil), types.HomesteadSigner{}, key)
	if err != nil {
		t.Fatalf("failed to sign test transaction: %v", err)
	}
	app, net := p2p.MsgPipe()
	var id enode.ID
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatalf("failed to generate random peer id: %v", err)
	}
	counter := &countingMsgWriter{MsgReadWriter: net}
	p := newPeer(xdc100, p2p.NewPeer(id, name, nil), counter, func(common.Hash) *types.Transaction { return tx })
	var closeOnce sync.Once
	terminate := func() { closeOnce.Do(p.close) }
	t.Cleanup(terminate)
	app.Close()
	return p, tx, counter, terminate
}

// runDrainCheck performs repeated asynchronous sends through send and fails the
// test if any of them blocks, which would indicate that the peer's broadcast
// loop stopped draining its queue after a send error. On a blocked send it
// terminates the peer first, so the stuck sender unblocks via p.term and cannot
// leak after the test has aborted.
func runDrainCheck(t *testing.T, what string, send, terminate func()) {
	t.Helper()
	for i := 0; i < 50; i++ {
		sent := make(chan struct{})
		go func() {
			defer close(sent)
			send()
		}()
		select {
		case <-sent:
		case <-time.After(5 * time.Second):
			terminate()
			// The blocked sender unblocks via p.term; join it before failing so
			// the failure path cannot leak the goroutine.
			<-sent
			t.Fatalf("%s blocked on attempt %d: the peer stopped draining after a send error", what, i)
		}
	}
}

// waitForWrites waits until the wrapped connection has seen its first write
// attempt and reports the total number of attempts observed so far. The
// broadcast loops launch at most one sender at a time and never start a new one
// after a failure, so once the count reaches one it must never grow again. The
// test fails if no write attempt is observed before the deadline.
func waitForWrites(t *testing.T, counter *countingMsgWriter) int32 {
	t.Helper()
	const deadline = 5 * time.Second

	timeout := time.NewTimer(deadline)
	defer timeout.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for counter.writes.Load() == 0 {
		select {
		case <-timeout.C:
			t.Fatalf("waitForWrites: no write attempt observed within %v, want 1", deadline)
		case <-ticker.C:
		}
	}
	return counter.writes.Load()
}

// TestBroadcastTransactionsKeepsDrainingAfterSendFailure reproduces the mainnet freeze:
// the broadcaster used to return on the first send error, leaving p.txBroadcast without a
// reader. Since p.term is only closed once the peer handler unwinds, every later
// AsyncSendTransactions blocked forever and took txBroadcastLoop, and through it the
// transaction pool, down with it.
func TestBroadcastTransactionsKeepsDrainingAfterSendFailure(t *testing.T) {
	p, tx, counter, terminate := newBroadcastTestPeer(t, "broadcaster")
	broadcastDone := make(chan struct{})
	go func() {
		defer close(broadcastDone)
		p.broadcastTransactions()
	}()
	t.Cleanup(func() { terminate(); <-broadcastDone })

	runDrainCheck(t, "AsyncSendTransactions", func() { p.AsyncSendTransactions([]common.Hash{tx.Hash()}) }, terminate)

	// The connection is broken, so the very first broadcast fails. After that
	// the broadcaster must only drain its queue and never attempt another write.
	if got := waitForWrites(t, counter); got != 1 {
		t.Fatalf("write attempts after failed send: got %d, want 1", got)
	}
	// Extra batches still have to drain without blocking or resending.
	runDrainCheck(t, "AsyncSendTransactions after failure", func() { p.AsyncSendTransactions([]common.Hash{tx.Hash()}) }, terminate)
	if got := counter.writes.Load(); got != 1 {
		t.Fatalf("write attempts after further drain: got %d, want 1", got)
	}
}

// TestAnnounceTransactionsKeepsDrainingAfterSendFailure is the announce-side
// counterpart: the announcer has to keep servicing p.txAnnounce until p.term,
// otherwise AsyncSendPooledTransactionHashes blocks forever.
func TestAnnounceTransactionsKeepsDrainingAfterSendFailure(t *testing.T) {
	p, tx, counter, terminate := newBroadcastTestPeer(t, "announcer")
	broadcastDone := make(chan struct{})
	go func() {
		defer close(broadcastDone)
		p.announceTransactions()
	}()
	t.Cleanup(func() { terminate(); <-broadcastDone })

	runDrainCheck(t, "AsyncSendPooledTransactionHashes", func() { p.AsyncSendPooledTransactionHashes([]common.Hash{tx.Hash()}) }, terminate)

	// The connection is broken, so the very first announcement fails. After that
	// the announcer must only drain its queue and never attempt another write.
	if got := waitForWrites(t, counter); got != 1 {
		t.Fatalf("write attempts after failed send: got %d, want 1", got)
	}
	// Extra batches still have to drain without blocking or resending.
	runDrainCheck(t, "AsyncSendPooledTransactionHashes after failure", func() { p.AsyncSendPooledTransactionHashes([]common.Hash{tx.Hash()}) }, terminate)
	if got := counter.writes.Load(); got != 1 {
		t.Fatalf("write attempts after further drain: got %d, want 1", got)
	}
}

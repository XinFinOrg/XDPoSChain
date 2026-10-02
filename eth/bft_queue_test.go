package eth

import (
	"math/big"
	"testing"
	"time"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/eth/downloader"
	"github.com/XinFinOrg/XDPoSChain/p2p"
	"github.com/XinFinOrg/XDPoSChain/p2p/enode"
)

func syncingFn(v bool) func() bool { return func() bool { return v } }

func TestBFTQueueEnqueueOnlyWhileSyncing(t *testing.T) {
	q := newBFTQueue()
	if q.enqueueIf(syncingFn(false), "p", common.Hash{1}, &types.Vote{}) {
		t.Fatal("message queued while not syncing")
	}
	if !q.enqueueIf(syncingFn(true), "p", common.Hash{1}, &types.Vote{}) {
		t.Fatal("message not queued while syncing")
	}
	// A duplicate is accepted but stored once.
	if !q.enqueueIf(syncingFn(true), "p", common.Hash{1}, &types.Vote{}) {
		t.Fatal("duplicate not accepted while syncing")
	}
	if n := q.len(); n != 1 {
		t.Fatalf("queue length: have %d, want 1", n)
	}
}

func TestBFTQueueTakeKeepsWhileSyncing(t *testing.T) {
	q := newBFTQueue()
	q.enqueueIf(syncingFn(true), "p", common.Hash{1}, &types.Vote{})

	if msgs := q.takeUnless(syncingFn(true)); msgs != nil {
		t.Fatalf("queue taken while syncing: %d messages", len(msgs))
	}
	msgs := q.takeUnless(syncingFn(false))
	if len(msgs) != 1 || msgs[0].hash != (common.Hash{1}) || msgs[0].peer != "p" {
		t.Fatalf("unexpected taken messages: %+v", msgs)
	}
	if n := q.len(); n != 0 {
		t.Fatalf("queue length after take: have %d, want 0", n)
	}
	// The hash set is reset too, so the same message can be queued again.
	q.enqueueIf(syncingFn(true), "p", common.Hash{1}, &types.Vote{})
	if n := q.len(); n != 1 {
		t.Fatalf("queue length after requeue: have %d, want 1", n)
	}
}

func TestBFTQueueDropsOldestWhenFull(t *testing.T) {
	q := newBFTQueue()
	for i := 0; i < maxQueuedBFTMsgs+1; i++ {
		q.enqueueIf(syncingFn(true), "p", common.BigToHash(big.NewInt(int64(i))), &types.Vote{})
	}
	msgs := q.takeUnless(syncingFn(false))
	if len(msgs) != maxQueuedBFTMsgs {
		t.Fatalf("queue length: have %d, want %d", len(msgs), maxQueuedBFTMsgs)
	}
	if first := msgs[0].hash; first != common.BigToHash(big.NewInt(1)) {
		t.Fatalf("oldest message not dropped, first hash %x", first)
	}
	if last := msgs[len(msgs)-1].hash; last != common.BigToHash(big.NewInt(maxQueuedBFTMsgs)) {
		t.Fatalf("newest message missing, last hash %x", last)
	}
}

func TestSyncRetryDelay(t *testing.T) {
	tests := []struct {
		failures int
		want     time.Duration
	}{
		{1, 10 * time.Second},
		{2, 20 * time.Second},
		{3, 40 * time.Second},
		{5, 160 * time.Second},
		{6, syncRetryMaxDelay},
		{100, syncRetryMaxDelay},
	}
	for _, tt := range tests {
		if got := syncRetryDelay(tt.failures); got != tt.want {
			t.Errorf("failures %d: have %v, want %v", tt.failures, got, tt.want)
		}
	}
}

// Tests that a vote received while the downloader is synchronising is queued
// instead of dropped, and handed to the BFT handler once the sync ends.
func TestVoteQueuedDuringSync(t *testing.T) {
	pm, _ := newTestProtocolManagerMust(t, downloader.FullSync, 0, nil, nil)
	defer pm.Stop()

	app, net := p2p.MsgPipe()
	defer app.Close()
	peer := pm.newPeer(xdc100, p2p.NewPeer(enode.ID{1}, "bft-queue-peer", nil), net, pm.txpool.Get)
	if err := pm.peers.Register(peer); err != nil {
		t.Fatalf("failed to register peer: %v", err)
	}
	defer pm.peers.Unregister(peer.id)

	current := pm.blockchain.CurrentBlock()
	localTD := pm.blockchain.GetTd(current.Hash(), current.Number.Uint64())
	peer.lock.Lock()
	peer.head = current.Hash()
	peer.td = new(big.Int).Add(localTD, big.NewInt(100))
	peer.lock.Unlock()

	// Hold the downloader in a synchronising state.
	stub := newStalledDownloaderPeer(pm.downloader, peer.id, pm.blockchain.Genesis().Header())
	if err := pm.downloader.RegisterPeer(peer.id, xdc100, stub); err != nil {
		t.Fatalf("failed to register downloader peer: %v", err)
	}
	defer pm.downloader.UnregisterPeer(peer.id)
	defer stub.release()

	syncDone := make(chan error, 1)
	go func() { syncDone <- pm.synchronise(peer) }()

	deadline := time.After(30 * time.Second)
	for !pm.downloader.Synchronising() {
		select {
		case <-deadline:
			t.Fatal("downloader never started synchronising")
		case <-time.After(time.Millisecond):
		}
	}

	// The vote is far from the local head, so the BFT handler discards it
	// without verification once it is processed.
	vote := &types.Vote{ProposedBlockInfo: &types.BlockInfo{Number: big.NewInt(1_000_000), Round: 1}}
	hash := vote.Hash()
	go p2p.Send(app, VoteMsg, vote)
	if err := pm.handleMsg(peer); err != nil {
		t.Fatalf("handleMsg failed: %v", err)
	}
	if n := pm.bftQueue.len(); n != 1 {
		t.Fatalf("queued messages during sync: have %d, want 1", n)
	}
	if pm.knownVotes.Contains(hash) {
		t.Fatal("vote marked as known before it was processed")
	}

	// End the sync; the queued vote must then be processed.
	stub.release()
	pm.downloader.UnregisterPeer(peer.id)
	select {
	case <-syncDone:
	case <-time.After(30 * time.Second):
		t.Fatal("sync did not finish")
	}
	if n := pm.bftQueue.len(); n != 0 {
		t.Fatalf("queued messages after sync: have %d, want 0", n)
	}
	if !pm.knownVotes.Contains(hash) {
		t.Fatal("queued vote not processed after sync")
	}
}

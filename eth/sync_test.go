// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package eth

import (
	"bytes"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/eth/downloader"
	"github.com/XinFinOrg/XDPoSChain/log"
	"github.com/XinFinOrg/XDPoSChain/p2p"
	"github.com/XinFinOrg/XDPoSChain/p2p/enode"
)

// lockedBuffer is a concurrency-safe log capture buffer. The protocol manager
// under test starts background goroutines (syncer, sync status logger, tx
// broadcast loops) and, in some tests, peer handler goroutines that keep
// emitting trace/debug logs while the test reads and resets the captured output,
// so a plain bytes.Buffer would race under -race and could corrupt the output.
// All access (write/read/reset) is serialized through a mutex.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func (b *lockedBuffer) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf.Reset()
}

// stalledDownloaderPeer is a downloader.Peer stub that answers the height probe
// and the common-ancestor search, then blocks all subsequent requests until
// released. It lets a test hold the downloader in a deterministic
// "synchronising with a discovered target" state without depending on a real
// sync still being in flight.
type stalledDownloaderPeer struct {
	id       string
	download *downloader.Downloader
	genesis  *types.Header

	releaseCh   chan struct{}
	releaseOnce sync.Once

	mu             sync.Mutex
	answeredNumber bool // Whether the ancestor-search header request was answered
}

func newStalledDownloaderPeer(dl *downloader.Downloader, id string, genesis *types.Header) *stalledDownloaderPeer {
	return &stalledDownloaderPeer{
		id:        id,
		download:  dl,
		genesis:   genesis,
		releaseCh: make(chan struct{}),
	}
}

// release unblocks all pending requests so the stalled sync can wind down.
func (p *stalledDownloaderPeer) release() {
	p.releaseOnce.Do(func() { close(p.releaseCh) })
}

// Head is unused by the downloader sync path (the head hash/TD are passed into
// Synchronise directly) but must exist to satisfy the downloader.Peer interface.
func (p *stalledDownloaderPeer) Head() (common.Hash, *big.Int) {
	return p.genesis.Hash(), big.NewInt(1)
}

// claimedHead is the header the stub advertises as the remote head, two blocks
// above the local genesis so the ancestor search converges on the genesis.
func (p *stalledDownloaderPeer) claimedHead() *types.Header {
	return &types.Header{
		ParentHash: p.genesis.Hash(),
		Number:     new(big.Int).SetUint64(2),
		Difficulty: big.NewInt(1),
	}
}

// RequestHeadersByHash answers the height probe with the claimed head header.
func (p *stalledDownloaderPeer) RequestHeadersByHash(h common.Hash, amount int, skip int, reverse bool) error {
	return p.download.DeliverHeaders(p.id, []*types.Header{p.claimedHead()})
}

// RequestHeadersByNumber answers the ancestor search (the first call) with the
// genesis and the claimed head so the search converges, then blocks all
// subsequent bulk-download requests until released.
func (p *stalledDownloaderPeer) RequestHeadersByNumber(from uint64, amount int, skip int, reverse bool) error {
	p.mu.Lock()
	answer := !p.answeredNumber
	p.answeredNumber = true
	p.mu.Unlock()
	if !answer {
		<-p.releaseCh
		return nil
	}
	// Reply with the genesis at number 0 plus synthetic headers matching the
	// span request, so the downloader finds the genesis as the common ancestor.
	step := uint64(skip + 1)
	headers := make([]*types.Header, 0, amount)
	for i := 0; i < amount; i++ {
		n := from + uint64(i)*step
		switch {
		case n == 0:
			headers = append(headers, p.genesis)
		case n == 2:
			headers = append(headers, p.claimedHead())
		default:
			headers = append(headers, &types.Header{Number: new(big.Int).SetUint64(n)})
		}
	}
	return p.download.DeliverHeaders(p.id, headers)
}

// RequestBodies blocks until released (the sync is paused during body download).
func (p *stalledDownloaderPeer) RequestBodies([]common.Hash) error { <-p.releaseCh; return nil }

// RequestReceipts blocks until released.
func (p *stalledDownloaderPeer) RequestReceipts([]common.Hash) error { <-p.releaseCh; return nil }

// RequestNodeData blocks until released.
func (p *stalledDownloaderPeer) RequestNodeData([]common.Hash) error { <-p.releaseCh; return nil }

// Tests that fast sync is disabled after a successful sync cycle.
func TestFastSyncDisabling100(t *testing.T) { testFastSyncDisabling(t, xdc100) }
func TestFastSyncDisabling164(t *testing.T) { testFastSyncDisabling(t, xdc164) }
func TestFastSyncDisabling165(t *testing.T) { testFastSyncDisabling(t, xdc165) }

// Tests that the periodic sync status logger emits a status line on every cycle,
// reporting the live network high-water mark from the peers' announced tips,
// regardless of whether the node is catching up or already in sync.
func TestSyncStatusLogger(t *testing.T) {
	pm, _ := newTestProtocolManagerMust(t, downloader.FullSync, 0, nil, nil)
	defer pm.Stop()

	// Capture the warn-level logs emitted by the sync status logger.
	logBuf := new(lockedBuffer)
	prevLog := log.Root()
	glog := log.NewGlogHandler(log.NewTerminalHandlerWithLevel(logBuf, log.LevelTrace, false))
	glog.Verbosity(log.LevelTrace)
	log.SetDefault(log.NewLogger(glog))
	defer log.SetDefault(prevLog)

	// Register a peer and give it a tip above our chain head.
	app, net := p2p.MsgPipe()
	defer app.Close()
	peer := pm.newPeer(xdc100, p2p.NewPeer(enode.ID{1}, "sync-status-peer", nil), net, pm.txpool.Get)
	if err := pm.peers.Register(peer); err != nil {
		t.Fatalf("failed to register peer: %v", err)
	}
	defer pm.peers.Unregister(peer.id)

	current := pm.blockchain.CurrentBlock().Number.Uint64()

	// A peer ahead of us must surface the gap...
	peer.SetTipNumber(current + 5)
	pm.reportSyncStatus()
	got := logBuf.String()
	if count := strings.Count(got, "Block synchronisation status"); count != 1 {
		t.Fatalf("expected exactly one sync status log, got %d, log: %q", count, got)
	}
	if !strings.Contains(got, fmt.Sprintf("highest=%d", current+5)) ||
		!strings.Contains(got, fmt.Sprintf("behind=%d", 5)) || !strings.Contains(got, "peers=1") {
		t.Fatalf("expected live high-water mark and gap, got %q", got)
	}
	// ...and once no peer advertises a higher tip, no gap is reported.
	logBuf.Reset()
	if err := pm.peers.Unregister(peer.id); err != nil {
		t.Fatalf("failed to unregister peer: %v", err)
	}
	pm.reportSyncStatus()
	got = logBuf.String()
	if !strings.Contains(got, "behind=0") {
		t.Fatalf("expected no gap when at the peer's head, got %q", got)
	}
}

// Tests that a real NewBlockHashesMsg announcement updates the peer's tip, which
// the sync status heartbeat then surfaces as the network high-water mark.
func TestAnnouncementUpdatesPeerTip(t *testing.T) {
	pm, _ := newTestProtocolManagerMust(t, downloader.FullSync, 8, nil, nil)
	defer pm.Stop()

	// Create a connected peer and deliver a real block-hash announcement for a
	// block the peer is known to have.
	tp, _ := newTestPeer("announce", xdc165, pm, true)
	defer tp.close()

	block := pm.blockchain.GetBlockByNumber(5)
	if block == nil {
		t.Fatalf("block #5 not found")
	}
	if err := p2p.Send(tp.app, NewBlockHashesMsg, newBlockHashesData{{Hash: block.Hash(), Number: block.NumberU64()}}); err != nil {
		t.Fatalf("failed to send block announcement: %v", err)
	}
	// Wait for the protocol handler to record the announced tip.
	deadline := time.After(5 * time.Second)
	for tp.peer.TipNumber() != block.NumberU64() {
		select {
		case <-deadline:
			t.Fatalf("peer tip not updated by NewBlockHashesMsg, have %d", tp.peer.TipNumber())
		case <-time.After(10 * time.Millisecond):
		}
	}
	// The heartbeat must reflect the announced tip.
	if highest := pm.peers.HighestTipNumber(); highest != block.NumberU64() {
		t.Fatalf("expected highest tip %d, got %d", block.NumberU64(), highest)
	}
}

// Tests that a far-future block announcement (which the fetcher would discard)
// does not inflate the peer's recorded tip.
func TestAnnouncementRejectsFarFutureTip(t *testing.T) {
	pm, _ := newTestProtocolManagerMust(t, downloader.FullSync, 8, nil, nil)
	defer pm.Stop()

	tp, _ := newTestPeer("announce", xdc165, pm, true)
	defer tp.close()

	// A plausible announcement within the fetcher's window is recorded as the
	// peer's tip.
	block := pm.blockchain.GetBlockByNumber(5)
	if err := p2p.Send(tp.app, NewBlockHashesMsg, newBlockHashesData{{Hash: block.Hash(), Number: block.NumberU64()}}); err != nil {
		t.Fatalf("failed to send block announcement: %v", err)
	}
	deadline := time.After(5 * time.Second)
	for tp.peer.TipNumber() != block.NumberU64() {
		select {
		case <-deadline:
			t.Fatalf("peer tip not updated by plausible announcement, have %d", tp.peer.TipNumber())
		case <-time.After(10 * time.Millisecond):
		}
	}
	// A far-future announcement must be discarded and must not move the tip.
	if err := p2p.Send(tp.app, NewBlockHashesMsg, newBlockHashesData{{Hash: common.Hash{0x01}, Number: ^uint64(0)}}); err != nil {
		t.Fatalf("failed to send far-future announcement: %v", err)
	}
	// Observe the tip for a while to ensure the rejected announcement left it
	// unchanged.
	deadline = time.After(500 * time.Millisecond)
	for {
		if got := tp.peer.TipNumber(); got != block.NumberU64() {
			t.Fatalf("far-future announcement moved the peer tip to %d, want %d", got, block.NumberU64())
		}
		select {
		case <-deadline:
			return
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// Tests that the NewBlockMsg handler records the peer's tip only for blocks
// within the fetcher's plausibility window, and ignores far-future blocks.
func TestNewBlockMsgUpdatesTip(t *testing.T) {
	pm, _ := newTestProtocolManagerMust(t, downloader.FullSync, 8, nil, nil)
	defer pm.Stop()

	tp, _ := newTestPeer("propagate", xdc165, pm, true)
	defer tp.close()

	// A plausible propagated block records its number as the peer's tip.
	plausible := pm.blockchain.GetBlockByNumber(5)
	if plausible == nil {
		t.Fatalf("block #5 not found")
	}
	if err := p2p.Send(tp.app, NewBlockMsg, []any{plausible, big.NewInt(131136)}); err != nil {
		t.Fatalf("failed to send plausible NewBlockMsg: %v", err)
	}
	deadline := time.After(5 * time.Second)
	for tp.peer.TipNumber() != plausible.NumberU64() {
		select {
		case <-deadline:
			t.Fatalf("peer tip not updated by plausible NewBlockMsg, have %d", tp.peer.TipNumber())
		case <-time.After(10 * time.Millisecond):
		}
	}
	// A far-future block (structurally valid but outside the plausibility
	// window) must be ignored and must not move the tip.
	future := types.NewBlockWithHeader(&types.Header{
		Number:     new(big.Int).SetUint64(^uint64(0)),
		Difficulty: big.NewInt(1),
		UncleHash:  types.EmptyUncleHash,
		TxHash:     types.EmptyRootHash,
	}).WithBody(types.Body{})
	if err := p2p.Send(tp.app, NewBlockMsg, []any{future, big.NewInt(131136)}); err != nil {
		t.Fatalf("failed to send far-future NewBlockMsg: %v", err)
	}
	// Observe the tip for a while to ensure the rejected block left it
	// unchanged.
	deadline = time.After(500 * time.Millisecond)
	for {
		if got := tp.peer.TipNumber(); got != plausible.NumberU64() {
			t.Fatalf("far-future NewBlockMsg moved the peer tip to %d, want %d", got, plausible.NumberU64())
		}
		select {
		case <-deadline:
			return
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// Tests that the sync status heartbeat merges the downloader's discovered
// target with the live announced-tip high-water mark and computes the gap.
func TestComputeSyncStatus(t *testing.T) {
	tests := []struct {
		current, highest, announcedTip uint64
		wantHighest, wantBehind        uint64
	}{
		// An active bulk sync target is reported even without announced tips.
		{current: 0, highest: 100, announcedTip: 0, wantHighest: 100, wantBehind: 100},
		// The announced tip keeps the high-water mark live outside bulk syncs.
		{current: 100, highest: 0, announcedTip: 150, wantHighest: 150, wantBehind: 50},
		// The higher of the two sources wins.
		{current: 100, highest: 120, announcedTip: 130, wantHighest: 130, wantBehind: 30},
		// Fully in sync reports no gap.
		{current: 120, highest: 120, announcedTip: 100, wantHighest: 120, wantBehind: 0},
	}
	for i, tt := range tests {
		got := computeSyncStatus(tt.current, tt.highest, tt.announcedTip)
		if got.current != tt.current || got.highest != tt.wantHighest || got.behind != tt.wantBehind {
			t.Fatalf("case %d: got %+v, want current=%d highest=%d behind=%d", i, got, tt.current, tt.wantHighest, tt.wantBehind)
		}
	}
}

// Tests that the sync status heartbeat reports the downloader's discovered
// target while a bulk sync is actively running, instead of the announced-tip
// high-water mark (which peers may not populate during a bulk sync). The sync
// is paused deterministically at the downloader's bulk-download phase by a stub
// peer, so the test never relies on a real sync still being in flight.
func TestSyncStatusDuringSync(t *testing.T) {
	pm, _ := newTestProtocolManagerMust(t, downloader.FullSync, 0, nil, nil)
	defer pm.Stop()

	// Capture the warn-level logs emitted by the sync status logger.
	logBuf := new(lockedBuffer)
	prevLog := log.Root()
	glog := log.NewGlogHandler(log.NewTerminalHandlerWithLevel(logBuf, log.LevelTrace, false))
	glog.Verbosity(log.LevelTrace)
	log.SetDefault(log.NewLogger(glog))
	defer log.SetDefault(prevLog)

	// Register a protocol peer so synchronise() has a best peer to pick, and
	// advertise a head ahead of our own.
	app, net := p2p.MsgPipe()
	defer app.Close()
	peer := pm.newPeer(xdc100, p2p.NewPeer(enode.ID{1}, "sync-status-peer", nil), net, pm.txpool.Get)
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

	// Register a stub downloader peer under the same id. It answers the height
	// probe and the ancestor search, then blocks the bulk download, holding the
	// downloader in a deterministic synchronising state with a known target.
	stub := newStalledDownloaderPeer(pm.downloader, peer.id, pm.blockchain.Genesis().Header())
	if err := pm.downloader.RegisterPeer(peer.id, xdc100, stub); err != nil {
		t.Fatalf("failed to register downloader peer: %v", err)
	}
	defer pm.downloader.UnregisterPeer(peer.id)
	defer stub.release()

	// Kick off a sync in the background; the stub keeps it synchronising.
	go pm.synchronise(pm.peers.BestPeer())

	// Wait until the downloader is actively synchronising with a discovered
	// target (the stub answers the height probe and the ancestor search, so the
	// target is set while the bulk download is paused).
	deadline := time.After(30 * time.Second)
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		if pm.downloader.Synchronising() && pm.downloader.Progress().HighestBlock > 0 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("downloader never reached an active sync with a discovered target")
		case <-ticker.C:
		}
	}
	// The sync is now deterministically paused with a known target: the
	// heartbeat must report it rather than the (empty) announced-tip high-water
	// mark.
	target := pm.downloader.Progress().HighestBlock
	logBuf.Reset()
	pm.reportSyncStatus()
	got := logBuf.String()
	if !strings.Contains(got, fmt.Sprintf("highest=%d", target)) {
		t.Fatalf("expected heartbeat to report downloader target %d during an active sync, got %q", target, got)
	}
}

// Tests that fast sync gets disabled as soon as a real block is successfully
// imported into the blockchain.
func testFastSyncDisabling(t *testing.T, protocol int) {
	t.Parallel()

	// Create a pristine protocol manager, check that fast sync is left enabled
	pmEmpty, _ := newTestProtocolManagerMust(t, downloader.FastSync, 0, nil, nil)
	defer pmEmpty.Stop()
	if atomic.LoadUint32(&pmEmpty.snapSync) == 0 {
		t.Fatalf("snap sync disabled on pristine blockchain")
	}
	// Create a full protocol manager, check that snap sync gets disabled
	pmFull, _ := newTestProtocolManagerMust(t, downloader.FastSync, 1024, nil, nil)
	defer pmFull.Stop()
	if atomic.LoadUint32(&pmFull.snapSync) == 1 {
		t.Fatalf("snap sync not disabled on non-empty blockchain")
	}
	// Sync up the two peers
	io1, io2 := p2p.MsgPipe()

	go pmFull.handle(pmFull.newPeer(protocol, p2p.NewPeer(enode.ID{}, "empty", nil), io2, pmFull.txpool.Get))
	go pmEmpty.handle(pmEmpty.newPeer(protocol, p2p.NewPeer(enode.ID{}, "full", nil), io1, pmEmpty.txpool.Get))

	deadline := time.After(15 * time.Second)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		if atomic.LoadUint32(&pmEmpty.snapSync) == 0 {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("snap sync not disabled after successful synchronisation")
		case <-ticker.C:
			pmEmpty.synchronise(pmEmpty.peers.BestPeer())
		}
	}
}

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
	"math/rand"
	"sync/atomic"
	"time"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/txpool"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/eth/downloader"
	"github.com/XinFinOrg/XDPoSChain/log"
	"github.com/XinFinOrg/XDPoSChain/p2p/enode"
)

const (
	forceSyncCycle      = 10 * time.Second // Time interval to force syncs, even if few peers are available
	minDesiredPeerCount = 5                // Amount of peers desired to start syncing

	// After a failed sync with a peer, that peer is not synced from again for
	// syncRetryBaseDelay, doubling on every further failure with the same peer
	// up to syncRetryMaxDelay. A successful sync with the peer resets its delay.
	// This keeps a peer with an invalid chain from pulling the node into a
	// failing sync (which queues all BFT messages) every few seconds, while
	// other peers can still be synced from.
	syncRetryBaseDelay = forceSyncCycle
	syncRetryMaxDelay  = 5 * time.Minute

	// A peer's failure count is forgotten once its backoff has been over for
	// this long.
	syncBackoffForget = time.Hour

	// This is the target size for the packs of transactions sent by txsyncLoop.
	// A pack can get larger than this if a single transactions exceeds this size.
	txsyncPackSize = 100 * 1024

	// syncStatusLogCycle is the interval at which the current sync status is
	// reported at warn level, so it is visible even when info/debug logs are
	// filtered out.
	syncStatusLogCycle = 10 * time.Minute
)

type txsync struct {
	p   *peer
	txs []*types.Transaction
}

// syncTransactions starts sending all currently pending transactions to the given peer.
func (pm *ProtocolManager) syncTransactions(p *peer) {
	// Assemble the set of transaction to broadcast or announce to the remote
	// peer. Fun fact, this is quite an expensive operation as it needs to sort
	// the transactions if the sorting is not cached yet. However, with a random
	// order, insertions could overflow the non-executable queues and get dropped.
	//
	// TODO(karalabe): Figure out if we could get away with random order somehow
	var txs types.Transactions
	pending := pm.txpool.Pending(txpool.PendingFilter{})
	for _, batch := range pending {
		for _, lazy := range batch {
			if tx := lazy.Resolve(); tx != nil {
				txs = append(txs, tx)
			}
		}
	}
	if len(txs) == 0 {
		return
	}
	// The xdc/165 protocol introduces proper transaction announcements, so instead
	// of dripping transactions across multiple peers, just send the entire list as
	// an announcement and let the remote side decide what they need (likely nothing).
	if p.version >= xdc165 {
		hashes := make([]common.Hash, len(txs))
		for i, tx := range txs {
			hashes[i] = tx.Hash()
		}
		p.AsyncSendPooledTransactionHashes(hashes)
		return
	}
	// Out of luck, peer is running legacy protocols, drop the txs over
	select {
	case pm.txsyncCh <- &txsync{p, txs}:
	case <-pm.quitSync:
	}
}

// txsyncLoop64 takes care of the initial transaction sync for each new
// connection. When a new peer appears, we relay all currently pending
// transactions. In order to minimise egress bandwidth usage, we send
// the transactions in small packs to one peer at a time.
func (pm *ProtocolManager) txsyncLoop64() {
	var (
		pending = make(map[enode.ID]*txsync)
		sending = false               // whether a send is active
		pack    = new(txsync)         // the pack that is being sent
		done    = make(chan error, 1) // result of the send
	)
	// send starts a sending a pack of transactions from the sync.
	send := func(s *txsync) {
		if s.p.version >= xdc165 {
			panic("initial transaction syncer running on xdc/165+")
		}
		// Fill pack with transactions up to the target size.
		size := common.StorageSize(0)
		pack.p = s.p
		pack.txs = pack.txs[:0]
		for i := 0; i < len(s.txs) && size < txsyncPackSize; i++ {
			pack.txs = append(pack.txs, s.txs[i])
			size += common.StorageSize(s.txs[i].Size())
		}
		// Remove the transactions that will be sent.
		s.txs = s.txs[:copy(s.txs, s.txs[len(pack.txs):])]
		if len(s.txs) == 0 {
			delete(pending, s.p.ID())
		}
		// Send the pack in the background.
		s.p.Log().Trace("Sending batch of transactions", "count", len(pack.txs), "bytes", size)
		sending = true
		go func() { done <- pack.p.SendTransactions64(pack.txs) }()
	}

	// pick chooses the next pending sync.
	pick := func() *txsync {
		if len(pending) == 0 {
			return nil
		}
		n := rand.Intn(len(pending)) + 1
		for _, s := range pending {
			if n--; n == 0 {
				return s
			}
		}
		return nil
	}

	for {
		select {
		case s := <-pm.txsyncCh:
			pending[s.p.ID()] = s
			if !sending {
				send(s)
			}
		case err := <-done:
			sending = false
			// Stop tracking peers that cause send failures.
			if err != nil {
				pack.p.Log().Debug("Transaction send failed", "err", err)
				delete(pending, pack.p.ID())
			}
			// Schedule the next send.
			if s := pick(); s != nil {
				send(s)
			}
		case <-pm.quitSync:
			return
		}
	}
}

// syncer is responsible for periodically synchronising with the network, both
// downloading hashes and blocks as well as handling the announcement handler.
func (pm *ProtocolManager) syncer() {
	// Start and ensure cleanup of sync mechanisms
	pm.blockFetcher.Start()
	pm.txFetcher.Start()
	pm.bft.Start()
	defer pm.blockFetcher.Stop()
	defer pm.txFetcher.Stop()
	defer pm.downloader.Terminate()
	defer pm.bft.Stop()

	// Wait for different events to fire synchronisation operations
	forceSync := time.NewTicker(forceSyncCycle)
	defer forceSync.Stop()

	var (
		syncing  bool                       // Whether a sync started here is running
		syncDone = make(chan syncResult, 1) // Result of the running sync
		backoff  = newSyncBackoff()         // Peers recently failed to sync from
	)
	startSync := func(peer *peer) {
		if syncing || peer == nil {
			return
		}
		syncing = true
		go func() { syncDone <- syncResult{peer: peer.id, err: pm.synchronise(peer)} }()
	}
	bestPeer := func() *peer {
		now := time.Now()
		return pm.peers.BestPeerExcluding(func(p *peer) bool { return backoff.blocked(p.id, now) })
	}

	for {
		select {
		case <-pm.newPeerCh:
			// Make sure we have peers to select from, then sync
			if pm.peers.Len() < minDesiredPeerCount {
				break
			}
			startSync(bestPeer())

		case p := <-pm.syncReqCh:
			// A peer announced a heavier chain; sync with it unless it is backed off
			if pm.peers.Peer(p.id) == nil || backoff.blocked(p.id, time.Now()) {
				break
			}
			startSync(p)

		case <-forceSync.C:
			// Force a sync even if not enough peers are present
			startSync(bestPeer())

		case res := <-syncDone:
			syncing = false
			pm.handleSyncResult(res, backoff)

		case <-pm.noMorePeers:
			return
		}
	}
}

// handleSyncResult folds one finished sync cycle into the peer's backoff state.
//
// The downloader owns the verdict on whether a failed cycle may be charged to the peer that
// served it: a cycle this node ended itself - a local condition of the chain, an import it cut
// short, a cancel it asked for, a download already running - says nothing about the peer, so
// the backoff has to agree with that verdict. See downloader.BackoffOnError. Leaving a
// charged-for peer's recorded failures in place, rather than clearing them, is deliberate: the
// cycle is no evidence either way.
func (pm *ProtocolManager) handleSyncResult(res syncResult, backoff *syncBackoff) {
	if res.err == nil {
		backoff.succeed(res.peer)
		return
	}
	if !pm.downloader.BackoffOnError(res.err) {
		log.Info("Synchronisation stopped by a local condition, peer not backed off", "peer", res.peer, "err", res.err)
		return
	}
	failures, delay := backoff.fail(res.peer, time.Now())
	log.Info("Synchronisation failed, backing off peer", "peer", res.peer, "failures", failures, "retryIn", delay, "err", res.err)
}

// requestSync asks the syncer to sync with a peer that announced a heavier
// chain, so the sync goes through the syncer's single-flight and backoff. The
// request is dropped if another is already pending; the syncer also syncs
// periodically.
func (pm *ProtocolManager) requestSync(p *peer) {
	select {
	case pm.syncReqCh <- p:
	default:
	}
}

// syncResult is the outcome of a sync attempt with a peer.
type syncResult struct {
	peer string
	err  error
}

// peerSyncBackoff is the backoff state of a single peer.
type peerSyncBackoff struct {
	failures int       // Consecutive failed syncs with the peer
	until    time.Time // The peer is not synced from before this time
}

// syncBackoff tracks failed syncs per peer. Entries are keyed by peer id, so a
// peer keeps its backoff when it is dropped and reconnects.
type syncBackoff struct {
	peers map[string]*peerSyncBackoff
}

func newSyncBackoff() *syncBackoff {
	return &syncBackoff{peers: make(map[string]*peerSyncBackoff)}
}

// blocked reports whether the peer is still backed off at the given time.
func (b *syncBackoff) blocked(id string, now time.Time) bool {
	s, ok := b.peers[id]
	return ok && now.Before(s.until)
}

// fail records a failed sync with the peer and returns its consecutive
// failure count and how long it is backed off for.
func (b *syncBackoff) fail(id string, now time.Time) (int, time.Duration) {
	b.prune(now)
	s, ok := b.peers[id]
	if !ok {
		s = new(peerSyncBackoff)
		b.peers[id] = s
	}
	s.failures++
	delay := syncRetryDelay(s.failures)
	s.until = now.Add(delay)
	return s.failures, delay
}

// succeed clears the peer's backoff after a successful sync.
func (b *syncBackoff) succeed(id string) {
	delete(b.peers, id)
}

// prune forgets peers whose backoff ended more than syncBackoffForget ago.
func (b *syncBackoff) prune(now time.Time) {
	for id, s := range b.peers {
		if now.Sub(s.until) > syncBackoffForget {
			delete(b.peers, id)
		}
	}
}

// syncRetryDelay returns how long a peer is backed off after the given number
// of consecutive failed syncs with it.
func syncRetryDelay(failures int) time.Duration {
	delay := syncRetryBaseDelay
	for i := 1; i < failures && delay < syncRetryMaxDelay; i++ {
		delay *= 2
	}
	return min(delay, syncRetryMaxDelay)
}

// syncStatusLogger periodically reports the current sync status at warn
// level so that it is always visible in the logs, regardless of whether
// info/debug logs are enabled, and independent of the one-shot start/finish
// logs emitted by the downloader itself.
func (pm *ProtocolManager) syncStatusLogger() {
	ticker := time.NewTicker(syncStatusLogCycle)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			pm.reportSyncStatus()

		case <-pm.quitSync:
			return
		}
	}
}

// reportSyncStatus emits a warn-level periodic sync status line, so that the
// current sync state is always visible in the logs every cycle regardless of
// whether the node is catching up or already in sync.
func (pm *ProtocolManager) reportSyncStatus() {
	var (
		current uint64
		highest uint64
	)
	// Seed current/highest from the downloader while it is actively
	// synchronising (it knows the discovered sync target and, in fast sync,
	// reports the snap block as the current height). Otherwise seed both from
	// the local chain head. computeSyncStatus then folds the live per-peer
	// announced-tip high-water mark into highest in both states, so the
	// reported highest always reflects the freshest known chain tip.
	if pm.downloader.Synchronising() {
		progress := pm.downloader.Progress()
		current, highest = progress.CurrentBlock, progress.HighestBlock
	} else {
		current = pm.blockchain.CurrentBlock().Number.Uint64()
	}
	status := computeSyncStatus(current, highest, pm.peers.HighestTipNumber())
	log.Warn("Block synchronisation status",
		"current", status.current,
		"highest", status.highest,
		"behind", status.behind,
		"peers", pm.peers.Len(),
	)
}

// syncStatus holds the values reported by the periodic sync status heartbeat.
type syncStatus struct {
	current uint64 // Local head, or the fast-sync snap block while bulk syncing
	highest uint64 // Highest known network block (downloader target + announced tips)
	behind  uint64 // Number of blocks behind the highest known network block
}

// computeSyncStatus derives the heartbeat values. It always folds the live
// network high-water mark (the highest block announced by any peer, bounded by
// IsPlausibleAnnouncement) into the reported highest, regardless of whether the
// downloader is bulk-syncing. The reported highest is therefore the maximum of
// the downloader target, the local head and the live announced tip in every
// state, so it reflects the freshest known chain tip.
func computeSyncStatus(current, highest, announcedTip uint64) syncStatus {
	highest = max(current, max(highest, announcedTip))
	behind := uint64(0)
	if highest > current {
		behind = highest - current
	}
	return syncStatus{current: current, highest: highest, behind: behind}
}

// synchronise tries to sync up our local block chain with a remote peer. It
// returns the downloader error if a sync was attempted and failed, and nil if
// the sync succeeded or was not needed.
func (pm *ProtocolManager) synchronise(peer *peer) error {
	// Short circuit if no peers are available
	if peer == nil {
		return nil
	}
	// Make sure the peer's TD is higher than our own
	currentBlock := pm.blockchain.CurrentBlock()
	td := pm.blockchain.GetTd(currentBlock.Hash(), currentBlock.Number.Uint64())
	pHead, pTd := peer.Head()
	if pTd.Cmp(td) <= 0 {
		return nil
	}
	// Otherwise try to sync with the downloader
	mode := downloader.FullSync
	if atomic.LoadUint32(&pm.snapSync) == 1 {
		// Fast sync was explicitly requested, and explicitly granted
		mode = downloader.FastSync
	} else if currentBlock.Number.Sign() == 0 && pm.blockchain.CurrentSnapBlock().Number.Sign() > 0 {
		// The database seems empty as the current block is the genesis. Yet the fast
		// block is ahead, so fast sync was enabled for this node at a certain point.
		// The only scenario where this can happen is if the user manually (or via a
		// bad block) rolled back a fast sync node below the sync point. In this case
		// however it's safe to reenable fast sync.
		atomic.StoreUint32(&pm.snapSync, 1)
		mode = downloader.FastSync
	}

	if mode == downloader.FastSync {
		// Make sure the peer's total difficulty we are synchronizing is higher.
		if pm.blockchain.GetTdByHash(pm.blockchain.CurrentSnapBlock().Hash()).Cmp(pTd) >= 0 {
			return nil
		}
	}

	// Process the BFT messages queued during the sync, whether it succeeded or not
	defer pm.drainBFTQueue()

	// Run the sync cycle, and disable fast sync if we've went past the pivot block
	if err := pm.downloader.Synchronise(peer.id, pHead, pTd, mode); err != nil {
		return err
	}
	if atomic.LoadUint32(&pm.snapSync) == 1 {
		log.Info("Fast sync complete, auto disabling")
		// Record the post-commit head BEFORE clearing the snapSync flag, so the
		// fetcher gate can never observe snapSync == 0 with graceHead still 0:
		// in that window a below-pivot canonical block (legitimately stateless,
		// headers and bodies only) would escalate from Warn to a "voting
		// stalled" Error — exactly the false positive the grace exists to
		// suppress. The head is still within the stall window of such blocks
		// right after the commit.
		//
		// Nil-guarded like the other CurrentBlock() readers (the fetcher gate,
		// the miner's pre-commit check): a completed fast sync implies a head,
		// and a missing one leaves graceHead at 0, which disables the grace the
		// same way a restart does.
		if head := pm.blockchain.CurrentBlock(); head != nil && head.Number != nil {
			pm.fastSyncGraceHead.Store(head.Number.Uint64())
		}
		atomic.StoreUint32(&pm.snapSync, 0)
	}
	atomic.StoreUint32(&pm.acceptTxs, 1) // Mark initial sync done
	return nil
	//if head := pm.blockchain.CurrentBlock(); head.NumberU64() > 0 {
	//	// We've completed a sync cycle, notify all peers of new state. This path is
	//	// essential in star-topology networks where a gateway node needs to notify
	//	// all its out-of-date peers of the availability of a new block. This failure
	//	// scenario will most often crop up in private and hackathon networks with
	//	// degenerate connectivity, but it should be healthy for the mainnet too to
	//	// more reliably update peers or the local TD state.
	//	go pm.BroadcastBlock(head, false)
	//}
}

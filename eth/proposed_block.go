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
	"sync/atomic"
	"time"

	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS/utils"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/log"
	"github.com/XinFinOrg/XDPoSChain/metrics"
)

// skippedProposedBlockState counts fetcher-gate skips on unexecuted state: the
// body is stored but its state trie does not open, so no QC or vote runs on it.
// A skip can be a benign fast-sync race, but sustained growth is a liveness
// stall. The body-absent cause is counted apart below: it is a routine
// transient, and counting it here would pollute the stall signal. Every
// proposed-block skip counter shares the skipped-proposed-block/ prefix, so one
// alert regex aggregates them; the engine gates' total is named outside that
// prefix on purpose.
var skippedProposedBlockState = metrics.NewRegisteredCounter("skipped-proposed-block/state", nil)

// skippedProposedBlockBody counts fetcher-gate skips on a canonical height whose
// body is not stored yet: the canonical marker is written before the body, so
// this is the benign half of the pair above and gets its own counter. It cannot
// share the engine gate's skipped-proposed-block/body-not-stored name - the
// registry rejects duplicate names - and the two count different paths: the
// engine gate judges when it is reached, this one counts what it had to park.
var skippedProposedBlockBody = metrics.NewRegisteredCounter("skipped-proposed-block/fetcher-body-not-stored", nil)

// skippedProposedBlockSnapSync counts fetcher-gate skips while fast sync runs:
// snapSync discards propagated blocks before executing them, so every
// propagation skips here by design. Sustained growth after the pivot commit
// means the flag never cleared and QC processing and voting are stalled.
var skippedProposedBlockSnapSync = metrics.NewRegisteredCounter("skipped-proposed-block/snap-sync", nil)

// skippedProposedBlockParkFull counts parked proposed blocks dropped because
// the retry map is at parkedProposedMax: the cap is the fourth exit of the
// park-and-retry wait, and a sustained non-zero rate means the wait can never
// drain - headers are arriving faster than the chain can store and execute
// them. Counted so the cap exit is observable, not a silent drop.
var skippedProposedBlockParkFull = metrics.NewRegisteredCounter("skipped-proposed-block/park-full", nil)

// proposedBlockStallWindow bounds how far behind the head the fetcher gate's
// Error escalation reaches. Voting happens within a few blocks of the head, so
// only a near-head canonical block with unopenable state can mean a live voting
// stall; farther back the same shape is expected (fast sync stores only headers
// and bodies below the pivot) and must not pollute the stall alert. It is a
// head-distance, not a time, so it tracks the chain rather than the clock.
const proposedBlockStallWindow = 64

// The fetcher gate parks a proposed block it cannot hand to the consensus
// handler yet instead of dropping the call: the body is written
// (rawdb.WriteBlock) before the canonical head (adoptHead) and before the state
// is executed, so a block that reads unready here is routinely ready moments
// later. One bounded waiter retries every parked header; for the state skip the
// only exits are ready, stale, deadline or the cap — "not ready right now" is
// not an exit. The snapSync skip is the one documented exception that drops
// instead of parking; see the gate.
const (
	parkedProposedMax      = 64
	parkedProposedPoll     = 100 * time.Millisecond
	parkedProposedDeadline = 90 * time.Second
	// parkedProposedStaleDistance is the fetcher's maxUncleDist: a parked header
	// the chain has moved this far past can no longer become canonical and is
	// dropped rather than retried.
	parkedProposedStaleDistance = 7
)

// parkedProposed is a proposed-block header the fetcher gate has to retry.
type parkedProposed struct {
	header   *types.Header
	deadline time.Time
}

// parkProposedBlock records a header whose body or state is not ready yet, so
// the waiter can hand it to the consensus handler once it is. Bounded by
// parkedProposedMax; a header already parked is not queued twice, but its
// deadline is refreshed: the hash's knowns entry is a bounded LRU, so the same
// block can be announced again shortly before its wait expires, and that
// re-observation must not end the wait at the first deadline.
func (pm *ProtocolManager) parkProposedBlock(header *types.Header) {
	hash := header.Hash()

	pm.parkedProposedMu.Lock()
	defer pm.parkedProposedMu.Unlock()
	if p, ok := pm.parkedProposed[hash]; ok {
		p.deadline = time.Now().Add(parkedProposedDeadline)
		return
	}
	if len(pm.parkedProposed) >= parkedProposedMax {
		// Bounded on purpose: the map must not outgrow the stall it outwaits.
		// The drop is the cap exit, and it is counted and logged so a map that
		// never drains is observable instead of silently losing retries.
		skippedProposedBlockParkFull.Inc(1)
		log.Debug("[fetcher] parked proposed block map is full, dropping retry", "number", header.Number, "hash", hash)
		return
	}
	pm.parkedProposed[hash] = &parkedProposed{header: header, deadline: time.Now().Add(parkedProposedDeadline)}
}

// waitParkedProposed retries the parked proposed blocks on a single ticker and
// exits with the node.
func (pm *ProtocolManager) waitParkedProposed() {
	ticker := time.NewTicker(parkedProposedPoll)
	defer ticker.Stop()

	for {
		select {
		case <-pm.quitSync:
			return
		case <-ticker.C:
			pm.scanParkedProposed()
		}
	}
}

// scanParkedProposed hands every parked header whose block is now stored and
// executed to the consensus handler, and drops the ones the chain moved past or
// whose deadline passed. Neither the handler nor the chain reads run under the
// lock: HasBlockAndExecutedState opens a state trie and CurrentBlock reads the
// head, and parkProposedBlock waits on this lock from the import goroutine.
//
// The deferred path calls the consensus handler directly rather than through
// the fetcher gate's closure, and deliberately so: an entry only turns ready
// once an import executed it, and the import path that matters here is the
// downloader's fast sync, which executes the blocks above the pivot through
// importBlockResults -> InsertChain while the snapSync flag is still set. Those
// blocks were executed and their state validated by InsertChain, so the
// snapSync branch - which guards the fetcher's own inserter, returning nil
// instead of importing while fast sync runs - has nothing left to add here.
// What stays load-bearing is the executed-state check below, run per entry
// before the handler; the engine's own gates then judge canonicality and
// storage, so this path is not a way around them.
//
// Delivery is claimed by deletion: the scan that removes an entry is the one
// that hands its header over. Overlapping scans can classify the same entry as
// ready, but only one wins the claim, so the consensus handler still runs at
// most once per parked header.
func (pm *ProtocolManager) scanParkedProposed() {
	pm.parkedProposedMu.Lock()
	handler := pm.proposedBlockHandler
	entries := make([]*parkedProposed, 0, len(pm.parkedProposed))
	for _, p := range pm.parkedProposed {
		entries = append(entries, p)
	}
	pm.parkedProposedMu.Unlock()

	head := pm.blockchain.CurrentBlock()

	var ready, drop []*parkedProposed

	for _, p := range entries {
		hash := p.header.Hash()
		if pm.blockchain.HasBlockAndExecutedState(hash, p.header.Number.Uint64()) {
			ready = append(ready, p)
			continue
		}
		if head != nil && head.Number != nil && p.header.Number.Uint64()+parkedProposedStaleDistance < head.Number.Uint64() {
			log.Debug("[fetcher] parked proposed block fell below the uncle distance, dropping", "number", p.header.Number, "hash", hash)
			drop = append(drop, p)
			continue
		}
		if time.Now().After(p.deadline) {
			log.Warn("[fetcher] parked proposed block was not ready in time, dropping", "number", p.header.Number, "hash", hash)
			drop = append(drop, p)
		}
	}

	deliver := pm.claimParkedProposed(ready, drop)
	if handler == nil {
		return
	}
	for _, header := range deliver {
		if err := handler(header); err != nil {
			log.Warn("[fetcher] deferred proposed block handler failed", "err", err, "number", header.Number, "hash", header.Hash())
		}
	}
}

// claimParkedProposed removes the entries a scan decided to end and returns the
// headers it won the right to deliver. Deleting under the map lock is the
// claim: two scans can both classify the same entry as ready, but the one that
// loses the identity check delivers nothing for it, so a header is never handed
// over twice. The identity check also keeps an entry that was parked again with
// a fresh deadline while the chain reads ran - that entry has a new pointer and
// must survive this scan.
func (pm *ProtocolManager) claimParkedProposed(ready, drop []*parkedProposed) []*types.Header {
	pm.parkedProposedMu.Lock()
	defer pm.parkedProposedMu.Unlock()

	var deliver []*types.Header
	for _, p := range ready {
		hash := p.header.Hash()
		if pm.parkedProposed[hash] != p {
			continue
		}
		delete(pm.parkedProposed, hash)
		deliver = append(deliver, p.header)
	}
	for _, p := range drop {
		hash := p.header.Hash()
		if pm.parkedProposed[hash] == p {
			delete(pm.parkedProposed, hash)
		}
	}
	return deliver
}

// newFetcherProposedBlockHandler builds the callback the fetcher runs. It gates
// the consensus handler on the snapSync flag and on executed state (see the
// NewProtocolManager wiring for why) and leaves canonicality to the engine; it
// reads pm.blockchain so the gate cannot diverge from the manager's chain.
func newFetcherProposedBlockHandler(pm *ProtocolManager, handleProposedBlock func(*types.Header) error) func(*types.Header) error {
	return func(header *types.Header) error {
		// A nil header or number is a caller bug, not a block observation, and this
		// closure dereferences the header before any chain read.
		if !utils.IsJudgeableHeader(header) {
			utils.SkipNilHeaderLog(utils.SkipSiteFetcher)
			return nil
		}
		if atomic.LoadUint32(&pm.snapSync) == 1 {
			// The flag stays set while a sync cycle fails (eth/sync.go): this node
			// is behind and its propagated blocks are being discarded rather than
			// imported. A stuck flag shows up as sustained growth of
			// skipped-proposed-block/snap-sync.
			//
			// Unlike the state skip below, this exit drops the call instead of
			// parking it, and the drop is not recoverable: the peer announced the
			// block once, and the fetcher's knowns set keeps suppressing the
			// re-announce, so the self-vote for a block observed only during fast
			// sync never runs. The downloader's handoffProposedBlock covers the
			// head the sync leaves behind, and mid-range blocks are history by
			// the time the flag clears, so what is lost is the self-vote for a
			// proposed block at the sync boundary - warned rather than silently
			// dropped, because a QC or voting stall that traces back here must
			// be visible without turning on debug logging.
			//
			// The handoff only runs on a successful cycle: Synchronise returning
			// an error takes eth/sync.go out before it, and the flag stays set
			// across the retry (it is set again when a rewound head looks empty),
			// so a failing cycle loses every proposed block it observes. One Warn
			// per block cannot show that aggregate; the counter is what a
			// stuck-flag alert has to read.
			skippedProposedBlockSnapSync.Inc(1)
			log.Warn("[fetcher] skipped proposed block handler during fast sync", "hash", header.Hash(), "number", header.Number)
			return nil
		}
		// Canonicality is judged through utils.IsCanonicalAt, the same predicate
		// the engine gates use, so the two call sites cannot drift; what is
		// site-specific here is only the stall escalation below (recency and
		// fast-sync grace). Deliberately not HasBlockAndFullState: a missing XDCX
		// trading/lending piece is not re-derivable, so demanding it would halt voting
		// on a correctly executed block. A false gate does not drop the block: it is
		// parked and retried until it is ready or a stale/deadline bound ends the
		// wait (parkProposedBlock), so a merely-not-yet block still gets its vote,
		// while a persistent skipped-proposed-block/state rate is the stall signal,
		// read against the engine's proposed-block-skip-total cross-check.
		//
		// One stateCache.OpenTrie per propagated block is negligible next to
		// block processing, so the check is deliberately uncached.
		if !pm.blockchain.HasBlockAndExecutedState(header.Hash(), header.Number.Uint64()) {
			// Park and retry rather than drop: the body/state can land moments
			// later, and only the stale/deadline bounds end the wait. The engine
			// re-checks canonicality and storage when the wait ends, so the
			// threshold is not lowered.
			pm.parkProposedBlock(header)
			// HasBlockAndExecutedState is false for two causes: the body is not
			// stored, or the state trie does not open. Only the second is the
			// stall this gate reports on, so the two are counted apart: a
			// canonical height with no body is a body problem, not unexecuted
			// state, and the canonical marker is written before the body - the
			// routine shape, not a stall. The engine gate grades the same shape
			// at Info for that reason, so this line matches it.
			if !pm.blockchain.HasBlock(header.Hash(), header.Number.Uint64()) {
				skippedProposedBlockBody.Inc(1)
				log.Info("[fetcher] skipped proposed block handler: block body not stored", "hash", header.Hash(), "number", header.Number)
				return nil
			}
			skippedProposedBlockState.Inc(1)
			// The body is stored, so what is missing is its state. A fast-sync
			// race and a stall look identical here; separate them by
			// canonicality, recency and the pivot-commit grace. Near the head a
			// canonical block whose state never executes is the alertable stall;
			// farther back the same shape is expected noise and Warns.
			head := pm.blockchain.CurrentBlock()
			canonical := utils.IsCanonicalAt(pm.blockchain, header)
			if canonical && isStallEscalation(head, header, pm.fastSyncGraceHead.Load()) {
				log.Error("[fetcher] skipped proposed block handler: canonical block state not executed, voting stalled", "hash", header.Hash(), "number", header.Number)
			} else {
				log.Warn("[fetcher] skipped proposed block handler: state not executed", "hash", header.Hash(), "number", header.Number)
			}
			return nil
		}
		return handleProposedBlock(header)
	}
}

// isStallEscalation reports whether a canonical block whose state has not
// executed yet is the alertable near-head stall, as opposed to the expected
// fast-sync shapes: a block far behind the head (stale) is noise, and so is a
// block inside the post-pivot grace, because right after a fast-sync commit
// the head sits at the pivot and blocks below it are legitimately stateless.
// The grace self-heals once the head moves proposedBlockStallWindow past the
// recorded height; graceHead == 0 (no recent fast sync, or a restart) disables
// it. A rollback below graceHead is also within the grace: the recorded height
// sits above the head again, so the below-pivot shape is the legitimately
// stateless one, not a stall. The subtractions are guarded against uint64
// underflow by the difference form and the short-circuits.
func isStallEscalation(head, header *types.Header, graceHead uint64) bool {
	// Stale: the head is a full window past the header, so the block can no
	// longer be the one voting happens on - expected fast-sync noise, not a
	// stall. The difference form and the guard clause keep the subtraction
	// from underflowing.
	if head != nil && head.Number != nil && head.Number.Uint64() > header.Number.Uint64() &&
		head.Number.Uint64()-header.Number.Uint64() > proposedBlockStallWindow {
		return false
	}
	// No recent fast sync, or a restart: nothing to be graceful about. A
	// header above the recorded pivot is past the grace by definition.
	if graceHead == 0 || header.Number.Uint64() > graceHead {
		return true
	}
	// A head that cannot be read is not evidence of a stall either way; treat
	// it as the grace covering the shape, which is the fast-sync-race reading.
	if head == nil || head.Number == nil {
		return true
	}
	// Past the grace: the head has reached the recorded pivot and moved a full
	// window beyond it, so the below-pivot shape is no longer explained by the
	// transition. A head still at (or below) the recorded pivot, or one that
	// has not moved a full window past it, is inside the grace - which also
	// covers a rollback below the recorded height.
	return head.Number.Uint64() >= graceHead &&
		head.Number.Uint64()-graceHead >= proposedBlockStallWindow
}

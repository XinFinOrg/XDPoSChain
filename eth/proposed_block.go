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
// block is absent or its state trie does not open, so no QC or vote runs on it.
// A skip can be a benign fast-sync race, but sustained growth is a liveness
// stall. Every proposed-block skip counter shares the skipped-proposed-block/
// prefix, so one alert regex aggregates them (see the runbook's counter table);
// the engine gates' total is named outside that prefix on purpose.
var skippedProposedBlockState = metrics.NewRegisteredCounter("skipped-proposed-block/state", nil)

// skippedProposedBlockSnapSync counts fetcher-gate skips while fast sync runs:
// snapSync discards propagated blocks before executing them, so every
// propagation skips here by design. Sustained growth after the pivot commit
// means the flag never cleared and QC processing and voting are stalled.
var skippedProposedBlockSnapSync = metrics.NewRegisteredCounter("skipped-proposed-block/snap-sync", nil)

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
// later. One bounded waiter retries every parked header; the only exits are
// ready, stale, deadline or the cap — "not ready right now" is not an exit.
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
// parkedProposedMax; a header already parked is not parked twice.
func (pm *ProtocolManager) parkProposedBlock(header *types.Header) {
	hash := header.Hash()

	pm.parkedProposedMu.Lock()
	defer pm.parkedProposedMu.Unlock()
	if _, ok := pm.parkedProposed[hash]; ok {
		return
	}
	if len(pm.parkedProposed) >= parkedProposedMax {
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
// whose deadline passed. The handler runs outside the lock.
func (pm *ProtocolManager) scanParkedProposed() {
	var ready []*types.Header

	pm.parkedProposedMu.Lock()
	handler := pm.proposedBlockHandler
	for hash, p := range pm.parkedProposed {
		if pm.blockchain.HasBlockAndExecutedState(hash, p.header.Number.Uint64()) {
			ready = append(ready, p.header)
			delete(pm.parkedProposed, hash)
			continue
		}
		head := pm.blockchain.CurrentBlock()
		if head != nil && head.Number != nil && p.header.Number.Uint64()+parkedProposedStaleDistance < head.Number.Uint64() {
			log.Debug("[fetcher] parked proposed block fell below the uncle distance, dropping", "number", p.header.Number, "hash", hash)
			delete(pm.parkedProposed, hash)
			continue
		}
		if time.Now().After(p.deadline) {
			log.Warn("[fetcher] parked proposed block was not ready in time, dropping", "number", p.header.Number, "hash", hash)
			delete(pm.parkedProposed, hash)
		}
	}
	pm.parkedProposedMu.Unlock()

	for _, header := range ready {
		if handler == nil {
			continue
		}
		if err := handler(header); err != nil {
			log.Warn("[fetcher] deferred proposed block handler failed", "err", err, "number", header.Number, "hash", header.Hash())
		}
	}
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
			// The flag stays set while a sync cycle fails (eth/sync.go): the node has no
			// state to judge blocks with. A stuck flag shows up as sustained growth of
			// skipped-proposed-block/snap-sync.
			skippedProposedBlockSnapSync.Inc(1)
			log.Debug("[fetcher] skipped proposed block handler during fast sync", "hash", header.Hash(), "number", header.Number)
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
			skippedProposedBlockState.Inc(1)
			// Park and retry rather than drop: the body/state can land moments
			// later, and only the stale/deadline bounds end the wait. The engine
			// re-checks canonicality and storage when the wait ends, so the
			// threshold is not lowered.
			pm.parkProposedBlock(header)
			// HasBlockAndExecutedState is false for two causes: the body is not
			// stored, or the state trie does not open. Only the second is the stall
			// this gate reports on, and the counter cannot tell them apart, so the log
			// names the cause: a canonical block with no body is a body problem, not
			// unexecuted state.
			if !pm.blockchain.HasBlock(header.Hash(), header.Number.Uint64()) {
				log.Warn("[fetcher] skipped proposed block handler: block body not stored", "hash", header.Hash(), "number", header.Number)
				return nil
			}
			// A fast-sync race and a stall look identical here; separate them by
			// canonicality, recency and the pivot-commit grace. Near the head a
			// canonical block whose state never executes is the alertable stall;
			// farther back the same shape is expected noise and Warns.
			head := pm.blockchain.CurrentBlock()
			// Difference form: a sum with the window could wrap uint64 near
			// MaxUint64; the guard clause keeps the subtraction from underflow.
			stale := head != nil && head.Number != nil && head.Number.Uint64() > header.Number.Uint64() &&
				head.Number.Uint64()-header.Number.Uint64() > proposedBlockStallWindow
			// Fast-sync transition grace: right after a fast-sync commit the head sits at
			// the pivot, so blocks below it are legitimately stateless and must not
			// escalate. It self-heals once the head moves proposedBlockStallWindow past
			// the recorded height; graceHead == 0 (no recent fast sync, or a restart)
			// disables it.
			graceHead := pm.fastSyncGraceHead.Load()
			// A rollback below graceHead is also within the grace: the recorded
			// height sits above the head again, so the below-pivot shape is the
			// legitimately-stateless one, not a stall. The short-circuit guards
			// the subtraction against underflow.
			inFastSyncGrace := graceHead != 0 &&
				header.Number.Uint64() <= graceHead &&
				head != nil && head.Number != nil &&
				(head.Number.Uint64() < graceHead ||
					head.Number.Uint64()-graceHead < proposedBlockStallWindow)
			canonical := utils.IsCanonicalAt(pm.blockchain, header)
			if canonical && !stale && !inFastSyncGrace {
				log.Error("[fetcher] skipped proposed block handler: canonical block state not executed, voting stalled", "hash", header.Hash(), "number", header.Number)
			} else {
				log.Warn("[fetcher] skipped proposed block handler: state not executed", "hash", header.Hash(), "number", header.Number)
			}
			return nil
		}
		return handleProposedBlock(header)
	}
}

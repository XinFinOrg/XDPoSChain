// Copyright 2026 The go-ethereum Authors
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

package core

import (
	"testing"

	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core/types"
)

// TestProcFutureBlocksEvictsNeverImportable covers a parked block whose parent is
// neither in the chain nor parked: it can never import, so it is evicted instead of
// being re-verified on every futureBlocksLoop tick.
//
// What the pass hands the engine's proposed-block hook is not observable from this
// package: procFutureBlocks reaches XDPoS's HandleProposedBlock through a type assertion on
// an XDPoS engine, and every engine a test in this package can build is ethash - so a
// pass that did hand a block over and one that handed none look exactly alike here.
// Observing it would take a test-only seam in the production assertion, which is why this
// test pins the queue and the head instead, and why the hook's argument stays unasserted.
func TestProcFutureBlocksEvictsNeverImportable(t *testing.T) {
	chain, blocks := newInsertChainTester(t, ethash.NewFaker(), 5, 0)

	if err := chain.addFutureBlock(blocks[2]); err != nil {
		t.Fatalf("failed to park block #%d: %v", blocks[2].NumberU64(), err)
	}
	chain.procFutureBlocks()

	if chain.futureBlocks.Contains(blocks[2].Hash()) {
		t.Fatal("a block that can never import must be evicted from the future queue")
	}
	if have, want := chain.CurrentBlock().Number.Uint64(), uint64(0); have != want {
		t.Fatalf("a block that can never import moved the head: have %d want %d", have, want)
	}
}

// TestProcFutureBlocksImportsTheLinkablePrefixAndEvictsTheUnlinkableTail covers a queue
// holding both a block that can be linked to the chain (#1) and one that cannot (#3): the
// first becomes the head, the second is evicted, and the pass leaves no head that it did
// not produce itself - the sorted queue tail (#3) is not the block to hand the engine.
// The hook's argument is not observable here, see the note above.
func TestProcFutureBlocksImportsTheLinkablePrefixAndEvictsTheUnlinkableTail(t *testing.T) {
	chain, blocks := newInsertChainTester(t, ethash.NewFaker(), 5, 0)

	for _, block := range []*types.Block{blocks[0], blocks[2]} {
		if err := chain.addFutureBlock(block); err != nil {
			t.Fatalf("failed to park block #%d: %v", block.NumberU64(), err)
		}
	}
	chain.procFutureBlocks()

	if want := uint64(1); chain.CurrentBlock().Number.Uint64() != want {
		t.Fatalf("unexpected head number: have %d want %d", chain.CurrentBlock().Number.Uint64(), want)
	}
	if chain.futureBlocks.Contains(blocks[0].Hash()) {
		t.Fatal("the imported block must leave the future queue")
	}
	if chain.futureBlocks.Contains(blocks[2].Hash()) {
		t.Fatal("the never-importable block must be evicted")
	}
}

// TestProcFutureBlocksKeepsParkedBlocksOnLocalInterruption covers a pass that runs while
// insertion is locally interrupted: InterruptInsert makes InsertChain report
// ErrInsertionInterrupted before it looks at the block at all, which says nothing about the
// block. The downloader turns that interruption on around every cancel
// (Downloader.Cancel) and the queue is drained on a 100ms tick, so evicting here would
// silently drop blocks that are ready to import - the batch that parked them already
// reported success, so nothing would ask for them again. The block has to survive the pass
// and import once insertion is allowed again.
func TestProcFutureBlocksKeepsParkedBlocksOnLocalInterruption(t *testing.T) {
	chain, blocks := newInsertChainTester(t, nil, 5, 0)
	if err := chain.addFutureBlock(blocks[0]); err != nil {
		t.Fatalf("failed to park block #%d: %v", blocks[0].NumberU64(), err)
	}

	chain.InterruptInsert(true)
	chain.procFutureBlocks()
	chain.InterruptInsert(false)

	if !chain.futureBlocks.Contains(blocks[0].Hash()) {
		t.Fatal("a local interruption evicted the parked block instead of leaving it for the next pass")
	}
	// The pass after the interruption has to import it: that is what the parked block is
	// kept for.
	chain.procFutureBlocks()
	if want := uint64(1); chain.CurrentBlock().Number.Uint64() != want {
		t.Fatalf("unexpected head number after the interruption: have %d want %d", chain.CurrentBlock().Number.Uint64(), want)
	}
}

// TestProcFutureBlocksKeepsParkedBlockOnLocalInsertAheadOfClock covers the state a clock that
// steps back past maxTimeFutureBlocks leaves behind: the block was parked while the clock was
// right, and re-queueing it now fails addFutureBlock's window test with
// ErrLocalInsertAheadOfClock. That error lives in this node's clock, not in the block, and it
// heals once the clock catches up - so the block has to survive the pass instead of being
// dropped for good.
func TestProcFutureBlocksKeepsParkedBlockOnLocalInsertAheadOfClock(t *testing.T) {
	// The stub hands the insertion the one local condition that heals, which is what
	// procFutureBlocks is asked about here: may a parked block stay parked when its failure
	// heals on its own. How such a condition is produced - a block past the future queue's
	// window, a chain whose clock stepped back - is the insertion path's own business and is
	// covered where it is written.
	engine := &failFromEngine{Engine: ethash.NewFaker(), fromNumber: 1, failErr: ErrLocalInsertAheadOfClock}
	chain, blocks := newFarFutureChain(t, engine)

	// Inject the parked block, the way rewindHeadMarkers injects a crash's leftovers.
	chain.futureBlocks.Add(blocks[0].Hash(), blocks[0])

	chain.procFutureBlocks()

	if !chain.futureBlocks.Contains(blocks[0].Hash()) {
		t.Fatal("a clock step-back evicted the parked block instead of leaving it for the next pass")
	}
}

// TestProcFutureBlocksEvictsParkedBlockOnLocalInsertCondition covers the other half of the
// local conditions: ErrLocalInsertCondition carries the ones a retry cannot repair - a record
// this node is missing, a segment with nothing stored - and every one of them is read the same
// way on the next tick. Keeping the block parked for one would re-verify it on every
// futureBlocksLoop tick and forever, so the pass has to evict it, like the block that can never
// import at all. A batch that carries it again adopts it on this very path.
func TestProcFutureBlocksEvictsParkedBlockOnLocalInsertCondition(t *testing.T) {
	engine := &failFromEngine{Engine: ethash.NewFaker(), fromNumber: 1, failErr: ErrLocalInsertCondition}
	chain, blocks := newFarFutureChain(t, engine)

	// Inject the parked block, the way rewindHeadMarkers injects a crash's leftovers.
	chain.futureBlocks.Add(blocks[0].Hash(), blocks[0])

	chain.procFutureBlocks()

	if chain.futureBlocks.Contains(blocks[0].Hash()) {
		t.Fatal("a local condition a retry cannot repair must evict the parked block, not re-verify it on every tick")
	}
}

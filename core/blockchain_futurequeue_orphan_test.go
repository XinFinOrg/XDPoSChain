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

	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/types"
)

// flippableErrEngine answers VerifyHeaders with whatever is registered for the number at the
// moment of the call. A parked block has to be able to change its answer between the pass that
// queues it and the pass that retries it - that is how a future block whose parent never
// arrived turns into an unlinkable one - and a fixed table cannot express that.
type flippableErrEngine struct {
	consensus.Engine
	errs map[uint64]error
}

func (e *flippableErrEngine) VerifyHeaders(chain consensus.ChainReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
	abort := make(chan struct{})
	results := make(chan error, len(headers))
	go func() {
		for _, header := range headers {
			select {
			case <-abort:
				return
			case results <- e.errs[header.Number.Uint64()]:
			}
		}
	}()
	return abort, results
}

// TestProcFutureBlocksOrphanIsNotABadBlock pins what a pass of the future-block queue must do
// with the descendants of a block it has just dropped: their parent is neither on the chain
// nor parked any more, so the only answer insertChain has left for them is ErrUnknownAncestor -
// which classifyInsertErr records as a bad block. They are orphans of this queue's own
// eviction rather than invalid blocks, so they have to leave the queue without being written
// into the bad block database.
//
// The shape needs a block that is parked while it is still ahead of the clock and only reports
// an unknown ancestor once its timestamp falls inside maxTimeFutureBlocks. XDPoS checks the
// timestamp before the parent lookup, so a parked chain whose root never linked is exactly
// this, and the stub engine states it per block.
func TestProcFutureBlocksOrphanIsNotABadBlock(t *testing.T) {
	engine := &flippableErrEngine{Engine: ethash.NewFaker(), errs: map[uint64]error{
		3: consensus.ErrFutureBlock,
		4: consensus.ErrFutureBlock,
		5: consensus.ErrFutureBlock,
	}}
	chain, blocks := newInsertChainTester(t, engine, 6, 0)

	// #3..#5 are dated ahead of the clock and parked here directly rather than through a
	// batch import: this case is about what the queue does when it drops the block it was
	// retrying, so it parks its own fixtures and does not lean on the tail-parking of a
	// batch - that behaviour is pinned by TestInsertChainQueuesFutureTailOfBatch.
	for _, block := range []*types.Block{blocks[2], blocks[3], blocks[4]} {
		chain.futureBlocks.Add(block.Hash(), block)
	}
	if n := chain.futureBlocks.Len(); n != 3 {
		t.Fatalf("parked %d blocks, want 3", n)
	}
	// The clock has caught up (the future window opened) and the parent never arrived, so #3
	// is unlinkable now. Its children can only report the same.
	engine.errs[3], engine.errs[4], engine.errs[5] = consensus.ErrUnknownAncestor, consensus.ErrUnknownAncestor, consensus.ErrUnknownAncestor

	chain.procFutureBlocks()

	if n := chain.futureBlocks.Len(); n != 0 {
		t.Fatalf("%d blocks left parked, want the orphaned chain drained", n)
	}
	// The root is the one that could not be linked, and recording it as a bad block is the
	// pre-existing answer of the insertion paths for that shape - this change deliberately
	// leaves it alone. What must not happen is the collateral: a descendant, whose only fault
	// is having been queued behind it, is not a bad block.
	for _, block := range blocks[3:5] {
		if bad := rawdb.ReadBadBlock(chain.ChainDb(), block.Hash()); bad != nil {
			t.Errorf("block %d was written into the bad block database after its parked parent was evicted", block.NumberU64())
		}
	}
}

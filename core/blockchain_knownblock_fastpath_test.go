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
	"errors"
	"testing"
)

// TestInsertBlockDoesNotPrecomputeAnExecutedBlock pins the look insertBlock takes before
// getResultBlock: a block this node already executed has nothing left to compute, so it is
// adopted from there instead of being run in full only for the result to be thrown away.
//
// The second look after getResultBlock is a concurrency window this case cannot reach; see
// adoptExecutedBlock for why it is kept. TestInsertBlockAdoptsKnownBlockAboveTheHead imports
// the same shape through insertBlock, so it lands on the fast path pinned here as well.
func TestInsertBlockDoesNotPrecomputeAnExecutedBlock(t *testing.T) {
	chain, blocks := newInsertChainTester(t, nil, 6, 0)
	target := blocks[4]

	// Import through the single-block entry, the one the fetcher uses: a block that went
	// through InsertChain is recorded in downloadingBlock, which insertBlock answers before
	// anything else - so a chain warmed up in batches never reaches this path at all.
	for _, block := range blocks {
		if err := chain.InsertBlock(block); err != nil {
			t.Fatalf("failed to import block #%d through the single-block path: %v", block.NumberU64(), err)
		}
	}
	// Move the head back while leaving the blocks and their state on disk, the shape a crash
	// or an interrupted rollback leaves behind.
	rewindHeadMarkers(chain, blocks[3])
	if have, want := chain.CurrentBlock().Number.Uint64(), blocks[3].NumberU64(); have != want {
		t.Fatalf("unexpected head after rollback: have %d want %d", have, want)
	}
	// The imports above ran every block they were handed, and getResultBlock records that in
	// calculatingBlock without ever removing it. Clear this block's entry, so that one found
	// after the import below can only have been written by that import.
	chain.calculatingBlock.Remove(target.HashNoValidator())
	if chain.calculatingBlock.Contains(target.HashNoValidator()) {
		t.Fatal("precondition: the block is still recorded as being calculated")
	}
	if err := chain.InsertBlock(target); err != nil {
		t.Fatalf("failed to re-import the known block: %v", err)
	}
	if have, want := chain.CurrentBlock().Number.Uint64(), target.NumberU64(); have != want {
		t.Fatalf("head did not advance over the known block: have %d want %d", have, want)
	}
	// getResultBlock is what records a block it is about to run. An entry here means the
	// already executed block was executed a second time, only for the result to be thrown
	// away by the adoption.
	if chain.calculatingBlock.Contains(target.HashNoValidator()) {
		t.Fatal("an already executed block was precomputed instead of adopted")
	}
}

// TestInsertBlockDoesNotAdoptDuringInterruption covers the same single-block entry point
// while insertion is locally interrupted: InterruptInsert is what the downloader turns on
// around every cancel (Downloader.Cancel), and the interruption says nothing about the
// block. The batch entry point answers it twice - at its entry and at the head of its
// loop - and the single-block path has to answer it too, instead of moving the head to a
// block the node would not adopt while it is being interrupted. The block stays where it
// is, and the pass that follows the interruption imports it (see
// TestProcFutureBlocksKeepsParkedBlocksOnLocalInterruption for the same contract on the
// queue).
func TestInsertBlockDoesNotAdoptDuringInterruption(t *testing.T) {
	chain, blocks := newInsertChainTester(t, nil, 6, 0)

	// Import through the single-block entry itself, so the block the adoption is asked
	// about is one this node executed. See TestInsertBlockAdoptsKnownBlockAboveTheHead
	// for why a chain warmed up in batches cannot show this path.
	for _, block := range blocks {
		if err := chain.InsertBlock(block); err != nil {
			t.Fatalf("failed to import block #%d through the single-block path: %v", block.NumberU64(), err)
		}
	}
	// Move the head back while leaving the blocks and their state on disk.
	rewindHeadMarkers(chain, blocks[3])
	if have, want := chain.CurrentBlock().Number.Uint64(), blocks[3].NumberU64(); have != want {
		t.Fatalf("unexpected head after rollback: have %d want %d", have, want)
	}

	chain.InterruptInsert(true)
	_, _, err := chain.insertBlock(blocks[4])
	chain.InterruptInsert(false)

	if !errors.Is(err, ErrInsertionInterrupted) {
		t.Fatalf("an interrupted single-block import reported %v, want %v", err, ErrInsertionInterrupted)
	}
	if have, want := chain.CurrentBlock().Number.Uint64(), blocks[3].NumberU64(); have != want {
		t.Fatalf("an interrupted import moved the head: have %d want %d", have, want)
	}
	// The block itself is untouched: the pass after the interruption adopts it.
	if _, _, err := chain.insertBlock(blocks[4]); err != nil {
		t.Fatalf("failed to re-import the known block after the interruption: %v", err)
	}
	if have, want := chain.CurrentBlock().Number.Uint64(), blocks[4].NumberU64(); have != want {
		t.Fatalf("head did not advance over the known block: have %d want %d", have, want)
	}
}

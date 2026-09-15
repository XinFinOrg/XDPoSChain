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

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// TestInsertSideChainReportsPureReimportSegmentWithoutTd covers a segment that holds no
// sidechain block at all: every one of its blocks is already canonical, so it added nothing
// to the chain and there is no accumulated total difficulty to compare it with. The scan
// ends on ErrUnknownAncestor, which the downloader blames on the peer - but the missing
// number lives in this node, not in the blocks, so the batch has to be reported as a local
// condition instead.
func TestInsertSideChainReportsPureReimportSegmentWithoutTd(t *testing.T) {
	chain, blocks := newInsertChainTester(t, nil, 6, 5) // head at #5

	// #4 is read back out of the database as a canonical re-import, and it is the only total
	// difficulty the scan could carry over.
	reimported := blocks[3]
	rawdb.DeleteTd(chain.ChainDb(), reimported.Hash(), reimported.NumberU64())
	chain.hc.tdCache.Remove(reimported.Hash())
	if td := chain.GetTd(reimported.Hash(), reimported.NumberU64()); td != nil {
		t.Fatal("precondition: the total difficulty is still readable")
	}

	batch := blocks[3:5] // #4 and #5
	results := make(chan error, len(batch))
	results <- consensus.ErrPrunedAncestor
	results <- consensus.ErrUnknownAncestor
	it := newInsertIterator(batch, results, chain.validator.(*BlockValidator))
	block, verr := it.next()
	if !errors.Is(verr, consensus.ErrPrunedAncestor) {
		t.Fatalf("unexpected verification result: have %v want %v", verr, consensus.ErrPrunedAncestor)
	}

	n, _, _, err := chain.insertSideChain(block, it, true)
	if !errors.Is(err, ErrLocalInsertCondition) {
		t.Fatalf("unexpected error: have %v want %v", err, ErrLocalInsertCondition)
	}
	if errors.Is(err, consensus.ErrUnknownAncestor) {
		t.Fatal("a segment this node cannot weigh must not be blamed on the peer's blocks")
	}
	if !IsLocalInsertError(err) {
		t.Fatalf("a segment this node cannot weigh says nothing about the peer: %v", err)
	}
	// The scan stopped on the second block of the batch, the one it could not link.
	if want := 1; n != want {
		t.Fatalf("unexpected failing index: have %d want %d", n, want)
	}
	if want := uint64(5); chain.CurrentBlock().Number.Uint64() != want {
		t.Fatalf("unexpected head number: have %d want %d", chain.CurrentBlock().Number.Uint64(), want)
	}
}

// TestInsertSideChainReportsFutureBlockAsLocal covers a pruned segment whose second block is
// dated ahead of this node's clock. The engine answers ErrFutureBlock from the timestamp alone,
// before it ever looks up the parent, so it takes nothing but a clock that stepped back - and
// the segment is written to disk as side entries either way. Blaming the peer for it would drop
// the peer that served a valid segment for a cause that lives in this node, the same one
// addFutureBlock already reports as a local condition.
func TestInsertSideChainReportsFutureBlockAsLocal(t *testing.T) {
	chain, blocks := newInsertChainTester(t, nil, 6, 5) // head at #5

	// #4 is read back out of the database as a canonical re-import and carries the total
	// difficulty over; #5 is the block whose timestamp the engine rejects.
	batch := blocks[3:5]
	results := make(chan error, len(batch))
	results <- consensus.ErrPrunedAncestor
	results <- consensus.ErrFutureBlock
	it := newInsertIterator(batch, results, chain.validator.(*BlockValidator))
	block, verr := it.next()
	if !errors.Is(verr, consensus.ErrPrunedAncestor) {
		t.Fatalf("unexpected verification result: have %v want %v", verr, consensus.ErrPrunedAncestor)
	}

	n, _, _, err := chain.insertSideChain(block, it, true)
	if !errors.Is(err, ErrLocalInsertCondition) {
		t.Fatalf("unexpected error: have %v want %v", err, ErrLocalInsertCondition)
	}
	if !errors.Is(err, consensus.ErrFutureBlock) {
		t.Fatalf("a local condition must keep the cause it wraps: have %v want %v", err, consensus.ErrFutureBlock)
	}
	if !IsLocalInsertError(err) {
		t.Fatalf("a block ahead of this node's clock says nothing about the peer: %v", err)
	}
	if classifyInsertErr(err).badBlock {
		t.Fatalf("a local condition must not be recorded as a bad block: %v", err)
	}
	// The scan stopped on the second block of the batch, the one the engine dated ahead.
	if want := 1; n != want {
		t.Fatalf("unexpected failing index: have %d want %d", n, want)
	}
	if want := uint64(5); chain.CurrentBlock().Number.Uint64() != want {
		t.Fatalf("unexpected head number: have %d want %d", chain.CurrentBlock().Number.Uint64(), want)
	}
}

// TestPrunedImportSideWithoutSidechainBlocks covers the segment shape TestPrunedImportSide
// never reaches: a batch made only of already stored, already canonical blocks whose state
// has been pruned. Every block of it is a re-import, so there is no sidechain total
// difficulty to accumulate and nothing to write - the batch is a no-op in which the head
// must not move, not a crash.
func TestPrunedImportSideWithoutSidechainBlocks(t *testing.T) {
	chain, blocks, _, _ := newPrunedCanonicalChain(t)

	// Everything below the state window is on disk and canonical, without any state.
	lastPruned := blocks[len(blocks)-TriesInMemory-1]
	if chain.HasBlockAndFullState(lastPruned.Hash(), lastPruned.NumberU64()) {
		t.Fatalf("block %d should be pruned", lastPruned.NumberU64())
	}
	batch := blocks[10:20]
	for _, block := range batch {
		if !chain.HasBlock(block.Hash(), block.NumberU64()) {
			t.Fatalf("block %d should be stored", block.NumberU64())
		}
	}
	head := chain.CurrentBlock()

	if n, err := chain.InsertChain(batch); err != nil {
		t.Fatalf("block %d: re-importing pruned canonical blocks: %v", n, err)
	}
	if now := chain.CurrentBlock(); now.Hash() != head.Hash() {
		t.Fatalf("head moved to %d, want it kept at %d", now.Number.Uint64(), head.Number.Uint64())
	}
}

// TestSideImportUsesTheLastStoredCanonicalTd pins which stored canonical block the
// sidechain total difficulty is based on when a segment opens on pruned canonical blocks.
// Keeping only the first one drops the difficulty of every block in between, which makes a
// sidechain that is one block longer than the canonical remainder look lighter than the
// head and skips the reorg it should have won.
func TestSideImportUsesTheLastStoredCanonicalTd(t *testing.T) {
	chain, blocks, engine, genDb := newPrunedCanonicalChain(t)

	// blocks holds 2*TriesInMemory blocks and everything up to and including index
	// TriesInMemory-1 has had its state pruned, so a segment opening there is a run of
	// re-imports whose total difficulty has to follow the last of them.
	const prefix = 100
	lastPruned := blocks[TriesInMemory-1] // #TriesInMemory, the fork starts right above it

	var sidechain []*types.Block
	for i := prefix; i > 0; i-- {
		sidechain = append(sidechain, blocks[TriesInMemory-i])
	}
	// One block longer than the canonical remainder: heavy enough to beat the head once the
	// whole prefix is counted, but not once only its first block is.
	fork, _ := GenerateChain(params.TestChainConfig, lastPruned, engine, genDb, TriesInMemory+1, func(i int, b *BlockGen) {
		b.SetCoinbase(common.Address{2})
	})
	sidechain = append(sidechain, fork...)

	if _, err := chain.InsertChain(sidechain); err != nil {
		t.Fatalf("failed to import the sidechain segment: %v", err)
	}
	head := chain.CurrentBlock()
	if want := fork[len(fork)-1]; head.Hash() != want.Hash() {
		t.Fatalf("head is %d / %x, want the fork tip %d / %x",
			head.Number.Uint64(), head.Hash(), want.NumberU64(), want.Hash())
	}
}

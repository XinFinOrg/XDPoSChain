// Copyright 2026 The XDPoSChain Authors
// This file is part of the XDPoSChain library.
//
// The XDPoSChain library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The XDPoSChain library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the XDPoSChain library. If not, see <http://www.gnu.org/licenses/>.

package core

import (
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/ethdb"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// copyStateRoot gives a block state on dst by copying its state root node from
// src, the database the chain was generated into. HasState only resolves the
// root node, so that is all a rewind needs to see the block as having state.
func copyStateRoot(t *testing.T, src ethdb.KeyValueReader, dst ethdb.KeyValueWriter, root common.Hash) {
	t.Helper()
	blob := rawdb.ReadLegacyTrieNode(src, root)
	if len(blob) == 0 {
		t.Fatalf("setup: state root %x missing from the generator database", root)
	}
	rawdb.WriteLegacyTrieNode(dst, root, blob)
}

// assertNoState fails the test if the block already has state, which would
// make the scenario a different one from what it claims to cover.
func assertNoState(t *testing.T, chain *BlockChain, block *types.Block) {
	t.Helper()
	if chain.HasState(block.Root()) {
		t.Fatalf("setup: block %d unexpectedly has state", block.NumberU64())
	}
}

// TestSetHeadSkipsStatelessIntermediateHeaders covers a --gcmode full rewind
// whose walk passes headers without state before it reaches a target that has
// state. The head block used to fall to genesis at the first such header and
// stay there, leaving header = target, block = 0.
func TestSetHeadSkipsStatelessIntermediateHeaders(t *testing.T) {
	chain, blocks, _, genDb := newPrunedCanonicalChain(t)

	const target = TriesInMemory / 2
	assertNoState(t, chain, blocks[target]) // block target+1
	copyStateRoot(t, genDb, chain.db, blocks[target-1].Root())

	if err := chain.SetHead(target); err != nil {
		t.Fatalf("SetHead: %v", err)
	}
	if n := chain.CurrentBlock().Number.Uint64(); n != target {
		t.Errorf("head block: have %d, want %d", n, target)
	}
	if n := chain.CurrentHeader().Number.Uint64(); n != target {
		t.Errorf("head header: have %d, want %d", n, target)
	}
	if n := chain.CurrentSnapBlock().Number.Uint64(); n != target {
		t.Errorf("head snap block: have %d, want %d", n, target)
	}
}

// TestSetHeadTargetWithoutState checks that a target with no state leaves the
// head block on the nearest lower block that has state, not on genesis.
func TestSetHeadTargetWithoutState(t *testing.T) {
	chain, blocks, _, genDb := newPrunedCanonicalChain(t)

	const (
		target   = TriesInMemory/2 + 100
		stateful = TriesInMemory / 2
	)
	for n := stateful + 1; n <= target; n++ {
		assertNoState(t, chain, blocks[n-1])
	}
	copyStateRoot(t, genDb, chain.db, blocks[stateful-1].Root())

	if err := chain.SetHead(target); err != nil {
		t.Fatalf("SetHead: %v", err)
	}
	head := chain.CurrentBlock()
	if n := head.Number.Uint64(); n != stateful {
		t.Errorf("head block: have %d, want %d", n, stateful)
	}
	if !chain.HasState(head.Root) {
		t.Errorf("head block %d has no state", head.Number)
	}
	if n := chain.CurrentHeader().Number.Uint64(); n != target {
		t.Errorf("head header: have %d, want %d", n, target)
	}
}

// TestSetHeadBelowPivotFallsBackToGenesis checks that the search for a block
// with state stops at the last fast sync pivot: below it no state was ever
// stored, so the head block goes to genesis, as before, without walking the
// rest of the chain.
func TestSetHeadBelowPivotFallsBackToGenesis(t *testing.T) {
	chain, blocks, _, genDb := newPrunedCanonicalChain(t)

	const (
		pivot  = TriesInMemory/2 + 200
		target = TriesInMemory/2 + 100
	)
	rawdb.WriteLastPivotNumber(chain.db, pivot)
	// State below the pivot that the search must not reach.
	copyStateRoot(t, genDb, chain.db, blocks[TriesInMemory/2-1].Root())

	if err := chain.SetHead(target); err != nil {
		t.Fatalf("SetHead: %v", err)
	}
	if n := chain.CurrentBlock().Number.Uint64(); n != 0 {
		t.Errorf("head block: have %d, want 0", n)
	}
	if n := chain.CurrentHeader().Number.Uint64(); n != target {
		t.Errorf("head header: have %d, want %d", n, target)
	}
}

// TestSetHeadAncientKeepsHeadBlockWithState runs a rewind into the ancient store
// across headers without state: delFn truncates the freezer, and the head block
// must still land on the target.
func TestSetHeadAncientKeepsHeadBlockWithState(t *testing.T) {
	gspec := &Genesis{Config: params.TestChainConfig}
	const (
		numBlocks    = 64
		ancientLimit = 40
		target       = 30
	)
	genDb, blocks, receipts := GenerateChainWithGenesis(gspec, ethash.NewFaker(), numBlocks, nil)

	db := newFreezerChainDB(t)
	chain, err := NewBlockChain(db, nil, gspec, ethash.NewFaker(), vm.Config{})
	if err != nil {
		t.Fatalf("new blockchain: %v", err)
	}
	if n, err := chain.InsertReceiptChain(blocks, receipts, ancientLimit, 0); err != nil {
		t.Fatalf("failed to insert receipt %d: %v", n, err)
	}
	chain.Stop()

	// Give only the head and the target state, and make the head the head block.
	head := blocks[numBlocks-1]
	copyStateRoot(t, genDb, db, head.Root())
	copyStateRoot(t, genDb, db, blocks[target-1].Root())
	rawdb.WriteHeadBlockHash(db, head.Hash())

	chain, err = NewBlockChain(db, nil, gspec, ethash.NewFaker(), vm.Config{})
	if err != nil {
		t.Fatalf("reopen blockchain: %v", err)
	}
	defer chain.Stop()
	if n := chain.CurrentBlock().Number.Uint64(); n != numBlocks {
		t.Fatalf("setup: head block got %d, want %d", n, numBlocks)
	}
	if frozen, _ := db.Ancients(); frozen != ancientLimit {
		t.Fatalf("setup: ancient item count got %d, want %d", frozen, ancientLimit)
	}
	assertNoState(t, chain, blocks[numBlocks-2])
	assertNoState(t, chain, blocks[target])

	if err := chain.SetHead(target); err != nil {
		t.Fatalf("SetHead: %v", err)
	}
	if frozen, _ := db.Ancients(); frozen != target+1 {
		t.Errorf("ancient item count: got %d, want %d", frozen, target+1)
	}
	if n := chain.CurrentBlock().Number.Uint64(); n != target {
		t.Errorf("head block: have %d, want %d", n, target)
	}
	if n := chain.CurrentHeader().Number.Uint64(); n != target {
		t.Errorf("head header: have %d, want %d", n, target)
	}
}

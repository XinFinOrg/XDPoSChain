// Copyright 2020 The go-ethereum Authors
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
	"fmt"
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// TestSetHeadCleansDanglingBlocks verifies that SetHead removes not only the
// canonical chain segment being rewound, but also any orphaned/dangling block
// data sitting above the current head (e.g. leftover from a previously
// interrupted rewind). Without this, the downloader's ancestor search can
// "jump" back onto the stale data instead of re-syncing the range.
func TestSetHeadCleansDanglingBlocks(t *testing.T) {
	var (
		engine  = ethash.NewFaker()
		genesis = &Genesis{
			BaseFee: big.NewInt(params.InitialBaseFee),
			Config:  params.AllEthashProtocolChanges,
		}
		db = rawdb.NewMemoryDatabase()
	)
	// Archive mode so every state is persisted and rewinding to an arbitrary
	// height lands exactly on that block instead of an earlier stateful one.
	chain, err := NewBlockChain(db, &CacheConfig{TrieDirtyDisabled: true}, genesis, engine, vm.Config{})
	if err != nil {
		t.Fatalf("failed to create chain: %v", err)
	}
	defer chain.Stop()

	_, blocks, _ := GenerateChainWithGenesis(genesis, engine, 64, nil)

	// Import blocks 1..32 as the canonical chain; head is now at 32.
	if _, err := chain.InsertChain(blocks[:32]); err != nil {
		t.Fatalf("failed to insert canonical chain: %v", err)
	}
	if head := chain.CurrentBlock().Number.Uint64(); head != 32 {
		t.Fatalf("unexpected head after import: have %d want 32", head)
	}

	// Simulate leftover data above the head by writing blocks 33..64 directly
	// to the database without advancing any head marker, mimicking a rewind
	// that was interrupted before its deletion batch was flushed.
	for _, block := range blocks[32:] {
		rawdb.WriteBlock(db, block)
	}
	for _, block := range blocks[32:] {
		if !chain.HasBlock(block.Hash(), block.NumberU64()) {
			t.Fatalf("setup failed: dangling block #%d not present", block.NumberU64())
		}
	}

	// Rewind the chain to block 16.
	if err := chain.SetHead(16); err != nil {
		t.Fatalf("failed to set head: %v", err)
	}
	if head := chain.CurrentBlock().Number.Uint64(); head != 16 {
		t.Fatalf("unexpected head after SetHead: have %d want 16", head)
	}

	// Every block above the new head must be gone: both the rewound canonical
	// segment (17..32) and the dangling leftover data (33..64).
	for _, block := range blocks[16:] {
		if chain.HasBlock(block.Hash(), block.NumberU64()) {
			t.Errorf("block #%d still present after SetHead, want wiped", block.NumberU64())
		}
	}
}

// TestSetHeadCleansDanglingBlocksAcrossGap verifies that SetHead wipes orphaned
// block data above the head even when it is NOT contiguous with the head, i.e.
// there is a gap between the head and the leftover data. This mirrors the real
// world failure where a fork/rollback leaves a disconnected canonical segment
// far above the head, causing the downloader to "jump" onto it.
func TestSetHeadCleansDanglingBlocksAcrossGap(t *testing.T) {
	var (
		engine  = ethash.NewFaker()
		genesis = &Genesis{
			BaseFee: big.NewInt(params.InitialBaseFee),
			Config:  params.AllEthashProtocolChanges,
		}
		db = rawdb.NewMemoryDatabase()
	)
	chain, err := NewBlockChain(db, &CacheConfig{TrieDirtyDisabled: true}, genesis, engine, vm.Config{})
	if err != nil {
		t.Fatalf("failed to create chain: %v", err)
	}
	defer chain.Stop()

	_, blocks, _ := GenerateChainWithGenesis(genesis, engine, 64, nil)

	// Import blocks 1..32 as the canonical chain; head is now at 32.
	if _, err := chain.InsertChain(blocks[:32]); err != nil {
		t.Fatalf("failed to insert canonical chain: %v", err)
	}

	// Write only blocks 40..64 as leftover data, leaving a GAP at heights
	// 33..39. This mimics an aborted rollback that deleted a contiguous chunk
	// just above the head but left a disconnected orphaned segment higher up.
	for _, block := range blocks[39:] {
		rawdb.WriteBlock(db, block)
	}
	for _, block := range blocks[39:] {
		if !chain.HasBlock(block.Hash(), block.NumberU64()) {
			t.Fatalf("setup failed: dangling block #%d not present", block.NumberU64())
		}
	}

	// Rewind the chain to block 16.
	if err := chain.SetHead(16); err != nil {
		t.Fatalf("failed to set head: %v", err)
	}
	if head := chain.CurrentBlock().Number.Uint64(); head != 16 {
		t.Fatalf("unexpected head after SetHead: have %d want 16", head)
	}

	// The disconnected orphaned segment 40..64 (across the 33..39 gap) must be
	// wiped, not just the contiguous range immediately above the head.
	for _, block := range blocks[39:] {
		if chain.HasBlock(block.Hash(), block.NumberU64()) {
			t.Errorf("dangling block #%d across gap still present after SetHead, want wiped", block.NumberU64())
		}
	}
}

// TestSetHeadCleansSideForkHashes verifies that SetHead removes all hashes at a
// rewound height, including side-fork/orphan hashes that share the same block
// number as canonical blocks.
func TestSetHeadCleansSideForkHashes(t *testing.T) {
	var (
		engine  = ethash.NewFaker()
		genesis = &Genesis{
			BaseFee: big.NewInt(params.InitialBaseFee),
			Config:  params.AllEthashProtocolChanges,
		}
		db = rawdb.NewMemoryDatabase()
	)
	chain, err := NewBlockChain(db, &CacheConfig{TrieDirtyDisabled: true}, genesis, engine, vm.Config{})
	if err != nil {
		t.Fatalf("failed to create chain: %v", err)
	}
	defer chain.Stop()

	_, blocks, _ := GenerateChainWithGenesis(genesis, engine, 64, nil)

	// Import a canonical chain to height 32.
	if _, err := chain.InsertChain(blocks[:32]); err != nil {
		t.Fatalf("failed to insert canonical chain: %v", err)
	}

	// Build an alternate fork from canonical block #16, yielding fork blocks
	// #17..#20 with hashes different from canonical blocks at those heights.
	forkBlocks, _ := GenerateChain(genesis.Config, blocks[15], engine, db, 4, func(i int, gen *BlockGen) {
		gen.SetExtra([]byte(fmt.Sprintf("side-fork-%d", i)))
	})
	for _, block := range forkBlocks {
		rawdb.WriteBlock(db, block)
	}

	// At fork height #17 we should now have at least two hashes: canonical + fork.
	if hashes := rawdb.ReadAllHashes(db, forkBlocks[0].NumberU64()); len(hashes) < 2 {
		t.Fatalf("setup failed: expected >=2 hashes at height %d, have %d", forkBlocks[0].NumberU64(), len(hashes))
	}

	// Rewind to block 16; both canonical (17..32) and side-fork (17..20) data
	// must be wiped.
	if err := chain.SetHead(16); err != nil {
		t.Fatalf("failed to set head: %v", err)
	}
	if head := chain.CurrentBlock().Number.Uint64(); head != 16 {
		t.Fatalf("unexpected head after SetHead: have %d want 16", head)
	}

	for _, block := range blocks[16:32] {
		if chain.HasBlock(block.Hash(), block.NumberU64()) {
			t.Errorf("canonical block #%d still present after SetHead, want wiped", block.NumberU64())
		}
	}
	for _, block := range forkBlocks {
		if chain.HasBlock(block.Hash(), block.NumberU64()) {
			t.Errorf("side-fork block #%d still present after SetHead, want wiped", block.NumberU64())
		}
	}
}

// TestSetHeadCleansRawdbMultiHashesAtSameHeight verifies that SetHead removes
// all header-hash entries at rewound heights from rawdb, even if multiple
// orphan blocks are present at the same block number.
func TestSetHeadCleansRawdbMultiHashesAtSameHeight(t *testing.T) {
	var (
		engine  = ethash.NewFaker()
		genesis = &Genesis{
			BaseFee: big.NewInt(params.InitialBaseFee),
			Config:  params.AllEthashProtocolChanges,
		}
		db = rawdb.NewMemoryDatabase()
	)
	chain, err := NewBlockChain(db, &CacheConfig{TrieDirtyDisabled: true}, genesis, engine, vm.Config{})
	if err != nil {
		t.Fatalf("failed to create chain: %v", err)
	}
	defer chain.Stop()

	_, blocks, _ := GenerateChainWithGenesis(genesis, engine, 64, nil)
	if _, err := chain.InsertChain(blocks[:32]); err != nil {
		t.Fatalf("failed to insert canonical chain: %v", err)
	}

	// Write two extra orphan blocks at height 17 directly into rawdb.
	orphanA, _ := GenerateChain(genesis.Config, blocks[15], engine, db, 1, func(_ int, gen *BlockGen) {
		gen.SetExtra([]byte("orphan-a"))
	})
	orphanB, _ := GenerateChain(genesis.Config, blocks[15], engine, db, 1, func(_ int, gen *BlockGen) {
		gen.SetExtra([]byte("orphan-b"))
	})
	rawdb.WriteBlock(db, orphanA[0])
	rawdb.WriteBlock(db, orphanB[0])

	if hashes := rawdb.ReadAllHashes(db, 17); len(hashes) < 3 {
		t.Fatalf("setup failed: expected >=3 hashes at height 17, have %d", len(hashes))
	}

	if err := chain.SetHead(16); err != nil {
		t.Fatalf("failed to set head: %v", err)
	}

	if hashes := rawdb.ReadAllHashes(db, 17); len(hashes) != 0 {
		t.Fatalf("height 17 still has %d hashes after SetHead, want 0", len(hashes))
	}
	if chain.HasBlock(orphanA[0].Hash(), orphanA[0].NumberU64()) {
		t.Fatalf("orphan-a block still present after SetHead")
	}
	if chain.HasBlock(orphanB[0].Hash(), orphanB[0].NumberU64()) {
		t.Fatalf("orphan-b block still present after SetHead")
	}
}

// TestSetHeadCleansOnlyBadBlocksAboveHead verifies that SetHead only removes
// bad block records for blocks strictly above the target height, preserving
// debugging data for blocks at or below the head.
func TestSetHeadCleansOnlyBadBlocksAboveHead(t *testing.T) {
	var (
		engine  = ethash.NewFaker()
		genesis = &Genesis{
			BaseFee: big.NewInt(params.InitialBaseFee),
			Config:  params.AllEthashProtocolChanges,
		}
		db = rawdb.NewMemoryDatabase()
	)
	chain, err := NewBlockChain(db, &CacheConfig{TrieDirtyDisabled: true}, genesis, engine, vm.Config{})
	if err != nil {
		t.Fatalf("failed to create chain: %v", err)
	}
	defer chain.Stop()

	// Build a chain 0..20
	blocks, _ := GenerateChain(genesis.Config, chain.Genesis(), engine, db, 20, nil)
	if _, err := chain.InsertChain(blocks); err != nil {
		t.Fatalf("failed to insert chain: %v", err)
	}

	// Create some bad block records
	badBlockLow := blocks[5]   // at height 6, below head
	badBlockHigh := blocks[15] // at height 16, above rewind target

	rawdb.WriteBadBlock(db, badBlockLow)
	rawdb.WriteBadBlock(db, badBlockHigh)

	// Verify both bad blocks are recorded
	allBadBefore := rawdb.ReadAllBadBlocks(db)
	if len(allBadBefore) != 2 {
		t.Fatalf("expected 2 bad blocks before SetHead, have %d", len(allBadBefore))
	}

	// Rewind to height 10 (below the high bad block)
	if err := chain.SetHead(10); err != nil {
		t.Fatalf("failed to set head: %v", err)
	}

	// Verify high bad block is cleaned (number 16 > 10)
	allBadAfter := rawdb.ReadAllBadBlocks(db)
	if len(allBadAfter) != 1 {
		t.Fatalf("expected 1 bad block after SetHead(10), have %d", len(allBadAfter))
	}

	// Verify the remaining bad block is the low one (number 6 <= 10)
	remaining := allBadAfter[0]
	if remaining.NumberU64() != 6 {
		t.Fatalf("remaining bad block has wrong number: got %d, want 6", remaining.NumberU64())
	}
	if remaining.Hash() != badBlockLow.Hash() {
		t.Fatalf("remaining bad block has wrong hash: got %x, want %x", remaining.Hash(), badBlockLow.Hash())
	}
}

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

// TestSetHeadCleansOnlyXdposSnapshotsAboveHead verifies that SetHead removes
// XDPoS snapshots strictly above the target height while preserving snapshots
// at or below the new head.
func TestSetHeadCleansOnlyXdposSnapshotsAboveHead(t *testing.T) {
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

	// Build a chain 0..25.
	blocks, _ := GenerateChain(genesis.Config, chain.Genesis(), engine, db, 25, nil)
	if _, err := chain.InsertChain(blocks); err != nil {
		t.Fatalf("failed to insert chain: %v", err)
	}

	// Enable XDPoS snapshot-number gating for SetHead cleanup only.
	// (Applied after import to avoid triggering UpdateM1 on ethash blocks.)
	configWithXdpos := genesis.Config.Clone()
	configWithXdpos.XDPoS = &params.XDPoSConfig{Epoch: 5, Gap: 4}
	chain.SetChainConfig(configWithXdpos)

	// Create snapshot records with mutually exclusive versions per hash.
	low := blocks[5]         // height 6, should be kept by SetHead(10)
	highV2 := blocks[15]     // height 16, should be removed via V2 path
	highV1Only := blocks[20] // height 21, should be removed via V1 fallback path

	if err := rawdb.WriteXdposV1Snapshot(db, low.Hash(), []byte(`{"number":6}`)); err != nil {
		t.Fatalf("failed to write v1 low snapshot: %v", err)
	}
	if err := rawdb.WriteXdposV2Snapshot(db, highV2.Hash(), []byte(`{"number":16}`)); err != nil {
		t.Fatalf("failed to write v2 high snapshot: %v", err)
	}
	if err := rawdb.WriteXdposV1Snapshot(db, highV1Only.Hash(), []byte(`{"number":21}`)); err != nil {
		t.Fatalf("failed to write v1 high-only snapshot: %v", err)
	}

	if _, err := rawdb.ReadXdposV1Snapshot(db, low.Hash()); err != nil {
		t.Fatalf("expected v1 low snapshot to exist before SetHead: %v", err)
	}
	if _, err := rawdb.ReadXdposV2Snapshot(db, highV2.Hash()); err != nil {
		t.Fatalf("expected v2 high snapshot to exist before SetHead: %v", err)
	}
	if _, err := rawdb.ReadXdposV1Snapshot(db, highV1Only.Hash()); err != nil {
		t.Fatalf("expected v1 high-only snapshot to exist before SetHead: %v", err)
	}

	if err := chain.SetHead(10); err != nil {
		t.Fatalf("failed to set head: %v", err)
	}

	if _, err := rawdb.ReadXdposV1Snapshot(db, low.Hash()); err != nil {
		t.Fatalf("expected v1 low snapshot to be kept after SetHead: %v", err)
	}
	if _, err := rawdb.ReadXdposV2Snapshot(db, highV2.Hash()); err == nil {
		t.Fatalf("expected v2 high snapshot to be removed after SetHead")
	}
	if _, err := rawdb.ReadXdposV1Snapshot(db, highV1Only.Hash()); err == nil {
		t.Fatalf("expected v1 high-only snapshot to be removed after SetHead")
	}
}

// TestSetHeadKeepsXdposSnapshotsWithoutAGap pins the other side of the gap predicate: with Gap == 0
// (or Gap > Epoch) it cannot match any height, so a rewind deletes no snapshot at all. The heights
// below are the epoch boundaries the (num+Gap)%Epoch == 0 form used to match, which is exactly the
// range this predicate is written to stop deleting: engine_v2 expresses the gap block as
// num%Epoch == Epoch-Gap, and with Gap == 0 that is unreachable, so accepting those heights here
// would have UpdateM1 run at every epoch switch and hit its log.Crit.
//
// The entries are keyed by block hash, so a rewound block's snapshot is never loaded again - the
// leftover is a leak rather than a wrong answer, and that is what this test pins.
func TestSetHeadKeepsXdposSnapshotsWithoutAGap(t *testing.T) {
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

	// Build a chain 0..25.
	blocks, _ := GenerateChain(genesis.Config, chain.Genesis(), engine, db, 25, nil)
	if _, err := chain.InsertChain(blocks); err != nil {
		t.Fatalf("failed to insert chain: %v", err)
	}

	// Applied after the import, like the test above: an XDPoS config in place during the import
	// would have the gap predicate - and with it UpdateM1 - reach blocks the chain has no
	// snapshots for. Gap 0 makes it unmatchable, which is what the rewind is being checked for.
	configWithXdpos := genesis.Config.Clone()
	configWithXdpos.XDPoS = &params.XDPoSConfig{Epoch: 5, Gap: 0}
	chain.SetChainConfig(configWithXdpos)

	// Heights 5 and 10: both are epoch boundaries and both are above the new head.
	rewound := []int{4, 9}
	for _, i := range rewound {
		block := blocks[i]
		if err := rawdb.WriteXdposV1Snapshot(db, block.Hash(), []byte(`{"number":1}`)); err != nil {
			t.Fatalf("failed to write the v1 snapshot for #%d: %v", block.NumberU64(), err)
		}
		if err := rawdb.WriteXdposV2Snapshot(db, block.Hash(), []byte(`{"number":1}`)); err != nil {
			t.Fatalf("failed to write the v2 snapshot for #%d: %v", block.NumberU64(), err)
		}
	}

	if err := chain.SetHead(2); err != nil {
		t.Fatalf("failed to set head: %v", err)
	}

	for _, i := range rewound {
		block := blocks[i]
		if chain.HasBlock(block.Hash(), block.NumberU64()) {
			t.Fatalf("block #%d is below the new head and must be gone", block.NumberU64())
		}
		if _, err := rawdb.ReadXdposV1Snapshot(db, block.Hash()); err != nil {
			t.Fatalf("the v1 snapshot of the rewound #%d was deleted: %v", block.NumberU64(), err)
		}
		if _, err := rawdb.ReadXdposV2Snapshot(db, block.Hash()); err != nil {
			t.Fatalf("the v2 snapshot of the rewound #%d was deleted: %v", block.NumberU64(), err)
		}
	}
}

// TestSetHeadRemovesExecutedMarkers pins the other end of the executed-block marker's life: a
// rewind deletes the body and the receipts of every block above the new head, and the marker
// has to go with them. A marker left behind would answer that this node executed a block whose
// receipts it no longer holds - a record it cannot read anything from - and db inspect would
// count it into the receipts bucket it belongs to no more.
func TestSetHeadRemovesExecutedMarkers(t *testing.T) {
	var (
		engine  = ethash.NewFaker()
		genesis = &Genesis{
			BaseFee: big.NewInt(params.InitialBaseFee),
			Config:  params.AllEthashProtocolChanges,
		}
		db = rawdb.NewMemoryDatabase()
	)
	// Archive mode so that every state is persisted and the rewind lands on the height asked
	// for, which is what lets the blocks above it be deleted one by one.
	chain, err := NewBlockChain(db, &CacheConfig{TrieDirtyDisabled: true}, genesis, engine, vm.Config{})
	if err != nil {
		t.Fatalf("failed to create chain: %v", err)
	}
	defer chain.Stop()

	_, blocks, _ := GenerateChainWithGenesis(genesis, engine, 32, nil)
	if _, err := chain.InsertChain(blocks); err != nil {
		t.Fatalf("failed to insert the chain: %v", err)
	}
	for _, block := range blocks {
		if !rawdb.HasExecutedMarker(db, block.Hash(), block.NumberU64()) {
			t.Fatalf("block #%d was executed, it must carry the marker", block.NumberU64())
		}
	}
	if err := chain.SetHead(16); err != nil {
		t.Fatalf("failed to set head: %v", err)
	}
	for _, block := range blocks {
		number := block.NumberU64()
		if number > 16 {
			if rawdb.HasReceipts(db, block.Hash(), number) {
				t.Errorf("the rewound block #%d kept its receipts", number)
			}
			if rawdb.HasExecutedMarker(db, block.Hash(), number) {
				t.Errorf("the rewound block #%d kept its executed marker", number)
			}
			continue
		}
		if !rawdb.HasExecutedMarker(db, block.Hash(), number) {
			t.Errorf("block #%d is at or below the new head, its marker must stay", number)
		}
	}
}

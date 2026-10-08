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

package downloader

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS/engines/engine_v2"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// TestFastSyncGapPivotResumesAfterInterruption guards the gap pivots of a resumed fast
// sync: once a cycle has committed every block below the configured pivot and then
// failed, the next cycle starts at the pivot, so the gap pivot blocks are never
// downloaded again. They must be read back from the local chain instead of failing
// every later cycle with "gap pivot block not found in downloaded results".
//
// Chain layout (Epoch=900, Gap=450, pivot=535, gap pivot=[450]):
//
//	local:  blocks 1-534 stored as fast blocks, head block still genesis
//	resume: sync starts at block 535, gap pivot 450 comes from the local chain
func TestFastSyncGapPivotResumesAfterInterruption(t *testing.T) {
	t.Parallel()

	tester := newTester()
	// TestXDPoSMockChainConfig has Epoch=900, Gap=450.
	tester.configOverride = params.TestXDPoSMockChainConfig
	defer tester.terminate()

	// 600 blocks: natural pivot = 600-1-64 = 535, gap pivot = 450.
	chainLen := 600
	chain := testChainBase.shorten(chainLen)
	tester.newPeer("peer", xdc100, chain)

	pivotNum := uint64(chainLen - 1 - fsMinFullBlocks) // = 535
	pivotHash := chain.headerm[chain.chain[pivotNum]].Hash()
	pivotRoot := chain.headerm[chain.chain[pivotNum]].Root
	gapHash := chain.headerm[chain.chain[450]].Hash()

	// Leave the local chain where an interrupted cycle does: every block below the
	// pivot committed with its receipts, but neither the pivot nor any state. Seeding
	// it directly keeps the processHeaders safety-net rollback, which covers this
	// whole short chain, from rewinding the snap head below the gap pivot.
	for _, hash := range chain.chain[1:pivotNum] {
		tester.ownHashes = append(tester.ownHashes, hash)
		tester.ownHeaders[hash] = chain.headerm[hash]
		tester.ownBlocks[hash] = chain.blockm[hash]
		tester.ownReceipts[hash] = chain.receiptm[hash]
		tester.ownChainTd[hash] = chain.tdm[hash]
	}
	if have := tester.CurrentSnapBlock().Number.Uint64(); have != pivotNum-1 {
		t.Fatalf("seeded snap head = %d, want %d", have, pivotNum-1)
	}

	tester.downloader.SetPivotBlock(pivotNum, pivotHash, pivotRoot)
	if err := tester.sync("peer", nil, FastSync); err != nil {
		t.Fatalf("resumed fast sync failed: %v", err)
	}
	assertOwnChain(t, tester, chainLen)

	if has, err := rawdb.HasXdposV2Snapshot(tester.downloader.stateDB, gapHash); err != nil || !has {
		t.Fatalf("gap pivot snapshot after resumed sync: has %v, err %v; want stored", has, err)
	}
}

// TestFastSyncAutoPivotGapSnapshot guards the gap snapshots of a fast sync without a
// configured pivot. The blocks below the automatically chosen pivot are never executed, so
// unless fast sync derives the snapshot of the gap block below it from synced state, the
// first epoch switch after the pivot stops on a missing snapshot.
//
// Chain layout (Epoch=900, Gap=450, automatic pivot=600-1-64=535, gap pivot=[450]):
//
//	fresh:  the whole chain is fetched in this cycle
//	resume: blocks 1-534 are already stored as fast blocks, so the cycle starts at the
//	        pivot and gap block 450 has to be read back from the local chain
func TestFastSyncAutoPivotGapSnapshot(t *testing.T) {
	t.Parallel()

	for _, resume := range []bool{false, true} {
		name := "fresh"
		if resume {
			name = "resume"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			tester := newTester()
			// TestXDPoSMockChainConfig has Epoch=900, Gap=450.
			tester.configOverride = params.TestXDPoSMockChainConfig
			defer tester.terminate()

			chainLen := 600
			chain := testChainBase.shorten(chainLen)
			tester.newPeer("peer", xdc100, chain)

			pivotNum := uint64(chainLen - 1 - fsMinFullBlocks) // = 535, chosen by the downloader
			if resume {
				for _, hash := range chain.chain[1:pivotNum] {
					tester.ownHashes = append(tester.ownHashes, hash)
					tester.ownHeaders[hash] = chain.headerm[hash]
					tester.ownBlocks[hash] = chain.blockm[hash]
					tester.ownReceipts[hash] = chain.receiptm[hash]
					tester.ownChainTd[hash] = chain.tdm[hash]
				}
			}
			// No SetPivotBlock: the pivot is the downloader's own choice.
			if err := tester.sync("peer", nil, FastSync); err != nil {
				t.Fatalf("fast sync failed: %v", err)
			}
			assertOwnChain(t, tester, chainLen)
			assertGapSnapshot(t, tester, 450, chain.headerm[chain.chain[450]].Hash())
		})
	}
}

// TestGapPivotNumbersWithoutXDPoS checks that a chain without XDPoS schedules no gap
// pivots, so an automatic-pivot fast sync there is unchanged.
func TestGapPivotNumbersWithoutXDPoS(t *testing.T) {
	t.Parallel()

	tester := newTester()
	defer tester.terminate()
	if gaps := tester.downloader.gapPivotNumbers(2251); gaps != nil {
		t.Fatalf("gap pivots without XDPoS = %v, want none", gaps)
	}
}

// assertGapSnapshot checks that the snapshot of gap block number is stored under hash
// and names that block and the test masternodes.
func assertGapSnapshot(t *testing.T, tester *downloadTester, number uint64, hash common.Hash) {
	t.Helper()
	blob, err := rawdb.ReadXdposV2Snapshot(tester.downloader.stateDB, hash)
	if err != nil || len(blob) == 0 {
		t.Fatalf("snapshot for gap block %d not stored: %v", number, err)
	}
	var snap engine_v2.SnapshotV2
	if err := json.Unmarshal(blob, &snap); err != nil {
		t.Fatalf("snapshot for gap block %d undecodable: %v", number, err)
	}
	if snap.Number != number || snap.Hash != hash {
		t.Errorf("snapshot names block %d %v, want %d %v", snap.Number, snap.Hash, number, hash)
	}
	if !slices.Equal(snap.NextEpochCandidates, testMasternodes) {
		t.Errorf("snapshot candidates = %v, want %v", snap.NextEpochCandidates, testMasternodes)
	}
}

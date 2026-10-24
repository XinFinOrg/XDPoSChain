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

package rawdb

import (
	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/ethdb"
	"github.com/XinFinOrg/XDPoSChain/log"
	"github.com/XinFinOrg/XDPoSChain/metrics"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// minimalRetention is how many recent blocks keep their bodies and receipts in
// minimal history mode, whatever the data file layout. The deepest consensus
// lookback is GetRewardForCheckpoint (contracts/utils.go), which walks
// 2*RewardCheckpoint (1800 on all networks) blocks back reading transactions
// and raw receipts; pruning above that line breaks reward and penalty
// calculation. The floor is the immutability threshold's floor rather than
// 1800 to leave room for a deeper lookback. See claude/plan §3.10 and §4.2.
//
// The freezer only freezes blocks FullImmutabilityThreshold (itself floored at
// this value) behind the head, so this term binds only when the threshold is
// set to its floor. It must hold regardless: with a small
// XDC_FREEZER_TABLE_SIZE the data file boundary alone would prune into the
// consensus window.
const minimalRetention = params.MinFullImmutabilityThreshold

var (
	minimalTailGauge          = metrics.NewRegisteredGauge("rawdb/minimal/tail", nil)
	minimalPrunedBodiesMeter  = metrics.NewRegisteredMeter("rawdb/minimal/pruned/bodies", nil)
	minimalPrunedReceiptMeter = metrics.NewRegisteredMeter("rawdb/minimal/pruned/receipts", nil)
)

// pruneTarget returns the block data tail minimal history mode prunes to,
// given the chain head and the largest tail that deletes only whole data files:
// the lower of that boundary and the consensus retention floor.
func pruneTarget(head, boundary uint64) uint64 {
	if head < minimalRetention {
		return 0
	}
	return min(boundary, head-minimalRetention)
}

// readPruneHead returns the number of the chain head the retention floor is
// measured from: the higher of the head block and the head fast block. During a
// fast sync the head block stays at genesis while the ancient store fills up to
// the pivot, so the fast block is what bounds the frozen range then; afterwards
// the two coincide.
func readPruneHead(db ethdb.KeyValueReader) uint64 {
	var head uint64
	for _, hash := range []common.Hash{ReadHeadBlockHash(db), ReadHeadFastBlockHash(db)} {
		if hash == (common.Hash{}) {
			continue
		}
		if number := ReadHeaderNumber(db, hash); number != nil {
			head = max(head, *number)
		}
	}
	return head
}

// pruneBlockData truncates the tail of the block data group in minimal history
// mode, so that the frozen bodies and receipts shrink to the newest data file
// of each table, clamped by the consensus retention floor. It is a no-op for a
// database in full mode, and when nothing new became prunable.
//
// It runs on the freezer goroutine, so it never races a freeze cycle.
func (f *chainFreezer) pruneBlockData(db ethdb.KeyValueReader) error {
	if ReadHistoryMode(db) != HistoryModeMinimal {
		return nil
	}
	prev, err := f.Tail(ChainFreezerBlockDataGroup)
	if err != nil {
		return err
	}
	// A file-based freezer deletes whole data files only. An in-memory freezer
	// has no files, so all of it is prunable down to the retention floor.
	var boundary uint64
	if freezer, ok := f.ancients.(*Freezer); ok {
		if boundary, err = freezer.tailFileBoundary(ChainFreezerBlockDataGroup); err != nil {
			return err
		}
	} else if boundary, err = f.Ancients(); err != nil {
		return err
	}
	target := pruneTarget(readPruneHead(db), boundary)
	if target <= prev {
		return nil
	}
	bodies, _ := f.AncientSize(ChainFreezerBodiesTable)
	receipts, _ := f.AncientSize(ChainFreezerReceiptTable)
	if _, err := f.TruncateTail(ChainFreezerBlockDataGroup, target); err != nil {
		return err
	}
	newBodies, _ := f.AncientSize(ChainFreezerBodiesTable)
	newReceipts, _ := f.AncientSize(ChainFreezerReceiptTable)

	minimalTailGauge.Update(int64(target))
	minimalPrunedBodiesMeter.Mark(int64(bodies - min(bodies, newBodies)))
	minimalPrunedReceiptMeter.Mark(int64(receipts - min(receipts, newReceipts)))
	log.Info("Pruned ancient block data", "tail", target, "previous", prev,
		"freed", common.StorageSize(bodies+receipts-min(bodies+receipts, newBodies+newReceipts)))
	return nil
}

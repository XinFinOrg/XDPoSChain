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

package state

import (
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/types"
)

// TestAddLogSnapshotRevert pins that a log emitted inside a call frame is
// journaled like any other state change: reverting the snapshot removes it and
// rolls the log index back, so the next log reuses the index. EIP-7708 transfer
// logs rely on this to disappear together with a reverted frame.
func TestAddLogSnapshotRevert(t *testing.T) {
	sdb, err := New(types.EmptyRootHash, NewDatabase(rawdb.NewMemoryDatabase()))
	if err != nil {
		t.Fatalf("failed to create state: %v", err)
	}
	txHash := common.HexToHash("0x01")
	sdb.SetTxContext(txHash, 0)

	snap := sdb.Snapshot()
	sdb.AddLog(&types.Log{Address: common.HexToAddress("0xaa")})
	if logs := sdb.GetLogs(txHash, 1, common.Hash{}); len(logs) != 1 {
		t.Fatalf("log count before revert = %d, want 1", len(logs))
	}
	sdb.RevertToSnapshot(snap)
	if logs := sdb.GetLogs(txHash, 1, common.Hash{}); len(logs) != 0 {
		t.Fatalf("log count after revert = %d, want 0", len(logs))
	}

	// The block-wide log counter must have been rolled back as well.
	sdb.AddLog(&types.Log{Address: common.HexToAddress("0xbb")})
	logs := sdb.GetLogs(txHash, 1, common.Hash{})
	if len(logs) != 1 {
		t.Fatalf("log count after second add = %d, want 1", len(logs))
	}
	if logs[0].Index != 0 {
		t.Errorf("log index after revert = %d, want 0", logs[0].Index)
	}
	if logs[0].Address != common.HexToAddress("0xbb") {
		t.Errorf("log address = %v, want 0xbb", logs[0].Address)
	}
}

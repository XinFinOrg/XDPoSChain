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

// Gas-refund tests for EIP-3298 (Removal of Refunds), activated in the Bogotá
// instruction set. EIP-3298 strikes every STORAGE_CLEAR_REFUND entry from the
// EIP-8038 SSTORE case table (gasSStore8037And8038) once Bogotá is active;
// the STORAGE_WRITE reversal refund and all charging rules are unchanged.
// Pre-activation behavior (Amsterdam active, Bogotá inactive) must remain
// byte-identical, charges included — only the refund counter changes.
//
// Spec: https://eips.ethereum.org/EIPS/eip-3298 (full snapshot fetched
// 2026-11-07: hegota-research-20261107/eip-3298.md).

package vm

import (
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/tracing"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/holiman/uint256"
)

var sstoreSelf = common.BytesToAddress([]byte("sstore-self"))

// amsterdam3298Config is Amsterdam-active, Bogotá-inactive: the pre-3298
// control path. It selects the same 8037/8038 SSTORE gas function, so the
// only difference against the Bogotá config below is EIP-3298 itself.
func amsterdam3298Config() *params.ChainConfig {
	cfg := *params.MergedTestChainConfig
	cfg.AmsterdamTime = new(uint64)
	return &cfg
}

// bogota3298Config is Bogotá-active with AmsterdamTime nil — an XDC-shaped
// schedule where Bogotá inherits the Amsterdam table via the fork-table
// constructor chain (newBogotaInstructionSet extends newAmsterdamInstructionSet).
func bogota3298Config() *params.ChainConfig {
	cfg := *params.MergedTestChainConfig
	cfg.BogotaTime = new(uint64)
	return &cfg
}

// refund3298EVM builds an EVM for the refund matrix. The Amsterdam control
// config needs a merge-shaped context (Random set): Rules.IsAmsterdam is
// merge-gated upstream, so with the XDPoS non-merge shape the control would
// silently fall back to the EIP-2200 table and compare apples with oranges.
// Rules.IsBogota is NOT merge-gated (5920 milestone), so the Bogotá config
// deliberately keeps the non-merge shape — that asymmetry is the production
// XDPoS reality and part of what these tests pin.
func refund3298EVM(statedb StateDB, cfg *params.ChainConfig, merge bool) *EVM {
	random := (*common.Hash)(nil)
	if merge {
		random = new(common.Hash)
	}
	ctx := BlockContext{
		CanTransfer: func(db StateDB, addr common.Address, amount *uint256.Int) bool {
			return db.GetBalance(addr).Cmp(amount) >= 0
		},
		Transfer: func(db StateDB, sender, recipient common.Address, amount *uint256.Int, _ *params.Rules) {
			db.SubBalance(sender, amount, tracing.BalanceChangeTransfer)
			db.AddBalance(recipient, amount, tracing.BalanceChangeTransfer)
		},
		BlockNumber:      big.NewInt(0),
		Random:           random,
		CostPerStateByte: params.CostPerStateByte,
	}
	return NewEVM(ctx, statedb, cfg, Config{})
}

// runSStore deploys code at sstoreSelf (with committed setup state) and
// executes it, returning the refund counter and the regular gas consumed.
// mergeCtx selects the merge-shaped context required by the Amsterdam
// control config (see refund3298EVM).
func runSStore(t *testing.T, cfg *params.ChainConfig, mergeCtx bool, code []byte, setup func(*state.StateDB)) (refund uint64, gasUsed uint64) {
	t.Helper()
	statedb, _ := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	statedb.CreateAccount(sstoreSelf)
	statedb.SetCode(sstoreSelf, code, tracing.CodeChangeUnspecified)
	if setup != nil {
		setup(statedb)
	}
	statedb.Finalise(true)
	gas := NewGasBudget(1_000_000, 0)
	_, result, err := refund3298EVM(statedb, cfg, mergeCtx).Call(common.Address{}, sstoreSelf, nil, gas, uint256.NewInt(0))
	if err != nil {
		t.Fatalf("call failed: %v", err)
	}
	assertBudgetSane(t, gas, result)
	return statedb.GetRefund(), 1_000_000 - result.RegularGas
}

var sstoreSlot = common.BytesToHash([]byte{1})

// sstoreClearProg: SSTORE(slot, 0) — the clear case (2.1.2b in the 8038 table).
var sstoreClearProg = []byte{0x60, 0x00, 0x60, 0x01, 0x55, 0x00}

// sstoreDirtyDeleteProg: SSTORE(slot, 7); SSTORE(slot, 0) — dirty write then
// clear (2.2.1.2: original non-zero, current dirty, value zero).
var sstoreDirtyDeleteProg = []byte{0x60, 0x07, 0x60, 0x01, 0x55, 0x60, 0x00, 0x60, 0x01, 0x55, 0x00}

// sstoreRestoreProg: SSTORE(slot, 7); SSTORE(slot, 5) with committed original
// 5 — the write-reversal case (2.2.2) whose STORAGE_WRITE refund EIP-3298
// explicitly preserves.
var sstoreRestoreProg = []byte{0x60, 0x07, 0x60, 0x01, 0x55, 0x60, 0x05, 0x60, 0x01, 0x55, 0x00}

func setCommittedSlot(val byte) func(*state.StateDB) {
	return func(db *state.StateDB) {
		db.SetState(sstoreSelf, sstoreSlot, common.BytesToHash([]byte{val}))
	}
}

// TestEIP3298ClearRefundRemoved: clearing a committed non-zero slot must
// grant STORAGE_CLEAR_REFUND pre-Bogotá and nothing under Bogotá.
func TestEIP3298ClearRefundRemoved(t *testing.T) {
	refundAms, _ := runSStore(t, amsterdam3298Config(), true, sstoreClearProg, setCommittedSlot(5))
	if refundAms != params.StorageClearRefundAmsterdam {
		t.Fatalf("control (Amsterdam): refund = %d, want %d", refundAms, params.StorageClearRefundAmsterdam)
	}
	refundBog, _ := runSStore(t, bogota3298Config(), false, sstoreClearProg, setCommittedSlot(5))
	if refundBog != 0 {
		t.Fatalf("Bogotá: clear-refund = %d, want 0 (EIP-3298)", refundBog)
	}
}

// TestEIP3298DirtyDeleteGrantRemoved: the 2.2.1.2 grant (dirty slot cleared)
// is a STORAGE_CLEAR_REFUND rule and must also vanish under Bogotá.
func TestEIP3298DirtyDeleteGrantRemoved(t *testing.T) {
	refundAms, _ := runSStore(t, amsterdam3298Config(), true, sstoreDirtyDeleteProg, setCommittedSlot(5))
	if refundAms != params.StorageClearRefundAmsterdam {
		t.Fatalf("control (Amsterdam): refund = %d, want %d", refundAms, params.StorageClearRefundAmsterdam)
	}
	refundBog, _ := runSStore(t, bogota3298Config(), false, sstoreDirtyDeleteProg, setCommittedSlot(5))
	if refundBog != 0 {
		t.Fatalf("Bogotá: dirty-delete refund = %d, want 0 (EIP-3298)", refundBog)
	}
}

// TestEIP3298WriteReversalPreserved: the STORAGE_WRITE refund for undoing an
// earlier in-tx write (2.2.2) is NOT a storage-clear rule and must survive
// under Bogotá. Control case — passes both before and after the change.
func TestEIP3298WriteReversalPreserved(t *testing.T) {
	for name, tc := range map[string]struct {
		cfg     *params.ChainConfig
		merge   bool
	}{
		"amsterdam": {amsterdam3298Config(), true},
		"bogota":    {bogota3298Config(), false},
	} {
		refund, _ := runSStore(t, tc.cfg, tc.merge, sstoreRestoreProg, setCommittedSlot(5))
		if refund != params.StorageWriteAmsterdam {
			t.Fatalf("%s: write-reversal refund = %d, want %d (must be preserved)", name, refund, params.StorageWriteAmsterdam)
		}
	}
}

// TestEIP3298ChargesUnchanged: EIP-3298 removes refunds, not charges — the
// regular gas consumed by the clear program must be identical under both
// configs. Control case — passes both before and after the change.
func TestEIP3298ChargesUnchanged(t *testing.T) {
	_, gasAms := runSStore(t, amsterdam3298Config(), true, sstoreClearProg, setCommittedSlot(5))
	_, gasBog := runSStore(t, bogota3298Config(), false, sstoreClearProg, setCommittedSlot(5))
	if gasAms != gasBog {
		t.Fatalf("gas charged differs: amsterdam %d, bogota %d (refund removal must not change charges)", gasAms, gasBog)
	}
}

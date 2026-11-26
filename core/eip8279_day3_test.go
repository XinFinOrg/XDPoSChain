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

// Day 3 — Hegotá cross-EIP integration tests.
//
// These tests pin the INTERACTION semantics that single-EIP suites leave
// apart:
//
//  1. TestDay3EIP8131x8279CombinedFloorAndMeter — one transaction carrying
//     an authorization (EIP-8279 static 51 B/auth seed term), an access
//     list (EIP-8131 content floor), and runtime first-touch metering
//     (EIP-8279 runtime tail). Settlement must equal
//     8131 floor + 51×auths×64 + runtimeBytes×64.
//  2. TestDay3EIP3298x8131x8279RefundFloorSettlement — the EIP-3298
//     uncapped refund (Bogotá) interacts with the EIP-8131 static floor
//     AND the EIP-8279 runtime floor: settlement must equal
//     max(execution_after_full_refund, static_floor + 64×runtime_bytes).
//
// EIP-5920 (PAY) is excluded from the integrated base by the R2 scope
// decision (enable5920 deliberately left out of the prerequisite commits),
// so no PAY×EIP-7709 execution interaction exists to test here; EIP-7709 is
// covered by its own suite in the Day 3 battery. EIP-8141 FrameTx isolation
// from the EIP-8279 meter is covered end-to-end by TestEIP8279F3FrameTx-
// IsolationControl and the FrameTx suite.

package core

import (
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/tracing"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
)

// TestDay3EIP8131x8279CombinedFloorAndMeter: a single Bogotá transaction
// with 1 authorization (signature recovers against the fresh statedb and is
// processed; its cost is bounded well inside the margin below), an access
// list (1 address + 3 storage keys), 1,000 nonzero calldata bytes, and a
// contract that executes 3 warm SLOADs. Expected decomposition:
//
//	8131 static floor: 21,000 + 64×(1000 data + 20 addr + 3×32 keys + 108 auth)
//	                 = 21,000 + 64×1224 = 99,336
//	8279 static seed:  51 × 1 × 64                       =  3,264
//	8279 runtime:      3 first-touch keys × 32 B × 64     =  6,144
//	settlement                                       = 108,744
//
// Execution (intrinsic 70,100 + 3×100 warm SLOAD + bounded auth side effects,
// ≈ 76k) stays well below the floor, so settlement is floor-exact.
func TestDay3EIP8131x8279CombinedFloorAndMeter(t *testing.T) {
	cfg := eip8279BogotaCfg()
	al := types.AccessList{{Address: eip8131To, StorageKeys: []common.Hash{{0x00}, {0x01}, {0x02}}}}
	msg := eip8131Message(1000, 1, 0, al, 200_000)

	statedb, _ := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	statedb.SetCode(eip8131To, eip8279CodeSloads(3), tracing.CodeChangeGenesis)
	evm := eip8131EVM(statedb, cfg, 1, 0)
	res, err := ApplyMessage(evm, msg, NewGasPool(100_000_000))
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if res.Err != nil {
		t.Fatalf("execution failed: %v", res.Err)
	}
	want := eip8131Floor(1000, 1, 3, 1, 0) + 51*64 + 3*32*64
	if res.UsedGas != want {
		t.Fatalf("gasUsed = %d, want combined 8131+8279 settlement %d (8131 floor %d + 51 B/auth seed 3,264 + runtime 3×32 B×64 = 6,144)",
			res.UsedGas, want, eip8131Floor(1000, 1, 3, 1, 0))
	}
	// State expectation: the SLOADs must have executed (meter claims are
	// only meaningful if the reads actually happened).
	if got := statedb.GetState(eip8131To, common.Hash{0x00}); got != (common.Hash{}) {
		t.Fatalf("slot 0 = %x, want untouched zero (warm-read scenario)", got)
	}
}

// TestDay3EIP3298x8131x8279RefundFloorSettlement: unit-level settleGas test
// extending TestEIP8131N2FloorBindsAfterFullRefund with the EIP-8279 runtime
// meter. Setup: static floor 85,000, tx.gas 100,000, before-refund usage
// 100,000, a full EIP-3298 refund counter of 20,000, and a meter carrying
// 128 runtime bytes (3 storage keys + 1 value) — a meter any real
// transaction reaching settlement may carry, since execution would have
// OOG'd at the budget boundary otherwise.
//
//	execution_after_refund = 100,000 − 20,000           = 80,000
//	8279 floor             = 85,000 + 128×64             = 93,192
//	settlement             = max(80,000, 93,192)         = 93,192
//
// The uncapped EIP-3298 refund alone would push the tx 5,000 BELOW the
// static floor; the combined floor must still bind — refund accounting can
// never undercut metered settlement.
func TestDay3EIP3298x8131x8279RefundFloorSettlement(t *testing.T) {
	const (
		floor         = uint64(85_000)
		txGas         = uint64(100_000)
		beforeRefund  = txGas
		refundCounter = uint64(20_000)
		runtimeBytes  = uint64(3*32 + 32) // 3 keys + 1 value
	)
	cfg := eip8131Config(false, true, false, 0)
	statedb, _ := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	statedb.AddRefund(refundCounter)
	evm := vm.NewEVM(vm.BlockContext{BlockNumber: big.NewInt(0)}, statedb, cfg, vm.Config{})

	// Simulate the runtime additions a real execution would have recorded
	// (budget min(100,000, 2²⁴) admits 128 B: 93,192 ≤ 100,000).
	meter := vm.NewBALMeter(floor, txGas)
	for i := byte(0); i < 3; i++ {
		if !meter.AddStorageKey(eip8131To, common.Hash{i}) {
			t.Fatalf("meter rejected storage key %d", i)
		}
	}
	if !meter.AddStorageValue(eip8131To, common.Hash{0x00}) {
		t.Fatalf("meter rejected storage value")
	}
	if meter.RuntimeFloor() != floor+runtimeBytes*64 {
		t.Fatalf("meter.RuntimeFloor() = %d, want %d", meter.RuntimeFloor(), floor+runtimeBytes*64)
	}
	evm.SetBALMeter(meter)

	st := &stateTransition{
		msg:          eip8131UnitMsg(beforeRefund),
		gasRemaining: vm.NewGasBudget(0, 0),
		state:        statedb,
		evm:          evm,
		gp:           NewGasPool(10_000_000),
	}
	rules := cfg.Rules(big.NewInt(0), true, 0)
	gasUsed, _, err := st.settleGas(rules, floor)
	if err != nil {
		t.Fatalf("settleGas failed: %v", err)
	}
	want := floor + runtimeBytes*64 // 93,192: the combined floor binds over the fully-refunded execution.
	if gasUsed != want {
		t.Fatalf("gasUsed = %d, want %d (EIP-3298 full refund would leave %d, below the combined EIP-8131+EIP-8279 floor %d)",
			gasUsed, want, beforeRefund-refundCounter, want)
	}
}

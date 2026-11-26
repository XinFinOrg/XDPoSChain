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

// D4 — EIP-3298 × EIP-8141 FrameTx refund settlement (protocol decision D4,
// Option A, approved 2026-11-11): under Bogotá, settleFrameTx applies no
// refund, matching the standard path (state_transition.go calcRefund).
//
// Equivalence argument under test (do not assume — demonstrate):
//
//   - Standard path, Bogotá: calcRefund returns min(refund_counter,
//     gasUsedBeforeRefund) — the counter in full (EIP-3298 removes the
//     1/5 cap). For any frame-executable operation set the counter is
//     structurally 0 under Bogotá (P4 T1: SSTORE-clear and SELFDESTRUCT
//     grants are struck; P4 T3: the one surviving source, the EIP-7702
//     existing-authority +12,500, is unreachable because FrameTx carries
//     no authorization list). min(0, x) = 0 — identical to the frame
//     branch's hard 0.
//   - Frame path, pre-Bogotá: the retained branch is
//     min(gasUsedBeforeRefund/5, counter) with the EIP-3529 quotient —
//     the same formula as the standard pre-Bogotá calcRefund.
//
// Tests:
//  1. TestEIP3298D4FrameSettlementBogotaZeroRefund — Bogotá frame with the
//     most refund-aggressive execution: counter == 0 AND UsedGas ==
//     MaxUsedGas (refund exactly zero at settlement).
//  2. TestEIP3298D4FrameSettlementPreBogotaCapRetained — pre-Bogotá
//     control: counter > 0 and UsedGas == MaxUsedGas −
//     min(MaxUsedGas/5, counter). Pins the retained 1/5-cap branch; a
//     regression applying the Bogotá branch unconditionally fails here.
//
// RED note: the Bogotá behavior is a no-op today (the counter is already
// 0 under Bogotá, so both the old 3529-cap line and the new branch settle
// identically). There is no honest RED for test 1 — it is a tripwire.
// Test 2 discriminates the gate: it fails if the Bogotá zero-refund
// branch leaks into pre-Bogotá settlement.
//
// Harness: reuses the frame fixtures (same test package).

package core

import (
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// d4RefundContract runs the P4 refund-aggressive code: SSTORE slot0
// 1→0 (clear) then SELFDESTRUCT with a 1-wei balance.
var d4RefundContract = common.BytesToAddress([]byte("d4-refund-contract"))

// d4RefundState builds the frame world state with the refund contract
// pre-seeded (slot0 = 1, committed so the clear reads as a true clear,
// mirroring p4RefundSetup).
func d4RefundState(t *testing.T) *state.StateDB {
	t.Helper()
	sdb := mkState(types.GenesisAlloc{
		senderAddr:         {Nonce: 0, Balance: big.NewInt(0)},
		frameContractPayer: {Code: frameApproveCode(0x1)},
		d4RefundContract: {
			Balance: big.NewInt(1),
			Code:    p4RefundExecCode(),
			Storage: map[common.Hash]common.Hash{{}: common.BigToHash(big.NewInt(1))},
		},
		p1PayBeneficiary: {Balance: big.NewInt(0)},
	})
	if _, err := sdb.Commit(0, true, true); err != nil {
		t.Fatalf("commit: %v", err)
	}
	return sdb
}

// d4RefundFrameTx assembles: execution approval (default code), payment
// approval (APPROVE), then a DEFAULT frame executing the refund contract.
func d4RefundFrameTx(t *testing.T) *types.FrameTx {
	t.Helper()
	ftx := frameTx(0, []types.Frame{
		{Mode: types.FrameModeVerify, Flags: 0x2, Limits: mkFrameLimits(100_000, 300_000)},
		{Mode: types.FrameModeVerify, Target: &frameContractPayer, Flags: 0x1, Limits: mkFrameLimits(100_000, 300_000)},
		{Mode: types.FrameModeDefault, Target: &d4RefundContract, Flags: 0x0, Limits: mkFrameLimits(1_000_000, 3_000_000)},
	}, []types.FrameSignature{{Scheme: types.FrameSigSchemeSecp256k1}})
	ftx.Signatures = defaultApproveSigs(t, senderKey, ftx)
	return ftx
}

// d4ApplyFrameTx executes a frame transaction against an explicit config
// (frameCoreEVM is pinned to cfgFrame; the Bogotá case needs its own).
func d4ApplyFrameTx(t *testing.T, sdb *state.StateDB, cfg *params.ChainConfig, ftx *types.FrameTx) *ExecutionResult {
	t.Helper()
	ctx := vm.BlockContext{
		CanTransfer:      CanTransfer,
		Transfer:         Transfer,
		GetHash:          func(uint64) common.Hash { return common.Hash{} },
		BlockNumber:      big.NewInt(0),
		Time:             0,
		Random:           &common.Hash{},
		Difficulty:       big.NewInt(0),
		BaseFee:          big.NewInt(0),
		BlobBaseFee:      big.NewInt(0),
		GasLimit:         60_000_000,
		CostPerStateByte: params.CostPerStateByte,
	}
	evm := vm.NewEVM(ctx, sdb, cfg, vm.Config{NoBaseFee: true})
	msg, err := TransactionToMessage(types.NewTx(ftx), frameSgn, evm.Context.BaseFee)
	if err != nil {
		t.Fatalf("to message: %v", err)
	}
	st := newStateTransition(evm, msg, NewGasPool(evm.Context.GasLimit), common.Address{})
	res, err := st.execute()
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	return res
}

// 1. Bogotá: the refund-aggressive frame executes successfully but the
// counter is structurally 0, and settlement applies a refund of exactly
// zero — UsedGas == MaxUsedGas (gasUsedBeforeRefund). This is the same
// value calcRefund would produce: min(counter=0, gasUsedBeforeRefund)=0.
func TestEIP3298D4FrameSettlementBogotaZeroRefund(t *testing.T) {
	cfg := *cfgFrame
	cfg.BogotaTime = new(uint64) // Bogotá active at genesis time

	sdb := d4RefundState(t)
	res := d4ApplyFrameTx(t, sdb, &cfg, d4RefundFrameTx(t))

	if got := sdb.GetRefund(); got != 0 {
		t.Fatalf("Bogotá frame refund counter = %d, want 0 (3298 strike; P4 T1)", got)
	}
	t.Logf("bogota: counter=0 usedGas=%d maxUsedGas(pre-refund)=%d refund=0", res.UsedGas, res.MaxUsedGas)
	if res.UsedGas != res.MaxUsedGas {
		t.Fatalf("UsedGas = %d, MaxUsedGas (pre-refund) = %d — Bogotá frame settlement must apply refund 0",
			res.UsedGas, res.MaxUsedGas)
	}
	if len(res.FrameReceipts) != 3 || res.FrameReceipts[2].Status != 1 {
		t.Fatalf("refund frame did not execute successfully: %+v", res.FrameReceipts)
	}
}

// 2. Pre-Bogotá control: the same frame accumulates a counter (the strike
// is the Bogotá gate, not the harness), and settlement applies
// min(gasUsedBeforeRefund/5, counter) — the retained EIP-3529 branch.
// Fails if the Bogotá zero-refund branch leaks pre-Bogotá.
func TestEIP3298D4FrameSettlementPreBogotaCapRetained(t *testing.T) {
	sdb := d4RefundState(t)
	res := d4ApplyFrameTx(t, sdb, cfgFrame, d4RefundFrameTx(t))

	counter := sdb.GetRefund()
	if counter == 0 {
		t.Fatalf("pre-Bogotá frame refund counter = 0, want > 0 (clear-refund must fire; P4 T2 analogue)")
	}
	wantRefund := res.MaxUsedGas / params.RefundQuotientEIP3529
	if wantRefund > counter {
		wantRefund = counter
	}
	if want := res.MaxUsedGas - wantRefund; res.UsedGas != want {
		t.Fatalf("UsedGas = %d, want %d (MaxUsedGas %d − min(MaxUsedGas/5, counter %d) = refund %d)",
			res.UsedGas, want, res.MaxUsedGas, counter, wantRefund)
	}
	t.Logf("preBogota: counter=%d usedGas=%d maxUsedGas(pre-refund)=%d refund=%d", counter, res.UsedGas, res.MaxUsedGas, wantRefund)
}

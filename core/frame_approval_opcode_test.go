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
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/holiman/uint256"
)

// TestFrameApproveOpcodeCombinedScope exercises the APPROVE opcode with
// scope EXECUTION_AND_PAYMENT (0x3) via explicit account code at the sender.
// The specification (EIP-8141 "APPROVE Instruction", scope 0x3 behavior)
// requires: revert if sender_approved or payer already set; revert if
// resolved_target != tx.sender; revert on insufficient balance; then set
// sender_approved, increment the sender nonce, set payer and collect
// max_cost. The combined scope does NOT require sender_approved to already
// be true (that precondition belongs to PAYMENT-only, 0x1).
func TestFrameApproveOpcodeCombinedScope(t *testing.T) {
	frames := []types.Frame{
		{Mode: types.FrameModeVerify, Flags: 0x3, Limits: mkFrameLimits(100_000, 300_000)},
	}
	ftx := frameTx(0, frames, []types.FrameSignature{{Scheme: types.FrameSigSchemeSecp256k1}})
	// Non-zero max_cost: with baseFee == 0, MaxCost == maxGas * tipCap.
	ftx.Fees.GasFeeCap = uint256.NewInt(1_000_000)
	ftx.Fees.GasTipCap = uint256.NewInt(2)
	ftx.Signatures = defaultApproveSigs(t, senderKey, ftx)

	sdb := mkState(types.GenesisAlloc{
		// The sender carries explicit code that calls APPROVE(0x3), so the
		// opcode path (not the protocol default code) is exercised.
		senderAddr:         {Balance: new(big.Int).Lsh(big.NewInt(1), 60), Code: frameApproveCode(0x3)},
		settlementCoinbase: {Balance: big.NewInt(0)}, // must exist to receive the priority fee
	})
	res, _, err := applyFrameTx(t, sdb, ftx)
	if err != nil {
		t.Fatalf("combined EXECUTION_AND_PAYMENT approval reverted: %v", err)
	}
	if res.Err != nil {
		t.Fatalf("combined EXECUTION_AND_PAYMENT approval reverted: %v", res.Err)
	}
	if nonce := sdb.GetNonce(senderAddr); nonce != 1 {
		t.Fatalf("sender nonce = %d, want 1 after combined approval", nonce)
	}
	if bal := sdb.GetBalance(senderAddr); bal.CmpUint64(0) == 0 {
		t.Fatal("max_cost was not collected from the sender")
	}
}

// TestFrameApproveOpcodeSeparateScopes anchors the two-step approval path
// (EXECUTION at the sender, then PAYMENT at a payer account) through
// explicit account code, which must keep working when the combined scope is
// fixed.
func TestFrameApproveOpcodeSeparateScopes(t *testing.T) {
	payer := common.BytesToAddress([]byte{0xf1})
	frames := []types.Frame{
		{Mode: types.FrameModeVerify, Flags: 0x2, Limits: mkFrameLimits(100_000, 300_000)},
		{Mode: types.FrameModeVerify, Target: &payer, Flags: 0x1, Limits: mkFrameLimits(100_000, 300_000)},
	}
	ftx := frameTx(0, frames, []types.FrameSignature{{Scheme: types.FrameSigSchemeSecp256k1}})
	ftx.Fees.GasFeeCap = uint256.NewInt(1_000_000)
	ftx.Fees.GasTipCap = uint256.NewInt(2)
	ftx.Signatures = defaultApproveSigs(t, senderKey, ftx)

	sdb := mkState(types.GenesisAlloc{
		senderAddr:         {Balance: new(big.Int).Lsh(big.NewInt(1), 60), Code: frameApproveCode(0x2)},
		payer:              {Balance: new(big.Int).Lsh(big.NewInt(1), 60), Code: frameApproveCode(0x1)},
		settlementCoinbase: {Balance: big.NewInt(0)},
	})
	res, _, err := applyFrameTx(t, sdb, ftx)
	if err != nil {
		t.Fatalf("separate approval execution failed: %v", err)
	}
	if res.Err != nil {
		t.Fatalf("separate approval execution failed: %v", res.Err)
	}
	if nonce := sdb.GetNonce(senderAddr); nonce != 1 {
		t.Fatalf("sender nonce = %d, want 1 after payment approval", nonce)
	}
	if bal := sdb.GetBalance(payer); bal.CmpUint64(0) == 0 {
		t.Fatal("max_cost was not collected from the payer")
	}
}

// TestFrameApproveOpcodePaymentRequiresExecution anchors the spec rule that
// PAYMENT-only (0x1) approval without a prior EXECUTION approval reverts.
func TestFrameApproveOpcodePaymentRequiresExecution(t *testing.T) {
	frames := []types.Frame{
		{Mode: types.FrameModeVerify, Flags: 0x1, Limits: mkFrameLimits(100_000, 300_000)},
	}
	ftx := frameTx(0, frames, []types.FrameSignature{{Scheme: types.FrameSigSchemeSecp256k1}})
	ftx.Fees.GasFeeCap = uint256.NewInt(1_000_000)
	ftx.Fees.GasTipCap = uint256.NewInt(2)
	ftx.Signatures = defaultApproveSigs(t, senderKey, ftx)

	sdb := mkState(types.GenesisAlloc{
		senderAddr:         {Balance: new(big.Int).Lsh(big.NewInt(1), 60), Code: frameApproveCode(0x1)},
		settlementCoinbase: {Balance: big.NewInt(0)},
	})
	if _, _, err := applyFrameTx(t, sdb, ftx); err == nil {
		t.Fatal("PAYMENT-only without EXECUTION: expected revert")
	}
	if nonce := sdb.GetNonce(senderAddr); nonce != 0 {
		t.Fatalf("sender nonce = %d, want 0 (effects unrolled)", nonce)
	}
}

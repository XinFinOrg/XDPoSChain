// Copyright 2026 The Ethereum Authors
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

// P4 — EIP-3298 × EIP-8141 (FrameTx) refund compatibility review tests.
//
// Finding under review (closure audit D4): the standard settlement
// (state_transition.go calcRefund) applies the EIP-3298 rule under Bogotá
// (full refund counter, no cap), but the FrameTx settlement
// (state_transition_frame.go settleFrameTx) still applies the EIP-3529
// 1/5-cap unconditionally.
//
// These tests pin WHY that divergence is latent rather than live under
// Bogotá: the refund counter is structurally unreachable under Bogotá for
// frame executions —
//
//  1. TestP4BogotaRefundCounterZeroDespiteClearAndSelfDestruct: the most
//     refund-aggressive execution (SSTORE slot delete + SELFDESTRUCT with
//     value) leaves GetRefund() == 0 under Bogotá — every vm-level grant
//     is struck by the 8037/8038 schedule under IsBogota.
//  2. TestP4PreBogotaControlRefundCounterPositive: the same execution
//     under Prague (pre-Bogotá) DOES accumulate a refund — the strike is
//     the Bogotá gate, not the harness.
//  3. TestP4BogotaStandardPath7702AuthRefundLive: the ONE refund source
//     that survives Bogotá is the pre-Amsterdam EIP-7702 existing-authority
//     refund (state_transition.go applyAuthorization, +12,500) — and it
//     exists only on the standard path: FrameTx carries no authorization
//     list (no SetCodeAuthorizations field), so a frame execution can
//     never accumulate it. This also proves calcRefund's Bogotá branch is
//     live code for regular transactions, not decoration.
//
// Conclusion delivered in HEGOTA_P4_EIP3298_FRAMETX_REFUND_REVIEW.md:
// no live consensus divergence; the frame 3529-cap line is a latent trap
// worth aligning (protocol decision D4).

package core

import (
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/tracing"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/holiman/uint256"
)

// p4RefundExecCode deletes slot0 (pre-seeded nonzero) and then
// SELFDESTRUCTs to p1PayBeneficiary.
func p4RefundExecCode() []byte {
	code := []byte{0x60, 0x00, 0x60, 0x00, 0x55} // PUSH1 0, PUSH1 0, SSTORE (delete)
	code = append(code, 0x73)                    // PUSH20
	code = append(code, p1PayBeneficiary.Bytes()...)
	code = append(code, 0xff) // SELFDESTRUCT
	return code
}

func p4RefundSetup() *state.StateDB {
	statedb := p1PaySetup(nil)
	statedb.CreateAccount(eip8131To)
	statedb.SetCode(eip8131To, p4RefundExecCode(), tracing.CodeChangeGenesis)
	statedb.SetNonce(eip8131To, 1, tracing.NonceChangeUnspecified)
	statedb.SetState(eip8131To, common.Hash{}, common.Hash{31: 0x01}) // slot0 = 1
	// Commit so original (committed) state = 1 — without this the delete
	// reads as a journal reset-to-original instead of a true clear.
	if _, err := statedb.Commit(0, true, true); err != nil {
		panic(err)
	}
	return statedb
}

func TestP4BogotaRefundCounterZeroDespiteClearAndSelfDestruct(t *testing.T) {
	statedb := p4RefundSetup()

	msg := p1PayMessage(0, nil, 500_000, 100)
	evm := eip8131EVM(statedb, eip8279BogotaCfg(), 1, 0)
	res, err := ApplyMessage(evm, msg, NewGasPool(10_000_000))
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if res.Err != nil {
		t.Fatalf("execution failed: %v", res.Err)
	}
	if got := statedb.GetRefund(); got != 0 {
		t.Fatalf("Bogotá refund counter = %d, want 0 (all vm-level grants struck under IsBogota)", got)
	}
}

func TestP4PreBogotaControlRefundCounterPositive(t *testing.T) {
	statedb := p4RefundSetup()

	// Prague-only config (Bogotá off): the same slot delete grants the
	// clear-refund on the 2200/3529 schedule.
	cfg := eip8131Config(true, false, false, 0)
	msg := p1PayMessage(0, nil, 500_000, 100)
	evm := eip8131EVM(statedb, cfg, 1, 0)
	res, err := ApplyMessage(evm, msg, NewGasPool(10_000_000))
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if res.Err != nil {
		t.Fatalf("execution failed: %v", res.Err)
	}
	if got := statedb.GetRefund(); got == 0 {
		t.Fatalf("Prague control refund counter = 0, want > 0 (clear-refund must fire pre-Bogotá)")
	}
}

func TestP4BogotaStandardPath7702AuthRefundLive(t *testing.T) {
	// One 7702 authorization whose authority account EXISTS at validation:
	// the pre-Amsterdam branch of applyAuthorization grants
	// CallNewAccountGas − TxAuthTupleGas = 12,500 — the only refund source
	// that survives Bogotá, and it lives only on the standard path.
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	auth, err := types.SignSetCode(key, types.SetCodeAuthorization{
		ChainID: *uint256.NewInt(1), Address: eip8131To, Nonce: 0,
	})
	if err != nil {
		t.Fatalf("sign auth: %v", err)
	}
	authority := crypto.PubkeyToAddress(key.PublicKey)

	msg := eip8131Message(0, 0, 0, nil, 500_000)
	msg.SetCodeAuthorizations = []types.SetCodeAuthorization{auth}

	statedb := p1PaySetup(nil)
	statedb.CreateAccount(authority) // Exist(authority) = true → refund fires
	statedb.SetCode(eip8131To, []byte{0x00}, tracing.CodeChangeGenesis)

	evm := eip8131EVM(statedb, eip8279BogotaCfg(), 1, 0)
	res, err := ApplyMessage(evm, msg, NewGasPool(10_000_000))
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if res.Err != nil {
		t.Fatalf("execution failed: %v", res.Err)
	}
	want := params.CallNewAccountGas - params.TxAuthTupleGas
	if got := statedb.GetRefund(); got != want {
		t.Fatalf("Bogotá 7702 refund counter = %d, want %d (existing-authority refund)", got, want)
	}
}

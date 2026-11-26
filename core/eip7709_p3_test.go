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

// P3 — EIP-7709 (state-serving BLOCKHASH) integration tests on the approved
// integrated base (`7cc3443` + 8279 GREEN + 5920 PAY + this track's 7709).
//
//  1. TestP3EIP5920x7709PayThenBlockhash — closes the Day-3 N/A: one Bogotá
//     transaction executes a nonzero PAY (EIP-5920) AND an in-window
//     BLOCKHASH read served from the EIP-2935 history ring (EIP-7709),
//     cold then warm, with the EIP-8279 meter active. Verifies exact gas
//     decomposition, both state writes, and the PAY balance movement.
//
// Observations pinned here, not asserted as rules:
//   - opBlockhash7709 reads the ring via raw GetState with NO EIP-8279
//     meter hook — a 32-byte ring read meters 0 BAL bytes today. Same
//     class as the PAY balance-pair question (D3); raised as D6 for the
//     protocol owner.
//   - The history-ring fixture account needs code or a nonzero nonce
//     (storage-only accounts are "empty" and deleted by Finalise).

package core

import (
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/tracing"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/holiman/uint256"
)

func TestP3EIP5920x7709PayThenBlockhash(t *testing.T) {
	const blockNum = 300
	seeded := common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000029901")

	statedb := p1PaySetup(nil)
	// Seed the history ring for block 299 (the future parent). The account
	// must be created explicitly — SetState/SetCode no-op on absent
	// accounts in this tree — and must not be "empty" (code + nonce), or
	// Finalise would delete it.
	statedb.CreateAccount(params.HistoryStorageAddress)
	statedb.SetCode(params.HistoryStorageAddress, params.HistoryStorageCode, tracing.CodeChangeGenesis)
	statedb.SetNonce(params.HistoryStorageAddress, 1, tracing.NonceChangeUnspecified)
	statedb.SetState(params.HistoryStorageAddress, params.HistoryStorageKey(299), seeded)

	// Contract: PAY 5 wei to B; BLOCKHASH(299) → slot0; BLOCKHASH(299) → slot1
	// (warm); STOP.
	code := []byte{0x60, 0x05} // PUSH1 5
	code = append(code, 0x73)  // PUSH20
	code = append(code, p1PayBeneficiary.Bytes()...)
	code = append(code, 0xfc)          // PAY
	code = append(code, 0x61, 0x01, 0x2b, 0x40) // PUSH2 299, BLOCKHASH
	code = append(code, 0x60, 0x00, 0x55)       // PUSH1 0, SSTORE
	code = append(code, 0x61, 0x01, 0x2b, 0x40) // PUSH2 299, BLOCKHASH (warm)
	code = append(code, 0x60, 0x01, 0x55)       // PUSH1 1, SSTORE
	code = append(code, 0x00)                   // STOP
	statedb.SetCode(eip8131To, code, tracing.CodeChangeGenesis)

	msg := p1PayMessage(0, nil, 500_000, 100) // funds the contract with 100 wei
	evm := eip8131EVM(statedb, eip8279BogotaCfg(), blockNum, 0)
	res, err := ApplyMessage(evm, msg, NewGasPool(10_000_000))
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if res.Err != nil {
		t.Fatalf("execution failed: %v", res.Err)
	}

	// Both ring reads served the seeded hash (cold then warm).
	if got := statedb.GetState(eip8131To, common.Hash{}); got != seeded {
		t.Fatalf("slot0 (cold BLOCKHASH) = %x, want seeded %x", got, seeded)
	}
	slot1 := common.Hash{31: 0x01}
	if got := statedb.GetState(eip8131To, slot1); got != seeded {
		t.Fatalf("slot1 (warm BLOCKHASH) = %x, want seeded %x", got, seeded)
	}
	// PAY moved exactly 5 wei.
	if bal := statedb.GetBalance(p1PayBeneficiary); bal.Cmp(uint256.NewInt(5)) != 0 {
		t.Fatalf("beneficiary balance = %v, want 5", bal)
	}

	// Gas decomposition:
	//   regular dimension: 21,000 intrinsic
	//   + 6   PUSH1+PUSH20 for PAY
	//   + 36,600 PAY (100 + 2,500 cold + 9,000 + 25,000)
	//   + 3   PUSH2
	//   + 3,020 BLOCKHASH cold (20 GasExtStep + 3,000 ColdStorageAccessAmsterdam)
	//   + 3 + 13,000 PUSH1 + SSTORE slot0 (3,000 cold + 10,000 first-write)
	//   + 3 + 120   PUSH2 + BLOCKHASH warm (20 + 100)
	//   + 3 + 13,000 PUSH1 + SSTORE slot1
	//   = 89,758 regular.
	//   EIP-8037 state dimension: 2 fresh slots × 97,920 (StorageCreationSize
	//   64 × CostPerStateByte 1,530) = 195,840; settleGas folds the 2D
	//   pools into the receipt scalar per its pool-overlap accounting
	//   (state_transition.go settleGas), yielding the settled 282,598
	//   (= 89,758 + 195,840 − 3,000 settle overlap). EIP-8279 runtime:
	//   2 fresh slots × 64 B → floor 29,192, far below execution.
	const wantGas = 282_598
	if res.UsedGas != wantGas {
		t.Fatalf("gasUsed = %d, want %d", res.UsedGas, wantGas)
	}
}

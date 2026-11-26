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

// P1 — EIP-5920 (PAY) integration tests on the approved integrated base
// (`7cc3443` + EIP-8279 GREEN + this file's activator).
//
// These tests pin the interaction semantics of PAY with the EIPs already on
// the base:
//
//  1. TestP1EIP5920PayTransferSettlement — PAY value transfer, gas
//     decomposition (warm constant 100 + cold delta 2,500 +
//     CallValueTransferGas 9,000 + CallNewAccountGas 25,000) and balance
//     consistency under Bogotá rules with the EIP-8279 meter active.
//     This also documents CURRENT EIP-8279 behavior for PAY: the meter has
//     no PAY hook, so PAY contributes 0 runtime BAL bytes. Whether a
//     cross-account nonzero PAY must meter the 2×32 balance pair
//     (mirroring the EIP-8279 CALL-family rule) is PROTOCOL QUESTION D3,
//     unresolved at the time of writing; under the "meter it" outcome this
//     fixture's floor grows by 64×64 = 4,096 while settlement here is
//     execution-dominated, so the assertion survives either ruling — but
//     the metering question itself must be settled before cross-client
//     claims.
//  2. TestP1EIP5920PayUnder8131Floor — a 0-value PAY to a warm,
//     pre-access-listed beneficiary inside a tx whose EIP-8131 static floor
//     exceeds execution: the floor binds over a PAY-containing transaction.
//  3. TestP1EIP5920PayRevertRollsBack — SSTORE + PAY inside a frame that
//     REVERTs: the value transfer and the storage write roll back; the tx
//     settles as a reverted execution (EIP-8279 revert-retention applies to
//     metered paths; PAY itself meters nothing today).
//
// EIP-7709 (BLOCKHASH) interaction is NOT covered here: EIP-7709 is not part
// of the integrated base (it lives only in the uncommitted dirty-tree work);
// the 5920×7709 same-fork-set test is P-track scope, not P1.

package core

import (
	"errors"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/tracing"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/holiman/uint256"
)

var p1PayBeneficiary = common.HexToAddress("0x00000000000000000000000000000000000b0d1e")

// p1PayMessage builds a Bogotá message to eip8131To with an optional value,
// reusing the eip8131 harness conventions (zero gas price, skip nonce checks).
func p1PayMessage(dataLen int, al types.AccessList, gasLimit, value uint64) *Message {
	msg := eip8131Message(dataLen, 0, 0, al, gasLimit)
	msg.Value = uint256.NewInt(value)
	return msg
}

// p1PaySetup returns a funded statedb with the given code deployed at
// eip8131To and a funded sender.
func p1PaySetup(code []byte) *state.StateDB {
	statedb, _ := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	statedb.AddBalance(eip8131From, uint256.NewInt(0).Mul(uint256.NewInt(1_000_000), uint256.NewInt(1_000_000_000)), tracing.BalanceChangeUnspecified)
	if code != nil {
		statedb.SetCode(eip8131To, code, tracing.CodeChangeGenesis)
	}
	return statedb
}

func p1PayApply(t *testing.T, statedb *state.StateDB, msg *Message) *ExecutionResult {
	t.Helper()
	evm := eip8131EVM(statedb, eip8279BogotaCfg(), 1, 0)
	res, err := ApplyMessage(evm, msg, NewGasPool(10_000_000))
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	return res
}

// p1PayCode returns contract code that pays `value` wei to p1PayBeneficiary
// via PAY (0xfc) and stops.
func p1PayCode(value byte) []byte {
	code := []byte{0x60, value} // PUSH1 value
	code = append(code, 0x73)   // PUSH20
	code = append(code, p1PayBeneficiary.Bytes()...)
	code = append(code, 0xfc) // PAY
	code = append(code, 0x00) // STOP
	return code
}

func TestP1EIP5920PayTransferSettlement(t *testing.T) {
	statedb := p1PaySetup(p1PayCode(5))
	msg := p1PayMessage(0, nil, 100_000, 100) // funds the contract with 100 wei

	res := p1PayApply(t, statedb, msg)
	if res.Err != nil {
		t.Fatalf("execution failed: %v", res.Err)
	}
	// Gas decomposition: intrinsic 21,000; PUSH1 3 + PUSH20 3 = 6; PAY warm
	// constant 100 + cold delta 2,500 (2600-100) + CallValueTransferGas 9,000
	// + CallNewAccountGas 25,000 (EIP-161-empty beneficiary); STOP 0.
	// (Any EIP-8037 state-gas dimension is untouched: PAY only moves balance
	// on existing-vs-new accounts here and gasPay charges RegularGas only.)
	const wantGas = 21_000 + 6 + 100 + 2_500 + 9_000 + 25_000
	if res.UsedGas != wantGas {
		t.Fatalf("gasUsed = %d, want %d", res.UsedGas, wantGas)
	}
	// Balances: contract received 100 from the tx and paid out 5; beneficiary
	// ends with exactly 5.
	if bal := statedb.GetBalance(p1PayBeneficiary); bal.Cmp(uint256.NewInt(5)) != 0 {
		t.Fatalf("beneficiary balance = %v, want 5", bal)
	}
	if bal := statedb.GetBalance(eip8131To); bal.Cmp(uint256.NewInt(95)) != 0 {
		t.Fatalf("contract balance = %v, want 95", bal)
	}
}

func TestP1EIP5920PayUnder8131Floor(t *testing.T) {
	// 0-value PAY to a warm (access-list pre-warmed) beneficiary: PAY costs
	// its 100 warm constant plus the two pushes (3+3). The EIP-8131 static
	// floor (21,000 + 64×(300 data + 20 access-list address) = 41,480)
	// exceeds execution (25,800 intrinsic + 106 = 25,906) and binds.
	statedb := p1PaySetup(p1PayCode(0))
	al := types.AccessList{{Address: p1PayBeneficiary}}
	msg := p1PayMessage(300, al, 100_000, 0)

	res := p1PayApply(t, statedb, msg)
	if res.Err != nil {
		t.Fatalf("execution failed: %v", res.Err)
	}
	const wantGas = 21_000 + 64*320 // 41,480: floor-bound settlement
	if res.UsedGas != wantGas {
		t.Fatalf("gasUsed = %d, want floor-bound %d", res.UsedGas, wantGas)
	}
	if bal := statedb.GetBalance(p1PayBeneficiary); !bal.IsZero() {
		t.Fatalf("beneficiary balance = %v, want 0 (0-value PAY)", bal)
	}
}

func TestP1EIP5920PayRevertRollsBack(t *testing.T) {
	// SSTORE slot0:=1, PAY 5 wei, then REVERT(0,0): both the storage write
	// and the value transfer roll back with the frame.
	// The gas limit must clear the EIP-8037 state-gas dimension: the SSTORE
	// charges StorageCreationSize(64) × CostPerStateByte(1530) = 97,920 state
	// gas from the limit-sized state reservoir on top of its 13,000 regular
	// gas (Amsterdam-style cold 3,000 + first-write surcharge 10,000, per the
	// Bogotá instruction set's Amsterdam lineage). 500,000 clears it; the
	// settled UsedGas (regular dimension) is 70,618.
	code := []byte{0x60, 0x01, 0x60, 0x00, 0x55} // PUSH1 1, PUSH1 0, SSTORE
	code = append(code, p1PayCode(5)[:len(p1PayCode(5))-1]...) // PAY section (drop STOP)
	code = append(code, 0x60, 0x00, 0x60, 0x00)                // PUSH1 0, PUSH1 0
	code = append(code, 0xfd)                                  // REVERT

	statedb := p1PaySetup(code)
	msg := p1PayMessage(0, nil, 500_000, 100)

	res := p1PayApply(t, statedb, msg)
	if !errors.Is(res.Err, vm.ErrExecutionReverted) {
		t.Fatalf("res.Err = %v, want ErrExecutionReverted", res.Err)
	}
	if bal := statedb.GetBalance(p1PayBeneficiary); !bal.IsZero() {
		t.Fatalf("beneficiary balance = %v, want 0 after revert", bal)
	}
	if val := statedb.GetState(eip8131To, common.Hash{}); val != (common.Hash{}) {
		t.Fatalf("slot 0 = %v, want 0 after revert", val)
	}
	if res.UsedGas == 0 {
		t.Fatalf("reverted execution must still consume gas")
	}
	// Regular-dimension decomposition: 21,000 intrinsic + 6 (2×PUSH1) +
	// 13,000 SSTORE + 6 (PUSH1+PUSH20) + 36,600 PAY + 6 (2×PUSH1) + 0 REVERT.
	const wantUsed = 70_618
	if res.UsedGas != wantUsed {
		t.Fatalf("gasUsed = %d, want %d", res.UsedGas, wantUsed)
	}
}

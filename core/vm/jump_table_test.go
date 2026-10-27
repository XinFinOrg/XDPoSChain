// Copyright 2022 The go-ethereum Authors
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

package vm

import (
	"math/big"
	"reflect"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/stretchr/testify/require"
)

// TestJumpTableCopy tests that deep copy is necessary to prevent modify shared jump table
func TestJumpTableCopy(t *testing.T) {
	tbl := newEip1559InstructionSet()
	require.Equal(t, uint64(0), tbl[SLOAD].constantGas)

	// a deep copy won't modify the shared jump table
	deepCopy := copyJumpTable(&tbl)
	deepCopy[SLOAD].constantGas = 100
	require.Equal(t, uint64(100), deepCopy[SLOAD].constantGas)
	require.Equal(t, uint64(0), tbl[SLOAD].constantGas)
}

// TestAmsterdamJumpTableSelection pins the fork-to-table selection in NewEVM and
// in LookupInstructionSet.
//
// TestEIP8024_Execution exercises the EIP-8024 handlers directly and never
// consults evm.table, so a selector that picked the wrong table - running
// Amsterdam bytecode against the Osaka table, or the reverse - would go
// unnoticed. EIP-8024 (DUPN, SWAPN, EXCHANGE) is the only instruction set the
// Amsterdam table adds over Osaka, so the two tables have to run different
// handlers for those three opcodes, and NewEVM must hand out the one its rules
// call for.
func TestAmsterdamJumpTableSelection(t *testing.T) {
	evmAt := func(cfg *params.ChainConfig) *EVM {
		return NewEVM(BlockContext{BlockNumber: big.NewInt(0)}, nil, nil, cfg, Config{})
	}
	osaka := evmAt(&params.ChainConfig{OsakaBlock: big.NewInt(0)})
	if osaka.table != &osakaInstructionSet {
		t.Fatalf("Osaka rules selected %p, want the Osaka instruction set", osaka.table)
	}
	amsterdam := evmAt(&params.ChainConfig{OsakaBlock: big.NewInt(0), AmsterdamBlock: big.NewInt(0)})
	if amsterdam.table != &amsterdamInstructionSet {
		t.Fatalf("Amsterdam rules selected %p, want the Amsterdam instruction set", amsterdam.table)
	}
	// EIP-8024 is the one instruction set the Amsterdam table adds over Osaka, so
	// its opcodes carry the EIP's gas there while Osaka still leaves them
	// undefined. The gas is what gets asserted: comparing handlers against Osaka
	// would only show that the two tables differ somewhere, not which operations
	// Amsterdam carries.
	for _, op := range []OpCode{DUPN, SWAPN, EXCHANGE} {
		if amsterdam.table[op].constantGas != GasFastestStep {
			t.Errorf("table[%#x].constantGas = %d, want the EIP-8024 gas of %d", op, amsterdam.table[op].constantGas, GasFastestStep)
		}
		if osaka.table[op].constantGas != 0 {
			t.Errorf("table[%#x].constantGas = %d on Osaka, want the opcode to stay undefined", op, osaka.table[op].constantGas)
		}
	}
	// LookupInstructionSet is the other selector; this test is its only in-repo
	// caller, so it is checked against the table NewEVM picked for the same rules.
	lookedUp, err := LookupInstructionSet(params.Rules{IsOsaka: true, IsAmsterdam: true})
	if err != nil {
		t.Fatalf("LookupInstructionSet returned an error: %v", err)
	}
	for _, op := range []OpCode{DUPN, SWAPN, EXCHANGE} {
		if reflect.ValueOf(lookedUp[op].execute).Pointer() != reflect.ValueOf(amsterdam.table[op].execute).Pointer() {
			t.Errorf("LookupInstructionSet[%#x] and NewEVM pick different handlers", op)
		}
	}
}

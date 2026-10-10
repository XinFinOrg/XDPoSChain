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

// TestAmsterdamJumpTableSelection pins the fork-to-table selection in NewEVM.
//
// TestEIP8024_Execution exercises the EIP-8024 handlers directly and never
// consults evm.table, so a selector that picked the wrong table - running
// Amsterdam bytecode against the Osaka table, or the reverse - would go
// unnoticed. EIP-8024 (DUPN, SWAPN, EXCHANGE) is the only instruction set the
// Amsterdam table adds over Osaka, so the two tables must differ exactly there,
// and NewEVM must hand out the one its rules call for.
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
	for _, op := range []OpCode{DUPN, SWAPN, EXCHANGE} {
		if osaka.table[op] == amsterdam.table[op] {
			t.Errorf("table[%#x] is shared between Osaka and Amsterdam, want the EIP-8024 entry to differ", op)
		}
	}
}

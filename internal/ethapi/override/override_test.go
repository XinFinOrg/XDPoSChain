// Copyright 2024 The go-ethereum Authors
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

package override

import (
	"maps"
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/common/hexutil"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/holiman/uint256"
)

type precompileContract struct{}

func (p *precompileContract) RequiredGas(input []byte) uint64 { return 0 }

func (p *precompileContract) Run(input []byte) ([]byte, error) { return nil, nil }

func (p *precompileContract) Name() string {
	return "test-implement"
}

func TestStateOverrideMovePrecompile(t *testing.T) {
	db := state.NewDatabase(rawdb.NewMemoryDatabase())
	statedb, err := state.New(common.Hash{}, db)
	if err != nil {
		t.Fatalf("failed to create statedb: %v", err)
	}
	precompiles := map[common.Address]vm.PrecompiledContract{
		common.BytesToAddress([]byte{0x1}): &precompileContract{},
		common.BytesToAddress([]byte{0x2}): &precompileContract{},
	}
	bytes2Addr := func(b []byte) *common.Address {
		a := common.BytesToAddress(b)
		return &a
	}
	var testSuite = []struct {
		overrides           StateOverride
		expectedPrecompiles map[common.Address]struct{}
		fail                bool
	}{
		{
			overrides: StateOverride{
				common.BytesToAddress([]byte{0x1}): {
					Code:             hex2Bytes("0xff"),
					MovePrecompileTo: bytes2Addr([]byte{0x2}),
				},
				common.BytesToAddress([]byte{0x2}): {
					Code: hex2Bytes("0x00"),
				},
			},
			// 0x2 has already been touched by the moveTo.
			fail: true,
		}, {
			overrides: StateOverride{
				common.BytesToAddress([]byte{0x1}): {
					Code:             hex2Bytes("0xff"),
					MovePrecompileTo: bytes2Addr([]byte{0xff}),
				},
				common.BytesToAddress([]byte{0x3}): {
					Code:             hex2Bytes("0x00"),
					MovePrecompileTo: bytes2Addr([]byte{0xfe}),
				},
			},
			// 0x3 is not a precompile.
			fail: true,
		}, {
			overrides: StateOverride{
				common.BytesToAddress([]byte{0x1}): {
					Code:             hex2Bytes("0xff"),
					MovePrecompileTo: bytes2Addr([]byte{0xff}),
				},
				common.BytesToAddress([]byte{0x2}): {
					Code:             hex2Bytes("0x00"),
					MovePrecompileTo: bytes2Addr([]byte{0xff}),
				},
			},
			// 0xff is already the destination of another precompile move.
			fail: true,
		}, {
			overrides: StateOverride{
				common.BytesToAddress([]byte{0x1}): {
					Code:             hex2Bytes("0xff"),
					MovePrecompileTo: bytes2Addr([]byte{0xff}),
				},
				common.BytesToAddress([]byte{0x2}): {
					Code:             hex2Bytes("0x00"),
					MovePrecompileTo: bytes2Addr([]byte{0xfe}),
				},
			},
			expectedPrecompiles: map[common.Address]struct{}{common.BytesToAddress([]byte{0xfe}): {}, common.BytesToAddress([]byte{0xff}): {}},
		},
	}

	for i, tt := range testSuite {
		cpy := maps.Clone(precompiles)
		// Apply overrides
		err := tt.overrides.Apply(statedb, cpy)
		if tt.fail {
			if err == nil {
				t.Errorf("test %d: want error, have nothing", i)
			}
			continue
		}
		if err != nil {
			t.Errorf("test %d: want no error, have %v", i, err)
			continue
		}
		// Precompile keys
		if len(cpy) != len(tt.expectedPrecompiles) {
			t.Errorf("test %d: precompile mismatch, want %d, have %d", i, len(tt.expectedPrecompiles), len(cpy))
		}
		for k := range tt.expectedPrecompiles {
			if _, ok := cpy[k]; !ok {
				t.Errorf("test %d: precompile not found: %s", i, k.String())
			}
		}
	}
}

// TestBlockOverridesApplySlotNum pins EIP-7843 under a block-number override:
// a slot is a block on this chain, so SLOTNUM has to move with NUMBER (docs/adr/0006-define-slot-number-as-block-number.md).
func TestBlockOverridesApplySlotNum(t *testing.T) {
	ctx := vm.BlockContext{BlockNumber: big.NewInt(19), SlotNum: 19}
	(&BlockOverrides{Number: (*hexutil.Big)(big.NewInt(1000))}).Apply(&ctx)
	if ctx.BlockNumber.Uint64() != 1000 || ctx.SlotNum != 1000 {
		t.Fatalf("after a number override: BlockNumber = %v, SlotNum = %d; want 1000 for both", ctx.BlockNumber, ctx.SlotNum)
	}
	// An override without a number leaves both fields alone.
	untouched := vm.BlockContext{BlockNumber: big.NewInt(19), SlotNum: 19}
	(&BlockOverrides{}).Apply(&untouched)
	if untouched.BlockNumber.Uint64() != 19 || untouched.SlotNum != 19 {
		t.Fatalf("without a number override: BlockNumber = %v, SlotNum = %d; want 19 for both", untouched.BlockNumber, untouched.SlotNum)
	}
}

// TestBlockOverridesSlotNumExecutes pins the behaviour ADR-0006 promises for
// RPC overrides: after a block-number override the EVM reports the overridden
// number from SLOTNUM, not just that the context field moved.
func TestBlockOverridesSlotNumExecutes(t *testing.T) {
	var (
		caller = common.HexToAddress("0x00000000000000000000000000000000000000aa")
		probe  = common.HexToAddress("0x00000000000000000000000000000000000000e1")
		// SLOTNUM, PUSH1 0, MSTORE, PUSH1 32, PUSH1 0, RETURN: return the slot number.
		code = common.FromHex("0x4b60005260206000f3")
	)
	statedb, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()))
	if err != nil {
		t.Fatalf("failed to create statedb: %v", err)
	}
	statedb.SetCode(probe, code)

	config := *params.TestChainConfig
	config.AmsterdamBlock = big.NewInt(0)
	ctx := vm.BlockContext{
		BlockNumber: big.NewInt(19),
		SlotNum:     19,
		GasLimit:    100000,
		CanTransfer: func(db vm.StateDB, a common.Address, amount *uint256.Int) bool { return true },
		Transfer: func(db vm.StateDB, a, b common.Address, amount *uint256.Int, rules *params.Rules) {
		},
	}
	(&BlockOverrides{Number: (*hexutil.Big)(big.NewInt(1000))}).Apply(&ctx)

	evm := vm.NewEVM(ctx, statedb, nil, &config, vm.Config{})
	evm.SetTxContext(vm.TxContext{Origin: caller, GasPrice: new(big.Int)})
	ret, _, err := evm.Call(caller, probe, nil, 100000, new(uint256.Int))
	if err != nil {
		t.Fatalf("call failed: %v", err)
	}
	if got := new(big.Int).SetBytes(ret).Uint64(); got != 1000 {
		t.Fatalf("SLOTNUM returned %d after a number override; want 1000", got)
	}
}

func hex2Bytes(str string) *hexutil.Bytes {
	rpcBytes := hexutil.Bytes(common.FromHex(str))
	return &rpcBytes
}

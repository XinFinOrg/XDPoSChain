// Copyright 2017 The go-ethereum Authors
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
	"bytes"
	"errors"
	"math"
	"math/big"
	"sort"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/common/hexutil"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/tracing"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/holiman/uint256"
)

// TestMemoryGasCost tests memory gas cost.
func TestMemoryGasCost(t *testing.T) {
	tests := []struct {
		size     uint64
		cost     uint64
		overflow bool
	}{
		{0x1fffffffe0, 36028809887088637, false},
		{0x1fffffffe1, 0, true},
	}
	for i, tt := range tests {
		v, err := memoryGasCost(&Memory{}, tt.size)
		if (err == ErrGasUintOverflow) != tt.overflow {
			t.Errorf("test %d: overflow mismatch: have %v, want %v", i, err == ErrGasUintOverflow, tt.overflow)
		}
		if v != tt.cost {
			t.Errorf("test %d: gas cost mismatch: have %v, want %v", i, v, tt.cost)
		}
	}
}

var eip2200Tests = []struct {
	original byte
	gaspool  uint64
	input    string
	used     uint64
	refund   uint64
	failure  error
}{
	{0, math.MaxUint64, "0x60006000556000600055", 1612, 0, nil},                // 0 -> 0 -> 0
	{0, math.MaxUint64, "0x60006000556001600055", 20812, 0, nil},               // 0 -> 0 -> 1
	{0, math.MaxUint64, "0x60016000556000600055", 20812, 19200, nil},           // 0 -> 1 -> 0
	{0, math.MaxUint64, "0x60016000556002600055", 20812, 0, nil},               // 0 -> 1 -> 2
	{0, math.MaxUint64, "0x60016000556001600055", 20812, 0, nil},               // 0 -> 1 -> 1
	{1, math.MaxUint64, "0x60006000556000600055", 5812, 15000, nil},            // 1 -> 0 -> 0
	{1, math.MaxUint64, "0x60006000556001600055", 5812, 4200, nil},             // 1 -> 0 -> 1
	{1, math.MaxUint64, "0x60006000556002600055", 5812, 0, nil},                // 1 -> 0 -> 2
	{1, math.MaxUint64, "0x60026000556000600055", 5812, 15000, nil},            // 1 -> 2 -> 0
	{1, math.MaxUint64, "0x60026000556003600055", 5812, 0, nil},                // 1 -> 2 -> 3
	{1, math.MaxUint64, "0x60026000556001600055", 5812, 4200, nil},             // 1 -> 2 -> 1
	{1, math.MaxUint64, "0x60026000556002600055", 5812, 0, nil},                // 1 -> 2 -> 2
	{1, math.MaxUint64, "0x60016000556000600055", 5812, 15000, nil},            // 1 -> 1 -> 0
	{1, math.MaxUint64, "0x60016000556002600055", 5812, 0, nil},                // 1 -> 1 -> 2
	{1, math.MaxUint64, "0x60016000556001600055", 1612, 0, nil},                // 1 -> 1 -> 1
	{0, math.MaxUint64, "0x600160005560006000556001600055", 40818, 19200, nil}, // 0 -> 1 -> 0 -> 1
	{1, math.MaxUint64, "0x600060005560016000556000600055", 10818, 19200, nil}, // 1 -> 0 -> 1 -> 0
	{1, 2306, "0x6001600055", 2306, 0, ErrOutOfGas},                            // 1 -> 1 (2300 sentry + 2xPUSH)
	{1, 2307, "0x6001600055", 806, 0, nil},                                     // 1 -> 1 (2301 sentry + 2xPUSH)
}

// TestEIP2200 tests eip 2200.
func TestEIP2200(t *testing.T) {
	for i, tt := range eip2200Tests {
		address := common.BytesToAddress([]byte("contract"))
		db := rawdb.NewMemoryDatabase()
		statedb, _ := state.New(types.EmptyRootHash, state.NewDatabase(db))
		statedb.CreateAccount(address)
		statedb.SetCode(address, hexutil.MustDecode(tt.input))
		statedb.SetState(address, common.Hash{}, common.BytesToHash([]byte{tt.original}))
		statedb.Finalise(true) // Push the state into the "original" slot

		vmctx := BlockContext{
			CanTransfer: func(StateDB, common.Address, *uint256.Int) bool { return true },
			Transfer:    func(StateDB, common.Address, common.Address, *uint256.Int, *params.Rules) {},
		}
		evm := NewEVM(vmctx, statedb, nil, params.AllEthashProtocolChanges, Config{ExtraEips: []int{2200}})

		_, gas, err := evm.Call(common.Address{}, address, nil, tt.gaspool, new(uint256.Int))
		if !errors.Is(err, tt.failure) {
			t.Errorf("test %d: failure mismatch: have %v, want %v", i, err, tt.failure)
		}
		if used := tt.gaspool - gas; used != tt.used {
			t.Errorf("test %d: gas used mismatch: have %v, want %v", i, used, tt.used)
		}
		if refund := evm.StateDB.GetRefund(); refund != tt.refund {
			t.Errorf("test %d: gas refund mismatch: have %v, want %v", i, refund, tt.refund)
		}
	}
}

type countingStateDB struct {
	*state.StateDB
	getStateCalls          int
	getCommittedStateCalls int
	getCombinedStateCalls  int
}

func (s *countingStateDB) GetState(addr common.Address, key common.Hash) common.Hash {
	s.getStateCalls++
	return s.StateDB.GetState(addr, key)
}

func (s *countingStateDB) GetCommittedState(addr common.Address, key common.Hash) common.Hash {
	s.getCommittedStateCalls++
	return s.StateDB.GetCommittedState(addr, key)
}

func (s *countingStateDB) GetStateAndCommittedState(addr common.Address, key common.Hash) (common.Hash, common.Hash) {
	s.getCombinedStateCalls++
	return s.StateDB.GetStateAndCommittedState(addr, key)
}

// TestEIP2200UsesCombinedStateGetter tests eip 2200 uses combined state getter.
func TestEIP2200UsesCombinedStateGetter(t *testing.T) {
	address := common.BytesToAddress([]byte("contract"))
	statedb, _ := state.New(types.EmptyRootHash, state.NewDatabase(rawdb.NewMemoryDatabase()))
	statedb.CreateAccount(address)
	statedb.SetCode(address, hexutil.MustDecode("0x6002600055"))
	statedb.SetState(address, common.Hash{}, common.BytesToHash([]byte{1}))
	statedb.Finalise(true)

	countingDB := &countingStateDB{StateDB: statedb}
	vmctx := BlockContext{
		CanTransfer: func(StateDB, common.Address, *uint256.Int) bool { return true },
		Transfer:    func(StateDB, common.Address, common.Address, *uint256.Int, *params.Rules) {},
	}
	evm := NewEVM(vmctx, countingDB, nil, params.AllEthashProtocolChanges, Config{ExtraEips: []int{2200}})

	_, _, err := evm.Call(common.Address{}, address, nil, math.MaxUint64, new(uint256.Int))
	if err != nil {
		t.Fatalf("call failed: %v", err)
	}
	if countingDB.getCombinedStateCalls == 0 {
		t.Fatalf("expected GetStateAndCommittedState to be used")
	}
	if countingDB.getStateCalls != 0 {
		t.Fatalf("expected GetState to be bypassed, got %d calls", countingDB.getStateCalls)
	}
	if countingDB.getCommittedStateCalls != 0 {
		t.Fatalf("expected GetCommittedState to be bypassed, got %d calls", countingDB.getCommittedStateCalls)
	}
}

// createGasSearchCeiling bounds the gas search in TestCreateGas. A case rejected
// by a size check fails at every gas amount, so the search returns the ceiling.
// The ceiling must therefore exceed what the creation itself costs, otherwise a
// creation that runs out of gas is indistinguishable from one rejected by the
// size check, and the case stops pinning the check.
const createGasSearchCeiling = 200_000

var createGasTests = []struct {
	code       string
	eip3860    bool
	gasUsed    uint64
	minimumGas uint64
}{
	// legacy create(0, 0, 0xc000) without 3860 used
	{"0x61C00060006000f0" + "600052" + "60206000F3", false, 41237, 41237},
	// legacy create(0, 0, 0xc000) _with_ 3860
	{"0x61C00060006000f0" + "600052" + "60206000F3", true, 44309, 44309},
	// create2(0, 0, 0xc001, 0) without 3860
	{"0x600061C00160006000f5" + "600052" + "60206000F3", false, 50471, 50471},
	// create2(0, 0, 0x20001, 0) (too large), with 3860
	{"0x60006202000160006000f5" + "600052" + "60206000F3", true, 32012, createGasSearchCeiling},
	// create2(0, 0, 0xc000, 0)
	// This case is trying to deploy code at (within) the Osaka limit
	{"0x600061C00060006000f5" + "600052" + "60206000F3", true, 53528, 53528},
	// create2(0, 0, 0x10001, 0)
	// This case exceeds the Osaka initcode limit but stays within the Amsterdam one
	{"0x60006201000160006000f5" + "600052" + "60206000F3", true, 62763, 62763},
	// create2(0, 0, 0x20001, 0)
	// This case is trying to deploy code exceeding the Amsterdam limit
	{"0x60006202000160006000f5" + "600052" + "60206000F3", true, 32024, createGasSearchCeiling}}

// TestCreateGas tests create gas.
func TestCreateGas(t *testing.T) {
	for i, tt := range createGasTests {
		var gasUsed = uint64(0)
		doCheck := func(testGas int) bool {
			address := common.BytesToAddress([]byte("contract"))
			statedb, _ := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
			statedb.CreateAccount(address)
			statedb.SetCode(address, hexutil.MustDecode(tt.code))
			statedb.Finalise(true)
			vmctx := BlockContext{
				CanTransfer: func(StateDB, common.Address, *uint256.Int) bool { return true },
				Transfer:    func(StateDB, common.Address, common.Address, *uint256.Int, *params.Rules) {},
				BlockNumber: big.NewInt(0),
			}
			config := Config{}
			legacyConfig := *params.AllEthashProtocolChanges
			legacyConfig.EIP1559Block = nil
			legacyConfig.CancunBlock = nil
			legacyConfig.PragueBlock = nil
			legacyConfig.OsakaBlock = nil
			legacyConfig.AmsterdamBlock = nil
			chainConfig := &legacyConfig
			if tt.eip3860 {
				config.ExtraEips = []int{3860}
				chainConfig = params.MergedTestChainConfig
			}

			evm := NewEVM(vmctx, statedb, nil, chainConfig, config)
			var startGas = uint64(testGas)
			ret, gas, err := evm.Call(common.Address{}, address, nil, startGas, new(uint256.Int))
			if err != nil {
				return false
			}
			gasUsed = startGas - gas
			if len(ret) != 32 {
				t.Fatalf("test %d: expected 32 bytes returned, have %d", i, len(ret))
			}
			if bytes.Equal(ret, make([]byte, 32)) {
				// Failure
				return false
			}
			return true
		}
		minGas := sort.Search(createGasSearchCeiling, doCheck)
		if uint64(minGas) != tt.minimumGas {
			t.Fatalf("test %d: min gas error, want %d, have %d", i, tt.minimumGas, minGas)
		}
		// If the deployment succeeded, we also check the gas used
		if minGas < createGasSearchCeiling {
			if gasUsed != tt.gasUsed {
				t.Errorf("test %d: gas used mismatch: have %v, want %v", i, gasUsed, tt.gasUsed)
			}
		}
	}
}

func newCallGasTestEVM(t *testing.T, statedb StateDB, rules params.Rules) *EVM {
	t.Helper()
	evm := NewEVM(BlockContext{
		BlockNumber: big.NewInt(0),
		CanTransfer: func(StateDB, common.Address, *uint256.Int) bool { return true },
		Transfer:    func(StateDB, common.Address, common.Address, *uint256.Int, *params.Rules) {},
	}, statedb, nil, params.TestChainConfig, Config{})
	evm.chainRules = rules
	return evm
}

func newCallGasTestStateDB(t *testing.T) *state.StateDB {
	t.Helper()
	statedb, err := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	if err != nil {
		t.Fatalf("failed to create state: %v", err)
	}
	return statedb
}

// callGasTestStack pushes gas, target and value so Back(0..2) match the CALL layout
func callGasTestStack(gas uint64, target common.Address, value *uint256.Int) *Stack {
	st := newstack()
	st.push(new(uint256.Int))            // retSize
	st.push(new(uint256.Int))            // retOffset
	st.push(new(uint256.Int))            // argsSize
	st.push(new(uint256.Int))            // argsOffset
	st.push(new(uint256.Int).Set(value)) // value
	st.push(new(uint256.Int).SetBytes(target.Bytes()))
	st.push(uint256.NewInt(gas))
	return st
}

// callGasCountingStateDB counts account reads so tests can assert an early out precedes them
type callGasCountingStateDB struct {
	StateDB
	emptyReads int
	codeReads  int
}

func (s *callGasCountingStateDB) Empty(addr common.Address) bool {
	s.emptyReads++
	return s.StateDB.Empty(addr)
}

func (s *callGasCountingStateDB) GetCode(addr common.Address) []byte {
	s.codeReads++
	return s.StateDB.GetCode(addr)
}

// TestCallVariantIntrinsicGas pins the stateless and stateful halves of the four variants
func TestCallVariantIntrinsicGas(t *testing.T) {
	var (
		emptyAddr    = common.HexToAddress("0xaa")
		fundedAddr   = common.HexToAddress("0xbb")
		noValue      = new(uint256.Int)
		oneWei       = uint256.NewInt(1)
		eip150And158 = params.Rules{IsEIP150: true, IsEIP158: true}
		eip150Only   = params.Rules{IsEIP150: true}
	)
	tests := []struct {
		name        string
		gasFunc     gasFunc
		rules       params.Rules
		value       *uint256.Int
		target      common.Address
		memSize     uint64
		readOnly    bool
		contractGas uint64
		want        uint64
		wantErr     error
	}{
		{"call, no value", gasCallIntrinsic, eip150And158, noValue, emptyAddr, 0, false, 100000, 0, nil},
		{"call, value to empty account", gasCallIntrinsic, eip150And158, oneWei, emptyAddr, 0, false, 100000, params.CallValueTransferGas + params.CallNewAccountGas, nil},
		{"call, value to funded account", gasCallIntrinsic, eip150And158, oneWei, fundedAddr, 0, false, 100000, params.CallValueTransferGas, nil},
		{"call, memory expansion", gasCallIntrinsic, eip150And158, noValue, fundedAddr, 32, false, 100000, 3, nil},
		{"call, value and memory expansion", gasCallIntrinsic, eip150And158, oneWei, emptyAddr, 32, false, 100000, params.CallValueTransferGas + params.CallNewAccountGas + 3, nil},
		{"call, pre-EIP-158 nonexistent account", gasCallIntrinsic, eip150Only, noValue, emptyAddr, 0, false, 100000, params.CallNewAccountGas, nil},
		{"call, pre-EIP-158 value to nonexistent account", gasCallIntrinsic, eip150Only, oneWei, emptyAddr, 0, false, 100000, params.CallNewAccountGas + params.CallValueTransferGas, nil},
		{"call, write protection", gasCallIntrinsic, eip150And158, oneWei, fundedAddr, 0, true, 100000, 0, ErrWriteProtection},
		{"call code, value", gasCallCodeIntrinsic, eip150And158, oneWei, fundedAddr, 0, false, 100000, params.CallValueTransferGas, nil},
		{"call code, no value", gasCallCodeIntrinsic, eip150And158, noValue, fundedAddr, 0, false, 100000, 0, nil},
		{"call code, memory expansion", gasCallCodeIntrinsic, eip150And158, noValue, fundedAddr, 32, false, 100000, 3, nil},
		{"delegate call", gasDelegateCallIntrinsic, eip150And158, noValue, fundedAddr, 0, false, 100000, 0, nil},
		{"delegate call, memory expansion", gasDelegateCallIntrinsic, eip150And158, noValue, fundedAddr, 32, false, 100000, 3, nil},
		{"static call", gasStaticCallIntrinsic, eip150And158, noValue, fundedAddr, 0, false, 100000, 0, nil},
		{"static call, memory expansion", gasStaticCallIntrinsic, eip150And158, noValue, fundedAddr, 32, false, 100000, 3, nil},
		{"call, memory overflow", gasCallIntrinsic, eip150And158, noValue, fundedAddr, 0x1fffffffe1, false, math.MaxUint64, 0, ErrGasUintOverflow},
		{"call code, memory overflow", gasCallCodeIntrinsic, eip150And158, noValue, fundedAddr, 0x1fffffffe1, false, math.MaxUint64, 0, ErrGasUintOverflow},
		{"delegate call, memory overflow", gasDelegateCallIntrinsic, eip150And158, noValue, fundedAddr, 0x1fffffffe1, false, math.MaxUint64, 0, ErrGasUintOverflow},
		{"static call, memory overflow", gasStaticCallIntrinsic, eip150And158, noValue, fundedAddr, 0x1fffffffe1, false, math.MaxUint64, 0, ErrGasUintOverflow},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			statedb := newCallGasTestStateDB(t)
			statedb.SetCode(fundedAddr, []byte{byte(STOP)})
			evm := newCallGasTestEVM(t, statedb, tt.rules)
			evm.readOnly = tt.readOnly

			contract := NewContract(common.Address{}, common.Address{}, new(uint256.Int), tt.contractGas, nil)
			stack := callGasTestStack(0, tt.target, tt.value)
			defer returnStack(stack)

			got, err := tt.gasFunc(evm, contract, stack, NewMemory(), tt.memSize)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("error mismatch: have %v, want %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("gas mismatch: have %d, want %d", got, tt.want)
			}
		})
	}
}

// TestCallVariantGasBinding pins which intrinsic each variant runs at the plain,
// EIP-2929 and EIP-7702 layers. Requested gas is zero, so a wrong binding moves
// the result by the value transfer or new-account charge; the delegate and
// static rows also run read-only.
func TestCallVariantGasBinding(t *testing.T) {
	var (
		emptyAddr = common.HexToAddress("0xaa")
		oneWei    = uint256.NewInt(1)
		rules     = params.Rules{IsEIP150: true, IsEIP158: true}
		coldCost  = params.ColdAccountAccessCostEIP2929 - params.WarmStorageReadCostEIP2929
	)
	tests := []struct {
		name     string
		gasFunc  gasFunc
		readOnly bool
		want     uint64
	}{
		{"call, plain", gasCall, false, params.CallValueTransferGas + params.CallNewAccountGas},
		{"call code, plain", gasCallCode, false, params.CallValueTransferGas},
		{"delegate call, plain", gasDelegateCall, false, 0},
		{"static call, plain", gasStaticCall, false, 0},
		{"call, eip-2929", gasCallEIP2929, false, coldCost + params.CallValueTransferGas + params.CallNewAccountGas},
		{"call code, eip-2929", gasCallCodeEIP2929, false, coldCost + params.CallValueTransferGas},
		{"delegate call, eip-2929", gasDelegateCallEIP2929, false, coldCost},
		{"static call, eip-2929", gasStaticCallEIP2929, false, coldCost},
		{"call, eip-7702", gasCallEIP7702, false, coldCost + params.CallValueTransferGas + params.CallNewAccountGas},
		{"call code, eip-7702", gasCallCodeEIP7702, false, coldCost + params.CallValueTransferGas},
		{"delegate call, eip-7702", gasDelegateCallEIP7702, false, coldCost},
		{"static call, eip-7702", gasStaticCallEIP7702, false, coldCost},
		{"delegate call, static context", gasDelegateCallEIP2929, true, coldCost},
		{"static call, static context", gasStaticCallEIP2929, true, coldCost},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			statedb := newCallGasTestStateDB(t)
			evm := newCallGasTestEVM(t, statedb, rules)
			evm.readOnly = tt.readOnly

			contract := NewContract(common.Address{}, common.Address{}, new(uint256.Int), 100000, nil)
			stack := callGasTestStack(0, emptyAddr, oneWei)
			defer returnStack(stack)

			got, err := tt.gasFunc(evm, contract, stack, NewMemory(), 0)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("gas mismatch: have %d, want %d", got, tt.want)
			}
		})
	}
}

// TestCallVariantGasCost pins the intrinsic plus the 63/64 nested budget of each calculator
func TestCallVariantGasCost(t *testing.T) {
	var (
		fundedAddr   = common.HexToAddress("0xbb")
		noValue      = new(uint256.Int)
		oneWei       = uint256.NewInt(1)
		eip150And158 = params.Rules{IsEIP150: true, IsEIP158: true}
		eip158Only   = params.Rules{IsEIP158: true}
		// Far above any budget below, so the 63/64 rule decides the nested gas.
		huge = uint64(1) << 40
	)
	tests := []struct {
		name        string
		gasFunc     gasFunc
		rules       params.Rules
		value       *uint256.Int
		memSize     uint64
		contractGas uint64
		requested   uint64
		want        uint64
		wantCallGas uint64
	}{
		// 6400 - 6400/64 = 6300 granted to the callee.
		{"call, 63/64 cap", gasCall, eip150And158, noValue, 0, 6400, huge, 6300, 6300},
		// The value case excludes the stipend: opCall grants it to the callee.
		{"call, value transfer under the cap", gasCall, eip150And158, oneWei, 0, 15400, huge, params.CallValueTransferGas + 6300, 6300},
		{"call, request below the cap", gasCall, eip150And158, noValue, 0, 6400, 100, 100, 100},
		{"call, no EIP-150", gasCall, eip158Only, noValue, 0, 6400, huge, huge, huge},
		{"delegate call, memory expansion", gasDelegateCall, eip150And158, noValue, 32, 6403, huge, 3 + 6300, 6300},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			statedb := newCallGasTestStateDB(t)
			statedb.SetCode(fundedAddr, []byte{byte(STOP)})
			evm := newCallGasTestEVM(t, statedb, tt.rules)

			contract := NewContract(common.Address{}, common.Address{}, new(uint256.Int), tt.contractGas, nil)
			stack := callGasTestStack(tt.requested, fundedAddr, tt.value)
			defer returnStack(stack)

			got, err := tt.gasFunc(evm, contract, stack, NewMemory(), tt.memSize)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("gas mismatch: have %d, want %d", got, tt.want)
			}
			if evm.callGasTemp != tt.wantCallGas {
				t.Errorf("callGasTemp mismatch: have %d, want %d", evm.callGasTemp, tt.wantCallGas)
			}
		})
	}
}

// TestCallVariantGasEIP7702 pins the EIP-7702 wrapper charges, aggregation and refund
func TestCallVariantGasEIP7702(t *testing.T) {
	var (
		delegated    = common.HexToAddress("0xdead")
		plainAddr    = common.HexToAddress("0xbb")
		target       = common.HexToAddress("0xaa")
		noValue      = new(uint256.Int)
		oneWei       = uint256.NewInt(1)
		eip150And158 = params.Rules{IsEIP150: true, IsEIP158: true}
		huge         = uint64(1) << 40
	)
	tests := []struct {
		name        string
		gasFunc     gasFunc
		account     common.Address
		value       *uint256.Int
		warmAccount bool
		warmTarget  bool
		contractGas uint64
		want        uint64
		wantCallGas uint64
	}{
		// Cold account 2500, cold delegated target 2600, then 63/64 of the rest.
		{"call, cold delegation", gasCallEIP7702, delegated, noValue, false, false, 100000, 2500 + 2600 + 93418, 93418},
		{"call, warm delegation", gasCallEIP7702, delegated, noValue, true, true, 100000, 100 + 98340, 98340},
		{"call, warm account and cold target", gasCallEIP7702, delegated, noValue, true, false, 100000, 2600 + 95879, 95879},
		{"call, no delegation", gasCallEIP7702, plainAddr, noValue, false, false, 100000, 2500 + 95977, 95977},
		{"call code, value", gasCallCodeEIP7702, plainAddr, oneWei, false, false, 17900, 2500 + params.CallValueTransferGas + 6300, 6300},
		{"delegate call", gasDelegateCallEIP7702, plainAddr, noValue, false, false, 8900, 2500 + 6300, 6300},
		{"static call", gasStaticCallEIP7702, plainAddr, noValue, false, false, 8900, 2500 + 6300, 6300},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			statedb := newCallGasTestStateDB(t)
			statedb.SetCode(delegated, types.AddressToDelegation(target))
			statedb.SetCode(plainAddr, []byte{byte(STOP)})
			if tt.warmAccount {
				statedb.AddAddressToAccessList(tt.account)
			}
			if tt.warmTarget {
				statedb.AddAddressToAccessList(target)
			}
			evm := newCallGasTestEVM(t, statedb, eip150And158)

			contract := NewContract(common.Address{}, common.Address{}, new(uint256.Int), tt.contractGas, nil)
			stack := callGasTestStack(huge, tt.account, tt.value)
			defer returnStack(stack)

			got, err := tt.gasFunc(evm, contract, stack, NewMemory(), 0)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("gas mismatch: have %d, want %d", got, tt.want)
			}
			if evm.callGasTemp != tt.wantCallGas {
				t.Errorf("callGasTemp mismatch: have %d, want %d", evm.callGasTemp, tt.wantCallGas)
			}
			if contract.Gas != tt.contractGas {
				t.Errorf("contract gas not restored: have %d, want %d", contract.Gas, tt.contractGas)
			}
		})
	}
}

// TestCallVariantGasEarlyOut covers the guards of all three layers: the plain
// calculator rejects before the account read, the EIP-2929 wrapper propagates
// it, and the EIP-7702 wrapper rejects before the delegation lookup, and before
// the access-list write on a static-context value transfer. The stateless-half
// guards are strict inequalities, so an exactly covered call is accepted.
func TestCallVariantGasEarlyOut(t *testing.T) {
	var (
		emptyAddr   = common.HexToAddress("0xaa")
		fundedAddr  = common.HexToAddress("0xbb")
		oneWei      = uint256.NewInt(1)
		rules       = params.Rules{IsEIP150: true, IsEIP158: true}
		berlinRules = params.Rules{IsEIP150: true, IsEIP158: true, IsBerlin: true}
	)
	t.Run("call before the account is inspected", func(t *testing.T) {
		statedb := &callGasCountingStateDB{StateDB: newCallGasTestStateDB(t)}
		evm := newCallGasTestEVM(t, statedb, rules)

		// One unit short of the value transfer charge
		contract := NewContract(common.Address{}, common.Address{}, new(uint256.Int), params.CallValueTransferGas-1, nil)
		stack := callGasTestStack(0, emptyAddr, oneWei)
		defer returnStack(stack)

		if _, err := gasCallIntrinsic(evm, contract, stack, NewMemory(), 0); !errors.Is(err, ErrOutOfGas) {
			t.Fatalf("error mismatch: have %v, want %v", err, ErrOutOfGas)
		}
		if statedb.emptyReads != 0 {
			t.Errorf("target account inspected before the stateless half was covered: %d reads", statedb.emptyReads)
		}
	})
	t.Run("the account is inspected when the intrinsic is covered", func(t *testing.T) {
		statedb := &callGasCountingStateDB{StateDB: newCallGasTestStateDB(t)}
		evm := newCallGasTestEVM(t, statedb, rules)

		contract := NewContract(common.Address{}, common.Address{}, new(uint256.Int), 100000, nil)
		stack := callGasTestStack(0, emptyAddr, oneWei)
		defer returnStack(stack)

		if _, err := gasCallIntrinsic(evm, contract, stack, NewMemory(), 0); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if statedb.emptyReads == 0 {
			t.Errorf("the counting StateDB did not observe the account read")
		}
	})
	t.Run("7702 before the target code is read", func(t *testing.T) {
		statedb := &callGasCountingStateDB{StateDB: newCallGasTestStateDB(t)}
		evm := newCallGasTestEVM(t, statedb, rules)

		// Enough for the cold charge and the stateless half, but not for the
		// new-account charge on an empty target
		contract := NewContract(common.Address{}, common.Address{}, new(uint256.Int), 36000, nil)
		stack := callGasTestStack(0, emptyAddr, oneWei)
		defer returnStack(stack)

		if _, err := gasCallEIP7702(evm, contract, stack, NewMemory(), 0); !errors.Is(err, ErrOutOfGas) {
			t.Fatalf("error mismatch: have %v, want %v", err, ErrOutOfGas)
		}
		if statedb.codeReads != 0 {
			t.Errorf("target code read before the intrinsic cost was covered: %d reads", statedb.codeReads)
		}
	})
	t.Run("7702 write protection before the access list", func(t *testing.T) {
		statedb := newCallGasTestStateDB(t)
		evm := newCallGasTestEVM(t, statedb, rules)
		evm.readOnly = true

		// Rejected before the access-list write and cold charge; the intrinsic
		// check would fire only after both
		contract := NewContract(common.Address{}, common.Address{}, new(uint256.Int), 100000, nil)
		stack := callGasTestStack(0, emptyAddr, oneWei)
		defer returnStack(stack)

		if _, err := gasCallEIP7702(evm, contract, stack, NewMemory(), 0); !errors.Is(err, ErrWriteProtection) {
			t.Fatalf("error mismatch: have %v, want %v", err, ErrWriteProtection)
		}
		if statedb.AddressInAccessList(emptyAddr) {
			t.Errorf("target joined the access list before the write protection check")
		}
		if contract.Gas != 100000 {
			t.Errorf("contract gas changed: have %d, want %d", contract.Gas, 100000)
		}
	})
	t.Run("2929 wrapper propagates the early out", func(t *testing.T) {
		statedb := &callGasCountingStateDB{StateDB: newCallGasTestStateDB(t)}
		evm := newCallGasTestEVM(t, statedb, berlinRules)

		// After the cold charge, one unit short of the value transfer charge, so
		// the stateless half is uncovered and the target must stay unread
		contract := NewContract(common.Address{}, common.Address{}, new(uint256.Int),
			params.ColdAccountAccessCostEIP2929-params.WarmStorageReadCostEIP2929+params.CallValueTransferGas-1, nil)
		stack := callGasTestStack(0, emptyAddr, oneWei)
		defer returnStack(stack)

		if _, err := gasCallEIP2929(evm, contract, stack, NewMemory(), 0); !errors.Is(err, ErrOutOfGas) {
			t.Fatalf("error mismatch: have %v, want %v", err, ErrOutOfGas)
		}
		if statedb.emptyReads != 0 {
			t.Errorf("target account inspected before the stateless half was covered: %d reads", statedb.emptyReads)
		}
	})
	t.Run("call accepts an exactly covered intrinsic", func(t *testing.T) {
		statedb := newCallGasTestStateDB(t)
		statedb.SetCode(fundedAddr, []byte{byte(STOP)})
		evm := newCallGasTestEVM(t, statedb, rules)

		// An existing account with value costs exactly the transfer charge, and
		// an exact fit is accepted; only a shortfall is rejected
		contract := NewContract(common.Address{}, common.Address{}, new(uint256.Int), params.CallValueTransferGas, nil)
		stack := callGasTestStack(0, fundedAddr, oneWei)
		defer returnStack(stack)

		gas, err := gasCall(evm, contract, stack, NewMemory(), 0)
		if err != nil {
			t.Fatalf("exactly covered intrinsic rejected: %v", err)
		}
		if gas != params.CallValueTransferGas {
			t.Errorf("gas mismatch: have %d, want %d", gas, params.CallValueTransferGas)
		}
	})
	t.Run("7702 accepts an exactly covered intrinsic", func(t *testing.T) {
		statedb := newCallGasTestStateDB(t)
		statedb.SetCode(fundedAddr, []byte{byte(STOP)})
		evm := newCallGasTestEVM(t, statedb, rules)

		// After the cold charge, what is left covers the intrinsic exactly
		coldCost := params.ColdAccountAccessCostEIP2929 - params.WarmStorageReadCostEIP2929
		contract := NewContract(common.Address{}, common.Address{}, new(uint256.Int),
			coldCost+params.CallValueTransferGas, nil)
		stack := callGasTestStack(0, fundedAddr, oneWei)
		defer returnStack(stack)

		gas, err := gasCallEIP7702(evm, contract, stack, NewMemory(), 0)
		if err != nil {
			t.Fatalf("exactly covered intrinsic rejected: %v", err)
		}
		if want := coldCost + params.CallValueTransferGas; gas != want {
			t.Errorf("gas mismatch: have %d, want %d", gas, want)
		}
	})
}

// TestCallVariantGasOpcodeCost runs the four variants through the jump table,
// covering the wiring and the constant and dynamic gas end to end.
func TestCallVariantGasOpcodeCost(t *testing.T) {
	var (
		caller     = common.HexToAddress("0xc0de")
		emptyAddr  = common.HexToAddress("0xaa")
		fundedAddr = common.HexToAddress("0xbb")
	)
	// Osaka and Amsterdam only add opcodes, so disable them to keep costs stable
	chainConfig := *params.TestChainConfig
	chainConfig.OsakaBlock = nil
	chainConfig.AmsterdamBlock = nil

	makeCode := func(op OpCode, target common.Address, value byte) []byte {
		code := []byte{byte(PUSH1), 0x00, byte(PUSH1), 0x00, byte(PUSH1), 0x00, byte(PUSH1), 0x00}
		if op == CALL || op == CALLCODE {
			code = append(code, byte(PUSH1), value)
		}
		code = append(code, byte(PUSH20))
		code = append(code, target.Bytes()...)
		return append(code, byte(PUSH1), 0xff, byte(op), byte(POP), byte(STOP))
	}

	tests := []struct {
		name   string
		op     OpCode
		target common.Address
		value  byte
		// Constant 100 (warm access, EIP-2929) + cold access 2500 + intrinsic + the
		// 255 granted to the callee.
		want uint64
	}{
		{"call to an empty account with value", CALL, emptyAddr, 1, 100 + 2500 + params.CallValueTransferGas + params.CallNewAccountGas + 255},
		{"call to a funded account with value", CALL, fundedAddr, 1, 100 + 2500 + params.CallValueTransferGas + 255},
		{"call without value", CALL, fundedAddr, 0, 100 + 2500 + 255},
		{"call code with value", CALLCODE, fundedAddr, 1, 100 + 2500 + params.CallValueTransferGas + 255},
		{"delegate call", DELEGATECALL, fundedAddr, 0, 100 + 2500 + 255},
		{"static call", STATICCALL, fundedAddr, 0, 100 + 2500 + 255},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			statedb := newCallGasTestStateDB(t)
			statedb.SetCode(fundedAddr, []byte{byte(STOP)})
			statedb.SetCode(caller, makeCode(tt.op, tt.target, tt.value))

			var (
				got    uint64
				traced bool
			)
			evm := NewEVM(BlockContext{
				BlockNumber: big.NewInt(0),
				CanTransfer: func(StateDB, common.Address, *uint256.Int) bool { return true },
				Transfer:    func(StateDB, common.Address, common.Address, *uint256.Int, *params.Rules) {},
			}, statedb, nil, &chainConfig, Config{Tracer: &tracing.Hooks{
				OnOpcode: func(pc uint64, op byte, gas, cost uint64, scope tracing.OpContext, rData []byte, depth int, err error) {
					if OpCode(op) == tt.op && !traced {
						got, traced = cost, true
					}
				},
			}})
			if _, _, err := evm.Call(common.Address{}, caller, nil, 1000000, new(uint256.Int)); err != nil {
				t.Fatalf("call failed: %v", err)
			}
			if !traced {
				t.Fatalf("%v was not executed", tt.op)
			}
			if got != tt.want {
				t.Errorf("opcode cost mismatch: have %d, want %d", got, tt.want)
			}
		})
	}
}

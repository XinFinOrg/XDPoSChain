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
	"bytes"
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/tracing"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// txGasEvent is one transaction-level gas change as a tracer observes it: the
// balance before and after the change in both dimensions, plus the reason.
type txGasEvent struct {
	old, new           uint64
	oldState, newState uint64
	reason             tracing.GasChangeReason
}

// txev builds an event whose state dimension is zero, the only value it can
// take on this tree: the state dimension is never written before Amsterdam.
func txev(old, new uint64, reason tracing.GasChangeReason) txGasEvent {
	return txGasEvent{old: old, new: new, reason: reason}
}

// checkTxGasEvents compares the events one by one, so a wrong balance, a
// reordered stream and a state dimension carrying a value all fail here.
func checkTxGasEvents(t *testing.T, what string, have, want []txGasEvent) {
	t.Helper()
	if len(have) != len(want) {
		t.Fatalf("%s: have %d events, want %d (all: %v)", what, len(have), len(want), have)
	}
	for i := range want {
		if have[i] != want[i] {
			t.Fatalf("%s: event %d: have %+v, want %+v (all: %v)", what, i, have[i], want[i], have)
		}
	}
}

// TestTxGasChangeStream pins the transaction-level gas stream on both sides of
// Amsterdam: the initial balance, the intrinsic gas, the calldata floor, the
// refunds and the leftover return. Each stream is spelled out verbatim for a
// V1-only and a V2-only tracer, so a dispatch path that drops V2, or a balance
// that is reported wrong on both, fails here.
func TestTxGasChangeStream(t *testing.T) {
	contract := common.HexToAddress("0x2222222222222222222222222222222222222222")
	clearSlot := []byte{byte(vm.PUSH1), 0x00, byte(vm.PUSH1), 0x00, byte(vm.SSTORE), byte(vm.STOP)}
	cases := []struct {
		name    string
		data    []byte
		to      *common.Address
		prepare func(*state.StateDB)
		want    map[bool][]txGasEvent // key: Amsterdam scheduled
	}{
		{
			"transfer", nil, nil, nil,
			map[bool][]txGasEvent{
				false: {
					txev(0, 100_000, tracing.GasChangeTxInitialBalance),
					txev(100_000, 79_000, tracing.GasChangeTxIntrinsicGas),
					txev(0, 79_000, tracing.GasChangeCallInitialBalance),
					txev(79_000, 0, tracing.GasChangeCallLeftOverReturned),
					txev(79_000, 0, tracing.GasChangeTxLeftOverReturned),
				},
				true: {
					txev(0, 100_000, tracing.GasChangeTxInitialBalance),
					txev(100_000, 85_000, tracing.GasChangeTxIntrinsicGas),
					txev(0, 85_000, tracing.GasChangeCallInitialBalance),
					txev(85_000, 0, tracing.GasChangeCallLeftOverReturned),
					txev(85_000, 0, tracing.GasChangeTxLeftOverReturned),
				},
			},
		},
		{
			"calldata floor", bytes.Repeat([]byte{0xff}, 100), nil, nil,
			map[bool][]txGasEvent{
				false: {
					txev(0, 100_000, tracing.GasChangeTxInitialBalance),
					txev(100_000, 77_400, tracing.GasChangeTxIntrinsicGas),
					txev(0, 77_400, tracing.GasChangeCallInitialBalance),
					txev(77_400, 0, tracing.GasChangeCallLeftOverReturned),
					txev(77_400, 75_000, tracing.GasChangeTxDataFloor),
					txev(75_000, 0, tracing.GasChangeTxLeftOverReturned),
				},
				true: {
					txev(0, 100_000, tracing.GasChangeTxInitialBalance),
					txev(100_000, 83_400, tracing.GasChangeTxIntrinsicGas),
					txev(0, 83_400, tracing.GasChangeCallInitialBalance),
					txev(83_400, 0, tracing.GasChangeCallLeftOverReturned),
					txev(83_400, 78_600, tracing.GasChangeTxDataFloor),
					txev(78_600, 0, tracing.GasChangeTxLeftOverReturned),
				},
			},
		},
		{
			"storage clear refund", nil, &contract, func(statedb *state.StateDB) {
				statedb.SetCode(contract, clearSlot)
				statedb.SetState(contract, common.Hash{}, common.HexToHash("01"))
				statedb.Finalise(true)
			},
			map[bool][]txGasEvent{
				false: {
					txev(0, 100_000, tracing.GasChangeTxInitialBalance),
					txev(100_000, 79_000, tracing.GasChangeTxIntrinsicGas),
					txev(0, 79_000, tracing.GasChangeCallInitialBalance),
					txev(79_000, 78_997, tracing.GasChangeCallOpCode),
					txev(78_997, 78_994, tracing.GasChangeCallOpCode),
					txev(78_994, 73_994, tracing.GasChangeCallOpCode),
					txev(73_994, 73_994, tracing.GasChangeCallOpCode),
					txev(73_994, 0, tracing.GasChangeCallLeftOverReturned),
					txev(73_994, 78_794, tracing.GasChangeTxRefunds),
					txev(78_794, 0, tracing.GasChangeTxLeftOverReturned),
				},
				true: {
					txev(0, 100_000, tracing.GasChangeTxInitialBalance),
					txev(100_000, 85_000, tracing.GasChangeTxIntrinsicGas),
					txev(0, 85_000, tracing.GasChangeCallInitialBalance),
					txev(85_000, 84_997, tracing.GasChangeCallOpCode),
					txev(84_997, 84_994, tracing.GasChangeCallOpCode),
					txev(84_994, 79_994, tracing.GasChangeCallOpCode),
					txev(79_994, 79_994, tracing.GasChangeCallOpCode),
					txev(79_994, 0, tracing.GasChangeCallLeftOverReturned),
					txev(79_994, 83_995, tracing.GasChangeTxRefunds),
					txev(83_995, 0, tracing.GasChangeTxLeftOverReturned),
				},
			},
		},
	}
	for _, fork := range []struct {
		name   string
		enable bool
	}{
		{"pre-Amsterdam", false},
		{"Amsterdam", true},
	} {
		for _, tc := range cases {
			t.Run(fork.name+"/"+tc.name, func(t *testing.T) {
				run := func(v2Only bool) []txGasEvent {
					events := []txGasEvent{}
					hooks := &tracing.Hooks{}
					if v2Only {
						hooks.OnGasChangeV2 = func(old, new tracing.Gas, reason tracing.GasChangeReason) {
							events = append(events, txGasEvent{old.Regular, new.Regular, old.State, new.State, reason})
						}
					} else {
						hooks.OnGasChange = func(old, new uint64, reason tracing.GasChangeReason) {
							events = append(events, txGasEvent{old: old, new: new, reason: reason})
						}
					}
					statedb, err := state.New(types.EmptyRootHash, state.NewDatabase(rawdb.NewMemoryDatabase()))
					if err != nil {
						t.Fatalf("failed to open state: %v", err)
					}
					header := &types.Header{
						Number:     common.Big1,
						Difficulty: new(big.Int),
						GasLimit:   8_000_000,
						BaseFee:    new(big.Int),
					}
					author := common.Address{}
					config := params.TestChainConfig.Clone()
					if fork.enable {
						config.AmsterdamBlock = big.NewInt(0)
					} else {
						config.AmsterdamBlock = nil
					}
					evm := vm.NewEVM(NewEVMBlockContext(header, nil, &author), statedb, nil, config, vm.Config{NoBaseFee: true, Tracer: hooks})
					if tc.prepare != nil {
						tc.prepare(statedb)
					}
					const gasLimit = 100_000
					msg := newTestMessage()
					msg.Data = tc.data
					msg.GasLimit = gasLimit
					if tc.to != nil {
						msg.To = tc.to
					}
					if _, err := ApplyMessage(evm, msg, new(GasPool).AddGas(gasLimit), common.Address{}); err != nil {
						t.Fatalf("apply: %v", err)
					}
					return events
				}
				checkTxGasEvents(t, "V1", run(false), tc.want[fork.enable])
				checkTxGasEvents(t, "V2", run(true), tc.want[fork.enable])
			})
		}
	}
}

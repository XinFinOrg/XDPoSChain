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

package vm

import (
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/tracing"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/holiman/uint256"
)

// gasEvent is one gas change as a tracer observes it: the balance before and
// after the change in both dimensions, plus the reason.
type gasEvent struct {
	old, new           uint64
	oldState, newState uint64
	reason             tracing.GasChangeReason
}

// ev builds an event whose state dimension is zero, the only value it can take
// on this tree: the state dimension is never written before Amsterdam.
func ev(old, new uint64, reason tracing.GasChangeReason) gasEvent {
	return gasEvent{old: old, new: new, reason: reason}
}

// evs builds an event with both dimensions spelled out.
func evs(old, new, oldState, newState uint64, reason tracing.GasChangeReason) gasEvent {
	return gasEvent{old: old, new: new, oldState: oldState, newState: newState, reason: reason}
}

// runGasEvents executes a call from a fresh EVM and returns the observed gas
// changes in order, from a tracer that registers exactly one hook variant.
func runGasEvents(t *testing.T, code map[common.Address][]byte, target common.Address, v2Only bool) []gasEvent {
	t.Helper()
	statedb := newCallGasTestStateDB(t)
	for addr, c := range code {
		statedb.SetCode(addr, c)
	}
	var events []gasEvent
	hooks := &tracing.Hooks{}
	if v2Only {
		hooks.OnGasChangeV2 = func(old, new tracing.Gas, reason tracing.GasChangeReason) {
			events = append(events, gasEvent{
				old: old.Regular, new: new.Regular,
				oldState: old.State, newState: new.State,
				reason: reason,
			})
		}
	} else {
		hooks.OnGasChange = func(old, new uint64, reason tracing.GasChangeReason) {
			events = append(events, ev(old, new, reason))
		}
	}
	evm := newCallGasTestEVM(t, statedb, params.Rules{IsEIP150: true, IsEIP158: true})
	evm.Config.Tracer = hooks
	if _, _, err := evm.Call(common.Address{}, target, nil, NewGasBudget(100_000), new(uint256.Int)); err != nil {
		t.Fatalf("call failed: %v", err)
	}
	return events
}

// checkGasEvents compares the events one by one, so a wrong balance, a
// reordered stream and a state dimension carrying a value all fail here.
func checkGasEvents(t *testing.T, what string, have, want []gasEvent) {
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

// TestGasTracingV2MatchesV1 pins the gas change stream a V2-only tracer and a
// V1-only tracer observe across a call and a nested call: the same ordered
// (old, new, reason) records, with no state dimension. The stream is spelled
// out verbatim, so a call site reporting wrong balances, a V2 event carrying
// state gas, and a mistake landing identically in both paths all fail.
func TestGasTracingV2MatchesV1(t *testing.T) {
	t.Run("call", func(t *testing.T) {
		callee := common.HexToAddress("0xc0de")
		code := map[common.Address][]byte{
			callee: {byte(PUSH1), 0x01, byte(POP), byte(STOP)},
		}
		// PUSH1 (3), POP (2), STOP (0), then the leftover returns to the caller.
		want := []gasEvent{
			ev(0, 100_000, tracing.GasChangeCallInitialBalance),
			ev(100_000, 99_997, tracing.GasChangeCallOpCode),
			ev(99_997, 99_995, tracing.GasChangeCallOpCode),
			ev(99_995, 99_995, tracing.GasChangeCallOpCode),
			ev(99_995, 0, tracing.GasChangeCallLeftOverReturned),
		}
		checkGasEvents(t, "V1", runGasEvents(t, code, callee, false), want)
		checkGasEvents(t, "V2", runGasEvents(t, code, callee, true), want)
	})
	t.Run("nested call", func(t *testing.T) {
		parent := common.HexToAddress("0xaaaa")
		child := common.HexToAddress("0xbbbb")
		callChild := []byte{byte(PUSH1), 0x00, byte(PUSH1), 0x00, byte(PUSH1), 0x00, byte(PUSH1), 0x00, byte(PUSH1), 0x00, byte(PUSH20)}
		callChild = append(callChild, child.Bytes()...)
		callChild = append(callChild, byte(GAS), byte(CALL), byte(POP), byte(STOP))
		code := map[common.Address][]byte{
			parent: callChild,
			child:  {byte(PUSH1), 0x01, byte(POP), byte(STOP)},
		}
		// Six PUSHes and GAS, then CALL: the cold child costs 2600 on top of
		// the 95859 it gets forwarded. The child hands its leftover back, the
		// caller is refunded, and the frame then closes at zero.
		want := []gasEvent{
			ev(0, 100_000, tracing.GasChangeCallInitialBalance),
			ev(100_000, 99_997, tracing.GasChangeCallOpCode),
			ev(99_997, 99_994, tracing.GasChangeCallOpCode),
			ev(99_994, 99_991, tracing.GasChangeCallOpCode),
			ev(99_991, 99_988, tracing.GasChangeCallOpCode),
			ev(99_988, 99_985, tracing.GasChangeCallOpCode),
			ev(99_985, 99_982, tracing.GasChangeCallOpCode),
			ev(99_982, 99_980, tracing.GasChangeCallOpCode),
			ev(99_980, 1_521, tracing.GasChangeCallOpCode),
			ev(0, 95_859, tracing.GasChangeCallInitialBalance),
			ev(95_859, 95_856, tracing.GasChangeCallOpCode),
			ev(95_856, 95_854, tracing.GasChangeCallOpCode),
			ev(95_854, 95_854, tracing.GasChangeCallOpCode),
			ev(95_854, 0, tracing.GasChangeCallLeftOverReturned),
			ev(1_521, 97_375, tracing.GasChangeCallLeftOverRefunded),
			ev(97_375, 97_373, tracing.GasChangeCallOpCode),
			ev(97_373, 97_373, tracing.GasChangeCallOpCode),
			ev(97_373, 0, tracing.GasChangeCallLeftOverReturned),
		}
		checkGasEvents(t, "V1", runGasEvents(t, code, parent, false), want)
		checkGasEvents(t, "V2", runGasEvents(t, code, parent, true), want)
	})
}

// runGasSite runs fn against a fresh EVM and returns the gas events a tracer
// that registers exactly one hook variant observed, in order.
func runGasSite(t *testing.T, v2Only bool, fn func(evm *EVM, statedb StateDB)) []gasEvent {
	t.Helper()
	var events []gasEvent
	hooks := &tracing.Hooks{}
	if v2Only {
		hooks.OnGasChangeV2 = func(old, new tracing.Gas, reason tracing.GasChangeReason) {
			events = append(events, gasEvent{
				old: old.Regular, new: new.Regular,
				oldState: old.State, newState: new.State,
				reason: reason,
			})
		}
	} else {
		hooks.OnGasChange = func(old, new uint64, reason tracing.GasChangeReason) {
			events = append(events, ev(old, new, reason))
		}
	}
	statedb := newCallGasTestStateDB(t)
	evm := newCallGasTestEVM(t, statedb, params.Rules{IsEIP150: true, IsEIP158: true})
	evm.Config.Tracer = hooks
	fn(evm, statedb)
	return events
}

// TestGasTracingV2CallSites pins the ordered gas stream of the call sites the
// successful-call test above does not reach: the four failing call entry
// points, the precompiled contract, the creation path and the contract-address
// collision. Each site is spelled out verbatim for both hook variants, so a
// site that stops dispatching to V2 or reports a wrong balance fails here.
func TestGasTracingV2CallSites(t *testing.T) {
	caller := common.HexToAddress("0xaaaa")
	callee := common.HexToAddress("0xcccc")
	initcode := []byte{byte(PUSH1), 0x00, byte(PUSH1), 0x00, byte(RETURN)}
	failing := []gasEvent{
		ev(0, 100_000, tracing.GasChangeCallInitialBalance),
		ev(100_000, 100_000, tracing.GasChangeCallOpCode),
		ev(100_000, 0, tracing.GasChangeCallFailedExecution),
	}
	cases := []struct {
		name string
		fn   func(evm *EVM, statedb StateDB)
		want []gasEvent
	}{
		{
			"Call", func(evm *EVM, statedb StateDB) {
				statedb.SetCode(callee, []byte{0xfe})
				evm.Call(caller, callee, nil, NewGasBudget(100_000), new(uint256.Int))
			}, failing,
		},
		{
			"CallCode", func(evm *EVM, statedb StateDB) {
				statedb.SetCode(callee, []byte{0xfe})
				evm.CallCode(caller, callee, nil, NewGasBudget(100_000), new(uint256.Int))
			}, failing,
		},
		{
			"DelegateCall", func(evm *EVM, statedb StateDB) {
				statedb.SetCode(callee, []byte{0xfe})
				evm.DelegateCall(caller, caller, callee, nil, NewGasBudget(100_000), new(uint256.Int))
			}, failing,
		},
		{
			"StaticCall", func(evm *EVM, statedb StateDB) {
				statedb.SetCode(callee, []byte{0xfe})
				evm.StaticCall(caller, callee, nil, NewGasBudget(100_000))
			}, failing,
		},
		{
			"precompiled contract", func(evm *EVM, statedb StateDB) {
				evm.Call(caller, common.BytesToAddress([]byte{0x01}), nil, NewGasBudget(100_000), new(uint256.Int))
			},
			[]gasEvent{
				ev(0, 100_000, tracing.GasChangeCallInitialBalance),
				ev(100_000, 97_000, tracing.GasChangeCallPrecompiledContract),
				ev(97_000, 0, tracing.GasChangeCallLeftOverReturned),
			},
		},
		{
			"creation", func(evm *EVM, statedb StateDB) {
				evm.Create(caller, initcode, NewGasBudget(100_000), new(uint256.Int))
			},
			[]gasEvent{
				ev(0, 100_000, tracing.GasChangeCallInitialBalance),
				ev(100_000, 99_997, tracing.GasChangeCallOpCode),
				ev(99_997, 99_994, tracing.GasChangeCallOpCode),
				ev(99_994, 99_994, tracing.GasChangeCallOpCode),
				ev(99_994, 99_994, tracing.GasChangeCallCodeStorage),
				ev(99_994, 0, tracing.GasChangeCallLeftOverReturned),
			},
		},
		{
			"address collision", func(evm *EVM, statedb StateDB) {
				addr := crypto.CreateAddress(caller, statedb.GetNonce(caller))
				statedb.SetNonce(addr, 1, tracing.NonceChangeNewContract)
				evm.Create(caller, initcode, NewGasBudget(100_000), new(uint256.Int))
			},
			[]gasEvent{
				ev(0, 100_000, tracing.GasChangeCallInitialBalance),
				ev(100_000, 0, tracing.GasChangeCallFailedExecution),
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			checkGasEvents(t, "V1", runGasSite(t, false, tc.fn), tc.want)
			checkGasEvents(t, "V2", runGasSite(t, true, tc.fn), tc.want)
		})
	}
}

// zeroState copies a stream with the state dimension cleared, the view a V1
// hook gets from the dispatcher's fallback.
func zeroState(events []gasEvent) []gasEvent {
	out := make([]gasEvent, len(events))
	for i, e := range events {
		out[i] = gasEvent{old: e.old, new: e.new, reason: e.reason}
	}
	return out
}

// TestGasTracingV2CarriesStateDimension pins that a budget handed to an
// exported entry point keeps its state dimension through the frame begin/end
// events: the initial balance and a returned leftover carry the full vector,
// and a state-only leftover still produces its event.
func TestGasTracingV2CarriesStateDimension(t *testing.T) {
	caller := common.HexToAddress("0xaaaa")
	callee := common.HexToAddress("0xcccc")
	budget := GasBudget{RegularGas: 100_000, StateGas: 7}
	initcode := []byte{byte(PUSH1), 0x00, byte(PUSH1), 0x00, byte(RETURN)}
	failing := []gasEvent{
		evs(0, 100_000, 0, 7, tracing.GasChangeCallInitialBalance),
		evs(100_000, 100_000, 7, 7, tracing.GasChangeCallOpCode),
		evs(100_000, 0, 7, 0, tracing.GasChangeCallFailedExecution),
	}
	cases := []struct {
		name string
		fn   func(evm *EVM, statedb StateDB)
		want []gasEvent
	}{
		{
			"Call", func(evm *EVM, statedb StateDB) {
				statedb.SetCode(callee, []byte{byte(PUSH1), 0x01, byte(POP), byte(STOP)})
				evm.Call(caller, callee, nil, budget, new(uint256.Int))
			},
			[]gasEvent{
				evs(0, 100_000, 0, 7, tracing.GasChangeCallInitialBalance),
				evs(100_000, 99_997, 7, 7, tracing.GasChangeCallOpCode),
				evs(99_997, 99_995, 7, 7, tracing.GasChangeCallOpCode),
				evs(99_995, 99_995, 7, 7, tracing.GasChangeCallOpCode),
				evs(99_995, 0, 7, 0, tracing.GasChangeCallLeftOverReturned),
			},
		},
		{
			"CallCode", func(evm *EVM, statedb StateDB) {
				statedb.SetCode(callee, []byte{0xfe})
				evm.CallCode(caller, callee, nil, budget, new(uint256.Int))
			}, failing,
		},
		{
			"DelegateCall", func(evm *EVM, statedb StateDB) {
				statedb.SetCode(callee, []byte{0xfe})
				evm.DelegateCall(caller, caller, callee, nil, budget, new(uint256.Int))
			}, failing,
		},
		{
			"StaticCall", func(evm *EVM, statedb StateDB) {
				statedb.SetCode(callee, []byte{0xfe})
				evm.StaticCall(caller, callee, nil, budget)
			}, failing,
		},
		{
			"creation", func(evm *EVM, statedb StateDB) {
				evm.Create(caller, initcode, budget, new(uint256.Int))
			},
			[]gasEvent{
				evs(0, 100_000, 0, 7, tracing.GasChangeCallInitialBalance),
				evs(100_000, 99_997, 7, 7, tracing.GasChangeCallOpCode),
				evs(99_997, 99_994, 7, 7, tracing.GasChangeCallOpCode),
				evs(99_994, 99_994, 7, 7, tracing.GasChangeCallOpCode),
				evs(99_994, 99_994, 7, 7, tracing.GasChangeCallCodeStorage),
				evs(99_994, 0, 7, 0, tracing.GasChangeCallLeftOverReturned),
			},
		},
		{
			"state-only leftover", func(evm *EVM, statedb StateDB) {
				evm.Call(caller, common.HexToAddress("0xdead"), nil, GasBudget{StateGas: 7}, new(uint256.Int))
			},
			[]gasEvent{
				evs(0, 0, 0, 7, tracing.GasChangeCallInitialBalance),
				evs(0, 0, 7, 0, tracing.GasChangeCallLeftOverReturned),
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			checkGasEvents(t, "V1", runGasSite(t, false, tc.fn), zeroState(tc.want))
			checkGasEvents(t, "V2", runGasSite(t, true, tc.fn), tc.want)
		})
	}
}

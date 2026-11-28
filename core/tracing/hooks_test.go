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

package tracing

import "testing"

func TestHooksHasGasHook(t *testing.T) {
	var nilHooks *Hooks
	if nilHooks.HasGasHook() {
		t.Error("nil hooks reported a gas hook")
	}
	if (&Hooks{}).HasGasHook() {
		t.Error("empty hooks reported a gas hook")
	}
	if !(&Hooks{OnGasChange: func(uint64, uint64, GasChangeReason) {}}).HasGasHook() {
		t.Error("V1 hook not reported")
	}
	if !(&Hooks{OnGasChangeV2: func(Gas, Gas, GasChangeReason) {}}).HasGasHook() {
		t.Error("V2 hook not reported")
	}
}

func TestHooksEmitGasChange(t *testing.T) {
	var (
		v1Calls, v2Calls int
		v1Old, v1New     uint64
		v2Old, v2New     Gas
	)
	v1 := func(old, new uint64, _ GasChangeReason) {
		v1Calls++
		v1Old, v1New = old, new
	}
	v2 := func(old, new Gas, _ GasChangeReason) {
		v2Calls++
		v2Old, v2New = old, new
	}
	old, new := Gas{Regular: 10, State: 1}, Gas{Regular: 5, State: 2}

	both := &Hooks{OnGasChange: v1, OnGasChangeV2: v2}
	both.EmitGasChange(old, new, GasChangeCallOpCode)
	if v2Calls != 1 || v1Calls != 0 {
		t.Fatalf("both hooks: V2 calls %d, V1 calls %d", v2Calls, v1Calls)
	}
	if v2Old != old || v2New != new {
		t.Errorf("V2 vectors: have %+v -> %+v, want %+v -> %+v", v2Old, v2New, old, new)
	}

	v1Calls, v1Old, v1New = 0, 0, 0
	(&Hooks{OnGasChange: v1}).EmitGasChange(old, new, GasChangeTxRefunds)
	if v1Calls != 1 || v1Old != 10 || v1New != 5 {
		t.Errorf("V1 fallback: calls %d, have %d -> %d, want 10 -> 5", v1Calls, v1Old, v1New)
	}

	v1Calls, v2Calls = 0, 0
	both.EmitGasChange(old, new, GasChangeIgnored)
	(&Hooks{}).EmitGasChange(old, new, GasChangeCallOpCode)
	var nilHooks *Hooks
	nilHooks.EmitGasChange(old, new, GasChangeCallOpCode)
	if v1Calls != 0 || v2Calls != 0 {
		t.Errorf("ignored or unregistered hook invoked: V1 %d, V2 %d", v1Calls, v2Calls)
	}
}

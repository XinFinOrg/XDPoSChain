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
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/holiman/uint256"
)

func TestGasCostsSumAndString(t *testing.T) {
	costs := GasCosts{RegularGas: 7, StateGas: 5}
	if got := costs.Sum(); got != 12 {
		t.Errorf("Sum: have %d, want 12", got)
	}
	if got := costs.String(); got != "<7,5>" {
		t.Errorf("String: have %q, want %q", got, "<7,5>")
	}
	var zero GasCosts
	if got := zero.Sum(); got != 0 {
		t.Errorf("zero Sum: have %d, want 0", got)
	}
	if got := zero.String(); got != "<0,0>" {
		t.Errorf("zero String: have %q, want %q", got, "<0,0>")
	}
}

func TestGasBudget(t *testing.T) {
	budget := NewGasBudget(100)
	if budget.RegularGas != 100 || budget.StateGas != 0 {
		t.Fatalf("NewGasBudget: have %v, want <100,0>", budget)
	}
	if !budget.CanAfford(GasCosts{RegularGas: 100}) {
		t.Error("CanAfford: exactly covered cost rejected")
	}
	if budget.CanAfford(GasCosts{RegularGas: 101}) {
		t.Error("CanAfford: uncovered cost accepted")
	}
	if prior, ok := budget.Charge(GasCosts{RegularGas: 100}); !ok || prior.RegularGas != 100 || budget.RegularGas != 0 {
		t.Errorf("Charge exact: prior %v, ok %v, left %d", prior, ok, budget.RegularGas)
	}

	insufficient := NewGasBudget(99)
	if prior, ok := insufficient.Charge(GasCosts{RegularGas: 100}); ok || prior.RegularGas != 99 || insufficient.RegularGas != 99 {
		t.Errorf("Charge short: prior %v, ok %v, left %d", prior, ok, insufficient.RegularGas)
	}
	withState := GasBudget{RegularGas: 1, StateGas: 1000}
	if _, ok := withState.Charge(GasCosts{RegularGas: 2}); ok {
		t.Error("Charge: state gas covered a regular shortfall")
	}

	refunding := NewGasBudget(10)
	if prior, changed := refunding.Refund(GasBudget{}); changed || prior.RegularGas != 10 || refunding.RegularGas != 10 {
		t.Errorf("Refund zero: prior %v, changed %v, left %d", prior, changed, refunding.RegularGas)
	}
	if prior, changed := refunding.Refund(NewGasBudget(5)); !changed || prior.RegularGas != 10 || refunding.RegularGas != 15 {
		t.Errorf("Refund: prior %v, changed %v, left %d", prior, changed, refunding.RegularGas)
	}

	start := GasBudget{RegularGas: 100, StateGas: 50}
	end := GasBudget{RegularGas: 70, StateGas: 999}
	if used := end.Used(start); used != 30 {
		t.Errorf("Used: have %d, want 30", used)
	}

	exhausted := GasBudget{RegularGas: 7, StateGas: 5}
	exhausted.Exhaust()
	if exhausted.RegularGas != 0 || exhausted.StateGas != 0 {
		t.Errorf("Exhaust: have %v, want <0,0>", exhausted)
	}

	src := GasBudget{RegularGas: 7, StateGas: 5}
	cp := src.Copy()
	src.RegularGas = 1
	if cp.RegularGas != 7 || cp.StateGas != 5 {
		t.Errorf("Copy: have %v, want <7,5>", cp)
	}
	if got := (GasBudget{RegularGas: 7, StateGas: 5}).String(); got != "<7,5>" {
		t.Errorf("String: have %q, want %q", got, "<7,5>")
	}

	for _, tc := range []struct {
		name   string
		budget GasBudget
		want   bool
	}{
		{"zero", GasBudget{}, true},
		{"regular only", GasBudget{RegularGas: 3}, false},
		{"state only", GasBudget{StateGas: 5}, false},
		{"both", GasBudget{RegularGas: 3, StateGas: 5}, false},
	} {
		if got := tc.budget.IsZero(); got != tc.want {
			t.Errorf("IsZero %s: have %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestGasBudgetAsTracing(t *testing.T) {
	budget := GasBudget{RegularGas: 7, StateGas: 5}
	if got := budget.AsTracing(); got.Regular != 7 || got.State != 5 {
		t.Errorf("AsTracing: have %+v, want Regular 7, State 5", got)
	}
	var empty GasBudget
	if got := empty.AsTracing(); got.Regular != 0 || got.State != 0 {
		t.Errorf("zero AsTracing: have %+v, want empty", got)
	}
}

func TestGasCostsStateGasIsZero(t *testing.T) {
	target := common.HexToAddress("0xaa")
	rules := params.Rules{IsEIP150: true, IsEIP158: true}
	tests := []struct {
		name string
		fn   gasFunc
	}{
		{"memory copier", gasMcopy},
		{"sstore legacy", gasSStore},
		{"sstore eip-2200", gasSStoreEIP2200},
		{"sstore eip-2929", gasSStoreEIP2929},
		{"sload eip-2929", gasSLoadEIP2929},
		{"extcodecopy eip-2929", gasExtCodeCopyEIP2929},
		{"account check eip-2929", gasEip2929AccountCheck},
		{"log", makeGasLog(0)},
		{"keccak256", gasKeccak256},
		{"pure memory", pureMemoryGascost},
		{"create2", gasCreate2},
		{"create eip-3860", gasCreateEip3860},
		{"create2 eip-3860", gasCreate2Eip3860},
		{"exp frontier", gasExpFrontier},
		{"exp eip-158", gasExpEIP158},
		{"call intrinsic", gasCallIntrinsic},
		{"callcode intrinsic", gasCallCodeIntrinsic},
		{"delegatecall intrinsic", gasDelegateCallIntrinsic},
		{"staticcall intrinsic", gasStaticCallIntrinsic},
		{"selfdestruct", gasSelfdestruct},
		{"selfdestruct eip-2929", gasSelfdestructEIP2929},
		{"call variant", gasCall},
		{"call variant eip-2929", gasCallEIP2929},
		{"call variant eip-7702", gasCallEIP7702},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			statedb := newCallGasTestStateDB(t)
			evm := newCallGasTestEVM(t, statedb, rules)
			contract := NewContract(common.Address{}, common.Address{}, new(uint256.Int), NewGasBudget(100000), nil)
			stack := callGasTestStack(0, target, new(uint256.Int))
			defer returnStack(stack)

			costs, err := tt.fn(evm, contract, stack, NewMemory(), 0)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if costs.StateGas != 0 {
				t.Errorf("StateGas: have %d, want 0", costs.StateGas)
			}
			if costs.Sum() != costs.RegularGas {
				t.Errorf("Sum: have %d, want RegularGas %d", costs.Sum(), costs.RegularGas)
			}
		})
	}
}

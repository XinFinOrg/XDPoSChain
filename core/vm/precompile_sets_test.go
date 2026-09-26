// Copyright 2025 The go-ethereum Authors
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
)

// TestPrecompileSetsByFork pins which precompiles each fork bucket exposes.
//
// The vector tests in contracts_test.go drive allPrecompiles directly, so they
// never consult activePrecompiledContracts or ActivePrecompiles: a precompile
// dropped from a production bucket, or a fork branch added to one switch and
// forgotten in the other, would leave every one of them green.
func TestPrecompileSetsByFork(t *testing.T) {
	blsContracts := []struct {
		addr common.Address
		name string
	}{
		{common.BytesToAddress([]byte{0x0b}), "BLS12_G1ADD"},
		{common.BytesToAddress([]byte{0x0c}), "BLS12_G1MSM"},
		{common.BytesToAddress([]byte{0x0d}), "BLS12_G2ADD"},
		{common.BytesToAddress([]byte{0x0e}), "BLS12_G2MSM"},
		{common.BytesToAddress([]byte{0x0f}), "BLS12_PAIRING_CHECK"},
		{common.BytesToAddress([]byte{0x10}), "BLS12_MAP_FP_TO_G1"},
		{common.BytesToAddress([]byte{0x11}), "BLS12_MAP_FP2_TO_G2"},
	}
	classic := []common.Address{
		common.BytesToAddress([]byte{0x01}), common.BytesToAddress([]byte{0x02}),
		common.BytesToAddress([]byte{0x03}), common.BytesToAddress([]byte{0x04}),
		common.BytesToAddress([]byte{0x05}), common.BytesToAddress([]byte{0x06}),
		common.BytesToAddress([]byte{0x07}), common.BytesToAddress([]byte{0x08}),
		common.BytesToAddress([]byte{0x09}),
	}
	// The XDCx precompiles only ever lived in the Byzantium and Istanbul
	// buckets. Later buckets miss them too, but that is a pre-existing gap and
	// not something this test may pin down: asserting presence would fail, and
	// asserting absence would freeze the gap in place as the expectation.
	xdcxContracts := []common.Address{
		common.BytesToAddress([]byte{0x1e}), common.BytesToAddress([]byte{0x28}),
		common.BytesToAddress([]byte{0x29}), common.BytesToAddress([]byte{0x2a}),
	}
	tests := []struct {
		name      string
		rules     params.Rules
		classic   int  // how many of 0x01-0x09 the bucket must hold
		blsActive bool // whether the EIP-2537 precompiles must be reachable
		kzgStub   bool // whether 0x0a must hold the failing point-evaluation stub
		xdcx      int  // how many XDCx precompiles the bucket must hold, 0 = don't check
	}{
		{name: "homestead", rules: params.Rules{}, classic: 4, kzgStub: false},
		{name: "byzantium", rules: params.Rules{IsByzantium: true}, classic: 8, kzgStub: false, xdcx: 4},
		{name: "istanbul", rules: params.Rules{IsIstanbul: true}, classic: 9, kzgStub: false, xdcx: 4},
		{name: "xdcv2", rules: params.Rules{IsXDCxDisable: true}, classic: 9, kzgStub: false},
		{name: "eip1559", rules: params.Rules{IsEIP1559: true}, classic: 9, kzgStub: false},
		{name: "prague", rules: params.Rules{IsPrague: true}, classic: 9, blsActive: true, kzgStub: true},
		{name: "osaka", rules: params.Rules{IsOsaka: true}, classic: 9, blsActive: true, kzgStub: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			set := activePrecompiledContracts(test.rules)
			list := ActivePrecompiles(test.rules)

			// Both switches in contracts.go have to agree, so the address list
			// is exactly the key set of the active bucket.
			if len(list) != len(set) {
				t.Fatalf("ActivePrecompiles returned %d addresses, active set holds %d contracts", len(list), len(set))
			}
			listed := make(map[common.Address]bool, len(list))
			for _, addr := range list {
				if _, ok := set[addr]; !ok {
					t.Errorf("address %v listed by ActivePrecompiles but absent from the active set", addr)
				}
				if listed[addr] {
					t.Errorf("address %v listed twice by ActivePrecompiles", addr)
				}
				listed[addr] = true
			}
			// Prague and Osaka only add to the EIP-1559 bucket, they must never
			// rebuild it: losing one of 0x01-0x09 would silently disable it.
			var found int
			for _, addr := range classic {
				if _, ok := set[addr]; ok {
					found++
				}
			}
			if found != test.classic {
				t.Errorf("active set holds %d of 0x01-0x09, want %d", found, test.classic)
			}
			// 0x0a is held by the always-failing stub in the two buckets that
			// schedule Prague; every earlier bucket must leave the address alone,
			// so a stub leaking downwards would change what past blocks mean.
			stub, ok := set[common.BytesToAddress([]byte{0x0a})]
			if ok != test.kzgStub {
				t.Errorf("0x0a stub: present = %v, want %v", ok, test.kzgStub)
			}
			if ok {
				if name := stub.Name(); name != "KZG_POINT_EVALUATION" {
					t.Errorf("0x0a: name = %q, want %q", name, "KZG_POINT_EVALUATION")
				}
				if !listed[common.BytesToAddress([]byte{0x0a})] {
					t.Error("0x0a stub absent from ActivePrecompiles")
				}
			}
			if test.xdcx > 0 {
				var xdcxFound int
				for _, addr := range xdcxContracts {
					if _, ok := set[addr]; ok {
						xdcxFound++
					}
				}
				if xdcxFound != test.xdcx {
					t.Errorf("active set holds %d XDCx precompiles, want %d", xdcxFound, test.xdcx)
				}
			}
			for _, contract := range blsContracts {
				pc, ok := set[contract.addr]
				if ok != test.blsActive {
					t.Fatalf("precompile %s at %v: active = %v, want %v", contract.name, contract.addr, ok, test.blsActive)
				}
				if !ok {
					continue
				}
				if name := pc.Name(); name != contract.name {
					t.Errorf("precompile at %v: name = %q, want %q", contract.addr, name, contract.name)
				}
				if !listed[contract.addr] {
					t.Errorf("precompile %s at %v absent from ActivePrecompiles", contract.name, contract.addr)
				}
			}
		})
	}
}

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
	"math/big"
	"slices"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/holiman/uint256"
)

// TestKZGPointEvaluationStubSet pins that the always-failing 0x0a stub is
// registered exactly in the buckets that are not activated yet, and is absent
// from every bucket whose rules are already live on mainnet. Adding it to an
// activated bucket would rewrite the semantics of all blocks since that fork.
func TestKZGPointEvaluationStubSet(t *testing.T) {
	// The fork flags that are set on the live networks: mainnet and Apothem
	// run under Cancun, which implies EIP1559 and every earlier fork.
	cancunRules := params.Rules{
		IsBerlin:   true,
		IsLondon:   true,
		IsShanghai: true,
		IsMerge:    true,
		IsCancun:   true,
		IsEIP1559:  true,
	}
	pragueRules := cancunRules
	pragueRules.IsPrague = true
	osakaRules := pragueRules
	osakaRules.IsOsaka = true

	var (
		stubAddr = common.BytesToAddress([]byte{0x0a})
		present  = []struct {
			name  string
			rules params.Rules
		}{
			{"prague", pragueRules},
			{"osaka", osakaRules},
		}
		absent = []struct {
			name  string
			rules params.Rules
		}{
			{"homestead", params.Rules{}},
			{"byzantium", params.Rules{IsByzantium: true}},
			{"istanbul", params.Rules{IsIstanbul: true}},
			{"xdcv2", params.Rules{IsXDCxDisable: true}},
			{"eip1559", params.Rules{IsEIP1559: true}},
			// The networks that are live today run under Cancun rules.
			{"cancun", cancunRules},
		}
	)
	for _, test := range present {
		t.Run("present/"+test.name, func(t *testing.T) {
			set := activePrecompiledContracts(test.rules)
			p, ok := set[stubAddr]
			if !ok {
				t.Fatalf("0x0a missing from the %s bucket", test.name)
			}
			if name := p.Name(); name != "KZG_POINT_EVALUATION" {
				t.Fatalf("0x0a wired to %q, want KZG_POINT_EVALUATION", name)
			}
			if got := p.RequiredGas(nil); got != params.BlobTxPointEvaluationPrecompileGas {
				t.Fatalf("0x0a priced at %d gas, want %d", got, params.BlobTxPointEvaluationPrecompileGas)
			}
			list := ActivePrecompiles(test.rules)
			if !slices.Contains(list, stubAddr) {
				t.Fatalf("0x0a missing from ActivePrecompiles(%s)", test.name)
			}
			// Both switches have to agree on the address list.
			if len(list) != len(set) {
				t.Fatalf("ActivePrecompiles(%s) returned %d addresses, bucket holds %d contracts", test.name, len(list), len(set))
			}
		})
	}
	for _, test := range absent {
		t.Run("absent/"+test.name, func(t *testing.T) {
			if _, ok := activePrecompiledContracts(test.rules)[stubAddr]; ok {
				t.Fatalf("0x0a must NOT be registered in the already-activated %s bucket", test.name)
			}
			if slices.Contains(ActivePrecompiles(test.rules), stubAddr) {
				t.Fatalf("0x0a must NOT be listed by ActivePrecompiles(%s)", test.name)
			}
		})
	}
}

// TestKZGPointEvaluationStubFails checks the observable semantics: a call to
// 0x0a must fail and burn all the gas handed to the frame. Burning the gas is
// implemented by evm.Call, not by RunPrecompiledContract, so the assertion has
// to go through a real EVM.
func TestKZGPointEvaluationStubFails(t *testing.T) {
	var (
		stubAddr = common.BytesToAddress([]byte{0x0a})
		caller   = common.HexToAddress("0x000000000000000000000000000000000000dead")
		zero     = uint256.NewInt(0)
	)
	// AllEthashProtocolChanges activates every fork including Osaka, so the
	// Osaka block has to be cleared to pin the rules to Prague.
	chainConfig := *params.AllEthashProtocolChanges
	chainConfig.PragueBlock = big.NewInt(0)
	chainConfig.OsakaBlock = nil

	statedb, err := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	if err != nil {
		t.Fatalf("failed to create state: %v", err)
	}
	evm := NewEVM(BlockContext{
		CanTransfer: func(StateDB, common.Address, *uint256.Int) bool { return true },
		Transfer:    func(StateDB, common.Address, common.Address, *uint256.Int) {},
		BlockNumber: big.NewInt(1),
		Time:        1,
		Random:      &common.Hash{},
	}, statedb, nil, &chainConfig, Config{})

	if !evm.chainRules.IsPrague || evm.chainRules.IsOsaka {
		t.Fatalf("expected prague rules, got %+v", evm.chainRules)
	}
	const gas uint64 = 100_000
	_, leftOverGas, err := evm.Call(caller, stubAddr, nil, gas, zero)
	if err == nil {
		t.Fatalf("expected the 0x0a call to fail, got success with %d gas left", leftOverGas)
	}
	if leftOverGas != 0 {
		t.Fatalf("expected all gas to be consumed, leftOverGas = %d", leftOverGas)
	}
}

// TestPraguePrecompilesExtendActivatedSet pins that the Prague and Osaka
// buckets still carry every entry of the bucket the activated networks use.
// Both buckets are written out by hand, so a dropped address or a mistyped
// implementation would otherwise go unnoticed.
func TestPraguePrecompilesExtendActivatedSet(t *testing.T) {
	activated := PrecompiledContractsEIP1559
	stubAddr := common.BytesToAddress([]byte{0x0a})
	modexpAddr := common.BytesToAddress([]byte{0x5})

	for _, test := range []struct {
		name string
		set  PrecompiledContracts
	}{
		{"prague", PrecompiledContractsPrague},
		{"osaka", PrecompiledContractsOsaka},
	} {
		t.Run(test.name, func(t *testing.T) {
			for addr, base := range activated {
				got, ok := test.set[addr]
				if !ok {
					t.Fatalf("%s dropped %v, which the activated bucket provides", test.name, addr)
				}
				if got.Name() != base.Name() {
					t.Fatalf("%s wired %v to %q, want %q", test.name, addr, got.Name(), base.Name())
				}
			}
			if _, ok := test.set[stubAddr]; !ok {
				t.Fatalf("%s does not register the 0x0a stub", test.name)
			}
		})
	}
	// The modexp variant is the one entry whose behaviour changes between
	// forks while its name stays the same, so pin the flags explicitly:
	// EIP-2565 applies from Berlin on, EIP-7823 and EIP-7883 only from Osaka.
	if m, ok := PrecompiledContractsPrague[modexpAddr].(*bigModExp); !ok || !m.eip2565 || m.eip7823 || m.eip7883 {
		t.Fatalf("prague modexp flags are wrong: %v", PrecompiledContractsPrague[modexpAddr])
	}
	if m, ok := PrecompiledContractsOsaka[modexpAddr].(*bigModExp); !ok || !m.eip2565 || !m.eip7823 || !m.eip7883 {
		t.Fatalf("osaka modexp flags are wrong: %v", PrecompiledContractsOsaka[modexpAddr])
	}
}

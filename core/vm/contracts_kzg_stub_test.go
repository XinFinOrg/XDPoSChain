package vm

import (
	"bytes"
	"errors"
	"math/big"
	"slices"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/holiman/uint256"
)

// The addresses these tests key on, declared once so that no case can quietly
// probe a different address than the one the bucket holds.
var (
	kzgPointEvalAddr = common.BytesToAddress([]byte{0x0a})
	modexpAddr       = common.BytesToAddress([]byte{0x05})
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
		present = []struct {
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
			p, ok := set[kzgPointEvalAddr]
			if !ok {
				t.Fatalf("0x0a missing from the %s bucket", test.name)
			}
			if name := p.Name(); name != "KZG_POINT_EVALUATION" {
				t.Fatalf("0x0a wired to %q, want KZG_POINT_EVALUATION", name)
			}
			// The upstream point evaluation price is 50000 (geth
			// params/protocol_params.go, BlobTxPointEvaluationPrecompileGas). Pin the
			// literal: comparing against the fork's own constant would still hold for
			// any value that constant is changed to.
			if got, want := p.RequiredGas(nil), uint64(50000); got != want {
				t.Fatalf("0x0a priced at %d gas, want the upstream %d", got, want)
			}
			// Prague and Osaka hold the same addresses, so neither membership nor
			// price can tell the two rule sets apart. Go through the selection with
			// the one entry whose behaviour differs per fork: EIP-7823 and EIP-7883
			// apply from Osaka on. Without this, pointing the Prague rules at the
			// Osaka bucket would still pass every assertion in this file.
			m, ok := set[modexpAddr].(*bigModExp)
			if !ok {
				t.Fatalf("the %s bucket has no modexp at 0x05", test.name)
			}
			if wantOsaka := test.name == "osaka"; m.eip7823 != wantOsaka || m.eip7883 != wantOsaka {
				t.Fatalf("the %s rules selected the modexp with eip7823=%v eip7883=%v, want both %v",
					test.name, m.eip7823, m.eip7883, wantOsaka)
			}
			list := ActivePrecompiles(test.rules)
			if !slices.Contains(list, kzgPointEvalAddr) {
				t.Fatalf("0x0a missing from ActivePrecompiles(%s)", test.name)
			}
			requireSameAddresses(t, test.name, test.rules)
		})
	}
	for _, test := range absent {
		t.Run("absent/"+test.name, func(t *testing.T) {
			requireSameAddresses(t, test.name, test.rules)
			if _, ok := activePrecompiledContracts(test.rules)[kzgPointEvalAddr]; ok {
				t.Fatalf("0x0a must NOT be registered in the already-activated %s bucket", test.name)
			}
			if slices.Contains(ActivePrecompiles(test.rules), kzgPointEvalAddr) {
				t.Fatalf("0x0a must NOT be listed by ActivePrecompiles(%s)", test.name)
			}
		})
	}
}

// requireSameAddresses pins that ActivePrecompiles and activePrecompiledContracts
// select the same addresses. Both are hand-written switches, and comparing only
// the lengths cannot tell two equal-length buckets apart: Prague and Osaka hold
// the same number of addresses, so swapping the two returns went unnoticed.
// Equal lengths plus a duplicate-free list whose every entry is in the bucket
// means the two sets are identical.
func requireSameAddresses(t *testing.T, fork string, rules params.Rules) {
	t.Helper()
	set := activePrecompiledContracts(rules)
	list := ActivePrecompiles(rules)
	if len(list) != len(set) {
		t.Fatalf("ActivePrecompiles(%s) returned %d addresses, bucket holds %d", fork, len(list), len(set))
	}
	sorted := slices.Clone(list)
	slices.SortFunc(sorted, common.Address.Cmp)
	for i, addr := range sorted {
		if _, ok := set[addr]; !ok {
			t.Fatalf("ActivePrecompiles(%s) lists %x, which the bucket does not hold", fork, addr.Bytes())
		}
		if i > 0 && addr == sorted[i-1] {
			t.Fatalf("ActivePrecompiles(%s) lists %x twice", fork, addr.Bytes())
		}
	}
}

// TestKZGPointEvaluationStubFails checks the observable semantics: a call to
// 0x0a must fail and burn all the gas handed to the frame. Burning the gas is
// implemented by evm.Call, not by RunPrecompiledContract, so the assertion has
// to go through a real EVM.
func TestKZGPointEvaluationStubFails(t *testing.T) {
	var (
		caller = common.HexToAddress("0x000000000000000000000000000000000000dead")
		zero   = uint256.NewInt(0)
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
	// The stub rejects every input, including the 192-byte shape a real point
	// evaluation would accept, so the cases differ only in length and content.
	// The frame is funded with twice the price the stub asks for, so Run is
	// reached in every case and a plain out-of-gas cannot make one of them pass.
	for _, test := range []struct {
		name  string
		input []byte
	}{
		{"nil", nil},
		{"one byte", []byte{0x00}},
		{"191 bytes", make([]byte, 191)},
		{"192 bytes", append(bytes.Repeat([]byte{0x42}, 96), bytes.Repeat([]byte{0x43}, 96)...)},
		{"200 bytes", make([]byte, 200)},
	} {
		t.Run("input/"+test.name, func(t *testing.T) {
			const gas uint64 = 100_000
			_, leftOverGas, err := evm.Call(caller, kzgPointEvalAddr, test.input, gas, zero)
			if !errors.Is(err, errKZGUnsupported) {
				t.Fatalf("0x0a call with %s returned %v, want %v", test.name, err, errKZGUnsupported)
			}
			if leftOverGas != 0 {
				t.Fatalf("expected all gas to be consumed, leftOverGas = %d", leftOverGas)
			}
		})
	}
}

// TestPraguePrecompilesExtendActivatedSet pins that the Prague and Osaka
// buckets still carry every entry of the bucket the activated networks use.
// Both buckets are written out by hand, so a dropped address or a mistyped
// implementation would otherwise go unnoticed.
func TestPraguePrecompilesExtendActivatedSet(t *testing.T) {
	activated := PrecompiledContractsEIP1559

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
			if _, ok := test.set[kzgPointEvalAddr]; !ok {
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

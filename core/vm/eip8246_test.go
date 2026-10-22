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
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/tracing"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/holiman/uint256"
)

// TestSelfdestruct6780EventForkGate pins the balance-change events emitted by a
// SELFDESTRUCT with the executing account or a distinct address as beneficiary,
// across the EIP-8246 fork boundary.
//
// The fork gate in opSelfdestruct6780 only shapes the hook layer: the final
// state is decided by the preserveBalance flag handed to the state layer, so a
// state-level test cannot tell whether the gate is still there. Pre-Amsterdam
// the instruction has to keep the historical transfer pair (a decrease and an
// increase of the full balance on top of the destruct decrease), exactly as
// the pre-EIP-8246 code did with its unconditional SubBalance/AddBalance.
// Amsterdam drops the pair and leaves the balance in place.
//
// The to-other rows pin the other half of the gate: a distinct beneficiary keeps
// the transfer pair on both sides of the fork, and only the self-beneficiary
// part is dropped. The extra decrease of pre-amsterdam/new-contract-to-other is
// the 0 -> 0 destruct decrease that hookedStateDB.SelfDestruct6780 raises after
// the instruction already moved the balance to the beneficiary; the
// self-beneficiary rows pin the same quirk.
func TestSelfdestruct6780EventForkGate(t *testing.T) {
	var (
		addr           = common.HexToAddress("0x8246824682468246824682468246824682468246")
		beneficiary    = common.HexToAddress("0xbe")
		code           = []byte{0x30, 0xff}       // ADDRESS; SELFDESTRUCT
		toOtherCode    = []byte{0x60, 0xbe, 0xff} // PUSH1 0xbe; SELFDESTRUCT
		initialBalance = int64(1000)
	)
	run := func(t *testing.T, amsterdam, newContract, toOther bool) (decrease, increase, burn int, balance, beneficiaryBalance int64, exists bool) {
		t.Helper()

		config := *params.AllEthashProtocolChanges
		if !amsterdam {
			config.AmsterdamBlock = nil
		}
		statedb, err := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
		if err != nil {
			t.Fatalf("failed to create state: %v", err)
		}
		statedb.CreateAccount(addr)
		if newContract {
			statedb.CreateContract(addr)
		} else {
			statedb.SetNonce(addr, 1, tracing.NonceChangeUnspecified)
		}
		evmCode := code
		if toOther {
			evmCode = toOtherCode
		}
		statedb.SetCode(addr, evmCode)
		statedb.AddBalance(addr, big.NewInt(initialBalance), tracing.BalanceChangeUnspecified)

		hooked := state.NewHookedState(statedb, &tracing.Hooks{
			OnBalanceChange: func(_ common.Address, _, _ *big.Int, reason tracing.BalanceChangeReason) {
				switch reason {
				case tracing.BalanceDecreaseSelfdestruct:
					decrease++
				case tracing.BalanceIncreaseSelfdestruct:
					increase++
				case tracing.BalanceDecreaseSelfdestructBurn:
					burn++
				}
			},
		})
		evm := NewEVM(BlockContext{
			BlockNumber: big.NewInt(0),
			CanTransfer: func(db StateDB, addr common.Address, amount *uint256.Int) bool {
				return db.GetBalance(addr).Cmp(amount.ToBig()) >= 0
			},
			Transfer: func(db StateDB, from, to common.Address, amount *uint256.Int, _ *params.Rules) {
				if amount.Sign() == 0 {
					return
				}
				db.SubBalance(from, amount.ToBig(), tracing.BalanceChangeUnspecified)
				db.AddBalance(to, amount.ToBig(), tracing.BalanceChangeUnspecified)
			},
		}, hooked, nil, &config, Config{})

		if _, _, err := evm.Call(common.Address{}, addr, nil, 100_000, new(uint256.Int)); err != nil {
			t.Fatalf("call failed: %v", err)
		}
		hooked.Finalise(true)
		return decrease, increase, burn, hooked.GetBalance(addr).Int64(), hooked.GetBalance(beneficiary).Int64(), hooked.Exist(addr)
	}

	for _, tc := range []struct {
		name            string
		amsterdam       bool
		newContract     bool
		toOther         bool
		wantDecrease    int
		wantIncrease    int
		wantBurn        int
		wantBalance     int64
		wantExists      bool
		wantBeneficiary int64
	}{
		// Before Amsterdam the balance a same-transaction contract destroyed
		// with itself is burnt, and the burn is reported at finalisation.
		{"pre-amsterdam/new-contract", false, true, false, 2, 1, 1, 0, false, 0},
		{"amsterdam/new-contract", true, true, false, 0, 0, 0, initialBalance, true, 0},
		{"pre-amsterdam/existing-contract", false, false, false, 1, 1, 0, initialBalance, true, 0},
		{"amsterdam/existing-contract", true, false, false, 0, 0, 0, initialBalance, true, 0},
		{"pre-amsterdam/existing-contract-to-other", false, false, true, 1, 1, 0, 0, true, initialBalance},
		{"amsterdam/existing-contract-to-other", true, false, true, 1, 1, 0, 0, true, initialBalance},
		{"pre-amsterdam/new-contract-to-other", false, true, true, 2, 1, 0, 0, false, initialBalance},
		{"amsterdam/new-contract-to-other", true, true, true, 1, 1, 0, 0, false, initialBalance},
	} {
		t.Run(tc.name, func(t *testing.T) {
			decrease, increase, burn, balance, beneficiaryBalance, exists := run(t, tc.amsterdam, tc.newContract, tc.toOther)
			if decrease != tc.wantDecrease || increase != tc.wantIncrease || burn != tc.wantBurn {
				t.Errorf("balance events = %d decreases, %d increases, %d burns, want %d, %d, %d",
					decrease, increase, burn, tc.wantDecrease, tc.wantIncrease, tc.wantBurn)
			}
			if balance != tc.wantBalance {
				t.Errorf("post-finalise balance = %d, want %d", balance, tc.wantBalance)
			}
			if beneficiaryBalance != tc.wantBeneficiary {
				t.Errorf("post-finalise beneficiary balance = %d, want %d", beneficiaryBalance, tc.wantBeneficiary)
			}
			if exists != tc.wantExists {
				t.Errorf("post-finalise existence = %v, want %v", exists, tc.wantExists)
			}
		})
	}
}

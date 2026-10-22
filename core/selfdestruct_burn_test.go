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
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/tracing"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// selfdestructCode returns the code of a contract that self-destructs to the
// given beneficiary, or to itself for the zero address. The same bytes work as
// init code and as runtime code.
func selfdestructCode(beneficiary common.Address) []byte {
	if beneficiary == (common.Address{}) {
		return []byte{0x30, 0xff} // ADDRESS; SELFDESTRUCT
	}
	return append(append([]byte{0x73}, beneficiary.Bytes()...), 0xff) // PUSH20 <beneficiary>; SELFDESTRUCT
}

// TestSelfdestructBurnHook drives transactions whose SELFDESTRUCT destroys the
// executing contract through block processing and pins the burn the balance
// hooks report. The burn must match the balance the destruction really
// destroys: a self-destruct that hands the balance to another account transfers
// it and burns nothing, and from EIP-6780 (Cancun) onwards a pre-existing
// contract is not destructed at all. Up to Cancun the legacy SELFDESTRUCT
// implementation runs, from Cancun the EIP-6780 one.
func TestSelfdestructBurnHook(t *testing.T) {
	var (
		key, _   = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		sender   = crypto.PubkeyToAddress(key.PublicKey)
		contract = common.HexToAddress("0xdead")
		other    = common.HexToAddress("0xbeef")
		gasPrice = new(big.Int).Mul(big.NewInt(20), big.NewInt(params.GWei))
		tests    = []struct {
			name         string
			fork         string
			preexisting  bool
			beneficiary  common.Address // zero means the contract itself
			wantBurn     *big.Int
			wantContract int64 // final balance of the contract account under test
			wantOther    int64 // final balance of the other account (beneficiary of to-other rows)
		}{
			// Up to Cancun the legacy implementation hands the balance to the
			// beneficiary and then clears the contract, so only a self-destruct
			// to itself burns anything.
			{"legacy/created/to-self", "legacy", false, common.Address{}, big.NewInt(1_000_000), 0, 0},
			{"legacy/created/to-other", "legacy", false, other, new(big.Int), 0, 1_000_000},
			{"legacy/pre-existing/to-self", "legacy", true, common.Address{}, big.NewInt(1_000), 0, 0},
			{"legacy/pre-existing/to-other", "legacy", true, other, new(big.Int), 0, 1_000},

			// From Cancun (EIP-6780) only a contract created in the same
			// transaction is destructed; a pre-existing one keeps its balance.
			{"cancun/created/to-self", "cancun", false, common.Address{}, big.NewInt(1_000_000), 0, 0},
			{"cancun/created/to-other", "cancun", false, other, new(big.Int), 0, 1_000_000},
			{"cancun/pre-existing/to-self", "cancun", true, common.Address{}, new(big.Int), 1_000, 0},
			{"cancun/pre-existing/to-other", "cancun", true, other, new(big.Int), 0, 1_000},

			// EIP-8246 (Amsterdam) keeps the balance of a destructed contract.
			{"amsterdam/created/to-self", "amsterdam", false, common.Address{}, new(big.Int), 1_000_000, 0},
			{"amsterdam/created/to-other", "amsterdam", false, other, new(big.Int), 0, 1_000_000},

			// A pre-existing contract is already left alone by EIP-6780, so
			// Amsterdam does not destruct it either.
			{"amsterdam/pre-existing/to-self", "amsterdam", true, common.Address{}, new(big.Int), 1_000, 0},
			{"amsterdam/pre-existing/to-other", "amsterdam", true, other, new(big.Int), 0, 1_000},
		}
	)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := *params.AllEthashProtocolChanges
			switch tt.fork {
			case "legacy":
				config.CancunBlock, config.PragueBlock, config.OsakaBlock, config.AmsterdamBlock = nil, nil, nil, nil
			case "cancun":
				config.PragueBlock, config.OsakaBlock, config.AmsterdamBlock = nil, nil, nil
			case "amsterdam":
				// AllEthashProtocolChanges already activates Amsterdam.
			default:
				t.Fatalf("unknown fork %q", tt.fork)
			}
			code := selfdestructCode(tt.beneficiary)

			var burned = new(big.Int)
			hooks := &tracing.Hooks{
				OnBalanceChange: func(addr common.Address, prev, new *big.Int, reason tracing.BalanceChangeReason) {
					if reason == tracing.BalanceDecreaseSelfdestructBurn {
						burned.Add(burned, prev)
					}
				},
			}

			db := rawdb.NewMemoryDatabase()
			alloc := types.GenesisAlloc{sender: {Balance: big.NewInt(params.Ether)}}
			if tt.preexisting {
				alloc[contract] = types.Account{Balance: big.NewInt(1_000), Code: code}
			}
			gspec := &Genesis{Config: &config, Alloc: alloc}
			genesis := gspec.MustCommit(db)

			blocks, receipts := GenerateChain(&config, genesis, ethash.NewFaker(), db, 1, func(i int, b *BlockGen) {
				var (
					tx  *types.Transaction
					err error
				)
				if tt.preexisting {
					tx, err = types.SignTx(types.NewTransaction(0, contract, new(big.Int), 100000, gasPrice, nil), types.LatestSigner(&config), key)
				} else {
					tx, err = types.SignTx(types.NewContractCreation(0, big.NewInt(1_000_000), 1_000_000, gasPrice, code), types.LatestSigner(&config), key)
				}
				if err != nil {
					t.Fatal(err)
				}
				b.AddTx(tx)
			})
			if status := receipts[0][0].Status; status != types.ReceiptStatusSuccessful {
				t.Fatalf("transaction failed with status %d", status)
			}

			chain, err := NewBlockChain(db, nil, gspec, ethash.NewFaker(), vm.Config{Tracer: hooks})
			if err != nil {
				t.Fatalf("failed to create the blockchain: %v", err)
			}
			defer chain.Stop()

			if _, err := chain.InsertChain(blocks); err != nil {
				t.Fatalf("failed to insert the block: %v", err)
			}
			if have, want := burned, tt.wantBurn; have.Cmp(want) != 0 {
				t.Errorf("reported burn = %v, want %v", have, want)
			}
			// The reported burn must not come at the cost of a different final
			// balance: whatever is not burnt stays with the beneficiary, or with
			// the contract when it appoints itself.
			statedb, err := chain.State()
			if err != nil {
				t.Fatalf("failed to open the post-block state: %v", err)
			}
			contractAddr := contract
			if !tt.preexisting {
				contractAddr = crypto.CreateAddress(sender, 0)
			}
			if have, want := statedb.GetBalance(contractAddr).Int64(), tt.wantContract; have != want {
				t.Errorf("post-block contract balance = %d, want %d", have, want)
			}
			if have, want := statedb.GetBalance(other).Int64(), tt.wantOther; have != want {
				t.Errorf("post-block other account balance = %d, want %d", have, want)
			}
		})
	}
}

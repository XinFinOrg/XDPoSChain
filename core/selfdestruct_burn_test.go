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

// TestSelfdestructBurnHook drives transactions whose SELFDESTRUCT destroys the
// executing contract through block processing and pins the burn the balance
// hooks report. The burn must match the balance the destruction really
// destroys, which from EIP-6780 (Cancun) onwards is only the case for a
// contract created in the same transaction that self-destructs to itself.
func TestSelfdestructBurnHook(t *testing.T) {
	var (
		key, _   = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		sender   = crypto.PubkeyToAddress(key.PublicKey)
		contract = common.HexToAddress("0xdead")
		gasPrice = new(big.Int).Mul(big.NewInt(20), big.NewInt(params.GWei))
		code     = []byte{0x30, 0xff} // ADDRESS; SELFDESTRUCT
		tests    = []struct {
			name        string
			amsterdam   *big.Int
			preexisting bool
			wantBurn    *big.Int
		}{
			// A contract created and self-destructed to itself within the
			// creation transaction burns its balance before Amsterdam.
			{"created-self-destruct-to-self", nil, false, big.NewInt(1_000_000)},
			// A pre-existing contract is not destructed by EIP-6780 at all, so
			// a self-destruct to self leaves its balance untouched: no burn.
			{"pre-existing-self-destruct-to-self", nil, true, new(big.Int)},
			// EIP-8246 keeps the balance of a destructed account.
			{"amsterdam-preserves-balance", big.NewInt(0), false, new(big.Int)},
		}
	)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := *params.AllEthashProtocolChanges
			config.AmsterdamBlock = tt.amsterdam

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
				if tt.preexisting {
					tx, err := types.SignTx(types.NewTransaction(0, contract, new(big.Int), 100000, gasPrice, nil), types.LatestSigner(&config), key)
					if err != nil {
						t.Fatal(err)
					}
					b.AddTx(tx)
					return
				}
				b.AddTx(eip8246CreateTx(t, key, &config, big.NewInt(1_000_000)))
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
		})
	}
}

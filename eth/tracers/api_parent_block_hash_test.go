// Copyright 2026 The XDPoSChain Authors
// This file is part of the XDPoSChain library.
//
// The XDPoSChain library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The XDPoSChain library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the XDPoSChain library. If not, see <http://www.gnu.org/licenses/>.

// This file pins the EIP-2935 parent hash history write in the two tracer test
// backends. Both rebuild the pre-state of a block from its parent the way block
// processing does, and that pre-state has to carry the same block level writes:
// without the ProcessParentBlockHash call the backend hands the tracer a state
// the chain never ran on.
package tracers

import (
	"bytes"
	"context"
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// TestStateAtTransactionAppliesParentBlockHash verifies that both tracer test
// backends apply the EIP-2935 parent hash history write block processing applies
// before the first transaction.
//
// The fixture covers the two shapes the write takes. Block 1 has the genesis
// state as its parent, which block processing never touched, so the write also
// deploys the history contract and backfills it before storing the parent hash.
// Blocks 2 and 3 start from a parent the chain itself produced, so the contract
// is already there and the write only stores the parent hash. Blocks 1 and 3 are
// empty and block 2 carries the only transaction: the empty ones leave through
// the early return, which applies the block level hooks only because the EVM is
// constructed ahead of it, and that early return is the path a hook appended
// after it would silently skip.
//
// params.TestChainConfig activates Prague at block zero, so every block of the
// fixture exercises the write. The assertions read it back from the pre-state
// the backend returns: the history contract must carry the canonical code, the
// slot of the parent block must hold the parent hash (the history contract
// stores it under block.number-1 modulo the serve window) and the pre-state root
// must have moved off the parent root: on block 1 deploying the contract alone
// moves it, while on blocks 2 and 3 only the new hash write does.
func TestStateAtTransactionAppliesParentBlockHash(t *testing.T) {
	accounts := newAccounts(2)
	genesis := &core.Genesis{
		Config: params.TestChainConfig,
		Alloc: types.GenesisAlloc{
			accounts[0].addr: {Balance: big.NewInt(9000000000000000000)},
			accounts[1].addr: {Balance: big.NewInt(9000000000000000000)},
		},
	}
	signer := types.HomesteadSigner{}
	backend := newTestBackend(t, 3, genesis, func(i int, b *core.BlockGen) {
		// Blocks 1 and 3 stay empty; block 2 carries the only transaction.
		if i != 1 {
			return
		}
		tx, err := types.SignTx(types.NewTx(&types.LegacyTx{
			Nonce:    0,
			To:       &accounts[1].addr,
			Value:    big.NewInt(1000),
			Gas:      params.TxGas,
			GasPrice: b.BaseFee(),
		}), signer, accounts[0].key)
		if err != nil {
			t.Fatalf("failed to sign the fixture transaction: %v", err)
		}
		b.AddTx(tx)
	})
	defer backend.chain.Stop()

	backends := []struct {
		name     string
		preState func(block *types.Block) (*state.StateDB, error)
	}{
		{
			name: "testBackend",
			preState: func(block *types.Block) (*state.StateDB, error) {
				_, _, statedb, release, err := backend.StateAtTransaction(context.Background(), block, 0, 0)
				if release != nil {
					defer release()
				}
				return statedb, err
			},
		},
		{
			name: "freshStateTraceBackend",
			preState: func(block *types.Block) (*state.StateDB, error) {
				fresh := &freshStateTraceBackend{testBackend: backend}
				_, _, statedb, release, err := fresh.StateAtTransaction(context.Background(), block, 0, 0)
				if release != nil {
					defer release()
				}
				return statedb, err
			},
		},
	}
	blocks := []struct {
		name   string
		number uint64
	}{
		{name: "empty block on the genesis parent", number: 1},
		{name: "block with a transaction", number: 2},
		{name: "empty block on a processed parent", number: 3},
	}
	for _, candidate := range backends {
		for _, fixture := range blocks {
			t.Run(candidate.name+"/"+fixture.name, func(t *testing.T) {
				block := backend.chain.GetBlockByNumber(fixture.number)
				if block == nil {
					t.Fatalf("block #%d is missing", fixture.number)
				}
				parent := backend.chain.GetBlockByNumber(fixture.number - 1)
				if parent == nil {
					t.Fatalf("parent of block #%d is missing", fixture.number)
				}
				statedb, err := candidate.preState(block)
				if err != nil {
					t.Fatalf("failed to rebuild the pre-state of block #%d: %v", fixture.number, err)
				}
				if have := statedb.GetCode(params.HistoryStorageAddress); !bytes.Equal(have, params.HistoryStorageCode) {
					t.Fatalf("history contract code mismatch in the pre-state of block #%d: have %d bytes, want %d",
						fixture.number, len(have), len(params.HistoryStorageCode))
				}
				var key common.Hash
				binary.BigEndian.PutUint64(key[24:], (fixture.number-1)%uint64(params.HistoryServeWindow))
				if have := statedb.GetState(params.HistoryStorageAddress, key); have != block.ParentHash() {
					t.Fatalf("parent hash slot of block #%d: have %x, want %x", fixture.number, have, block.ParentHash())
				}
				if root := statedb.IntermediateRoot(true); root == parent.Root() {
					t.Fatalf("pre-state root of block #%d equals the parent root %x, the history write is missing",
						fixture.number, root)
				}
			})
		}
	}
}

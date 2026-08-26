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

package txpool_test

import (
	"math/big"
	"testing"
	"time"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/txpool"
	"github.com/XinFinOrg/XDPoSChain/core/txpool/legacypool"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/params"
)

var (
	headTestKey, _  = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	headTestAddress = crypto.PubkeyToAddress(headTestKey.PublicKey)
	headTestFunds   = big.NewInt(1000000000000000000)
	headTestGenesis = &core.Genesis{
		Config: params.TestChainConfig,
		Alloc: types.GenesisAlloc{
			headTestAddress: {Balance: headTestFunds},
		},
		BaseFee: big.NewInt(params.InitialBaseFee),
	}
	headTestSigner = types.LatestSigner(headTestGenesis.Config)
)

// newHeadTestEnv builds a chain of n blocks (each consuming one nonce of the
// test address) and a txpool layered on top of it. The chain head subscription
// is established inside txpool.New, so the head events emitted by InsertChain
// below must be delivered to the pool loop.
func newHeadTestEnv(t *testing.T, n int) (*core.BlockChain, *txpool.TxPool) {
	t.Helper()

	_, blocks, _ := core.GenerateChainWithGenesis(headTestGenesis, ethash.NewFaker(), n, func(i int, gen *core.BlockGen) {
		gasPrice := big.NewInt(params.InitialBaseFee)
		if baseFee := gen.BaseFee(); baseFee != nil {
			gasPrice = new(big.Int).Set(baseFee)
		}
		tx, err := types.SignTx(types.NewTransaction(gen.TxNonce(headTestAddress), common.Address{0x00}, big.NewInt(1000), params.TxGas, gasPrice, nil), headTestSigner, headTestKey)
		if err != nil {
			panic(err)
		}
		gen.AddTx(tx)
	})

	db := rawdb.NewMemoryDatabase()
	chain, err := core.NewBlockChain(db, nil, headTestGenesis, ethash.NewFaker(), vm.Config{})
	if err != nil {
		t.Fatalf("Failed to create blockchain: %v", err)
	}
	legacyPool := legacypool.New(legacypool.DefaultConfig, chain)
	pool, err := txpool.New(0, chain, []txpool.SubPool{legacyPool})
	if err != nil {
		t.Fatalf("Failed to create tx pool: %v", err)
	}
	if _, err := chain.InsertChain(blocks); err != nil {
		t.Fatalf("Failed to insert blocks: %v", err)
	}
	return chain, pool
}

// TestHeadEventDeliveredAfterNew verifies that the pool observes the head moved
// by InsertChain right after New. Before the subscription moved into New, the
// loop subscribed asynchronously and could miss the head event, leaving the
// pool's pending nonce at genesis and rejecting a fresh transaction as
// ErrNonceTooHigh.
func TestHeadEventDeliveredAfterNew(t *testing.T) {
	chain, pool := newHeadTestEnv(t, 10)
	defer chain.Stop()
	defer pool.Close()

	head := chain.CurrentBlock()
	state, err := chain.StateAt(head.Root)
	if err != nil {
		t.Fatalf("Failed to open head state: %v", err)
	}
	nonce := state.GetNonce(headTestAddress)
	if nonce != 10 {
		t.Fatalf("Unexpected chain nonce, got: %d, want: 10", nonce)
	}
	// Wait for the pool to process the head event emitted by InsertChain right
	// after New. If the event was lost, the pending nonce never advances past
	// the genesis state and this loop times out.
	deadline := time.Now().Add(5 * time.Second)
	for pool.PoolNonce(headTestAddress) != nonce {
		if time.Now().After(deadline) {
			t.Fatalf("Pool never observed head nonce %d, pending nonce still %d", nonce, pool.PoolNonce(headTestAddress))
		}
		time.Sleep(10 * time.Millisecond)
	}
	// A transaction at the current head nonce must be accepted; a pool that
	// missed the head event would reject it as ErrNonceTooHigh.
	gasPrice := big.NewInt(params.InitialBaseFee)
	if head.BaseFee != nil {
		gasPrice = new(big.Int).Set(head.BaseFee)
	}
	tx, err := types.SignTx(types.NewTransaction(nonce, common.Address{0x00}, big.NewInt(1000), params.TxGas, gasPrice, nil), headTestSigner, headTestKey)
	if err != nil {
		t.Fatalf("Failed to sign transaction: %v", err)
	}
	if errs := pool.Add([]*types.Transaction{tx}, true); errs[0] != nil {
		t.Fatalf("Transaction at head nonce rejected: %v", errs[0])
	}
	// And it must be visible as pending, not stuck in the queue.
	pending, queued := pool.ContentFrom(headTestAddress)
	if len(pending) != 1 || len(queued) != 0 {
		t.Fatalf("Unexpected pool content, got pending %d, queued %d, want pending 1", len(pending), len(queued))
	}
}

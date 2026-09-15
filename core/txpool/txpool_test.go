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

package txpool_test

import (
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/txpool"
	"github.com/XinFinOrg/XDPoSChain/core/txpool/legacypool"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/event"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// TestMinGasPriceResolvesAtPendingBlock checks that MinGasPrice resolves the gas
// schedule at the block pending on top of the head, the height admission
// validation prices a transaction at.
func TestMinGasPriceResolvesAtPendingBlock(t *testing.T) {
	cfg := *params.TestChainConfig
	cfg.Gas50xBlock = big.NewInt(100)
	cfg.Gas2500xBlock = big.NewInt(200)

	chain, pool := newMinGasPriceTestEnv(t, &cfg, 200)
	defer chain.Stop()
	defer pool.Close()

	var (
		baseline = big.NewInt(common.DefaultMinGasPrice)
		gas50x   = new(big.Int).Mul(baseline, big.NewInt(50))
		gas2500x = new(big.Int).Mul(baseline, big.NewInt(2500))
	)

	// The chain is rewound from high to low: SetHead only goes backwards, and
	// each step is followed by Sync so the pool has processed the new head.
	if err := pool.Sync(); err != nil {
		t.Fatalf("failed to sync the txpool: %v", err)
	}
	if have := pool.MinGasPrice(); have.Cmp(gas2500x) != 0 {
		t.Fatalf("head 200: MinGasPrice = %v, want %v", have, gas2500x)
	}
	for _, tc := range []struct {
		head uint64
		want *big.Int
	}{
		{head: 199, want: gas2500x}, // pending 200, the fork fires
		{head: 198, want: gas50x},   // pending 199
		{head: 99, want: gas50x},    // pending 100, the fork fires
		{head: 98, want: baseline},  // pending 99
	} {
		if err := chain.SetHead(tc.head); err != nil {
			t.Fatalf("failed to rewind to %d: %v", tc.head, err)
		}
		if err := pool.Sync(); err != nil {
			t.Fatalf("failed to sync the txpool at %d: %v", tc.head, err)
		}
		if have := pool.MinGasPrice(); have.Cmp(tc.want) != 0 {
			t.Errorf("head %d: MinGasPrice = %v, want %v", tc.head, have, tc.want)
		}
	}
}

// TestMinGasPriceFallsBackWithoutHeadNumber checks the floor a head without a
// block number resolves to. Admission validation passes a nil number to the gas
// schedule in that state too, so the fallback is what keeps the tracker pricing
// transactions against the same floor the pool admits them at.
func TestMinGasPriceFallsBackWithoutHeadNumber(t *testing.T) {
	// The tiers are scheduled low enough that a nil number and the number the
	// guard would otherwise fall into resolve to different tiers, so the
	// assertion below cannot pass by accident.
	cfg := *params.TestChainConfig
	cfg.Gas50xBlock = big.NewInt(1)
	cfg.Gas2500xBlock = big.NewInt(200)

	pool, err := txpool.New(0, numberlessChain{cfg: &cfg}, nil)
	if err != nil {
		t.Fatalf("failed to create tx pool: %v", err)
	}
	defer pool.Close()

	// No block number means no tier is scheduled, so the fallback price is the
	// baseline tier. Pinned here so a new tier cannot silently change what the
	// assertion below is about.
	want := params.GetMinGasPrice(nil, &cfg)
	if baseline := big.NewInt(common.DefaultMinGasPrice); want.Cmp(baseline) != 0 {
		t.Fatalf("baseline tier changed: have %v, want %v", want, baseline)
	}
	if have := pool.MinGasPrice(); have.Cmp(want) != 0 {
		t.Fatalf("MinGasPrice = %v, want %v", have, want)
	}
}

// numberlessChain reports a head that carries no block number, the state a
// chain is in before its first block is known.
type numberlessChain struct{ cfg *params.ChainConfig }

func (c numberlessChain) Config() *params.ChainConfig { return c.cfg }

func (c numberlessChain) CurrentBlock() *types.Header { return &types.Header{} }

func (c numberlessChain) StateAt(common.Hash) (*state.StateDB, error) {
	return state.New(types.EmptyRootHash, state.NewDatabase(rawdb.NewMemoryDatabase()))
}

func (c numberlessChain) SubscribeChainHeadEvent(ch chan<- core.ChainHeadEvent) event.Subscription {
	return event.NewSubscription(func(quit <-chan struct{}) error {
		<-quit
		return nil
	})
}

// newMinGasPriceTestEnv builds a chain of n empty blocks over cfg and a txpool
// layered on top of it. The blocks carry no transactions: only the head height
// matters for the gas schedule.
func newMinGasPriceTestEnv(t *testing.T, cfg *params.ChainConfig, n int) (*core.BlockChain, *txpool.TxPool) {
	t.Helper()

	genesis := &core.Genesis{
		Config:  cfg,
		BaseFee: big.NewInt(params.InitialBaseFee),
	}
	_, blocks, _ := core.GenerateChainWithGenesis(genesis, ethash.NewFaker(), n, nil)

	db := rawdb.NewMemoryDatabase()
	chain, err := core.NewBlockChain(db, nil, genesis, ethash.NewFaker(), vm.Config{})
	if err != nil {
		t.Fatalf("failed to create blockchain: %v", err)
	}
	legacyPool := legacypool.New(legacypool.DefaultConfig, chain)
	pool, err := txpool.New(0, chain, []txpool.SubPool{legacyPool})
	if err != nil {
		t.Fatalf("failed to create tx pool: %v", err)
	}
	if _, err := chain.InsertChain(blocks); err != nil {
		t.Fatalf("failed to insert blocks: %v", err)
	}
	return chain, pool
}

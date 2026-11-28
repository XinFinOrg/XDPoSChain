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
	"github.com/XinFinOrg/XDPoSChain/params"
)

// TestBlockchainInitHook pins that a live tracer attached through vm.Config
// receives the chain configuration when the blockchain is created. The supply
// tracer decides from this hook whether SELFDESTRUCT still burns the destructed
// balance (EIP-8246); if the call disappears the tracer keeps the pre-fork
// accounting silently, so the delivery itself needs a guard.
func TestBlockchainInitHook(t *testing.T) {
	gspec := &Genesis{
		Config: &params.ChainConfig{
			ChainID:        big.NewInt(1338),
			HomesteadBlock: new(big.Int),
			Ethash:         new(params.EthashConfig),
		},
		Alloc: types.GenesisAlloc{
			common.Address{1}: {Balance: big.NewInt(1)},
		},
		Difficulty: big.NewInt(1),
	}

	var (
		calls  int
		gotCfg *params.ChainConfig
	)
	hooks := &tracing.Hooks{
		OnBlockchainInit: func(chainConfig *params.ChainConfig) {
			calls++
			gotCfg = chainConfig
		},
	}
	chain, err := NewBlockChain(rawdb.NewMemoryDatabase(), nil, gspec, ethash.NewFaker(), vm.Config{Tracer: hooks})
	if err != nil {
		t.Fatalf("failed to create the blockchain: %v", err)
	}
	defer chain.Stop()

	if calls != 1 {
		t.Fatalf("OnBlockchainInit called %d time(s), want 1", calls)
	}
	if gotCfg == nil {
		t.Fatal("OnBlockchainInit received a nil chain config")
	}
	if gotCfg.ChainID.Cmp(gspec.Config.ChainID) != 0 {
		t.Errorf("OnBlockchainInit chain id = %v, want %v", gotCfg.ChainID, gspec.Config.ChainID)
	}
	if gotCfg.HomesteadBlock.Cmp(gspec.Config.HomesteadBlock) != 0 {
		t.Errorf("OnBlockchainInit homestead block = %v, want %v", gotCfg.HomesteadBlock, gspec.Config.HomesteadBlock)
	}
	if gotCfg.AmsterdamBlock != nil {
		t.Errorf("OnBlockchainInit Amsterdam block = %v, want nil", gotCfg.AmsterdamBlock)
	}
}

// Copyright 2026 The XDPoSChain Authors
// This file is part of the XDPoSChain library.

package core

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// TestMulticall3HardFork checks that the canonical Multicall3 code is installed
// at the block that activates Prague and at no earlier block, and that the state
// transition which validates blocks installs it too: without the latter the
// imported blocks would not match the state the chain announces.
func TestMulticall3HardFork(t *testing.T) {
	config := *params.TestChainConfig
	config.PragueBlock = big.NewInt(2)
	config.OsakaBlock = nil

	var (
		engine  = ethash.NewFaker()
		genesis = &Genesis{BaseFee: big.NewInt(params.InitialBaseFee), Config: &config}
	)
	db, blocks, _ := GenerateChainWithGenesis(genesis, engine, 4, nil)

	for _, block := range blocks {
		statedb, err := state.New(block.Root(), state.NewDatabase(db))
		if err != nil {
			t.Fatalf("failed to open the state at block %d: %v", block.NumberU64(), err)
		}
		code := statedb.GetCode(params.Multicall3Address)
		if block.NumberU64() < config.PragueBlock.Uint64() {
			if len(code) != 0 {
				t.Fatalf("block %d: Multicall3 installed before Prague", block.NumberU64())
			}
			continue
		}
		if !bytes.Equal(code, params.Multicall3RuntimeCode) {
			t.Fatalf("block %d: Multicall3 code length %d, want %d", block.NumberU64(), len(code), len(params.Multicall3RuntimeCode))
		}
		if nonce := statedb.GetNonce(params.Multicall3Address); nonce != 1 {
			t.Fatalf("block %d: Multicall3 nonce = %d, want 1", block.NumberU64(), nonce)
		}
	}
	chain, err := NewBlockChain(db, &CacheConfig{TrieDirtyDisabled: true}, genesis, engine, vm.Config{})
	if err != nil {
		t.Fatalf("failed to create chain: %v", err)
	}
	defer chain.Stop()

	if _, err := chain.InsertChain(blocks); err != nil {
		t.Fatalf("failed to insert chain: %v", err)
	}
}

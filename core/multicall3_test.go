// Copyright 2026 The XDPoSChain Authors
// This file is part of the XDPoSChain library.

package core

import (
	"bytes"
	"fmt"
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/tracing"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/ethdb"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// multicall3StateAt opens the state a block left behind.
func multicall3StateAt(t *testing.T, db ethdb.Database, root common.Hash) *state.StateDB {
	t.Helper()

	statedb, err := state.New(root, state.NewDatabase(db))
	if err != nil {
		t.Fatalf("failed to open the state at root %x: %v", root, err)
	}
	return statedb
}

// multicall3Config returns the configuration the hook cases share: TestChainConfig
// with Prague active at pragueBlock and Osaka off.
func multicall3Config(pragueBlock *big.Int) *params.ChainConfig {
	config := *params.TestChainConfig
	config.PragueBlock = pragueBlock
	config.OsakaBlock = nil
	config.AmsterdamBlock = nil
	return &config
}

// assertMulticall3Code fails unless code is the canonical runtime code, printing the
// hash and the length it landed with. context names the state the code was read from.
func assertMulticall3Code(t *testing.T, code []byte, context string) {
	t.Helper()

	if bytes.Equal(code, params.Multicall3RuntimeCode) {
		return
	}
	t.Fatalf("%s: Multicall3 code hash = %x, want %x (length %d)", context, crypto.Keccak256Hash(code), crypto.Keccak256Hash(params.Multicall3RuntimeCode), len(code))
}

// TestMulticall3HardFork checks that the canonical Multicall3 code is installed at the
// Prague activation block and at no earlier block, and that block validation installs it
// too, or the imported blocks would not match the state the chain announces.
//
// Prague is covered both at a concrete block and from genesis, where the install lands on
// the first processed block and the genesis state stays without code.
func TestMulticall3HardFork(t *testing.T) {
	for _, tc := range []struct {
		name           string
		pragueBlock    *big.Int
		wantFirstBlock uint64
	}{
		{name: "activated at a block", pragueBlock: big.NewInt(2), wantFirstBlock: 2},
		{name: "active from genesis", pragueBlock: big.NewInt(0), wantFirstBlock: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := multicall3Config(tc.pragueBlock)

			var (
				engine  = ethash.NewFaker()
				genesis = &Genesis{BaseFee: big.NewInt(params.InitialBaseFee), Config: config}
			)
			db, blocks, _ := GenerateChainWithGenesis(genesis, engine, 4, nil)

			if code := multicall3StateAt(t, db, genesis.ToBlock().Root()).GetCode(params.Multicall3Address); len(code) != 0 {
				t.Fatalf("genesis: Multicall3 code length %d, want 0", len(code))
			}
			for _, block := range blocks {
				statedb := multicall3StateAt(t, db, block.Root())
				code := statedb.GetCode(params.Multicall3Address)
				if block.NumberU64() < tc.wantFirstBlock {
					if len(code) != 0 {
						t.Fatalf("block %d: Multicall3 installed before the Prague activation block", block.NumberU64())
					}
					continue
				}
				assertMulticall3Code(t, code, fmt.Sprintf("block %d", block.NumberU64()))
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
		})
	}
}

// TestMulticall3RuntimeCodeIsCallable calls the installed contract: pinning the length
// and hash only says the bytes are canonical, executing them says the account works.
func TestMulticall3RuntimeCodeIsCallable(t *testing.T) {
	config := multicall3Config(big.NewInt(2))

	var (
		engine  = ethash.NewFaker()
		genesis = &Genesis{BaseFee: big.NewInt(params.InitialBaseFee), Config: config}
	)
	db, blocks, _ := GenerateChainWithGenesis(genesis, engine, 2, nil)

	chain, err := NewBlockChain(db, &CacheConfig{TrieDirtyDisabled: true}, genesis, engine, vm.Config{})
	if err != nil {
		t.Fatalf("failed to create chain: %v", err)
	}
	defer chain.Stop()

	block := blocks[len(blocks)-1]
	if block.NumberU64() < config.PragueBlock.Uint64() {
		t.Fatalf("the generated chain stops at block %d, before the Prague activation block", block.NumberU64())
	}
	context := NewEVMBlockContext(block.Header(), chain, &block.Header().Coinbase)
	evm := vm.NewEVM(context, multicall3StateAt(t, db, block.Root()), nil, config, vm.Config{})

	// getBlockNumber() returns block.number; it is a known selector of the runtime
	// code, so a wrong or truncated constant fails here rather than on a live network.
	ret, _, err := evm.StaticCall(common.Address{}, params.Multicall3Address, common.FromHex("0x42cbb15c"), 100_000)
	if err != nil {
		t.Fatalf("getBlockNumber() on the installed Multicall3 failed: %v", err)
	}
	if have, want := new(big.Int).SetBytes(ret), block.Number(); have.Cmp(want) != 0 {
		t.Fatalf("Multicall3.getBlockNumber() = %v, want %v", have, want)
	}
}

// multicall3EmptyState returns a fresh in-memory state for the hook level cases.
func multicall3EmptyState(t *testing.T) *state.StateDB {
	t.Helper()

	statedb, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()))
	if err != nil {
		t.Fatalf("failed to create the state: %v", err)
	}
	return statedb
}

// TestMulticall3HardForkGuardsInstalledCode covers the guard around the install: a
// replay over the activation block stays a no-op on the canonical code, while any
// other code at the address fails the transition instead of being replaced.
func TestMulticall3HardForkGuardsInstalledCode(t *testing.T) {
	config := multicall3Config(big.NewInt(2))

	t.Run("canonical code is accepted", func(t *testing.T) {
		statedb := multicall3EmptyState(t)
		statedb.SetCode(params.Multicall3Address, params.Multicall3RuntimeCode)

		ApplyMulticall3HardFork(config, statedb, big.NewInt(2))

		assertMulticall3Code(t, statedb.GetCode(params.Multicall3Address), "after the replay")
	})

	t.Run("foreign code is refused", func(t *testing.T) {
		statedb := multicall3EmptyState(t)
		statedb.SetCode(params.Multicall3Address, []byte{0x60, 0x00})

		defer func() {
			if recover() == nil {
				t.Fatal("installing over foreign code did not fail")
			}
		}()
		ApplyMulticall3HardFork(config, statedb, big.NewInt(2))
	})
}

// TestMulticall3HardForkReinstallsMissingCode covers the self-healing install: like
// ProcessParentBlockHash, a Prague-active block re-installs the code when the address
// lost it, so a node missing the account recovers instead of reverting its calls. The
// install does not reset the account, so the balance it carries stays.
func TestMulticall3HardForkReinstallsMissingCode(t *testing.T) {
	config := multicall3Config(big.NewInt(2))

	t.Run("a block after the activation installs the code", func(t *testing.T) {
		statedb := multicall3EmptyState(t)
		ApplyMulticall3HardFork(config, statedb, big.NewInt(9))

		assertMulticall3Code(t, statedb.GetCode(params.Multicall3Address), "at a block after the activation")
		if nonce := statedb.GetNonce(params.Multicall3Address); nonce != 1 {
			t.Fatalf("Multicall3 nonce = %d, want 1", nonce)
		}
	})

	t.Run("the install keeps the balance the account carries", func(t *testing.T) {
		statedb := multicall3EmptyState(t)
		statedb.SetBalance(params.Multicall3Address, big.NewInt(7), tracing.BalanceChangeUnspecified)

		ApplyMulticall3HardFork(config, statedb, big.NewInt(9))

		if have := statedb.GetBalance(params.Multicall3Address); have.Cmp(big.NewInt(7)) != 0 {
			t.Fatalf("Multicall3 balance = %v after the install, want 7", have)
		}
	})

	t.Run("a block before the activation stays untouched", func(t *testing.T) {
		statedb := multicall3EmptyState(t)
		ApplyMulticall3HardFork(config, statedb, big.NewInt(1))

		if code := statedb.GetCode(params.Multicall3Address); len(code) != 0 {
			t.Fatalf("block 1: Multicall3 code length %d, want 0", len(code))
		}
	})
}

// TestMulticall3HardForkIgnoresGenesisBlock checks that block zero is left untouched:
// the genesis block never goes through block processing, so a replay starting from it
// must not install the contract into the committed genesis state.
func TestMulticall3HardForkIgnoresGenesisBlock(t *testing.T) {
	config := multicall3Config(big.NewInt(0))

	statedb := multicall3EmptyState(t)
	ApplyMulticall3HardFork(config, statedb, big.NewInt(0))

	if code := statedb.GetCode(params.Multicall3Address); len(code) != 0 {
		t.Fatalf("block 0: Multicall3 code length %d, want 0", len(code))
	}
	if nonce := statedb.GetNonce(params.Multicall3Address); nonce != 0 {
		t.Fatalf("block 0: Multicall3 nonce = %d, want 0", nonce)
	}
}

// Copyright 2026 The XDPoSChain Authors
// This file is part of the XDPoSChain library.

package core

import (
	"bytes"
	"fmt"
	"math/big"
	"slices"
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
	"github.com/holiman/uint256"
)

func eip7997Config(amsterdamBlock *big.Int) *params.ChainConfig {
	config := *params.TestChainConfig
	config.AmsterdamBlock = amsterdamBlock
	return &config
}

func eip7997StateAt(t *testing.T, db ethdb.Database, root common.Hash) *state.StateDB {
	t.Helper()

	statedb, err := state.New(root, state.NewDatabase(db))
	if err != nil {
		t.Fatalf("failed to open the state at root %x: %v", root, err)
	}
	return statedb
}

func eip7997EmptyState(t *testing.T) *state.StateDB {
	t.Helper()

	statedb, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()))
	if err != nil {
		t.Fatalf("failed to create the state: %v", err)
	}
	return statedb
}

func assertEIP7997Code(t *testing.T, code []byte, context string) {
	t.Helper()

	if bytes.Equal(code, params.DeterministicFactoryCode) {
		return
	}
	t.Fatalf("%s: factory code hash = %x, want %x (length %d)", context, crypto.Keccak256Hash(code), crypto.Keccak256Hash(params.DeterministicFactoryCode), len(code))
}

func TestEIP7997HardFork(t *testing.T) {
	for _, tc := range []struct {
		name           string
		amsterdamBlock *big.Int
		wantFirstBlock uint64
	}{
		{name: "activated at a block", amsterdamBlock: big.NewInt(2), wantFirstBlock: 2},
		{name: "active from genesis", amsterdamBlock: big.NewInt(0), wantFirstBlock: 1},
		{name: "not scheduled", amsterdamBlock: nil, wantFirstBlock: 5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := eip7997Config(tc.amsterdamBlock)

			var (
				engine  = ethash.NewFaker()
				genesis = &Genesis{BaseFee: big.NewInt(params.InitialBaseFee), Config: config}
			)
			db, blocks, _ := GenerateChainWithGenesis(genesis, engine, 4, nil)

			if code := eip7997StateAt(t, db, genesis.ToBlock().Root()).GetCode(params.DeterministicFactoryAddress); len(code) != 0 {
				t.Fatalf("genesis: factory code length %d, want 0", len(code))
			}
			for _, block := range blocks {
				statedb := eip7997StateAt(t, db, block.Root())
				code := statedb.GetCode(params.DeterministicFactoryAddress)
				if block.NumberU64() < tc.wantFirstBlock {
					if len(code) != 0 {
						t.Fatalf("block %d: factory installed before Amsterdam", block.NumberU64())
					}
					continue
				}
				assertEIP7997Code(t, code, fmt.Sprintf("block %d", block.NumberU64()))
				if nonce := statedb.GetNonce(params.DeterministicFactoryAddress); nonce != 1 {
					t.Fatalf("block %d: factory nonce = %d, want 1", block.NumberU64(), nonce)
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

func TestEIP7997RuntimeCodeIsCallable(t *testing.T) {
	config := eip7997Config(big.NewInt(2))

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
	if block.NumberU64() < config.AmsterdamBlock.Uint64() {
		t.Fatalf("the generated chain stops at block %d, before the Amsterdam activation block", block.NumberU64())
	}
	context := NewEVMBlockContext(block.Header(), chain, &block.Header().Coinbase)
	statedb := eip7997StateAt(t, db, block.Root())
	evm := vm.NewEVM(context, statedb, nil, config, vm.Config{})

	salt := [32]byte{1}
	initcode := common.FromHex("0x600160005260206000f3")
	input := append(salt[:], initcode...)
	ret, _, err := evm.Call(common.Address{}, params.DeterministicFactoryAddress, input, 200_000, uint256.NewInt(0))
	if err != nil {
		t.Fatalf("CREATE2 through the factory failed: %v", err)
	}
	want := crypto.CreateAddress2(params.DeterministicFactoryAddress, salt, crypto.Keccak256Hash(initcode).Bytes())
	if len(ret) != 20 || !bytes.Equal(ret, want.Bytes()) {
		t.Fatalf("CREATE2 returned %x, want %s", ret, want)
	}
	if code := statedb.GetCode(want); len(code) == 0 {
		t.Fatalf("contract at %s has no code", want)
	}
}

func TestEIP7997HardForkGuardsInstalledCode(t *testing.T) {
	config := eip7997Config(big.NewInt(2))

	t.Run("canonical code is accepted", func(t *testing.T) {
		statedb := eip7997EmptyState(t)
		statedb.SetCode(params.DeterministicFactoryAddress, params.DeterministicFactoryCode)
		statedb.SetNonce(params.DeterministicFactoryAddress, 42, tracing.NonceChangeUnspecified)
		statedb.SetBalance(params.DeterministicFactoryAddress, big.NewInt(7), tracing.BalanceChangeUnspecified)

		ApplyEIP7997HardFork(config, statedb, big.NewInt(2))

		assertEIP7997Code(t, statedb.GetCode(params.DeterministicFactoryAddress), "after the replay")
		if nonce := statedb.GetNonce(params.DeterministicFactoryAddress); nonce != 42 {
			t.Fatalf("factory nonce = %d after the replay, want 42", nonce)
		}
		if have := statedb.GetBalance(params.DeterministicFactoryAddress); have.Cmp(big.NewInt(7)) != 0 {
			t.Fatalf("factory balance = %v after the replay, want 7", have)
		}
	})

	t.Run("foreign code is refused", func(t *testing.T) {
		statedb := eip7997EmptyState(t)
		statedb.SetCode(params.DeterministicFactoryAddress, []byte{0x60, 0x00})

		defer func() {
			if recover() == nil {
				t.Fatal("installing over foreign code did not fail")
			}
		}()
		ApplyEIP7997HardFork(config, statedb, big.NewInt(2))
	})
}

func TestEIP7997HardForkReinstallsMissingCode(t *testing.T) {
	config := eip7997Config(big.NewInt(2))

	t.Run("a block after the activation installs the code", func(t *testing.T) {
		statedb := eip7997EmptyState(t)
		ApplyEIP7997HardFork(config, statedb, big.NewInt(9))

		assertEIP7997Code(t, statedb.GetCode(params.DeterministicFactoryAddress), "at a block after the activation")
		if nonce := statedb.GetNonce(params.DeterministicFactoryAddress); nonce != 1 {
			t.Fatalf("factory nonce = %d, want 1", nonce)
		}
	})

	t.Run("the install keeps the balance the account carries", func(t *testing.T) {
		statedb := eip7997EmptyState(t)
		statedb.SetBalance(params.DeterministicFactoryAddress, big.NewInt(7), tracing.BalanceChangeUnspecified)

		ApplyEIP7997HardFork(config, statedb, big.NewInt(9))

		if have := statedb.GetBalance(params.DeterministicFactoryAddress); have.Cmp(big.NewInt(7)) != 0 {
			t.Fatalf("factory balance = %v after the install, want 7", have)
		}
	})

	t.Run("a block before the activation stays untouched", func(t *testing.T) {
		statedb := eip7997EmptyState(t)
		ApplyEIP7997HardFork(config, statedb, big.NewInt(1))

		if code := statedb.GetCode(params.DeterministicFactoryAddress); len(code) != 0 {
			t.Fatalf("block 1: factory code length %d, want 0", len(code))
		}
	})
}

func TestEIP7997HardForkIgnoresGenesisBlock(t *testing.T) {
	config := eip7997Config(big.NewInt(0))

	statedb := eip7997EmptyState(t)
	ApplyEIP7997HardFork(config, statedb, big.NewInt(0))

	if code := statedb.GetCode(params.DeterministicFactoryAddress); len(code) != 0 {
		t.Fatalf("block 0: factory code length %d, want 0", len(code))
	}
	if nonce := statedb.GetNonce(params.DeterministicFactoryAddress); nonce != 0 {
		t.Fatalf("block 0: factory nonce = %d, want 0", nonce)
	}
}

func TestEIP7997HardForkReportsToTheTracer(t *testing.T) {
	config := eip7997Config(big.NewInt(2))

	statedb := eip7997EmptyState(t)
	var codeChanges, nonceChanges []common.Address
	hooked := state.NewHookedState(statedb, &tracing.Hooks{
		OnCodeChange: func(addr common.Address, prevCodeHash common.Hash, prev []byte, codeHash common.Hash, code []byte) {
			codeChanges = append(codeChanges, addr)
		},
		OnNonceChangeV2: func(addr common.Address, prev, next uint64, reason tracing.NonceChangeReason) {
			nonceChanges = append(nonceChanges, addr)
		},
	})

	ApplyEIP7997HardFork(config, hooked, big.NewInt(2))

	if !slices.Contains(codeChanges, params.DeterministicFactoryAddress) {
		t.Fatalf("factory code change not reported to the tracer, got %v", codeChanges)
	}
	if !slices.Contains(nonceChanges, params.DeterministicFactoryAddress) {
		t.Fatalf("factory nonce change not reported to the tracer, got %v", nonceChanges)
	}
	if code := statedb.GetCode(params.DeterministicFactoryAddress); !bytes.Equal(code, params.DeterministicFactoryCode) {
		t.Fatalf("factory code missing from the EVM state: %x", code)
	}
}

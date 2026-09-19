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

package tracers

import (
	"context"
	"math/big"
	"reflect"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// replayIntermediateRoots rebuilds the per-transaction state roots of a block with the
// block processing entry point, giving the tracer result an expectation to be matched
// against that comes from a path other than the one under test. The roots it returns are
// the ones the transactions leave behind, taken before the block level finalisation, so
// the last of them is not block.Root(): finalisation still credits the block reward on
// top of it. The helper covers that step separately, closing the block the way chain
// generation does and checking that finalised state against the block root, and it is
// that check which pins the returned roots to the chain.
func replayIntermediateRoots(t *testing.T, backend *testBackend, config *params.ChainConfig, block *types.Block) []common.Hash {
	t.Helper()

	parent := backend.chain.GetBlockByNumber(block.NumberU64() - 1)
	if parent == nil {
		t.Fatalf("expected block #%d", block.NumberU64()-1)
	}
	statedb, err := backend.chain.StateAt(parent.Root())
	if err != nil {
		t.Fatalf("failed to load the parent state: %v", err)
	}
	signer := types.MakeSigner(config, block.Number())
	evm := vm.NewEVM(core.NewEVMBlockContext(block.Header(), backend.chain, nil), statedb, nil, config, vm.Config{})
	// Block level pre-execution, mirroring what both debug_intermediateRoots and block
	// processing do before the first transaction.
	if config.IsPrague(block.Number()) {
		core.ProcessParentBlockHash(block.ParentHash(), evm)
	}
	feeCapacity := statedb.GetTRC21FeeCapacityFromState()
	var (
		usedGas  uint64
		roots    []common.Hash
		receipts = make([]*types.Receipt, 0, len(block.Transactions()))
	)
	for i, tx := range block.Transactions() {
		var balance *big.Int
		if tx.To() != nil {
			if value, ok := feeCapacity[*tx.To()]; ok {
				balance = value
			}
		}
		msg, err := core.TransactionToMessage(tx, signer, balance, block.Number(), block.BaseFee(), config)
		if err != nil {
			t.Fatalf("failed to build the message of transaction %d: %v", i, err)
		}
		statedb.SetTxContext(tx.Hash(), i)
		receipt, _, _, err := core.ApplyTransactionWithEVM(msg, new(core.GasPool).AddGas(msg.GasLimit), statedb, block.Number(), block.Hash(), tx, &usedGas, evm, balance)
		if err != nil {
			t.Fatalf("replay of transaction %d failed: %v", i, err)
		}
		receipts = append(receipts, receipt)
		roots = append(roots, statedb.IntermediateRoot(config.IsEIP158(block.Number())))
	}
	// Apply the block level finalisation (e.g. the block reward) on top of the last
	// transaction, exactly like chain generation does, and check the result against the
	// root the block carries. Without this the expectation would only prove that the two
	// replay paths agree with each other.
	final, err := backend.engine.Finalize(backend.chain, block.Header(), statedb, statedb.Copy(), block.Transactions(), block.Uncles(), receipts)
	if err != nil {
		t.Fatalf("failed to finalise the replayed block: %v", err)
	}
	if final.Root() != block.Root() {
		t.Fatalf("replayed block root %x does not match the block root %x", final.Root(), block.Root())
	}
	return roots
}

// TestIntermediateRootsMatchesBlockProcessing verifies that the pre-state replay behind
// debug_intermediateRoots follows block processing. The block carries a fee paying
// transaction whose fee belongs to the coinbase owner, a transaction to an XDCX system
// address which block processing routes to ApplyEmptyTransaction, and a following
// transaction of the same sender reusing its nonce. It asserts one root per transaction
// and compares every one of them against the root that replaying the same block through
// core.ApplyTransactionWithEVM produces, so the two replay paths cannot agree with each
// other silently; that second path then closes the block the way chain generation does and
// checks the finalised state against the block state root, which is what pins the roots
// both paths report to the chain. Replaying with core.ApplyMessage diverges and fails this
// test.
func TestIntermediateRootsMatchesBlockProcessing(t *testing.T) {
	t.Parallel()

	config := *params.TestChainConfig // TIPXDCXBlock is 0: the receiver fork is active
	config.TIPXDCXReceiverDisableBlock = nil

	accounts := newAccounts(2)
	coinbase := common.HexToAddress("0x000000000000000000000000000000000000c01b")
	owner := common.HexToAddress("0x0000000000000000000000000000000000000b0b")
	tradingState := common.TradingStateAddrBinary

	// Seed the candidate-owner mapping so statedb.GetOwner(coinbase) resolves to owner:
	// block processing credits the block fee to that owner, and the replay must do the same.
	ownerSlot := state.GetLocMappingAtKey(coinbase.Hash(), 1) // slotValidatorMapping["validatorsState"]
	genesis := &core.Genesis{
		Config: &config,
		Alloc: types.GenesisAlloc{
			accounts[0].addr: {Balance: big.NewInt(9000000000000000000)},
			accounts[1].addr: {Balance: big.NewInt(9000000000000000000)},
			common.MasternodeVotingSMCBinary: {
				Storage: map[common.Hash]common.Hash{
					common.BigToHash(ownerSlot): owner.Hash(),
				},
			},
		},
	}
	signer := types.MakeSigner(&config, common.Big1)

	backend := newTestBackend(t, 1, genesis, func(i int, b *core.BlockGen) {
		b.SetCoinbase(coinbase)
		// Pay above the base fee so the block fee is non zero and the owner credit is
		// observable in the state root.
		gasPrice := b.BaseFee()
		if gasPrice == nil {
			gasPrice = big.NewInt(1_000_000_000)
		} else {
			gasPrice = new(big.Int).Add(gasPrice, big.NewInt(1))
		}

		first, err := types.SignTx(types.NewTx(&types.LegacyTx{
			Nonce:    0,
			To:       &tradingState,
			Value:    big.NewInt(1000),
			Gas:      params.TxGas,
			GasPrice: gasPrice,
		}), signer, accounts[0].key)
		if err != nil {
			t.Fatalf("failed to sign the trading transaction: %v", err)
		}
		b.AddTx(first)

		second, err := types.SignTx(types.NewTx(&types.LegacyTx{
			Nonce:    0, // same nonce: the first transaction did not increment it
			To:       &accounts[1].addr,
			Value:    big.NewInt(1000),
			Gas:      params.TxGas,
			GasPrice: gasPrice,
		}), signer, accounts[0].key)
		if err != nil {
			t.Fatalf("failed to sign the following transaction: %v", err)
		}
		b.AddTx(second)
	})
	defer backend.teardown()

	block := backend.chain.GetBlockByNumber(1)
	if block == nil {
		t.Fatal("expected block #1")
	}
	// Guard the premise: without a fee there is nothing for the owner credit to change, and
	// the rest of the test could not tell ApplyMessage from ApplyTransactionWithEVM.
	processed, err := backend.chain.StateAt(block.Root())
	if err != nil {
		t.Fatalf("failed to load the processed state: %v", err)
	}
	if got := processed.GetBalance(owner); got.Sign() == 0 {
		t.Fatalf("block processing credited no fee to the coinbase owner, the test premise does not hold")
	}

	api := NewAPI(backend)
	roots, err := api.IntermediateRoots(context.Background(), block.Hash(), nil)
	if err != nil {
		t.Fatalf("IntermediateRoots failed: %v", err)
	}
	if want := len(block.Transactions()); len(roots) != want {
		t.Fatalf("intermediate roots = %d, want %d (one per transaction)", len(roots), want)
	}

	// Rebuild the same roots with the block processing entry point: the tracer must not
	// produce a different state for any transaction, and the replay checks its own result
	// against block.Root() once the block finalisation has been applied.
	if want := replayIntermediateRoots(t, backend, &config, block); !reflect.DeepEqual(roots, want) {
		t.Fatalf("intermediate roots %x do not match the block processing replay %x", roots, want)
	}
}

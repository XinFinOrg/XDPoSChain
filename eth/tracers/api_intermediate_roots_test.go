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

// intermediateRootsForkCases are the receiver fork settings the intermediate-roots test
// below runs over. The fork decides how block processing handles the transaction sent to
// the XDCX system address, and the replay has to follow it either way: with the fork active
// the transaction is routed to ApplyEmptyTransaction, which neither checks nor increments
// the sender nonce, so the follower reuses nonce 0; without the fork the transaction is an
// ordinary EVM call that bumps the nonce, so the follower carries nonce 1. The base skipped
// such a transaction outright through tx.IsSkipNonceTransaction(), which loses the nonce
// increment the follower relies on once the fork is off and truncates the root list.
var intermediateRootsForkCases = []struct {
	name          string
	tipXDCXBlock  *big.Int
	followerNonce uint64
}{
	{name: "receiver fork active", tipXDCXBlock: common.Big0, followerNonce: 0},
	{name: "receiver fork inactive", tipXDCXBlock: nil, followerNonce: 1},
}

// TestIntermediateRootsMatchesBlockProcessing verifies that the pre-state replay behind
// debug_intermediateRoots follows block processing, over both receiver fork settings. The
// block carries a fee paying transaction whose fee belongs to the coinbase owner, a
// transaction to an XDCX system address, and a following transaction of the same sender. It
// asserts one root per transaction and compares every one of them against the root that
// replaying the same block through core.ApplyTransactionWithEVM produces, so the two replay
// paths cannot agree with each other silently; that second path then closes the block the
// way chain generation does and checks the finalised state against the block state root,
// which is what pins the roots both paths report to the chain. Replaying with
// core.ApplyMessage diverges and fails this test.
func TestIntermediateRootsMatchesBlockProcessing(t *testing.T) {
	t.Parallel()

	for _, tc := range intermediateRootsForkCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			runIntermediateRootsForkCase(t, tc.tipXDCXBlock, tc.followerNonce)
		})
	}
}

// runIntermediateRootsForkCase builds the fixture of one receiver fork setting and compares
// the intermediate roots debug_intermediateRoots reports against a replay through
// core.ApplyTransactionWithEVM.
func runIntermediateRootsForkCase(t *testing.T, tipXDCXBlock *big.Int, followerNonce uint64) {
	t.Helper()

	config := *params.TestChainConfig
	config.TIPXDCXBlock = tipXDCXBlock
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
			Nonce:    followerNonce, // 0 with the receiver fork active, 1 without it
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

// TestIntermediateRootsMatchesBlockProcessingForASignTransaction verifies that a block
// carrying a transaction to common.BlockSignersBinary is replayed through the same entry
// point as block processing instead of being executed as an ordinary EVM transaction. Once
// TIPSigning is active block processing routes such a transaction to ApplySignTransaction,
// which finalises the pending state and bumps the sender nonce but never enters the EVM, so
// the sender is charged no gas and the value is not transferred; the block therefore also
// carries the sender's following transaction at nonce 1, the one that relies on that bump.
// Replaying the sign transaction with core.ApplyMessage instead charges for the gas, moves
// the value and records a fee, which is what makes this case fail rather than merely return
// different roots.
//
// The route itself is not what this case pins: routeTransaction answers block processing and
// the replay alike, so changing that predicate moves both sides together and the comparison
// below would still hold. What it pins is that the tracer goes through that shared entry
// point at all.
func TestIntermediateRootsMatchesBlockProcessingForASignTransaction(t *testing.T) {
	t.Parallel()

	config := *params.TestChainConfig
	accounts := newAccounts(2)
	signer := types.MakeSigner(&config, common.Big1)
	blockSigners := common.BlockSignersBinary

	genesis := &core.Genesis{
		Config: &config,
		Alloc: types.GenesisAlloc{
			accounts[0].addr: {Balance: big.NewInt(9000000000000000000)},
			accounts[1].addr: {Balance: big.NewInt(9000000000000000000)},
		},
	}
	backend := newTestBackend(t, 1, genesis, func(i int, b *core.BlockGen) {
		gasPrice := b.BaseFee()
		if gasPrice == nil {
			gasPrice = big.NewInt(1_000_000_000)
		} else {
			gasPrice = new(big.Int).Add(gasPrice, big.NewInt(1))
		}

		// A transaction to the block signers address: the sign route handles it natively.
		sign, err := types.SignTx(types.NewTx(&types.LegacyTx{
			Nonce:    0,
			To:       &blockSigners,
			Value:    big.NewInt(1000),
			Gas:      params.TxGas,
			GasPrice: gasPrice,
		}), signer, accounts[0].key)
		if err != nil {
			t.Fatalf("failed to sign the transaction to the block signers address: %v", err)
		}
		b.AddTx(sign)

		// The following transaction of the same sender relies on the nonce the sign route
		// bumped, so it carries nonce 1.
		follower, err := types.SignTx(types.NewTx(&types.LegacyTx{
			Nonce:    1,
			To:       &accounts[1].addr,
			Value:    big.NewInt(1000),
			Gas:      params.TxGas,
			GasPrice: gasPrice,
		}), signer, accounts[0].key)
		if err != nil {
			t.Fatalf("failed to sign the following transaction: %v", err)
		}
		b.AddTx(follower)
	})
	defer backend.teardown()

	block := backend.chain.GetBlockByNumber(1)
	if block == nil {
		t.Fatal("expected block #1")
	}
	if !config.IsTIPSigning(block.Number()) {
		t.Fatal("the sign route is not active for this block, the test premise does not hold")
	}
	// Guard the premise from the other side too: block processing must have taken the sign
	// route, which transfers nothing. Executing the same transaction with the EVM would have
	// moved its value to the block signers account.
	processed, err := backend.chain.StateAt(block.Root())
	if err != nil {
		t.Fatalf("failed to load the processed state: %v", err)
	}
	if got := processed.GetBalance(blockSigners); got.Sign() != 0 {
		t.Fatalf("block processing moved %v to the block signers account, it did not take the sign route", got)
	}
	if got := processed.GetNonce(accounts[0].addr); got != 2 {
		t.Fatalf("block processing left the sender nonce at %d, want 2 (one per transaction)", got)
	}

	api := NewAPI(backend)
	roots, err := api.IntermediateRoots(context.Background(), block.Hash(), nil)
	if err != nil {
		t.Fatalf("IntermediateRoots failed: %v", err)
	}
	if want := len(block.Transactions()); len(roots) != want {
		t.Fatalf("intermediate roots = %d, want %d (one per transaction)", len(roots), want)
	}

	// Rebuild the same roots with the block processing entry point, the way the receiver
	// fork cases above do.
	if want := replayIntermediateRoots(t, backend, &config, block); !reflect.DeepEqual(roots, want) {
		t.Fatalf("intermediate roots %x do not match the block processing replay %x", roots, want)
	}
}

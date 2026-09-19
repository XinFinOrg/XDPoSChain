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
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// blockProcessingRoots rebuilds the per-transaction state roots of a block with the
// block processing entry point, giving the tracer result an expectation to be matched
// against that comes from a path other than the one under test. The roots it returns are
// the ones the transactions leave behind, taken before the block level finalisation, so
// the last of them is not block.Root(): finalisation still credits the block reward on
// top of it. The helper covers that step separately, closing the block the way chain
// generation does and checking that finalised state against the block root, and it is
// that check which pins the returned roots to the chain.
func blockProcessingRoots(t *testing.T, backend *testBackend, config *params.ChainConfig, block *types.Block) []common.Hash {
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
	core.ApplyTIPSigningHardFork(config, statedb, block.Number())
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

// TestIntermediateRootsMatchesBlockProcessingAtTIPSigningActivation verifies that
// debug_intermediateRoots replays the block level state changes block processing performs
// before the first transaction of a block. TIPSigning removes the legacy block signers
// account at its activation block, and a replay that starts from the parent state without
// removing it reports intermediate roots of a state the chain never had.
//
// The fixture pins its premise twice: the account is in the parent state (otherwise
// removing it would change nothing and the test could not tell a correct replay from a
// diverging one) and it is gone from the state the imported block carries, which is the
// state block processing produced. The expectation then comes from
// blockProcessingRoots, which mirrors block processing and checks its own finalised
// state against block.Root(), so the two replay paths cannot agree with each other
// silently.
func TestIntermediateRootsMatchesBlockProcessingAtTIPSigningActivation(t *testing.T) {
	t.Parallel()

	legacySigners := common.BlockSignersBinary
	legacySignersBalance := big.NewInt(1234)
	accounts := newAccounts(2)

	config := *params.TestChainConfig
	// TIPSigning is activated in the traced block. Every fork ordered after it moves with
	// it, because the config rejects one taking effect before the forks that follow it.
	// They all become active from the first block, which is what TestChainConfig already
	// describes for them (it activates them at genesis).
	one := func() *big.Int { return big.NewInt(1) }
	config.TIPSigningBlock = one()
	config.TIPRandomizeBlock = one()
	config.TIPIncreaseMasternodesBlock = one()
	config.DenylistBlock = one()
	config.TIPNoHalvingMNRewardBlock = one()
	config.TIPXDCXBlock = one()
	config.TIPXDCXLendingBlock = one()
	config.TIPXDCXCancellationFeeBlock = one()
	config.TIPTRC21FeeBlock = one()
	config.Gas50xBlock = one()
	config.BerlinBlock = one()
	config.LondonBlock = one()
	config.MergeBlock = one()
	config.ShanghaiBlock = one()
	config.EIP1559Block = one()
	config.CancunBlock = one()
	config.PragueBlock = one()
	config.OsakaBlock = one()

	genesis := &core.Genesis{
		Config: &config,
		Alloc: types.GenesisAlloc{
			accounts[0].addr: {Balance: big.NewInt(9000000000000000000)},
			accounts[1].addr: {Balance: big.NewInt(9000000000000000000)},
			legacySigners:    {Balance: legacySignersBalance},
		},
	}
	signer := types.MakeSigner(&config, common.Big1)
	backend := newTestBackend(t, 1, genesis, func(i int, b *core.BlockGen) {
		// Pay above the base fee so the block carries a fee paying transaction whose fee
		// belongs to the coinbase owner: the removal of the account alone would be
		// visible as well, but a block that changes nothing else could not show that the
		// replay keeps up with the state the removal left behind.
		gasPrice := b.BaseFee()
		if gasPrice == nil {
			gasPrice = big.NewInt(1_000_000_000)
		} else {
			gasPrice = new(big.Int).Add(gasPrice, big.NewInt(1))
		}
		for nonce := uint64(0); nonce < 2; nonce++ {
			tx, err := types.SignTx(types.NewTx(&types.LegacyTx{
				Nonce:    nonce,
				To:       &accounts[1].addr,
				Value:    big.NewInt(1000),
				Gas:      params.TxGas,
				GasPrice: gasPrice,
			}), signer, accounts[0].key)
			if err != nil {
				t.Fatalf("failed to sign transaction %d: %v", nonce, err)
			}
			b.AddTx(tx)
		}
	})
	defer backend.teardown()

	block := backend.chain.GetBlockByNumber(1)
	if block == nil {
		t.Fatal("expected block #1")
	}
	parent := backend.chain.GetBlockByNumber(0)
	if parent == nil {
		t.Fatal("expected the genesis block")
	}
	parentState, err := backend.chain.StateAt(parent.Root())
	if err != nil {
		t.Fatalf("failed to load the parent state: %v", err)
	}
	if have := parentState.GetBalance(legacySigners); have.Cmp(legacySignersBalance) != 0 {
		t.Fatalf("the parent state does not hold the legacy block signers account: have %v, want %v", have, legacySignersBalance)
	}
	processedState, err := backend.chain.StateAt(block.Root())
	if err != nil {
		t.Fatalf("failed to load the processed state: %v", err)
	}
	if have := processedState.GetBalance(legacySigners); have.Sign() != 0 {
		t.Fatalf("block processing kept the legacy block signers account: have %v", have)
	}

	want := blockProcessingRoots(t, backend, &config, block)
	api := NewAPI(backend)
	roots, err := api.IntermediateRoots(context.Background(), block.Hash(), nil)
	if err != nil {
		t.Fatalf("failed to trace the intermediate roots: %v", err)
	}
	if len(roots) != len(want) {
		t.Fatalf("wrong number of intermediate roots: have %d, want %d", len(roots), len(want))
	}
	for i := range want {
		if roots[i] != want[i] {
			t.Fatalf("intermediate root %d of the activation block: have %x, want %x", i, roots[i], want[i])
		}
	}
}

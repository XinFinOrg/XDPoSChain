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

package eth

import (
	"context"
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// TestStateAtTransactionRemovesLegacyBlockSignersAtTIPSigningActivation verifies that the
// pre-state stateAtTransaction hands to the tracer runs the block level state changes block
// processing performs before the first transaction of a block. TIPSigning removes the legacy
// block signers account at the block that activates it; debug_traceTransaction and
// debug_traceCall rebuild that block from its parent state through this function, so without
// the removal they run against an account canonical execution had already removed.
//
// The removal is asserted through the state root, not through the in-session balance: the
// removal goes through state.StateDB.DeleteAddress, which only deletes the account from the
// trie and leaves the cached state object readable in the same session (core/state/statedb.go
// DeleteAddress -> deleteStateObject). Rebuilding the state from the root the replay produced
// is therefore the only way to observe the removal from this function's return value.
//
// The fixture pins its premise from both sides: the account is in the parent state (otherwise
// the removal would change nothing) and it is gone from the state the imported block carries,
// which is the state block processing produced.
func TestStateAtTransactionRemovesLegacyBlockSignersAtTIPSigningActivation(t *testing.T) {
	t.Parallel()

	legacySigners := common.BlockSignersBinary
	legacySignersBalance := big.NewInt(1234)

	config := params.TestChainConfig.Clone()
	// TIPSigning is activated in the traced block. Every fork ordered after it moves with
	// it, because the config rejects one taking effect before the forks that follow it.
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
		Config: config,
		Alloc: types.GenesisAlloc{
			testBank:      {Balance: new(big.Int).Mul(big.NewInt(params.Ether), big.NewInt(2))},
			legacySigners: {Balance: legacySignersBalance},
		},
		Difficulty: big.NewInt(1),
	}
	db := rawdb.NewMemoryDatabase()
	engine := ethash.NewFaker()
	chain, err := core.NewBlockChain(db, nil, genesis, engine, vm.Config{})
	if err != nil {
		t.Fatalf("failed to create blockchain: %v", err)
	}
	defer chain.Stop()

	signer := types.MakeSigner(config, common.Big1)
	_, blocks, _ := core.GenerateChainWithGenesis(genesis, engine, 1, func(i int, b *core.BlockGen) {
		gasPrice := b.BaseFee()
		if gasPrice == nil {
			gasPrice = big.NewInt(1_000_000_000)
		}
		tx, err := types.SignTx(types.NewTx(&types.LegacyTx{
			Nonce:    0,
			To:       &testBank,
			Value:    big.NewInt(1),
			Gas:      params.TxGas,
			GasPrice: gasPrice,
		}), signer, testBankKey)
		if err != nil {
			t.Fatalf("failed to sign the transaction: %v", err)
		}
		b.AddTx(tx)
	})
	if _, err := chain.InsertChain(blocks); err != nil {
		t.Fatalf("failed to insert the generated chain: %v", err)
	}
	block := chain.GetBlockByNumber(1)
	if block == nil {
		t.Fatal("expected block #1")
	}
	parent := chain.GetBlockByNumber(0)
	if parent == nil {
		t.Fatal("expected the genesis block")
	}
	// The premise: the legacy account is in the parent state, and block processing removed
	// it from the state the imported block carries.
	parentState, err := chain.StateAt(parent.Root())
	if err != nil {
		t.Fatalf("failed to load the parent state: %v", err)
	}
	if have := parentState.GetBalance(legacySigners); have.Cmp(legacySignersBalance) != 0 {
		t.Fatalf("the parent state does not hold the legacy block signers account: have %v, want %v", have, legacySignersBalance)
	}
	processedState, err := chain.StateAt(block.Root())
	if err != nil {
		t.Fatalf("failed to load the processed state: %v", err)
	}
	if have := processedState.GetBalance(legacySigners); have.Sign() != 0 {
		t.Fatalf("block processing kept the legacy block signers account: have %v", have)
	}

	// The replay behind debug_traceTransaction / debug_traceCall.
	eth := &Ethereum{blockchain: chain, chainDb: db}
	_, _, statedb, release, err := eth.stateAtTransaction(context.Background(), block, 0, 0)
	if release != nil {
		defer release()
	}
	if err != nil {
		t.Fatalf("stateAtTransaction failed: %v", err)
	}
	if statedb == nil {
		t.Fatal("expected the pre-state of the first transaction")
	}
	// The removal goes through DeleteAddress, which only deletes the account from the trie
	// and leaves the cached state object readable in this session, so the replay result is
	// read back through the trie: commit the replayed state and rebuild from its root.
	root, err := statedb.Commit(block.NumberU64(), config.IsEIP158(block.Number()))
	if err != nil {
		t.Fatalf("failed to commit the replayed state: %v", err)
	}
	if err := statedb.Database().TrieDB().Commit(root, false); err != nil {
		t.Fatalf("failed to flush the replayed trie: %v", err)
	}
	rebuilt, err := state.New(root, statedb.Database())
	if err != nil {
		t.Fatalf("failed to rebuild the state from the replayed root: %v", err)
	}
	if have := rebuilt.GetBalance(legacySigners); have.Sign() != 0 {
		t.Fatalf("the pre-state of the TIPSigning activation block still holds the legacy block signers account: have %v", have)
	}
	if rebuilt.Exist(legacySigners) {
		t.Fatal("the pre-state of the TIPSigning activation block still has the legacy block signers account in the trie")
	}
}

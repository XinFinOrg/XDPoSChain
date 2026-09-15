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
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// TestReorgLeavesNewHeadToCaller pins the contract documented on BlockChain.reorg:
// the new head block is not processed there and its canonical markers are written
// by the caller. Handling the head inside reorg as well writes the same markers
// twice and, when it is a gap block, refreshes the masternode set (UpdateM1) twice.
func TestReorgLeavesNewHeadToCaller(t *testing.T) {
	// Create a pristine chain and database
	genDb, _, blockchain, err := newCanonical(ethash.NewFaker(), 0, true)
	if err != nil {
		t.Fatalf("failed to create pristine chain: %v", err)
	}
	defer blockchain.Stop()

	// A canonical chain and a competing fork of the same weight, both rooted at
	// genesis. The fork is stored as a side chain, so the head stays on the
	// canonical chain and the reorg can be triggered by hand below.
	canonical := makeBlockChain(blockchain.chainConfig, blockchain.Genesis(), 2, ethash.NewFaker(), genDb, 10)
	if _, err := blockchain.InsertChain(canonical); err != nil {
		t.Fatalf("failed to insert canonical chain: %v", err)
	}
	fork := makeBlockChain(blockchain.chainConfig, blockchain.Genesis(), 2, ethash.NewFaker(), genDb, 20)
	if _, err := blockchain.InsertChain(fork); err != nil {
		t.Fatalf("failed to insert the fork: %v", err)
	}
	if head := blockchain.CurrentBlock(); head.Hash() != canonical[len(canonical)-1].Hash() {
		t.Fatalf("head moved onto the fork, want it kept as a side chain: have %x, want %x", head.Hash(), canonical[len(canonical)-1].Hash())
	}
	// Run the reorg the way writeBlockWithState does, but stop right before the
	// caller writes the new head.
	oldHead := blockchain.CurrentBlock()
	newHead := fork[len(fork)-1]
	if err := blockchain.reorg(oldHead, newHead.Header()); err != nil {
		t.Fatalf("failed to reorg: %v", err)
	}
	// Every non-head block of the new chain must be canonical...
	for _, block := range fork[:len(fork)-1] {
		if have := rawdb.ReadCanonicalHash(blockchain.db, block.NumberU64()); have != block.Hash() {
			t.Fatalf("canonical hash mismatch at %d: have %x, want %x", block.NumberU64(), have, block.Hash())
		}
	}
	// ...while the new head itself must be left to the caller: the stale marker of
	// the old chain is cleared, and the head is not written here.
	if have := rawdb.ReadCanonicalHash(blockchain.db, newHead.NumberU64()); have != (common.Hash{}) {
		t.Fatalf("reorg left a canonical marker at %d (%x), the caller must write it", newHead.NumberU64(), have)
	}
}

// TestReorgKeepsTheNewHeadTxLookup pins that a reorg does not drop the lookup entries of the
// transactions of the new head. They are rewound on the old chain and kept on the new one,
// so deleting them here and relying on the caller to write them back would leave the index
// inconsistent in between - and a caller that forgets would leave it inconsistent for good.
func TestReorgKeepsTheNewHeadTxLookup(t *testing.T) {
	key, _ := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	genesis := &Genesis{
		Alloc:   types.GenesisAlloc{crypto.PubkeyToAddress(key.PublicKey): {Balance: big.NewInt(1000000000000000)}},
		BaseFee: big.NewInt(params.InitialBaseFee),
		Config:  params.TestChainConfig,
	}
	genDb := rawdb.NewMemoryDatabase()
	if _, err := genesis.Commit(genDb); err != nil {
		t.Fatalf("failed to commit genesis: %v", err)
	}
	engine := ethash.NewFaker()
	blockchain, err := NewBlockChain(rawdb.NewMemoryDatabase(), nil, genesis, engine, vm.Config{})
	if err != nil {
		t.Fatalf("failed to create tester chain: %v", err)
	}
	defer blockchain.Stop()

	tx, err := types.SignTx(
		types.NewTransaction(0, common.Address{1}, common.Big1, params.TxGas, big.NewInt(params.InitialBaseFee), nil),
		types.LatestSignerForChainID(genesis.Config.ChainID), key)
	if err != nil {
		t.Fatalf("failed to sign the transaction: %v", err)
	}
	// Both heads carry the same transaction, so the reorg moves it between two chains that
	// both hold it instead of dropping it.
	canonical, _ := GenerateChain(genesis.Config, genesis.ToBlock(), engine, genDb, 2, func(i int, b *BlockGen) {
		b.SetCoinbase(common.Address{0: byte(i)})
		if i == 1 {
			b.AddTx(tx)
		}
	})
	if _, err := blockchain.InsertChain(canonical); err != nil {
		t.Fatalf("failed to insert the canonical chain: %v", err)
	}
	fork, _ := GenerateChain(genesis.Config, genesis.ToBlock(), engine, genDb, 2, func(i int, b *BlockGen) {
		b.SetCoinbase(common.Address{0: 0x30, 19: byte(i)})
		if i == 1 {
			b.AddTx(tx)
		}
	})
	if _, err := blockchain.InsertChain(fork); err != nil {
		t.Fatalf("failed to insert the fork: %v", err)
	}
	if head := blockchain.CurrentBlock(); head.Hash() != canonical[1].Hash() {
		t.Fatalf("head moved onto the fork, want it kept as a side chain: have %x, want %x", head.Hash(), canonical[1].Hash())
	}
	// Run the reorg the way writeBlockWithState does, stopping before the caller writes the
	// new head: the lookup entry has to be intact already at that point.
	if err := blockchain.reorg(blockchain.CurrentBlock(), fork[1].Header()); err != nil {
		t.Fatalf("failed to reorg: %v", err)
	}
	if entry := rawdb.ReadTxLookupEntry(blockchain.ChainDb(), tx.Hash()); entry == nil {
		t.Fatal("the reorg dropped the new head's transaction from the lookup table")
	}
}

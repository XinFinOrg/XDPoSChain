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
	"time"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// TestReorgLeavesNewHeadToCaller pins the contract documented on BlockChain.reorg: the new head
// block is not processed there and its canonical markers are written by the caller. Handling the
// head inside reorg too would write the same markers twice and refresh the masternode set
// (UpdateM1) twice for a gap block.
func TestReorgLeavesNewHeadToCaller(t *testing.T) {
	// Create a pristine chain and database
	genDb, _, blockchain, err := newCanonical(ethash.NewFaker(), 0, true)
	if err != nil {
		t.Fatalf("failed to create pristine chain: %v", err)
	}

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
	closeAfterReorg(t, blockchain, newHead)
	if _, _, err := blockchain.reorg(oldHead, newHead.Header()); err != nil {
		t.Fatalf("failed to reorg: %v", err)
	}
	// Every non-head block of the new chain must be canonical...
	for _, block := range fork[:len(fork)-1] {
		if have := rawdb.ReadCanonicalHash(blockchain.db, block.NumberU64()); have != block.Hash() {
			t.Fatalf("canonical hash mismatch at %d: have %x, want %x", block.NumberU64(), have, block.Hash())
		}
	}
	// ...while the new head itself is left to the caller: the stale marker of the old chain is
	// cleared, the head is not written here, and the in-memory head must not have been moved onto
	// it either. A marker check cannot see that last part: the stale-marker sweep clears the new
	// head's number whether or not reorg processed the block.
	if head := blockchain.CurrentBlock(); head.Hash() == newHead.Hash() {
		t.Fatalf("reorg moved the in-memory head onto the new head %d, the caller must write it", newHead.NumberU64())
	}
	if have := rawdb.ReadCanonicalHash(blockchain.db, newHead.NumberU64()); have != (common.Hash{}) {
		t.Fatalf("reorg left a canonical marker at %d (%x), the caller must write it", newHead.NumberU64(), have)
	}
}

// TestReorgKeepsTheNewHeadTxLookup pins that a reorg does not drop the lookup entries of the new
// head's transactions. They are rewound on the old chain and kept on the new one, so deleting them
// here and relying on the caller to write them back would leave the index inconsistent in between.
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
	closeAfterReorg(t, blockchain, fork[1])
	// Run the reorg the way writeBlockWithState does, stopping before the caller writes the
	// new head: the lookup entry has to be intact already at that point.
	if _, _, err := blockchain.reorg(blockchain.CurrentBlock(), fork[1].Header()); err != nil {
		t.Fatalf("failed to reorg: %v", err)
	}
	if entry := rawdb.ReadTxLookupEntry(blockchain.ChainDb(), tx.Hash()); entry == nil {
		t.Fatal("the reorg dropped the new head's transaction from the lookup table")
	}
}

// TestReorgTxLookupLockCoversHeadWrite pins that the reorg's write lock is still held when the
// head write restores the canonical marker the reorg deleted. A reader admitted in between would
// resolve a lookup retained from a transaction both heads carry against a missing marker and read
// nil for a transaction the node still serves as canonical.
func TestReorgTxLookupLockCoversHeadWrite(t *testing.T) {
	var (
		key, _  = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		address = crypto.PubkeyToAddress(key.PublicKey)
		emitter = common.HexToAddress("0x0000000000000000000000000000000000000010")
		gspec   = &Genesis{
			Config: &params.ChainConfig{
				ChainID:        big.NewInt(1338),
				HomesteadBlock: new(big.Int),
				Ethash:         new(params.EthashConfig),
			},
			Alloc: types.GenesisAlloc{
				address: {Balance: big.NewInt(params.Ether)},
				emitter: {Code: []byte{0x60, 0x00, 0x60, 0x00, 0xa0, 0x00}},
			},
			Difficulty: big.NewInt(1),
		}
	)
	// The full faker accepts the higher difficulty below, which the generator's own rule would
	// reject; XDPoS v1 gets the same shape from its turn-based difficulty.
	engine := ethash.NewFullFaker()
	genDb := rawdb.NewMemoryDatabase()
	if _, err := gspec.Commit(genDb); err != nil {
		t.Fatalf("failed to commit genesis: %v", err)
	}
	newTx := func(nonce, value int64) *types.Transaction {
		tx, err := types.SignTx(types.NewTransaction(uint64(nonce), emitter, big.NewInt(value), 100000, big.NewInt(1), nil), types.HomesteadSigner{}, key)
		if err != nil {
			t.Fatalf("failed to sign the transaction: %v", err)
		}
		return tx
	}
	bc, err := NewBlockChain(rawdb.NewMemoryDatabase(), nil, gspec, engine, vm.Config{})
	if err != nil {
		t.Fatalf("failed to create chain: %v", err)
	}
	canonical, _ := GenerateChain(gspec.Config, bc.Genesis(), engine, genDb, 4, func(i int, b *BlockGen) {
		b.AddTx(newTx(int64(i), int64(i)+1))
	})
	// One competing block on the canonical head's parent, carrying the same transaction as the
	// head. The extra difficulty makes it outrank the head at the same height, so the import
	// takes the writeBlockWithState -> adoptHead path instead of stopping at the side chain.
	fork, _ := GenerateChain(gspec.Config, canonical[2], engine, genDb, 1, func(i int, b *BlockGen) {
		b.SetCoinbase(common.Address{0: 0x02})
		b.AddTx(newTx(3, 4))
	})
	if fork[0].Transactions()[0].Hash() != canonical[3].Transactions()[0].Hash() {
		t.Fatal("test setup: the fork block does not carry the head's transaction")
	}
	forkHead := fork[0].Header()
	forkHead.Difficulty = new(big.Int).Add(canonical[3].Difficulty(), common.Big1)
	fork[0] = fork[0].WithSeal(forkHead)

	if _, err := bc.InsertChain(canonical); err != nil {
		t.Fatalf("failed to insert the canonical chain: %v", err)
	}
	tx := canonical[3].Transactions()[0]
	if got, hash, num, _ := bc.ReadTransaction(tx.Hash()); got == nil || hash != canonical[3].Hash() || num != 4 {
		t.Fatal("test setup: the transaction is not readable at the canonical head")
	}

	entered := make(chan struct{})
	release := make(chan struct{})
	insertDone := make(chan struct{})
	testHookAfterReorg = func() {
		close(entered)
		<-release
	}
	defer func() {
		testHookAfterReorg = nil
		select {
		case <-release:
		default:
			close(release)
		}
		select {
		case <-insertDone:
		case <-time.After(5 * time.Second):
		}
		bc.Stop()
	}()

	insertErr := make(chan error, 1)
	go func() {
		defer close(insertDone)
		_, err := bc.InsertChain(types.Blocks{fork[0]})
		insertErr <- err
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the import never reached the window between the reorg and the head write")
	}
	// The cleanup batch has run: the head's canonical marker is gone while the lookup entry is
	// retained, and the node still serves the old head.
	if head := bc.CurrentBlock(); head.Hash() != canonical[3].Hash() {
		t.Fatalf("head moved before the head write: have %x, want %x", head.Hash(), canonical[3].Hash())
	}
	if have := rawdb.ReadCanonicalHash(bc.db, 4); have != (common.Hash{}) {
		t.Fatalf("canonical marker at 4 still present: %x", have)
	}
	if entry := rawdb.ReadTxLookupEntry(bc.db, tx.Hash()); entry == nil || *entry != 4 {
		t.Fatalf("lookup entry moved before the head write: %v", entry)
	}
	// The lock has to cover the head write: a successful read lock here would admit the reader
	// into exactly the window above.
	if bc.txLookupLock.TryRLock() {
		bc.txLookupLock.RUnlock()
		t.Fatal("the lookup lock is not held across the head write")
	}
	resumed := make(chan struct{})
	go func() {
		bc.ReadTransaction(tx.Hash())
		close(resumed)
	}()
	select {
	case <-resumed:
		t.Fatal("a transaction lookup returned inside the reorg-to-head-write window")
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	select {
	case err := <-insertErr:
		if err != nil {
			t.Fatalf("failed to insert the fork head: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the import did not finish after the head write")
	}
	select {
	case <-resumed:
	case <-time.After(5 * time.Second):
		t.Fatal("the transaction lookup did not resume after the head write")
	}
	if got, hash, num, _ := bc.ReadTransaction(tx.Hash()); got == nil || hash != fork[0].Hash() || num != 4 {
		t.Fatal("the transaction is not readable at the adopted head")
	}
}

// closeAfterReorg stops the chain in the state the reorg contract leaves it: the reorg has run and
// the caller has not written the new head yet. Stop cannot work from it, because saveData resolves
// the head by number while its canonical marker is gone, so it panics on a nil block, and a panic
// raised in cleanup buries whatever the test asserted. Writing the caller's half first keeps the
// assertions readable on the passing and failing paths alike. See BlockChain.reorg.
func closeAfterReorg(t *testing.T, chain *BlockChain, newHead *types.Block) {
	t.Helper()
	t.Cleanup(func() {
		if have := rawdb.ReadCanonicalHash(chain.db, newHead.NumberU64()); have != newHead.Hash() {
			chain.writeHeadBlock(newHead, nil)
		}
		chain.Stop()
	})
}

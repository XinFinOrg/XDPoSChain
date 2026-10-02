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
	"errors"
	"math/big"
	"sync/atomic"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/ethdb"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// trieRefusingDB hands out batches whose write is refused once the batch carries a trie node,
// so that a commit this node's own trie database refuses can be driven without a real disk
// failing. A trie node is stored under its own hash and nothing else in this chain is: a
// block, its body, its receipts, its total difficulty and its preimages are all written under
// a prefix, so a bare 32-byte key is what tells the two apart.
//
// The distinction is what keeps the refusal off the block batch of writeBlockWithState. That
// batch is what makes the block, its receipts and its total difficulty land together, and a
// failure of it is a log.Crit rather than an error: refusing it would take the test process
// down with it instead of failing the case.
type trieRefusingDB struct {
	ethdb.Database
	refuse atomic.Bool
}

func (db *trieRefusingDB) NewBatch() ethdb.Batch {
	return &trieRefusingBatch{Batch: db.Database.NewBatch(), refuse: &db.refuse}
}

type trieRefusingBatch struct {
	ethdb.Batch
	refuse *atomic.Bool
	trie   bool
}

func (b *trieRefusingBatch) Put(key []byte, value []byte) error {
	if len(key) == common.HashLength {
		b.trie = true
	}
	return b.Batch.Put(key, value)
}

func (b *trieRefusingBatch) Reset() {
	b.trie = false
	b.Batch.Reset()
}

func (b *trieRefusingBatch) Write() error {
	if b.refuse.Load() && b.trie {
		return errRefusedWrite
	}
	return b.Batch.Write()
}

// TestInsertChainReportsARefusedCommitAsLocal covers a state or trie commit this node's own
// trie database refuses while a block is being written. The block has been executed and
// validated by then, so the failure says nothing about it and nothing about the peer that
// served it: reported as it came out of the commit it was classified as the block's fault,
// and the downloader dropped that peer for it. The cause is kept by wrapping, so an operator
// still reads what the database answered.
//
// An archive node is what makes the commit reachable: it flushes the trie of every block it
// writes, where a full node leaves the nodes in memory until the garbage collector gets to
// them. The commit of the block itself is not the only one the refusal could land on - the
// trading and lending state commits and the state commit are wrapped for the same reason -
// and the case does not claim to tell them apart: all four are this node's own writes.
func TestInsertChainReportsARefusedCommitAsLocal(t *testing.T) {
	var (
		key, _  = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		address = crypto.PubkeyToAddress(key.PublicKey)
		gspec   = &Genesis{
			Alloc:   types.GenesisAlloc{address: {Balance: big.NewInt(1000000000000000)}},
			BaseFee: big.NewInt(params.InitialBaseFee),
			Config:  params.TestChainConfig,
		}
	)
	db := &trieRefusingDB{Database: rawdb.NewMemoryDatabase()}
	_, blocks, _ := GenerateChainWithGenesis(gspec, ethash.NewFaker(), 2, nil)
	chain, err := NewBlockChain(db, &CacheConfig{TrieDirtyDisabled: true}, gspec, ethash.NewFaker(), vm.Config{})
	if err != nil {
		t.Fatalf("failed to create chain: %v", err)
	}
	defer chain.Stop()
	defer db.refuse.Store(false)

	db.refuse.Store(true)

	n, err := chain.InsertChain(blocks[:1])
	if !errors.Is(err, errRefusedWrite) {
		t.Fatalf("block %d: a refused commit must be reported with its cause, have %v", n, err)
	}
	if !errors.Is(err, ErrLocalInsertCondition) {
		t.Fatalf("block %d: a commit this node refused is a local condition, have %v", n, err)
	}
	if !IsLocalInsertError(err) {
		t.Fatalf("a commit this node refused must not be blamed on the peer: %v", err)
	}
	// The block was written before its commit was asked for, but the head is only ever moved
	// together with the state it points at, so it stays on the genesis it started from.
	if head := chain.CurrentBlock().Number.Uint64(); head != 0 {
		t.Fatalf("the head moved to #%d while the commit of #1 was refused", head)
	}
}

// TestInsertChainLeavesNoMarkerBehindARefusedCommit covers what the refused commit above leaves
// on the block it was writing. The block itself, its receipts and its total difficulty are
// written before the state is committed, so they are on disk; the marker of an execution is not,
// because it is written once every commit of writeBlockWithState has succeeded.
//
// Written together with the block instead, the marker survived the refusal, and the next
// delivery of that block was answered as known: writeKnownBlock adopted it and moved the head
// onto a state this node never persisted, which nothing would have written afterwards. The
// marker being absent is what sends that delivery through execution again.
func TestInsertChainLeavesNoMarkerBehindARefusedCommit(t *testing.T) {
	var (
		key, _  = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		address = crypto.PubkeyToAddress(key.PublicKey)
		gspec   = &Genesis{
			Alloc:   types.GenesisAlloc{address: {Balance: big.NewInt(1000000000000000)}},
			BaseFee: big.NewInt(params.InitialBaseFee),
			Config:  params.TestChainConfig,
		}
	)
	db := &trieRefusingDB{Database: rawdb.NewMemoryDatabase()}
	_, blocks, _ := GenerateChainWithGenesis(gspec, ethash.NewFaker(), 2, nil)
	chain, err := NewBlockChain(db, &CacheConfig{TrieDirtyDisabled: true}, gspec, ethash.NewFaker(), vm.Config{})
	if err != nil {
		t.Fatalf("failed to create chain: %v", err)
	}
	defer chain.Stop()
	defer db.refuse.Store(false)

	target := blocks[0]
	db.refuse.Store(true)
	if _, err := chain.InsertChain(types.Blocks{target}); !errors.Is(err, ErrLocalInsertCondition) {
		t.Fatalf("the commit of #%d must be reported as refused, have %v", target.NumberU64(), err)
	}
	// The block went to disk before the commit that was refused: only the marker is missing.
	if !chain.HasBlock(target.Hash(), target.NumberU64()) {
		t.Fatal("the block must be on disk, it is written before its state is committed")
	}
	if rawdb.HasExecutedMarker(chain.ChainDb(), target.Hash(), target.NumberU64()) {
		t.Fatal("a refused commit must not leave the marker of an execution behind")
	}
	if chain.HasExecutedBlock(target.Hash(), target.NumberU64()) {
		t.Fatal("a block whose commit this node refused must not count as executed")
	}
	// A delivery of it therefore cannot be adopted: the head moves only by running it, which
	// is what the second delivery below does with the refusal gone.
	db.refuse.Store(false)
	if _, err := chain.InsertChain(types.Blocks{target}); err != nil {
		t.Fatalf("re-delivering the block must not fail once the database accepts the write: %v", err)
	}
	if !rawdb.HasExecutedMarker(chain.ChainDb(), target.Hash(), target.NumberU64()) {
		t.Fatal("running the block is what writes the marker, and it must be there afterwards")
	}
	if head := chain.CurrentBlock(); head.Hash() != target.Hash() {
		t.Fatalf("the head must be the block that was run again, have #%d %s", head.Number.Uint64(), head.Hash())
	}
}

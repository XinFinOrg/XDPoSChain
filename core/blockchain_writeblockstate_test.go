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

	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// TestWriteBlockWithStateReportsAMissingHeadTdBeforeWriting covers when the head's total
// difficulty is read: before the block, its receipts and its state are written, not after.
// The import reports a failure either way, so only the write itself tells the two orders
// apart - and a block left on disk for an import that reported failure is a state the next
// attempt has to recognise before it can make any progress.
//
// The block being imported comes from a sibling branch, because the head's total difficulty
// and the parent's have to be different records for this to say anything: on a single chain
// the block after the head has the head as its parent, so the parent lookup - which is read
// before anything is written either way - fails first and the order under test never runs.
func TestWriteBlockWithStateReportsAMissingHeadTdBeforeWriting(t *testing.T) {
	key, _ := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	address := crypto.PubkeyToAddress(key.PublicKey)
	gspec := &Genesis{
		Alloc:   types.GenesisAlloc{address: {Balance: big.NewInt(1000000000000000)}},
		BaseFee: big.NewInt(params.InitialBaseFee),
		Config:  params.TestChainConfig,
	}
	// The canonical chain, imported in full, and a sibling branch sharing its genesis and
	// its first block while stamping a different extra data on its second.
	_, canonical, _ := GenerateChainWithGenesis(gspec, ethash.NewFaker(), 6, nil)
	_, fork, _ := GenerateChainWithGenesis(gspec, ethash.NewFaker(), 6, func(i int, gen *BlockGen) {
		if i == 1 {
			gen.SetExtra([]byte("fork"))
		}
	})
	if fork[0].Hash() != canonical[0].Hash() {
		t.Fatal("precondition: the branches must share their first block")
	}

	chain, err := NewBlockChain(rawdb.NewMemoryDatabase(), nil, gspec, ethash.NewFaker(), vm.Config{})
	if err != nil {
		t.Fatalf("failed to create tester chain: %v", err)
	}
	t.Cleanup(chain.Stop)
	if _, err := chain.InsertChain(canonical); err != nil {
		t.Fatalf("failed to insert the canonical chain: %v", err)
	}

	// Drop the head's record the way a pruned or truncated database would, cache included.
	// The record of the parent the fork block links to is left in place, so the parent lookup
	// the import performs first still succeeds.
	head := chain.CurrentBlock()
	rawdb.DeleteTd(chain.ChainDb(), head.Hash(), head.Number.Uint64())
	chain.hc.tdCache.Remove(head.Hash())

	target := fork[1]
	if target.ParentHash() != canonical[0].Hash() {
		t.Fatal("precondition: the fork block must link to a block this node holds")
	}
	_, err = chain.InsertChain(types.Blocks{target})
	if err == nil {
		t.Fatal("an import must fail while the head's total difficulty cannot be read")
	}
	if !IsLocalInsertError(err) {
		t.Fatalf("a record missing in this node must not be blamed on the blocks: %v", err)
	}
	if chain.HasBlock(target.Hash(), target.NumberU64()) {
		t.Fatal("the failing import wrote the block before reading the head's total difficulty")
	}
}

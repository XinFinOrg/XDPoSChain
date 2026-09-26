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
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// TestInsertSideChainReportsMissingParentTd covers the guard around the total difficulty the
// scan accumulates onto. big.Int.Add dereferences its operands, so a parent whose record is
// not stored used to panic in the middle of an import instead of failing the call. The record
// is missing in this node rather than wrong in the block, so the failure is reported as a
// local condition - the same answer getResultBlock gives for the same read, and the one that
// keeps the peer out of it.
//
// The block that stopped the scan is not written to disk - the record is checked before the
// accumulation and before the write - and the index handed back is that block's, so a caller
// carries on from it rather than from one past it.
func TestInsertSideChainReportsMissingParentTd(t *testing.T) {
	chain, blocks, engine, genDb := newPrunedCanonicalChain(t)

	// A fork reached from a canonical block whose record is dropped below, so the scan
	// accumulates onto a total difficulty this node no longer holds.
	lastPrunedIndex := len(blocks) - TriesInMemory - 1
	parent := blocks[lastPrunedIndex]
	fork, _ := GenerateChain(params.TestChainConfig, parent, engine, genDb, 2*TriesInMemory, func(i int, b *BlockGen) {
		b.SetCoinbase(common.Address{2})
	})
	rawdb.DeleteTd(chain.ChainDb(), parent.Hash(), parent.NumberU64())
	chain.hc.tdCache.Remove(parent.Hash())
	if td := chain.GetTd(parent.Hash(), parent.NumberU64()); td != nil {
		t.Fatalf("precondition: the parent record must be gone, have %v", td)
	}

	head := chain.CurrentBlock()
	n, err := chain.InsertChain(fork)
	if err == nil {
		t.Fatalf("block %d: a parent without a total difficulty must be reported", n)
	}
	if !errors.Is(err, ErrLocalInsertCondition) {
		t.Fatalf("unexpected error: have %v want %v", err, ErrLocalInsertCondition)
	}
	if !IsLocalInsertError(err) {
		t.Fatalf("a record missing in this node must not be blamed on the blocks: %v", err)
	}
	if want := 0; n != want {
		t.Fatalf("unexpected failing index: have %d want %d", n, want)
	}
	if chain.HasBlock(fork[0].Hash(), fork[0].NumberU64()) {
		t.Fatal("the block that stopped the scan must not be written to disk")
	}
	if want := head.Number.Uint64(); chain.CurrentBlock().Number.Uint64() != want {
		t.Fatalf("unexpected head number: have %d want %d", chain.CurrentBlock().Number.Uint64(), want)
	}
}

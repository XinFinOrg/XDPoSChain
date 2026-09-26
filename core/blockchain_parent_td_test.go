// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, but WITHOUT ANY WARRANTY; without even
// the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package core

import (
	"errors"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
)

// TestParentTdReportsMissingTotalDifficulty covers the guard around the parent's total
// difficulty: the block that reaches writeBlockWithState has a parent whose header the
// verifiers have already asked for, so a nil there is this node no longer holding the
// parent's record and not an ancestor it does not know. Reporting it as ErrUnknownAncestor
// hands the downloader a failure it turns into errInvalidChain, and drops the peer that
// served a batch this node cannot import - with every peer after it, since the record no
// peer can supply is the one that is missing.
func TestParentTdReportsMissingTotalDifficulty(t *testing.T) {
	chain, blocks := newInsertChainTester(t, nil, 6, 5) // head at #5

	// A block whose parent is below the head: the head's own record stays in place, so the
	// parent's is the only one the import can fail on.
	parent := blocks[3]
	// GenerateChain executes on top of the parent's state, which it has to read out of the
	// database it is handed: the chain's own trie database still holds it in memory, so it
	// goes to disk first.
	if err := chain.triedb.Commit(parent.Root(), false); err != nil {
		t.Fatalf("precondition: failed to flush the parent state: %v", err)
	}
	// The extra data is what makes the fork a block of its own: without it the generated
	// block is byte for byte the #5 the chain already holds, and the import would answer
	// ErrKnownBlock instead of reaching the read this covers.
	fork, _ := GenerateChain(chain.chainConfig, parent, chain.engine, chain.db, 1, func(i int, b *BlockGen) {
		b.SetExtra([]byte("fork of #4"))
	})

	// Drop the record the way a pruned or truncated database would, cache included.
	rawdb.DeleteTd(chain.ChainDb(), parent.Hash(), parent.NumberU64())
	chain.hc.tdCache.Remove(parent.Hash())

	_, err := chain.InsertChain(fork)
	if err == nil {
		t.Fatal("a block whose parent has no total difficulty must not be imported")
	}
	if !errors.Is(err, ErrLocalInsertCondition) {
		t.Fatalf("unexpected error: have %v want %v", err, ErrLocalInsertCondition)
	}
	if errors.Is(err, consensus.ErrUnknownAncestor) {
		t.Fatalf("a parent this node holds must not be reported as an unknown ancestor: %v", err)
	}
	// What the downloader asks: a local condition is one it must not blame the peer for.
	if !IsLocalInsertError(err) {
		t.Fatalf("a record missing in this node must not be blamed on the blocks: %v", err)
	}
}

// TestParentTdKeepsAnUnknownAncestorUnknown pins the other half of the same guard: a parent
// this node does not hold at all is still the peer's to answer for, so splitting the two
// reads must not turn every unlinkable batch into a local condition.
func TestParentTdKeepsAnUnknownAncestorUnknown(t *testing.T) {
	chain, blocks := newInsertChainTester(t, nil, 6, 5) // head at #5

	parent := blocks[3] // #4, below the head: the head itself stays readable throughout
	if err := chain.triedb.Commit(parent.Root(), false); err != nil {
		t.Fatalf("precondition: failed to flush the parent state: %v", err)
	}
	fork, _ := GenerateChain(chain.chainConfig, parent, chain.engine, chain.db, 1, func(i int, b *BlockGen) {
		b.SetExtra([]byte("orphan of #5"))
	})
	// Both records go, so the parent is a block this node does not hold at all - the case
	// that has to stay answerable by the peer that served it.
	rawdb.DeleteTd(chain.ChainDb(), parent.Hash(), parent.NumberU64())
	chain.hc.tdCache.Remove(parent.Hash())
	rawdb.DeleteHeader(chain.ChainDb(), parent.Hash(), parent.NumberU64())
	chain.hc.headerCache.Remove(parent.Hash())

	_, err := chain.InsertChain(fork)
	if err == nil {
		t.Fatal("a block whose parent is not stored must not be imported")
	}
	if !errors.Is(err, consensus.ErrUnknownAncestor) {
		t.Fatalf("unexpected error: have %v want %v", err, consensus.ErrUnknownAncestor)
	}
	if IsLocalInsertError(err) {
		t.Fatalf("a parent this node does not hold is not a condition of its own: %v", err)
	}
}

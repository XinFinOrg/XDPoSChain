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

	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
)

// TestWriteKnownBlockReportsAnInconsistentChain pins the sentinel an adoption that has to
// reorganise hands up when the reorg itself fails on a record of this node's own chain.
// reorg reports errInvalidOldChain/errInvalidNewChain when it walks a chain and does not find
// a record, which is this node's chain disagreeing with itself rather than anything about the
// blocks it was handed. Folding that into ErrLocalInsertRefused - the sentinel for a reorg
// this node refuses - would leave the wrapper behind and lose which of the two conditions
// this node is in: the class table reads both as local, but DescribeLocalInsertFailure answers
// "the local chain is inconsistent" for one and "cannot be imported" for the other, and only
// the first tells an operator to repair the node instead of re-running the same file.
func TestWriteKnownBlockReportsAnInconsistentChain(t *testing.T) {
	genDb, _, blockchain, err := newCanonical(ethash.NewFaker(), 0, true)
	if err != nil {
		t.Fatalf("failed to create pristine chain: %v", err)
	}
	defer blockchain.Stop()

	canonical := makeBlockChain(blockchain.chainConfig, blockchain.Genesis(), 10, ethash.NewFaker(), genDb, 10)
	if _, err := blockchain.InsertChain(canonical); err != nil {
		t.Fatalf("failed to insert canonical chain: %v", err)
	}
	fork := makeBlockChain(blockchain.chainConfig, blockchain.Genesis(), 10, ethash.NewFaker(), genDb, 20)
	if _, err := blockchain.InsertChain(fork); err != nil {
		t.Fatalf("failed to insert the fork: %v", err)
	}
	// Roll the head below the fork point so the first re-imported known block sits off the
	// head and has to reorganise, exactly as TestWriteKnownBlockReorgsToKnownFork does.
	rewindHeadMarkers(blockchain, canonical[2])
	head := blockchain.CurrentBlock()

	// Drop one header of the canonical chain's own walk: below the head and above the fork
	// point. reorg reduces both chains to the common ancestor before it rewrites anything, so
	// the first read it cannot answer is #2's, and that read is what the sentinel is for. The
	// header is cached - the imports above read it - so the cache is dropped as well,
	// otherwise the cache and not the database would be what the assertion reads.
	missing := canonical[1]
	rawdb.DeleteHeader(blockchain.db, missing.Hash(), missing.NumberU64())
	blockchain.hc.headerCache.Purge()

	n, err := blockchain.InsertChain(fork[3:])
	if !errors.Is(err, errInvalidOldChain) {
		t.Fatalf("an unreadable record of this node's own chain must be reported as such: have %v (index %d)", err, n)
	}
	if errors.Is(err, ErrLocalInsertRefused) {
		t.Fatalf("a chain that disagrees with itself is not a reorg this node refused: %v", err)
	}
	if !IsLocalInsertError(err) {
		t.Fatalf("a record this node is missing says nothing about the peer that served the batch: %v", err)
	}
	if reason, ok := DescribeLocalInsertFailure(err); !ok || reason != "the local chain is inconsistent" {
		t.Fatalf("the operator has to be told which condition this is: have %q, ok=%v", reason, ok)
	}
	if now := blockchain.CurrentBlock(); now.Hash() != head.Hash() {
		t.Fatalf("head moved to %d, want it kept at %d", now.Number.Uint64(), head.Number.Uint64())
	}
}

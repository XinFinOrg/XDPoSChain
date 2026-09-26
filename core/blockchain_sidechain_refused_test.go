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
	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/params"
)

func TestInsertSideChainReportsRefusedReorgAsLocal(t *testing.T) {
	chain, blocks, engine, genDb := newPrunedCanonicalChain(t)

	// A fork started below the state window and kept short, so the segment stays lighter
	// than the head and the reorg is refused.
	lastPruned := blocks[TriesInMemory-1]
	fork, _ := GenerateChain(params.TestChainConfig, lastPruned, engine, genDb, 2, func(i int, b *BlockGen) {
		b.SetCoinbase(common.Address{2})
	})
	// The scan stops on its second block with an error the segment cannot be linked from,
	// which is the shape of a segment that ran out of numbers to import.
	batch := types.Blocks{fork[0], blocks[len(blocks)-1]}
	results := make(chan error, len(batch))
	results <- consensus.ErrPrunedAncestor
	results <- consensus.ErrUnknownAncestor
	it := newInsertIterator(batch, results, chain.validator)
	block, verr := it.next()
	if !errors.Is(verr, consensus.ErrPrunedAncestor) {
		t.Fatalf("unexpected verification result: have %v want %v", verr, consensus.ErrPrunedAncestor)
	}

	head := chain.CurrentBlock()
	_, _, _, err := chain.insertSideChain(block, it, true)
	if !errors.Is(err, ErrLocalInsertRefused) {
		t.Fatalf("unexpected error: have %v want %v", err, ErrLocalInsertRefused)
	}
	if !IsLocalInsertError(err) {
		t.Fatalf("a reorg this node refuses says nothing about the peer: %v", err)
	}
	if classifyInsertErr(err).retryable {
		t.Fatalf("a refused reorg is refused again on every retry: %v", err)
	}
	if now := chain.CurrentBlock(); now.Hash() != head.Hash() {
		t.Fatalf("head moved to %d, want it kept at %d", now.Number.Uint64(), head.Number.Uint64())
	}
}

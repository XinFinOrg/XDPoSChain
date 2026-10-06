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
	"testing"

	"github.com/XinFinOrg/XDPoSChain/consensus"
)

func TestInsertSideChainKeepsTheHeadWhenTheSegmentDoesNotBeatIt(t *testing.T) {
	chain, blocks := newInsertChainTester(t, nil, 5, 5) // everything is on disk, head at #5

	batch := blocks[2:5] // #3, #4 and #5, all of them canonical and already the head's ancestors
	validator := &knownBlockSegmentValidator{
		BlockValidator: chain.validator.(*BlockValidator),
		bodyErrors:     map[uint64]error{batch[1].NumberU64(): ErrKnownBlock},
	}
	results := make(chan error, len(batch))
	results <- consensus.ErrPrunedAncestor
	for i := 1; i < len(batch); i++ {
		results <- nil
	}
	it := newInsertIterator(batch, results, validator)
	head := chain.CurrentBlock()

	if _, _, _, err := chain.insertSideChain(batch[0], it, true); err != nil {
		t.Fatalf("a segment that does not beat the head is not an error: %v", err)
	}
	if now := chain.CurrentBlock(); now.Hash() != head.Hash() {
		t.Fatalf("head moved to %d, want it kept at %d", now.Number.Uint64(), head.Number.Uint64())
	}
}

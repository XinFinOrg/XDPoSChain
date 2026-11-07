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

import "testing"

// TestProcFutureBlocksKeepsPrunedAncestorParkedBlock is the counterpart of the test above and pins
// the shape that must NOT be evicted: a parked block whose parent is on the chain without its state.
// InsertChain routes it through insertSideChain, which reports success without adopting the block,
// so it never reaches the eviction branch - and that is the point, because its state can still be
// rebuilt while a block dropped from the queue is never offered again by the downloader. Folding
// this shape into the same eviction rule would trade repeated verification for a stalled range.
func TestProcFutureBlocksKeepsPrunedAncestorParkedBlock(t *testing.T) {
	t.Parallel()

	chain, blocks, _, _ := newPrunedCanonicalChain(t)

	// A canonical block below the state window: it is on disk, its state is gone.
	parked := blocks[len(blocks)-TriesInMemory-1]
	if chain.HasBlockAndFullState(parked.Hash(), parked.NumberU64()) {
		t.Fatal("the block must be pruned, otherwise the shape is not covered")
	}
	chain.futureBlocks.Add(parked.Hash(), parked)

	chain.procFutureBlocks()

	if !chain.futureBlocks.Contains(parked.Hash()) {
		t.Fatal("a pruned block whose state can be rebuilt must stay in the future queue")
	}
}

// TestPrunedImportSide covers the sidechain shapes a peer may serve on top of canonical blocks this
// node already stores, including ones whose state has been pruned: a prepended canonical prefix must
// not be mistaken for a ghost-state attack, and the batch must still be routed as a sidechain import
// after that prefix is trimmed.
func TestPrunedImportSide(t *testing.T) {
	t.Parallel()

	// The cases differ in how much of the canonical chain is prepended to the
	// sidechain and where the fork leaves it: above, at or below the prune
	// point. Every case builds its own chain and database, so they run side by
	// side instead of one after the other.
	for _, tc := range []struct {
		name                 string
		canonicalInSidechain int
		belowPrunePoint      int
	}{
		{"three canonical blocks, fork above the prune point", 3, 3},
		{"three canonical blocks, fork below the prune point", 3, -3},
		{"ten canonical blocks, fork at the prune point", 10, 0},
		{"one canonical block, fork ten above the prune point", 1, 10},
		{"one canonical block, fork ten below the prune point", 1, -10},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			testSideImport(t, tc.canonicalInSidechain, tc.belowPrunePoint)
		})
	}
}

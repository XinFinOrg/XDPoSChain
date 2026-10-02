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
)

func TestInsertBlockAdoptsKnownBlockAboveTheHead(t *testing.T) {
	chain, blocks := newInsertChainTester(t, nil, 6, 0)

	// Import through the single-block entry itself. A block that went through InsertChain
	// is recorded in downloadingBlock, which insertBlock reads before anything else and
	// answers without touching the head - so a chain warmed up in batches cannot show
	// this path at all.
	for _, block := range blocks {
		if err := chain.InsertBlock(block); err != nil {
			t.Fatalf("failed to import block #%d through the single-block path: %v", block.NumberU64(), err)
		}
	}
	// Move the head back while leaving the blocks and their state on disk.
	rewindHeadMarkers(chain, blocks[3])
	if have, want := chain.CurrentBlock().Number.Uint64(), blocks[3].NumberU64(); have != want {
		t.Fatalf("unexpected head after rollback: have %d want %d", have, want)
	}
	ev, lg, err := chain.insertBlock(blocks[4])
	if err != nil {
		t.Fatalf("failed to re-import the known block: %v", err)
	}
	if len(ev) == 0 {
		t.Fatal("the adoption reported no events")
	}
	if len(lg) != 0 {
		t.Fatalf("a rollback re-import delivered %d log(s), want none", len(lg))
	}
	if have, want := chain.CurrentBlock().Number.Uint64(), blocks[4].NumberU64(); have != want {
		t.Fatalf("head did not advance over the known block: have %d want %d", have, want)
	}
	// The adoption has to write the block the node executed, and it was canonical before
	// the rollback left its canonical mapping in place - so nothing is promoted and no
	// log may be delivered a second time.
	if block := chain.GetBlockByNumber(blocks[4].NumberU64()); block == nil || block.Hash() != blocks[4].Hash() {
		t.Fatalf("block #%d is not canonical after the adoption", blocks[4].NumberU64())
	}
}

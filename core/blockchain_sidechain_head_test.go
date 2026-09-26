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
	"testing"

	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
)

// TestInsertSideChainAnnouncesTheHeadTheRebuildMoved covers the one shape in which a rebuild
// of stored ancestors moves the head, and the one in which the events that say so are dropped:
// the segment is imported in chunks, every chunk but the last drops the events it raised to
// stay within the memory allowance, and the last chunk drops them too when its own import
// fails. This fork carries the head event in the events a caller posts rather than sending it
// from the import itself, so a return that carries none leaves the subscribers - the tx pool
// and the miner - on a head this node has already left.
//
// Reaching the shape takes a node that holds blocks above its own head with a total
// difficulty and without a state, which is what a rebuild that did not finish leaves behind:
// the rebuild walks down from the batch until it finds a state, so every block it re-imports
// is one whose total difficulty is below the head's unless it sits above it. They are seeded
// here the way insertSideChain writes them - header, body and total difficulty, no state.
//
// What this case does not cover is the chunk that is dropped for crossing the memory
// allowance: that takes 2048 blocks. It is the same root cause - a return carrying no events -
// and the same fix; the case covers the return the same code path reaches without them.
func TestInsertSideChainAnnouncesTheHeadTheRebuildMoved(t *testing.T) {
	failErr := errors.New("header verification failed on the last block of the rebuild")
	engine := &numberErrEngine{
		Engine: ethash.NewFaker(),
		errs: map[uint64]error{
			8: failErr,
		},
	}
	chain, blocks := newInsertChainTester(t, engine, 9, 3) // #1-#9, head at #3

	// #4-#8 are on disk with a total difficulty and without a state.
	for i := 3; i <= 7; i++ {
		parent := blocks[i-1]
		parentTd := chain.GetTd(parent.Hash(), parent.NumberU64())
		if parentTd == nil {
			t.Fatalf("no total difficulty for the parent of #%d", blocks[i].NumberU64())
		}
		td := new(big.Int).Add(parentTd, blocks[i].Difficulty())
		if err := chain.writeBlockWithoutState(blocks[i], td); err != nil {
			t.Fatalf("block #%d: failed to write the stored entry: %v", blocks[i].NumberU64(), err)
		}
	}

	headCh := make(chan ChainHeadEvent, 8)
	sub := chain.SubscribeChainHeadEvent(headCh)
	defer sub.Unsubscribe()

	// #9 links to #8, which is stored without its state, so the batch is imported as a
	// sidechain and rebuilt: #4-#9, with #8 failing the verification that ends it.
	if _, err := chain.InsertChain(blocks[8:]); !errors.Is(err, failErr) {
		t.Fatalf("unexpected error: have %v want %v", err, failErr)
	}
	if want := uint64(7); chain.CurrentBlock().Number.Uint64() != want {
		t.Fatalf("unexpected head number: have %d want %d", chain.CurrentBlock().Number.Uint64(), want)
	}
	select {
	case ev := <-headCh:
		if ev.Block.NumberU64() != 7 {
			t.Fatalf("head event is for #%d, want the head the rebuild moved to, #7", ev.Block.NumberU64())
		}
	default:
		t.Fatal("no head event for the head the rebuild moved to")
	}
	// One batch raises one head event, the failed one included.
	select {
	case ev := <-headCh:
		t.Fatalf("a second head event was raised for #%d", ev.Block.NumberU64())
	default:
	}
}

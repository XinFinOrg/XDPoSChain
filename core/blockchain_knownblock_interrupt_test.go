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
)

// TestWriteKnownBlockRefusesAfterInterrupt pins that an interrupted chain does not adopt a known
// block either. writeBlockWithState answers the interruption itself, and the batch and single-block
// callers answer it before they call in; insertSideChain's adoption of a stored prefix has no check
// of its own, so the answer has to come from the adoption function. Without it the head moves after
// the chain was told to stop, and the batch reports a success the shutdown had already cancelled.
//
// The fixture is the shape the adoption path exists for: blocks this node executed but did not adopt,
// left above the head by a rewind.
func TestWriteKnownBlockRefusesAfterInterrupt(t *testing.T) {
	chain, blocks := newInsertChainTester(t, nil, 6, 6)
	// Roll the head back to block 3 while leaving 4, 5 and 6 on disk with their state and their
	// execution marker.
	rewindHeadMarkers(chain, blocks[3])

	if have, want := chain.CurrentBlock().Number.Uint64(), blocks[3].NumberU64(); have != want {
		t.Fatalf("precondition: the head must sit on %d after the rewind, have %d", want, have)
	}
	if !chain.HasExecutedBlock(blocks[4].Hash(), blocks[4].NumberU64()) {
		t.Fatal("precondition: block 4 must be executed and on disk, otherwise the shape is not covered")
	}
	// Control: without the interrupt the stored block is adopted and moves the head, so the
	// refusal below is the interruption's doing rather than a block that could never be adopted.
	if adopted, _, err := chain.writeKnownBlock(blocks[4]); err != nil || adopted == nil {
		t.Fatalf("the stored block must be adopted without an interrupt: adopted=%v err=%v", adopted, err)
	}
	if have, want := chain.CurrentBlock().Number.Uint64(), blocks[4].NumberU64(); have != want {
		t.Fatalf("the control adoption must move the head to %d, have %d", want, have)
	}
	// The same call on the next stored block, with the chain told to stop first.
	chain.InterruptInsert(true)
	defer chain.InterruptInsert(false)

	adopted, promoted, err := chain.writeKnownBlock(blocks[5])
	if !errors.Is(err, ErrInsertionInterrupted) {
		t.Fatalf("an interrupted chain must not adopt a known block, have %v", err)
	}
	if !IsLocalInsertError(err) {
		t.Fatalf("the interruption is a condition of this node, not of the block: %v", err)
	}
	if adopted != nil || promoted {
		t.Fatalf("an interrupted chain must not adopt a known block, have adopted=%v promoted=%v", adopted, promoted)
	}
	if have, want := chain.CurrentBlock().Number.Uint64(), blocks[4].NumberU64(); have != want {
		t.Fatalf("the head must stay where the interrupt found it: have %d want %d", have, want)
	}
}

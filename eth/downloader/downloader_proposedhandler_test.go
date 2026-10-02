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

package downloader

import (
	"errors"
	"fmt"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/event"
)

// TestImportBlockResultsGatesTheProposedBlockHandler pins that the downloader only hands
// the engine a batch tail that became the canonical head. A nil error from InsertChain
// does not make the tail one: a re-delivered range below the head, a fork batch, or a
// tail parked in the future queue stays out of the chain, and the handler would advance
// the consensus state - QC and vote - for a block that is not in it.
func TestImportBlockResultsGatesTheProposedBlockHandler(t *testing.T) {
	tester := newTester()
	defer tester.terminate()

	// Pre-populate the tester's local chain with everything below the batch tail, so that the
	// head starts below that tail and importing the batch is what moves it onto the tail. The
	// setup is stated as an assertion rather than assumed: were the head already sitting on the
	// tail, the first import could not move it and the expectations below would mean nothing.
	chain := testChainBase.shorten(4)
	tail := chain.headBlock()
	below := chain.chain[:len(chain.chain)-1]
	tester.ownHashes = append(tester.ownHashes[:0], below...)
	for _, hash := range below {
		tester.ownHeaders[hash] = chain.headerm[hash]
		if block := chain.blockm[hash]; block != nil {
			tester.ownBlocks[hash] = block
			// Stub stateDb so CurrentBlock's lookup succeeds.
			tester.stateDb.Put(block.Root().Bytes(), []byte{0x00})
		}
		tester.ownChainTd[hash] = chain.tdm[hash]
	}
	if have := tester.downloader.blockchain.CurrentBlock(); have.Hash() == tail.Hash() {
		t.Fatal("the tester must start below the batch tail, otherwise the batch cannot move the head")
	}
	blocks := make(types.Blocks, 0, len(chain.chain)-1)
	for _, hash := range chain.chain[1:] {
		blocks = append(blocks, chain.blockm[hash])
	}
	results := func(blocks types.Blocks) []*fetchResult {
		out := make([]*fetchResult, len(blocks))
		for i, block := range blocks {
			out[i] = &fetchResult{Header: block.Header(), Uncles: block.Uncles(), Transactions: block.Transactions()}
		}
		return out
	}
	// The batch that reaches the head: the tail is canonical, so the engine is told.
	if err := tester.downloader.importBlockResults(results(blocks)); err != nil {
		t.Fatalf("failed to import the head batch: %v", err)
	}
	if seen := tester.proposedHandled(); len(seen) != 1 || seen[0].Hash() != chain.headBlock().Hash() {
		t.Fatalf("the engine was handed %v, want the batch tail %x", seen, chain.headBlock().Hash())
	}
	// A range below the head: InsertChain reports success, but its tail never became the
	// head, so the engine must not be told about it.
	if err := tester.downloader.importBlockResults(results(blocks[:2])); err != nil {
		t.Fatalf("failed to re-deliver a range below the head: %v", err)
	}
	if seen := tester.proposedHandled(); len(seen) != 1 {
		t.Fatalf("the engine was handed %v for a tail that is not the head", seen)
	}
	// The same range re-delivered in full: every block of it is already canonical and the tail
	// is the head it left behind, so the head does not move. The batch may still answer without
	// an error, which is the point of the check - a nil error alone does not make its tail one
	// the consensus state has to be advanced to, and the handler would reprocess the QC of that
	// head and ask whether it may vote for it a second time.
	if err := tester.downloader.importBlockResults(results(blocks)); err != nil {
		t.Fatalf("failed to re-deliver the head range: %v", err)
	}
	if seen := tester.proposedHandled(); len(seen) != 1 {
		t.Fatalf("the engine was handed %v for a batch that did not move the head", seen)
	}
}

// parkedTailChain is a chain whose batch moves the head to a block that is not the batch tail,
// which is what a tail parked in the future queue leaves behind: InsertChain reports no error,
// the prefix it did import became canonical, and the tail is still in the queue. The head is
// reported before and after the insertion so that the downloader's decision can be driven
// without a future queue.
type parkedTailChain struct {
	*downloadTester
	imported bool
	before   *types.Header
	after    *types.Header
}

func (c *parkedTailChain) InsertChain(blocks types.Blocks) (int, error) {
	c.imported = true
	return 0, nil
}

func (c *parkedTailChain) CurrentBlock() *types.Header {
	if c.imported {
		return c.after
	}
	return c.before
}

// TestImportBlockResultsHandsTheHeadWhenTheTailIsParked pins the other half of the handoff: the
// batch tail is not the head, but the batch still moved the head, and the block it moved to is
// the one the consensus state has to be advanced to. Skipping the handler there drops the QC
// and the vote of the block that actually became canonical.
func TestImportBlockResultsHandsTheHeadWhenTheTailIsParked(t *testing.T) {
	tester := newTester()
	defer tester.terminate()

	chain := testChainBase.shorten(4)
	blocks := make(types.Blocks, 0, len(chain.chain)-1)
	for _, hash := range chain.chain[1:] {
		blocks = append(blocks, chain.blockm[hash])
	}
	prefix, tail := blocks[len(blocks)-2], blocks[len(blocks)-1]
	if prefix.Hash() == tail.Hash() {
		t.Fatal("the batch needs a prefix of its own, otherwise the shape is not covered")
	}
	results := make([]*fetchResult, len(blocks))
	for i, block := range blocks {
		results[i] = &fetchResult{Header: block.Header(), Uncles: block.Uncles(), Transactions: block.Transactions()}
	}
	// The head sat at the genesis block, the batch imported up to the prefix, and the tail was
	// left in the future queue.
	wrapper := &parkedTailChain{
		downloadTester: tester,
		before:         chain.genesis.Header(),
		after:          prefix.Header(),
	}
	dl := New(tester.stateDb, new(event.TypeMux), wrapper, nil, tester.dropPeer, tester.handleProposedBlock)
	defer dl.Terminate()

	if err := dl.importBlockResults(results); err != nil {
		t.Fatalf("failed to import a batch whose tail is parked: %v", err)
	}
	if seen := tester.proposedHandled(); len(seen) != 1 || seen[0].Hash() != prefix.Hash() {
		t.Fatalf("the engine was handed %v, want the head this batch moved to %x", seen, prefix.Hash())
	}
}

// failingTailChain imports the prefix of the batch it is handed - the head moves to it - and
// stops on the batch's last block. It is the shape a segment that InsertChain rejected leaves
// behind: the index it reports is the block that failed, and the blocks below it are already
// on the chain, so the head the consensus state has to advance to is the prefix.
type failingTailChain struct {
	*downloadTester
	imported bool
	before   *types.Header
	after    *types.Header
	err      error
}

func (c *failingTailChain) InsertChain(blocks types.Blocks) (int, error) {
	c.imported = true
	return len(blocks) - 1, c.err
}

func (c *failingTailChain) CurrentBlock() *types.Header {
	if c.imported {
		return c.after
	}
	return c.before
}

// TestImportBlockResultsHandsTheHeadWhenASegmentFails pins the last half of the handoff: a
// batch that InsertChain stopped on is still one whose prefix moved the head, and QC and vote
// have to follow that head. Both error branches used to return before the handler ran, and the
// cycle is given up on a local condition - so the next one re-delivers the same range, which
// no longer moves the head and hands nothing over: the vote of the block that did become
// canonical was never sent.
func TestImportBlockResultsHandsTheHeadWhenASegmentFails(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		moved      bool // whether the head moved before the batch failed
		wantLocal  bool
		wantHanded bool
	}{
		// A local condition: the cycle is given up, the peer is not blamed.
		{"local condition", fmt.Errorf("%w: no total difficulty for the parent of block 4", core.ErrLocalInsertCondition), true, true, true},
		// A batch the peer can be held to: it is reported as an invalid chain all the same.
		{"invalid chain", errors.New("invalid block"), true, false, true},
		// A fork batch, or one re-delivered below the head: nothing moved, nothing is handed over.
		{"invalid chain that left the head", errors.New("invalid block"), false, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tester := newTester()
			defer tester.terminate()

			chain := testChainBase.shorten(4)
			blocks := make(types.Blocks, 0, len(chain.chain)-1)
			for _, hash := range chain.chain[1:] {
				blocks = append(blocks, chain.blockm[hash])
			}
			prefix := blocks[len(blocks)-2]
			results := make([]*fetchResult, len(blocks))
			for i, block := range blocks {
				results[i] = &fetchResult{Header: block.Header(), Uncles: block.Uncles(), Transactions: block.Transactions()}
			}
			// The head sat at the genesis block; the batch imported up to the prefix when it
			// moved the head, and stopped on the block above it.
			after := chain.genesis.Header()
			if tt.moved {
				after = prefix.Header()
			}
			wrapper := &failingTailChain{
				downloadTester: tester,
				before:         chain.genesis.Header(),
				after:          after,
				err:            tt.err,
			}
			dl := New(tester.stateDb, new(event.TypeMux), wrapper, nil, tester.dropPeer, tester.handleProposedBlock)
			defer dl.Terminate()

			err := dl.importBlockResults(results)
			if have := errors.Is(err, errLocalInsertFailure); have != tt.wantLocal {
				t.Fatalf("the local condition was reported as %v, want local=%v: err %v", have, tt.wantLocal, err)
			}
			if !tt.wantLocal && !errors.Is(err, errInvalidChain) {
				t.Fatalf("a failure the peer can be held to must be reported as an invalid chain: %v", err)
			}
			seen := tester.proposedHandled()
			if !tt.wantHanded {
				if len(seen) != 0 {
					t.Fatalf("the engine was handed %v for a batch that did not move the head", seen)
				}
				return
			}
			if len(seen) != 1 || seen[0].Hash() != prefix.Hash() {
				t.Fatalf("the engine was handed %v, want the head this batch moved to %x", seen, prefix.Hash())
			}
		})
	}
}

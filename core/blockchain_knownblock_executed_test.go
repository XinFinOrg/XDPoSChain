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

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/types"
)

// TestKnownBlockNeverExecutedIsNotReportedAsKnown pins what "known" has to mean to the
// insertion paths: a block this node never executed must not be reported as known just
// because it is on disk and names a state root the trie database happens to resolve, so
// that it goes through execution, where ValidateState rejects the root it claims.
//
// writeBlockWithoutState is the only production writer that leaves a block on disk without
// its state and without its receipts - insertSideChain uses it for the blocks of a segment
// whose ancestors are pruned - so such a block can name any root that already exists.
// HasBlockAndFullState is satisfied by that alone, HasExecutedBlock is not, and ValidateBody
// and writeKnownBlock both follow the latter.
//
// The weaker invariant - that the head does not move onto such a block either way - is
// pinned by TestKnownBlockNeverExecutedIsNotAdopted, which holds both before and after this
// classification changed.
func TestKnownBlockNeverExecutedIsNotReportedAsKnown(t *testing.T) {
	cases := []struct {
		name string
		root func(parent *types.Block) common.Hash
	}{
		// trie.New resolves no node at all for these two, so OpenTrie succeeds without any
		// state being present.
		{"empty root", func(*types.Block) common.Hash { return types.EmptyRootHash }},
		{"zero root", func(*types.Block) common.Hash { return common.Hash{} }},
		// A root that really is in the database, borrowed from another block.
		{"root of another block", func(parent *types.Block) common.Hash { return parent.Root() }},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			_, _, chain, err := newCanonical(ethash.NewFaker(), 4, true)
			if err != nil {
				t.Fatalf("could not make new canonical in test: %v", err)
			}
			defer chain.Stop()

			head := chain.CurrentBlock()
			parent := chain.GetBlock(head.Hash(), head.Number.Uint64())
			if parent == nil {
				t.Fatal("parent block missing")
			}
			// The successor carries the parent's transactions and uncle hash, so the state
			// root is the only thing that is a lie about it.
			header := types.CopyHeader(parent.Header())
			header.Number = new(big.Int).Add(parent.Number(), big.NewInt(1))
			header.ParentHash = parent.Hash()
			header.Time = parent.Time() + 1
			header.Difficulty = ethash.CalcDifficulty(chain.chainConfig, header.Time, parent.Header())
			header.Root = tt.root(parent)
			block := types.NewBlockWithHeader(header).WithBody(types.Body{Transactions: parent.Transactions()})

			td := new(big.Int).Add(parent.Difficulty(), chain.GetTd(parent.Hash(), parent.NumberU64()))
			if err := chain.writeBlockWithoutState(block, td); err != nil {
				t.Fatalf("could not store the block without its state: %v", err)
			}
			// The two preconditions the classification works against: a root that resolves,
			// and no receipts - execution is what would have written them.
			if !chain.HasBlockAndFullState(block.Hash(), block.NumberU64()) {
				t.Fatal("the block must look stored with its state, otherwise the shape is not covered")
			}
			if rawdb.HasReceipts(chain.ChainDb(), block.Hash(), block.NumberU64()) {
				t.Fatal("the block must have no receipts, it was never executed")
			}
			if rawdb.HasExecutedMarker(chain.ChainDb(), block.Hash(), block.NumberU64()) {
				t.Fatal("the block must have no marker, this node never executed it")
			}
			if chain.HasExecutedBlock(block.Hash(), block.NumberU64()) {
				t.Fatal("the block must not count as executed, this node never executed it")
			}
			// The classification follows that, so the block is not skipped as known.
			if err := chain.validator.ValidateBody(block); errors.Is(err, ErrKnownBlock) {
				t.Fatal("a block this node never executed must not be reported as known")
			}
			// And the adoption path refuses it even when it is entered directly.
			if adopted, _, err := chain.writeKnownBlock(block); err != nil || adopted != nil {
				t.Fatalf("writeKnownBlock adopted a block this node never executed: adopted=%v err=%v", adopted, err)
			}
			// Importing it therefore executes it, and the state root it claims does not
			// reproduce: the import fails instead of moving the head.
			if _, err := chain.InsertChain(types.Blocks{block}); err == nil {
				t.Fatal("a block whose state root its own execution does not reproduce was imported")
			}
			if got := chain.CurrentBlock(); got.Hash() == block.Hash() {
				t.Fatalf("the head moved to #%d %s, a block this node never executed", got.Number.Uint64(), got.Hash())
			}
		})
	}
}

// TestKnownBlockWithFastSyncReceiptsIsNotAdopted is the receipts counterpart of the test above:
// there the block was a side entry with no receipts at all, here it is one that InsertReceiptChain
// completed a fast sync range with. The body and the receipts are on disk, the state the header
// names was never written, and the root it claims resolves only because it is borrowed - the empty
// root, the zero root, or the root of the block below it.
//
// Receipts alone answered this shape as executed: ValidateBody reported it known, and
// writeKnownBlock adopted it - it beats the head on total difficulty - moving the head onto a
// block this node never ran, with Process and ValidateState never seeing it. The marker
// writeBlockWithState writes is what separates the two, and this is the case that keeps the
// receipts from being asked again instead.
func TestKnownBlockWithFastSyncReceiptsIsNotAdopted(t *testing.T) {
	cases := []struct {
		name string
		root func(parent *types.Block) common.Hash
	}{
		// trie.New resolves no node at all for these two, so OpenTrie succeeds without any
		// state being present.
		{"empty root", func(*types.Block) common.Hash { return types.EmptyRootHash }},
		{"zero root", func(*types.Block) common.Hash { return common.Hash{} }},
		// A root that really is in the database: the state of the block below, which this node
		// did execute.
		{"root of the parent", func(parent *types.Block) common.Hash { return parent.Root() }},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			_, _, chain, err := newCanonical(ethash.NewFaker(), 4, true)
			if err != nil {
				t.Fatalf("could not make new canonical in test: %v", err)
			}
			defer chain.Stop()

			head := chain.CurrentBlock()
			parent := chain.GetBlock(head.Hash(), head.Number.Uint64())
			if parent == nil {
				t.Fatal("parent block missing")
			}
			// A block this node imported itself carries the marker; the successor below is the
			// same shape on disk apart from it, which is what the case turns on.
			if !rawdb.HasExecutedMarker(chain.ChainDb(), parent.Hash(), parent.NumberU64()) {
				t.Fatal("a block this node executed must carry the marker")
			}
			// The successor is empty and names a root it did not produce. The header has to
			// describe an empty block, otherwise ValidateBody rejects it before the
			// classification is reached and the shape is not covered.
			header := types.CopyHeader(parent.Header())
			header.Number = new(big.Int).Add(parent.Number(), big.NewInt(1))
			header.ParentHash = parent.Hash()
			header.Time = parent.Time() + 1
			header.Difficulty = ethash.CalcDifficulty(chain.chainConfig, header.Time, parent.Header())
			header.Root = tt.root(parent)
			header.TxHash = types.EmptyRootHash
			header.ReceiptHash = types.EmptyRootHash
			header.UncleHash = types.EmptyUncleHash
			header.Bloom = types.Bloom{}
			header.GasUsed = 0
			block := types.NewBlockWithHeader(header)

			// Complete it the way a fast sync does: the header first, which also stores the
			// total difficulty the fork-choice gate compares, then the body and the receipts.
			if n, err := chain.InsertHeaderChain([]*types.Header{header}, 1); err != nil {
				t.Fatalf("could not insert the header at %d: %v", n, err)
			}
			if n, err := chain.InsertReceiptChain(types.Blocks{block}, []types.Receipts{nil}); err != nil {
				t.Fatalf("could not insert the receipts at %d: %v", n, err)
			}
			// The shape the classification works against: receipts on disk and a root that
			// resolves, but no marker.
			if !rawdb.HasReceipts(chain.ChainDb(), block.Hash(), block.NumberU64()) {
				t.Fatal("the block must have receipts, a fast sync wrote them")
			}
			if !chain.HasBlockAndFullState(block.Hash(), block.NumberU64()) {
				t.Fatal("the block must look stored with its state, otherwise the shape is not covered")
			}
			if rawdb.HasExecutedMarker(chain.ChainDb(), block.Hash(), block.NumberU64()) {
				t.Fatal("the block must have no marker, this node never executed it")
			}
			if chain.HasExecutedBlock(block.Hash(), block.NumberU64()) {
				t.Fatal("the block must not count as executed, this node never executed it")
			}
			// It beats the head on total difficulty, so losing fork choice is not what keeps it
			// out of the chain.
			if td := chain.GetTd(block.Hash(), block.NumberU64()); td == nil {
				t.Fatal("the header chain must have stored the total difficulty the gate compares")
			}
			// The classification follows the marker, so the block is not skipped as known.
			if err := chain.validator.ValidateBody(block); errors.Is(err, ErrKnownBlock) {
				t.Fatal("a block this node never executed must not be reported as known")
			}
			// And the adoption path refuses it even when it is entered directly, which is what
			// keeps the head off a block this node never ran.
			if adopted, _, err := chain.writeKnownBlock(block); err != nil || adopted != nil {
				t.Fatalf("writeKnownBlock adopted a block this node never executed: adopted=%v err=%v", adopted, err)
			}
			if got := chain.CurrentBlock(); got.Hash() == block.Hash() {
				t.Fatalf("the head moved to #%d %s, a block this node never executed", got.Number.Uint64(), got.Hash())
			}
			// Re-delivering it runs it like any other block: either the execution reproduces
			// the root it names - and then the head may move, because this node did run it -
			// or the import fails and the head stays where it is.
			if _, err := chain.InsertChain(types.Blocks{block}); err != nil {
				if got := chain.CurrentBlock(); got.Hash() == block.Hash() {
					t.Fatalf("the head moved to #%d %s although its import failed", got.Number.Uint64(), got.Hash())
				}
				return
			}
			if got := chain.CurrentBlock(); got.Hash() == block.Hash() && !rawdb.HasExecutedMarker(chain.ChainDb(), block.Hash(), block.NumberU64()) {
				t.Fatal("the head moved onto the block, but this node never executed it")
			}
		})
	}
}

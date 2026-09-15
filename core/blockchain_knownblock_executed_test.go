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

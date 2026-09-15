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
	"testing"

	"github.com/XinFinOrg/XDPoSChain/core/types"
)

// TestImportBlockResultsGatesTheProposedBlockHandler pins that the downloader only hands
// the engine a batch tail that became the canonical head. A nil error from InsertChain
// does not make the tail one: a re-delivered range below the head, a fork batch, or a
// tail parked in the future queue stays out of the chain, and the handler would advance
// the consensus state - QC and vote - for a block that is not in it.
func TestImportBlockResultsGatesTheProposedBlockHandler(t *testing.T) {
	tester := newTester()
	defer tester.terminate()

	// Pre-populate the tester's local chain so that CurrentBlock() sits at #4.
	chain := testChainBase.shorten(4)
	tester.ownHashes = append(tester.ownHashes[:0], chain.chain...)
	for hash, header := range chain.headerm {
		tester.ownHeaders[hash] = header
	}
	for _, block := range chain.blockm {
		tester.ownBlocks[block.Hash()] = block
		// Stub stateDb so CurrentBlock's lookup succeeds.
		tester.stateDb.Put(block.Root().Bytes(), []byte{0x00})
	}
	for hash, td := range chain.tdm {
		tester.ownChainTd[hash] = td
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
}

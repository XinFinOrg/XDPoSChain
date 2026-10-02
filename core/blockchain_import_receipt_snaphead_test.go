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

	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/types"
)

// TestInsertReceiptChainReportsAMissingSnapHeadRecord covers the comparison the receipt import
// makes against the fast sync head once every block of the batch has been written: both heads are
// read from this node's database, and the fast sync head's total difficulty was dereferenced. A
// database that lost that record - or one that reports no fast sync head at all - has nothing to
// compare it with, so the import panicked instead of reporting the condition. It is the same read
// writeBlockWithState reports as a local one when the parent or the head it writes on has no
// record: a record of this node, saying nothing about the blocks the peer served.
//
// The build below imports the first half of the range twice - headers for all of it, receipts for
// the first three blocks - because the receipts are what move the fast sync head off the genesis,
// and it is that head whose record the case drops. The batch the case imports then starts above
// it, so the block it ends at has a record of its own and the comparison is reached.
//
// The control is the same shape with the record in place: without it the case could pass for a
// reason of its own, such as the comparison never being reached at all.
//
// It lives in its own file rather than in blockchain_import_receipt_test.go, which the commit it
// fixes does not touch but the interruption commit created: a case added there would leave that
// commit unable to be reverted alone, which is a property this branch measures.
func TestInsertReceiptChainReportsAMissingSnapHeadRecord(t *testing.T) {
	// build returns a chain whose headers 1..5 are written, whose receipts 1..3 are written, and
	// whose fast sync head is therefore block 3, with the record of that head optionally dropped.
	build := func(t *testing.T, dropSnapTd bool) (*BlockChain, types.Blocks) {
		t.Helper()

		chain, blocks := newInsertChainTester(t, nil, 5, 0)
		// Headers only: a receipt import completes a header chain, and a block that is already
		// there would be skipped instead of written.
		headers := make([]*types.Header, len(blocks))
		for i, block := range blocks {
			headers[i] = block.Header()
		}
		if n, err := chain.InsertHeaderChain(headers, 1); err != nil {
			t.Fatalf("header %d: failed to insert headers: %v", n, err)
		}
		receipts := make([]types.Receipts, len(blocks))
		if n, err := chain.InsertReceiptChain(blocks[:3], receipts[:3]); err != nil {
			t.Fatalf("index %d: failed to insert the receipts of the range below: %v", n, err)
		}
		snap := chain.CurrentSnapBlock()
		if snap == nil || snap.Number.Uint64() != 3 {
			t.Fatalf("precondition: the imported receipts must have moved the fast sync head onto #3, have %v", snap)
		}
		if dropSnapTd {
			rawdb.DeleteTd(chain.ChainDb(), snap.Hash(), snap.Number.Uint64())
			// The header chain reads its own total difficulty cache before the database, so a
			// record removed from the database alone is answered from there.
			chain.hc.tdCache.Remove(snap.Hash())
		}
		return chain, blocks
	}

	// The control: every record is in place, so the receipts above the fast sync head go in.
	chain, blocks := build(t, false)
	receipts := make([]types.Receipts, len(blocks))
	if n, err := chain.InsertReceiptChain(blocks[3:], receipts[3:]); err != nil {
		t.Fatalf("index %d: the receipts above the fast sync head must be imported: %v", n, err)
	}

	// The case: the record of the fast sync head is gone.
	chain, blocks = build(t, true)
	receipts = make([]types.Receipts, len(blocks))
	n, err := chain.InsertReceiptChain(blocks[3:], receipts[3:])
	if !errors.Is(err, ErrLocalInsertCondition) {
		t.Fatalf("index %d: a missing record of this node must be reported as a local condition, have %v", n, err)
	}
	if !IsLocalInsertError(err) {
		t.Fatalf("a missing record of this node must not be blamed on the peer: %v", err)
	}
}

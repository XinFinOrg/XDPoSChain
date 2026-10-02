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
)

// TestHeadTdReportsMissingTotalDifficulty covers the guard around the head's total difficulty: the
// methods of big.Int panic on a nil receiver, so a chain that lost the record for its own head has
// to fail with a local condition instead of dereferencing nil - and a record this node is missing
// is nothing the blocks can be blamed for.
func TestHeadTdReportsMissingTotalDifficulty(t *testing.T) {
	chain, _ := newInsertChainTester(t, nil, 6, 5) // head at #5

	head := chain.CurrentBlock()
	if td, err := chain.headTd(head); err != nil || td == nil {
		t.Fatalf("precondition: the head total difficulty must be readable, have td=%v err=%v", td, err)
	}

	// Drop the record the way a pruned or truncated database would, cache included.
	rawdb.DeleteTd(chain.ChainDb(), head.Hash(), head.Number.Uint64())
	chain.hc.tdCache.Remove(head.Hash())

	td, err := chain.headTd(head)
	if err == nil {
		t.Fatalf("a head with no total difficulty must be reported, have td=%v", td)
	}
	if !errors.Is(err, ErrLocalInsertCondition) {
		t.Fatalf("unexpected error: have %v want %v", err, ErrLocalInsertCondition)
	}
	if !IsLocalInsertError(err) {
		t.Fatalf("a record missing in this node must not be blamed on the blocks: %v", err)
	}
	if td, err := chain.headTd(nil); err == nil {
		t.Fatalf("a nil head must be reported instead of dereferenced, have td=%v", td)
	}
}

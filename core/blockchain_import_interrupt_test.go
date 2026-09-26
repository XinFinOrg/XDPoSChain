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

// TestInsertChainReportsInterruptedInsertionAtEntry covers the entry guard of insertChain:
// an interruption that lands before the first block is inspected must not be reported as a
// (zero block) success either, otherwise the caller believes a batch it never got.
func TestInsertChainReportsInterruptedInsertionAtEntry(t *testing.T) {
	chain, blocks := newInsertChainTester(t, nil, 5, 0)
	chain.InterruptInsert(true)

	n, err := chain.InsertChain(blocks)
	if err == nil {
		t.Fatal("InsertChain reported success although the insertion was interrupted before the first block")
	}
	if !errors.Is(err, ErrInsertionInterrupted) {
		t.Fatalf("unexpected error: have %v want %v", err, ErrInsertionInterrupted)
	}
	if want := 0; n != want {
		t.Fatalf("unexpected failing index: have %d want %d", n, want)
	}
	if want := uint64(0); chain.CurrentBlock().Number.Uint64() != want {
		t.Fatalf("unexpected head number: have %d want %d", chain.CurrentBlock().Number.Uint64(), want)
	}
	if block := chain.GetBlockByNumber(1); block != nil {
		t.Fatalf("block #1 was written although the insertion was interrupted before the first block")
	}
}

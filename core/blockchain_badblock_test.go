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

// TestInsertChainReportsBadBlockBehindKnownPrefix pins that a batch stopped by an invalid
// block directly behind a prefix this node already has is recorded like every other stop on
// an invalid block: the invalid block lands in the bad-block database instead of only in a
// log line, and the head stays on the prefix it did import.
func TestInsertChainReportsBadBlockBehindKnownPrefix(t *testing.T) {
	chain, blocks := newInsertChainTester(t, nil, 5, 3) // #1..#3 are imported, the head is #3
	invalid := errors.New("transaction root hash mismatch")
	chain.validator = &failBodyValidator{Validator: chain.validator, failNumber: 4, failErr: invalid}

	n, err := chain.InsertChain(blocks[2:]) // #3 is known, #4 fails body validation
	// n is the index of blocks[3] (#4) within the batch handed in, not its number.
	if want := 1; n != want {
		t.Fatalf("unexpected failing index: have %d want %d", n, want)
	}
	if IsLocalInsertError(err) {
		t.Fatalf("an invalid block is a consensus failure, not a local condition: %v", err)
	}
	if rawdb.ReadBadBlock(chain.ChainDb(), blocks[3].Hash()) == nil {
		t.Fatal("the invalid block behind a known prefix was not recorded as a bad block")
	}
	if want := uint64(3); chain.CurrentBlock().Number.Uint64() != want {
		t.Fatalf("unexpected head number: have %d want %d", chain.CurrentBlock().Number.Uint64(), want)
	}
}

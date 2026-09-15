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

	"github.com/XinFinOrg/XDPoSChain/core/types"
)

// TestInsertReceiptChainReportsInterruption covers the interruption check of a receipt
// batch. The blocks before the one that stopped the batch may already have been flushed
// to disk, so reporting a nil error would claim the whole batch had been written - the
// very thing an interrupted insertion must not claim. The sentinel is local, so the
// downloader cancels the content processing instead of dropping the peer.
func TestInsertReceiptChainReportsInterruption(t *testing.T) {
	chain, blocks := newInsertChainTester(t, nil, 5, 5)
	receipts := make([]types.Receipts, len(blocks))

	chain.InterruptInsert(true)
	defer chain.InterruptInsert(false)

	n, err := chain.InsertReceiptChain(blocks, receipts)
	if !errors.Is(err, ErrInsertionInterrupted) {
		t.Fatalf("unexpected error: have %v want %v", err, ErrInsertionInterrupted)
	}
	if want := 0; n != want {
		t.Fatalf("unexpected failing index: have %d want %d", n, want)
	}
}

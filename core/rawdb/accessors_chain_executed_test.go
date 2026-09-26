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

package rawdb

import (
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
)

// TestExecutedMarkerTravelsWithTheReceipts pins the pair the executed-block marker forms with
// the receipts it vouches for: HasExecutedMarker answers whether this node's own execution of
// the block is recorded, and that record is only meaningful while the receipts the same
// execution produced are on disk. WriteReceipts and WriteExecutedMarker are written as a pair,
// so the call that removes the receipts has to take the marker with them.
func TestExecutedMarkerTravelsWithTheReceipts(t *testing.T) {
	db := NewMemoryDatabase()
	hash, number := common.HexToHash("0x1234"), uint64(7)

	WriteReceipts(db, hash, number, nil)
	WriteExecutedMarker(db, hash, number)
	if !HasReceipts(db, hash, number) {
		t.Fatal("the receipts must be readable once written")
	}
	if !HasExecutedMarker(db, hash, number) {
		t.Fatal("the marker must be readable once written")
	}
	DeleteReceipts(db, hash, number)
	if HasReceipts(db, hash, number) {
		t.Fatal("the receipts must be gone after DeleteReceipts")
	}
	if HasExecutedMarker(db, hash, number) {
		t.Fatal("the marker outlived the receipts it vouches for")
	}
}

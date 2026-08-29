// Copyright 2025 The XDPoSChain Authors
// This file is part of the XDPoSChain library.
//
// The XDPoSChain library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The XDPoSChain library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the XDPoSChain library. If not, see <http://www.gnu.org/licenses/>.

package rawdb

import (
	"math/big"
	"path/filepath"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/ethdb"
	"github.com/XinFinOrg/XDPoSChain/ethdb/leveldb"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// writeTestChain writes a synthetic canonical chain of `count` blocks (0..count-1)
// into the key-value side of db, including the head markers the freezer needs.
func writeTestChain(t *testing.T, db ethdb.Database, count uint64) []*types.Header {
	t.Helper()

	headers := make([]*types.Header, 0, count)
	var parent common.Hash
	for i := uint64(0); i < count; i++ {
		header := &types.Header{
			Number:     new(big.Int).SetUint64(i),
			ParentHash: parent,
			Difficulty: big.NewInt(1),
			Extra:      []byte("xdpos-freezer-test"),
		}
		hash := header.Hash()
		parent = hash

		WriteHeader(db, header)
		WriteCanonicalHash(db, hash, i)
		WriteBody(db, hash, i, &types.Body{})
		WriteReceipts(db, hash, i, types.Receipts{})
		WriteTd(db, hash, i, new(big.Int).SetUint64(i+1))
		headers = append(headers, header)
	}
	last := headers[len(headers)-1]
	WriteHeadBlockHash(db, last.Hash())
	WriteHeadHeaderHash(db, last.Hash())
	return headers
}

func newFreezerBackedDB(t *testing.T) (ethdb.Database, string) {
	t.Helper()
	dir := t.TempDir()
	ancient := filepath.Join(dir, "ancient")
	kv, err := leveldb.New(filepath.Join(dir, "chaindata"), 0, 0, "", false)
	if err != nil {
		t.Fatalf("open leveldb: %v", err)
	}
	db, err := NewDatabaseWithFreezer(kv, ancient, "", false)
	if err != nil {
		kv.Close()
		t.Fatalf("open freezer-backed db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db, ancient
}

// TestChainFreezerMovesDataToAncients is the end-to-end Phase 1 check: with a
// lowered immutability threshold, a freeze cycle must relocate everything below
// HEAD-threshold out of the key-value store and into the ancient store, and the
// data must still read back identically afterwards.
func TestChainFreezerMovesDataToAncients(t *testing.T) {
	defer func(v uint64) { params.FullImmutabilityThreshold = v }(params.FullImmutabilityThreshold)
	params.FullImmutabilityThreshold = 10

	db, _ := newFreezerBackedDB(t)
	const count = 40
	headers := writeTestChain(t, db, count)

	if frozen, _ := db.Ancients(); frozen != 0 {
		t.Fatalf("expected empty ancient store, got %d items", frozen)
	}
	if err := db.(*freezerdb).Freeze(); err != nil {
		t.Fatalf("freeze: %v", err)
	}

	// HEAD is block 39, threshold 10, so blocks 0..29 must be frozen.
	wantFrozen := uint64(count - params.FullImmutabilityThreshold)
	frozen, err := db.Ancients()
	if err != nil {
		t.Fatalf("Ancients: %v", err)
	}
	if frozen != wantFrozen {
		t.Fatalf("frozen count: got %d, want %d", frozen, wantFrozen)
	}

	// Every frozen block must still read back correctly, and must now be served
	// by the ancient store rather than leveldb.
	// Block 0 is deliberately retained in the key-value store by the freezer, so
	// the "no longer in leveldb" assertion starts at block 1.
	for i := uint64(0); i < frozen; i++ {
		want := headers[i]
		if got := ReadCanonicalHash(db, i); got != want.Hash() {
			t.Fatalf("canonical hash %d: got %x, want %x", i, got, want.Hash())
		}
		if got := ReadHeader(db, want.Hash(), i); got == nil || got.Hash() != want.Hash() {
			t.Fatalf("header %d not readable after freezing", i)
		}
		if blob, err := db.Ancient(ChainFreezerHeaderTable, i); err != nil || len(blob) == 0 {
			t.Fatalf("header %d not present in ancient store: %v", i, err)
		}
		// The key-value copy must be gone: that is the whole point of freezing.
		if i != 0 {
			if has, _ := db.Has(headerKey(i, want.Hash())); has {
				t.Fatalf("header %d still present in key-value store after freezing", i)
			}
		}
	}
	// Blocks at and above the threshold must remain in the key-value store.
	for i := frozen; i < count; i++ {
		if has, _ := db.Has(headerKey(i, headers[i].Hash())); !has {
			t.Fatalf("header %d should still be in the key-value store", i)
		}
	}
}

// TestTotalDifficultyNeverFrozen locks in this fork's deliberate deviation from
// upstream go-ethereum: there is no "diffs" ancient table, TD lives only in the
// key-value store, and it survives freezing. See claude/plan 3.4.
func TestTotalDifficultyNeverFrozen(t *testing.T) {
	defer func(v uint64) { params.FullImmutabilityThreshold = v }(params.FullImmutabilityThreshold)
	params.FullImmutabilityThreshold = 10

	db, _ := newFreezerBackedDB(t)
	const count = 40
	headers := writeTestChain(t, db, count)

	if err := db.(*freezerdb).Freeze(); err != nil {
		t.Fatalf("freeze: %v", err)
	}
	frozen, _ := db.Ancients()
	if frozen == 0 {
		t.Fatal("nothing was frozen, test is vacuous")
	}
	// There must be no total-difficulty ancient table at all.
	if _, err := db.AncientSize("diffs"); err == nil {
		t.Fatal("a \"diffs\" ancient table exists; TD must never be frozen in this fork")
	}
	// TD must still be readable for every frozen block, straight from leveldb.
	for i := uint64(0); i < frozen; i++ {
		td := ReadTd(db, headers[i].Hash(), i)
		if td == nil {
			t.Fatalf("total difficulty for frozen block %d is missing", i)
		}
		if td.Uint64() != i+1 {
			t.Fatalf("total difficulty %d: got %d, want %d", i, td.Uint64(), i+1)
		}
	}
}

// TestFreezerGenesisMismatchRejected verifies the consistency guard that stops a
// node from pairing a freezer with a key-value store from a different chain.
func TestFreezerGenesisMismatchRejected(t *testing.T) {
	defer func(v uint64) { params.FullImmutabilityThreshold = v }(params.FullImmutabilityThreshold)
	params.FullImmutabilityThreshold = 10

	dir := t.TempDir()
	ancient := filepath.Join(dir, "ancient")

	// First run: build a small frozen chain.
	kv, err := leveldb.New(filepath.Join(dir, "chaindata"), 0, 0, "", false)
	if err != nil {
		t.Fatalf("open leveldb: %v", err)
	}
	db, err := NewDatabaseWithFreezer(kv, ancient, "", false)
	if err != nil {
		t.Fatalf("open freezer-backed db: %v", err)
	}
	writeTestChain(t, db, 40)
	if err := db.(*freezerdb).Freeze(); err != nil {
		t.Fatalf("freeze: %v", err)
	}
	if frozen, _ := db.Ancients(); frozen == 0 {
		t.Fatal("nothing was frozen, test is vacuous")
	}
	db.Close()

	// Second run: pair that same ancient store with a fresh key-value store
	// carrying a different genesis. This must be refused.
	kv2, err := leveldb.New(filepath.Join(dir, "chaindata2"), 0, 0, "", false)
	if err != nil {
		t.Fatalf("open second leveldb: %v", err)
	}
	defer kv2.Close()
	WriteCanonicalHash(kv2, common.HexToHash("0xdeadbeef"), 0)

	if _, err := NewDatabaseWithFreezer(kv2, ancient, "", false); err == nil {
		t.Fatal("expected genesis mismatch to be rejected, but the database opened")
	}
}

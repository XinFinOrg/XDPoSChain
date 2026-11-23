// Copyright 2020 The go-ethereum Authors
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
	"bytes"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/ethdb"
)

func TestTableDatabase(t *testing.T)            { testTableDatabase(t, "prefix") }
func TestEmptyPrefixTableDatabase(t *testing.T) { testTableDatabase(t, "") }

type testReplayer struct {
	puts [][]byte
	dels [][]byte
}

func (r *testReplayer) Put(key []byte, value []byte) error {
	r.puts = append(r.puts, key)
	return nil
}

func (r *testReplayer) Delete(key []byte) error {
	r.dels = append(r.dels, key)
	return nil
}

func testTableDatabase(t *testing.T, prefix string) {
	db := NewTable(NewMemoryDatabase(), prefix)

	var entries = []struct {
		key   []byte
		value []byte
	}{
		{[]byte{0x01, 0x02}, []byte{0x0a, 0x0b}},
		{[]byte{0x03, 0x04}, []byte{0x0c, 0x0d}},
		{[]byte{0x05, 0x06}, []byte{0x0e, 0x0f}},

		{[]byte{0xff, 0xff, 0x01}, []byte{0x1a, 0x1b}},
		{[]byte{0xff, 0xff, 0x02}, []byte{0x1c, 0x1d}},
		{[]byte{0xff, 0xff, 0x03}, []byte{0x1e, 0x1f}},
	}

	// Test Put/Get operation
	for _, entry := range entries {
		db.Put(entry.key, entry.value)
	}
	for _, entry := range entries {
		got, err := db.Get(entry.key)
		if err != nil {
			t.Fatalf("Failed to get value: %v", err)
		}
		if !bytes.Equal(got, entry.value) {
			t.Fatalf("Value mismatch: want=%v, got=%v", entry.value, got)
		}
	}

	// Test batch operation
	db = NewTable(NewMemoryDatabase(), prefix)
	batch := db.NewBatch()
	for _, entry := range entries {
		batch.Put(entry.key, entry.value)
	}
	batch.Write()
	for _, entry := range entries {
		got, err := db.Get(entry.key)
		if err != nil {
			t.Fatalf("Failed to get value: %v", err)
		}
		if !bytes.Equal(got, entry.value) {
			t.Fatalf("Value mismatch: want=%v, got=%v", entry.value, got)
		}
	}

	// Test batch replayer
	r := &testReplayer{}
	batch.Replay(r)
	for index, entry := range entries {
		got := r.puts[index]
		if !bytes.Equal(got, entry.key) {
			t.Fatalf("Key mismatch: want=%v, got=%v", entry.key, got)
		}
	}

	check := func(iter ethdb.Iterator, expCount, index int) {
		count := 0
		for iter.Next() {
			key, value := iter.Key(), iter.Value()
			if !bytes.Equal(key, entries[index].key) {
				t.Fatalf("Key mismatch: want=%v, got=%v", entries[index].key, key)
			}
			if !bytes.Equal(value, entries[index].value) {
				t.Fatalf("Value mismatch: want=%v, got=%v", entries[index].value, value)
			}
			index += 1
			count++
		}
		if count != expCount {
			t.Fatalf("Wrong number of elems, exp %d got %d", expCount, count)
		}
		iter.Release()
	}
	// Test iterators
	check(db.NewIterator(nil, nil), 6, 0)
	// Test iterators with prefix
	check(db.NewIterator([]byte{0xff, 0xff}, nil), 3, 3)
	// Test iterators with start point
	check(db.NewIterator(nil, []byte{0xff, 0xff, 0x02}), 2, 4)
	// Test iterators with prefix and start point
	check(db.NewIterator([]byte{0xee}, nil), 0, 0)
	check(db.NewIterator(nil, []byte{0x00}), 6, 0)

	// Test range deletion
	if err := db.DeleteRange(nil, nil); err != nil {
		t.Fatalf("Failed to delete range: %v", err)
	}
	for _, entry := range entries {
		if _, err := db.Get(entry.key); err == nil {
			t.Fatal("Unexpected item after deletion")
		}
	}
	// Test range deletion by batch
	batch = db.NewBatch()
	for _, entry := range entries {
		batch.Put(entry.key, entry.value)
	}
	batch.Write()
	batch.Reset()
	batch.DeleteRange(nil, nil)
	batch.Write()
	for _, entry := range entries {
		if _, err := db.Get(entry.key); err == nil {
			t.Fatal("Unexpected item after deletion")
		}
	}
	// Test range deletion through the batch replayer, into a table with a
	// different prefix: the replayer has to strip the source prefix and keep
	// the deletion inside the destination table.
	dst := NewMemoryDatabase()
	dstTable := NewTable(dst, "dst"+prefix)
	for _, entry := range entries {
		if err := dstTable.Put(entry.key, entry.value); err != nil {
			t.Fatalf("Failed to seed destination table: %v", err)
		}
	}
	if err := dst.Put([]byte("unrelated"), []byte("value")); err != nil {
		t.Fatalf("Failed to seed unrelated key: %v", err)
	}
	batch = db.NewBatch()
	batch.DeleteRange(nil, nil)
	if err := batch.Replay(dstTable); err != nil {
		t.Fatalf("Failed to replay range deletion: %v", err)
	}
	for _, entry := range entries {
		if _, err := dstTable.Get(entry.key); err == nil {
			t.Fatal("Unexpected item after replayed deletion")
		}
	}
	if _, err := dst.Get([]byte("unrelated")); err != nil {
		t.Fatal("Replay deleted a key outside the destination table")
	}
}

// TestTableDeleteRangeUnboundedBound pins what an unbounded table deletion
// actually covers. A nil end becomes ethdb.MaximumKey after the table prefix,
// so table-relative keys at or beyond 32 0xFF bytes are outside the range.
func TestTableDeleteRangeUnboundedBound(t *testing.T) {
	db := NewTable(NewMemoryDatabase(), "p")

	ff := func(n int) []byte { return bytes.Repeat([]byte{0xff}, n) }
	entries := []struct {
		name     string
		key      []byte
		survives bool
	}{
		{"ordinary", []byte("ordinary"), false},
		{"ff31_fe", append(ff(31), 0xfe), false},
		{"ff32", ff(32), true},
		{"ff32_00", append(ff(32), 0x00), true},
		{"ff33", ff(33), true},
	}
	for _, entry := range entries {
		if err := db.Put(entry.key, []byte(entry.name)); err != nil {
			t.Fatalf("Failed to seed %s: %v", entry.name, err)
		}
	}
	if err := db.DeleteRange(nil, nil); err != nil {
		t.Fatalf("Failed to delete range: %v", err)
	}
	for _, entry := range entries {
		has, err := db.Has(entry.key)
		if err != nil {
			t.Fatalf("%s: %v", entry.name, err)
		}
		if has != entry.survives {
			t.Fatalf("%s: has %v, want %v, the unbounded end is prefix||MaximumKey", entry.name, has, entry.survives)
		}
	}
}

// TestTableDeleteRangeNamespace pins that a table-level range deletion stays
// inside the table namespace and honours nil-versus-empty bounds. Both backends
// run the same assertions: the table wrapper prefixes the bounds before they
// reach the store, and a missing prefix would widen the range into the
// neighbouring table or the raw key space.
func TestTableDeleteRangeNamespace(t *testing.T) {
	for _, backend := range []string{"memorydb", "leveldb"} {
		t.Run(backend, func(t *testing.T) {
			var db ethdb.Database
			if backend == "leveldb" {
				leveldb, err := NewLevelDBDatabase(t.TempDir(), 16, 16, "", false)
				if err != nil {
					t.Fatalf("Failed to open leveldb: %v", err)
				}
				db = leveldb
			} else {
				db = NewMemoryDatabase()
			}
			defer db.Close()
			testTableDeleteRangeNamespace(t, db)
		})
	}
}

func testTableDeleteRangeNamespace(t *testing.T, db ethdb.Database) {
	t.Helper()

	var (
		p, q    = NewTable(db, "p"), NewTable(db, "q")
		keys    = []string{"a", "b", "c", "d"}
		rawKeys = []string{"aa", "mm", "zz"} // "mm" sits between an unprefixed start and its prefixed form
	)
	seed := func() {
		t.Helper()
		for _, key := range rawKeys {
			if err := db.Put([]byte(key), []byte("v")); err != nil {
				t.Fatalf("Failed to seed raw key %s: %v", key, err)
			}
		}
		for _, key := range keys {
			for _, table := range []ethdb.Database{p, q} {
				if err := table.Put([]byte(key), []byte("v")); err != nil {
					t.Fatalf("Failed to seed table key %s: %v", key, err)
				}
			}
		}
	}
	has := func(table ethdb.Database, key string) bool {
		ok, err := table.Has([]byte(key))
		if err != nil {
			t.Fatalf("Failed to check key %s: %v", key, err)
		}
		return ok
	}
	check := func(label string, table ethdb.Database, want map[string]bool) {
		t.Helper()
		for _, key := range keys {
			if got := has(table, key); got != want[key] {
				t.Fatalf("%s: table key %s has %v, want %v", label, key, got, want[key])
			}
		}
	}
	checkRaw := func(label string) {
		t.Helper()
		for _, key := range rawKeys {
			if !has(db, key) {
				t.Fatalf("%s: raw key %s was deleted outside the table", label, key)
			}
		}
	}
	all := map[string]bool{"a": true, "b": true, "c": true, "d": true}

	// A bounded store-level range only removes the keys inside the table range.
	seed()
	if err := p.DeleteRange([]byte("b"), []byte("d")); err != nil {
		t.Fatalf("Failed to delete range: %v", err)
	}
	check("store bounded", p, map[string]bool{"a": true, "b": false, "c": false, "d": true})
	check("store bounded", q, all)
	checkRaw("store bounded")

	// The same range through a batch has to reach the same keys.
	seed()
	batch := p.NewBatch()
	if err := batch.DeleteRange([]byte("b"), []byte("d")); err != nil {
		t.Fatalf("Failed to queue range: %v", err)
	}
	if err := batch.Write(); err != nil {
		t.Fatalf("Failed to write batch: %v", err)
	}
	check("batch bounded", p, map[string]bool{"a": true, "b": false, "c": false, "d": true})
	check("batch bounded", q, all)
	checkRaw("batch bounded")

	// An unbounded batch range clears the table, not the store.
	seed()
	batch = p.NewBatch()
	if err := batch.DeleteRange(nil, nil); err != nil {
		t.Fatalf("Failed to queue unbounded range: %v", err)
	}
	if err := batch.Write(); err != nil {
		t.Fatalf("Failed to write batch: %v", err)
	}
	check("batch unbounded", p, map[string]bool{"a": false, "b": false, "c": false, "d": false})
	check("batch unbounded", q, all)
	checkRaw("batch unbounded")

	// A nil end stays unbounded; an empty (non-nil) end is an empty range.
	seed()
	if err := p.DeleteRange([]byte("b"), nil); err != nil {
		t.Fatalf("Failed to delete range: %v", err)
	}
	check("nil end", p, map[string]bool{"a": true, "b": false, "c": false, "d": false})
	checkRaw("nil end")

	seed()
	if err := p.DeleteRange([]byte("b"), []byte{}); err != nil {
		t.Fatalf("Failed to delete empty range: %v", err)
	}
	check("empty end", p, all)
	checkRaw("empty end")

	seed()
	batch = p.NewBatch()
	if err := batch.DeleteRange([]byte("b"), []byte{}); err != nil {
		t.Fatalf("Failed to queue empty range: %v", err)
	}
	if err := batch.Write(); err != nil {
		t.Fatalf("Failed to write batch: %v", err)
	}
	check("empty end batch", p, all)
	checkRaw("empty end batch")
}

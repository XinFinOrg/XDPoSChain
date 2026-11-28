// Copyright 2019 The go-ethereum Authors
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

package dbtest

import (
	"bytes"
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/ethdb"
)

// TestDatabaseSuite runs a suite of tests against a KeyValueStore database
// implementation.
func TestDatabaseSuite(t *testing.T, New func() ethdb.KeyValueStore) {
	t.Run("Iterator", func(t *testing.T) {
		tests := []struct {
			content map[string]string
			prefix  string
			start   string
			order   []string
		}{
			// Empty databases should be iterable
			{map[string]string{}, "", "", nil},
			{map[string]string{}, "non-existent-prefix", "", nil},

			// Single-item databases should be iterable
			{map[string]string{"key": "val"}, "", "", []string{"key"}},
			{map[string]string{"key": "val"}, "k", "", []string{"key"}},
			{map[string]string{"key": "val"}, "l", "", nil},

			// Multi-item databases should be fully iterable
			{
				map[string]string{"k1": "v1", "k5": "v5", "k2": "v2", "k4": "v4", "k3": "v3"},
				"", "",
				[]string{"k1", "k2", "k3", "k4", "k5"},
			},
			{
				map[string]string{"k1": "v1", "k5": "v5", "k2": "v2", "k4": "v4", "k3": "v3"},
				"k", "",
				[]string{"k1", "k2", "k3", "k4", "k5"},
			},
			{
				map[string]string{"k1": "v1", "k5": "v5", "k2": "v2", "k4": "v4", "k3": "v3"},
				"l", "",
				nil,
			},
			// Multi-item databases should be prefix-iterable
			{
				map[string]string{
					"ka1": "va1", "ka5": "va5", "ka2": "va2", "ka4": "va4", "ka3": "va3",
					"kb1": "vb1", "kb5": "vb5", "kb2": "vb2", "kb4": "vb4", "kb3": "vb3",
				},
				"ka", "",
				[]string{"ka1", "ka2", "ka3", "ka4", "ka5"},
			},
			{
				map[string]string{
					"ka1": "va1", "ka5": "va5", "ka2": "va2", "ka4": "va4", "ka3": "va3",
					"kb1": "vb1", "kb5": "vb5", "kb2": "vb2", "kb4": "vb4", "kb3": "vb3",
				},
				"kc", "",
				nil,
			},
			// Multi-item databases should be prefix-iterable with start position
			{
				map[string]string{
					"ka1": "va1", "ka5": "va5", "ka2": "va2", "ka4": "va4", "ka3": "va3",
					"kb1": "vb1", "kb5": "vb5", "kb2": "vb2", "kb4": "vb4", "kb3": "vb3",
				},
				"ka", "3",
				[]string{"ka3", "ka4", "ka5"},
			},
			{
				map[string]string{
					"ka1": "va1", "ka5": "va5", "ka2": "va2", "ka4": "va4", "ka3": "va3",
					"kb1": "vb1", "kb5": "vb5", "kb2": "vb2", "kb4": "vb4", "kb3": "vb3",
				},
				"ka", "8",
				nil,
			},
		}
		for i, tt := range tests {
			// Create the key-value data store
			db := New()
			for key, val := range tt.content {
				if err := db.Put([]byte(key), []byte(val)); err != nil {
					t.Fatalf("test %d: failed to insert item %s:%s into database: %v", i, key, val, err)
				}
			}
			// Iterate over the database with the given configs and verify the results
			it, idx := db.NewIterator([]byte(tt.prefix), []byte(tt.start)), 0
			for it.Next() {
				if len(tt.order) <= idx {
					t.Errorf("test %d: prefix=%q more items than expected: checking idx=%d (key %q), expecting len=%d", i, tt.prefix, idx, it.Key(), len(tt.order))
					break
				}
				if !bytes.Equal(it.Key(), []byte(tt.order[idx])) {
					t.Errorf("test %d: item %d: key mismatch: have %s, want %s", i, idx, string(it.Key()), tt.order[idx])
				}
				if !bytes.Equal(it.Value(), []byte(tt.content[tt.order[idx]])) {
					t.Errorf("test %d: item %d: value mismatch: have %s, want %s", i, idx, string(it.Value()), tt.content[tt.order[idx]])
				}
				idx++
			}
			if err := it.Error(); err != nil {
				t.Errorf("test %d: iteration failed: %v", i, err)
			}
			if idx != len(tt.order) {
				t.Errorf("test %d: iteration terminated prematurely: have %d, want %d", i, idx, len(tt.order))
			}
			db.Close()
		}
	})

	t.Run("IteratorWith", func(t *testing.T) {
		db := New()
		defer db.Close()

		keys := []string{"1", "2", "3", "4", "6", "10", "11", "12", "20", "21", "22"}
		slices.Sort(keys) // 1, 10, 11, etc

		for _, k := range keys {
			if err := db.Put([]byte(k), nil); err != nil {
				t.Fatal(err)
			}
		}

		{
			it := db.NewIterator(nil, nil)
			got, want := iterateKeys(it), keys
			if err := it.Error(); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("Iterator: got: %s; want: %s", got, want)
			}
		}

		{
			it := db.NewIterator([]byte("1"), nil)
			got, want := iterateKeys(it), []string{"1", "10", "11", "12"}
			if err := it.Error(); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("IteratorWith(1,nil): got: %s; want: %s", got, want)
			}
		}

		{
			it := db.NewIterator([]byte("5"), nil)
			got, want := iterateKeys(it), []string{}
			if err := it.Error(); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("IteratorWith(5,nil): got: %s; want: %s", got, want)
			}
		}

		{
			it := db.NewIterator(nil, []byte("2"))
			got, want := iterateKeys(it), []string{"2", "20", "21", "22", "3", "4", "6"}
			if err := it.Error(); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("IteratorWith(nil,2): got: %s; want: %s", got, want)
			}
		}

		{
			it := db.NewIterator(nil, []byte("5"))
			got, want := iterateKeys(it), []string{"6"}
			if err := it.Error(); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("IteratorWith(nil,5): got: %s; want: %s", got, want)
			}
		}
	})

	t.Run("KeyValueOperations", func(t *testing.T) {
		db := New()
		defer db.Close()

		key := []byte("foo")

		if got, err := db.Has(key); err != nil {
			t.Error(err)
		} else if got {
			t.Errorf("wrong value: %t", got)
		}

		value := []byte("hello world")
		if err := db.Put(key, value); err != nil {
			t.Error(err)
		}

		if got, err := db.Has(key); err != nil {
			t.Error(err)
		} else if !got {
			t.Errorf("wrong value: %t", got)
		}

		if got, err := db.Get(key); err != nil {
			t.Error(err)
		} else if !bytes.Equal(got, value) {
			t.Errorf("wrong value: %q", got)
		}

		if err := db.Delete(key); err != nil {
			t.Error(err)
		}

		if got, err := db.Has(key); err != nil {
			t.Error(err)
		} else if got {
			t.Errorf("wrong value: %t", got)
		}
	})

	t.Run("Batch", func(t *testing.T) {
		db := New()
		defer db.Close()

		b := db.NewBatch()
		for _, k := range []string{"1", "2", "3", "4"} {
			if err := b.Put([]byte(k), nil); err != nil {
				t.Fatal(err)
			}
		}

		if has, err := db.Has([]byte("1")); err != nil {
			t.Fatal(err)
		} else if has {
			t.Error("db contains element before batch write")
		}

		if err := b.Write(); err != nil {
			t.Fatal(err)
		}

		{
			it := db.NewIterator(nil, nil)
			if got, want := iterateKeys(it), []string{"1", "2", "3", "4"}; !reflect.DeepEqual(got, want) {
				t.Errorf("got: %s; want: %s", got, want)
			}
		}

		b.Reset()

		// Mix writes and deletes in batch
		b.Put([]byte("5"), nil)
		b.Delete([]byte("1"))
		b.Put([]byte("6"), nil)
		b.Delete([]byte("3"))
		b.Put([]byte("3"), nil)

		if err := b.Write(); err != nil {
			t.Fatal(err)
		}

		{
			it := db.NewIterator(nil, nil)
			if got, want := iterateKeys(it), []string{"2", "3", "4", "5", "6"}; !reflect.DeepEqual(got, want) {
				t.Errorf("got: %s; want: %s", got, want)
			}
		}
	})

	t.Run("BatchReplay", func(t *testing.T) {
		db := New()
		defer db.Close()

		want := []string{"1", "2", "3", "4"}
		b := db.NewBatch()
		for _, k := range want {
			if err := b.Put([]byte(k), nil); err != nil {
				t.Fatal(err)
			}
		}

		b2 := db.NewBatch()
		if err := b.Replay(b2); err != nil {
			t.Fatal(err)
		}

		if err := b2.Replay(db); err != nil {
			t.Fatal(err)
		}

		it := db.NewIterator(nil, nil)
		if got := iterateKeys(it); !reflect.DeepEqual(got, want) {
			t.Errorf("got: %s; want: %s", got, want)
		}
	})

	t.Run("DeleteRange", func(t *testing.T) {
		db := New()
		defer db.Close()

		for i := 0; i < 20; i++ {
			if err := db.Put([]byte(fmt.Sprintf("key-%02d", i)), []byte("value")); err != nil {
				t.Fatal(err)
			}
		}
		// Delete the range [key-05, key-15).
		if err := db.DeleteRange([]byte("key-05"), []byte("key-15")); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 20; i++ {
			key := []byte(fmt.Sprintf("key-%02d", i))
			has, err := db.Has(key)
			if err != nil {
				t.Fatal(err)
			}
			if want := i < 5 || i >= 15; has != want {
				t.Fatalf("key %s: has %v, want %v", key, has, want)
			}
		}
		// Batch based range deletion.
		batch := db.NewBatch()
		if err := batch.DeleteRange([]byte("key-00"), []byte("key-03")); err != nil {
			t.Fatal(err)
		}
		if err := batch.Write(); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 5; i++ {
			has, err := db.Has([]byte(fmt.Sprintf("key-%02d", i)))
			if err != nil {
				t.Fatal(err)
			}
			if want := i >= 3; has != want {
				t.Fatalf("key %d: has %v, want %v", i, has, want)
			}
		}
		// Degenerate ranges delete nothing: an inverted range and an empty
		// range both stay empty whatever the iteration order is.
		if err := db.DeleteRange([]byte("key-19"), []byte("key-03")); err != nil {
			t.Fatal(err)
		}
		if err := db.DeleteRange([]byte("key-16"), []byte("key-16")); err != nil {
			t.Fatal(err)
		}
		for _, key := range []string{"key-03", "key-04", "key-16", "key-19"} {
			has, err := db.Has([]byte(key))
			if err != nil {
				t.Fatal(err)
			}
			if !has {
				t.Fatalf("%s: deleted by a degenerate range", key)
			}
		}
		// An empty lower bound is the first key, and the end stays exclusive.
		if err := db.DeleteRange([]byte(""), []byte("key-04")); err != nil {
			t.Fatal(err)
		}
		if has, err := db.Has([]byte("key-03")); err != nil || has {
			t.Fatalf("key-03: has %v, err %v", has, err)
		}
		if has, err := db.Has([]byte("key-04")); err != nil || !has {
			t.Fatalf("key-04: has %v, err %v", has, err)
		}
		// Unbounded range deletion.
		if err := db.DeleteRange(nil, nil); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 20; i++ {
			has, err := db.Has([]byte(fmt.Sprintf("key-%02d", i)))
			if err != nil {
				t.Fatal(err)
			}
			if has {
				t.Fatalf("key %d: still present after unbounded deletion", i)
			}
		}
	})

	t.Run("BatchDeleteRange", func(t *testing.T) {
		db := New()
		defer db.Close()

		addKeys := func(start, stop int) {
			for i := start; i <= stop; i++ {
				if err := db.Put([]byte(strconv.Itoa(i)), []byte("val-"+strconv.Itoa(i))); err != nil {
					t.Fatal(err)
				}
			}
		}
		checkKeys := func(start, stop int, shouldExist bool) {
			for i := start; i <= stop; i++ {
				key := []byte(strconv.Itoa(i))
				has, err := db.Has(key)
				if err != nil {
					t.Fatal(err)
				}
				if has != shouldExist {
					t.Fatalf("key %s: has %v, want %v", key, has, shouldExist)
				}
			}
		}

		// A queued range deletion only takes effect on Write.
		addKeys(1, 10)
		batch := db.NewBatch()
		if err := batch.DeleteRange([]byte("3"), []byte("8")); err != nil {
			t.Fatal(err)
		}
		checkKeys(1, 10, true)
		if err := batch.Write(); err != nil {
			t.Fatal(err)
		}
		checkKeys(1, 2, true)
		checkKeys(3, 7, false)
		checkKeys(8, 10, true)

		// Unbounded deletion.
		addKeys(3, 7)
		batch = db.NewBatch()
		if err := batch.DeleteRange(nil, nil); err != nil {
			t.Fatal(err)
		}
		if err := batch.Write(); err != nil {
			t.Fatal(err)
		}
		checkKeys(1, 10, false)

		// Mixed Put, Delete and DeleteRange in one batch.
		addKeys(1, 10)
		batch = db.NewBatch()
		if err := batch.Put([]byte("5"), []byte("new-val-5")); err != nil {
			t.Fatal(err)
		}
		if err := batch.Delete([]byte("9")); err != nil {
			t.Fatal(err)
		}
		if err := batch.DeleteRange([]byte("1"), []byte("3")); err != nil {
			t.Fatal(err)
		}
		if err := batch.Write(); err != nil {
			t.Fatal(err)
		}
		checkKeys(1, 2, false)
		checkKeys(3, 4, true)
		checkKeys(6, 8, true)
		checkKeys(9, 9, false)
		if value, err := db.Get([]byte("5")); err != nil || !bytes.Equal(value, []byte("new-val-5")) {
			t.Fatalf("key 5: value %q, err %v", value, err)
		}

		// Reset drops a queued range deletion.
		batch = db.NewBatch()
		if err := batch.DeleteRange([]byte("1"), []byte("9")); err != nil {
			t.Fatal(err)
		}
		batch.Reset()
		if err := batch.Delete([]byte("8")); err != nil {
			t.Fatal(err)
		}
		if err := batch.Write(); err != nil {
			t.Fatal(err)
		}
		checkKeys(3, 7, true)
		checkKeys(8, 8, false)
	})

	t.Run("BatchDeleteRangeValueSize", func(t *testing.T) {
		db := New()
		defer db.Close()

		// A range that only matches the empty key still queues one deletion.
		// ValueSize must not report zero, or a caller flushing on
		// ValueSize() > 0 would drop the batch and leave the key behind.
		if err := db.Put([]byte(""), []byte("v")); err != nil {
			t.Fatal(err)
		}
		batch := db.NewBatch()
		if err := batch.DeleteRange(nil, []byte("a")); err != nil {
			t.Fatal(err)
		}
		if size := batch.ValueSize(); size <= 0 {
			t.Fatalf("range deletion of the empty key reports ValueSize %d, want > 0", size)
		}
		if err := batch.Write(); err != nil {
			t.Fatal(err)
		}
		if has, err := db.Has([]byte("")); err != nil || has {
			t.Fatalf("empty key: has %v, err %v", has, err)
		}

		// An unbounded range carries no bound bytes either, but it is still
		// pending work.
		if err := db.Put([]byte("k"), []byte("v")); err != nil {
			t.Fatal(err)
		}
		batch = db.NewBatch()
		if err := batch.DeleteRange(nil, nil); err != nil {
			t.Fatal(err)
		}
		if size := batch.ValueSize(); size <= 0 {
			t.Fatalf("unbounded range deletion reports ValueSize %d, want > 0", size)
		}
		if err := batch.Write(); err != nil {
			t.Fatal(err)
		}
		if has, err := db.Has([]byte("k")); err != nil || has {
			t.Fatalf("key k: has %v, err %v", has, err)
		}
	})

	t.Run("BatchReplayWithDeleteRange", func(t *testing.T) {
		db := New()
		defer db.Close()

		for i := 1; i <= 10; i++ {
			if err := db.Put([]byte(strconv.Itoa(i)), []byte("val-"+strconv.Itoa(i))); err != nil {
				t.Fatal(err)
			}
		}
		batch := db.NewBatch()
		batch.Put([]byte("new-key-1"), []byte("new-val-1"))
		batch.DeleteRange([]byte("3"), []byte("7"))
		batch.Delete([]byte("8"))
		batch.Put([]byte("new-key-2"), []byte("new-val-2"))

		// Replay into another batch, then write it.
		replayed := db.NewBatch()
		if err := batch.Replay(replayed); err != nil {
			t.Fatal(err)
		}
		if err := replayed.Write(); err != nil {
			t.Fatal(err)
		}
		for i := 3; i <= 6; i++ {
			if has, err := db.Has([]byte(strconv.Itoa(i))); err != nil || has {
				t.Fatalf("key %d: has %v, err %v", i, has, err)
			}
		}
		if has, err := db.Has([]byte("7")); err != nil || !has {
			t.Fatalf("key 7 must survive the exclusive end: has %v, err %v", has, err)
		}
		if has, err := db.Has([]byte("8")); err != nil || has {
			t.Fatalf("key 8 must be deleted: has %v, err %v", has, err)
		}
		for _, key := range []string{"new-key-1", "new-key-2"} {
			if has, err := db.Has([]byte(key)); err != nil || !has {
				t.Fatalf("%s: has %v, err %v", key, has, err)
			}
		}
		// Replay directly into the database.
		direct := db.NewBatch()
		if err := direct.DeleteRange([]byte("1"), []byte("3")); err != nil {
			t.Fatal(err)
		}
		if err := direct.Replay(db); err != nil {
			t.Fatal(err)
		}
		for i := 1; i <= 2; i++ {
			if has, err := db.Has([]byte(strconv.Itoa(i))); err != nil || has {
				t.Fatalf("key %d: has %v, err %v", i, has, err)
			}
		}
	})

	t.Run("OperationsAfterClose", func(t *testing.T) {
		db := New()
		if err := db.Put([]byte("key"), []byte("value")); err != nil {
			t.Fatal(err)
		}
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Get([]byte("key")); err == nil {
			t.Fatalf("expected error on Get after Close")
		}
		if _, err := db.Has([]byte("key")); err == nil {
			t.Fatalf("expected error on Has after Close")
		}
		if err := db.Put([]byte("key2"), []byte("value2")); err == nil {
			t.Fatalf("expected error on Put after Close")
		}
		if err := db.Delete([]byte("key")); err == nil {
			t.Fatalf("expected error on Delete after Close")
		}
		if err := db.DeleteRange([]byte("a"), []byte("b")); err == nil {
			t.Fatalf("expected error on DeleteRange after Close")
		}
		batch := db.NewBatch()
		if err := batch.Put([]byte("batchkey"), []byte("batchval")); err != nil {
			t.Fatalf("expected no error on batch.Put after Close, got %v", err)
		}
		if err := batch.Write(); err == nil {
			t.Fatalf("expected error on batch.Write after Close")
		}
	})
}

func iterateKeys(it ethdb.Iterator) []string {
	keys := []string{}
	for it.Next() {
		keys = append(keys, string(it.Key()))
	}
	slices.Sort(keys)
	it.Release()
	return keys
}

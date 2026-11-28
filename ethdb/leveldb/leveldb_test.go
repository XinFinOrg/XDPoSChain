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

package leveldb

import (
	"errors"
	"fmt"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/ethdb"
	"github.com/XinFinOrg/XDPoSChain/ethdb/dbtest"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/storage"
)

func TestLevelDB(t *testing.T) {
	t.Run("DatabaseSuite", func(t *testing.T) {
		dbtest.TestDatabaseSuite(t, func() ethdb.KeyValueStore {
			db, err := leveldb.Open(storage.NewMemStorage(), nil)
			if err != nil {
				t.Fatal(err)
			}
			return &Database{
				db: db,
			}
		})
	})
}

// TestBatchDeleteRangePendingPut pins the leveldb batch semantics: the bounds
// are resolved against the committed keys, so a key this batch inserts for the
// first time survives, while a put of an already committed key is deleted by
// the range. memorydb deletes both instead, see the same test in that package.
func TestBatchDeleteRangePendingPut(t *testing.T) {
	t.Run("FreshKey", func(t *testing.T) {
		db := newTestDatabase(t)
		defer db.Close()

		batch := db.NewBatch()
		if err := batch.Put([]byte("5"), []byte("v")); err != nil {
			t.Fatal(err)
		}
		if err := batch.DeleteRange([]byte("1"), []byte("9")); err != nil {
			t.Fatal(err)
		}
		if err := batch.Write(); err != nil {
			t.Fatal(err)
		}
		has, err := db.Has([]byte("5"))
		if err != nil {
			t.Fatal(err)
		}
		if !has {
			t.Fatalf("key 5 was first inserted by the same batch and must survive the committed-only range")
		}
	})
	t.Run("CommittedKey", func(t *testing.T) {
		db := newTestDatabase(t)
		defer db.Close()

		if err := db.Put([]byte("5"), []byte("old")); err != nil {
			t.Fatal(err)
		}
		batch := db.NewBatch()
		if err := batch.Put([]byte("5"), []byte("new")); err != nil {
			t.Fatal(err)
		}
		if err := batch.DeleteRange([]byte("1"), []byte("9")); err != nil {
			t.Fatal(err)
		}
		if err := batch.Write(); err != nil {
			t.Fatal(err)
		}
		has, err := db.Has([]byte("5"))
		if err != nil {
			t.Fatal(err)
		}
		if has {
			t.Fatalf("key 5 was already committed and must be deleted by the range appended after its put")
		}
	})
}

// TestBatchDeleteRangeAfterClose pins the iterator error check of
// (*batch).DeleteRange: on a closed database the iterator reports ErrClosed and
// DeleteRange has to surface it instead of silently queueing nothing.
func TestBatchDeleteRangeAfterClose(t *testing.T) {
	db := newTestDatabase(t)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := db.NewBatch().DeleteRange([]byte("a"), []byte("b")); err == nil {
		t.Fatal("expected an error from DeleteRange on a closed database")
	}
}

// failingReadsStorage wraps a storage.Storage and fails every file open once
// armed, so the iterator error paths of DeleteRange can be exercised without a
// real disk failure.
type failingReadsStorage struct {
	storage.Storage
	armed bool
}

// errReadFailure is the error a failingReadsStorage returns when armed.
var errReadFailure = errors.New("injected storage read failure")

// Open implements storage.Storage.
func (s *failingReadsStorage) Open(fd storage.FileDesc) (storage.Reader, error) {
	if s.armed {
		return nil, errReadFailure
	}
	return s.Storage.Open(fd)
}

// TestDeleteRangeIteratorError pins the iterator error checks of both
// DeleteRange implementations: a read failure has to surface as an error
// instead of the range being reported as deleted.
func TestDeleteRangeIteratorError(t *testing.T) {
	store := &failingReadsStorage{Storage: storage.NewMemStorage()}
	open := func() *Database {
		raw, err := leveldb.Open(store, nil)
		if err != nil {
			t.Fatal(err)
		}
		return &Database{db: raw}
	}
	// Write the range, flush it into a table file and reopen, so the next
	// iterator has to read through the storage instead of the memtable.
	db := open()
	putTestKeys(t, db, 0, 100)
	if err := db.Compact(nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db = open()
	defer db.Close()

	for _, entry := range []struct {
		name string
		call func() error
	}{
		{"store", func() error { return db.DeleteRange([]byte("key-00000"), []byte("l")) }},
		{"batch", func() error { return db.NewBatch().DeleteRange([]byte("key-00000"), []byte("l")) }},
	} {
		store.armed = true
		err := entry.call()
		store.armed = false
		if !errors.Is(err, errReadFailure) {
			t.Fatalf("%s DeleteRange over an unreadable range: err %v, want %v", entry.name, err, errReadFailure)
		}
	}
}

// newTestDatabase opens a leveldb database on in-memory storage.
func newTestDatabase(t *testing.T) *Database {
	t.Helper()

	raw, err := leveldb.Open(storage.NewMemStorage(), nil)
	if err != nil {
		t.Fatal(err)
	}
	return &Database{db: raw}
}

// putTestKeys seeds count keys named key-<first+i>, five digits wide.
func putTestKeys(t *testing.T, db *Database, first, count int) {
	t.Helper()

	batch := db.NewBatch()
	for i := first; i < first+count; i++ {
		if err := batch.Put([]byte(fmt.Sprintf("key-%05d", i)), []byte("v")); err != nil {
			t.Fatal(err)
		}
	}
	if err := batch.Write(); err != nil {
		t.Fatal(err)
	}
}

func putOutsideKeys(t *testing.T, db *Database) {
	t.Helper()

	for _, key := range []string{"aaa-outside", "zzz-outside"} {
		if err := db.Put([]byte(key), []byte("v")); err != nil {
			t.Fatal(err)
		}
	}
}

// countTestKeys counts the key-* entries in the database.
func countTestKeys(t *testing.T, db *Database) int {
	t.Helper()

	it := db.NewIterator([]byte("key-"), nil)
	defer it.Release()

	var count int
	for it.Next() {
		count++
	}
	if err := it.Error(); err != nil {
		t.Fatal(err)
	}
	return count
}

// checkOutsideKeys asserts that both seeded keys outside the range survive.
func checkOutsideKeys(t *testing.T, db *Database) {
	t.Helper()

	for _, key := range []string{"aaa-outside", "zzz-outside"} {
		has, err := db.Has([]byte(key))
		if err != nil {
			t.Fatal(err)
		}
		if !has {
			t.Fatalf("%s was deleted by an in-range call", key)
		}
	}
}

// TestDeleteRangeKeyLimit pins the store-level 10,000-key cap: a range of
// exactly 10,000 keys completes, while 10,001 keys commits the first 10,000
// and returns ErrTooManyKeys for the caller to retry.
func TestDeleteRangeKeyLimit(t *testing.T) {
	const (
		start = "key-00000"
		end   = "l" // past every key-* key, before zzz-outside
	)

	t.Run("ExactlyLimit", func(t *testing.T) {
		db := newTestDatabase(t)
		defer db.Close()

		putTestKeys(t, db, 0, 10000)
		putOutsideKeys(t, db)

		if err := db.DeleteRange([]byte(start), []byte(end)); err != nil {
			t.Fatalf("range of exactly 10000 keys: %v", err)
		}
		if count := countTestKeys(t, db); count != 0 {
			t.Fatalf("%d keys left after deleting exactly 10000", count)
		}
		checkOutsideKeys(t, db)
	})

	t.Run("OverLimit", func(t *testing.T) {
		db := newTestDatabase(t)
		defer db.Close()

		putTestKeys(t, db, 0, 10001)
		putOutsideKeys(t, db)

		err := db.DeleteRange([]byte(start), []byte(end))
		if !errors.Is(err, ethdb.ErrTooManyKeys) {
			t.Fatalf("range of 10001 keys: err %v, want ErrTooManyKeys", err)
		}
		if count := countTestKeys(t, db); count != 1 {
			t.Fatalf("%d keys left after ErrTooManyKeys, want 1 (the 10001st)", count)
		}
		if has, err := db.Has([]byte("key-10000")); err != nil || !has {
			t.Fatalf("key-10000: has %v, err %v", has, err)
		}
		checkOutsideKeys(t, db)

		if err := db.DeleteRange([]byte(start), []byte(end)); err != nil {
			t.Fatalf("retry after ErrTooManyKeys: %v", err)
		}
		if count := countTestKeys(t, db); count != 0 {
			t.Fatalf("%d keys left after the retry", count)
		}
		checkOutsideKeys(t, db)
	})
}

// TestBatchDeleteRangeKeyLimit pins the batch-level cap: the 10,000 deletions
// queued before ErrTooManyKeys are not committed until Write, and a retry only
// makes progress once a batch has been written.
func TestBatchDeleteRangeKeyLimit(t *testing.T) {
	const (
		start = "key-00000"
		end   = "l"
	)

	t.Run("Written", func(t *testing.T) {
		db := newTestDatabase(t)
		defer db.Close()

		putTestKeys(t, db, 0, 10001)
		putOutsideKeys(t, db)

		batch := db.NewBatch()
		err := batch.DeleteRange([]byte(start), []byte(end))
		if !errors.Is(err, ethdb.ErrTooManyKeys) {
			t.Fatalf("range of 10001 keys: err %v, want ErrTooManyKeys", err)
		}
		if size := batch.ValueSize(); size <= 0 {
			t.Fatalf("partial batch reports ValueSize %d, want > 0", size)
		}
		if count := countTestKeys(t, db); count != 10001 {
			t.Fatalf("%d keys left before Write, want 10001", count)
		}
		checkOutsideKeys(t, db)

		if err := batch.Write(); err != nil {
			t.Fatal(err)
		}
		if count := countTestKeys(t, db); count != 1 {
			t.Fatalf("%d keys left after writing the partial batch, want 1", count)
		}
		checkOutsideKeys(t, db)

		batch = db.NewBatch()
		if err := batch.DeleteRange([]byte(start), []byte(end)); err != nil {
			t.Fatalf("retry after the partial batch: %v", err)
		}
		if err := batch.Write(); err != nil {
			t.Fatal(err)
		}
		if count := countTestKeys(t, db); count != 0 {
			t.Fatalf("%d keys left after the retry", count)
		}
	})

	t.Run("Reset", func(t *testing.T) {
		db := newTestDatabase(t)
		defer db.Close()

		putTestKeys(t, db, 0, 10001)

		batch := db.NewBatch()
		err := batch.DeleteRange([]byte(start), []byte(end))
		if !errors.Is(err, ethdb.ErrTooManyKeys) {
			t.Fatalf("range of 10001 keys: err %v, want ErrTooManyKeys", err)
		}
		batch.Reset()
		if size := batch.ValueSize(); size != 0 {
			t.Fatalf("reset batch reports ValueSize %d, want 0", size)
		}
		if err := batch.Write(); err != nil {
			t.Fatalf("writing a reset batch: %v", err)
		}
		if count := countTestKeys(t, db); count != 10001 {
			t.Fatalf("%d keys left after writing a reset batch, want 10001", count)
		}

		// A discarded batch leaves no progress, so the retry hits the cap again.
		batch = db.NewBatch()
		err = batch.DeleteRange([]byte(start), []byte(end))
		if !errors.Is(err, ethdb.ErrTooManyKeys) {
			t.Fatalf("retry after Reset: err %v, want ErrTooManyKeys", err)
		}
		if err := batch.Write(); err != nil {
			t.Fatal(err)
		}
		if count := countTestKeys(t, db); count != 1 {
			t.Fatalf("%d keys left after writing the retried batch, want 1", count)
		}

		batch = db.NewBatch()
		if err := batch.DeleteRange([]byte(start), []byte(end)); err != nil {
			t.Fatalf("final retry: %v", err)
		}
		if err := batch.Write(); err != nil {
			t.Fatal(err)
		}
		if count := countTestKeys(t, db); count != 0 {
			t.Fatalf("%d keys left after the final retry", count)
		}
	})
}

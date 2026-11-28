// Copyright 2018 The go-ethereum Authors
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

package memorydb

import (
	"testing"

	"github.com/XinFinOrg/XDPoSChain/ethdb"
	"github.com/XinFinOrg/XDPoSChain/ethdb/dbtest"
)

func TestMemoryDB(t *testing.T) {
	t.Run("DatabaseSuite", func(t *testing.T) {
		dbtest.TestDatabaseSuite(t, func() ethdb.KeyValueStore {
			return New()
		})
	})
}

// TestBatchDeleteRangePendingPut pins the memorydb batch semantics: the bounds
// are applied at Write time over the whole key space, including writes queued
// in the same batch, so both a key this batch inserts for the first time and a
// put of an already committed key are deleted. leveldb keeps the former
// instead, see the same test there.
func TestBatchDeleteRangePendingPut(t *testing.T) {
	t.Run("FreshKey", func(t *testing.T) {
		db := New()
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
		if has {
			t.Fatalf("key 5 was first inserted by the same batch and must be deleted at Write time")
		}
	})
	t.Run("CommittedKey", func(t *testing.T) {
		db := New()
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
			t.Fatalf("key 5 was already committed and must be deleted at Write time")
		}
	})
}

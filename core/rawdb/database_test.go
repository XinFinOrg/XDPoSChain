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
	"errors"
	"io"
	"math/big"
	"os"
	"strings"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/ethdb"
)

// captureStdout runs fn with os.Stdout redirected to a pipe and returns whatever
// fn wrote to it. InspectDatabase renders its report straight to os.Stdout, so
// that is the only place the effect of its early return on an aborted walk shows.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	orig := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = orig }()

	fn()

	if err := w.Close(); err != nil {
		t.Fatalf("failed to close the pipe writer: %v", err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("failed to read the captured output: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("failed to close the pipe reader: %v", err)
	}
	return string(out)
}

// TestInspectDatabaseIteratorError checks that a keyspace walk the database
// aborts halfway is reported, instead of rendering a table built from a partial
// scan and returning nil, and that a walk that runs to the end still renders the
// report. The failing store at the bottom of this file is a copy of the one
// TestDeleteDanglingHashes uses; see the note there.
func TestInspectDatabaseIteratorError(t *testing.T) {
	db := NewMemoryDatabase()
	defer db.Close()
	writeOrphanHeaders(db, 10, 5)

	walkErr := errors.New("iterator failed")
	store := &failingIterStore{Database: db, limit: 1, err: walkErr}
	var aborted error
	rendered := captureStdout(t, func() { aborted = InspectDatabase(store, nil, nil) })
	if !errors.Is(aborted, walkErr) {
		t.Fatalf("expected the iterator error to be returned, got %v", aborted)
	}
	if rendered != "" {
		t.Fatalf("an aborted walk rendered a report built from a partial scan:\n%s", rendered)
	}

	// The other side of the same boundary: the early return above must not
	// degenerate into a walk that never renders anything.
	var clean error
	report := captureStdout(t, func() { clean = InspectDatabase(db, nil, nil) })
	if clean != nil {
		t.Fatalf("clean walk returned an error: %v", clean)
	}
	if !strings.Contains(strings.ToUpper(report), "TOTAL") {
		t.Fatalf("clean walk did not render the report:\n%s", report)
	}
}

// The three declarations below are a verbatim copy of the fixtures
// TestDeleteDanglingHashes uses in accessors_chain_test.go, which dev-upgrade
// does not have yet. They are duplicated here only so this branch builds on its
// own; once that branch lands, rebase and delete everything from this comment
// to the end of the file, leaving captureStdout and TestInspectDatabaseIteratorError
// to pick the shared fixtures up from accessors_chain_test.go.

// failingIterator wraps an iterator so that it stops feeding keys after limit
// items and then reports err, imitating a database that aborts the walk halfway.
type failingIterator struct {
	inner ethdb.Iterator
	limit int
	err   error
}

func (it *failingIterator) Next() bool {
	if it.limit <= 0 {
		return false
	}
	if !it.inner.Next() {
		return false
	}
	it.limit--
	return true
}

func (it *failingIterator) Error() error {
	if it.limit <= 0 {
		return it.err
	}
	return it.inner.Error()
}

func (it *failingIterator) Key() []byte   { return it.inner.Key() }
func (it *failingIterator) Value() []byte { return it.inner.Value() }
func (it *failingIterator) Release()      { it.inner.Release() }

// failingIterStore hands out failingIterator instances over a backing database.
type failingIterStore struct {
	ethdb.Database
	limit int
	err   error
}

func (db *failingIterStore) NewIterator(prefix, start []byte) ethdb.Iterator {
	return &failingIterator{inner: db.Database.NewIterator(prefix, start), limit: db.limit, err: db.err}
}

// writeOrphanHeaders writes count headers at the heights immediately above head.
// Each header comes with the total-difficulty entry and the canonical marker that
// a real import would have left next to it.
func writeOrphanHeaders(db ethdb.KeyValueWriter, head uint64, count int) []*types.Header {
	headers := make([]*types.Header, 0, count)
	for i := 1; i <= count; i++ {
		number := head + uint64(i)
		header := &types.Header{Number: new(big.Int).SetUint64(number)}
		WriteHeader(db, header)
		WriteTd(db, header.Hash(), number, big.NewInt(int64(i+1)))
		WriteCanonicalHash(db, header.Hash(), number)
		headers = append(headers, header)
	}
	return headers
}

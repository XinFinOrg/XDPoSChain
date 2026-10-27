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
	"os"
	"strings"
	"testing"
)

// captureStdout runs fn with os.Stdout redirected to a pipe and returns whatever
// fn wrote to it. InspectDatabase renders its report straight to os.Stdout, so
// that is the only place the effect of its early return on an aborted walk shows
// up. The pipe is drained from its own goroutine so that fn cannot deadlock
// against the pipe buffer, however much it writes; keep that property when
// reusing this helper. Swapping the global os.Stdout also assumes the test runs
// serially, which the package does.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	orig := os.Stdout
	os.Stdout = w
	t.Cleanup(func() { os.Stdout = orig })

	var (
		out   string
		rdErr error
		done  = make(chan struct{})
	)
	go func() {
		defer close(done)
		bs, err := io.ReadAll(r)
		out, rdErr = string(bs), err
	}()

	fn()

	if err := w.Close(); err != nil {
		t.Fatalf("failed to close the pipe writer: %v", err)
	}
	<-done
	if err := r.Close(); err != nil {
		t.Fatalf("failed to close the pipe reader: %v", err)
	}
	if rdErr != nil {
		t.Fatalf("failed to read the captured output: %v", rdErr)
	}
	return out
}

// TestInspectDatabaseIteratorError checks that a keyspace walk that the database
// aborts halfway is reported as an error, instead of rendering a table built from a partial
// scan and returning nil, and that a walk that runs to the end still renders the
// report. The failing store it uses is shared with
// TestDeleteDanglingHashesIteratorError, in accessors_chain_test.go.
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
	var cleanErr error
	report := captureStdout(t, func() { cleanErr = InspectDatabase(db, nil, nil) })
	if cleanErr != nil {
		t.Fatalf("clean walk returned an error: %v", cleanErr)
	}
	if !strings.Contains(strings.ToUpper(report), "TOTAL") {
		t.Fatalf("clean walk did not render the report:\n%s", report)
	}
	// A footer alone is not a report: a table that lost its data rows, or one
	// whose total collapsed to zero, would still satisfy the check above.
	if !strings.Contains(strings.ToUpper(report), "KEY-VALUE STORE") {
		t.Fatalf("clean walk did not render the per-category rows:\n%s", report)
	}
	var totals int
	for _, line := range strings.Split(report, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || !strings.EqualFold(fields[1], "TOTAL") {
			continue
		}
		totals++
		if strings.Contains(strings.ToUpper(line), "0.00 B") {
			t.Fatalf("clean walk rendered a zero total over a non-empty database:\n%s", report)
		}
	}
	// The loop above only checks the rows it recognises, so the total row has to
	// be accounted for explicitly: a renderer whose output no longer matches the
	// column layout probed here would otherwise leave the check above vacuous.
	if totals == 0 {
		t.Fatalf("clean walk rendered no total row:\n%s", report)
	}
}

// The fixtures failingIterator, failingIterStore and writeOrphanHeaders that
// this test uses live in accessors_chain_test.go, next to the other tests that
// need them.

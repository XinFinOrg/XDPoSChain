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

package testlog

import (
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/XinFinOrg/XDPoSChain/log"
)

// recorder is a T that keeps every line passed to Logf.
type recorder struct {
	mu   sync.Mutex
	msgs []string
}

func (r *recorder) Logf(format string, args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.msgs = append(r.msgs, fmt.Sprintf(format, args...))
}

func (r *recorder) Helper() {}

func (r *recorder) messages() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.msgs...)
}

// assertRecords fails the test unless got contains exactly the want
// messages, in order, each as a substring of its record.
func assertRecords(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d records, want %d: %q", len(got), len(want), got)
	}
	for i, w := range want {
		if !strings.Contains(got[i], w) {
			t.Fatalf("record %d is %q, want it to contain %q", i, got[i], w)
		}
	}
}

// TestLoggerKeepsAllRecordsAtMostVerboseLevel: at the most verbose level every
// record, severe ones included, has to reach the test log.
func TestLoggerKeepsAllRecordsAtMostVerboseLevel(t *testing.T) {
	rec := new(recorder)
	l := Logger(rec, log.LvlTrace)
	l.Debug("debug message")
	l.Info("info message")
	l.Error("error message")

	assertRecords(t, rec.messages(), []string{"debug message", "info message", "error message"})
}

// TestLoggerDropsRecordsBelowTheConfiguredLevel: at info, debug records are
// dropped while records at or above the level still get through. Without it a
// strict "greater than" comparison would also pass the test above.
func TestLoggerDropsRecordsBelowTheConfiguredLevel(t *testing.T) {
	rec := new(recorder)
	l := Logger(rec, log.LvlInfo)

	l.Debug("debug message")
	if msgs := rec.messages(); len(msgs) != 0 {
		t.Fatalf("got %d records for a message below the configured level: %q", len(msgs), msgs)
	}

	l.Info("info message")
	l.Error("error message")

	assertRecords(t, rec.messages(), []string{"info message", "error message"})
}

// TestSubLoggerPrintsItsOwnRecords: a logger derived with With writes through
// the handler With attached to it, attributes included.
func TestSubLoggerPrintsItsOwnRecords(t *testing.T) {
	rec := new(recorder)
	sub := Logger(rec, log.LvlTrace).With("component", "sub")
	sub.Info("from sub-logger")

	msgs := rec.messages()
	if len(msgs) != 1 {
		t.Fatalf("got %d records, want 1: %q", len(msgs), msgs)
	}
	if !strings.Contains(msgs[0], "from sub-logger") {
		t.Fatalf("record %q does not contain the message", msgs[0])
	}
	if !strings.Contains(msgs[0], "component=") || !strings.Contains(msgs[0], "sub") {
		t.Fatalf("record %q does not carry the logger's attribute", msgs[0])
	}
}

// TestParentAndSubLoggerKeepSeparateRecords: the logger and the one derived
// from it each flush their own buffer, so every record shows up exactly once.
func TestParentAndSubLoggerKeepSeparateRecords(t *testing.T) {
	rec := new(recorder)
	root := Logger(rec, log.LvlTrace)

	root.Info("root before")
	sub := root.With("component", "sub")
	sub.Info("sub message")
	root.Info("root after")

	msgs := rec.messages()
	want := []string{"root before", "sub message", "root after"}
	assertRecords(t, msgs, want)
	all := strings.Join(msgs, "\n")
	for _, w := range want {
		if got := strings.Count(all, w); got != 1 {
			t.Fatalf("%q appears %d times, want exactly once: %q", w, got, msgs)
		}
	}
}

// TestAttributeListsAreNotShared: appending attributes must not write into the
// slice a sibling handler still points at.
func TestAttributeListsAreNotShared(t *testing.T) {
	parent := &bufHandler{
		buf:   []slog.Record{},
		attrs: make([]slog.Attr, 1, 4),
		level: log.LvlTrace,
	}
	parent.attrs[0] = slog.String("parent", "p")

	first := parent.WithAttrs([]slog.Attr{slog.String("child", "first")}).(*bufHandler)
	second := parent.WithAttrs([]slog.Attr{slog.String("child", "second")}).(*bufHandler)

	if got := first.attrs[len(first.attrs)-1].Value.String(); got != "first" {
		t.Fatalf("first child's attribute was overwritten: child=%q", got)
	}
	if got := second.attrs[len(second.attrs)-1].Value.String(); got != "second" {
		t.Fatalf("second child's attribute was overwritten: child=%q", got)
	}
}

// TestTerminalFormatKeepsSiblingAttributes: terminalFormat must not write into
// the attribute array a sibling handler still reads. The two handlers below
// share one backing array, with spare capacity, on purpose.
func TestTerminalFormatKeepsSiblingAttributes(t *testing.T) {
	shared := make([]slog.Attr, 2, 4)
	shared[0] = slog.String("parent", "p")
	shared[1] = slog.String("sibling", "keep")

	victim := &bufHandler{attrs: shared[:1], level: log.LvlTrace}
	sibling := &bufHandler{attrs: shared[:2], level: log.LvlTrace}

	rec := slog.NewRecord(time.Now(), slog.LevelInfo, "message", 0)
	rec.Add("record", "attr")
	_ = victim.terminalFormat(rec)

	if got := sibling.attrs[1].Value.String(); got != "keep" {
		t.Fatalf("sibling attribute was overwritten by terminalFormat: sibling=%q", got)
	}
}

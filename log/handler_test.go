package log

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"
)

// refusingWriter rejects every write, so that Handle has an error to report.
type refusingWriter struct{}

var errWriteRefused = errors.New("write refused")

func (refusingWriter) Write([]byte) (int, error) { return 0, errWriteRefused }

// TestTerminalHandlerReportsWriteErrors checks that a rejected write reaches
// the caller instead of being silently dropped.
func TestTerminalHandlerReportsWriteErrors(t *testing.T) {
	h := NewTerminalHandlerWithLevel(refusingWriter{}, LevelInfo, false)
	rec := slog.NewRecord(time.Now(), slog.LevelInfo, "message", 0)
	if err := h.Handle(context.Background(), rec); !errors.Is(err, errWriteRefused) {
		t.Fatalf("Handle error is %v, want %v", err, errWriteRefused)
	}
}

// TestTerminalHandlerSharesMutex checks that handlers derived from a parent
// serialize their writes through the parent's mutex: they all write to the
// same writer, and fieldPadding is read under the same lock.
func TestTerminalHandlerSharesMutex(t *testing.T) {
	parent := NewTerminalHandler(io.Discard, false)
	child := parent.WithAttrs([]slog.Attr{slog.String("component", "child")}).(*TerminalHandler)
	if child.mu != parent.mu {
		t.Fatal("sub-handler does not share the parent's mutex")
	}
}

// TestTerminalHandlerDerivedHandlerBlocksOnParentMutex checks that the shared
// mutex is actually held while a derived handler writes: with the parent lock
// taken, a child's Handle must wait. A child carrying its own mutex writes
// straight through instead.
func TestTerminalHandlerDerivedHandlerBlocksOnParentMutex(t *testing.T) {
	parent := NewTerminalHandler(io.Discard, false)
	child := parent.WithAttrs([]slog.Attr{slog.String("component", "child")}).(*TerminalHandler)
	rec := slog.NewRecord(time.Now(), slog.LevelInfo, "message", 0)

	parent.mu.Lock()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = child.Handle(context.Background(), rec)
	}()

	select {
	case <-done:
		parent.mu.Unlock()
		t.Fatal("sub-handler wrote without waiting for the parent's mutex")
	case <-time.After(100 * time.Millisecond):
	}
	parent.mu.Unlock()
	<-done
}

// TestTerminalHandlerKeepsSiblingAttributes checks that appending attributes
// does not write into the array a sibling handler still points at. The parent
// below carries spare attribute capacity, which repeated appends leave behind.
func TestTerminalHandlerKeepsSiblingAttributes(t *testing.T) {
	parent := NewTerminalHandler(io.Discard, false)
	parent.attrs = make([]slog.Attr, 1, 4)
	parent.attrs[0] = slog.String("parent", "p")

	first := parent.WithAttrs([]slog.Attr{slog.String("child", "first")}).(*TerminalHandler)
	second := parent.WithAttrs([]slog.Attr{slog.String("child", "second")}).(*TerminalHandler)

	if got := first.attrs[1].Value.String(); got != "first" {
		t.Fatalf("first child's attribute was overwritten: child=%q", got)
	}
	if got := second.attrs[1].Value.String(); got != "second" {
		t.Fatalf("second child's attribute was overwritten: child=%q", got)
	}
}

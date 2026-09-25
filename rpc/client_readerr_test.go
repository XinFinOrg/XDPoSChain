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

package rpc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// errTestRead is the read error reported by readErrDuringWriteCodec and
// readErrWriteFailCodec.
var errTestRead = errors.New("test read error")

// errTestWrite is the write error used to force a reconnect.
var errTestWrite = errors.New("test write error")

// readErrDuringWriteCodec is a ServerCodec which fails the read while the caller
// is still blocked inside writeJSON. It reproduces the interleaving where
// dispatch handles the read error before the pending send is reported, and the
// write then succeeds anyway.
type readErrDuringWriteCodec struct {
	ServerCodec

	writeStartedOnce sync.Once
	closeOnce        sync.Once

	writeStarted chan struct{}
	connClosed   chan struct{}
}

func newReadErrDuringWriteCodec(codec ServerCodec) *readErrDuringWriteCodec {
	return &readErrDuringWriteCodec{
		ServerCodec:  codec,
		writeStarted: make(chan struct{}),
		connClosed:   make(chan struct{}),
	}
}

// readBatch reports a read error, but not before the peer has started to write.
func (c *readErrDuringWriteCodec) readBatch() ([]*jsonrpcMessage, bool, error) {
	<-c.writeStarted
	return nil, false, errTestRead
}

// writeJSON reports success, but only after the connection has been torn down,
// which means dispatch has already handled the read error reported above.
func (c *readErrDuringWriteCodec) writeJSON(ctx context.Context, msg interface{}, isError bool) error {
	c.writeStartedOnce.Do(func() { close(c.writeStarted) })
	<-c.connClosed
	return nil
}

// close is called by clientConn.close, which runs handler.close first, so
// signalling here means dispatch has finished handling the read error.
func (c *readErrDuringWriteCodec) close() {
	c.closeOnce.Do(func() { close(c.connClosed) })
	c.ServerCodec.close()
}

// TestCallFailsWhenReadErrorPrecedesWrite checks that a call whose write
// completes after the connection read loop has died returns the read error
// instead of waiting forever for a response that can never arrive.
func TestCallFailsWhenReadErrorPrecedesWrite(t *testing.T) {
	p1, p2 := net.Pipe()
	defer p2.Close()

	codec := newReadErrDuringWriteCodec(NewCodec(p1))
	client, err := newClient(context.Background(), new(clientConfig), func(context.Context) (ServerCodec, error) {
		return codec, nil
	})
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- client.CallContext(ctx, nil, "test_method")
	}()

	select {
	case err := <-errCh:
		if !errors.Is(err, errTestRead) {
			t.Fatalf("call returned %q, want %q", err, errTestRead)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("call did not return")
	}
}

// readErrWriteFailCodec fails the read and then fails the write, so that the
// pending request is retried on a reconnected connection.
type readErrWriteFailCodec struct {
	ServerCodec

	writeStartedOnce sync.Once
	closeOnce        sync.Once

	writeStarted chan struct{}
	connClosed   chan struct{}
}

func newReadErrWriteFailCodec(codec ServerCodec) *readErrWriteFailCodec {
	return &readErrWriteFailCodec{
		ServerCodec:  codec,
		writeStarted: make(chan struct{}),
		connClosed:   make(chan struct{}),
	}
}

func (c *readErrWriteFailCodec) readBatch() ([]*jsonrpcMessage, bool, error) {
	<-c.writeStarted
	return nil, false, errTestRead
}

// writeJSON waits for the read error to be handled before failing the write, so
// that dispatch establishes the new connection afterwards.
func (c *readErrWriteFailCodec) writeJSON(ctx context.Context, msg interface{}, isError bool) error {
	c.writeStartedOnce.Do(func() { close(c.writeStarted) })
	<-c.connClosed
	return errTestWrite
}

// close is called by clientConn.close, which runs handler.close first, so
// signalling here means dispatch has finished handling the read error.
func (c *readErrWriteFailCodec) close() {
	c.closeOnce.Do(func() { close(c.connClosed) })
	c.ServerCodec.close()
}

// responseCodec answers the first request it sees with "ok".
type responseCodec struct {
	ServerCodec

	answerOnce sync.Once
	answered   chan struct{}

	resp *jsonrpcMessage
}

func newResponseCodec(codec ServerCodec) *responseCodec {
	return &responseCodec{
		ServerCodec: codec,
		answered:    make(chan struct{}),
	}
}

func (c *responseCodec) readBatch() ([]*jsonrpcMessage, bool, error) {
	<-c.answered
	if c.resp != nil {
		resp := c.resp
		c.resp = nil
		return []*jsonrpcMessage{resp}, false, nil
	}
	<-c.closed()
	return nil, false, io.EOF
}

func (c *responseCodec) writeJSON(ctx context.Context, msg interface{}, isError bool) error {
	req, ok := msg.(*jsonrpcMessage)
	if !ok {
		return fmt.Errorf("unexpected message type %T", msg)
	}
	c.answerOnce.Do(func() {
		c.resp = &jsonrpcMessage{Version: "2.0", ID: req.ID, Result: json.RawMessage(`"ok"`)}
		close(c.answered)
	})
	return nil
}

// TestCallSurvivesReconnectAfterReadError checks that a request which is retried
// on a reconnected connection still receives its response, i.e. that it is not
// failed by the read error of the connection it was first written to.
func TestCallSurvivesReconnectAfterReadError(t *testing.T) {
	p1, p2 := net.Pipe()
	defer p2.Close()
	p3, p4 := net.Pipe()
	defer p4.Close()

	first := newReadErrWriteFailCodec(NewCodec(p1))
	second := newResponseCodec(NewCodec(p3))

	connects := 0
	client, err := newClient(context.Background(), new(clientConfig), func(context.Context) (ServerCodec, error) {
		connects++
		if connects == 1 {
			return first, nil
		}
		return second, nil
	})
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var (
		result string
		errCh  = make(chan error, 1)
	)
	go func() {
		errCh <- client.CallContext(ctx, &result, "test_method")
	}()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("call failed although it was retried on a new connection: %v", err)
		}
		if result != "ok" {
			t.Fatalf("call returned %q, want %q", result, "ok")
		}
	case <-time.After(30 * time.Second):
		t.Fatal("call did not return")
	}
}

// notifyReadErrCodec fails the read immediately and reports any later write as
// successful, so that a notification sent on the dead connection completes its
// write without a reconnect.
type notifyReadErrCodec struct {
	ServerCodec

	closeOnce  sync.Once
	connClosed chan struct{}
}

func newNotifyReadErrCodec(codec ServerCodec) *notifyReadErrCodec {
	return &notifyReadErrCodec{
		ServerCodec: codec,
		connClosed:  make(chan struct{}),
	}
}

func (c *notifyReadErrCodec) readBatch() ([]*jsonrpcMessage, bool, error) {
	return nil, false, errTestRead
}

// writeJSON reports success, but only after the connection has been torn down,
// which means dispatch has already handled the read error.
func (c *notifyReadErrCodec) writeJSON(ctx context.Context, msg interface{}, isError bool) error {
	<-c.connClosed
	return nil
}

// close is called by clientConn.close, which runs handler.close first, so
// signalling here means dispatch has finished handling the read error.
func (c *notifyReadErrCodec) close() {
	c.closeOnce.Do(func() { close(c.connClosed) })
	c.ServerCodec.close()
}

// TestNotifyAfterReadErrorDoesNotPanic checks that a notification sent after the
// connection read loop has died does not panic: notifications have no response
// channel, so the failure path for orphaned requests must leave them alone.
func TestNotifyAfterReadErrorDoesNotPanic(t *testing.T) {
	p1, p2 := net.Pipe()
	defer p2.Close()

	codec := newNotifyReadErrCodec(NewCodec(p1))
	client, err := newClient(context.Background(), new(clientConfig), func(context.Context) (ServerCodec, error) {
		return codec, nil
	})
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	// Wait until dispatch has handled the read error.
	<-codec.connClosed

	// The second notification synchronises with the failure path of the first
	// one: the send lock is only released after dispatch has handled the
	// completion of the previous send, so a panic there cannot be missed.
	for i := 0; i < 2; i++ {
		if err := client.Notify(context.Background(), "test_method"); err != nil {
			t.Fatalf("notify %d failed: %v", i, err)
		}
	}
}

// blockedWriteCodec reports the read error once the write has started and keeps
// the write blocked until the test releases it.
type blockedWriteCodec struct {
	ServerCodec

	writeStartedOnce sync.Once
	closeOnce        sync.Once

	writeStarted chan struct{}
	connClosed   chan struct{}
	releaseWrite chan struct{}
}

func newBlockedWriteCodec(codec ServerCodec) *blockedWriteCodec {
	return &blockedWriteCodec{
		ServerCodec:  codec,
		writeStarted: make(chan struct{}),
		connClosed:   make(chan struct{}),
		releaseWrite: make(chan struct{}),
	}
}

func (c *blockedWriteCodec) readBatch() ([]*jsonrpcMessage, bool, error) {
	<-c.writeStarted
	return nil, false, errTestRead
}

func (c *blockedWriteCodec) writeJSON(ctx context.Context, msg interface{}, isError bool) error {
	c.writeStartedOnce.Do(func() { close(c.writeStarted) })
	<-c.releaseWrite
	return nil
}

// close is called by clientConn.close, which runs handler.close first, so
// signalling here means dispatch has finished handling the read error.
func (c *blockedWriteCodec) close() {
	c.closeOnce.Do(func() { close(c.connClosed) })
	c.ServerCodec.close()
}

// TestClientCloseFailsUnansweredRequest checks that closing a client while a
// request is still being written does not leave that request waiting forever:
// Close documents that it aborts in-flight requests.
func TestClientCloseFailsUnansweredRequest(t *testing.T) {
	p1, p2 := net.Pipe()
	defer p2.Close()

	codec := newBlockedWriteCodec(NewCodec(p1))
	client, err := newClient(context.Background(), new(clientConfig), func(context.Context) (ServerCodec, error) {
		return codec, nil
	})
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- client.CallContext(ctx, nil, "test_method") }()

	// Wait until dispatch has handled the read error.
	select {
	case <-codec.connClosed:
	case <-time.After(10 * time.Second):
		t.Fatal("connection was not closed in time")
	}

	// Close while the write is still blocked: the send completion cannot be
	// pending in the dispatch select yet, so the close case always wins.
	closed := make(chan struct{})
	go func() { client.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(10 * time.Second):
		t.Fatal("client.Close did not return")
	}

	// Let the blocked write report success.
	close(codec.releaseWrite)

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("call succeeded unexpectedly")
		}
		if errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("call was left hanging until its context deadline: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("call did not return")
	}
}

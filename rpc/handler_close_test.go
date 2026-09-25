package rpc

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

const teardownTestTimeout = 10 * time.Second

// blockingService is a test service whose method only returns once the request
// context is done. It reports when the method has been entered and when it has
// observed the cancellation, so the tests can synchronise with the server side
// instead of sleeping.
type blockingService struct {
	entered   chan struct{}
	exited    chan struct{}
	enterOnce sync.Once
	exitOnce  sync.Once
}

// newBlockingService returns a blockingService with fresh signalling channels.
func newBlockingService() *blockingService {
	return &blockingService{entered: make(chan struct{}), exited: make(chan struct{})}
}

// WaitForContext parks until the request context is done and reports the
// cancellation it observed.
func (s *blockingService) WaitForContext(ctx context.Context) error {
	s.enterOnce.Do(func() { close(s.entered) })
	<-ctx.Done()
	s.exitOnce.Do(func() { close(s.exited) })
	return ctx.Err()
}

func waitForCallSignal(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(teardownTestTimeout):
		t.Fatalf("timed out waiting for %s", what)
	}
}

// waitForCodecRelease checks that the server dropped the codec of the torn down
// connection, which only happens once ServeCodec returned.
func waitForCodecRelease(t *testing.T, srv *Server) {
	t.Helper()
	deadline := time.Now().Add(teardownTestTimeout)
	for {
		srv.mutex.Lock()
		tracked := len(srv.codecs)
		srv.mutex.Unlock()
		if tracked == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("server still tracks %d codec(s) after the connection was torn down", tracked)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestHandlerCloseKeepsRunningCallAlive guards the behaviour handler.close is
// documented to have: a call that is still running must not observe the
// cancellation of its context, otherwise a single request served through
// serveSingleRequest is aborted before it can produce its response (see
// go-ethereum #19430).
func TestHandlerCloseKeepsRunningCallAlive(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()
	h := newHandler(context.Background(), NewCodec(serverConn), sequentialIDGenerator(), new(serviceRegistry), 0, 0)

	entered := make(chan struct{})
	release := make(chan struct{})
	ctxErr := make(chan error, 1)
	h.startCallProc(func(cp *callProc) {
		close(entered)
		<-release
		ctxErr <- cp.ctx.Err()
	})
	<-entered

	closed := make(chan struct{})
	go func() {
		h.close(io.EOF, nil)
		close(closed)
	}()

	select {
	case <-closed:
		t.Fatal("handler.close returned before the running call finished")
	case <-time.After(100 * time.Millisecond):
	}

	close(release)
	if err := <-ctxErr; err != nil {
		t.Fatalf("request context cancelled while the call was still running: %v", err)
	}
	waitForCallSignal(t, closed, "handler.close to return after the call finished")
	if err := h.rootCtx.Err(); !errors.Is(err, context.Canceled) {
		t.Fatalf("root context not cancelled by handler.close: %v", err)
	}
}

// TestHandlerCloseAbortReturnsWhileCallWaitsForContext checks that tearing down
// a connection is not blocked by a call that only returns once its context is
// cancelled: closeAbort cancels the contexts of the calls until the grace
// elapsed, and the calls observe the cancellation. A grace of zero models the
// teardown of a connection this node initiated, where no response can be
// delivered anymore.
func TestHandlerCloseAbortReturnsWhileCallWaitsForContext(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()
	h := newHandler(context.Background(), NewCodec(serverConn), sequentialIDGenerator(), new(serviceRegistry), 0, 0)

	entered := make(chan struct{})
	cancelled := make(chan struct{})
	h.startCallProc(func(cp *callProc) {
		close(entered)
		<-cp.ctx.Done()
		close(cancelled)
	})
	<-entered

	closed := make(chan struct{})
	go func() {
		h.closeAbort(io.EOF, nil, 0)
		close(closed)
	}()

	waitForCallSignal(t, closed, "handler.closeAbort to return while the call waits for its context")
	waitForCallSignal(t, cancelled, "the call to observe the cancellation")
}

// TestHandlerCloseAbortKeepsRunningCallAlive guards the other half of
// closeAbort: with a grace period, a call that produces its response within the
// grace must not observe a cancellation of its context. The read side of a
// connection can be gone while the peer still reads the response to a request
// it already sent, which is what TestServerShortLivedConn checks.
func TestHandlerCloseAbortKeepsRunningCallAlive(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()
	h := newHandler(context.Background(), NewCodec(serverConn), sequentialIDGenerator(), new(serviceRegistry), 0, 0)

	entered := make(chan struct{})
	release := make(chan struct{})
	ctxErr := make(chan error, 1)
	h.startCallProc(func(cp *callProc) {
		close(entered)
		<-release
		ctxErr <- cp.ctx.Err()
	})
	<-entered

	closed := make(chan struct{})
	go func() {
		h.closeAbort(io.EOF, nil, teardownResponseGrace)
		close(closed)
	}()

	select {
	case <-closed:
		t.Fatal("handler.closeAbort returned before the call finished or the grace elapsed")
	case <-time.After(100 * time.Millisecond):
	}

	close(release)
	if err := <-ctxErr; err != nil {
		t.Fatalf("request context cancelled while the call was still running: %v", err)
	}
	waitForCallSignal(t, closed, "handler.closeAbort to return after the call finished")
	if err := h.rootCtx.Err(); !errors.Is(err, context.Canceled) {
		t.Fatalf("root context not cancelled by handler.closeAbort: %v", err)
	}
}

// TestServerTeardownCancelsCallWaitingForContext covers the two ways a
// connection is torn down: the peer disappearing (read error) and Server.Stop.
// In both cases a call that only returns once its context is cancelled must not
// keep the teardown, and with it the codec, alive.
func TestServerTeardownCancelsCallWaitingForContext(t *testing.T) {
	t.Run("peer closes", func(t *testing.T) {
		srv := NewServer()
		svc := newBlockingService()
		if err := srv.RegisterName("block", svc); err != nil {
			t.Fatal(err)
		}
		serverConn, clientConn := net.Pipe()
		go srv.ServeCodec(NewCodec(serverConn), 0)

		client, err := newClient(context.Background(), new(clientConfig), func(context.Context) (ServerCodec, error) {
			return NewCodec(clientConn), nil
		})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), teardownTestTimeout)
		defer cancel()
		go client.CallContext(ctx, nil, "block_waitForContext")
		waitForCallSignal(t, svc.entered, "the call to reach the server")

		// The peer goes away while the call is still waiting for its context.
		// A read error cancels the call contexts only after
		// teardownResponseGrace elapsed, which is why observing the
		// cancellation can take that long.
		clientConn.Close()

		waitForCallSignal(t, svc.exited, "the call to observe the cancellation")
		waitForCodecRelease(t, srv)
		client.Close()
		serverConn.Close()
	})
	t.Run("server stops", func(t *testing.T) {
		srv := newTestServer()
		svc := newBlockingService()
		if err := srv.RegisterName("block", svc); err != nil {
			t.Fatal(err)
		}
		client := DialInProc(srv)

		ctx, cancel := context.WithTimeout(context.Background(), teardownTestTimeout)
		defer cancel()
		go client.CallContext(ctx, nil, "block_waitForContext")
		waitForCallSignal(t, svc.entered, "the call to reach the server")

		srv.Stop()

		waitForCallSignal(t, svc.exited, "the call to observe the cancellation")
		waitForCodecRelease(t, srv)
		client.Close()
	})
}

// delayedService answers after a short delay and observes its context, like the
// registered API methods do. A peer that closes only its write side must still
// receive that answer.
type delayedService struct {
	delay time.Duration
}

// Result answers after the configured delay, or as soon as its context is
// cancelled.
func (s *delayedService) Result(ctx context.Context) (string, error) {
	select {
	case <-time.After(s.delay):
		return "ok", nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// TestServerTeardownDeliversResponseToHalfClosedPeer covers the case
// TestServerShortLivedConn establishes for a method that observes its context:
// a peer that writes a request and then closes only its write side still
// receives the response. Cancelling the call contexts as soon as the read side
// dies replaces that response with a cancellation error.
func TestServerTeardownDeliversResponseToHalfClosedPeer(t *testing.T) {
	srv := NewServer()
	if err := srv.RegisterName("delayed", &delayedService{delay: 100 * time.Millisecond}); err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("can't listen:", err)
	}
	defer listener.Close()
	go srv.ServeListener(listener)

	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal("can't dial:", err)
	}
	defer conn.Close()
	// Failing fast matters here: a response that is never written shows up as a
	// read that never returns.
	conn.SetDeadline(time.Now().Add(teardownTestTimeout))

	if _, err := conn.Write([]byte(`{"jsonrpc":"2.0","id":1,"method":"delayed_result"}` + "\n")); err != nil {
		t.Fatal("can't write the request:", err)
	}
	if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal("can't half close the connection:", err)
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("reading the response of a half closed peer: %v", err)
	}
	if !bytes.Contains(buf[:n], []byte(`"result":"ok"`)) {
		t.Fatalf("half closed peer did not receive the result: %s", buf[:n])
	}
}

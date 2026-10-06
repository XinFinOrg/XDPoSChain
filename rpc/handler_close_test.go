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
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

const teardownTestTimeout = 10 * time.Second

// graceTestBound bounds the wait a running teardown grace may impose on a call,
// as teardownResponseGrace (3s) plus a second of scheduling slack. It is a fixed
// value on purpose: a bound derived from teardownResponseGrace would grow with
// it and could not catch a grace that became too long.
const graceTestBound = 4 * time.Second

// zeroGraceTestBound bounds the return of a teardown that was given a zero
// grace: it must not wait for a grace at all, so it has to return well before
// teardownResponseGrace. The bound is fixed and independent of
// teardownResponseGrace on purpose, so an implementation that ignores the grace
// parameter and waits the response grace out fails here instead of passing a
// bound that grew with it. A second is the slack the Client.Close case uses.
const zeroGraceTestBound = time.Second

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

// TestHandlerCloseKeepsRunningCallAlive guards the behaviour both teardown
// paths are documented to have: a call that is still running must not observe
// the cancellation of its context. A single request served through
// serveSingleRequest is otherwise aborted before it can produce its response
// (see go-ethereum #19430), and with a grace period the response of a peer that
// can still read would be dropped as well.
func TestHandlerCloseKeepsRunningCallAlive(t *testing.T) {
	tests := []struct {
		name     string
		teardown func(h *handler)
	}{
		{"close", func(h *handler) { h.close(io.EOF, nil) }},
		{"closeAbort", func(h *handler) { h.closeAbort(io.EOF, nil, teardownResponseGrace, nil, nil) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
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
				test.teardown(h)
				close(closed)
			}()

			select {
			case <-closed:
				t.Fatal("the teardown returned before the running call finished")
			case <-time.After(100 * time.Millisecond):
			}

			close(release)
			if err := <-ctxErr; err != nil {
				t.Fatalf("request context cancelled while the call was still running: %v", err)
			}
			waitForCallSignal(t, closed, "the teardown to return after the call finished")
			if err := h.rootCtx.Err(); !errors.Is(err, context.Canceled) {
				t.Fatalf("root context not cancelled by the teardown: %v", err)
			}
		})
	}
}

// TestHandlerCloseAbortReturnsWhileCallWaitsForContext checks that tearing down
// a connection is not blocked by a call that only returns once its context is
// cancelled: closeAbort cancels the contexts of the calls until the grace
// elapsed, and the calls observe the cancellation. A grace of zero models the
// teardown of a connection this node initiated, where no response can be
// delivered anymore, and it must not turn into a wait either: the teardown
// returns within zeroGraceTestBound here.
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
	start := time.Now()
	go func() {
		h.closeAbort(io.EOF, nil, 0, nil, nil)
		close(closed)
	}()

	waitForCallSignal(t, closed, "handler.closeAbort to return while the call waits for its context")
	if elapsed := time.Since(start); elapsed > zeroGraceTestBound {
		t.Fatalf("handler.closeAbort waited %v with a zero grace", elapsed)
	}
	waitForCallSignal(t, cancelled, "the call to observe the cancellation")
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

// TestHandlerCloseAbortStoppedBySignal checks that every signal ends a running
// grace period right away: a teardown this node started, where the connection
// is going away so the calls are cancelled without being given their chance to
// deliver a response, the client closing, which ends the grace of every
// connection it has, and the codec being closed locally (Server.Stop), after
// which a response would not reach the peer anymore.
func TestHandlerCloseAbortStoppedBySignal(t *testing.T) {
	tests := []struct {
		name     string
		signal   func(codec ServerCodec, abort, clientAbort chan struct{})
		expected string
	}{
		{"local teardown", func(_ ServerCodec, abort, _ chan struct{}) { close(abort) }, "handler.closeAbort to return after the local teardown"},
		{"client close", func(_ ServerCodec, _, clientAbort chan struct{}) { close(clientAbort) }, "handler.closeAbort to return after the client closed"},
		{"codec close", func(codec ServerCodec, _, _ chan struct{}) { codec.close() }, "handler.closeAbort to return after the codec was closed"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			serverConn, clientConn := net.Pipe()
			defer serverConn.Close()
			defer clientConn.Close()
			codec := NewCodec(serverConn)
			h := newHandler(context.Background(), codec, sequentialIDGenerator(), new(serviceRegistry), 0, 0)

			entered := make(chan struct{})
			cancelled := make(chan struct{})
			h.startCallProc(func(cp *callProc) {
				close(entered)
				<-cp.ctx.Done()
				close(cancelled)
			})
			<-entered

			// The grace is an hour long and the call parks on its context, so
			// closeAbort can only return once the signal ended its wait.
			abort := make(chan struct{})
			clientAbort := make(chan struct{})
			closed := make(chan struct{})
			go func() {
				h.closeAbort(io.EOF, nil, time.Hour, abort, clientAbort)
				close(closed)
			}()
			test.signal(codec, abort, clientAbort)

			waitForCallSignal(t, closed, test.expected)
			waitForCallSignal(t, cancelled, "the call to observe the cancellation")
		})
	}
}

// writeSignalingConn reports the first write on a connection, so a test can
// tell that a request reached the connection before the write blocks.
type writeSignalingConn struct {
	net.Conn
	once    sync.Once
	started chan struct{}
}

func (c *writeSignalingConn) Write(p []byte) (int, error) {
	c.once.Do(func() { close(c.started) })
	return c.Conn.Write(p)
}

// startInFlightCall sends a request of this node and returns its operation once
// the request was written. The dispatch loop registers the operation before
// handing the request to the connection, so it is in flight by then.
func startInFlightCall(t *testing.T, client *Client, reader *bufio.Reader) *requestOp {
	t.Helper()
	msg, err := client.newMessage("block_missing")
	if err != nil {
		t.Fatal(err)
	}
	op := &requestOp{ids: []json.RawMessage{msg.ID}, resp: make(chan []*jsonrpcMessage, 1)}
	go func() { _ = client.send(context.Background(), op, msg) }()
	if _, err := reader.ReadString('\n'); err != nil {
		t.Fatal("can't read the request:", err)
	}
	return op
}

// waitForTeardownGrace brings the client into the state where the teardown of
// its connection runs with the full grace period, and returns once that
// teardown failed the first in-flight call started here. That failure is the
// observable that the grace period is running, which a sleep cannot establish.
//
// The client is served over peer, whose bytes are read through reader, and it
// must have a service registered under "block". The peer is closed by this
// helper.
func waitForTeardownGrace(t *testing.T, client *Client, peer net.Conn, reader *bufio.Reader, svc *blockingService) {
	t.Helper()

	// Two in-flight calls of this node. The dispatch loop hands the operation
	// of the last request it sent to the teardown, and that can only be the
	// second one here, so the first one is not kept and its failure is what
	// the test can wait for.
	first := startInFlightCall(t, client, reader)
	startInFlightCall(t, client, reader)

	// The peer asks the client to run a call that only returns once its context
	// is done, so the teardown that follows runs with the full grace period.
	req := &jsonrpcMessage{Version: vsn, ID: json.RawMessage("1"), Method: "block_waitForContext"}
	if err := NewCodec(peer).writeJSON(context.Background(), req, false); err != nil {
		t.Fatal("can't write the request:", err)
	}
	waitForCallSignal(t, svc.entered, "the call to reach the client")

	// The read side dies and starts the teardown, which fails the first
	// in-flight call of this node.
	peer.Close()
	select {
	case <-first.resp:
		if first.err == nil {
			t.Fatal("the in-flight call was not failed by the teardown")
		}
	case <-time.After(teardownTestTimeout):
		t.Fatal("timed out waiting for the teardown to fail the in-flight call")
	}
}

// TestClientCloseStopsTeardownGrace checks that Client.Close does not have to
// wait for the grace period a read error started: the client tears its
// connection down, which ends the wait right away and cancels the call parked
// on its context.
func TestClientCloseStopsTeardownGrace(t *testing.T) {
	peerConn, clientConn := net.Pipe()
	defer peerConn.Close()
	defer clientConn.Close()

	client, err := newClient(context.Background(), new(clientConfig), func(context.Context) (ServerCodec, error) {
		return NewCodec(clientConn), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	svc := newBlockingService()
	if err := client.RegisterName("block", svc); err != nil {
		t.Fatal(err)
	}

	waitForTeardownGrace(t, client, peerConn, bufio.NewReader(peerConn), svc)

	start := time.Now()
	client.Close()
	elapsed := time.Since(start)
	waitForCallSignal(t, svc.exited, "the call to observe the cancellation")
	if elapsed > time.Second {
		t.Fatalf("Client.Close waited %v for the teardown grace", elapsed)
	}
}

// TestClientReconnectStopsTeardownGrace checks that a reconnect ends the grace
// period of the connection it replaces: the old connection goes away because
// this node started a new one, so its calls are cancelled without waiting the
// grace out, the same way Client.Close ends it through the client wide signal.
func TestClientReconnectStopsTeardownGrace(t *testing.T) {
	firstPeer, firstConn := net.Pipe()
	defer firstPeer.Close()
	defer firstConn.Close()
	secondPeer, secondConn := net.Pipe()
	defer secondPeer.Close()
	defer secondConn.Close()

	writeStarted := make(chan struct{})
	var (
		connectMu sync.Mutex
		connects  int
	)
	client, err := newClient(context.Background(), new(clientConfig), func(context.Context) (ServerCodec, error) {
		connectMu.Lock()
		connects++
		n := connects
		connectMu.Unlock()
		if n == 1 {
			return NewCodec(&writeSignalingConn{Conn: firstConn, started: writeStarted}), nil
		}
		return NewCodec(secondConn), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	svc := newBlockingService()
	if err := client.RegisterName("block", svc); err != nil {
		t.Fatal(err)
	}

	// The peer asks the client to run a call that only returns once its context
	// is done, so the teardown of the first connection runs with the full grace
	// period.
	req := &jsonrpcMessage{Version: vsn, ID: json.RawMessage("1"), Method: "block_waitForContext"}
	if err := NewCodec(firstPeer).writeJSON(context.Background(), req, false); err != nil {
		t.Fatal("can't write the request:", err)
	}
	waitForCallSignal(t, svc.entered, "the call to reach the client")

	// A call of this node whose request blocks on the connection: the peer
	// reads nothing, so the write only fails once the peer goes away.
	ctx, cancel := context.WithTimeout(context.Background(), teardownTestTimeout)
	defer cancel()
	go func() { _ = client.CallContext(ctx, nil, "block_missing") }()
	waitForCallSignal(t, writeStarted, "the request to reach the connection")

	// The read side dies, which starts the teardown with the full grace period,
	// and the blocked write fails, which makes the client reconnect: that
	// reconnect aborts the teardown of the connection it replaces.
	start := time.Now()
	firstPeer.Close()
	waitForCallSignal(t, svc.exited, "the call to observe the cancellation")
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("the reconnect waited %v for the teardown grace", elapsed)
	}
	client.Close()
}

// TestClientCloseEndsTeardownOfUnpublishedConnection checks that Client.Close
// ends the grace period of a connection that curConn does not point at.
// dispatch installs the connection of a reconnect after starting its read loop,
// so a Close taking the curConn snapshot between the two would otherwise leave
// the running teardown waiting the grace out.
func TestClientCloseEndsTeardownOfUnpublishedConnection(t *testing.T) {
	peerConn, clientConn := net.Pipe()
	defer peerConn.Close()
	defer clientConn.Close()

	client, err := newClient(context.Background(), new(clientConfig), func(context.Context) (ServerCodec, error) {
		return NewCodec(clientConn), nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// The connection that runs the teardown stands for the one dispatch would
	// install on a reconnect: curConn keeps pointing at the first connection.
	otherPeer, otherConn := net.Pipe()
	defer otherPeer.Close()
	defer otherConn.Close()
	other := client.newClientConn(NewCodec(otherConn))

	entered := make(chan struct{})
	cancelled := make(chan struct{})
	other.handler.startCallProc(func(cp *callProc) {
		close(entered)
		<-cp.ctx.Done()
		close(cancelled)
	})
	<-entered

	// An hour long grace leaves the client-wide signal of Client.Close as the
	// only way for the teardown below to return.
	closed := make(chan struct{})
	go func() {
		other.close(io.EOF, nil, time.Hour)
		close(closed)
	}()

	client.Close()

	waitForCallSignal(t, closed, "the connection teardown to return once the client closed")
	waitForCallSignal(t, cancelled, "the call to observe the cancellation")
}

// TestClientTeardownGraceBoundsCallerWait anchors the bound a running teardown
// grace puts on the calls of this client. A request that can no longer be
// answered is only failed once the teardown returned, because the dispatch loop
// stays in it, so the caller's own deadline and a request started after the read
// error wait for at most teardownResponseGrace. Without a call in flight the
// teardown returns immediately, and cancelling any earlier would drop the
// response a half closed peer can still receive (see
// TestServerTeardownDeliversResponseToHalfClosedPeer). The tests assert the
// upper bound only: they keep the grace from growing, while an implementation
// that ends the wait sooner (see #2640) stays acceptable.
func TestClientTeardownGraceBoundsCallerWait(t *testing.T) {
	// The teardown is entered with this call registered and the caller's
	// deadline expires while the grace runs. Depending on whether dispatch
	// handles the completion of the write or the read error first, the call is
	// either kept for a reconnect and returns the caller's deadline, or it is
	// failed right away by the teardown; both stay within the grace.
	t.Run("in-flight call", func(t *testing.T) {
		peerConn, clientConn := net.Pipe()
		defer peerConn.Close()
		defer clientConn.Close()

		client, err := newClient(context.Background(), new(clientConfig), func(context.Context) (ServerCodec, error) {
			return NewCodec(clientConn), nil
		})
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		svc := newBlockingService()
		if err := client.RegisterName("block", svc); err != nil {
			t.Fatal(err)
		}
		reader := bufio.NewReader(peerConn)

		// The peer asks this client to run a call that only returns once its
		// context is done, so the teardown that follows runs with the full
		// grace period.
		req := &jsonrpcMessage{Version: vsn, ID: json.RawMessage("1"), Method: "block_waitForContext"}
		if err := NewCodec(peerConn).writeJSON(context.Background(), req, false); err != nil {
			t.Fatal("can't write the request:", err)
		}
		waitForCallSignal(t, svc.entered, "the call to reach the client")

		// A call of this node with a deadline of its own. The peer reads the
		// request, so the write completes and the call is in flight by then.
		returned := make(chan time.Duration, 1)
		go func() {
			start := time.Now()
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer cancel()
			_ = client.CallContext(ctx, nil, "block_missing")
			returned <- time.Since(start)
		}()
		if _, err := reader.ReadString('\n'); err != nil {
			t.Fatal("can't read the request:", err)
		}

		// The read side dies, which starts the teardown with the full grace.
		peerConn.Close()

		select {
		case d := <-returned:
			if d > graceTestBound {
				t.Fatalf("the call with a deadline waited %v for the teardown grace", d)
			}
		case <-time.After(graceTestBound):
			t.Fatal("the call with a deadline did not return within the grace bound")
		}
	})

	// The teardown already runs when the request is started, so dispatch cannot
	// fail it before the teardown returned. The request has no deadline of its
	// own, so the bound has to be observed from here.
	t.Run("new call", func(t *testing.T) {
		peerConn, clientConn := net.Pipe()
		defer peerConn.Close()
		defer clientConn.Close()

		client, err := newClient(context.Background(), new(clientConfig), func(context.Context) (ServerCodec, error) {
			return NewCodec(clientConn), nil
		})
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		svc := newBlockingService()
		if err := client.RegisterName("block", svc); err != nil {
			t.Fatal(err)
		}

		waitForTeardownGrace(t, client, peerConn, bufio.NewReader(peerConn), svc)

		start := time.Now()
		returned := make(chan error, 1)
		go func() { returned <- client.CallContext(context.Background(), nil, "block_missing") }()
		select {
		case err := <-returned:
			if err == nil {
				t.Fatal("the request started while the teardown ran was not failed")
			}
			if elapsed := time.Since(start); elapsed > graceTestBound {
				t.Fatalf("the request started while the teardown ran waited %v", elapsed)
			}
		case <-time.After(graceTestBound):
			t.Fatal("the request started while the teardown ran was not failed within the grace bound")
		}
	})
}

// drainTestBound bounds the release of a connection whose call ignores its
// context: the response grace, the drain grace and a second of scheduling
// slack. Like graceTestBound it is a fixed value on purpose, so a longer bound
// cannot hide behind it.
const drainTestBound = 5 * time.Second

// ignoringService is a test service whose method blocks until the test releases
// it and never observes the request context. It models a method that keeps
// running after its context was cancelled, which a teardown has to bound
// instead of waiting for it.
type ignoringService struct {
	entered   chan struct{}
	release   chan struct{}
	exited    chan struct{}
	enterOnce sync.Once
	exitOnce  sync.Once
}

// newIgnoringService returns an ignoringService with fresh signalling channels.
func newIgnoringService() *ignoringService {
	return &ignoringService{entered: make(chan struct{}), release: make(chan struct{}), exited: make(chan struct{})}
}

// IgnoreContext blocks until the test releases the call. It does not look at
// its request context, so a cancellation cannot unblock it.
func (s *ignoringService) IgnoreContext() error {
	s.enterOnce.Do(func() { close(s.entered) })
	<-s.release
	s.exitOnce.Do(func() { close(s.exited) })
	return nil
}

// TestHandlerCloseAbortBoundedDrainForIgnoringCall checks the bound on the wait
// that follows the cancelled contexts: a call that never observes its context
// keeps the teardown from returning only until teardownDrainGrace elapsed. The
// teardown must still wait that long, so a response a cancelled call is writing
// still reaches the peer, and it must return afterwards, so the connection is
// released even though the call keeps running.
func TestHandlerCloseAbortBoundedDrainForIgnoringCall(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()
	h := newHandler(context.Background(), NewCodec(serverConn), sequentialIDGenerator(), new(serviceRegistry), 0, 0)

	entered := make(chan struct{})
	release := make(chan struct{})
	exited := make(chan struct{})
	h.startCallProc(func(cp *callProc) {
		close(entered)
		<-release
		close(exited)
	})
	<-entered

	closed := make(chan struct{})
	start := time.Now()
	go func() {
		h.closeAbort(io.EOF, nil, 0, nil, nil)
		close(closed)
	}()

	// The call ignores the cancellation, so the drain is what ends the wait. A
	// teardown returning earlier dropped the response a cancelled call is
	// writing; one returning later holds the connection for a call that may
	// never return. An early return is asserted on the elapsed time instead of
	// racing the return against a shorter timer: a runner that delays the timer
	// past the drain would otherwise find both channels ready and report a
	// teardown that waited the drain out as too early.
	waitForCallSignal(t, closed, "the teardown to return after the drain grace")
	if elapsed := time.Since(start); elapsed < teardownDrainGrace-100*time.Millisecond {
		t.Fatalf("the teardown returned after %v, before the drain grace elapsed", elapsed)
	}
	if err := h.rootCtx.Err(); !errors.Is(err, context.Canceled) {
		t.Fatalf("root context not cancelled by the teardown: %v", err)
	}
	select {
	case <-exited:
		t.Fatal("the call returned without being released")
	default:
	}
	close(release)
	waitForCallSignal(t, exited, "the call to finish once released")
}

// TestServerTeardownReleasesConnectionWhenCallIgnoresContext covers the two
// teardown paths with a call that never observes its context: the connection,
// and with it the codec, the ServeCodec goroutine and the Server.codecs entry,
// is released once the drain elapsed instead of staying alive until the call
// returns.
func TestServerTeardownReleasesConnectionWhenCallIgnoresContext(t *testing.T) {
	t.Run("peer closes", func(t *testing.T) {
		srv := NewServer()
		svc := newIgnoringService()
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
		go client.CallContext(ctx, nil, "block_ignoreContext")
		waitForCallSignal(t, svc.entered, "the call to reach the server")

		// The peer goes away while the call is still running. The read error
		// starts the teardown, which gives the response grace and then the
		// drain before the connection is released.
		start := time.Now()
		clientConn.Close()

		waitForCodecRelease(t, srv)
		if elapsed := time.Since(start); elapsed > drainTestBound {
			t.Fatalf("the server tracked the codec for %v, more than the %v bound", elapsed, drainTestBound)
		}
		close(svc.release)
		waitForCallSignal(t, svc.exited, "the call to finish once released")
		client.Close()
		serverConn.Close()
	})
	t.Run("server stops", func(t *testing.T) {
		srv := newTestServer()
		svc := newIgnoringService()
		if err := srv.RegisterName("block", svc); err != nil {
			t.Fatal(err)
		}
		client := DialInProc(srv)

		ctx, cancel := context.WithTimeout(context.Background(), teardownTestTimeout)
		defer cancel()
		go client.CallContext(ctx, nil, "block_ignoreContext")
		waitForCallSignal(t, svc.entered, "the call to reach the server")

		// Closing the codecs unblocks the teardown, which then has to get past
		// the call that ignores its context to release the connection.
		start := time.Now()
		srv.Stop()

		waitForCodecRelease(t, srv)
		if elapsed := time.Since(start); elapsed > drainTestBound {
			t.Fatalf("the server tracked the codec for %v, more than the %v bound", elapsed, drainTestBound)
		}
		close(svc.release)
		waitForCallSignal(t, svc.exited, "the call to finish once released")
		client.Close()
	})
}

// TestClientCloseReleasesConnectionWhenCallIgnoresContext checks that
// Client.Close does not wait for a call that ignores the cancellation of its
// context: the call keeps running, but the connection it held is released and
// Close returns.
func TestClientCloseReleasesConnectionWhenCallIgnoresContext(t *testing.T) {
	peerConn, clientConn := net.Pipe()
	defer peerConn.Close()
	defer clientConn.Close()

	client, err := newClient(context.Background(), new(clientConfig), func(context.Context) (ServerCodec, error) {
		return NewCodec(clientConn), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	svc := newIgnoringService()
	if err := client.RegisterName("block", svc); err != nil {
		t.Fatal(err)
	}

	// The peer asks this client to run a call that never observes its context.
	req := &jsonrpcMessage{Version: vsn, ID: json.RawMessage("1"), Method: "block_ignoreContext"}
	if err := NewCodec(peerConn).writeJSON(context.Background(), req, false); err != nil {
		t.Fatal("can't write the request:", err)
	}
	waitForCallSignal(t, svc.entered, "the call to reach the client")

	closed := make(chan struct{})
	start := time.Now()
	go func() {
		client.Close()
		close(closed)
	}()
	waitForCallSignal(t, closed, "Client.Close to return while the call ignores its context")
	if elapsed := time.Since(start); elapsed > drainTestBound {
		t.Fatalf("Client.Close waited %v for a call that ignores its context", elapsed)
	}
	close(svc.release)
	waitForCallSignal(t, svc.exited, "the call to finish once released")
}

// TestHandlerCloseAbortFailsSubscriptionRegisteredAfterTeardown covers a call
// that outlives the teardown of its connection: it observes no cancellation and
// only reaches addSubscriptions after closeAbort returned. The subscription it
// registers must be failed right away, because the teardown already cancelled
// the subscriptions of the connection and nothing would ever close this one.
func TestHandlerCloseAbortFailsSubscriptionRegisteredAfterTeardown(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()
	h := newHandler(context.Background(), NewCodec(serverConn), sequentialIDGenerator(), new(serviceRegistry), 0, 0)

	entered := make(chan struct{})
	release := make(chan struct{})
	registered := make(chan *Subscription, 1)
	h.startCallProc(func(cp *callProc) {
		close(entered)
		<-release
		n := &Notifier{h: h, namespace: "test"}
		sub := n.CreateSubscription()
		cp.notifiers = append(cp.notifiers, n)
		h.addSubscriptions(cp.notifiers)
		registered <- sub
	})
	<-entered

	// The call ignores the cancellation, so the drain is what ends the
	// teardown. It returned before the call reaches addSubscriptions below.
	h.closeAbort(io.EOF, nil, 0, nil, nil)
	close(release)

	var sub *Subscription
	select {
	case sub = <-registered:
	case <-time.After(teardownTestTimeout):
		t.Fatal("the call did not register its subscription")
	}

	// The subscription was failed with the error of the teardown and its error
	// channel was closed, so a consumer is not left waiting on it.
	select {
	case err := <-sub.Err():
		if !errors.Is(err, io.EOF) {
			t.Fatalf("subscription failed with %v, want the teardown error", err)
		}
	default:
		t.Fatal("the subscription registered after the teardown was not failed")
	}
	if _, ok := <-sub.Err(); ok {
		t.Fatal("the subscription error channel was not closed")
	}

	// It was not kept either: a subscription left in the handler is never
	// cancelled again and leaks with the handler.
	h.subLock.Lock()
	kept := len(h.serverSubs)
	h.subLock.Unlock()
	if kept != 0 {
		t.Fatalf("the handler kept %d subscription(s) registered after the teardown", kept)
	}
}

// Copyright 2021 The go-ethereum Authors
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

package eth

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/metrics"
	"github.com/XinFinOrg/XDPoSChain/p2p"
	"github.com/XinFinOrg/XDPoSChain/p2p/enode"
	"github.com/XinFinOrg/XDPoSChain/p2p/tracker"
)

// TestMain turns metrics on once for the whole package. The request tracker is a
// process-wide singleton gated on metrics.Enabled(), and Enable writes a plain
// global that the meter ticker reads without synchronisation, so it must not be
// called while tests are already running.
func TestMain(m *testing.M) {
	metrics.Enable()
	os.Exit(m.Run())
}

// newDispatcherTestPeer creates a wire peer backed by an in-memory message pipe
// and returns the remote end of the pipe so tests can inspect requests.
func newDispatcherTestPeer(t *testing.T) (*Peer, *p2p.MsgPipeRW) {
	t.Helper()

	var id enode.ID
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatalf("failed to generate random peer id: %v", err)
	}
	return newDispatcherTestPeerWithID(t, id)
}

// newDispatcherTestPeerWithID creates a test peer with a caller-chosen identity,
// so a test can simulate a reconnect of the same remote peer.
func newDispatcherTestPeerWithID(t *testing.T, id enode.ID) (*Peer, *p2p.MsgPipeRW) {
	t.Helper()

	app, net := p2p.MsgPipe()

	peer := NewPeer(XDC166, p2p.NewPeer(id, "dispatcher", nil), net, func(common.Hash) *types.Transaction { return nil })
	t.Cleanup(func() {
		peer.Close()
		app.Close()
		// The tracker is process-wide and the dispatcher cancels its leftover
		// requests only after consuming p.term: wait for it here, or a late
		// cancel lands in the next test that reads the shared gauge. The wait is
		// bounded so a peer loop that never exits fails this test instead of
		// hanging the whole package until `go test -timeout`.
		done := make(chan struct{})
		go func() {
			peer.broadcastWg.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Errorf("peer loops did not exit after Close")
		}
	})
	return peer, app
}

// dispatchTestRequest sends a request from the peer and consumes it from the
// remote end of the pipe, returning once the request is registered as pending.
func dispatchTestRequest(t *testing.T, peer *Peer, app *p2p.MsgPipeRW, req *Request) {
	t.Helper()

	reqErr := make(chan error, 1)
	go func() { reqErr <- peer.dispatchRequest(req) }()

	msgCh := make(chan p2p.Msg, 1)
	readErr := make(chan error, 1)
	go func() {
		msg, err := app.ReadMsg()
		if err != nil {
			readErr <- err
			return
		}
		msgCh <- msg
	}()

	// One deadline covers both the wire message and the dispatcher's verdict, so
	// a regression that sends the packet without a verdict fails here instead of
	// hanging the package until `go test -timeout`.
	deadline := time.After(3 * time.Second)
	var accepted bool

	for {
		select {
		case msg := <-msgCh:
			if msg.Code != req.code {
				msg.Discard()
				t.Fatalf("request code mismatch: have %d, want %d", msg.Code, req.code)
			}
			msg.Discard()
			if !accepted {
				select {
				case err := <-reqErr:
					if err != nil {
						t.Fatalf("failed to dispatch request: %v", err)
					}
				case <-deadline:
					app.Close()
					t.Fatal("timed out waiting for the dispatcher verdict")
				}
			}
			return

		case err := <-reqErr:
			if err != nil {
				app.Close()
				t.Fatalf("failed to dispatch request: %v", err)
			}
			accepted = true

		case err := <-readErr:
			app.Close()
			t.Fatalf("failed to read dispatched request: %v", err)

		case <-deadline:
			app.Close()
			t.Fatal("timed out waiting for dispatched request")
		}
	}
}

// dispatchTestVerdict waits for the verdict of a dispatchResponse whose
// response the consumer already acknowledged, so a reader stuck after the
// acknowledgement fails this test instead of hanging the package until
// `go test -timeout`.
func dispatchTestVerdict(t *testing.T, errCh <-chan error) error {
	t.Helper()

	select {
	case err := <-errCh:
		return err
	case <-time.After(3 * time.Second):
		t.Fatal("dispatchResponse hung after the response was acknowledged")
	}
	return nil
}

// dispatchTestPeerExit waits until the peer loops exit after Close, so a
// teardown assertion runs after the dispatcher has released the connection's
// reservations.
func dispatchTestPeerExit(t *testing.T, peer *Peer) {
	t.Helper()

	done := make(chan struct{})
	go func() {
		peer.broadcastWg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("peer loops did not exit after Close")
	}
}

// TestDispatcherRequestResponse checks that a response is matched to its
// outstanding request and delivered on the requester's sink.
func TestDispatcherRequestResponse(t *testing.T) {
	peer, app := newDispatcherTestPeer(t)

	sink := make(chan *Response, 1)
	req := &Request{
		id:   1,
		sink: sink,
		code: GetBlockHeadersMsg,
		want: BlockHeadersMsg,
		data: []common.Hash{},
	}
	dispatchTestRequest(t, peer, app, req)

	resErr := make(chan error, 1)
	go func() {
		resErr <- peer.dispatchResponse(&Response{id: 1, code: BlockHeadersMsg, Res: &BlockHeadersPacket{}})
	}()

	select {
	case res := <-sink:
		if res.Req != req {
			t.Fatalf("response matched to wrong request")
		}
		if res.Time <= 0 {
			t.Fatalf("response round trip time not measured: %v", res.Time)
		}
		res.Done <- nil
	case <-time.After(3 * time.Second):
		t.Fatal("response not delivered")
	}
	if err := dispatchTestVerdict(t, resErr); err != nil {
		t.Fatalf("dispatchResponse failed: %v", err)
	}
}

// TestDispatcherDanglingResponse checks that responses with an unknown request
// id are reported as dangling and the dispatcher keeps serving later requests.
func TestDispatcherDanglingResponse(t *testing.T) {
	peer, app := newDispatcherTestPeer(t)

	if err := peer.dispatchResponse(&Response{id: 1, code: BlockHeadersMsg, Res: &BlockHeadersPacket{}}); !errors.Is(err, errDanglingResponse) {
		t.Fatalf("dangling response mismatch: have %v, want %v", err, errDanglingResponse)
	}
	// The dispatcher must stay alive after a dangling response.
	sink := make(chan *Response, 1)
	req := &Request{
		id:   2,
		sink: sink,
		code: GetBlockHeadersMsg,
		want: BlockHeadersMsg,
		data: []common.Hash{},
	}
	dispatchTestRequest(t, peer, app, req)

	resErr := make(chan error, 1)
	go func() {
		resErr <- peer.dispatchResponse(&Response{id: 2, code: BlockHeadersMsg, Res: &BlockHeadersPacket{}})
	}()

	select {
	case res := <-sink:
		res.Done <- nil
	case <-time.After(3 * time.Second):
		t.Fatal("dispatcher stopped serving after a dangling response")
	}
	if err := dispatchTestVerdict(t, resErr); err != nil {
		t.Fatalf("dispatchResponse failed: %v", err)
	}
}

// TestDispatcherMismatchingResponseType checks that a response of the wrong
// packet type is not delivered to the requester.
func TestDispatcherMismatchingResponseType(t *testing.T) {
	peer, app := newDispatcherTestPeer(t)

	sink := make(chan *Response, 1)
	req := &Request{
		id:   1,
		sink: sink,
		code: GetBlockHeadersMsg,
		want: BlockHeadersMsg,
		data: []common.Hash{},
	}
	dispatchTestRequest(t, peer, app, req)

	resErr := make(chan error, 1)
	go func() {
		resErr <- peer.dispatchResponse(&Response{id: 1, code: BlockBodiesMsg, Res: &BlockBodiesPacket{}})
	}()
	select {
	case res := <-sink:
		res.Done <- nil
		t.Fatal("mismatching response was delivered")
	case err := <-resErr:
		if !errors.Is(err, errMismatchingResponseType) {
			t.Fatalf("mismatching response mismatch: have %v, want %v", err, errMismatchingResponseType)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("dispatchResponse hung on mismatching response")
	}
}

// TestDispatcherCancelledRequest checks that a late response to a cancelled
// request is discarded.
func TestDispatcherCancelledRequest(t *testing.T) {
	stale := metrics.GetOrRegisterMeter(
		fmt.Sprintf("p2p/stale/%s/%d/%#02x", ProtocolName, XDC166, BlockHeadersMsg), nil)
	staleBase := stale.Snapshot().Count()
	wait := metrics.GetOrRegisterHistogramLazy(
		fmt.Sprintf("p2p/wait/%s/%d/%#02x", ProtocolName, XDC166, GetBlockHeadersMsg), nil,
		func() metrics.Sample { return metrics.NewExpDecaySample(1028, 0.015) },
	)
	// The histogram uses a resetting sample: clear it so the post-reply count
	// only reflects this test.
	wait.Clear()

	peer, app := newDispatcherTestPeer(t)

	sink := make(chan *Response, 1)
	req := &Request{
		id:   1,
		sink: sink,
		code: GetBlockHeadersMsg,
		want: BlockHeadersMsg,
		data: []common.Hash{},
	}
	dispatchTestRequest(t, peer, app, req)

	if err := req.Close(); err != nil {
		t.Fatalf("failed to cancel request: %v", err)
	}
	resErr := make(chan error, 1)
	go func() {
		resErr <- peer.dispatchResponse(&Response{id: 1, code: BlockHeadersMsg, Res: &BlockHeadersPacket{}})
	}()
	select {
	case res := <-sink:
		res.Done <- nil
		t.Fatal("cancelled request received a response")
	case err := <-resErr:
		// The request left the pending table on cancellation, so the late reply
		// is rejected as dangling even though the tracker still holds the id:
		// the tracker matches it to the cancelled request, releases the id and
		// meters the reply as stale instead of recording a round trip.
		if !errors.Is(err, errDanglingResponse) {
			t.Fatalf("late response mismatch: have %v, want %v", err, errDanglingResponse)
		}
		if got := stale.Snapshot().Count() - staleBase; got != 1 {
			t.Fatalf("late reply not counted as stale: have %d, want 1", got)
		}
		if got := wait.Snapshot().Count(); got != 0 {
			t.Fatalf("late reply entered the wait histogram: have %d new samples, want 0", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("dispatchResponse hung on late response")
	}
}

// TestDispatcherCloseDuringDelivery checks that a response blocked on delivery
// is released with errDisconnected when the peer is closed (geth #30918).
func TestDispatcherCloseDuringDelivery(t *testing.T) {
	peer, app := newDispatcherTestPeer(t)

	// Unbuffered sink without a reader: dispatchResponse blocks on delivery.
	sink := make(chan *Response)
	req := &Request{
		id:   1,
		sink: sink,
		code: GetBlockHeadersMsg,
		want: BlockHeadersMsg,
		data: []common.Hash{},
	}
	dispatchTestRequest(t, peer, app, req)

	res := &Response{id: 1, code: BlockHeadersMsg, Res: &BlockHeadersPacket{}, accepted: make(chan struct{})}
	resErr := make(chan error, 1)
	go func() {
		resErr <- peer.dispatchResponse(res)
	}()
	select {
	case <-res.accepted:
	case <-time.After(3 * time.Second):
		t.Fatal("response was not accepted")
	}
	peer.Close()

	select {
	case err := <-resErr:
		if !errors.Is(err, errDisconnected) {
			t.Fatalf("unexpected dispatch error: have %v, want %v", err, errDisconnected)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("dispatchResponse hung after peer was closed")
	}
}

// TestDispatcherCloseDuringAck checks that a reader waiting for the consumer's
// acknowledgement is released when the peer is closed.
func TestDispatcherCloseDuringAck(t *testing.T) {
	peer, app := newDispatcherTestPeer(t)

	sink := make(chan *Response)
	req := &Request{
		id:   1,
		sink: sink,
		code: GetBlockHeadersMsg,
		want: BlockHeadersMsg,
		data: []common.Hash{},
	}
	dispatchTestRequest(t, peer, app, req)

	// Consume the response without acknowledging it, leaving the reader blocked
	// on res.Done until the peer is closed.
	consumed := make(chan struct{})
	go func() {
		<-sink
		close(consumed)
	}()

	res := &Response{id: 1, code: BlockHeadersMsg, Res: &BlockHeadersPacket{}, accepted: make(chan struct{})}
	resErr := make(chan error, 1)
	go func() {
		resErr <- peer.dispatchResponse(res)
	}()
	select {
	case <-res.accepted:
	case <-time.After(3 * time.Second):
		t.Fatal("response was not accepted")
	}
	select {
	case <-consumed:
	case <-time.After(3 * time.Second):
		t.Fatal("response was not delivered")
	}
	peer.Close()

	select {
	case err := <-resErr:
		if !errors.Is(err, errDisconnected) {
			t.Fatalf("unexpected dispatch error: have %v, want %v", err, errDisconnected)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("dispatchResponse hung waiting for acknowledgement")
	}
}

// TestDispatcherCloseAfterBufferedDelivery checks that cancelling a request
// whose response is already queued on a buffered sink releases the reader
// instead of leaving it blocked on the acknowledgement.
func TestDispatcherCloseAfterBufferedDelivery(t *testing.T) {
	peer, app := newDispatcherTestPeer(t)

	sink := make(chan *Response, 1)
	req := &Request{
		id:   1,
		sink: sink,
		code: GetBlockHeadersMsg,
		want: BlockHeadersMsg,
		data: []common.Hash{},
	}
	dispatchTestRequest(t, peer, app, req)

	res := &Response{id: 1, code: BlockHeadersMsg, Res: &BlockHeadersPacket{}, accepted: make(chan struct{})}
	resErr := make(chan error, 1)
	go func() {
		resErr <- peer.dispatchResponse(res)
	}()
	select {
	case <-res.accepted:
	case <-time.After(3 * time.Second):
		t.Fatal("response was not accepted")
	}
	// The buffered sink takes the response without a reader, so the response
	// routine is now waiting for the acknowledgement.
	deadline := time.Now().Add(3 * time.Second)
	for len(sink) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("response was not queued on the sink")
		}
		time.Sleep(time.Millisecond)
	}
	// The requester abandons the response without reading it.
	if err := req.Close(); err != nil {
		t.Fatalf("failed to cancel request: %v", err)
	}
	select {
	case err := <-resErr:
		if err != nil {
			t.Fatalf("dispatchResponse failed after cancellation: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("dispatchResponse hung on the acknowledgement after cancellation")
	}
	// The cancellation must have drained the queued response instead of leaving
	// it for a later reader to pick up after the request was abandoned.
	if left := len(sink); left != 0 {
		t.Fatalf("cancelled response left in the sink: %d", left)
	}
}

// TestDispatcherCloseAfterOwnership checks that a response the consumer already
// took out of the sink keeps its Done verdict: closing the request afterwards
// must not make dispatchResponse discard the handler result.
func TestDispatcherCloseAfterOwnership(t *testing.T) {
	peer, app := newDispatcherTestPeer(t)

	sink := make(chan *Response, 1)
	req := &Request{
		id:   1,
		sink: sink,
		code: GetBlockHeadersMsg,
		want: BlockHeadersMsg,
		data: []common.Hash{},
	}
	dispatchTestRequest(t, peer, app, req)

	res := &Response{id: 1, code: BlockHeadersMsg, Res: &BlockHeadersPacket{}, accepted: make(chan struct{})}
	resErr := make(chan error, 1)
	go func() {
		resErr <- peer.dispatchResponse(res)
	}()
	select {
	case <-res.accepted:
	case <-time.After(3 * time.Second):
		t.Fatal("response was not accepted")
	}
	// Wait for the response to be queued, then take it out: the consumer now
	// owns the handler verdict.
	deadline := time.Now().Add(3 * time.Second)
	for len(sink) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("response was not queued on the sink")
		}
		time.Sleep(time.Millisecond)
	}
	resp := <-sink

	if err := req.Close(); err != nil {
		t.Fatalf("failed to cancel request: %v", err)
	}
	sentinel := errors.New("handler verdict")
	resp.Done <- sentinel

	select {
	case err := <-resErr:
		if !errors.Is(err, sentinel) {
			t.Fatalf("handler verdict lost after cancellation: have %v, want %v", err, sentinel)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("dispatchResponse hung waiting for the handler verdict")
	}
}

// TestDispatcherCloseAfterClosedSink checks that a consumer that took the
// response and closed the sink before cancelling still owes its verdict: the
// closed channel must not be mistaken for a queued response.
func TestDispatcherCloseAfterClosedSink(t *testing.T) {
	peer, app := newDispatcherTestPeer(t)

	sink := make(chan *Response, 1)
	req := &Request{
		id:   1,
		sink: sink,
		code: GetBlockHeadersMsg,
		want: BlockHeadersMsg,
		data: []common.Hash{},
	}
	dispatchTestRequest(t, peer, app, req)

	res := &Response{id: 1, code: BlockHeadersMsg, Res: &BlockHeadersPacket{}, accepted: make(chan struct{})}
	resErr := make(chan error, 1)
	go func() {
		resErr <- peer.dispatchResponse(res)
	}()
	select {
	case <-res.accepted:
	case <-time.After(3 * time.Second):
		t.Fatal("response was not accepted")
	}
	// Wait for the response to be queued, take it out and close the sink before
	// cancelling: the sink is now closed and empty.
	deadline := time.Now().Add(3 * time.Second)
	for len(sink) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("response was not queued on the sink")
		}
		time.Sleep(time.Millisecond)
	}
	resp := <-sink
	close(sink)

	if err := req.Close(); err != nil {
		t.Fatalf("failed to cancel request: %v", err)
	}
	sentinel := errors.New("handler verdict")
	resp.Done <- sentinel

	select {
	case err := <-resErr:
		if !errors.Is(err, sentinel) {
			t.Fatalf("handler verdict lost after closing the sink: have %v, want %v", err, sentinel)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("dispatchResponse hung waiting for the handler verdict")
	}
}

// TestDispatcherDoubleClose checks that closing a request twice is a no-op
// instead of panicking on an already closed channel, and that the released id
// stays reserved until the cancelled request's late reply arrives.
func TestDispatcherDoubleClose(t *testing.T) {
	peer, app := newDispatcherTestPeer(t)

	first := &Request{
		id:   1,
		sink: make(chan *Response, 1),
		code: GetBlockHeadersMsg,
		want: BlockHeadersMsg,
		data: []common.Hash{},
	}
	dispatchTestRequest(t, peer, app, first)

	if err := first.Close(); err != nil {
		t.Fatalf("first close failed: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("second close failed: %v", err)
	}
	// The id is still reserved: a newer request cannot take it over until the
	// cancelled request's late reply arrives.
	second := &Request{
		id:   1,
		sink: make(chan *Response, 1),
		code: GetBlockHeadersMsg,
		want: BlockHeadersMsg,
		data: []common.Hash{},
	}
	errCh := make(chan error, 1)
	go func() { errCh <- peer.dispatchRequest(second) }()

	select {
	case err := <-errCh:
		if !errors.Is(err, tracker.ErrCollision) {
			t.Fatalf("reuse of a cancelled id: have %v, want %v", err, tracker.ErrCollision)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("reuse of a cancelled id was not rejected")
	}
	// The late reply releases the id and is rejected as dangling.
	if _, err := dispatchTestResponse(t, peer, first.id, nil); !errors.Is(err, errDanglingResponse) {
		t.Fatalf("late reply mismatch: have %v, want %v", err, errDanglingResponse)
	}
	// The id is free again and a new request can use it.
	third := &Request{
		id:   1,
		sink: make(chan *Response, 1),
		code: GetBlockHeadersMsg,
		want: BlockHeadersMsg,
		data: []common.Hash{},
	}
	dispatchTestRequest(t, peer, app, third)

	resErr := make(chan error, 1)
	go func() {
		resErr <- peer.dispatchResponse(&Response{id: 1, code: BlockHeadersMsg, Res: &BlockHeadersPacket{}})
	}()
	select {
	case res := <-third.sink:
		res.Done <- nil
		if res.Req != third {
			t.Fatalf("response matched to the cancelled request")
		}
	case err := <-resErr:
		t.Fatalf("response to the reused id was rejected: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("response to the reused id was not delivered")
	}
	if err := dispatchTestVerdict(t, resErr); err != nil {
		t.Fatalf("dispatchResponse failed: %v", err)
	}
}

// TestDispatcherCloseAfterFulfilmentIDReuse checks that closing a request that
// was already serviced cannot untrack a newer request that took over its id.
// The id reuse is deliberate contract-violating setup for this defensive test:
// callers must not repeat an id within a connection, because a duplicate reply
// would be indistinguishable from the new request's reply (see Request).
func TestDispatcherCloseAfterFulfilmentIDReuse(t *testing.T) {
	peer, app := newDispatcherTestPeer(t)

	first := &Request{
		id:   1,
		sink: make(chan *Response, 1),
		code: GetBlockHeadersMsg,
		want: BlockHeadersMsg,
		data: []common.Hash{},
	}
	dispatchTestRequest(t, peer, app, first)

	resErr := make(chan error, 1)
	go func() {
		resErr <- peer.dispatchResponse(&Response{id: 1, code: BlockHeadersMsg, Res: &BlockHeadersPacket{}})
	}()
	select {
	case res := <-first.sink:
		res.Done <- nil
	case <-time.After(3 * time.Second):
		t.Fatal("response not delivered")
	}
	if err := dispatchTestVerdict(t, resErr); err != nil {
		t.Fatalf("dispatchResponse failed: %v", err)
	}
	// The fulfilled request left the pending table, so the dispatcher accepts the
	// reuse; the test repeats the id on purpose to exercise the defensive case.
	// Callers must not repeat an id within a connection (see Request).
	second := &Request{
		id:   1,
		sink: make(chan *Response, 1),
		code: GetBlockHeadersMsg,
		want: BlockHeadersMsg,
		data: []common.Hash{},
	}
	dispatchTestRequest(t, peer, app, second)

	// A late close of the serviced request must not mistake the new owner for
	// the request it once tracked.
	if err := first.Close(); err != nil {
		t.Fatalf("close of the fulfilled request failed: %v", err)
	}
	resErr = make(chan error, 1)
	go func() {
		resErr <- peer.dispatchResponse(&Response{id: 1, code: BlockHeadersMsg, Res: &BlockHeadersPacket{}})
	}()
	select {
	case res := <-second.sink:
		res.Done <- nil
		if res.Req != second {
			t.Fatalf("response matched to the fulfilled request")
		}
	case err := <-resErr:
		t.Fatalf("response to the reused id was rejected: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("response to the reused id was not delivered")
	}
	if err := dispatchTestVerdict(t, resErr); err != nil {
		t.Fatalf("dispatchResponse failed: %v", err)
	}
}

// TestDispatcherDuplicateRequestID checks that a request id cannot be reused
// while it is still in flight, so the first requester cannot be overwritten.
func TestDispatcherDuplicateRequestID(t *testing.T) {
	peer, app := newDispatcherTestPeer(t)

	sink := make(chan *Response, 1)
	first := &Request{
		id:   1,
		sink: sink,
		code: GetBlockHeadersMsg,
		want: BlockHeadersMsg,
		data: []common.Hash{},
	}
	dispatchTestRequest(t, peer, app, first)

	// A duplicate is never written to the wire, so it cannot go through
	// dispatchTestRequest, which waits for the request to appear on the pipe.
	second := &Request{
		id:   1,
		sink: make(chan *Response, 1),
		code: GetBlockHeadersMsg,
		want: BlockHeadersMsg,
		data: []common.Hash{},
	}
	errCh := make(chan error, 1)
	go func() { errCh <- peer.dispatchRequest(second) }()

	select {
	case err := <-errCh:
		if !errors.Is(err, errDuplicateRequest) {
			t.Fatalf("duplicate request mismatch: have %v, want %v", err, errDuplicateRequest)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("duplicate request was not rejected")
	}
	// The first request must still own the id and receive its response.
	resErr := make(chan error, 1)
	go func() {
		resErr <- peer.dispatchResponse(&Response{id: 1, code: BlockHeadersMsg, Res: &BlockHeadersPacket{}})
	}()
	select {
	case res := <-sink:
		res.Done <- nil
		if res.Req != first {
			t.Fatalf("response matched to wrong request")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("original request lost its response")
	}
	if err := dispatchTestVerdict(t, resErr); err != nil {
		t.Fatalf("dispatchResponse failed: %v", err)
	}
}

// TestDispatcherRequestWaitObservesClose checks that a request whose write is
// blocked is released with errDisconnected when the peer is torn down, instead
// of hanging until the wire write completes.
func TestDispatcherRequestWaitObservesClose(t *testing.T) {
	peer, app := newDispatcherTestPeer(t)

	// Read the request off the wire but never consume its payload: p2p.Send
	// stays blocked inside the dispatcher until the payload is read or the pipe
	// is closed, and the peer teardown below only closes the term channel.
	msgCh := make(chan p2p.Msg, 1)
	go func() {
		if msg, err := app.ReadMsg(); err == nil {
			msgCh <- msg
		}
	}()
	req := &Request{
		id:   1,
		sink: make(chan *Response, 1),
		code: GetBlockHeadersMsg,
		want: BlockHeadersMsg,
		data: []common.Hash{},
	}
	errCh := make(chan error, 1)
	go func() { errCh <- peer.dispatchRequest(req) }()

	select {
	case <-msgCh:
	case <-time.After(3 * time.Second):
		t.Fatal("request was not written")
	}
	peer.Close()

	select {
	case err := <-errCh:
		if !errors.Is(err, errDisconnected) {
			t.Fatalf("unexpected dispatch error: have %v, want %v", err, errDisconnected)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("dispatchRequest hung after the peer was closed")
	}
	// Closing the pipe unblocks the pending write; the dispatcher must then
	// publish its late verdict and exit instead of blocking on a waiter that is
	// already gone.
	app.Close()
	done := make(chan struct{})
	go func() {
		peer.broadcastWg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("dispatcher goroutine leaked after the peer was closed")
	}
}

// TestDispatcherTracksRequest checks that a dispatched request is registered
// with the RTT tracker and untracked once the response is acknowledged.
func TestDispatcherTracksRequest(t *testing.T) {
	// Metrics are on for the whole package (see TestMain). Every assertion below
	// is a delta, so the shared process-wide gauge cannot disturb other tests.
	gauge := metrics.GetOrRegisterGauge(
		fmt.Sprintf("p2p/tracked/%s/%d/%#02x", ProtocolName, XDC166, GetBlockHeadersMsg), nil)
	base := int64(gauge.Snapshot())

	peer, app := newDispatcherTestPeer(t)

	sink := make(chan *Response, 1)
	req := &Request{
		id:   1,
		sink: sink,
		code: GetBlockHeadersMsg,
		want: BlockHeadersMsg,
		data: []common.Hash{},
	}
	dispatchTestRequest(t, peer, app, req)

	if got := int64(gauge.Snapshot()) - base; got != 1 {
		t.Fatalf("tracked gauge mismatch after dispatch: have %d, want 1", got)
	}
	resErr := make(chan error, 1)
	go func() {
		resErr <- peer.dispatchResponse(&Response{id: 1, code: BlockHeadersMsg, Res: &BlockHeadersPacket{}})
	}()
	select {
	case res := <-sink:
		res.Done <- nil
	case <-time.After(3 * time.Second):
		t.Fatal("response not delivered")
	}
	if err := dispatchTestVerdict(t, resErr); err != nil {
		t.Fatalf("dispatchResponse failed: %v", err)
	}
	if got := int64(gauge.Snapshot()) - base; got != 0 {
		t.Fatalf("tracked gauge mismatch after fulfilment: have %d, want 0", got)
	}
}

// TestDispatcherCancelReservesID checks that cancelling a pending request keeps
// its tracker record, and thus its wire id, until the late reply arrives.
func TestDispatcherCancelReservesID(t *testing.T) {
	gauge := metrics.GetOrRegisterGauge(
		fmt.Sprintf("p2p/tracked/%s/%d/%#02x", ProtocolName, XDC166, GetBlockHeadersMsg), nil)
	base := int64(gauge.Snapshot())

	peer, app := newDispatcherTestPeer(t)

	req := &Request{
		id:   1,
		sink: make(chan *Response, 1),
		code: GetBlockHeadersMsg,
		want: BlockHeadersMsg,
		data: []common.Hash{},
	}
	dispatchTestRequest(t, peer, app, req)

	if got := int64(gauge.Snapshot()) - base; got != 1 {
		t.Fatalf("tracked gauge mismatch after dispatch: have %d, want 1", got)
	}
	if err := req.Close(); err != nil {
		t.Fatalf("failed to cancel request: %v", err)
	}
	// The pending entry is gone, but the tracker still reserves the id.
	if got := int64(gauge.Snapshot()) - base; got != 1 {
		t.Fatalf("tracked gauge mismatch after cancel: have %d, want 1", got)
	}
	// The late reply releases the reservation and is rejected as dangling.
	if _, err := dispatchTestResponse(t, peer, req.id, nil); !errors.Is(err, errDanglingResponse) {
		t.Fatalf("late reply mismatch: have %v, want %v", err, errDanglingResponse)
	}
	if got := int64(gauge.Snapshot()) - base; got != 0 {
		t.Fatalf("tracked gauge mismatch after the late reply: have %d, want 0", got)
	}
}

// The expiry path of a cancelled reservation is covered by the tracker tests
// (TestCancelledRequestExpiresWithoutLost): swapping the package-level tracker
// here would race with dispatcher goroutines left over from other tests.

// TestDispatcherSendFailureUntracksRequest checks that a request which never
// reaches the wire is untracked instead of expiring as a remote timeout.
func TestDispatcherSendFailureUntracksRequest(t *testing.T) {
	gauge := metrics.GetOrRegisterGauge(
		fmt.Sprintf("p2p/tracked/%s/%d/%#02x", ProtocolName, XDC166, GetBlockHeadersMsg), nil)
	base := int64(gauge.Snapshot())

	peer, app := newDispatcherTestPeer(t)
	// A closed pipe makes the wire write fail before anything is sent.
	app.Close()

	req := &Request{
		id:   1,
		sink: make(chan *Response, 1),
		code: GetBlockHeadersMsg,
		want: BlockHeadersMsg,
		data: []common.Hash{},
	}
	if err := peer.dispatchRequest(req); err == nil {
		t.Fatal("dispatch succeeded on a closed pipe")
	}
	if got := int64(gauge.Snapshot()) - base; got != 0 {
		t.Fatalf("tracked gauge mismatch after a failed send: have %d, want 0", got)
	}
}

// TestDispatcherCloseUntracksRequest checks that a peer teardown clears the
// tracker records of every request still pending on it.
func TestDispatcherCloseUntracksRequest(t *testing.T) {
	gauge := metrics.GetOrRegisterGauge(
		fmt.Sprintf("p2p/tracked/%s/%d/%#02x", ProtocolName, XDC166, GetBlockHeadersMsg), nil)
	base := int64(gauge.Snapshot())

	peer, app := newDispatcherTestPeer(t)

	req := &Request{
		id:   1,
		sink: make(chan *Response, 1),
		code: GetBlockHeadersMsg,
		want: BlockHeadersMsg,
		data: []common.Hash{},
	}
	dispatchTestRequest(t, peer, app, req)

	if got := int64(gauge.Snapshot()) - base; got != 1 {
		t.Fatalf("tracked gauge mismatch after dispatch: have %d, want 1", got)
	}
	peer.Close()

	// The teardown is handled asynchronously by the dispatcher goroutine.
	deadline := time.Now().Add(3 * time.Second)
	for int64(gauge.Snapshot())-base != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("tracked gauge mismatch after peer close: have %d, want 0", int64(gauge.Snapshot())-base)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestDispatcherReconnectKeepsIDScope checks that request tracking is scoped to
// the connection: a reconnect with the same peer id can reuse its wire ids
// before the old connection is torn down, and the real teardown of the old
// connection must release only its own scope, not the new reservations.
func TestDispatcherReconnectKeepsIDScope(t *testing.T) {
	var id enode.ID
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatalf("failed to generate peer id: %v", err)
	}
	peer1, app1 := newDispatcherTestPeerWithID(t, id)
	old := &Request{
		id:   1,
		sink: make(chan *Response, 1),
		code: GetBlockHeadersMsg,
		want: BlockHeadersMsg,
		data: []common.Hash{},
	}
	dispatchTestRequest(t, peer1, app1, old)
	if err := old.Close(); err != nil {
		t.Fatalf("failed to cancel the old request: %v", err)
	}

	// Reconnect before the old connection is torn down: the new connection owns
	// a fresh id scope, so the reused id is accepted.
	peer2, app2 := newDispatcherTestPeerWithID(t, id)
	reuse := &Request{
		id:   1,
		sink: make(chan *Response, 1),
		code: GetBlockHeadersMsg,
		want: BlockHeadersMsg,
		data: []common.Hash{},
	}
	dispatchTestRequest(t, peer2, app2, reuse)

	// Tear the old connection down through the dispatcher and wait for it to
	// exit: the teardown may only release its own scope, leaving the new
	// connection's reservation in place.
	peer1.Close()
	app1.Close()
	dispatchTestPeerExit(t, peer1)

	// The old connection's cancelled id is free again, which proves the
	// teardown ran against the right scope.
	if err := requestTracker.Track(peer1.id, peer1.conn, XDC166, GetBlockHeadersMsg, BlockHeadersMsg, 1); err != nil {
		t.Fatalf("teardown did not release the old connection's id: %v", err)
	}
	requestTracker.Drop(peer1.id, peer1.conn, 1)

	if err := reuse.Close(); err != nil {
		t.Fatalf("failed to cancel the reused request: %v", err)
	}

	third := &Request{
		id:   1,
		sink: make(chan *Response, 1),
		code: GetBlockHeadersMsg,
		want: BlockHeadersMsg,
		data: []common.Hash{},
	}
	reuseErr := make(chan error, 1)
	go func() { reuseErr <- peer2.dispatchRequest(third) }()
	select {
	case err := <-reuseErr:
		if !errors.Is(err, tracker.ErrCollision) {
			t.Fatalf("reuse after a stale teardown: have %v, want %v", err, tracker.ErrCollision)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("reuse after a stale teardown was not rejected")
	}
	// The late reply for the cancelled request is dangling, not delivered to
	// whichever request would have taken over the id.
	if _, err := dispatchTestResponse(t, peer2, 1, nil); !errors.Is(err, errDanglingResponse) {
		t.Fatalf("late reply mismatch: have %v, want %v", err, errDanglingResponse)
	}
}

// TestDispatcherCloseRacingWithRead checks the ownership contract when a
// cancellation races with the consumer taking the response: either the consumer
// took it and its Done verdict is returned, or the dispatcher drained it and
// returned nil without leaving anything queued.
func TestDispatcherCloseRacingWithRead(t *testing.T) {
	peer, app := newDispatcherTestPeer(t)
	sentinel := errors.New("handler verdict")

	for i := 0; i < 20; i++ {
		id := uint64(100 + i)
		sink := make(chan *Response, 1)
		req := &Request{
			id:   id,
			sink: sink,
			code: GetBlockHeadersMsg,
			want: BlockHeadersMsg,
			data: []common.Hash{},
		}
		dispatchTestRequest(t, peer, app, req)

		res := &Response{id: id, code: BlockHeadersMsg, Res: &BlockHeadersPacket{}, accepted: make(chan struct{})}
		resErr := make(chan error, 1)
		go func() { resErr <- peer.dispatchResponse(res) }()
		select {
		case <-res.accepted:
		case <-time.After(3 * time.Second):
			t.Fatalf("iteration %d: response was not accepted", i)
		}
		deadline := time.Now().Add(3 * time.Second)
		for len(sink) == 0 {
			if time.Now().After(deadline) {
				t.Fatalf("iteration %d: response was not queued", i)
			}
			time.Sleep(time.Millisecond)
		}

		// The reader races the dispatcher for the queued response. It also
		// wakes on cancellation, so it cannot leak when the dispatcher drains.
		got := make(chan *Response, 1)
		go func() {
			select {
			case resp := <-sink:
				got <- resp
			case <-req.cancel:
				got <- nil
			}
		}()
		if err := req.Close(); err != nil {
			t.Fatalf("iteration %d: failed to cancel: %v", i, err)
		}
		var resp *Response
		select {
		case resp = <-got:
		case <-time.After(3 * time.Second):
			t.Fatalf("iteration %d: reader did not finish", i)
		}
		if resp != nil {
			resp.Done <- sentinel
		}
		select {
		case err := <-resErr:
			if resp != nil {
				if !errors.Is(err, sentinel) {
					t.Fatalf("iteration %d: consumer verdict lost: have %v, want %v", i, err, sentinel)
				}
			} else if err != nil {
				t.Fatalf("iteration %d: unexpected dispatch error: %v", i, err)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("iteration %d: dispatchResponse hung", i)
		}
		if left := len(sink); left != 0 {
			t.Fatalf("iteration %d: response left in the sink: %d", i, left)
		}
	}
}

// dispatchTestResponse dispatches one headers reply for id. With want set it
// waits for the reply on want's sink and acknowledges it; with want nil it only
// returns the dispatcher's verdict.
func dispatchTestResponse(t *testing.T, peer *Peer, id uint64, want *Request) (*Response, error) {
	t.Helper()

	errCh := make(chan error, 1)
	go func() {
		errCh <- peer.dispatchResponse(&Response{id: id, code: BlockHeadersMsg, Res: &BlockHeadersPacket{}})
	}()
	if want == nil {
		select {
		case err := <-errCh:
			return nil, err
		case <-time.After(3 * time.Second):
			t.Fatal("dispatchResponse hung on a reply nobody consumes")
		}
	}
	select {
	case res := <-want.sink:
		res.Done <- nil
		return res, dispatchTestVerdict(t, errCh)
	case err := <-errCh:
		return nil, err
	case <-time.After(3 * time.Second):
		t.Fatal("response not delivered")
	}
	return nil, nil
}

// TestDispatcherMultipleRequestsOutOfOrder checks that several same-kind
// requests can be in flight on one peer and that each reply is matched by id,
// not by arrival order or packet type.
func TestDispatcherMultipleRequestsOutOfOrder(t *testing.T) {
	peer, app := newDispatcherTestPeer(t)

	reqs := []*Request{
		{id: 1, sink: make(chan *Response, 1), code: GetBlockHeadersMsg, want: BlockHeadersMsg, data: []common.Hash{}},
		{id: 2, sink: make(chan *Response, 1), code: GetBlockHeadersMsg, want: BlockHeadersMsg, data: []common.Hash{}},
		{id: 3, sink: make(chan *Response, 1), code: GetBlockHeadersMsg, want: BlockHeadersMsg, data: []common.Hash{}},
	}
	for _, req := range reqs {
		dispatchTestRequest(t, peer, app, req)
	}
	// Reply out of order: 3, 1, 2.
	for _, idx := range []int{2, 0, 1} {
		want := reqs[idx]
		res, err := dispatchTestResponse(t, peer, want.id, want)
		if err != nil {
			t.Fatalf("reply to id %d rejected: %v", want.id, err)
		}
		if res.Req != want {
			t.Fatalf("reply to id %d matched request id %d", want.id, res.Req.id)
		}
	}
	// The table is empty again, so the same ids are now dangling.
	for _, req := range reqs {
		if _, err := dispatchTestResponse(t, peer, req.id, nil); !errors.Is(err, errDanglingResponse) {
			t.Fatalf("reply to fulfilled id %d: have %v, want %v", req.id, err, errDanglingResponse)
		}
	}
}

// TestDispatcherLateReplyAfterCancelNotMisrouted checks that a late reply to a
// cancelled request is rejected even while a same-kind request is in flight,
// instead of being handed to the newer request.
func TestDispatcherLateReplyAfterCancelNotMisrouted(t *testing.T) {
	peer, app := newDispatcherTestPeer(t)

	cancelled := &Request{id: 1, sink: make(chan *Response, 1), code: GetBlockHeadersMsg, want: BlockHeadersMsg, data: []common.Hash{}}
	live := &Request{id: 2, sink: make(chan *Response, 1), code: GetBlockHeadersMsg, want: BlockHeadersMsg, data: []common.Hash{}}
	dispatchTestRequest(t, peer, app, cancelled)
	dispatchTestRequest(t, peer, app, live)

	if err := cancelled.Close(); err != nil {
		t.Fatalf("failed to cancel request: %v", err)
	}
	if _, err := dispatchTestResponse(t, peer, cancelled.id, nil); !errors.Is(err, errDanglingResponse) {
		t.Fatalf("late reply to a cancelled id: have %v, want %v", err, errDanglingResponse)
	}
	select {
	case res := <-live.sink:
		res.Done <- nil
		t.Fatalf("late reply to the cancelled request was delivered to request id %d", res.Req.id)
	default:
	}
	res, err := dispatchTestResponse(t, peer, live.id, live)
	if err != nil {
		t.Fatalf("reply to the live request rejected: %v", err)
	}
	if res.Req != live {
		t.Fatalf("reply matched request id %d, want %d", res.Req.id, live.id)
	}
}

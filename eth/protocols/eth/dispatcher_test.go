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
	"testing"
	"time"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/p2p"
	"github.com/XinFinOrg/XDPoSChain/p2p/enode"
)

// newDispatcherTestPeer creates a wire peer backed by an in-memory message pipe
// and returns the remote end of the pipe so tests can inspect requests.
func newDispatcherTestPeer(t *testing.T) (*Peer, *p2p.MsgPipeRW) {
	t.Helper()

	app, net := p2p.MsgPipe()

	var id enode.ID
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatalf("failed to generate random peer id: %v", err)
	}
	peer := NewPeer(XDC166, p2p.NewPeer(id, "dispatcher", nil), net, func(common.Hash) *types.Transaction { return nil })
	t.Cleanup(func() {
		peer.Close()
		app.Close()
	})
	return peer, app
}

// dispatchTestRequest sends a request from the peer and consumes it from the
// remote end of the pipe, returning once the request is registered as pending.
func dispatchTestRequest(t *testing.T, peer *Peer, app *p2p.MsgPipeRW, req *Request) {
	t.Helper()

	reqErr := make(chan error, 1)
	go func() { reqErr <- peer.dispatchRequest(req) }()

	msg, err := app.ReadMsg()
	if err != nil {
		t.Fatalf("failed to read dispatched request: %v", err)
	}
	if msg.Code != req.code {
		t.Fatalf("request code mismatch: have %d, want %d", msg.Code, req.code)
	}
	msg.Discard()

	if err := <-reqErr; err != nil {
		t.Fatalf("failed to dispatch request: %v", err)
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
	if err := <-resErr; err != nil {
		t.Fatalf("dispatchResponse failed: %v", err)
	}
}

// TestDispatcherDanglingResponse checks that responses with an unknown request
// id are dropped and the dispatcher keeps serving later requests.
func TestDispatcherDanglingResponse(t *testing.T) {
	peer, app := newDispatcherTestPeer(t)

	if err := peer.dispatchResponse(&Response{id: 1, code: BlockHeadersMsg, Res: &BlockHeadersPacket{}}); err != nil {
		t.Fatalf("dangling response returned error: %v", err)
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
	if err := <-resErr; err != nil {
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

	if err := peer.dispatchResponse(&Response{id: 1, code: BlockBodiesMsg, Res: &BlockBodiesPacket{}}); err != nil {
		t.Fatalf("mismatching response returned error: %v", err)
	}
	select {
	case <-sink:
		t.Fatal("mismatching response was delivered")
	default:
	}
}

// TestDispatcherCancelledRequest checks that a late response to a cancelled
// request is discarded.
func TestDispatcherCancelledRequest(t *testing.T) {
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
	if err := peer.dispatchResponse(&Response{id: 1, code: BlockHeadersMsg, Res: &BlockHeadersPacket{}}); err != nil {
		t.Fatalf("late response returned error: %v", err)
	}
	select {
	case <-sink:
		t.Fatal("cancelled request received a response")
	default:
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

	resErr := make(chan error, 1)
	go func() {
		resErr <- peer.dispatchResponse(&Response{id: 1, code: BlockHeadersMsg, Res: &BlockHeadersPacket{}})
	}()
	// Give the response dispatcher time to reach the delivery select.
	time.Sleep(100 * time.Millisecond)
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

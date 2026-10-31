// Copyright 2015 The go-ethereum Authors
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
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/forkid"
	"github.com/XinFinOrg/XDPoSChain/p2p"
	"github.com/XinFinOrg/XDPoSChain/p2p/enode"
)

// newHandshakePeer creates a wire peer over one end of a fresh message pipe and
// returns it together with the remote end, so the test can play the other side
// of the handshake.
func newHandshakePeer(t *testing.T, name string, version uint) (*Peer, *p2p.MsgPipeRW) {
	t.Helper()

	app, net := p2p.MsgPipe()

	var id enode.ID
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatalf("failed to generate random peer id: %v", err)
	}
	peer := NewPeer(version, p2p.NewPeer(id, name, nil), net, nil)
	t.Cleanup(func() {
		app.Close()
		peer.Close()
	})
	return peer, app
}

// chainStatus is the status state of the (fake) local chain used by the tests.
type chainStatus struct {
	td      *big.Int
	head    common.Hash
	genesis common.Hash
	forkID  forkid.ID
}

// statusOf gathers the status fields a node would hand to a peer for the given
// chain.
func statusOf(backend *testBackend) chainStatus {
	head := backend.chain.CurrentHeader()
	genesis := backend.chain.Genesis()
	return chainStatus{
		td:      backend.chain.GetTd(head.Hash(), head.Number.Uint64()),
		head:    head.Hash(),
		genesis: genesis.Hash(),
		forkID:  forkid.NewID(backend.chain.Config(), genesis, head.Number.Uint64()),
	}
}

// handshakePayload builds the status message a peer of the given version sends
// for the given chain state.
func handshakePayload(version uint, status chainStatus) (interface{}, error) {
	switch version {
	case XDC165, XDC164, XDC166:
		return &StatusPacket{
			ProtocolVersion: uint32(version),
			NetworkID:       testNetworkID,
			TD:              status.td,
			Head:            status.head,
			Genesis:         status.genesis,
			ForkID:          status.forkID,
		}, nil
	case XDC100:
		return &StatusPacket100{
			ProtocolVersion: uint32(version),
			NetworkId:       testNetworkID,
			TD:              status.td,
			CurrentBlock:    status.head,
			GenesisBlock:    status.genesis,
		}, nil
	}
	return nil, fmt.Errorf("unsupported eth protocol version: %d", version)
}

// serveHandshake performs the wire handshake against the given chain status,
// as the node layer would.
func serveHandshake(peer *Peer, version uint, status chainStatus, filter forkid.Filter) error {
	switch version {
	case XDC165, XDC164, XDC166:
		return peer.Handshake(testNetworkID, status.td, status.head, status.genesis, status.forkID, filter)
	case XDC100:
		return peer.Handshake(testNetworkID, status.td, status.head, status.genesis, status.forkID, nil)
	}
	return fmt.Errorf("unsupported eth protocol version: %d", version)
}

// TestHandshake100 checks that both peers complete the xdc/100 form of the
// handshake and end up carrying each other's head and total difficulty.
func TestHandshake100(t *testing.T) {
	backend := newTestBackend(t, 1, nil)
	testHandshake(t, backend, XDC100)
}

// TestHandshake164 checks that both peers complete the forkid-carrying form of
// the handshake and end up carrying each other's head and total difficulty.
func TestHandshake164(t *testing.T) {
	backend := newTestBackend(t, 1, nil)
	testHandshake(t, backend, XDC164)
}

// TestHandshake166 checks that both peers complete the request-id-capable form
// of the handshake — same forkid-carrying status shape as xdc/164 — and end up
// carrying each other's head and total difficulty.
func TestHandshake166(t *testing.T) {
	backend := newTestBackend(t, 1, nil)
	testHandshake(t, backend, XDC166)
}

func testHandshake(t *testing.T, backend *testBackend, version uint) {
	app, net := p2p.MsgPipe()
	defer app.Close()

	var id enode.ID
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatalf("failed to generate random peer id: %v", err)
	}
	peer := NewPeer(version, p2p.NewPeer(id, "peer", nil), net, nil)
	defer peer.Close()

	status := statusOf(backend)
	remote := &Peer{
		Peer:    p2p.NewPeer(enode.ID{0x01}, "remote", nil),
		rw:      app,
		version: version,
	}
	// The remote side speaks directly over the pipe, without a broadcast loop.
	errc := make(chan error, 2)
	filter := forkid.NewFilter(backend.chain)
	go func() { errc <- serveHandshake(peer, version, status, filter) }()
	go func() { errc <- serveHandshake(remote, version, status, filter) }()

	for i := 0; i < 2; i++ {
		select {
		case err := <-errc:
			if err != nil {
				t.Fatalf("handshake failed: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("handshake did not complete within 2 seconds")
		}
	}
	// Both sides must now carry the remote head and difficulty.
	for i, p := range []*Peer{peer, remote} {
		hash, td := p.Head()
		if hash != status.head {
			t.Errorf("peer %d: head mismatch: have %x, want %x", i, hash, status.head)
		}
		if td.Cmp(status.td) != 0 {
			t.Errorf("peer %d: td mismatch: have %v, want %v", i, td, status.td)
		}
	}
}

// Tests that handshake failures are detected and reported correctly.
func TestStatusMsgErrors100(t *testing.T) {
	backend := newTestBackend(t, 0, nil)
	status := statusOf(backend)

	tests := []struct {
		code      uint64
		data      interface{}
		wantError error
	}{
		{
			code: TransactionMsg, data: []interface{}{},
			wantError: errResp(ErrNoStatusMsg, "first msg has code 2 (!= 0)"),
		},
		{
			code: StatusMsg, data: StatusPacket100{10, testNetworkID, status.td, status.head, status.genesis},
			wantError: errResp(ErrProtocolVersionMismatch, "10 (!= %d)", XDC100),
		},
		{
			code: StatusMsg, data: StatusPacket100{XDC100, 999, status.td, status.head, status.genesis},
			wantError: errResp(ErrNetworkIDMismatch, "999 (!= %d)", testNetworkID),
		},
		{
			code: StatusMsg, data: StatusPacket100{XDC100, testNetworkID, status.td, status.head, common.Hash{3}},
			wantError: errResp(ErrGenesisMismatch, "0300000000000000 (!= %x)", status.genesis.Bytes()[:8]),
		},
	}
	for i, test := range tests {
		t.Run(fmt.Sprintf("case %d", i), func(t *testing.T) {
			peer, app := newHandshakePeer(t, "peer", XDC100)
			runRejectedHandshake(t, peer, app, XDC100, status, forkid.NewFilter(backend.chain), test.code, test.data, test.wantError)
		})
	}
}

func TestStatusMsgErrors164(t *testing.T) {
	backend := newTestBackend(t, 0, nil)
	status := statusOf(backend)

	tests := []struct {
		code      uint64
		data      interface{}
		wantError error
	}{
		{
			code: TransactionMsg, data: []interface{}{},
			wantError: errResp(ErrNoStatusMsg, "first msg has code 2 (!= 0)"),
		},
		{
			code: StatusMsg, data: StatusPacket{10, testNetworkID, status.td, status.head, status.genesis, status.forkID},
			wantError: errResp(ErrProtocolVersionMismatch, "10 (!= %d)", XDC164),
		},
		{
			code: StatusMsg, data: StatusPacket{XDC164, 999, status.td, status.head, status.genesis, status.forkID},
			wantError: errResp(ErrNetworkIDMismatch, "999 (!= %d)", testNetworkID),
		},
		{
			code: StatusMsg, data: StatusPacket{XDC164, testNetworkID, status.td, status.head, common.Hash{3}, status.forkID},
			wantError: errResp(ErrGenesisMismatch, "0300000000000000000000000000000000000000000000000000000000000000 (!= %x)", status.genesis),
		},
		{
			code: StatusMsg, data: StatusPacket{XDC164, testNetworkID, status.td, status.head, status.genesis, forkid.ID{Hash: [4]byte{0x00, 0x01, 0x02, 0x03}}},
			wantError: errResp(ErrForkIDRejected, "%s", forkid.ErrLocalIncompatibleOrStale.Error()),
		},
	}
	for i, test := range tests {
		t.Run(fmt.Sprintf("case %d", i), func(t *testing.T) {
			peer, app := newHandshakePeer(t, "peer", XDC164)
			runRejectedHandshake(t, peer, app, XDC164, status, forkid.NewFilter(backend.chain), test.code, test.data, test.wantError)
		})
	}
}

// runRejectedHandshake completes the local side's status send, feeds the remote
// side's crafted first message to the handshake and checks the reported error.
func runRejectedHandshake(t *testing.T, peer *Peer, app *p2p.MsgPipeRW, version uint, status chainStatus, filter forkid.Filter, code uint64, data interface{}, wantError error) {
	t.Helper()

	errc := make(chan error, 1)
	go func() { errc <- serveHandshake(peer, version, status, filter) }()

	// Consume the status our side sends out, so only the crafted message is left
	// for the handshake to read.
	msg, err := app.ReadMsg()
	if err != nil {
		t.Fatalf("failed to read local status: %v", err)
	}
	if msg.Code != StatusMsg {
		t.Fatalf("local status code mismatch: have %x, want %x", msg.Code, StatusMsg)
	}
	// Discard the payload, or our side's send never completes.
	msg.Discard()

	// The crafted message may be rejected before its payload is consumed, so
	// send it from a goroutine and let the pipe teardown release it.
	go func() { p2p.Send(app, code, data) }()
	select {
	case err := <-errc:
		if err == nil {
			t.Fatalf("handshake returned nil error, want %v", wantError)
		}
		if err.Error() != wantError.Error() {
			t.Fatalf("wrong error: got %v, want %v", err, wantError)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("handshake did not shut down within 2 seconds")
	}
}

// TestExtraStatusMsg checks that a status message arriving after the handshake
// tears the peer down instead of being acted on.
func TestExtraStatusMsg(t *testing.T) {
	backend := newTestBackend(t, 0, nil)
	status := statusOf(backend)

	peer, app := newHandshakePeer(t, "peer", XDC164)

	// Complete the handshake first, exactly as the node layer would.
	errc := make(chan error, 1)
	go func() { errc <- serveHandshake(peer, XDC164, status, forkid.NewFilter(backend.chain)) }()
	msg, err := app.ReadMsg()
	if err != nil {
		t.Fatalf("failed to read local status: %v", err)
	}
	if msg.Code != StatusMsg {
		t.Fatalf("local status code mismatch: have %x, want %x", msg.Code, StatusMsg)
	}
	msg.Discard()

	payload, err := handshakePayload(XDC164, status)
	if err != nil {
		t.Fatalf("failed to build status payload: %v", err)
	}
	go func() { p2p.Send(app, StatusMsg, payload) }()
	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("handshake failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("handshake did not complete within 2 seconds")
	}
	// Serve the peer and send a second, uncontrolled status message.
	done := make(chan error, 1)
	go func() { done <- Handle(backend, peer) }()

	go func() { p2p.Send(app, StatusMsg, payload) }()
	select {
	case err := <-done:
		want := errResp(ErrExtraStatusMsg, "uncontrolled status message")
		if err == nil || err.Error() != want.Error() {
			t.Fatalf("extra status error mismatch: have %v, want %v", err, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("extra status message was not rejected within 2 seconds")
	}
}

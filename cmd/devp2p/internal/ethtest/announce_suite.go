// Copyright 2021 The go-ethereum Authors
// This file is part of go-ethereum.
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with go-ethereum. If not, see <http://www.gnu.org/licenses/>.

// The announcement conformance cases exercise the block announcement path
// against a live node: oversized announcements must be rejected with a
// disconnect (upstream #21792), announcements for already-known blocks must
// not be propagated (upstream #22474), and an unknown block hash announcement
// must make the node retrieve the announced header (upstream #22535). Node-run
// verification of these cases is the §8.3 devnet matrix; CI runs only the
// node-less shape tests around them.
package ethtest

import (
	"errors"
	"fmt"
	"math/big"
	"net"
	"time"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	ethproto "github.com/XinFinOrg/XDPoSChain/eth/protocols/eth"
	"github.com/XinFinOrg/XDPoSChain/internal/utesting"
)

// announceTimeout bounds the wait windows of the announcement cases, mirroring
// the timeout the upstream announcement tests read with
// (upstream #21792/#22474/#22535).
const announceTimeout = 20 * time.Second

// blockAnnouncement is the suite-local NewBlock announcement payload, matching
// the node's eth.NewBlockPacket wire shape (block plus total difficulty).
type blockAnnouncement struct {
	Block *types.Block
	TD    *big.Int
}

// TestLargeAnnounce tests the announcement mechanism with oversized payloads:
// a block header with multi-megabyte fields, a multi-megabyte total difficulty
// carried by a consistent block, and both at once. Each invalid announcement
// must get the announcing connection disconnected rather than processed
// (upstream #21792).
//
// The upstream case's final leg announces a valid successor block and watches
// it propagate; that leg needs a real block beyond the fixture chain head,
// which the frozen testdata set cannot provide (plan §0), so it is not ported.
func (s *Suite) TestLargeAnnounce(t *utesting.T) {
	t.Log(`This test announces blocks with oversized header fields or total difficulty and expects a disconnect for each.`)
	announcements := []*blockAnnouncement{
		// A block whose header carries multi-megabyte number and difficulty
		// fields, announced with the suite's own total difficulty. The body
		// hashes stay consistent with the empty body, so the rejection comes
		// from the announcement sanity check and not from an earlier body
		// mismatch, which the node drops silently.
		{Block: largeBlock(), TD: s.chain.TD()},
		// A consistent block, announced with a multi-megabyte total difficulty.
		{Block: s.chain.Head(), TD: largeNumber(2)},
		// Both oversized at once.
		{Block: largeBlock(), TD: largeNumber(2)},
	}
	for i, announcement := range announcements {
		t.Logf("testing malicious announcement: %d", i)
		sendConn, err := s.dialAndPeer(nil)
		if err != nil {
			t.Fatalf("peering failed: %v", err)
		}
		if err := sendConn.Write(ethProto, ethproto.NewBlockMsg, announcement); err != nil {
			sendConn.Close()
			t.Fatalf("failed to write announcement: %v", err)
		}
		if err := expectDisconnectWithin(sendConn, announceTimeout); err != nil {
			sendConn.Close()
			t.Fatalf("no disconnect after oversized announcement %d: %v", i, err)
		}
	}
}

// TestOldAnnounce sends a NewBlock announcement for a block in the middle of
// the fixture chain and verifies the node does not propagate it to another
// peer within the wait window (upstream #22474).
func (s *Suite) TestOldAnnounce(t *utesting.T) {
	t.Log(`This test announces an already-known block and expects no propagation within the wait window.`)
	sendConn, err := s.dialAndPeer(nil)
	if err != nil {
		t.Fatalf("peering failed: %v", err)
	}
	defer sendConn.Close()
	recvConn, err := s.dialAndPeer(nil)
	if err != nil {
		t.Fatalf("peering failed: %v", err)
	}
	defer recvConn.Close()

	old := s.chain.blocks[s.chain.Len()/2]
	announcement := &blockAnnouncement{Block: old, TD: old.Difficulty()}
	if err := sendConn.Write(ethProto, ethproto.NewBlockMsg, announcement); err != nil {
		t.Fatalf("failed to write old announcement: %v", err)
	}
	// Upstream waits for twice its base timeout here: the absence of a
	// propagation is only meaningful once the node had ample time to forward
	// the announcement.
	if err := expectNoBlockAnnouncement(recvConn, 2*announceTimeout); err != nil {
		t.Fatalf("old block was propagated: %v", err)
	}
}

// TestBlockHashAnnounce sends a NewBlockHashes announcement for a block the
// node does not have and verifies the node reacts by requesting the announced
// header from the announcing peer (upstream #22535).
//
// Upstream serves the requested header from a full-chain fixture and watches
// the block propagate; the frozen testdata set has no successor block, so the
// ported case verifies the retrieval request and stops there (plan §0).
func (s *Suite) TestBlockHashAnnounce(t *utesting.T) {
	t.Log(`This test announces an unknown block hash and expects the node to request the announced header.`)
	sendConn, err := s.dialAndPeer(nil)
	if err != nil {
		t.Fatalf("peering failed: %v", err)
	}
	defer sendConn.Close()

	hash, number := s.unknownSuccessorHash()
	if err := sendConn.Write(ethProto, ethproto.NewBlockHashesMsg, &ethproto.NewBlockHashesPacket{{Hash: hash, Number: number}}); err != nil {
		t.Fatalf("failed to write to connection: %v", err)
	}
	// The node answers the announcement with a single-header query for the
	// announced hash; assert its shape once it arrives. The wait is bounded:
	// read timeouts are retried until the window closes, then the case fails,
	// so a node that never asks cannot stall the run (upstream #32551).
	deadline := time.Now().Add(announceTimeout)
	for time.Now().Before(deadline) {
		msg, err := sendConn.ReadEth()
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			t.Fatalf("failed to read header request: %v", err)
		}
		req, ok := msg.(*getBlockHeadersData)
		if !ok {
			continue
		}
		if req.Amount != 1 {
			t.Fatalf("unexpected number of block headers requested: %d", req.Amount)
		}
		if req.Origin.Hash != hash {
			t.Fatalf("unexpected block header requested: have hash %s, want hash %s", req.Origin.Hash, hash)
		}
		return
	}
	t.Fatalf("timed out waiting for the header request within %s", announceTimeout)
}

// TestBlockHashAnnounce_66 runs the block hash announcement case over a
// xdc/166 connection: the retrieval request arrives in its two-element shape
// and must be decoded with its request id (upstream #22535).
func (s *Suite) TestBlockHashAnnounce_66(t *utesting.T) {
	t.Log(`This test announces an unknown block hash over xdc/166 and expects the node to request the announced header.`)
	sendConn, ok := s.setupConnection66(t)
	if !ok {
		return
	}
	defer sendConn.Close()

	hash, number := s.unknownSuccessorHash()
	if err := sendConn.Write(ethProto, ethproto.NewBlockHashesMsg, &ethproto.NewBlockHashesPacket{{Hash: hash, Number: number}}); err != nil {
		t.Fatalf("failed to write to connection: %v", err)
	}
	// Bounded wait, like the legacy variant above (upstream #32551).
	deadline := time.Now().Add(announceTimeout)
	for time.Now().Before(deadline) {
		_, msg, err := sendConn.ReadEth66()
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			t.Fatalf("failed to read header request: %v", err)
		}
		req, ok := msg.(*getBlockHeadersData)
		if !ok {
			continue
		}
		if req.Amount != 1 {
			t.Fatalf("unexpected number of block headers requested: %d", req.Amount)
		}
		if req.Origin.Hash != hash {
			t.Fatalf("unexpected block header requested: have hash %s, want hash %s", req.Origin.Hash, hash)
		}
		return
	}
	t.Fatalf("timed out waiting for the header request within %s", announceTimeout)
}

// unknownSuccessorHash returns a hash the fixture chain does not carry, one
// block past its head so the fetcher treats the announcement as plausible.
func (s *Suite) unknownSuccessorHash() (common.Hash, uint64) {
	return randHash(), uint64(s.chain.Len())
}

// expectDisconnectWithin reads frames until the connection is torn down and
// reports an error when the peer stays reachable for the whole window. A
// disconnect reason frame or an abrupt read failure both count as a teardown;
// ping frames are answered so the peer does not drop us for idling, and read
// timeouts are retried until the window closes.
func expectDisconnectWithin(conn *Conn, window time.Duration) error {
	deadline := time.Now().Add(window)
	for {
		code, _, err := conn.Read()
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				if time.Now().After(deadline) {
					return fmt.Errorf("peer stayed connected for %s", window)
				}
				continue
			}
			// The peer tore the connection down without a reason frame.
			return nil
		}
		switch code {
		case discMsg:
			return nil
		case pingMsg:
			if err := conn.Write(baseProto, pongMsg, []byte{}); err != nil {
				return fmt.Errorf("failed to reply pong: %w", err)
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("peer stayed connected for %s", window)
		}
	}
}

// expectNoBlockAnnouncement reads raw frames for the given window and reports
// an error as soon as a block announcement frame (NewBlock or NewBlockHashes)
// shows up. Frames are classified by message code because the client decodes
// announcement payloads opaquely and the XDC BFT chatter shares the same
// opaque shape; the eth code space is offset past the devp2p frames, so the
// classification goes through the same full-space guard the xdc/166 read path
// uses. Read timeouts are retried until the window closes, while an early
// teardown fails the wait since it could hide a propagation that was about to
// arrive.
func expectNoBlockAnnouncement(conn *Conn, window time.Duration) error {
	deadline := time.Now().Add(window)
	for {
		code, _, err := conn.Read()
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				if time.Now().After(deadline) {
					return nil
				}
				continue
			}
			return fmt.Errorf("connection failed before the window closed: %w", err)
		}
		if isEth66MsgCode(code) {
			switch code - protoOffset(ethProto) {
			case ethproto.NewBlockMsg, ethproto.NewBlockHashesMsg:
				return fmt.Errorf("received announcement frame with code %d", code)
			}
		}
		switch code {
		case discMsg:
			return fmt.Errorf("peer disconnected before the window closed")
		case pingMsg:
			if err := conn.Write(baseProto, pongMsg, []byte{}); err != nil {
				return fmt.Errorf("failed to reply pong: %w", err)
			}
		}
		if time.Now().After(deadline) {
			return nil
		}
	}
}

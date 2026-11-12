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

const announceTimeout = 20 * time.Second

type blockAnnouncement struct {
	Block *types.Block
	TD    *big.Int
}

// TestLargeAnnounce covers the oversized payload legs of the upstream case
// (#21792); its valid-successor leg needs a block beyond the frozen fixture
// head, so it is not ported
func (s *Suite) TestLargeAnnounce(t *utesting.T) {
	t.Log(`This test announces blocks with oversized header fields or total difficulty and expects a disconnect for each.`)
	announcements := []*blockAnnouncement{
		// Body hashes stay consistent with the empty body so the rejection comes
		// from the announcement sanity check, not from a body mismatch the node
		// drops silently
		{Block: largeBlock(), TD: s.chain.TD()},
		{Block: s.chain.Head(), TD: largeNumber(2)},
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
	// Twice the base timeout, as upstream: absence of propagation is only
	// meaningful once the node had ample time to forward it
	if err := expectNoBlockAnnouncement(recvConn, 2*announceTimeout); err != nil {
		t.Fatalf("old block was propagated: %v", err)
	}
}

// TestBlockHashAnnounce stops at the retrieval request; upstream also serves
// the header and watches propagation, which needs a block beyond the fixture
// head (#22535)
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

func (s *Suite) TestBlockHashAnnounce_Xdc166(t *utesting.T) {
	t.Log(`This test announces an unknown block hash over xdc/166 and expects the node to request the announced header.`)
	sendConn, ok := s.setupConnectionXdc166(t)
	if !ok {
		return
	}
	defer sendConn.Close()

	hash, number := s.unknownSuccessorHash()
	// The height must clear the fetcher staleness window; on this devnet
	// difficulty is 1 per block, so TD tracks the head height and the immediate
	// successor is the honest announcement
	if sendConn.remoteTD != nil {
		number = sendConn.remoteTD.Uint64()
	}
	if err := sendConn.Write(ethProto, ethproto.NewBlockHashesMsg, &ethproto.NewBlockHashesPacket{{Hash: hash, Number: number}}); err != nil {
		t.Fatalf("failed to write to connection: %v", err)
	}
	deadline := time.Now().Add(announceTimeout)
	for time.Now().Before(deadline) {
		_, msg, err := sendConn.ReadXdc166()
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

func (s *Suite) unknownSuccessorHash() (common.Hash, uint64) {
	return randHash(), uint64(s.chain.Len())
}

// A disconnect frame and an abrupt read failure both count as a teardown
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

// Frames are classified by message code because the XDC BFT chatter shares the
// opaque announcement payload shape; an early teardown fails the wait since it
// could hide a propagation that was about to arrive
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
		if isXdc166MsgCode(code) {
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

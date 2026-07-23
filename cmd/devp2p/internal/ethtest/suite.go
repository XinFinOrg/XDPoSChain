// Copyright 2020 The go-ethereum Authors
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
	"crypto/ecdsa"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/internal/utesting"
	"github.com/XinFinOrg/XDPoSChain/p2p"
	"github.com/XinFinOrg/XDPoSChain/p2p/enode"
	"github.com/XinFinOrg/XDPoSChain/p2p/rlpx"
	"github.com/XinFinOrg/XDPoSChain/rlp"
)

const handshakeTimeout = 5 * time.Second

// Suite represents a minimal conformance test set that is compatible with
// the protocol packages available in this repository snapshot.
type Suite struct {
	Dest *enode.Node
}

// NewSuite creates and returns a compatibility subset suite.
// The extra string parameters are currently unused and kept for API parity.
func NewSuite(dest *enode.Node, _, _, _ string) (*Suite, error) {
	return &Suite{Dest: dest}, nil
}

// EthTests returns the enabled compatibility subset.
//
// Scope freeze:
//  1. Keep only tests that depend on RLPx/devp2p handshake primitives available
//     in this repository snapshot.
//  2. Avoid extending coverage into protocol packages that are not importable in
//     this fork state.
//  3. Maintain behavior via boundary-driven hello/message-code/payload cases.
func (s *Suite) EthTests() []utesting.Test {
	return []utesting.Test{
		// Baseline.
		{Name: "RLPxHandshake", Fn: s.TestRLPxHandshake},

		// Identity-focused hello boundary tests.
		{Name: "MalformedHello", Fn: s.TestMalformedHello},
		{Name: "MalformedHelloShortID", Fn: s.TestMalformedHelloShortID},
		{Name: "MalformedHelloEmptyID", Fn: s.TestMalformedHelloEmptyID},
		{Name: "MalformedHelloLongID", Fn: s.TestMalformedHelloLongID},
		{Name: "MalformedHelloZeroID", Fn: s.TestMalformedHelloZeroID},
		{Name: "MalformedHelloMismatchedID", Fn: s.TestMalformedHelloMismatchedID},

		// Capability-focused hello boundary tests.
		{Name: "HelloWithoutEthCap", Fn: s.TestHelloWithoutEthCap},
		{Name: "HelloWithEmptyCaps", Fn: s.TestHelloWithEmptyCaps},
		{Name: "HelloWithEmptyCapName", Fn: s.TestHelloWithEmptyCapName},
		{Name: "HelloWithLongCapName", Fn: s.TestHelloWithLongCapName},
		{Name: "HelloWithNULCapName", Fn: s.TestHelloWithNULCapName},
		{Name: "HelloWithMismatchedIDAndEmptyCaps", Fn: s.TestHelloWithMismatchedIDAndEmptyCaps},
		{Name: "HelloWithUnsortedNonEthCaps", Fn: s.TestHelloWithUnsortedNonEthCaps},
		{Name: "HelloWithDuplicateEthCaps", Fn: s.TestHelloWithDuplicateEthCaps},

		// Version and mixed hello semantics.
		{Name: "HelloWithZeroVersion", Fn: s.TestHelloWithZeroVersion},
		{Name: "HelloWithMaxVersion", Fn: s.TestHelloWithMaxVersion},
		{Name: "HelloWithZeroVersionAndEmptyCaps", Fn: s.TestHelloWithZeroVersionAndEmptyCaps},

		// Post-RLPx first-message code handling.
		{Name: "WrongFirstMessageCode", Fn: s.TestWrongFirstMessageCode},
		{Name: "FirstMessageDisconnect", Fn: s.TestFirstMessageDisconnect},
		{Name: "FirstMessageDisconnectInvalidPayload", Fn: s.TestFirstMessageDisconnectInvalidPayload},
		{Name: "FirstMessageDisconnectEmptyPayload", Fn: s.TestFirstMessageDisconnectEmptyPayload},

		// Handshake payload size/encoding/type boundaries.
		{Name: "OversizedHelloPayload", Fn: s.TestOversizedHelloPayload},
		{Name: "EmptyHelloPayload", Fn: s.TestEmptyHelloPayload},
		{Name: "TruncatedHelloPayload", Fn: s.TestTruncatedHelloPayload},
		{Name: "InvalidHelloRLP", Fn: s.TestInvalidHelloRLP},
		{Name: "HelloPayloadWrongRLPType", Fn: s.TestHelloPayloadWrongRLPType},
		{Name: "HelloPayloadEmptyList", Fn: s.TestHelloPayloadEmptyList},
		{Name: "HelloPayloadShortList", Fn: s.TestHelloPayloadShortList},
		{Name: "HelloPayloadVersionWrongType", Fn: s.TestHelloPayloadVersionWrongType},
	}
}

func (s *Suite) TestRLPxHandshake(t *utesting.T) {
	t.Log(`This test verifies that the peer accepts a plain RLPx handshake.`)
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	conn, err := s.dialConn(key)
	if err != nil {
		t.Fatalf("rlpx handshake failed: %v", err)
	}
	conn.Close()
}

func (s *Suite) TestMalformedHello(t *utesting.T) {
	t.Log(`This test sends a malformed devp2p hello and expects a disconnect.`)
	s.runMalformedHelloNamedCase(t, "MalformedHello")
}

func (s *Suite) TestMalformedHelloShortID(t *utesting.T) {
	t.Log(`This test sends a hello with a too-short peer id and expects a disconnect.`)
	s.runMalformedHelloNamedCase(t, "MalformedHelloShortID")
}

func (s *Suite) TestMalformedHelloEmptyID(t *utesting.T) {
	t.Log(`This test sends a hello with an empty peer id and expects a disconnect.`)
	s.runMalformedHelloNamedCase(t, "MalformedHelloEmptyID")
}

func (s *Suite) TestMalformedHelloLongID(t *utesting.T) {
	t.Log(`This test sends a hello with an overly long peer id and expects a disconnect.`)
	s.runMalformedHelloNamedCase(t, "MalformedHelloLongID")
}

func (s *Suite) TestMalformedHelloZeroID(t *utesting.T) {
	t.Log(`This test sends a hello with an all-zero peer id and expects a disconnect.`)
	s.runMalformedHelloNamedCase(t, "MalformedHelloZeroID")
}

func (s *Suite) TestMalformedHelloMismatchedID(t *utesting.T) {
	t.Log(`This test sends a hello with a non-zero but mismatched peer id and expects a disconnect.`)
	s.runMalformedHelloNamedCase(t, "MalformedHelloMismatchedID")
}

func (s *Suite) TestHelloWithoutEthCap(t *utesting.T) {
	t.Log(`This test sends a hello that omits eth capability and expects a disconnect.`)
	s.runMalformedHelloNamedCase(t, "HelloWithoutEthCap")
}

func (s *Suite) TestHelloWithZeroVersion(t *utesting.T) {
	t.Log(`This test sends a hello with protocol version zero and expects a disconnect.`)
	s.runMalformedHelloNamedCase(t, "HelloWithZeroVersion")
}

func (s *Suite) TestHelloWithMaxVersion(t *utesting.T) {
	t.Log(`This test sends a hello with max uint64 version and expects a disconnect.`)
	s.runMalformedHelloNamedCase(t, "HelloWithMaxVersion")
}

func (s *Suite) TestHelloWithZeroVersionAndEmptyCaps(t *utesting.T) {
	t.Log(`This test sends a hello with zero version and empty capabilities and expects a disconnect.`)
	s.runMalformedHelloNamedCase(t, "HelloWithZeroVersionAndEmptyCaps")
}

func (s *Suite) TestHelloWithEmptyCaps(t *utesting.T) {
	t.Log(`This test sends a hello with empty capabilities and expects a disconnect.`)
	s.runMalformedHelloNamedCase(t, "HelloWithEmptyCaps")
}

func (s *Suite) TestHelloWithEmptyCapName(t *utesting.T) {
	t.Log(`This test sends a hello with an empty capability name and expects a disconnect.`)
	s.runMalformedHelloNamedCase(t, "HelloWithEmptyCapName")
}

func (s *Suite) TestHelloWithLongCapName(t *utesting.T) {
	t.Log(`This test sends a hello with an overly long capability name and expects a disconnect.`)
	s.runMalformedHelloNamedCase(t, "HelloWithLongCapName")
}

func (s *Suite) TestHelloWithNULCapName(t *utesting.T) {
	t.Log(`This test sends a hello with a NUL byte in capability name and expects a disconnect.`)
	s.runMalformedHelloNamedCase(t, "HelloWithNULCapName")
}

func (s *Suite) TestHelloWithMismatchedIDAndEmptyCaps(t *utesting.T) {
	t.Log(`This test sends a hello with mismatched id and empty capabilities and expects a disconnect.`)
	s.runMalformedHelloNamedCase(t, "HelloWithMismatchedIDAndEmptyCaps")
}

func (s *Suite) TestHelloWithUnsortedNonEthCaps(t *utesting.T) {
	t.Log(`This test sends a hello with unsorted non-eth capabilities and expects a disconnect.`)
	s.runMalformedHelloNamedCase(t, "HelloWithUnsortedNonEthCaps")
}

func (s *Suite) TestOversizedHelloPayload(t *utesting.T) {
	t.Log(`This test sends an oversized hello payload and expects a disconnect.`)
	s.withRLPxConn(t, func(conn *rlpx.Conn) {
		// p2p readProtocolHandshake enforces a 2KB max size for hello.
		oversized := make([]byte, 2049)
		s.expectDisconnectAfterHelloPayload(t, conn, oversized)
	})
}

func (s *Suite) TestWrongFirstMessageCode(t *utesting.T) {
	t.Log(`This test sends a non-handshake first message code and expects a disconnect.`)
	s.withRLPxConn(t, func(conn *rlpx.Conn) {
		// The first post-RLPx message must be handshakeMsg.
		s.expectDisconnectAfterMessage(t, conn, pingMsg, []byte{})
	})
}

func (s *Suite) TestFirstMessageDisconnect(t *utesting.T) {
	t.Log(`This test sends a disconnect as first post-RLPx message and expects disconnect handling.`)
	s.withRLPxConn(t, func(conn *rlpx.Conn) {
		reasonPayload, err := rlp.EncodeToBytes([1]p2p.DiscReason{p2p.DiscRequested})
		if err != nil {
			t.Fatalf("failed to encode disconnect reason: %v", err)
		}
		s.expectDisconnectAfterMessage(t, conn, discMsg, reasonPayload)
	})
}

func (s *Suite) TestFirstMessageDisconnectInvalidPayload(t *utesting.T) {
	t.Log(`This test sends a disconnect with invalid reason payload and expects disconnect handling.`)
	s.withRLPxConn(t, func(conn *rlpx.Conn) {
		// Invalid RLP for [1]DiscReason decoding path on receiver side.
		s.expectDisconnectAfterMessage(t, conn, discMsg, []byte{0xff})
	})
}

func (s *Suite) TestFirstMessageDisconnectEmptyPayload(t *utesting.T) {
	t.Log(`This test sends a disconnect with empty payload and expects disconnect handling.`)
	s.withRLPxConn(t, func(conn *rlpx.Conn) {
		// Empty payload should fail disconnect-reason decoding on receiver side.
		s.expectDisconnectAfterMessage(t, conn, discMsg, []byte{})
	})
}

func (s *Suite) TestEmptyHelloPayload(t *utesting.T) {
	t.Log(`This test sends an empty hello payload and expects a disconnect.`)
	s.withRLPxConn(t, func(conn *rlpx.Conn) {
		s.expectDisconnectAfterHelloPayload(t, conn, []byte{})
	})
}

func (s *Suite) TestTruncatedHelloPayload(t *utesting.T) {
	t.Log(`This test sends a truncated hello RLP payload and expects a disconnect.`)
	s.withRLPxConn(t, func(conn *rlpx.Conn) {
		// List length prefix (1 byte) without element content.
		s.expectDisconnectAfterHelloPayload(t, conn, []byte{0xc1})
	})
}

func (s *Suite) TestInvalidHelloRLP(t *utesting.T) {
	t.Log(`This test sends invalid hello RLP bytes and expects a disconnect.`)
	s.withRLPxConn(t, func(conn *rlpx.Conn) {
		s.expectDisconnectAfterHelloPayload(t, conn, []byte{0xff})
	})
}

func (s *Suite) TestHelloPayloadWrongRLPType(t *utesting.T) {
	t.Log(`This test sends hello payload with wrong RLP type and expects a disconnect.`)
	s.withRLPxConn(t, func(conn *rlpx.Conn) {
		// RLP empty string, while hello expects a list/struct payload.
		s.expectDisconnectAfterHelloPayload(t, conn, []byte{0x80})
	})
}

func (s *Suite) TestHelloPayloadEmptyList(t *utesting.T) {
	t.Log(`This test sends hello payload as an empty RLP list and expects a disconnect.`)
	s.withRLPxConn(t, func(conn *rlpx.Conn) {
		// RLP empty list. Decoded hello has zero-value fields and invalid identity.
		s.expectDisconnectAfterHelloPayload(t, conn, []byte{0xc0})
	})
}

func (s *Suite) TestHelloPayloadShortList(t *utesting.T) {
	t.Log(`This test sends hello payload as a short RLP list and expects a disconnect.`)
	s.withRLPxConn(t, func(conn *rlpx.Conn) {
		// RLP list with a single element (version only), missing required hello fields.
		s.expectDisconnectAfterHelloPayload(t, conn, []byte{0xc1, 0x05})
	})
}

func (s *Suite) TestHelloPayloadVersionWrongType(t *utesting.T) {
	t.Log(`This test sends hello payload with wrong version field type and expects a disconnect.`)
	s.withRLPxConn(t, func(conn *rlpx.Conn) {
		// RLP list with one element: empty list, but hello version expects uint.
		s.expectDisconnectAfterHelloPayload(t, conn, []byte{0xc1, 0xc0})
	})
}

func (s *Suite) TestHelloWithDuplicateEthCaps(t *utesting.T) {
	t.Log(`This test sends a hello with duplicate eth capabilities and expects a disconnect.`)
	s.runMalformedHelloNamedCase(t, "HelloWithDuplicateEthCaps")
}

func malformedHelloByCase(name string, pub0 []byte) *protoHandshake {
	base := &protoHandshake{
		Version: 5,
		Caps:    []p2p.Cap{{Name: "eth", Version: 63}},
		ID:      pub0,
	}
	builders := map[string]func() *protoHandshake{
		"MalformedHello": func() *protoHandshake {
			cpy := append([]byte(nil), pub0...)
			return &protoHandshake{Version: base.Version, Caps: base.Caps, ID: append(cpy, byte(0))}
		},
		"MalformedHelloShortID": func() *protoHandshake {
			return &protoHandshake{Version: base.Version, Caps: base.Caps, ID: pub0[:63]}
		},
		"MalformedHelloEmptyID": func() *protoHandshake {
			return &protoHandshake{Version: base.Version, Caps: base.Caps, ID: nil}
		},
		"MalformedHelloLongID": func() *protoHandshake {
			longID := make([]byte, 128)
			copy(longID, pub0)
			return &protoHandshake{Version: base.Version, Caps: base.Caps, ID: longID}
		},
		"MalformedHelloZeroID": func() *protoHandshake {
			return &protoHandshake{Version: base.Version, Caps: base.Caps, ID: make([]byte, 64)}
		},
		"MalformedHelloMismatchedID": func() *protoHandshake {
			mismatch := append([]byte(nil), pub0...)
			mismatch[0] ^= 0x01
			return &protoHandshake{Version: base.Version, Caps: base.Caps, ID: mismatch}
		},
		"HelloWithoutEthCap": func() *protoHandshake {
			return &protoHandshake{Version: base.Version, Caps: []p2p.Cap{{Name: "les", Version: 2}}, ID: base.ID}
		},
		"HelloWithZeroVersion": func() *protoHandshake {
			return &protoHandshake{Version: 0, Caps: base.Caps, ID: base.ID}
		},
		"HelloWithMaxVersion": func() *protoHandshake {
			return &protoHandshake{Version: ^uint64(0), Caps: base.Caps, ID: base.ID}
		},
		"HelloWithZeroVersionAndEmptyCaps": func() *protoHandshake {
			return &protoHandshake{Version: 0, Caps: []p2p.Cap{}, ID: base.ID}
		},
		"HelloWithEmptyCaps": func() *protoHandshake {
			return &protoHandshake{Version: base.Version, Caps: []p2p.Cap{}, ID: base.ID}
		},
		"HelloWithEmptyCapName": func() *protoHandshake {
			return &protoHandshake{Version: base.Version, Caps: []p2p.Cap{{Name: "", Version: 63}}, ID: base.ID}
		},
		"HelloWithLongCapName": func() *protoHandshake {
			return &protoHandshake{Version: base.Version, Caps: []p2p.Cap{{Name: strings.Repeat("x", 512), Version: 1}}, ID: base.ID}
		},
		"HelloWithNULCapName": func() *protoHandshake {
			return &protoHandshake{Version: base.Version, Caps: []p2p.Cap{{Name: "et\x00h", Version: 63}}, ID: base.ID}
		},
		"HelloWithMismatchedIDAndEmptyCaps": func() *protoHandshake {
			mismatch := append([]byte(nil), pub0...)
			mismatch[0] ^= 0x01
			return &protoHandshake{Version: base.Version, Caps: []p2p.Cap{}, ID: mismatch}
		},
		"HelloWithUnsortedNonEthCaps": func() *protoHandshake {
			return &protoHandshake{
				Version: base.Version,
				Caps: []p2p.Cap{
					{Name: "zzz", Version: 2},
					{Name: "les", Version: 1},
				},
				ID: base.ID,
			}
		},
		"HelloWithDuplicateEthCaps": func() *protoHandshake {
			return &protoHandshake{
				Version: base.Version,
				Caps: []p2p.Cap{
					{Name: "eth", Version: 63},
					{Name: "eth", Version: 63},
				},
				ID: base.ID,
			}
		},
	}
	if builder, ok := builders[name]; ok {
		return builder()
	}
	panic("unknown malformed hello case: " + name)
}

func (s *Suite) runMalformedHelloNamedCase(t *utesting.T, caseName string) {
	s.withRLPxConnAndKey(t, func(conn *rlpx.Conn, key *ecdsa.PrivateKey) {
		pub0 := crypto.FromECDSAPub(&key.PublicKey)[1:]
		s.expectDisconnectAfterHello(t, conn, malformedHelloByCase(caseName, pub0))
	})
}

func (s *Suite) withRLPxConn(t *utesting.T, fn func(conn *rlpx.Conn)) {
	s.withRLPxConnAndKey(t, func(conn *rlpx.Conn, _ *ecdsa.PrivateKey) {
		fn(conn)
	})
}

func (s *Suite) withRLPxConnAndKey(t *utesting.T, fn func(conn *rlpx.Conn, key *ecdsa.PrivateKey)) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	conn, err := s.dialConn(key)
	if err != nil {
		t.Fatalf("rlpx handshake failed: %v", err)
	}
	defer conn.Close()
	fn(conn, key)
}

func (s *Suite) expectDisconnectAfterHello(t *utesting.T, conn *rlpx.Conn, hello *protoHandshake) {
	payload, err := rlp.EncodeToBytes(hello)
	if err != nil {
		t.Fatalf("failed to encode malformed hello: %v", err)
	}
	s.expectDisconnectAfterHelloPayload(t, conn, payload)
}

func (s *Suite) expectDisconnectAfterHelloPayload(t *utesting.T, conn *rlpx.Conn, payload []byte) {
	s.expectDisconnectAfterMessage(t, conn, handshakeMsg, payload)
}

func (s *Suite) expectDisconnectAfterMessage(t *utesting.T, conn *rlpx.Conn, code uint64, payload []byte) {
	if _, err := conn.Write(code, payload); err != nil {
		t.Fatalf("failed to write test message: %v", err)
	}

	conn.SetReadDeadline(time.Now().Add(handshakeTimeout))
	code, _, _, err := conn.Read()
	if err != nil {
		return
	}
	if code == discMsg {
		return
	}
	t.Fatalf("expected disconnect after test message, got msg code %d", code)
}

func (s *Suite) dialConn(key *ecdsa.PrivateKey) (*rlpx.Conn, error) {
	tcpEndpoint, ok := s.Dest.TCPEndpoint()
	if !ok {
		return nil, fmt.Errorf("node has no TCP endpoint")
	}
	fd, err := net.DialTimeout("tcp", tcpEndpoint.String(), handshakeTimeout)
	if err != nil {
		return nil, err
	}

	conn := rlpx.NewConn(fd, s.Dest.Pubkey())
	_, err = conn.Handshake(key)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

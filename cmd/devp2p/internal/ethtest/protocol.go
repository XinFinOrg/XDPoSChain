// Copyright 2023 The go-ethereum Authors
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
	"github.com/XinFinOrg/XDPoSChain/p2p"
	"github.com/XinFinOrg/XDPoSChain/rlp"
)

// Unexported devp2p message codes from p2p/peer.go.
const (
	handshakeMsg = 0x00
	discMsg      = 0x01
	pingMsg      = 0x02
	pongMsg      = 0x03
)

// Unexported devp2p protocol lengths from p2p package.
//
// These are a second copy of wire facts that the node also states in
// eth/protocols/eth. A standalone client deliberately does not import the node's
// tables, but the copies have drifted: ProtocolLengths in the wire layer is the
// message-code space bound (230/227/227), while ethProtoLen here is the number of
// messages the suites actually read. getProto() panics on any frame code that
// falls outside the ranges built from these lengths, and the XDC BFT codes
// (0xe0-0xe2) and the pooled transaction trio (0xe3-0xe5) frame to 240-245, well
// past ethProtoLen's 16+18=34. Nothing breaks today because the live-node suites
// never run in CI and the decode tests bypass getProto, but a node on xdc/100+
// that sends a vote to this client would trip the panic. The values are kept as
// they are: changing them is a behaviour change for the suite, tracked
// separately.
const (
	baseProtoLen = 16
	ethProtoLen  = 18
	// snapProtoLen accommodates snap/2 (EIP-8189) which extends snap/1 with two
	// additional message codes (GetBlockAccessLists=0x08, BlockAccessLists=0x09).
	// Using 10 is safe for snap/1 connections because the extra codes are simply
	// never used on that protocol version.
	snapProtoLen = 10
)

// Unexported handshake structure from p2p/peer.go.
type protoHandshake struct {
	Version    uint64
	Name       string
	Caps       []p2p.Cap
	ListenPort uint64
	ID         []byte
	Rest       []rlp.RawValue `rlp:"tail"`
}

type Hello = protoHandshake

// Proto is an enum representing devp2p protocol types.
type Proto int

const (
	baseProto Proto = iota
	ethProto
	snapProto
)

// getProto returns the protocol a certain message code is associated with
// (assuming the negotiated capabilities are exactly {eth,snap})
func getProto(code uint64) Proto {
	switch {
	case code < baseProtoLen:
		return baseProto
	case code < baseProtoLen+ethProtoLen:
		return ethProto
	case code < baseProtoLen+ethProtoLen+snapProtoLen:
		return snapProto
	default:
		panic("unhandled msg code beyond last protocol")
	}
}

// protoOffset will return the offset at which the specified protocol's messages
// begin.
func protoOffset(proto Proto) uint64 {
	switch proto {
	case baseProto:
		return 0
	case ethProto:
		return baseProtoLen
	case snapProto:
		return baseProtoLen + ethProtoLen
	default:
		panic("unhandled protocol")
	}
}

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
	"math/big"
	"sync/atomic"
	"time"

	ethproto "github.com/XinFinOrg/XDPoSChain/eth/protocols/eth"
)

// PeerInfo represents a short summary of the Ethereum sub-protocol metadata known
// about a connected peer.
type PeerInfo struct {
	Version    int      `json:"version"`    // Ethereum protocol version negotiated
	Difficulty *big.Int `json:"difficulty"` // Total difficulty of the peer's blockchain
	Head       string   `json:"head"`       // SHA3 hash of the peer's best owned block
}

// peer is the node layer's handle on a wire peer: the wire state plus the
// bookkeeping the node layer keeps on top of it. Everything the wire layer owns
// (sending, marking, the known sets, the handshake) is promoted from the
// embedded peer.
type peer struct {
	*ethproto.Peer

	forkDrop *time.Timer // Timed connection dropper if forks aren't validated in time

	// removed is set exactly once to make peer removal idempotent.
	removed atomic.Bool
}

// Info gathers and returns a collection of metadata known about a peer.
func (p *peer) Info() *PeerInfo {
	hash, td := p.Head()

	return &PeerInfo{
		Version:    int(p.Version()),
		Difficulty: td,
		Head:       hash.Hex(),
	}
}

// markRemoved claims the peer's removal, returning true only for the first
// caller so the unregister sequence runs exactly once per peer.
func (p *peer) markRemoved() bool {
	return !p.removed.Swap(true)
}

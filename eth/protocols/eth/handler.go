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
	"fmt"
	"time"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/metrics"
	"github.com/XinFinOrg/XDPoSChain/p2p"
	"github.com/XinFinOrg/XDPoSChain/p2p/enode"
	"github.com/XinFinOrg/XDPoSChain/p2p/enr"
)

func errResp(code errCode, format string, v ...interface{}) error {
	return fmt.Errorf("%v - %v", code, fmt.Sprintf(format, v...))
}

// TxPool defines the part of a transaction pool implementation the wire layer
// needs to answer transaction retrieval requests from remote peers.
type TxPool interface {
	// Get retrieves the transaction from the local txpool with the given hash.
	Get(hash common.Hash) *types.Transaction
}

// Handler is the callback through which the node layer runs a peer's inbound
// message loop once the handshake is complete.
type Handler func(peer *Peer) error

// Backend interface provides the common API services (that are provided by
// both full and light clients) with access to necessary functions.
//
// The wire layer cannot import the node layer that embeds it (that would be an
// import cycle), so everything it needs from the node arrives through this
// interface. It is the single seam of the split.
type Backend interface {
	// Chain retrieves the blockchain object to depend on.
	Chain() *core.BlockChain

	// TxPool retrieves the transaction pool object to depend on.
	TxPool() TxPool

	// AcceptTxs reports whether the node is synchronised enough to process
	// inbound transaction traffic at all.
	AcceptTxs() bool

	// RunPeer is invoked when a peer joins on the `eth` protocol. The handler is
	// the inbound message dispatcher the node layer wants the peer to run after
	// its own peer bookkeeping is done.
	RunPeer(peer *Peer, handler Handler) error

	// Handle is invoked from within a peer's message loop with every inbound
	// packet the wire layer decoded but does not act on itself. Size is the wire
	// size of the message.
	Handle(peer *Peer, packet Packet, size uint32) error

	// NodeInfo retrieves the local node's metadata for protocol registration.
	NodeInfo() interface{}

	// PeerInfo retrieves the metadata of the peer with the given id for protocol
	// registration.
	PeerInfo(id enode.ID) interface{}
}

// MakeProtocols constructs the P2P protocol definitions for `eth`.
func MakeProtocols(backend Backend) []p2p.Protocol {
	protocols := make([]p2p.Protocol, len(ProtocolVersions))
	for i, version := range ProtocolVersions {
		length, ok := ProtocolLengths[version]
		if !ok {
			panic(fmt.Sprintf("makeProtocol for unknown version %d", version))
		}
		protocols[i] = p2p.Protocol{
			Name:    ProtocolName,
			Version: version,
			Length:  length,
			Run: func(p *p2p.Peer, rw p2p.MsgReadWriter) error {
				peer := NewPeer(version, p, rw, backend.TxPool().Get)
				defer peer.Close()

				return backend.RunPeer(peer, func(peer *Peer) error {
					return Handle(backend, peer)
				})
			},
			NodeInfo: func() interface{} {
				return backend.NodeInfo()
			},
			PeerInfo: func(id enode.ID) interface{} {
				return backend.PeerInfo(id)
			},
			Attributes: []enr.Entry{currentENREntry(backend.Chain())},
		}
	}
	return protocols
}

// Handle is the callback invoked to manage the inbound message flow of an `eth`
// peer. When this function terminates, the peer is disconnected.
func Handle(backend Backend, peer *Peer) error {
	// Handle incoming messages until the connection is torn down
	for {
		if err := handleMessage(backend, peer); err != nil {
			peer.Log().Debug("Ethereum message handling failed", "err", err)
			return err
		}
	}
}

// handlersFor returns the handler table of the negotiated protocol version. The
// comparisons are ordered newest first so a future version inherits the newest
// table instead of falling back to the legacy one.
func handlersFor(version uint) map[uint64]msgHandler {
	switch {
	case version >= XDC166:
		return eth166
	case version >= XDC165:
		return eth165
	default:
		return eth100
	}
}

// handleMessage is invoked whenever an inbound message is received from a remote
// peer. The remote connection is torn down upon returning any error.
func handleMessage(backend Backend, peer *Peer) error {
	// Read the next message from the remote peer, and ensure it's fully consumed
	msg, err := peer.rw.ReadMsg()
	if err != nil {
		return err
	}
	if msg.Size > protocolMaxMsgSize {
		return errResp(ErrMsgTooLarge, "%v > %v", msg.Size, protocolMaxMsgSize)
	}
	defer msg.Discard()

	// Track the amount of time it takes to serve the request and run the handler
	if metrics.Enabled() {
		h := fmt.Sprintf("%s/%s/%d/%#02x", p2p.HandleHistName, ProtocolName, peer.Version(), msg.Code)
		defer func(start time.Time) {
			sampler := func() metrics.Sample {
				return metrics.ResettingSample(
					metrics.NewExpDecaySample(1028, 0.015),
				)
			}
			metrics.GetOrRegisterHistogramLazy(h, nil, sampler).Update(time.Since(start).Microseconds())
		}(time.Now())
	}

	// Handle the message depending on its contents
	if handler := handlersFor(peer.version)[msg.Code]; handler != nil {
		return handler(backend, msg, peer)
	}
	return errResp(ErrInvalidMsgCode, "%v", msg.Code)
}

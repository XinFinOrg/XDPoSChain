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
	"encoding/json"
	"fmt"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/log"
	"github.com/XinFinOrg/XDPoSChain/p2p"
	"github.com/XinFinOrg/XDPoSChain/p2p/enode"
	"github.com/XinFinOrg/XDPoSChain/p2p/enr"
	"github.com/XinFinOrg/XDPoSChain/rlp"
)

const (
	softResponseLimit = 2 * 1024 * 1024 // Target maximum size of returned blocks, headers or node data.
	estHeaderRlpSize  = 500             // Approximate size of an RLP encoded block header

	// maxHeadersServe is the maximum number of block headers to serve. It bounds
	// the chain lookups a single query may cost; the reply payload is capped by
	// softResponseLimit instead.
	maxHeadersServe = 192

	// maxBodiesServe is the maximum number of block bodies to serve. This number
	// is there to limit the number of disk lookups, the payload itself being
	// capped by softResponseLimit.
	maxBodiesServe = 128

	// maxNodeDataServe is the maximum number of state trie nodes to serve. It
	// bounds the number of database lookups; the reply payload is capped by
	// softResponseLimit.
	maxNodeDataServe = 384

	// maxReceiptsServe is the maximum number of block receipts to serve. This
	// number is there to limit the number of disk lookups, the payload itself
	// being capped by softResponseLimit.
	maxReceiptsServe = 256

	// maxPooledTransactionsServe is the maximum number of pooled transactions to
	// serve. It is a backstop above what softResponseLimit allows for transactions
	// of a realistic size: every hash in the request costs a pool lookup, served
	// or not.
	maxPooledTransactionsServe = 4096
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

	// Handle the message depending on its contents
	switch {
	case msg.Code == StatusMsg:
		// Status messages should never arrive after the handshake
		return errResp(ErrExtraStatusMsg, "uncontrolled status message")

		// Block header query, collect the requested headers and reply
	case msg.Code == GetBlockHeadersMsg:
		// Decode the complex header query
		var query GetBlockHeadersPacket
		if err := msg.Decode(&query); err != nil {
			return errResp(ErrDecode, "%v: %v", msg, err)
		}
		hashMode := query.Origin.Hash != (common.Hash{})
		first := true
		maxNonCanonical := uint64(100)

		// Gather headers until the fetch or network limits is reached
		var (
			bytes   common.StorageSize
			headers []*types.Header
			unknown bool
			lookups int
		)
		for !unknown && len(headers) < int(query.Amount) && bytes < softResponseLimit &&
			len(headers) < maxHeadersServe && lookups < 2*maxHeadersServe {
			lookups++
			// Retrieve the next header satisfying the query
			var origin *types.Header
			if hashMode {
				if first {
					first = false
					origin = backend.Chain().GetHeaderByHash(query.Origin.Hash)
					if origin != nil {
						query.Origin.Number = origin.Number.Uint64()
					}
				} else {
					origin = backend.Chain().GetHeader(query.Origin.Hash, query.Origin.Number)
				}
			} else {
				origin = backend.Chain().GetHeaderByNumber(query.Origin.Number)
			}
			if origin == nil {
				break
			}
			headers = append(headers, origin)
			bytes += estHeaderRlpSize

			// Advance to the next header of the query
			switch {
			case hashMode && query.Reverse:
				// Hash based traversal towards the genesis block
				ancestor := query.Skip + 1
				if ancestor == 0 {
					unknown = true
				} else {
					query.Origin.Hash, query.Origin.Number = backend.Chain().GetAncestor(query.Origin.Hash, query.Origin.Number, ancestor, &maxNonCanonical)
					unknown = query.Origin.Hash == (common.Hash{})
				}
			case hashMode && !query.Reverse:
				// Hash based traversal towards the leaf block
				var (
					current = origin.Number.Uint64()
					next    = current + query.Skip + 1
				)
				if next <= current {
					infos, _ := json.MarshalIndent(peer.Peer.Info(), "", "  ")
					peer.Log().Warn("GetBlockHeaders skip overflow attack", "current", current, "skip", query.Skip, "next", next, "attacker", infos)
					unknown = true
				} else {
					if header := backend.Chain().GetHeaderByNumber(next); header != nil {
						nextHash := header.Hash()
						expOldHash, _ := backend.Chain().GetAncestor(nextHash, next, query.Skip+1, &maxNonCanonical)
						if expOldHash == query.Origin.Hash {
							query.Origin.Hash, query.Origin.Number = nextHash, next
						} else {
							unknown = true
						}
					} else {
						unknown = true
					}
				}
			case query.Reverse:
				// Number based traversal towards the genesis block
				if query.Origin.Number >= query.Skip+1 {
					query.Origin.Number -= query.Skip + 1
				} else {
					unknown = true
				}

			case !query.Reverse:
				// Number based traversal towards the leaf block
				query.Origin.Number += query.Skip + 1
			}
		}
		return peer.SendBlockHeaders(headers)

	case msg.Code == BlockHeadersMsg:
		// A batch of headers arrived to one of our previous requests
		var headers BlockHeadersPacket
		if err := msg.Decode(&headers); err != nil {
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}
		return backend.Handle(peer, &headers, msg.Size)

	case msg.Code == GetBlockBodiesMsg:
		// Decode the block body retrieval message
		var query GetBlockBodiesPacket
		if err := msg.Decode(&query); err != nil {
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}
		// Gather blocks until the fetch or network limits is reached
		var (
			bytes  int
			bodies []rlp.RawValue
		)
		for lookups, hash := range query {
			if bytes >= softResponseLimit || len(bodies) >= maxBodiesServe || lookups >= 2*maxBodiesServe {
				break
			}
			// Retrieve the requested block body, skipping if unknown to us
			if data := backend.Chain().GetBodyRLP(hash); len(data) != 0 {
				bodies = append(bodies, data)
				bytes += len(data)
			}
		}
		return peer.SendBlockBodiesRLP(bodies)

	case msg.Code == BlockBodiesMsg:
		// A batch of block bodies arrived to one of our previous requests
		var request BlockBodiesPacket
		if err := msg.Decode(&request); err != nil {
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}
		return backend.Handle(peer, &request, msg.Size)

	case peer.version >= XDC100 && msg.Code == GetNodeDataMsg:
		// Decode the trie node data retrieval message
		var query GetNodeDataPacket
		if err := msg.Decode(&query); err != nil {
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}
		// Gather state data until the fetch or network limits is reached
		var (
			bytes int
			data  [][]byte
		)
		for lookups, hash := range query {
			if bytes >= softResponseLimit || len(data) >= maxNodeDataServe || lookups >= 2*maxNodeDataServe {
				break
			}
			// Retrieve the requested state entry, skipping if unknown to us
			// todo now the code and trienode is mixed in the protocol level,
			// separate these two types.
			entry, err := backend.Chain().TrieNode(hash)
			if len(entry) == 0 || err != nil {
				// Read the contract code with prefix only to save unnecessary lookups.
				entry, err = backend.Chain().ContractCodeWithPrefix(hash)
			}
			if err == nil && len(entry) > 0 {
				data = append(data, entry)
				bytes += len(entry)
			}
		}
		return peer.SendNodeData(data)

	case peer.version >= XDC100 && msg.Code == NodeDataMsg:
		// A batch of node state data arrived to one of our previous requests
		var data NodeDataPacket
		if err := msg.Decode(&data); err != nil {
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}
		return backend.Handle(peer, &data, msg.Size)

	case peer.version >= XDC100 && msg.Code == GetReceiptsMsg:
		// Decode the block receipts retrieval message
		var query GetReceiptsPacket
		if err := msg.Decode(&query); err != nil {
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}
		// Gather state data until the fetch or network limits is reached
		var (
			bytes    int
			receipts []rlp.RawValue
		)
		for lookups, hash := range query {
			if bytes >= softResponseLimit || len(receipts) >= maxReceiptsServe || lookups >= 2*maxReceiptsServe {
				break
			}
			// Retrieve the requested block's receipts, skipping if unknown to us
			results := backend.Chain().GetReceiptsByHash(hash)
			if results == nil {
				if header := backend.Chain().GetHeaderByHash(hash); header == nil || header.ReceiptHash != types.EmptyRootHash {
					continue
				}
			}
			// If known, encode and queue for response packet
			if encoded, err := rlp.EncodeToBytes(results); err != nil {
				log.Error("Failed to encode receipt", "err", err)
			} else {
				receipts = append(receipts, encoded)
				bytes += len(encoded)
			}
		}
		return peer.SendReceiptsRLP(receipts)

	case peer.version >= XDC100 && msg.Code == ReceiptsMsg:
		// A batch of receipts arrived to one of our previous requests
		var receipts ReceiptsPacket
		if err := msg.Decode(&receipts); err != nil {
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}
		return backend.Handle(peer, &receipts, msg.Size)

	case msg.Code == NewBlockHashesMsg:
		var announces NewBlockHashesPacket
		if err := msg.Decode(&announces); err != nil {
			return errResp(ErrDecode, "%v: %v", msg, err)
		}
		return backend.Handle(peer, &announces, msg.Size)

	case msg.Code == NewBlockMsg:
		// Retrieve and decode the propagated block
		var request NewBlockPacket
		if err := msg.Decode(&request); err != nil {
			return errResp(ErrDecode, "%v: %v", msg, err)
		}
		// Stamp the block with the transport facts: when the frame arrived and,
		// later on, which peer it came from.
		request.Block.ReceivedAt = msg.ReceivedAt
		return backend.Handle(peer, &request, msg.Size)

	case msg.Code == NewPooledTransactionHashesMsg && peer.version >= XDC165:
		// Transaction announcements are only acted on once the node is synchronised
		if !backend.AcceptTxs() {
			return nil
		}
		var hashes NewPooledTransactionHashesPacket
		if err := msg.Decode(&hashes); err != nil {
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}
		return backend.Handle(peer, &hashes, msg.Size)

	case msg.Code == GetPooledTransactionsMsg && peer.version >= XDC165:
		// Decode the pooled transactions retrieval message
		var query GetPooledTransactionsPacket
		if err := msg.Decode(&query); err != nil {
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}
		// Gather transactions until the fetch or network limits is reached
		var (
			bytes  int
			hashes []common.Hash
			txs    []rlp.RawValue
		)
		for lookups, hash := range query {
			if bytes >= softResponseLimit || len(hashes) >= maxPooledTransactionsServe || lookups >= 2*maxPooledTransactionsServe {
				break
			}
			// Retrieve the requested transaction, skipping if unknown to us
			tx := backend.TxPool().Get(hash)
			if tx == nil {
				continue
			}
			// If known, encode and queue for response packet
			if encoded, err := rlp.EncodeToBytes(tx); err != nil {
				log.Error("Failed to encode transaction", "err", err)
			} else {
				hashes = append(hashes, hash)
				txs = append(txs, encoded)
				bytes += len(encoded)
			}
		}
		return peer.SendPooledTransactionsRLP(hashes, txs)

	case msg.Code == TransactionMsg:
		// Transactions arrived, make sure we have a valid and fresh chain to handle them
		if !backend.AcceptTxs() {
			return nil
		}
		var txs TransactionsPacket
		if err := msg.Decode(&txs); err != nil {
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}
		if err := txs.sanityCheck(); err != nil {
			return errResp(ErrDecode, "%v", err)
		}
		return backend.Handle(peer, &txs, msg.Size)

	case msg.Code == PooledTransactionsMsg && peer.version >= XDC165:
		// Transactions arrived, make sure we have a valid and fresh chain to handle them
		if !backend.AcceptTxs() {
			return nil
		}
		var txs PooledTransactionsPacket
		if err := msg.Decode(&txs); err != nil {
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}
		if err := txs.sanityCheck(); err != nil {
			return errResp(ErrDecode, "%v", err)
		}
		return backend.Handle(peer, &txs, msg.Size)

	case msg.Code == OrderTxMsg:
		// Transactions arrived, make sure we have a valid and fresh chain to handle them
		if !backend.AcceptTxs() {
			return nil
		}
		var txs OrderTransactionsPacket
		if err := msg.Decode(&txs); err != nil {
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}
		if err := txs.sanityCheck(); err != nil {
			return errResp(ErrDecode, "%v", err)
		}
		return backend.Handle(peer, &txs, msg.Size)

	case msg.Code == LendingTxMsg:
		// Transactions arrived, make sure we have a valid and fresh chain to handle them
		if !backend.AcceptTxs() {
			return nil
		}
		var txs LendingTransactionsPacket
		if err := msg.Decode(&txs); err != nil {
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}
		if err := txs.sanityCheck(); err != nil {
			return errResp(ErrDecode, "%v", err)
		}
		return backend.Handle(peer, &txs, msg.Size)

	case msg.Code == VoteMsg:
		var vote VotePacket
		if err := msg.Decode(&vote); err != nil {
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}
		return backend.Handle(peer, &vote, msg.Size)

	case msg.Code == TimeoutMsg:
		var timeout TimeoutPacket
		if err := msg.Decode(&timeout); err != nil {
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}
		return backend.Handle(peer, &timeout, msg.Size)

	case msg.Code == SyncInfoMsg:
		var syncInfo SyncInfoPacket
		if err := msg.Decode(&syncInfo); err != nil {
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}
		return backend.Handle(peer, &syncInfo, msg.Size)

	default:
		return errResp(ErrInvalidMsgCode, "%v", msg.Code)
	}
}

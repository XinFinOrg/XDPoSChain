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
	"time"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/log"
	"github.com/XinFinOrg/XDPoSChain/p2p"
	"github.com/XinFinOrg/XDPoSChain/rlp"
	"github.com/XinFinOrg/XDPoSChain/trie"
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

	// maxBlockHashesAnnounce is the per-message announcement cap. The fetcher
	// tracks at most hashLimit (256) per peer, so a larger batch buys no
	// retrieval, and exceeding the cap drops the peer as a protocol violation
	// (nodes announce one per message).
	maxBlockHashesAnnounce = 1024

	// maxAnnounceRLPSize is the worst-case wire cost of one announcement: list
	// header, 32-byte hash and 64-bit number.
	maxAnnounceRLPSize = 43

	// maxAnnounceFrameSize is maxBlockHashesAnnounce entries at the worst-case
	// size plus list header slack, so an over-cap frame fails before the RLP
	// decode.
	maxAnnounceFrameSize = maxBlockHashesAnnounce*maxAnnounceRLPSize + 8

	// maxAnnounceRate is the per-peer budget in announcements per second,
	// refilled into a bucket of maxAnnounceBurst; a node announces one hash per
	// block, so it sits far above honest traffic.
	maxAnnounceRate  = 256
	maxAnnounceBurst = maxBlockHashesAnnounce
)

// msgHandler serves one inbound message. The message is passed by value because
// the handlers need the transport facts p2p.Msg carries (Size, ReceivedAt) and
// its methods have value receivers.
type msgHandler func(backend Backend, msg p2p.Msg, peer *Peer) error

// eth100 serves xdc/100 and xdc/164: both advertise the same message codes.
var eth100 = map[uint64]msgHandler{
	StatusMsg:          handleStatus,
	NewBlockHashesMsg:  handleNewBlockHashes,
	TransactionMsg:     handleTransactions,
	GetBlockHeadersMsg: handleGetBlockHeaders,
	BlockHeadersMsg:    handleBlockHeaders,
	GetBlockBodiesMsg:  handleGetBlockBodies,
	BlockBodiesMsg:     handleBlockBodies,
	NewBlockMsg:        handleNewBlock,
	OrderTxMsg:         handleOrderTransactions,
	LendingTxMsg:       handleLendingTransactions,
	GetNodeDataMsg:     handleGetNodeData,
	NodeDataMsg:        handleNodeData,
	GetReceiptsMsg:     handleGetReceipts,
	ReceiptsMsg:        handleReceipts,
	VoteMsg:            handleVote,
	TimeoutMsg:         handleTimeout,
	SyncInfoMsg:        handleSyncInfo,
}

var eth165 = map[uint64]msgHandler{
	StatusMsg:          handleStatus,
	NewBlockHashesMsg:  handleNewBlockHashes,
	TransactionMsg:     handleTransactions,
	GetBlockHeadersMsg: handleGetBlockHeaders,
	BlockHeadersMsg:    handleBlockHeaders,
	GetBlockBodiesMsg:  handleGetBlockBodies,
	BlockBodiesMsg:     handleBlockBodies,
	NewBlockMsg:        handleNewBlock,
	OrderTxMsg:         handleOrderTransactions,
	LendingTxMsg:       handleLendingTransactions,
	GetNodeDataMsg:     handleGetNodeData,
	NodeDataMsg:        handleNodeData,
	GetReceiptsMsg:     handleGetReceipts,
	ReceiptsMsg:        handleReceipts,
	VoteMsg:            handleVote,
	TimeoutMsg:         handleTimeout,
	SyncInfoMsg:        handleSyncInfo,

	NewPooledTransactionHashesMsg: handleNewPooledTransactionHashes,
	GetPooledTransactionsMsg:      handleGetPooledTransactions,
	PooledTransactionsMsg:         handlePooledTransactions,
}

var eth166 = map[uint64]msgHandler{
	StatusMsg:         handleStatus,
	NewBlockHashesMsg: handleNewBlockHashes,
	TransactionMsg:    handleTransactions,
	NewBlockMsg:       handleNewBlock,
	OrderTxMsg:        handleOrderTransactions,
	LendingTxMsg:      handleLendingTransactions,
	VoteMsg:           handleVote,
	TimeoutMsg:        handleTimeout,
	SyncInfoMsg:       handleSyncInfo,

	NewPooledTransactionHashesMsg: handleNewPooledTransactionHashes,

	GetBlockHeadersMsg:       handleGetBlockHeaders66,
	BlockHeadersMsg:          handleBlockHeaders66,
	GetBlockBodiesMsg:        handleGetBlockBodies66,
	BlockBodiesMsg:           handleBlockBodies66,
	GetNodeDataMsg:           handleGetNodeData66,
	NodeDataMsg:              handleNodeData66,
	GetReceiptsMsg:           handleGetReceipts66,
	ReceiptsMsg:              handleReceipts66,
	GetPooledTransactionsMsg: handleGetPooledTransactions66,
	PooledTransactionsMsg:    handlePooledTransactions66,
}

func handleStatus(backend Backend, msg p2p.Msg, peer *Peer) error {
	// Status messages should never arrive after the handshake
	return errResp(ErrExtraStatusMsg, "uncontrolled status message")
}

func handleGetBlockHeaders(backend Backend, msg p2p.Msg, peer *Peer) error {
	// Decode the complex header query.
	var query GetBlockHeadersPacket
	if err := msg.Decode(&query); err != nil {
		return errResp(ErrDecode, "%v: %v", msg, err)
	}
	return peer.SendBlockHeaders(serviceBlockHeaders(backend, &query, peer))
}

// handleGetBlockHeaders66 serves a block header query over xdc/166: the request
// carries a request id that is echoed back verbatim on the response.
func handleGetBlockHeaders66(backend Backend, msg p2p.Msg, peer *Peer) error {
	// Decode the complex header query.
	var query GetBlockHeadersPacket166
	if err := msg.Decode(&query); err != nil {
		return errResp(ErrDecode, "%v: %v", msg, err)
	}
	return peer.ReplyBlockHeaders(query.RequestId, serviceBlockHeaders(backend, query.GetBlockHeadersPacket, peer))
}

// serviceBlockHeaders advances the query origin, so the caller must own it.
func serviceBlockHeaders(backend Backend, query *GetBlockHeadersPacket, peer *Peer) []*types.Header {
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
	return headers
}

// handleBlockHeaders delivers a batch of headers that arrived for one of our
// previous requests.
func handleBlockHeaders(backend Backend, msg p2p.Msg, peer *Peer) error {
	var headers BlockHeadersPacket
	if err := msg.Decode(&headers); err != nil {
		return errResp(ErrDecode, "msg %v: %v", msg, err)
	}
	return backend.Handle(peer, &headers, msg.Size)
}

func handleBlockHeaders66(backend Backend, msg p2p.Msg, peer *Peer) error {
	var res BlockHeadersPacket166
	if err := msg.Decode(&res); err != nil {
		return errResp(ErrDecode, "msg %v: %v", msg, err)
	}
	// The xdc/166 reply no longer reaches the node layer's Handle, so keep the
	// legacy header hardening on this path before the response is dispatched.
	if err := types.SanityCheckHeaders([]*types.Header(res.BlockHeadersPacket)); err != nil {
		return err
	}
	return peer.dispatchResponse(&Response{
		id:   res.RequestId,
		code: BlockHeadersMsg,
		Res:  &res.BlockHeadersPacket,
	})
}

func handleGetBlockBodies(backend Backend, msg p2p.Msg, peer *Peer) error {
	var query GetBlockBodiesPacket
	if err := msg.Decode(&query); err != nil {
		return errResp(ErrDecode, "msg %v: %v", msg, err)
	}
	return peer.SendBlockBodiesRLP(serviceBlockBodies(backend, query))
}

func handleGetBlockBodies66(backend Backend, msg p2p.Msg, peer *Peer) error {
	var query GetBlockBodiesPacket166
	if err := msg.Decode(&query); err != nil {
		return errResp(ErrDecode, "msg %v: %v", msg, err)
	}
	return peer.ReplyBlockBodiesRLP(query.RequestId, serviceBlockBodies(backend, query.GetBlockBodiesPacket))
}

func serviceBlockBodies(backend Backend, query GetBlockBodiesPacket) []rlp.RawValue {
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
	return bodies
}

// handleBlockBodies delivers a batch of block bodies that arrived for one of our
// previous requests.
func handleBlockBodies(backend Backend, msg p2p.Msg, peer *Peer) error {
	var request BlockBodiesPacket
	if err := msg.Decode(&request); err != nil {
		return errResp(ErrDecode, "msg %v: %v", msg, err)
	}
	if err := request.sanityCheck(); err != nil {
		return err
	}
	return backend.Handle(peer, &request, msg.Size)
}

func handleBlockBodies66(backend Backend, msg p2p.Msg, peer *Peer) error {
	var res BlockBodiesPacket166
	if err := msg.Decode(&res); err != nil {
		return errResp(ErrDecode, "msg %v: %v", msg, err)
	}
	// Keep the legacy hardening over xdc/166: the sanity check bounds
	// the uncle headers (e.g. the 20 KB Extra cap) before the backend
	// sees them.
	if err := res.BlockBodiesPacket.sanityCheck(); err != nil {
		return err
	}
	return peer.dispatchResponse(&Response{
		id:   res.RequestId,
		code: BlockBodiesMsg,
		Res:  &res.BlockBodiesPacket,
	})
}

func handleGetNodeData(backend Backend, msg p2p.Msg, peer *Peer) error {
	var query GetNodeDataPacket
	if err := msg.Decode(&query); err != nil {
		return errResp(ErrDecode, "msg %v: %v", msg, err)
	}
	return peer.SendNodeData(serviceNodeData(backend, query))
}

func handleGetNodeData66(backend Backend, msg p2p.Msg, peer *Peer) error {
	var query GetNodeDataPacket166
	if err := msg.Decode(&query); err != nil {
		return errResp(ErrDecode, "msg %v: %v", msg, err)
	}
	return peer.ReplyNodeData(query.RequestId, serviceNodeData(backend, query.GetNodeDataPacket))
}

func serviceNodeData(backend Backend, query GetNodeDataPacket) [][]byte {
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
	return data
}

// handleNodeData delivers a batch of state trie nodes that arrived for one of
// our previous requests.
func handleNodeData(backend Backend, msg p2p.Msg, peer *Peer) error {
	var data NodeDataPacket
	if err := msg.Decode(&data); err != nil {
		return errResp(ErrDecode, "msg %v: %v", msg, err)
	}
	return backend.Handle(peer, &data, msg.Size)
}

func handleNodeData66(backend Backend, msg p2p.Msg, peer *Peer) error {
	var res NodeDataPacket166
	if err := msg.Decode(&res); err != nil {
		return errResp(ErrDecode, "msg %v: %v", msg, err)
	}
	return peer.dispatchResponse(&Response{
		id:   res.RequestId,
		code: NodeDataMsg,
		Res:  &res.NodeDataPacket,
	})
}

func handleGetReceipts(backend Backend, msg p2p.Msg, peer *Peer) error {
	var query GetReceiptsPacket
	if err := msg.Decode(&query); err != nil {
		return errResp(ErrDecode, "msg %v: %v", msg, err)
	}
	return peer.SendReceiptsRLP(serviceReceipts(backend, query))
}

func handleGetReceipts66(backend Backend, msg p2p.Msg, peer *Peer) error {
	var query GetReceiptsPacket166
	if err := msg.Decode(&query); err != nil {
		return errResp(ErrDecode, "msg %v: %v", msg, err)
	}
	return peer.ReplyReceiptsRLP(query.RequestId, serviceReceipts(backend, query.GetReceiptsPacket))
}

func serviceReceipts(backend Backend, query GetReceiptsPacket) []rlp.RawValue {
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
	return receipts
}

// handleReceipts delivers a batch of receipts that arrived for one of our
// previous requests.
func handleReceipts(backend Backend, msg p2p.Msg, peer *Peer) error {
	var receipts ReceiptsPacket
	if err := msg.Decode(&receipts); err != nil {
		return errResp(ErrDecode, "msg %v: %v", msg, err)
	}
	return backend.Handle(peer, &receipts, msg.Size)
}

func handleReceipts66(backend Backend, msg p2p.Msg, peer *Peer) error {
	var res ReceiptsPacket166
	if err := msg.Decode(&res); err != nil {
		return errResp(ErrDecode, "msg %v: %v", msg, err)
	}
	return peer.dispatchResponse(&Response{
		id:   res.RequestId,
		code: ReceiptsMsg,
		Res:  &res.ReceiptsPacket,
	})
}

func handleNewBlockHashes(backend Backend, msg p2p.Msg, peer *Peer) error {
	if msg.Size > maxAnnounceFrameSize {
		propHashInRejectedMeter.Mark(1)
		return errResp(ErrMsgTooLarge, "announce frame %v > %v", msg.Size, maxAnnounceFrameSize)
	}
	var announces NewBlockHashesPacket
	if err := msg.Decode(&announces); err != nil {
		return errResp(ErrDecode, "%v: %v", msg, err)
	}
	if len(announces) > maxBlockHashesAnnounce {
		propHashInRejectedMeter.Mark(1)
		return errResp(ErrMsgTooLarge, "%d announcements > %d", len(announces), maxBlockHashesAnnounce)
	}
	if !peer.spendAnnounceBudget(len(announces)) {
		propHashInRejectedMeter.Mark(1)
		return errResp(ErrMsgTooLarge, "%d announcements over the per-peer budget", len(announces))
	}
	return backend.Handle(peer, &announces, msg.Size)
}

func handleNewBlock(backend Backend, msg p2p.Msg, peer *Peer) error {
	// Retrieve and decode the propagated block
	var request NewBlockPacket
	if err := msg.Decode(&request); err != nil {
		return errResp(ErrDecode, "%v: %v", msg, err)
	}
	// Drop a block whose payload does not match its own header without
	// disconnecting the peer: the remote may still be running an older build.
	if hash := types.CalcUncleHash(request.Block.Uncles()); hash != request.Block.UncleHash() {
		log.Warn("Propagated block has invalid uncles", "have", hash, "exp", request.Block.UncleHash())
		return nil // TODO(karalabe): return error eventually, but wait a few releases
	}
	if hash := types.DeriveSha(request.Block.Transactions(), trie.NewStackTrie(nil)); hash != request.Block.TxHash() {
		log.Warn("Propagated block has invalid body", "have", hash, "exp", request.Block.TxHash())
		return nil // TODO(karalabe): return error eventually, but wait a few releases
	}
	if err := request.sanityCheck(); err != nil {
		return err
	}
	// Stamp the block with the transport facts: when the frame arrived and
	// which peer it came from.
	request.Block.ReceivedAt = msg.ReceivedAt
	request.Block.ReceivedFrom = peer

	// Mark the peer as owning the block, so it is never propagated back to it
	peer.MarkBlock(request.Block.Hash())

	return backend.Handle(peer, &request, msg.Size)
}

func handleNewPooledTransactionHashes(backend Backend, msg p2p.Msg, peer *Peer) error {
	// Transaction announcements are only acted on once the node is synchronised
	if !backend.AcceptTxs() {
		return nil
	}
	var hashes NewPooledTransactionHashesPacket
	if err := msg.Decode(&hashes); err != nil {
		return errResp(ErrDecode, "msg %v: %v", msg, err)
	}
	return backend.Handle(peer, &hashes, msg.Size)
}

func handleGetPooledTransactions(backend Backend, msg p2p.Msg, peer *Peer) error {
	var query GetPooledTransactionsPacket
	if err := msg.Decode(&query); err != nil {
		return errResp(ErrDecode, "msg %v: %v", msg, err)
	}
	hashes, txs := servicePooledTransactions(backend, query)
	return peer.SendPooledTransactionsRLP(hashes, txs)
}

func handleGetPooledTransactions66(backend Backend, msg p2p.Msg, peer *Peer) error {
	var query GetPooledTransactionsPacket166
	if err := msg.Decode(&query); err != nil {
		return errResp(ErrDecode, "msg %v: %v", msg, err)
	}
	hashes, txs := servicePooledTransactions(backend, query.GetPooledTransactionsPacket)
	return peer.ReplyPooledTransactionsRLP(query.RequestId, hashes, txs)
}

func servicePooledTransactions(backend Backend, query GetPooledTransactionsPacket) ([]common.Hash, []rlp.RawValue) {
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
	return hashes, txs
}

func handleTransactions(backend Backend, msg p2p.Msg, peer *Peer) error {
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
}

// handlePooledTransactions delivers a batch of pooled transactions that arrived
// for one of our previous requests.
func handlePooledTransactions(backend Backend, msg p2p.Msg, peer *Peer) error {
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
}

func handlePooledTransactions66(backend Backend, msg p2p.Msg, peer *Peer) error {
	// Transactions arrived, make sure we have a valid and fresh chain to handle them
	if !backend.AcceptTxs() {
		return nil
	}
	var res PooledTransactionsPacket166
	if err := msg.Decode(&res); err != nil {
		return errResp(ErrDecode, "msg %v: %v", msg, err)
	}
	// Keep the legacy hardening over xdc/166: a nil transaction in the
	// payload must not reach the transaction handling.
	if err := res.PooledTransactionsPacket.sanityCheck(); err != nil {
		return errResp(ErrDecode, "%v", err)
	}
	// RequestTxs keeps its error-only signature and does not register a
	// pending dispatcher id, so the reply must stay on the node-layer path.
	// Only fulfil the tracker entry created when the request was sent.
	requestTracker.Fulfil(peer.id, peer.conn, peer.version, PooledTransactionsMsg, res.RequestId, time.Now())
	return backend.Handle(peer, &res.PooledTransactionsPacket, msg.Size)
}

func handleOrderTransactions(backend Backend, msg p2p.Msg, peer *Peer) error {
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
}

func handleLendingTransactions(backend Backend, msg p2p.Msg, peer *Peer) error {
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
}

func handleVote(backend Backend, msg p2p.Msg, peer *Peer) error {
	var vote VotePacket
	if err := msg.Decode(&vote); err != nil {
		return errResp(ErrDecode, "msg %v: %v", msg, err)
	}
	return backend.Handle(peer, &vote, msg.Size)
}

func handleTimeout(backend Backend, msg p2p.Msg, peer *Peer) error {
	var timeout TimeoutPacket
	if err := msg.Decode(&timeout); err != nil {
		return errResp(ErrDecode, "msg %v: %v", msg, err)
	}
	return backend.Handle(peer, &timeout, msg.Size)
}

func handleSyncInfo(backend Backend, msg p2p.Msg, peer *Peer) error {
	var syncInfo SyncInfoPacket
	if err := msg.Decode(&syncInfo); err != nil {
		return errResp(ErrDecode, "msg %v: %v", msg, err)
	}
	return backend.Handle(peer, &syncInfo, msg.Size)
}

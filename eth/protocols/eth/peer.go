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
	"errors"
	"fmt"
	"math/big"
	"sync"
	"sync/atomic"
	"time"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/p2p"
	"github.com/XinFinOrg/XDPoSChain/rlp"
	mapset "github.com/deckarep/golang-set/v2"
)

const (
	// MaxKnownTxs is the maximum number of transaction hashes to keep in the
	// known list (prevent DOS).
	MaxKnownTxs = 32768
	// MaxKnownOrderTxs is the maximum number of order transaction hashes to keep
	// in the known list (prevent DOS).
	MaxKnownOrderTxs = 32768
	// MaxKnownLendingTxs is the maximum number of lending transaction hashes to
	// keep in the known list (prevent DOS).
	MaxKnownLendingTxs = 32768
	// maxKnownBlocks is the maximum number of block hashes to keep in the known
	// list (prevent DOS).
	maxKnownBlocks = 1024

	// maxQueuedTxs is the maximum number of transactions to queue up before dropping
	// older broadcasts.
	maxQueuedTxs = 4096

	// maxQueuedTxAnns is the maximum number of transaction announcements to queue up
	// before dropping older announcements.
	maxQueuedTxAnns = 4096

	// maxQueuedBlocks is the maximum number of block propagations to queue up before
	// dropping broadcasts. There's not much point in queueing stale blocks, so a few
	// that might cover uncles should be enough.
	maxQueuedBlocks = 4

	// maxQueuedBlockAnns is the maximum number of block announcements to queue up before
	// dropping broadcasts. Similarly to block propagations, there's no point to queue
	// above some healthy uncle limit, so use that.
	maxQueuedBlockAnns = 4

	// TxsyncPackSize is the target size for the packs of transactions sent by the
	// transaction broadcast and announce loops. A pack can get larger than this if
	// a single transaction exceeds this size.
	TxsyncPackSize = 100 * 1024

	// MaxKnownVote is the maximum number of BFT vote hashes to keep in the known
	// list (prevent DOS).
	MaxKnownVote = 131072
	// MaxKnownTimeout is the maximum number of BFT timeout hashes to keep in the
	// known list (prevent DOS).
	MaxKnownTimeout = 131072
	// MaxKnownSyncInfo is the maximum number of BFT sync info hashes to keep in
	// the known list (prevent DOS).
	MaxKnownSyncInfo = 131072
)

// ErrLegacyRequest is returned by the request senders on protocol versions
// below xdc/166. The request has already been written to the wire; its reply
// still travels through the node layer's legacy Handle path instead of a
// request sink. It is not a failure and must not penalise the peer.
var ErrLegacyRequest = errors.New("legacy request")

// propEvent is a block propagation, waiting for its turn in the broadcast queue.
type propEvent struct {
	block *types.Block
	td    *big.Int
}

// peerConnSeq hands out a process-unique connection id. Request tracking is
// scoped to the connection, not the peer id: a reconnect may reuse the peer id
// while the previous connection's teardown is still in flight.
var peerConnSeq atomic.Uint64

// Peer is a remote peer on the eth wire protocol: it owns the message pipe and
// the bookkeeping of what the remote side is known to have seen. It has no
// reference back into the node: everything the peer needs arrives through its
// constructor.
type Peer struct {
	id   string
	conn uint64 // Process-unique connection id for request tracking

	reqIDSeq atomic.Uint64 // Per-connection request id allocator, reset by reconnect

	*p2p.Peer
	rw p2p.MsgReadWriter

	version uint // Protocol version negotiated

	head common.Hash
	td   *big.Int
	lock sync.RWMutex

	tipNumber uint64 // Highest block number announced by the peer (live network high-water mark)

	// Inbound NewBlockHashes announcement budget, touched only by the peer's message loop
	announceTokens float64
	announceRefill time.Time

	knownBlocks     mapset.Set[common.Hash] // Set of block hashes known to be known by this peer
	queuedBlocks    chan *propEvent         // Queue of blocks to broadcast to the peer
	queuedBlockAnns chan *types.Block       // Queue of blocks to announce to the peer

	knownTxs        mapset.Set[common.Hash] // Set of transaction hashes known to be known by this peer
	knownOrderTxs   mapset.Set[common.Hash] // Set of order transaction hashes known to be known by this peer
	knownLendingTxs mapset.Set[common.Hash] // Set of lending transaction hashes known to be known by this peer
	txBroadcast     chan []common.Hash      // Channel used to queue transaction propagation requests
	txAnnounce      chan []common.Hash      // Channel used to queue transaction announcement requests

	getPooledTx func(common.Hash) *types.Transaction // Callback used to retrieve transaction from txpool

	reqDispatch chan *request  // Dispatch channel to send requests and track them until fulfilment
	reqCancel   chan *cancel   // Dispatch channel to cancel pending requests and untrack them
	resDispatch chan *response // Dispatch channel to fulfil pending requests and untrack them

	term        chan struct{}  // Termination channel to stop the broadcaster
	broadcastWg sync.WaitGroup // Tracks the broadcaster goroutines so they can be awaited
	closeOnce   sync.Once      // Ensures term is closed exactly once

	knownVote     mapset.Set[common.Hash] // Set of BFT Vote known to be known by this peer
	knownTimeout  mapset.Set[common.Hash] // Set of BFT timeout known to be known by this peer
	knownSyncInfo mapset.Set[common.Hash] // Set of BFT Sync Info known to be known by this peer
}

// NewPeer creates a new wire peer on top of the given message pipe, starting the
// broadcast loops that push data towards the remote side and the dispatcher that
// serves request/reply traffic. The returned peer must be closed to stop those
// loops.
func NewPeer(version uint, p *p2p.Peer, rw p2p.MsgReadWriter, getPooledTx func(hash common.Hash) *types.Transaction) *Peer {
	mrw := newMeteredMsgWriter(rw)
	if m, ok := mrw.(*meteredMsgReadWriter); ok {
		m.Init(int(version))
	}
	peer := &Peer{
		Peer:            p,
		rw:              mrw,
		version:         version,
		td:              new(big.Int),
		id:              fmt.Sprintf("%x", p.ID().Bytes()[:8]),
		conn:            peerConnSeq.Add(1),
		knownTxs:        mapset.NewSet[common.Hash](),
		knownBlocks:     mapset.NewSet[common.Hash](),
		knownOrderTxs:   mapset.NewSet[common.Hash](),
		knownLendingTxs: mapset.NewSet[common.Hash](),
		queuedBlocks:    make(chan *propEvent, maxQueuedBlocks),
		queuedBlockAnns: make(chan *types.Block, maxQueuedBlockAnns),
		txBroadcast:     make(chan []common.Hash),
		txAnnounce:      make(chan []common.Hash),
		reqDispatch:     make(chan *request),
		reqCancel:       make(chan *cancel),
		resDispatch:     make(chan *response),
		getPooledTx:     getPooledTx,
		term:            make(chan struct{}),

		knownVote:     mapset.NewSet[common.Hash](),
		knownTimeout:  mapset.NewSet[common.Hash](),
		knownSyncInfo: mapset.NewSet[common.Hash](),
	}
	// Start up the broadcasters and the request dispatcher. They terminate when
	// the peer is closed.
	peer.broadcastWg.Go(peer.broadcastBlocks)
	peer.broadcastWg.Go(peer.broadcastTransactions)
	if version >= XDC165 {
		peer.broadcastWg.Go(peer.announceTransactions)
	}
	peer.broadcastWg.Go(peer.dispatcher)
	return peer
}

// Close signals the broadcast goroutines and the request dispatcher to
// terminate. It is safe for concurrent and repeated calls: only the first call
// closes term.
func (p *Peer) Close() {
	p.closeOnce.Do(func() { close(p.term) })
}

// ID retrieves the peer's unique identifier.
func (p *Peer) ID() string {
	return p.id
}

// Version retrieves the peer's negotiated protocol version.
func (p *Peer) Version() uint {
	return p.version
}

// Head retrieves a copy of the current head hash and total difficulty of the
// peer.
func (p *Peer) Head() (hash common.Hash, td *big.Int) {
	p.lock.RLock()
	defer p.lock.RUnlock()

	copy(hash[:], p.head[:])
	return hash, new(big.Int).Set(p.td)
}

// SetHead updates the head hash and total difficulty of the peer.
func (p *Peer) SetHead(hash common.Hash, td *big.Int) {
	p.lock.Lock()
	defer p.lock.Unlock()

	copy(p.head[:], hash[:])
	p.td.Set(td)
}

// TipNumber retrieves the highest block number announced by the peer.
func (p *Peer) TipNumber() uint64 {
	p.lock.RLock()
	defer p.lock.RUnlock()
	return p.tipNumber
}

// SetTipNumber records the highest block number announced by the peer. The tip
// only ever moves forward; unlike SetHead (which conservatively tracks the
// parent of an announced block), this reflects the actual tip the peer has
// advertised, so it can serve as a live network high-water mark.
func (p *Peer) SetTipNumber(number uint64) {
	p.lock.Lock()
	defer p.lock.Unlock()
	if number > p.tipNumber {
		p.tipNumber = number
	}
}

// MarkBlock marks a block as known for the peer, ensuring that the block will
// never be propagated to this particular peer.
func (p *Peer) MarkBlock(hash common.Hash) {
	// If we reached the memory allowance, drop a previously known block hash
	for p.knownBlocks.Cardinality() >= maxKnownBlocks {
		p.knownBlocks.Pop()
	}
	p.knownBlocks.Add(hash)
}

// KnownBlock returns whether the peer is known to already have the given block.
func (p *Peer) KnownBlock(hash common.Hash) bool {
	return p.knownBlocks.Contains(hash)
}

// MarkTransaction marks a transaction as known for the peer, ensuring that it
// will never be propagated to this particular peer.
func (p *Peer) MarkTransaction(hash common.Hash) {
	// If we reached the memory allowance, drop a previously known transaction hash
	for p.knownTxs.Cardinality() >= MaxKnownTxs {
		p.knownTxs.Pop()
	}
	p.knownTxs.Add(hash)
}

// KnownTransaction returns whether the peer is known to already have the given
// transaction.
func (p *Peer) KnownTransaction(hash common.Hash) bool {
	return p.knownTxs.Contains(hash)
}

// MarkOrderTransaction marks an order transaction as known for the peer,
// ensuring that it will never be propagated to this particular peer.
func (p *Peer) MarkOrderTransaction(hash common.Hash) {
	// If we reached the memory allowance, drop a previously known transaction hash
	for p.knownOrderTxs.Cardinality() >= MaxKnownOrderTxs {
		p.knownOrderTxs.Pop()
	}
	p.knownOrderTxs.Add(hash)
}

// KnownOrderTransaction returns whether the peer is known to already have the
// given order transaction.
func (p *Peer) KnownOrderTransaction(hash common.Hash) bool {
	return p.knownOrderTxs.Contains(hash)
}

// MarkLendingTransaction marks a lending transaction as known for the peer,
// ensuring that it will never be propagated to this particular peer.
func (p *Peer) MarkLendingTransaction(hash common.Hash) {
	// If we reached the memory allowance, drop a previously known transaction hash
	for p.knownLendingTxs.Cardinality() >= MaxKnownLendingTxs {
		p.knownLendingTxs.Pop()
	}
	p.knownLendingTxs.Add(hash)
}

// KnownLendingTransaction returns whether the peer is known to already have the
// given lending transaction.
func (p *Peer) KnownLendingTransaction(hash common.Hash) bool {
	return p.knownLendingTxs.Contains(hash)
}

// MarkVote marks a vote as known for the peer, ensuring that it will never be
// propagated to this particular peer.
func (p *Peer) MarkVote(hash common.Hash) {
	// If we reached the memory allowance, drop a previously known vote hash
	for p.knownVote.Cardinality() >= MaxKnownVote {
		p.knownVote.Pop()
	}
	p.knownVote.Add(hash)
}

// KnownVote returns whether the peer is known to already have the given vote.
func (p *Peer) KnownVote(hash common.Hash) bool {
	return p.knownVote.Contains(hash)
}

// MarkTimeout marks a timeout as known for the peer, ensuring that it will never
// be propagated to this particular peer.
func (p *Peer) MarkTimeout(hash common.Hash) {
	// If we reached the memory allowance, drop a previously known timeout hash
	for p.knownTimeout.Cardinality() >= MaxKnownTimeout {
		p.knownTimeout.Pop()
	}
	p.knownTimeout.Add(hash)
}

// KnownTimeout returns whether the peer is known to already have the given
// timeout.
func (p *Peer) KnownTimeout(hash common.Hash) bool {
	return p.knownTimeout.Contains(hash)
}

// MarkSyncInfo marks a sync info as known for the peer, ensuring that it will
// never be propagated to this particular peer.
func (p *Peer) MarkSyncInfo(hash common.Hash) {
	// If we reached the memory allowance, drop a previously known sync info hash
	for p.knownSyncInfo.Cardinality() >= MaxKnownSyncInfo {
		p.knownSyncInfo.Pop()
	}
	p.knownSyncInfo.Add(hash)
}

// KnownSyncInfo returns whether the peer is known to already have the given sync
// info.
func (p *Peer) KnownSyncInfo(hash common.Hash) bool {
	return p.knownSyncInfo.Contains(hash)
}

// SendTransactions64 sends transactions to the peer and includes the hashes
// in its transaction hash set for future reference.
//
// This method is legacy support for initial transaction exchange in eth/64 and
// prior. For xdc/165 and higher use SendPooledTransactionHashes.
func (p *Peer) SendTransactions64(txs types.Transactions) error {
	return p.sendTransactions(txs)
}

// sendTransactions sends transactions to the peer and includes the hashes
// in its transaction hash set for future reference.
//
// This method is a helper used by the async transaction sender. Don't call it
// directly as the queueing (memory) and transmission (bandwidth) costs should
// not be managed directly.
func (p *Peer) sendTransactions(txs types.Transactions) error {
	// Mark all the transactions as known, but ensure we don't overflow our limits
	for p.knownTxs.Cardinality() > max(0, MaxKnownTxs-len(txs)) {
		p.knownTxs.Pop()
	}
	for _, tx := range txs {
		p.knownTxs.Add(tx.Hash())
	}
	return p2p.Send(p.rw, TransactionMsg, txs)
}

// SendOrderTransactions sends order transactions to the peer and includes the
// hashes in its transaction hash set for future reference.
func (p *Peer) SendOrderTransactions(txs types.OrderTransactions) error {
	for p.knownOrderTxs.Cardinality() >= MaxKnownOrderTxs {
		p.knownOrderTxs.Pop()
	}

	for _, tx := range txs {
		p.knownOrderTxs.Add(tx.Hash())
	}
	return p2p.Send(p.rw, OrderTxMsg, txs)
}

// SendLendingTransactions sends lending transactions to the peer and includes
// the hashes in its transaction hash set for future reference.
func (p *Peer) SendLendingTransactions(txs types.LendingTransactions) error {
	for p.knownLendingTxs.Cardinality() >= MaxKnownLendingTxs {
		p.knownLendingTxs.Pop()
	}

	for _, tx := range txs {
		p.knownLendingTxs.Add(tx.Hash())
	}
	return p2p.Send(p.rw, LendingTxMsg, txs)
}

// AsyncSendTransactions queues a list of transactions (by hash) to eventually
// propagate to a remote peer. The number of pending sends are capped (new ones
// will force old sends to be dropped)
func (p *Peer) AsyncSendTransactions(hashes []common.Hash) {
	select {
	case p.txBroadcast <- hashes:
		// Mark all the transactions as known, but ensure we don't overflow our limits
		for p.knownTxs.Cardinality() > max(0, MaxKnownTxs-len(hashes)) {
			p.knownTxs.Pop()
		}
		for _, hash := range hashes {
			p.knownTxs.Add(hash)
		}
	case <-p.term:
		p.Log().Debug("Dropping transaction propagation", "count", len(hashes))
	}
}

// sendPooledTransactionHashes sends transaction hashes to the peer and includes
// them in its transaction hash set for future reference.
//
// This method is a helper used by the async transaction announcer. Don't call it
// directly as the queueing (memory) and transmission (bandwidth) costs should
// not be managed directly.
func (p *Peer) sendPooledTransactionHashes(hashes []common.Hash) error {
	// Mark all the transactions as known, but ensure we don't overflow our limits
	for p.knownTxs.Cardinality() > max(0, MaxKnownTxs-len(hashes)) {
		p.knownTxs.Pop()
	}
	for _, hash := range hashes {
		p.knownTxs.Add(hash)
	}
	return p2p.Send(p.rw, NewPooledTransactionHashesMsg, hashes)
}

// AsyncSendPooledTransactionHashes queues a list of transactions hashes to eventually
// announce to a remote peer.  The number of pending sends are capped (new ones
// will force old sends to be dropped)
func (p *Peer) AsyncSendPooledTransactionHashes(hashes []common.Hash) {
	select {
	case p.txAnnounce <- hashes:
		// Mark all the transactions as known, but ensure we don't overflow our limits
		for p.knownTxs.Cardinality() > max(0, MaxKnownTxs-len(hashes)) {
			p.knownTxs.Pop()
		}
		for _, hash := range hashes {
			p.knownTxs.Add(hash)
		}
	case <-p.term:
		p.Log().Debug("Dropping transaction announcement", "count", len(hashes))
	}
}

// SendPooledTransactionsRLP sends requested transactions to the peer and adds the
// hashes in its transaction hash set for future reference.
//
// Note, the method assumes the hashes are correct and correspond to the list of
// transactions being sent.
func (p *Peer) SendPooledTransactionsRLP(hashes []common.Hash, txs []rlp.RawValue) error {
	// Mark all the transactions as known, but ensure we don't overflow our limits
	for p.knownTxs.Cardinality() > max(0, MaxKnownTxs-len(hashes)) {
		p.knownTxs.Pop()
	}
	for _, hash := range hashes {
		p.knownTxs.Add(hash)
	}
	return p2p.Send(p.rw, PooledTransactionsMsg, txs)
}

// ReplyPooledTransactionsRLP sends requested transactions to the peer with the
// given request id and adds the hashes in its transaction hash set for future
// reference, the same way as SendPooledTransactionsRLP.
//
// Note, the method assumes the hashes are correct and correspond to the list of
// transactions being sent.
func (p *Peer) ReplyPooledTransactionsRLP(id uint64, hashes []common.Hash, txs []rlp.RawValue) error {
	// Mark all the transactions as known, but ensure we don't overflow our limits
	for p.knownTxs.Cardinality() > max(0, MaxKnownTxs-len(hashes)) {
		p.knownTxs.Pop()
	}
	for _, hash := range hashes {
		p.knownTxs.Add(hash)
	}
	// Not packed into PooledTransactionsPacket to avoid RLP decoding
	return p2p.Send(p.rw, PooledTransactionsMsg, PooledTransactionsRLPPacket166{
		RequestId:                   id,
		PooledTransactionsRLPPacket: txs,
	})
}

// SendNewBlockHashes announces the availability of a number of blocks through
// a hash notification.
func (p *Peer) SendNewBlockHashes(hashes []common.Hash, numbers []uint64) error {
	// Mark all the block hashes as known, but ensure we don't overflow our limits
	for p.knownBlocks.Cardinality() > max(0, maxKnownBlocks-len(hashes)) {
		p.knownBlocks.Pop()
	}
	for _, hash := range hashes {
		p.knownBlocks.Add(hash)
	}
	request := make(NewBlockHashesPacket, len(hashes))
	for i := 0; i < len(hashes); i++ {
		request[i].Hash = hashes[i]
		request[i].Number = numbers[i]
	}
	return p2p.Send(p.rw, NewBlockHashesMsg, request)
}

// AsyncSendNewBlockHash queues the availability of a block for propagation to a
// remote peer. If the peer's broadcast queue is full, the event is silently
// dropped.
func (p *Peer) AsyncSendNewBlockHash(block *types.Block) {
	select {
	case p.queuedBlockAnns <- block:
		// Mark all the block hash as known, but ensure we don't overflow our limits
		for p.knownBlocks.Cardinality() >= maxKnownBlocks {
			p.knownBlocks.Pop()
		}
		p.knownBlocks.Add(block.Hash())
	default:
		p.Log().Debug("Dropping block announcement", "number", block.NumberU64(), "hash", block.Hash())
	}
}

// SendNewBlock propagates an entire block to a remote peer.
func (p *Peer) SendNewBlock(block *types.Block, td *big.Int) error {
	// Mark all the block hash as known, but ensure we don't overflow our limits
	for p.knownBlocks.Cardinality() >= maxKnownBlocks {
		p.knownBlocks.Pop()
	}
	p.knownBlocks.Add(block.Hash())
	return p2p.Send(p.rw, NewBlockMsg, &NewBlockPacket{Block: block, TD: td})
}

// AsyncSendNewBlock queues an entire block for propagation to a remote peer. If
// the peer's broadcast queue is full, the event is silently dropped.
func (p *Peer) AsyncSendNewBlock(block *types.Block, td *big.Int) {
	select {
	case p.queuedBlocks <- &propEvent{block: block, td: td}:
		// Mark all the block hash as known, but ensure we don't overflow our limits
		for p.knownBlocks.Cardinality() >= maxKnownBlocks {
			p.knownBlocks.Pop()
		}
		p.knownBlocks.Add(block.Hash())
	default:
		p.Log().Debug("Dropping block propagation", "number", block.NumberU64(), "hash", block.Hash())
	}
}

// SendBlockHeaders sends a batch of block headers to the remote peer.
func (p *Peer) SendBlockHeaders(headers []*types.Header) error {
	return p2p.Send(p.rw, BlockHeadersMsg, headers)
}

// ReplyBlockHeaders is the xdc/166 version of SendBlockHeaders.
func (p *Peer) ReplyBlockHeaders(id uint64, headers []*types.Header) error {
	return p2p.Send(p.rw, BlockHeadersMsg, BlockHeadersPacket166{
		RequestId:          id,
		BlockHeadersPacket: headers,
	})
}

// SendBlockBodies sends a batch of block contents to the remote peer.
func (p *Peer) SendBlockBodies(bodies []*BlockBody) error {
	return p2p.Send(p.rw, BlockBodiesMsg, BlockBodiesPacket(bodies))
}

// SendBlockBodiesRLP sends a batch of block contents to the remote peer from
// an already RLP encoded format.
func (p *Peer) SendBlockBodiesRLP(bodies []rlp.RawValue) error {
	return p2p.Send(p.rw, BlockBodiesMsg, bodies)
}

// ReplyBlockBodiesRLP is the xdc/166 version of SendBlockBodiesRLP.
func (p *Peer) ReplyBlockBodiesRLP(id uint64, bodies []rlp.RawValue) error {
	// Not packed into BlockBodiesPacket to avoid RLP decoding
	return p2p.Send(p.rw, BlockBodiesMsg, BlockBodiesRLPPacket166{
		RequestId:            id,
		BlockBodiesRLPPacket: bodies,
	})
}

// SendNodeData sends a batch of arbitrary internal data, corresponding to the
// hashes requested.
func (p *Peer) SendNodeData(data [][]byte) error {
	return p2p.Send(p.rw, NodeDataMsg, data)
}

// ReplyNodeData is the xdc/166 response to GetNodeData.
func (p *Peer) ReplyNodeData(id uint64, data [][]byte) error {
	return p2p.Send(p.rw, NodeDataMsg, NodeDataPacket166{
		RequestId:      id,
		NodeDataPacket: data,
	})
}

// SendReceiptsRLP sends a batch of transaction receipts, corresponding to the
// ones requested from an already RLP encoded format.
func (p *Peer) SendReceiptsRLP(receipts []rlp.RawValue) error {
	return p2p.Send(p.rw, ReceiptsMsg, receipts)
}

// ReplyReceiptsRLP is the xdc/166 response to GetReceipts.
func (p *Peer) ReplyReceiptsRLP(id uint64, receipts []rlp.RawValue) error {
	return p2p.Send(p.rw, ReceiptsMsg, ReceiptsRLPPacket166{
		RequestId:         id,
		ReceiptsRLPPacket: receipts,
	})
}

// SendVote sends a BFT vote to the peer and marks it as known.
func (p *Peer) SendVote(vote *types.Vote) error {
	for p.knownVote.Cardinality() >= MaxKnownVote {
		p.knownVote.Pop()
	}

	p.knownVote.Add(vote.Hash())
	return p2p.Send(p.rw, VoteMsg, (*VotePacket)(vote))
}

// SendTimeout sends a BFT timeout to the peer and marks it as known.
func (p *Peer) SendTimeout(timeout *types.Timeout) error {
	for p.knownTimeout.Cardinality() >= MaxKnownTimeout {
		p.knownTimeout.Pop()
	}

	p.knownTimeout.Add(timeout.Hash())
	return p2p.Send(p.rw, TimeoutMsg, (*TimeoutPacket)(timeout))
}

// SendSyncInfo sends a BFT sync info to the peer and marks it as known.
func (p *Peer) SendSyncInfo(syncInfo *types.SyncInfo) error {
	for p.knownSyncInfo.Cardinality() >= MaxKnownSyncInfo {
		p.knownSyncInfo.Pop()
	}

	p.knownSyncInfo.Add(syncInfo.Hash())
	return p2p.Send(p.rw, SyncInfoMsg, (*SyncInfoPacket)(syncInfo))
}

// nextRequestID hands out the wire-level id of the next request on this
// connection. Both the dispatcher and the tracker require ids that never repeat
// within a connection (see Request), so this is a plain counter rather than a
// random draw; a reconnect gets a fresh Peer and therefore a fresh id scope.
func (p *Peer) nextRequestID() uint64 {
	return p.reqIDSeq.Add(1)
}

// RequestOneHeader is a wrapper around the header query functions to fetch a
// single header. It is used solely by the fetcher.
func (p *Peer) RequestOneHeader(hash common.Hash, sink chan *Response) (*Request, error) {
	p.Log().Debug("Fetching single header", "hash", hash)
	query := GetBlockHeadersPacket{
		Origin:  HashOrNumber{Hash: hash},
		Amount:  uint64(1),
		Skip:    uint64(0),
		Reverse: false,
	}
	if p.Version() < XDC166 {
		return nil, p.sendLegacyRequest(GetBlockHeadersMsg, &query)
	}
	id := p.nextRequestID()
	req := &Request{
		id:   id,
		sink: sink,
		code: GetBlockHeadersMsg,
		want: BlockHeadersMsg,
		data: &GetBlockHeadersPacket166{
			RequestId:             id,
			GetBlockHeadersPacket: &query,
		},
	}
	if err := p.dispatchRequest(req); err != nil {
		return nil, err
	}
	return req, nil
}

// RequestHeadersByHash fetches a batch of blocks' headers corresponding to the
// specified header query, based on the hash of an origin block.
func (p *Peer) RequestHeadersByHash(origin common.Hash, amount int, skip int, reverse bool, sink chan *Response) (*Request, error) {
	p.Log().Debug("Fetching batch of headers", "count", amount, "fromhash", origin, "skip", skip, "reverse", reverse)
	query := GetBlockHeadersPacket{
		Origin:  HashOrNumber{Hash: origin},
		Amount:  uint64(amount),
		Skip:    uint64(skip),
		Reverse: reverse,
	}
	if p.Version() < XDC166 {
		return nil, p.sendLegacyRequest(GetBlockHeadersMsg, &query)
	}
	id := p.nextRequestID()
	req := &Request{
		id:   id,
		sink: sink,
		code: GetBlockHeadersMsg,
		want: BlockHeadersMsg,
		data: &GetBlockHeadersPacket166{
			RequestId:             id,
			GetBlockHeadersPacket: &query,
		},
	}
	if err := p.dispatchRequest(req); err != nil {
		return nil, err
	}
	return req, nil
}

// RequestHeadersByNumber fetches a batch of blocks' headers corresponding to the
// specified header query, based on the number of an origin block.
func (p *Peer) RequestHeadersByNumber(origin uint64, amount int, skip int, reverse bool, sink chan *Response) (*Request, error) {
	p.Log().Debug("Fetching batch of headers", "count", amount, "fromnum", origin, "skip", skip, "reverse", reverse)
	query := GetBlockHeadersPacket{
		Origin:  HashOrNumber{Number: origin},
		Amount:  uint64(amount),
		Skip:    uint64(skip),
		Reverse: reverse,
	}
	if p.Version() < XDC166 {
		return nil, p.sendLegacyRequest(GetBlockHeadersMsg, &query)
	}
	id := p.nextRequestID()
	req := &Request{
		id:   id,
		sink: sink,
		code: GetBlockHeadersMsg,
		want: BlockHeadersMsg,
		data: &GetBlockHeadersPacket166{
			RequestId:             id,
			GetBlockHeadersPacket: &query,
		},
	}
	if err := p.dispatchRequest(req); err != nil {
		return nil, err
	}
	return req, nil
}

// RequestBodies fetches a batch of blocks' bodies corresponding to the hashes
// specified.
func (p *Peer) RequestBodies(hashes []common.Hash, sink chan *Response) (*Request, error) {
	p.Log().Debug("Fetching batch of block bodies", "count", len(hashes))
	if p.Version() < XDC166 {
		return nil, p.sendLegacyRequest(GetBlockBodiesMsg, hashes)
	}
	id := p.nextRequestID()
	req := &Request{
		id:   id,
		sink: sink,
		code: GetBlockBodiesMsg,
		want: BlockBodiesMsg,
		data: &GetBlockBodiesPacket166{
			RequestId:            id,
			GetBlockBodiesPacket: hashes,
		},
	}
	if err := p.dispatchRequest(req); err != nil {
		return nil, err
	}
	return req, nil
}

// RequestNodeData fetches a batch of arbitrary data from a node's known state
// data, corresponding to the specified hashes.
func (p *Peer) RequestNodeData(hashes []common.Hash, sink chan *Response) (*Request, error) {
	p.Log().Debug("Fetching batch of state data", "count", len(hashes))
	if p.Version() < XDC166 {
		return nil, p.sendLegacyRequest(GetNodeDataMsg, hashes)
	}
	id := p.nextRequestID()
	req := &Request{
		id:   id,
		sink: sink,
		code: GetNodeDataMsg,
		want: NodeDataMsg,
		data: &GetNodeDataPacket166{
			RequestId:         id,
			GetNodeDataPacket: hashes,
		},
	}
	if err := p.dispatchRequest(req); err != nil {
		return nil, err
	}
	return req, nil
}

// RequestReceipts fetches a batch of transaction receipts from a remote node.
func (p *Peer) RequestReceipts(hashes []common.Hash, sink chan *Response) (*Request, error) {
	p.Log().Debug("Fetching batch of receipts", "count", len(hashes))
	if p.Version() < XDC166 {
		return nil, p.sendLegacyRequest(GetReceiptsMsg, hashes)
	}
	id := p.nextRequestID()
	req := &Request{
		id:   id,
		sink: sink,
		code: GetReceiptsMsg,
		want: ReceiptsMsg,
		data: &GetReceiptsPacket166{
			RequestId:         id,
			GetReceiptsPacket: hashes,
		},
	}
	if err := p.dispatchRequest(req); err != nil {
		return nil, err
	}
	return req, nil
}

// RequestTxs fetches a batch of transactions from a remote node.
func (p *Peer) RequestTxs(hashes []common.Hash) error {
	p.Log().Debug("Fetching batch of transactions", "count", len(hashes))
	if p.Version() < XDC166 {
		return p2p.Send(p.rw, GetPooledTransactionsMsg, hashes)
	}
	id := p.nextRequestID()
	// The tracker only meters the round trip: a local id collision or the
	// pending limit must not fail an otherwise fine request, nor make the tx
	// fetcher treat the peer as faulty. The reply then simply counts as stale.
	tracked := true
	if err := requestTracker.Track(p.id, p.conn, p.version, GetPooledTransactionsMsg, PooledTransactionsMsg, id); err != nil {
		tracked = false
		p.Log().Debug("Failed to track pooled transactions request", "err", err, "id", id)
	}
	if err := p2p.Send(p.rw, GetPooledTransactionsMsg, &GetPooledTransactionsPacket166{
		RequestId:                   id,
		GetPooledTransactionsPacket: hashes,
	}); err != nil {
		if tracked {
			requestTracker.Drop(p.id, p.conn, id)
		}
		return err
	}
	return nil
}

// sendLegacyRequest writes a bare request payload on a pre-xdc/166 peer and
// reports the legacy sentinel on success. The reply arrives through the node
// layer instead of a request sink.
func (p *Peer) sendLegacyRequest(code uint64, data interface{}) error {
	if err := p2p.Send(p.rw, code, data); err != nil {
		return err
	}
	return ErrLegacyRequest
}

// String implements fmt.Stringer.
func (p *Peer) String() string {
	return fmt.Sprintf("Peer %s [%s]", p.id,
		fmt.Sprintf("eth/%2d", p.version),
	)
}

func (p *Peer) spendAnnounceBudget(n int) bool {
	now := time.Now()
	if p.announceRefill.IsZero() {
		p.announceTokens = maxAnnounceBurst
	} else if refilled := p.announceTokens + now.Sub(p.announceRefill).Seconds()*maxAnnounceRate; refilled < maxAnnounceBurst {
		p.announceTokens = refilled
	} else {
		p.announceTokens = maxAnnounceBurst
	}
	p.announceRefill = now

	if p.announceTokens < float64(n) {
		return false
	}
	p.announceTokens -= float64(n)
	return true
}

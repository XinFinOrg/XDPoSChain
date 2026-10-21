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
	MaxKnownTxs        = 32768 // Maximum transactions hashes to keep in the known list (prevent DOS)
	MaxKnownOrderTxs   = 32768 // Maximum transactions hashes to keep in the known list (prevent DOS)
	MaxKnownLendingTxs = 32768 // Maximum transactions hashes to keep in the known list (prevent DOS)
	MaxKnownBlocks     = 1024  // Maximum block hashes to keep in the known list (prevent DOS)

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

	handshakeTimeout = 5 * time.Second

	MaxKnownVote     = 131072 // Maximum transactions hashes to keep in the known list (prevent DOS)
	MaxKnownTimeout  = 131072 // Maximum transactions hashes to keep in the known list (prevent DOS)
	MaxKnownSyncInfo = 131072 // Maximum transactions hashes to keep in the known list (prevent DOS)
)

// propEvent is a block propagation, waiting for its turn in the broadcast queue.
type propEvent struct {
	block *types.Block
	td    *big.Int
}

type Peer struct {
	id string

	*p2p.Peer
	rw p2p.MsgReadWriter

	version  int         // Protocol version negotiated
	forkDrop *time.Timer // Timed connection dropper if forks aren't validated in time

	head common.Hash
	td   *big.Int
	lock sync.RWMutex

	tipNumber uint64 // Highest block number announced by the Peer (live network high-water mark)

	knownBlocks     mapset.Set[common.Hash] // Set of block hashes known to be known by this Peer
	queuedBlocks    chan *propEvent         // Queue of blocks to broadcast to the Peer
	queuedBlockAnns chan *types.Block       // Queue of blocks to announce to the Peer

	knownTxs        mapset.Set[common.Hash] // Set of transaction hashes known to be known by this Peer
	knownOrderTxs   mapset.Set[common.Hash] // Set of order transaction hashes known to be known by this Peer
	knownLendingTxs mapset.Set[common.Hash] // Set of lending transaction hashes known to be known by this Peer
	txBroadcast     chan []common.Hash      // Channel used to queue transaction propagation requests
	txAnnounce      chan []common.Hash      // Channel used to queue transaction announcement requests

	getPooledTx func(common.Hash) *types.Transaction // Callback used to retrieve transaction from txpool

	term        chan struct{}  // Termination channel to stop the broadcaster
	broadcastWg sync.WaitGroup // Tracks the broadcaster goroutines so they can be awaited
	closeOnce   sync.Once      // Ensures term is closed exactly once

	// removed is set exactly once to make peer removal idempotent.
	removed atomic.Bool

	knownVote     mapset.Set[common.Hash] // Set of BFT Vote known to be known by this Peer
	knownTimeout  mapset.Set[common.Hash] // Set of BFT timeout known to be known by this Peer
	knownSyncInfo mapset.Set[common.Hash] // Set of BFT Sync Info known to be known by this Peer
}

func NewPeer(version int, p *p2p.Peer, rw p2p.MsgReadWriter, getPooledTx func(hash common.Hash) *types.Transaction) *Peer {
	return &Peer{
		Peer:            p,
		rw:              rw,
		version:         version,
		id:              fmt.Sprintf("%x", p.ID().Bytes()[:8]),
		knownTxs:        mapset.NewSet[common.Hash](),
		knownBlocks:     mapset.NewSet[common.Hash](),
		knownOrderTxs:   mapset.NewSet[common.Hash](),
		knownLendingTxs: mapset.NewSet[common.Hash](),
		queuedBlocks:    make(chan *propEvent, maxQueuedBlocks),
		queuedBlockAnns: make(chan *types.Block, maxQueuedBlockAnns),
		txBroadcast:     make(chan []common.Hash),
		txAnnounce:      make(chan []common.Hash),
		getPooledTx:     getPooledTx,
		term:            make(chan struct{}),

		knownVote:     mapset.NewSet[common.Hash](),
		knownTimeout:  mapset.NewSet[common.Hash](),
		knownSyncInfo: mapset.NewSet[common.Hash](),
	}
}

// markRemoved claims the peer's removal, returning true only for the first
// caller so the unregister sequence runs exactly once per peer.
func (p *Peer) markRemoved() bool {
	return !p.removed.Swap(true)
}

// close signals the broadcast goroutine to terminate. It is safe for
// concurrent and repeated calls: only the first call closes term.
func (p *Peer) Close() {
	p.closeOnce.Do(func() { close(p.term) })
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
	for p.knownBlocks.Cardinality() >= MaxKnownBlocks {
		p.knownBlocks.Pop()
	}
	p.knownBlocks.Add(hash)
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

// OrderMarkTransaction marks a order transaction as known for the peer, ensuring that it
// will never be propagated to this particular peer.
func (p *Peer) MarkOrderTransaction(hash common.Hash) {
	// If we reached the memory allowance, drop a previously known transaction hash
	for p.knownOrderTxs.Cardinality() >= MaxKnownOrderTxs {
		p.knownOrderTxs.Pop()
	}
	p.knownOrderTxs.Add(hash)
}

// MarkLendingTransaction marks a lending transaction as known for the peer, ensuring that it
// will never be propagated to this particular peer.
func (p *Peer) MarkLendingTransaction(hash common.Hash) {
	// If we reached the memory allowance, drop a previously known transaction hash
	for p.knownLendingTxs.Cardinality() >= MaxKnownLendingTxs {
		p.knownLendingTxs.Pop()
	}
	p.knownLendingTxs.Add(hash)
}

// MarkVote marks a vote as known for the peer, ensuring that it
// will never be propagated to this particular peer.
func (p *Peer) MarkVote(hash common.Hash) {
	// If we reached the memory allowance, drop a previously known transaction hash
	for p.knownVote.Cardinality() >= MaxKnownVote {
		p.knownVote.Pop()
	}
	p.knownVote.Add(hash)
}

// MarkTimeout marks a timeout as known for the peer, ensuring that it
// will never be propagated to this particular peer.
func (p *Peer) MarkTimeout(hash common.Hash) {
	// If we reached the memory allowance, drop a previously known transaction hash
	for p.knownTimeout.Cardinality() >= MaxKnownTimeout {
		p.knownTimeout.Pop()
	}
	p.knownTimeout.Add(hash)
}

// MarkSyncInfo marks a syncInfo as known for the peer, ensuring that it
// will never be propagated to this particular peer.
func (p *Peer) MarkSyncInfo(hash common.Hash) {
	// If we reached the memory allowance, drop a previously known transaction hash
	for p.knownSyncInfo.Cardinality() >= MaxKnownSyncInfo {
		p.knownSyncInfo.Pop()
	}
	p.knownSyncInfo.Add(hash)
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

// SendTransactions sends transactions to the peer and includes the hashes
// in its transaction hash set for future reference.
func (p *Peer) SendOrderTransactions(txs types.OrderTransactions) error {
	for p.knownOrderTxs.Cardinality() >= MaxKnownOrderTxs {
		p.knownOrderTxs.Pop()
	}

	for _, tx := range txs {
		p.knownOrderTxs.Add(tx.Hash())
	}
	return p2p.Send(p.rw, OrderTxMsg, txs)
}

// SendTransactions sends transactions to the peer and includes the hashes
// in its transaction hash set for future reference.
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

// SendNewBlockHashes announces the availability of a number of blocks through
// a hash notification.
func (p *Peer) SendNewBlockHashes(hashes []common.Hash, numbers []uint64) error {
	// Mark all the block hashes as known, but ensure we don't overflow our limits
	for p.knownBlocks.Cardinality() > max(0, MaxKnownBlocks-len(hashes)) {
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
		for p.knownBlocks.Cardinality() >= MaxKnownBlocks {
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
	for p.knownBlocks.Cardinality() >= MaxKnownBlocks {
		p.knownBlocks.Pop()
	}
	p.knownBlocks.Add(block.Hash())
	return p2p.Send(p.rw, NewBlockMsg, []interface{}{block, td})
}

// AsyncSendNewBlock queues an entire block for propagation to a remote peer. If
// the peer's broadcast queue is full, the event is silently dropped.
func (p *Peer) AsyncSendNewBlock(block *types.Block, td *big.Int) {
	select {
	case p.queuedBlocks <- &propEvent{block: block, td: td}:
		// Mark all the block hash as known, but ensure we don't overflow our limits
		for p.knownBlocks.Cardinality() >= MaxKnownBlocks {
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

// SendBlockBodies sends a batch of block contents to the remote peer.
func (p *Peer) SendBlockBodies(bodies []*BlockBody) error {
	return p2p.Send(p.rw, BlockBodiesMsg, BlockBodiesPacket(bodies))
}

// SendBlockBodiesRLP sends a batch of block contents to the remote peer from
// an already RLP encoded format.
func (p *Peer) SendBlockBodiesRLP(bodies []rlp.RawValue) error {
	return p2p.Send(p.rw, BlockBodiesMsg, bodies)
}

// SendNodeDataRLP sends a batch of arbitrary internal data, corresponding to the
// hashes requested.
func (p *Peer) SendNodeData(data [][]byte) error {
	return p2p.Send(p.rw, NodeDataMsg, data)
}

// SendReceiptsRLP sends a batch of transaction receipts, corresponding to the
// ones requested from an already RLP encoded format.
func (p *Peer) SendReceiptsRLP(receipts []rlp.RawValue) error {
	return p2p.Send(p.rw, ReceiptsMsg, receipts)
}

func (p *Peer) SendVote(vote *types.Vote) error {
	for p.knownVote.Cardinality() >= MaxKnownVote {
		p.knownVote.Pop()
	}

	p.knownVote.Add(vote.Hash())
	return p2p.Send(p.rw, VoteMsg, vote)
}

/*
func (p *Peer) AsyncSendVote() {

}
*/
func (p *Peer) SendTimeout(timeout *types.Timeout) error {
	for p.knownTimeout.Cardinality() >= MaxKnownTimeout {
		p.knownTimeout.Pop()
	}

	p.knownTimeout.Add(timeout.Hash())
	return p2p.Send(p.rw, TimeoutMsg, timeout)
}

/*
func (p *Peer) AsyncSendTimeout() {

}
*/
func (p *Peer) SendSyncInfo(syncInfo *types.SyncInfo) error {
	for p.knownSyncInfo.Cardinality() >= MaxKnownSyncInfo {
		p.knownSyncInfo.Pop()
	}

	p.knownSyncInfo.Add(syncInfo.Hash())
	return p2p.Send(p.rw, SyncInfoMsg, syncInfo)
}

/*
func (p *Peer) AsyncSendSyncInfo() {

}
*/

// RequestOneHeader is a wrapper around the header query functions to fetch a
// single header. It is used solely by the fetcher.
func (p *Peer) RequestOneHeader(hash common.Hash) error {
	p.Log().Debug("Fetching single header", "hash", hash)
	return p2p.Send(p.rw, GetBlockHeadersMsg, &GetBlockHeadersPacket{Origin: HashOrNumber{Hash: hash}, Amount: uint64(1), Skip: uint64(0), Reverse: false})
}

// RequestHeadersByHash fetches a batch of blocks' headers corresponding to the
// specified header query, based on the hash of an origin block.
func (p *Peer) RequestHeadersByHash(origin common.Hash, amount int, skip int, reverse bool) error {
	p.Log().Debug("Fetching batch of headers", "count", amount, "fromhash", origin, "skip", skip, "reverse", reverse)
	return p2p.Send(p.rw, GetBlockHeadersMsg, &GetBlockHeadersPacket{Origin: HashOrNumber{Hash: origin}, Amount: uint64(amount), Skip: uint64(skip), Reverse: reverse})
}

// RequestHeadersByNumber fetches a batch of blocks' headers corresponding to the
// specified header query, based on the number of an origin block.
func (p *Peer) RequestHeadersByNumber(origin uint64, amount int, skip int, reverse bool) error {
	p.Log().Debug("Fetching batch of headers", "count", amount, "fromnum", origin, "skip", skip, "reverse", reverse)
	return p2p.Send(p.rw, GetBlockHeadersMsg, &GetBlockHeadersPacket{Origin: HashOrNumber{Number: origin}, Amount: uint64(amount), Skip: uint64(skip), Reverse: reverse})
}

// RequestBodies fetches a batch of blocks' bodies corresponding to the hashes
// specified.
func (p *Peer) RequestBodies(hashes []common.Hash) error {
	p.Log().Debug("Fetching batch of block bodies", "count", len(hashes))
	return p2p.Send(p.rw, GetBlockBodiesMsg, hashes)
}

// RequestNodeData fetches a batch of arbitrary data from a node's known state
// data, corresponding to the specified hashes.
func (p *Peer) RequestNodeData(hashes []common.Hash) error {
	p.Log().Debug("Fetching batch of state data", "count", len(hashes))
	return p2p.Send(p.rw, GetNodeDataMsg, hashes)
}

// RequestReceipts fetches a batch of transaction receipts from a remote node.
func (p *Peer) RequestReceipts(hashes []common.Hash) error {
	p.Log().Debug("Fetching batch of receipts", "count", len(hashes))
	return p2p.Send(p.rw, GetReceiptsMsg, hashes)
}

// RequestTxs fetches a batch of transactions from a remote node.
func (p *Peer) RequestTxs(hashes []common.Hash) error {
	p.Log().Debug("Fetching batch of transactions", "count", len(hashes))
	return p2p.Send(p.rw, GetPooledTransactionsMsg, hashes)
}

// String implements fmt.Stringer.
func (p *Peer) String() string {
	return fmt.Sprintf("Peer %s [%s]", p.id,
		fmt.Sprintf("eth/%2d", p.version),
	)
}

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
	"math"
	"math/big"
	"sync"
	"sync/atomic"
	"time"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/common/lru"
	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/forkid"
	"github.com/XinFinOrg/XDPoSChain/core/txpool"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/eth/bft"
	"github.com/XinFinOrg/XDPoSChain/eth/downloader"
	"github.com/XinFinOrg/XDPoSChain/eth/fetcher"
	ethproto "github.com/XinFinOrg/XDPoSChain/eth/protocols/eth"
	"github.com/XinFinOrg/XDPoSChain/ethdb"
	"github.com/XinFinOrg/XDPoSChain/event"
	"github.com/XinFinOrg/XDPoSChain/log"
	"github.com/XinFinOrg/XDPoSChain/p2p"
	"github.com/XinFinOrg/XDPoSChain/params"
)

const (
	// txChanSize is the size of channel listening to NewTxsEvent.
	// The number is referenced from the size of tx pool.
	txChanSize = 4096

	// minimim number of peers to broadcast entire blocks and transactions to.
	minBroadcastPeers = 4
)

var (
	syncChallengeTimeout = 15 * time.Second // Time allowance for a node to reply to the DAO handshake challenge
)

// txPool defines the methods needed from a transaction pool implementation to
// support all the operations needed by the Ethereum protocol.
type txPool interface {
	// Has returns an indicator whether txpool has a transaction
	// cached with the given hash.
	Has(hash common.Hash) bool

	// Get retrieves the transaction from local txpool with given
	// tx hash.
	Get(hash common.Hash) *types.Transaction

	// Add should add the given transactions to the pool.
	Add(txs []*types.Transaction, sync bool) []error

	// Pending should return pending transactions.
	// The slice should be modifiable by the caller.
	Pending(filter txpool.PendingFilter) map[common.Address][]*txpool.LazyTransaction

	// SubscribeTransactions subscribes to new transaction events. The subscriber
	// can decide whether to receive notifications only for newly seen transactions
	// or also for reorged out ones.
	SubscribeTransactions(ch chan<- core.NewTxsEvent, reorgs bool) event.Subscription
}

// orderPool defines the methods needed from an order pool implementation to
// support all the operations needed by the Ethereum protocol.
type orderPool interface {
	// AddRemotes should add the given transactions to the pool.
	AddRemotes([]*types.OrderTransaction) []error

	// Pending should return pending transactions.
	// The slice should be modifiable by the caller.
	Pending() (map[common.Address]types.OrderTransactions, error)

	// SubscribeTxPreEvent should return an event subscription of
	// TxPreEvent and send events to the given channel.
	SubscribeTxPreEvent(chan<- core.OrderTxPreEvent) event.Subscription
}

// lendingPool defines the methods needed from a lending pool implementation to
// support all the operations needed by the Ethereum protocol.
type lendingPool interface {
	// AddRemotes should add the given transactions to the pool.
	AddRemotes([]*types.LendingTransaction) []error

	// Pending should return pending transactions.
	// The slice should be modifiable by the caller.
	Pending() (map[common.Address]types.LendingTransactions, error)

	// SubscribeTxPreEvent should return an event subscription of
	// TxPreEvent and send events to the given channel.
	SubscribeTxPreEvent(chan<- core.LendingTxPreEvent) event.Subscription
}

type ProtocolManager struct {
	networkId  uint64
	forkFilter forkid.Filter // Fork ID filter, constant across the lifetime of the node

	snapSync  uint32 // Flag whether snap sync is enabled (gets disabled if we already have blocks)
	acceptTxs uint32 // Flag whether we're considered synchronised (enables transaction processing)

	txpool      txPool
	orderpool   orderPool
	lendingpool lendingPool
	blockchain  *core.BlockChain
	maxPeers    int

	downloader   *downloader.Downloader
	blockFetcher *fetcher.BlockFetcher
	txFetcher    *fetcher.TxFetcher
	peers        *peerSet
	bft          *bft.Bfter

	eventMux      *event.TypeMux
	txsCh         chan core.NewTxsEvent
	orderTxCh     chan core.OrderTxPreEvent
	lendingTxCh   chan core.LendingTxPreEvent
	txsSub        event.Subscription
	orderTxSub    event.Subscription
	lendingTxSub  event.Subscription
	minedBlockSub *event.TypeMuxSubscription

	// channels for fetcher, syncer, txsyncLoop
	newPeerCh   chan *peer
	syncReqCh   chan *peer // Peers announcing a chain heavier than ours
	txsyncCh    chan *txsync
	quitSync    chan struct{}
	noMorePeers chan struct{}

	// wait group is used for graceful shutdowns during downloading
	// and processing
	wg sync.WaitGroup

	// Test fields or hooks
	broadcastTxAnnouncesOnly bool // Testing field, disable transaction propagation

	knownTxs       *lru.Cache[common.Hash, struct{}]
	knowOrderTxs   *lru.Cache[common.Hash, struct{}]
	knowLendingTxs *lru.Cache[common.Hash, struct{}]

	// V2 messages
	knownVotes     *lru.Cache[common.Hash, struct{}]
	knownSyncInfos *lru.Cache[common.Hash, struct{}]
	knownTimeouts  *lru.Cache[common.Hash, struct{}]
	bftQueue       *bftQueue // BFT messages received while synchronising
}

// NewProtocolManagerEx add order pool to protocol
func NewProtocolManagerEx(config *params.ChainConfig, mode downloader.SyncMode, networkID uint64, mux *event.TypeMux, txpool txPool, orderpool orderPool, lendingpool lendingPool, engine consensus.Engine, blockchain *core.BlockChain, chaindb ethdb.Database) (*ProtocolManager, error) {
	protocol, err := NewProtocolManager(config, mode, networkID, mux, txpool, engine, blockchain, chaindb)
	if err != nil {
		return nil, err
	}
	protocol.addOrderPoolProtocol(orderpool)
	protocol.addLendingPoolProtocol(lendingpool)
	return protocol, nil
}

// NewProtocolManager returns a new ethereum sub protocol manager. The Ethereum sub protocol manages peers capable
// with the ethereum network.
func NewProtocolManager(config *params.ChainConfig, mode downloader.SyncMode, networkID uint64, mux *event.TypeMux, txpool txPool, engine consensus.Engine, blockchain *core.BlockChain, chaindb ethdb.Database) (*ProtocolManager, error) {
	// Create the protocol manager with the base fields
	manager := &ProtocolManager{
		networkId:      networkID,
		forkFilter:     forkid.NewFilter(blockchain),
		eventMux:       mux,
		txpool:         txpool,
		blockchain:     blockchain,
		peers:          newPeerSet(),
		newPeerCh:      make(chan *peer),
		syncReqCh:      make(chan *peer, 1),
		noMorePeers:    make(chan struct{}),
		txsyncCh:       make(chan *txsync),
		quitSync:       make(chan struct{}),
		knownTxs:       lru.NewCache[common.Hash, struct{}](ethproto.MaxKnownTxs),
		knowOrderTxs:   lru.NewCache[common.Hash, struct{}](ethproto.MaxKnownOrderTxs),
		knowLendingTxs: lru.NewCache[common.Hash, struct{}](ethproto.MaxKnownLendingTxs),
		knownVotes:     lru.NewCache[common.Hash, struct{}](ethproto.MaxKnownVote),
		knownSyncInfos: lru.NewCache[common.Hash, struct{}](ethproto.MaxKnownSyncInfo),
		knownTimeouts:  lru.NewCache[common.Hash, struct{}](ethproto.MaxKnownTimeout),
		bftQueue:       newBFTQueue(),
		orderpool:      nil,
		lendingpool:    nil,
		orderTxSub:     nil,
		lendingTxSub:   nil,
	}
	// Figure out whether to allow fast sync or not
	if mode == downloader.FastSync && blockchain.CurrentBlock().Number.Sign() > 0 {
		log.Warn("Blockchain not empty, fast sync disabled")
		mode = downloader.FullSync
	}
	if mode == downloader.FastSync {
		manager.snapSync = uint32(1)
	}

	var handleProposedBlock func(header *types.Header) error
	if config.XDPoS != nil {
		handleProposedBlock = func(header *types.Header) error {
			return engine.(*XDPoS.XDPoS).HandleProposedBlock(blockchain, header)
		}
	} else {
		handleProposedBlock = func(header *types.Header) error {
			return nil
		}
	}

	// Construct the different synchronisation mechanisms
	manager.downloader = downloader.New(chaindb, manager.eventMux, blockchain, nil, manager.removePeer, handleProposedBlock)

	validator := func(header *types.Header) error {
		return engine.VerifyHeader(blockchain, header, true)
	}

	heighter := func() uint64 {
		return blockchain.CurrentBlock().Number.Uint64()
	}

	inserter := func(block *types.Block) error {
		// If fast sync is running, deny importing weird blocks
		if atomic.LoadUint32(&manager.snapSync) == 1 {
			log.Warn("Discarded bad propagated block", "number", block.Number(), "hash", block.Hash())
			return nil
		}
		atomic.StoreUint32(&manager.acceptTxs, 1) // Mark initial sync done on any fetcher import
		return manager.blockchain.InsertBlock(block)
	}

	prepare := func(block *types.Block) error {
		// If fast sync is running, deny importing weird blocks
		if atomic.LoadUint32(&manager.snapSync) == 1 {
			log.Warn("Discarded bad propagated block", "number", block.Number(), "hash", block.Hash())
			return nil
		}
		atomic.StoreUint32(&manager.acceptTxs, 1) // Mark initial sync done on any fetcher import
		return manager.blockchain.PrepareBlock(block)
	}
	manager.blockFetcher = fetcher.NewBlockFetcher(blockchain.GetBlockByHash, validator, handleProposedBlock, manager.BroadcastBlock, heighter, inserter, prepare, manager.removePeer)

	fetchTx := func(peer string, hashes []common.Hash) error {
		p := manager.peers.Peer(peer)
		if p == nil {
			return errors.New("unknown peer")
		}
		return p.RequestTxs(hashes)
	}
	addTxs := func(txs []*types.Transaction) []error {
		return manager.txpool.Add(txs, false)
	}
	manager.txFetcher = fetcher.NewTxFetcher(txpool.Has, addTxs, fetchTx)

	//Define bft function
	broadcasts := bft.BroadcastFns{
		Vote:     manager.BroadcastVote,
		Timeout:  manager.BroadcastTimeout,
		SyncInfo: manager.BroadcastSyncInfo,
	}
	manager.bft = bft.New(broadcasts, blockchain, heighter)
	if blockchain.Config().XDPoS != nil {
		manager.bft.InitEpochNumber()
		manager.bft.SetConsensusFuns(engine)
	}

	return manager, nil
}

func (pm *ProtocolManager) addOrderPoolProtocol(orderpool orderPool) {
	pm.orderpool = orderpool
}

func (pm *ProtocolManager) addLendingPoolProtocol(lendingpool lendingPool) {
	pm.lendingpool = lendingpool
}

func (pm *ProtocolManager) removePeer(id string) {
	// Short circuit if the peer was already removed
	peer := pm.peers.Peer(id)
	if peer == nil {
		return
	}
	// Claim the removal exactly once; concurrent callers become no-ops.
	if !peer.markRemoved() {
		return
	}
	log.Debug("Removing Ethereum peer", "peer", id)

	// Unregister the peer from the downloader and Ethereum peer set
	pm.downloader.UnregisterPeer(id)
	pm.txFetcher.Drop(id)

	// Unregister should succeed: the guard above guarantees the peer is still
	// in the set.
	if err := pm.peers.Unregister(id); err != nil {
		log.Debug("Peer removal failed", "peer", id, "err", err)
	}
	// Hard disconnect at the networking layer
	peer.Peer.Disconnect(p2p.DiscUselessPeer)
}

// registerDownloaderPeer registers the peer with the downloader, undoing the
// registration if the peer's removal was claimed in the meantime; otherwise a
// stale entry would block a reconnect of the same node id. Returns
// DiscUselessPeer to abort the handshake, matching removePeer's disconnect
// reason.
func (pm *ProtocolManager) registerDownloaderPeer(p *peer) error {
	if err := pm.downloader.RegisterPeer(p.ID(), int(p.Version()), p); err != nil {
		return err
	}
	if p.removed.Load() {
		// Undo the registration; UnregisterPeer is a no-op if already removed.
		pm.downloader.UnregisterPeer(p.ID())
		return p2p.DiscUselessPeer
	}
	return nil
}

func (pm *ProtocolManager) Start(maxPeers int) {
	pm.maxPeers = maxPeers

	// broadcast and announce transactions (only new ones, not resurrected ones)
	pm.txsCh = make(chan core.NewTxsEvent, txChanSize)
	pm.txsSub = pm.txpool.SubscribeTransactions(pm.txsCh, false)
	pm.orderTxCh = make(chan core.OrderTxPreEvent, txChanSize)
	if pm.orderpool != nil {
		pm.orderTxSub = pm.orderpool.SubscribeTxPreEvent(pm.orderTxCh)
	}
	pm.lendingTxCh = make(chan core.LendingTxPreEvent, txChanSize)
	if pm.lendingpool != nil {
		pm.lendingTxSub = pm.lendingpool.SubscribeTxPreEvent(pm.lendingTxCh)
	}
	go pm.txBroadcastLoop()
	go pm.orderTxBroadcastLoop()
	go pm.lendingTxBroadcastLoop()
	// broadcast mined blocks
	pm.minedBlockSub = pm.eventMux.Subscribe(core.NewMinedBlockEvent{})
	go pm.minedBroadcastLoop()

	// start sync handlers
	go pm.syncer()

	go pm.syncStatusLogger()
	go pm.txsyncLoop64() // TODO(karalabe): Legacy initial tx echange, drop with eth/64.
}

func (pm *ProtocolManager) Stop() {
	log.Info("Stopping Ethereum protocol")

	pm.txsSub.Unsubscribe() // quits txBroadcastLoop
	if pm.orderTxSub != nil {
		pm.orderTxSub.Unsubscribe()
	}
	if pm.lendingTxSub != nil {
		pm.lendingTxSub.Unsubscribe()
	}
	pm.minedBlockSub.Unsubscribe() // quits blockBroadcastLoop

	// Quit the sync loop.
	// After this send has completed, no new peers will be accepted.
	pm.noMorePeers <- struct{}{}

	// Quit fetcher, txsyncLoop.
	close(pm.quitSync)

	// Disconnect existing sessions.
	// This also closes the gate for any new registrations on the peer set.
	// sessions which are already established but not added to pm.peers yet
	// will exit when they try to register.
	pm.peers.Close()

	// Wait for all peer handler goroutines and the loops to come down.
	pm.wg.Wait()

	log.Info("Ethereum protocol stopped")
}

// RunPeer implements ethproto.Backend: it performs the node layer's side of the peer
// life cycle (the handshake, the bookkeeping and the sync kick-off) and then
// hands the peer over to the wire layer's inbound message loop.
func (pm *ProtocolManager) RunPeer(p *ethproto.Peer, handler ethproto.Handler) error {
	peer := &peer{Peer: p}
	select {
	case pm.newPeerCh <- peer:
		pm.wg.Add(1)
		defer pm.wg.Done()

		return pm.handle(peer, handler)
	case <-pm.quitSync:
		return p2p.DiscQuitting
	}
}

// handle is the callback invoked to manage the life cycle of an eth peer. When
// this function terminates, the peer is disconnected.
func (pm *ProtocolManager) handle(p *peer, handler ethproto.Handler) error {
	// Ignore maxPeers if this is a trusted peer
	if pm.peers.Len() >= pm.maxPeers && !p.Peer.Info().Network.Trusted {
		return p2p.DiscTooManyPeers
	}
	p.Log().Debug("Ethereum peer connected", "name", p.Name())

	// Execute the Ethereum handshake
	var (
		genesis = pm.blockchain.Genesis()
		head    = pm.blockchain.CurrentHeader()
		hash    = head.Hash()
		number  = head.Number.Uint64()
		td      = pm.blockchain.GetTd(hash, number)
	)
	if err := p.Handshake(pm.networkId, td, hash, genesis.Hash(), forkid.NewID(pm.blockchain.Config(), genesis, number), pm.forkFilter); err != nil {
		p.Log().Debug("Ethereum handshake failed", "err", err)
		return err
	}
	// Register the peer locally
	if err := pm.peers.Register(p); err != nil {
		p.Log().Error("Ethereum peer registration failed", "err", err)
		return err
	}
	defer pm.removePeer(p.ID())

	// Register the peer in the downloader. If the downloader considers it banned, we disconnect
	if err := pm.registerDownloaderPeer(p); err != nil {
		return err
	}
	p.Log().Info("Register peer", "nodeid", p.Peer.Peer.ID().String(), "version", p.Version(), "addr", p.RemoteAddr())
	// Propagate existing transactions. new transactions appearing
	// after this will be sent via broadcasts.
	pm.syncTransactions(p)

	// If we're DAO hard-fork aware, validate any remote peer with regard to the hard-fork
	if daoBlock := pm.blockchain.Config().DAOForkBlock; daoBlock != nil {
		// Request the peer's DAO fork header for extra-data validation
		if err := p.RequestHeadersByNumber(daoBlock.Uint64(), 1, 0, false); err != nil {
			return err
		}
		// Start a timer to disconnect if the peer doesn't reply in time
		p.forkDrop = time.AfterFunc(syncChallengeTimeout, func() {
			p.Log().Debug("Timed out DAO fork-check, dropping")
			pm.removePeer(p.ID())
		})
		// Make sure it's cleaned up if the peer dies off
		defer func() {
			if p.forkDrop != nil {
				p.forkDrop.Stop()
				p.forkDrop = nil
			}
		}()
	}
	// Hand the peer over to the wire layer's inbound message loop
	return handler(p.Peer)
}

// BroadcastBlock will either propagate a block to a subset of it's peers, or
// will only announce it's availability (depending what's requested).
func (pm *ProtocolManager) BroadcastBlock(block *types.Block, propagate bool) {
	hash := block.Hash()
	peers := pm.peers.PeersWithoutBlock(hash)

	// If propagation is requested, send to a subset of the peer
	if propagate {
		// Calculate the TD of the block (it's not imported yet, so block.Td is not valid)
		var td *big.Int
		if parent := pm.blockchain.GetBlock(block.ParentHash(), block.NumberU64()-1); parent != nil {
			td = new(big.Int).Add(block.Difficulty(), pm.blockchain.GetTd(block.ParentHash(), block.NumberU64()-1))
		} else {
			log.Error("Propagating dangling block", "number", block.Number(), "hash", hash)
			return
		}
		// Send the block to a subset of our peers
		for _, peer := range peers {
			peer.SendNewBlock(block, td)
		}
		log.Trace("Propagated block", "hash", hash, "recipients", len(peers), "duration", common.PrettyDuration(time.Since(block.ReceivedAt)))
		return
	}
	// Otherwise if the block is indeed in out own chain, announce it
	if pm.blockchain.HasBlock(hash, block.NumberU64()) {
		for _, peer := range peers {
			peer.SendNewBlockHashes([]common.Hash{hash}, []uint64{block.NumberU64()})
		}
		log.Trace("Announced block", "hash", hash, "recipients", len(peers), "duration", common.PrettyDuration(time.Since(block.ReceivedAt)))
	}
}

// BroadcastTransactions will propagate a batch of transactions to all peers which are not known to
// already have the given transaction.
func (pm *ProtocolManager) BroadcastTransactions(txs types.Transactions, propagate bool) {
	var (
		txset = make(map[*peer][]common.Hash)
		annos = make(map[*peer][]common.Hash)
	)
	// Broadcast transactions to a batch of peers not knowing about it
	if propagate {
		for _, tx := range txs {
			peers := pm.peers.PeersWithoutTx(tx.Hash())

			// Send the block to a subset of our peers
			transferLen := int(math.Sqrt(float64(len(peers))))
			if transferLen < minBroadcastPeers {
				transferLen = minBroadcastPeers
			}
			if transferLen > len(peers) {
				transferLen = len(peers)
			}
			transfer := peers[:transferLen]
			for _, peer := range transfer {
				txset[peer] = append(txset[peer], tx.Hash())
			}
			log.Trace("Broadcast transaction", "hash", tx.Hash(), "recipients", len(peers))
		}
		for peer, hashes := range txset {
			peer.AsyncSendTransactions(hashes)
		}
		return
	}
	// Otherwise only broadcast the announcement to peers
	for _, tx := range txs {
		peers := pm.peers.PeersWithoutTx(tx.Hash())
		for _, peer := range peers {
			annos[peer] = append(annos[peer], tx.Hash())
		}
	}
	for peer, hashes := range annos {
		if peer.Version() >= ethproto.XDC165 {
			peer.AsyncSendPooledTransactionHashes(hashes)
		} else {
			peer.AsyncSendTransactions(hashes)
		}
	}
}

// BroadcastVote will propagate a Vote to all peers which are not known to
// already have the given vote.
func (pm *ProtocolManager) BroadcastVote(vote *types.Vote) {
	hash := vote.Hash()
	peers := pm.peers.PeersWithoutVote(hash)
	if len(peers) > 0 {
		for _, peer := range peers {
			err := peer.SendVote(vote)
			if err != nil {
				log.Debug("[BroadcastVote] Fail to broadcast vote message", "peerId", peer.ID(), "version", peer.Version(), "blockNum", vote.ProposedBlockInfo.Number, "err", err)
				pm.removePeer(peer.ID())
			}
		}
		log.Trace("Propagated Vote", "vote hash", vote.Hash(), "voted block hash", vote.ProposedBlockInfo.Hash.Hex(), "number", vote.ProposedBlockInfo.Number, "round", vote.ProposedBlockInfo.Round, "recipients", len(peers))
	}
}

// BroadcastTimeout will propagate a Timeout to all peers which are not known to
// already have the given timeout.
func (pm *ProtocolManager) BroadcastTimeout(timeout *types.Timeout) {
	hash := timeout.Hash()
	peers := pm.peers.PeersWithoutTimeout(hash)
	if len(peers) > 0 {
		for _, peer := range peers {
			err := peer.SendTimeout(timeout)
			if err != nil {
				log.Debug("[BroadcastTimeout] Fail to broadcast timeout message, remove peer", "peerId", peer.ID(), "version", peer.Version(), "timeout", timeout, "err", err)
				pm.removePeer(peer.ID())
			}
		}
		log.Trace("Propagated Timeout", "hash", hash, "recipients", len(peers))
	}
}

// BroadcastSyncInfo will propagate a SyncInfo to all peers which are not known to
// already have the given SyncInfo.
func (pm *ProtocolManager) BroadcastSyncInfo(syncInfo *types.SyncInfo) {
	hash := syncInfo.Hash()
	peers := pm.peers.PeersWithoutSyncInfo(hash)
	if len(peers) > 0 {
		for _, peer := range peers {
			err := peer.SendSyncInfo(syncInfo)
			if err != nil {
				log.Debug("[BroadcastSyncInfo] Fail to broadcast syncInfo message, remove peer", "peerId", peer.ID(), "version", peer.Version(), "syncInfo", syncInfo, "err", err)
				pm.removePeer(peer.ID())
			}
		}
		log.Trace("Propagated SyncInfo", "hash", hash, "recipients", len(peers))
	}
}

// OrderBroadcastTx will propagate a transaction to all peers which are not known to
// already have the given transaction.
func (pm *ProtocolManager) OrderBroadcastTx(hash common.Hash, tx *types.OrderTransaction) {
	// Broadcast transaction to a batch of peers not knowing about it
	peers := pm.peers.OrderPeersWithoutTx(hash)
	//FIXME include this again: peers = peers[:int(math.Sqrt(float64(len(peers))))]
	for _, peer := range peers {
		peer.SendOrderTransactions(types.OrderTransactions{tx})
	}
	log.Trace("Broadcast order transaction", "hash", hash, "recipients", len(peers))
}

// LendingBroadcastTx will propagate a transaction to all peers which are not known to
// already have the given transaction.
func (pm *ProtocolManager) LendingBroadcastTx(hash common.Hash, tx *types.LendingTransaction) {
	// Broadcast transaction to a batch of peers not knowing about it
	peers := pm.peers.LendingPeersWithoutTx(hash)
	//FIXME include this again: peers = peers[:int(math.Sqrt(float64(len(peers))))]
	for _, peer := range peers {
		peer.SendLendingTransactions(types.LendingTransactions{tx})
	}
	log.Trace("Broadcast lending transaction", "hash", hash, "recipients", len(peers))
}

// minedBroadcastLoop broadcast loop
func (pm *ProtocolManager) minedBroadcastLoop() {
	// automatically stops if unsubscribe
	for obj := range pm.minedBlockSub.Chan() {
		switch ev := obj.Data.(type) {
		case core.NewMinedBlockEvent:
			pm.BroadcastBlock(ev.Block, true) // First propagate block to peers
			//self.BroadcastBlock(ev.Block, false) // Only then announce to the rest
		}
	}
}

func (pm *ProtocolManager) txBroadcastLoop() {
	for {
		select {
		case event := <-pm.txsCh:
			// For testing purpose only, disable propagation
			if pm.broadcastTxAnnouncesOnly {
				pm.BroadcastTransactions(event.Txs, false)
				continue
			}
			pm.BroadcastTransactions(event.Txs, true)  // First propagate transactions to peers
			pm.BroadcastTransactions(event.Txs, false) // Only then announce to the rest

		// Err() channel will be closed when unsubscribing.
		case <-pm.txsSub.Err():
			return
		}
	}
}

// orderTxBroadcastLoop broadcast order
func (pm *ProtocolManager) orderTxBroadcastLoop() {
	if pm.orderTxSub == nil {
		return
	}
	for {
		select {
		case event := <-pm.orderTxCh:
			pm.OrderBroadcastTx(event.Tx.Hash(), event.Tx)

			// Err() channel will be closed when unsubscribing.
		case <-pm.orderTxSub.Err():
			return
		}
	}
}

// lendingTxBroadcastLoop broadcast order
func (pm *ProtocolManager) lendingTxBroadcastLoop() {
	if pm.lendingTxSub == nil {
		return
	}
	for {
		select {
		case event := <-pm.lendingTxCh:
			pm.LendingBroadcastTx(event.Tx.Hash(), event.Tx)

			// Err() channel will be closed when unsubscribing.
		case <-pm.lendingTxSub.Err():
			return
		}
	}
}

// NodeInfo represents a short summary of the Ethereum sub-protocol metadata
// known about the host peer.
type NodeInfo struct {
	Network    uint64              `json:"network"`    // XDC network ID (50=xinfin, 51=apothem, 551=devnet)
	Difficulty *big.Int            `json:"difficulty"` // Total difficulty of the host's blockchain
	Genesis    common.Hash         `json:"genesis"`    // SHA3 hash of the host's genesis block
	Config     *params.ChainConfig `json:"config"`     // Chain configuration for the fork rules
	Head       common.Hash         `json:"head"`       // SHA3 hash of the host's best owned block
}

// NodeInfo retrieves some protocol metadata about the running host node.
func (pm *ProtocolManager) NodeInfo() *NodeInfo {
	currentBlock := pm.blockchain.CurrentBlock()
	config := pm.blockchain.Config()
	if config != nil {
		config = config.CloneForJSON()
	}
	return &NodeInfo{
		Network:    pm.networkId,
		Difficulty: pm.blockchain.GetTd(currentBlock.Hash(), currentBlock.Number.Uint64()),
		Genesis:    pm.blockchain.Genesis().Hash(),
		Config:     config,
		Head:       currentBlock.Hash(),
	}
}

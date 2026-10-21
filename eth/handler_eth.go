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
	"sync/atomic"
	"time"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus/misc"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/eth/fetcher"
	ethproto "github.com/XinFinOrg/XDPoSChain/eth/protocols/eth"
	"github.com/XinFinOrg/XDPoSChain/log"
	"github.com/XinFinOrg/XDPoSChain/p2p/enode"
	"github.com/XinFinOrg/XDPoSChain/trie"
)

// ethHandler adapts the protocol manager to the wire layer's Backend interface,
// erasing the concrete type of the metadata the protocol manager exposes.
type ethHandler struct{ *ProtocolManager }

// NodeInfo implements ethproto.Backend, returning the node metadata the p2p layer
// reports for this capability.
func (h ethHandler) NodeInfo() interface{} { return h.ProtocolManager.NodeInfo() }

// Chain implements ethproto.Backend.
func (pm *ProtocolManager) Chain() *core.BlockChain { return pm.blockchain }

// TxPool implements ethproto.Backend.
func (pm *ProtocolManager) TxPool() ethproto.TxPool { return pm.txpool }

// AcceptTxs implements ethproto.Backend. The node ignores inbound transaction
// traffic until it has caught up with the chain.
func (pm *ProtocolManager) AcceptTxs() bool { return atomic.LoadUint32(&pm.acceptTxs) != 0 }

// PeerInfo implements ethproto.Backend, returning the metadata the p2p layer reports
// for a connected peer.
func (pm *ProtocolManager) PeerInfo(id enode.ID) interface{} {
	if p := pm.peers.Peer(fmt.Sprintf("%x", id[:8])); p != nil {
		return p.Info()
	}
	return nil
}

// Handle implements ethproto.Backend. It is invoked for every inbound message the
// wire layer decoded but does not act on itself: the data-retrieval queries are
// served by the wire layer, everything here is a reaction to peer activity.
//
// Everything the common path needs lives on the wire peer: its id, the marks and
// the head bookkeeping. The node-layer peer is looked up only in the two branches
// that need node state (the DAO fork-check timer and the syncer hand-off), and a
// miss there skips that reaction instead of failing the message loop: a miss means
// the peer is already being removed, which is idempotent elsewhere. Upstream
// returns "unregistered during callback" there instead; skipping is deliberate,
// and costs at most one missed sync kick-off on the syncer hand-off, which
// syncer()'s BestPeer loop retries.
func (pm *ProtocolManager) Handle(p *ethproto.Peer, packet ethproto.Packet, size uint32) error {
	switch packet := packet.(type) {
	case *ethproto.BlockHeadersPacket:
		headers := []*types.Header(*packet)
		if err := types.SanityCheckHeaders(headers); err != nil {
			return err
		}
		// If no headers were received, but we're expending a DAO fork check, maybe it's that
		if len(headers) == 0 {
			if peer := pm.peers.Peer(p.ID()); peer != nil && peer.forkDrop != nil {
				// Possibly an empty reply to the fork header checks, sanity check TDs
				verifyDAO := true

				// If we already have a DAO header, we can check the peer's TD against it. If
				// the peer's ahead of this, it too must have a reply to the DAO check
				if daoHeader := pm.blockchain.GetHeaderByNumber(pm.blockchain.Config().DAOForkBlock.Uint64()); daoHeader != nil {
					if _, td := p.Head(); td.Cmp(pm.blockchain.GetTd(daoHeader.Hash(), daoHeader.Number.Uint64())) >= 0 {
						verifyDAO = false
					}
				}
				// If we're seemingly on the same chain, disable the drop timer
				if verifyDAO {
					peer.Log().Debug("Seems to be on the same side of the DAO fork")
					peer.forkDrop.Stop()
					peer.forkDrop = nil
					return nil
				}
			}
		}
		// Filter out any explicitly requested headers, deliver the rest to the downloader
		filter := len(headers) == 1
		if filter {
			// If it's a potential DAO fork check, validate against the rules
			if peer := pm.peers.Peer(p.ID()); peer != nil && peer.forkDrop != nil && pm.blockchain.Config().DAOForkBlock.Cmp(headers[0].Number) == 0 {
				// Disable the fork drop timer
				peer.forkDrop.Stop()
				peer.forkDrop = nil

				// Validate the header and either drop the peer or continue
				if err := misc.VerifyDAOHeaderExtraData(pm.blockchain.Config(), headers[0]); err != nil {
					peer.Log().Debug("Verified to be on the other side of the DAO fork, dropping")
					return err
				}
				peer.Log().Debug("Verified to be on the same side of the DAO fork")
				return nil
			}
			// Irrelevant of the fork checks, send the header to the fetcher just in case
			headers = pm.blockFetcher.FilterHeaders(p.ID(), headers, time.Now())
		}
		if len(headers) > 0 || !filter {
			if err := pm.downloader.DeliverHeaders(p.ID(), headers); err != nil {
				log.Debug("Failed to deliver headers", "err", err)
			}
		}

	case *ethproto.BlockBodiesPacket:
		request := *packet
		if err := request.SanityCheck(); err != nil {
			return err
		}
		// Deliver them all to the downloader for queuing
		transactions := make([][]*types.Transaction, len(request))
		uncles := make([][]*types.Header, len(request))

		for i, body := range request {
			transactions[i] = body.Transactions
			uncles[i] = body.Uncles
		}
		// Filter out any explicitly requested bodies, deliver the rest to the downloader
		filter := len(transactions) > 0 || len(uncles) > 0
		if filter {
			transactions, uncles = pm.blockFetcher.FilterBodies(p.ID(), transactions, uncles, time.Now())
		}
		if len(transactions) > 0 || len(uncles) > 0 || !filter {
			if err := pm.downloader.DeliverBodies(p.ID(), transactions, uncles); err != nil {
				log.Debug("Failed to deliver bodies", "err", err)
			}
		}

	case *ethproto.NodeDataPacket:
		// A batch of node state data arrived to one of our previous requests:
		// deliver all to the downloader
		if err := pm.downloader.DeliverNodeData(p.ID(), *packet); err != nil {
			log.Debug("Failed to deliver node state data", "err", err)
		}

	case *ethproto.ReceiptsPacket:
		// A batch of receipts arrived to one of our previous requests: deliver
		// all to the downloader
		if err := pm.downloader.DeliverReceipts(p.ID(), [][]*types.Receipt(*packet)); err != nil {
			log.Debug("Failed to deliver receipts", "err", err)
		}

	case *ethproto.NewBlockHashesPacket:
		announces := *packet

		// Mark the hashes as present at the remote node and track the highest
		// plausible announced block as the peer's live tip.
		height := pm.blockchain.CurrentBlock().Number.Uint64()
		var tip uint64
		for _, block := range announces {
			p.MarkBlock(block.Hash)
			if fetcher.IsPlausibleAnnouncement(block.Number, height) {
				tip = max(tip, block.Number)
			}
		}
		if tip > 0 {
			p.SetTipNumber(tip)
		}
		// Schedule all the unknown hashes for retrieval
		unknown := make(ethproto.NewBlockHashesPacket, 0, len(announces))
		for _, block := range announces {
			if !pm.blockchain.HasBlock(block.Hash, block.Number) {
				unknown = append(unknown, block)
			}
		}
		for _, block := range unknown {
			pm.blockFetcher.Notify(p.ID(), block.Hash, block.Number, time.Now(), p.RequestOneHeader, p.RequestBodies)
		}

	case *ethproto.NewBlockPacket:
		request := packet
		if hash := types.CalcUncleHash(request.Block.Uncles()); hash != request.Block.UncleHash() {
			log.Warn("Propagated block has invalid uncles", "have", hash, "exp", request.Block.UncleHash())
			break // TODO(karalabe): return error eventually, but wait a few releases
		}
		if hash := types.DeriveSha(request.Block.Transactions(), trie.NewStackTrie(nil)); hash != request.Block.TxHash() {
			log.Warn("Propagated block has invalid body", "have", hash, "exp", request.Block.TxHash())
			break // TODO(karalabe): return error eventually, but wait a few releases
		}
		if err := request.SanityCheck(); err != nil {
			return err
		}
		request.Block.ReceivedFrom = p

		// Mark the peer as owning the block, track its tip (only when the block
		// number is within the fetcher's plausibility window), and schedule it
		// for import
		p.MarkBlock(request.Block.Hash())
		if fetcher.IsPlausibleAnnouncement(request.Block.NumberU64(), pm.blockchain.CurrentBlock().Number.Uint64()) {
			p.SetTipNumber(request.Block.NumberU64())
		}
		pm.blockFetcher.Enqueue(p.ID(), request.Block)

		// Assuming the block is importable by the peer, but possibly not yet done so,
		// calculate the head hash and TD that the peer truly must have.
		var (
			trueHead = request.Block.ParentHash()
			trueTD   = new(big.Int).Sub(request.TD, request.Block.Difficulty())
		)
		// Update the peers total difficulty if better than the previous
		if _, td := p.Head(); trueTD.Cmp(td) > 0 {
			p.SetHead(trueHead, trueTD)

			// Schedule a sync if above ours. Note, this will not fire a sync for a gap of
			// a singe block (as the true TD is below the propagated block), however this
			// scenario should easily be covered by the fetcher.
			currentBlock := pm.blockchain.CurrentBlock()
			if trueTD.Cmp(pm.blockchain.GetTd(currentBlock.Hash(), currentBlock.Number.Uint64())) > 0 {
				// The syncer is handed the node-layer peer; one that is already
				// gone has nobody to sync from.
				if peer := pm.peers.Peer(p.ID()); peer != nil {
					pm.requestSync(peer)
				}
			}
		}

	case *ethproto.NewPooledTransactionHashesPacket:
		// New transaction announcement arrived: mark them and schedule retrieval
		hashes := []common.Hash(*packet)
		for _, hash := range hashes {
			p.MarkTransaction(hash)
		}
		pm.txFetcher.Notify(p.ID(), hashes)

	case *ethproto.TransactionsPacket:
		pm.handleTransactions(p, []*types.Transaction(*packet), false)

	case *ethproto.PooledTransactionsPacket:
		pm.handleTransactions(p, []*types.Transaction(*packet), true)

	case *ethproto.OrderTransactionsPacket:
		txs := []*types.OrderTransaction(*packet)

		for _, tx := range txs {
			p.MarkOrderTransaction(tx.Hash())
			if pm.knowOrderTxs.Contains(tx.Hash()) {
				log.Trace("Discard known tx", "hash", tx.Hash(), "nonce", tx.Nonce())
			} else {
				pm.knowOrderTxs.Add(tx.Hash(), struct{}{})
			}
		}

		if pm.orderpool != nil {
			pm.orderpool.AddRemotes(txs)
		}

	case *ethproto.LendingTransactionsPacket:
		txs := []*types.LendingTransaction(*packet)

		for _, tx := range txs {
			p.MarkLendingTransaction(tx.Hash())
			if pm.knowLendingTxs.Contains(tx.Hash()) {
				log.Trace("Discard known tx", "hash", tx.Hash(), "nonce", tx.Nonce())
			} else {
				pm.knowLendingTxs.Add(tx.Hash(), struct{}{})
			}
		}

		if pm.lendingpool != nil {
			pm.lendingpool.AddRemotes(txs)
		}

	case *ethproto.VotePacket:
		vote := (*types.Vote)(packet)
		p.MarkVote(vote.Hash())

		// The sender never resends a message it marked as known to us, so queue
		// it while synchronising instead of dropping it.
		if pm.bftQueue.enqueueIf(pm.downloader.Synchronising, p.ID(), vote.Hash(), size, vote) {
			break
		}
		pm.handleVote(p.ID(), vote)

	case *ethproto.TimeoutPacket:
		timeout := (*types.Timeout)(packet)
		p.MarkTimeout(timeout.Hash())

		if pm.bftQueue.enqueueIf(pm.downloader.Synchronising, p.ID(), timeout.Hash(), size, timeout) {
			break
		}
		pm.handleTimeout(p.ID(), timeout)

	case *ethproto.SyncInfoPacket:
		syncInfo := (*types.SyncInfo)(packet)
		p.MarkSyncInfo(syncInfo.Hash())

		if pm.bftQueue.enqueueIf(pm.downloader.Synchronising, p.ID(), syncInfo.Hash(), size, syncInfo) {
			break
		}
		pm.handleSyncInfo(p.ID(), syncInfo)
	}
	return nil
}

// handleTransactions reacts to an inbound batch of transactions: it marks them
// as known to the peer and hands them to the transaction fetcher.
func (pm *ProtocolManager) handleTransactions(peer *ethproto.Peer, txs []*types.Transaction, direct bool) {
	for _, tx := range txs {
		// Mark the remote transaction as known
		peer.MarkTransaction(tx.Hash())
		if pm.knownTxs.Contains(tx.Hash()) {
			log.Trace("Discard known tx", "hash", tx.Hash(), "nonce", tx.Nonce(), "to", tx.To())
		} else {
			pm.knownTxs.Add(tx.Hash(), struct{}{})
		}
	}
	pm.txFetcher.Enqueue(peer.ID(), txs, direct)
}

// handleVote passes a vote to the BFT handler unless it is already known.
func (pm *ProtocolManager) handleVote(peer string, vote *types.Vote) {
	if pm.knownVotes.Contains(vote.Hash()) {
		log.Trace("Discarded vote, known vote", "vote hash", vote.Hash(), "voted block hash", vote.ProposedBlockInfo.Hash.Hex(), "number", vote.ProposedBlockInfo.Number, "round", vote.ProposedBlockInfo.Round)
		return
	}
	pm.knownVotes.Add(vote.Hash(), struct{}{})
	go pm.bft.Vote(peer, vote)
}

// handleTimeout passes a timeout to the BFT handler unless it is already known.
func (pm *ProtocolManager) handleTimeout(peer string, timeout *types.Timeout) {
	if pm.knownTimeouts.Contains(timeout.Hash()) {
		log.Trace("Discarded Timeout, known Timeout", "Signature", timeout.Signature, "hash", timeout.Hash(), "round", timeout.Round)
		return
	}
	pm.knownTimeouts.Add(timeout.Hash(), struct{}{})
	go pm.bft.Timeout(peer, timeout)
}

// handleSyncInfo passes a syncInfo to the BFT handler unless it is already known.
func (pm *ProtocolManager) handleSyncInfo(peer string, syncInfo *types.SyncInfo) {
	if pm.knownSyncInfos.Contains(syncInfo.Hash()) {
		log.Trace("Discarded SyncInfo, known SyncInfo", "hash", syncInfo.Hash())
		return
	}
	pm.knownSyncInfos.Add(syncInfo.Hash(), struct{}{})
	go pm.bft.SyncInfo(peer, syncInfo)
}

// drainBFTQueue processes the BFT messages queued during a sync. It does
// nothing if another sync is already running; that sync drains the queue when
// it finishes.
func (pm *ProtocolManager) drainBFTQueue() {
	msgs := pm.bftQueue.takeUnless(pm.downloader.Synchronising)
	if len(msgs) == 0 {
		return
	}
	log.Debug("Processing BFT messages queued during sync", "count", len(msgs))
	for _, m := range msgs {
		switch v := m.msg.(type) {
		case *types.Vote:
			pm.handleVote(m.peer, v)
		case *types.Timeout:
			pm.handleTimeout(m.peer, v)
		case *types.SyncInfo:
			pm.handleSyncInfo(m.peer, v)
		}
	}
}

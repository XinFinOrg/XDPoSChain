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
	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/types"
)

// broadcastBlocks is a write loop that multiplexes blocks and block accouncements
// to the remote peer. The goal is to have an async writer that does not lock up
// node internals and at the same time rate limits queued data.
func (p *Peer) broadcastBlocks() {
	for {
		select {
		case prop := <-p.queuedBlocks:
			if err := p.SendNewBlock(prop.block, prop.td); err != nil {
				return
			}
			p.Log().Trace("Propagated block", "number", prop.block.Number(), "hash", prop.block.Hash(), "td", prop.td)

		case block := <-p.queuedBlockAnns:
			if err := p.SendNewBlockHashes([]common.Hash{block.Hash()}, []uint64{block.NumberU64()}); err != nil {
				return
			}
			p.Log().Trace("Announced block", "number", block.Number(), "hash", block.Hash())

		case <-p.term:
			return
		}
	}
}

// broadcastTransactions is a write loop that schedules transaction broadcasts
// to the remote peer. The goal is to have an async writer that does not lock up
// node internals and at the same time rate limits queued data.
func (p *Peer) broadcastTransactions() {
	var (
		queue  []common.Hash         // Queue of hashes to broadcast as full transactions
		done   chan struct{}         // Non-nil if background broadcaster is running
		fail   = make(chan error, 1) // Channel used to receive network error
		failed bool                  // Keep draining the queue once sending is hopeless
	)
	for {
		// If there's no in-flight broadcast running, check if a new one is needed
		if done == nil && len(queue) > 0 {
			// Pile transaction until we reach our allowed network limit
			var (
				hashes []common.Hash
				txs    []*types.Transaction
				size   common.StorageSize
			)
			for i := 0; i < len(queue) && size < TxsyncPackSize; i++ {
				if tx := p.getPooledTx(queue[i]); tx != nil {
					txs = append(txs, tx)
					size += common.StorageSize(tx.Size())
				}
				hashes = append(hashes, queue[i])
			}
			queue = queue[:copy(queue, queue[len(hashes):])]

			// If there's anything available to transfer, fire up an async writer
			if len(txs) > 0 {
				done = make(chan struct{})
				go func() {
					if err := p.sendTransactions(txs); err != nil {
						fail <- err
						return
					}
					close(done)
					p.Log().Trace("Sent transactions", "count", len(txs))
				}()
			}
		}
		// Transfer goroutine may or may not have been started, listen for events
		select {
		case hashes := <-p.txBroadcast:
			// If the connection failed, discard all transaction events
			if failed {
				continue
			}
			// New batch of transactions to be broadcast, queue them (with cap)
			queue = append(queue, hashes...)
			if len(queue) > maxQueuedTxs {
				// Fancy copy and resize to ensure buffer doesn't grow indefinitely
				queue = queue[:copy(queue, queue[len(queue)-maxQueuedTxs:])]
			}

		case <-done:
			done = nil

		case err := <-fail:
			// p.term is only closed when the peer is removed from the peer set
			// (removePeer -> Unregister -> close), which may lag the connection
			// failure. Stay around as a reader, or
			// AsyncSendTransactions would block forever.
			failed, queue, done = true, nil, nil
			p.Log().Debug("Transaction broadcast send failed, draining queued events", "err", err)

		case <-p.term:
			return
		}
	}
}

// announceTransactions is a write loop that schedules transaction broadcasts
// to the remote peer. The goal is to have an async writer that does not lock up
// node internals and at the same time rate limits queued data.
func (p *Peer) announceTransactions() {
	var (
		queue  []common.Hash         // Queue of hashes to announce as transaction stubs
		done   chan struct{}         // Non-nil if background announcer is running
		fail   = make(chan error, 1) // Channel used to receive network error
		failed bool                  // Keep draining the queue once sending is hopeless
	)
	for {
		// If there's no in-flight announce running, check if a new one is needed
		if done == nil && len(queue) > 0 {
			// Pile transaction hashes until we reach our allowed network limit
			var (
				hashes  []common.Hash
				pending []common.Hash
				size    common.StorageSize
			)
			for i := 0; i < len(queue) && size < TxsyncPackSize; i++ {
				if p.getPooledTx(queue[i]) != nil {
					pending = append(pending, queue[i])
					size += common.HashLength
				}
				hashes = append(hashes, queue[i])
			}
			queue = queue[:copy(queue, queue[len(hashes):])]

			// If there's anything available to transfer, fire up an async writer
			if len(pending) > 0 {
				done = make(chan struct{})
				go func() {
					if err := p.sendPooledTransactionHashes(pending); err != nil {
						fail <- err
						return
					}
					close(done)
					p.Log().Trace("Sent transaction announcements", "count", len(pending))
				}()
			}
		}
		// Transfer goroutine may or may not have been started, listen for events
		select {
		case hashes := <-p.txAnnounce:
			// If the connection failed, discard all transaction events
			if failed {
				continue
			}
			// New batch of transactions to be broadcast, queue them (with cap)
			queue = append(queue, hashes...)
			if len(queue) > maxQueuedTxAnns {
				// Fancy copy and resize to ensure buffer doesn't grow indefinitely
				queue = queue[:copy(queue, queue[len(queue)-maxQueuedTxAnns:])]
			}

		case <-done:
			done = nil

		case err := <-fail:
			// p.term is only closed when the peer is removed from the peer set
			// (removePeer -> Unregister -> close), which may lag the connection
			// failure. Stay around as a reader, or
			// AsyncSendPooledTransactionHashes would block forever.
			failed, queue, done = true, nil, nil
			p.Log().Debug("Transaction announcement send failed, draining queued events", "err", err)

		case <-p.term:
			return
		}
	}
}

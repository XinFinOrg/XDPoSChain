// Copyright 2023 The go-ethereum Authors
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

// Package locals implements tracking for "local" transactions
package locals

import (
	"cmp"
	"slices"
	"sync"
	"time"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/txpool"
	"github.com/XinFinOrg/XDPoSChain/core/txpool/legacypool"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/log"
	"github.com/XinFinOrg/XDPoSChain/metrics"
	"github.com/XinFinOrg/XDPoSChain/params"
)

var (
	recheckInterval = time.Minute
	localGauge      = metrics.GetOrRegisterGauge("txpool/local", nil)

	// Tracked transactions a gas schedule fork priced out of the pool. They stay
	// tracked so a rollback past the fork can pick them up again, but recheck
	// holds them back from resubmission, so they are broken out here.
	//
	// Only transactions missing from the pool are counted: a tracked transaction
	// the pool still has is counted as ok instead. local minus belowfloor is
	// therefore the tracked transactions the pool holds plus the ones recheck
	// resubmits this round, not just the latter.
	belowFloorGauge = metrics.GetOrRegisterGauge("txpool/local/belowfloor", nil)
)

// TxTracker is a struct used to track priority transactions; it will check from
// time to time if the main pool has forgotten about any of the transaction
// it is tracking, and if so, submit it again.
// This is used to track 'locals'.
// This struct does not care about transaction validity, price-bumps or account limits,
// but optimistically accepts transactions.
type TxTracker struct {
	all    map[common.Hash]*types.Transaction       // All tracked transactions
	byAddr map[common.Address]*legacypool.SortedMap // Transactions by address

	journal   *journal       // Journal of local transaction to back up to disk
	rejournal time.Duration  // How often to rotate journal
	pool      *txpool.TxPool // The tx pool to interact with
	signer    types.Signer

	shutdownCh chan struct{}
	mu         sync.Mutex
	wg         sync.WaitGroup
}

// New creates a new TxTracker
func New(journalPath string, journalTime time.Duration, chainConfig *params.ChainConfig, next *txpool.TxPool) *TxTracker {
	pool := &TxTracker{
		all:        make(map[common.Hash]*types.Transaction),
		byAddr:     make(map[common.Address]*legacypool.SortedMap),
		signer:     types.LatestSigner(chainConfig),
		shutdownCh: make(chan struct{}),
		pool:       next,
	}
	if journalPath != "" {
		pool.journal = newTxJournal(journalPath)
		pool.rejournal = journalTime
	}
	return pool
}

// Track adds a transaction to the tracked set.
func (tracker *TxTracker) Track(tx *types.Transaction) {
	tracker.TrackAll([]*types.Transaction{tx})
}

// IsRetryableReject determines whether an add error is temporary and retryable.
func (tracker *TxTracker) IsRetryableReject(err error) bool {
	return IsTemporaryReject(err)
}

// TrackAll adds a list of transactions to the tracked set.
func (tracker *TxTracker) TrackAll(txs []*types.Transaction) {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()

	for _, tx := range txs {
		// If we're already tracking it, it's a no-op
		if _, ok := tracker.all[tx.Hash()]; ok {
			continue
		}
		// Theoretically, checking the error here is unnecessary since sender recovery
		// is already part of basic validation. However, retrieving the sender address
		// from the transaction cache is effectively a no-op if it was previously verified.
		// Therefore, the error is still checked just in case.
		addr, err := types.Sender(tracker.signer, tx)
		if err != nil { // Ignore this tx
			continue
		}
		list := tracker.byAddr[addr]
		if list == nil {
			list = legacypool.NewSortedMap()
			tracker.byAddr[addr] = list
		}
		// A transaction tracked for a nonce that is already taken supersedes the
		// one it replaces. SortedMap.Put overwrites silently, so the replaced
		// transaction has to be dropped here: it is never returned by Forward
		// again, and leaving it in `all` would keep journaling it forever,
		// where it can win the nonce on the next load and resurrect a
		// transaction the user already replaced.
		//
		// Which of the two supersedes the other is decided the way the pool
		// decides it:
		//
		//   1. The pool still holds one of them. It occupies a nonce with at
		//      most one transaction, so whichever it holds won the nonce. This
		//      is checked first because the order transactions reach TrackAll
		//      is not the order they were accepted in: AddLocal tracks a local
		//      transaction only after Add has released the subpool lock, so two
		//      concurrent submissions can be accepted in one order and reach
		//      here in the other.
		//   2. The pool holds neither -- two submissions it has since
		//      discarded, or a journal an older version wrote. Fall back to the
		//      substitution rules legacypool applies in list.Add: a special
		//      transaction always claims its nonce, a regular one must not
		//      evict a pending special one, and otherwise a replacement has to
		//      beat the transaction it replaces on both fee cap and tip. The
		//      price bump is deliberately not repeated here: it is a pool
		//      policy, and a transaction that beats the old one but misses the
		//      bump behaves exactly as it did before, so no case gets worse.
		//
		// Dropping the loser here also converges a journal written by an older
		// version, which can hold both a transaction and its replacement: load
		// feeds the file straight into TrackAll, so the replacement wins the
		// nonce instead of whichever entry the older rotation happened to sort
		// last, and the next rotation rewrites the journal from the converged
		// set.
		if replaced := list.Get(tx.Nonce()); replaced != nil {
			switch {
			case tracker.pool.Has(tx.Hash()):
				// The pool accepted this one, so it holds the nonce. A tracked
				// transaction that is dearer does not change that: it is one an
				// older version journalled after the pool rejected it as
				// retryable, and resubmitting it would evict this one.
			case tracker.pool.Has(replaced.Hash()):
				// The pool still holds the transaction this one would replace:
				// it lost the race for the nonce there.
				log.Debug("Ignoring tracked local transaction the pool superseded", "nonce", tx.Nonce(),
					"kept", replaced.Hash(), "ignored", tx.Hash())
				continue
			case tx.IsSpecialTransaction():
				// A special transaction always claims its nonce.
			case replaced.IsSpecialTransaction():
				// A regular transaction must not evict a pending special one,
				// however much dearer it is.
				log.Debug("Ignoring tracked local transaction that would evict a special one", "nonce", tx.Nonce(),
					"kept", replaced.Hash(), "ignored", tx.Hash())
				continue
			case replaced.GasFeeCapCmp(tx) >= 0 || replaced.GasTipCapCmp(tx) >= 0:
				// Not a replacement the pool would accept: keep the one that is
				// already tracked.
				log.Debug("Ignoring tracked local transaction the tracked one outbids", "nonce", tx.Nonce(),
					"kept", replaced.Hash(), "ignored", tx.Hash())
				continue
			}
			delete(tracker.all, replaced.Hash())
			log.Debug("Replaced tracked local transaction", "nonce", tx.Nonce(),
				"replaced", replaced.Hash(), "replacement", tx.Hash())
		}
		list.Put(tx)
		tracker.all[tx.Hash()] = tx

		if tracker.journal != nil {
			_ = tracker.journal.insert(tx)
		}
	}
	localGauge.Update(int64(len(tracker.all)))
}

// recheck checks and returns any transactions that needs to be resubmitted.
func (tracker *TxTracker) recheck(journalCheck bool) []*types.Transaction {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()

	var (
		numStales     = 0
		numOk         = 0
		numBelowFloor = 0
		resubmits     []*types.Transaction
	)
	// Resolved once: it can only change on a chain head update, and a change
	// mid-recheck would make the counters below inconsistent.
	floor := tracker.pool.MinGasPrice()

	for sender, txs := range tracker.byAddr {
		// Wipe the stales
		stales := txs.Forward(tracker.pool.Nonce(sender))
		for _, tx := range stales {
			delete(tracker.all, tx.Hash())
		}
		numStales += len(stales)

		// Check the non-stale
		for _, tx := range txs.Flatten() {
			if tracker.pool.Has(tx.Hash()) {
				numOk++
				continue
			}
			// A gas schedule fork can raise the floor above transactions that
			// were admitted under the previous tier. Re-submitting them only
			// yields ErrUnderMinGasPrice, so hold them back until the floor
			// drops again: a reorg or a set-head rollback past the fork
			// reinstates them, and the pool does not bring back what it swept.
			// They stay tracked, so recheck picks them up again on its own.
			// Special transactions are exempt, exactly as during admission.
			if !tx.IsSpecialTransaction() && tx.GasPriceIntCmp(floor) < 0 {
				numBelowFloor++
				continue
			}
			resubmits = append(resubmits, tx)
		}
	}

	if journalCheck { // rejournal
		rejournal := make(map[common.Address]types.Transactions)
		for _, tx := range tracker.all {
			addr, _ := types.Sender(tracker.signer, tx)
			rejournal[addr] = append(rejournal[addr], tx)
		}
		// Sort them
		for _, list := range rejournal {
			// cmp(a, b) should return a negative number when a < b,
			slices.SortFunc(list, func(a, b *types.Transaction) int {
				return cmp.Compare(a.Nonce(), b.Nonce())
			})
		}
		// Rejournal the tracker while holding the lock. No new transactions will
		// be added to the old journal during this period, preventing any potential
		// transaction loss.
		if tracker.journal != nil {
			if err := tracker.journal.rotate(rejournal); err != nil {
				log.Warn("Transaction journal rotation failed", "err", err)
			}
		}
	}
	localGauge.Update(int64(len(tracker.all)))
	belowFloorGauge.Update(int64(numBelowFloor))
	log.Debug("Tx tracker status", "need-resubmit", len(resubmits), "stale", numStales,
		"ok", numOk, "below-floor", numBelowFloor)
	return resubmits
}

// Start implements node.Lifecycle interface
// Start is called after all services have been constructed and the networking
// layer was also initialized to spawn any goroutines required by the service.
func (tracker *TxTracker) Start() error {
	if tracker.journal != nil {
		if err := tracker.journal.load(func(transactions []*types.Transaction) []error {
			tracker.TrackAll(transactions)
			return nil
		}); err != nil {
			log.Warn("Failed to load transaction journal", "err", err)
		}
		// Ensure the writer is ready before Start returns so Track/TrackAll can
		// persist transactions immediately.
		if err := tracker.journal.setupWriter(); err != nil {
			return err
		}
	}
	tracker.wg.Go(tracker.loop)
	return nil
}

// Stop implements node.Lifecycle interface
// Stop terminates all goroutines belonging to the service, blocking until they
// are all terminated.
func (tracker *TxTracker) Stop() error {
	close(tracker.shutdownCh)
	tracker.wg.Wait()

	tracker.mu.Lock()
	var err error
	if tracker.journal != nil {
		err = tracker.journal.close()
	}
	tracker.mu.Unlock()
	return err
}

func (tracker *TxTracker) loop() {
	var (
		lastJournal = time.Now()
		timer       = time.NewTimer(10 * time.Second) // Do initial check after 10 seconds, do rechecks more seldom.
	)
	for {
		select {
		case <-tracker.shutdownCh:
			return
		case <-timer.C:
			var rejournal bool
			if tracker.journal != nil && time.Since(lastJournal) > tracker.rejournal {
				rejournal, lastJournal = true, time.Now()
				log.Debug("Rejournal the transaction tracker")
			}
			resubmits := tracker.recheck(rejournal)
			if len(resubmits) > 0 {
				tracker.pool.Add(resubmits, false)
			}
			timer.Reset(recheckInterval)
		}
	}
}

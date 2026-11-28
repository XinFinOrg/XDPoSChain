// Copyright 2026 The go-ethereum Authors
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

package legacypool

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/txpool"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/event"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// setupQueueLimitPool creates a pool with a custom per-account queue limit.
func setupQueueLimitPool(t testing.TB, accountQueue uint64) *LegacyPool {
	t.Helper()

	return setupQueueAdmissionPool(t, accountQueue, testTxPoolConfig.GlobalSlots, testTxPoolConfig.GlobalQueue)
}

// newQueueLimitPool creates a pool with a custom per-account queue limit and
// leaves closing it to the caller.
func newQueueLimitPool(t testing.TB, accountQueue uint64) *LegacyPool {
	t.Helper()

	return newQueueAdmissionPool(t, accountQueue, testTxPoolConfig.GlobalSlots, testTxPoolConfig.GlobalQueue)
}

// setupQueueAdmissionPool creates a pool with custom per-account and global
// limits.
func setupQueueAdmissionPool(t testing.TB, accountQueue, globalSlots, globalQueue uint64) *LegacyPool {
	t.Helper()

	pool := newQueueAdmissionPool(t, accountQueue, globalSlots, globalQueue)
	t.Cleanup(func() { pool.Close() })
	return pool
}

// newQueueAdmissionPool creates a pool with custom per-account and global
// limits without registering a cleanup; the caller must close it.
func newQueueAdmissionPool(t testing.TB, accountQueue, globalSlots, globalQueue uint64) *LegacyPool {
	t.Helper()

	statedb, _ := state.New(types.EmptyRootHash, state.NewDatabase(rawdb.NewMemoryDatabase()))
	blockchain := newTestBlockChain(params.TestChainConfig, 1000000, statedb, new(event.Feed))

	config := testTxPoolConfig
	config.AccountQueue = accountQueue
	config.GlobalSlots = globalSlots
	config.GlobalQueue = globalQueue

	pool := New(config, blockchain)
	if err := pool.Init(config.PriceLimit, blockchain.CurrentBlock(), newReserver()); err != nil {
		t.Fatalf("failed to init pool: %v", err)
	}
	<-pool.initDoneCh

	return pool
}

func fundedKey(t testing.TB, pool *LegacyPool) *ecdsa.PrivateKey {
	t.Helper()

	key, _ := crypto.GenerateKey()
	testAddBalance(pool, crypto.PubkeyToAddress(key.PublicKey), big.NewInt(1_000_000_000_000_000))
	return key
}

// unaffordableTransaction signs a transaction at the given nonce that spends
// more than the funded balance, so the stateful validation rejects it and the
// gap the batch was going to fill stays open.
func unaffordableTransaction(t testing.TB, key *ecdsa.PrivateKey, nonce uint64) *types.Transaction {
	t.Helper()

	tx, err := types.SignTx(
		types.NewTransaction(nonce, common.Address{}, big.NewInt(2_000_000_000_000_000), 100000, big.NewInt(300000000), nil),
		types.HomesteadSigner{}, key)
	if err != nil {
		t.Fatalf("failed to sign transaction: %v", err)
	}
	return tx
}

// checkQueueAdmissionResults verifies the invariant a batch must keep: every
// transaction it reports as accepted is in the pool, unless a later candidate
// of the same sender and nonce was accepted and replaced it, and every
// transaction it reports as rejected is not. A transaction that silently
// disappeared fails the check.
func checkQueueAdmissionResults(t *testing.T, pool *LegacyPool, batch types.Transactions, errs []error) {
	t.Helper()

	type slot struct {
		sender common.Address
		nonce  uint64
	}
	// accepted holds the sender and nonce pairs a later candidate of the batch
	// got accepted at, so an earlier candidate at the same slot was replaced.
	accepted := make(map[slot]bool, len(batch))
	for i := len(batch) - 1; i >= 0; i-- {
		tx := batch[i]
		from, _ := types.Sender(pool.signer, tx)
		key := slot{from, tx.Nonce()}
		pooled := pool.all.Get(tx.Hash()) != nil
		switch {
		case accepted[key]:
			if pooled {
				t.Fatalf("nonce %d: replaced by a later candidate but still pooled", tx.Nonce())
			}
		case errs[i] == nil && !pooled:
			t.Fatalf("nonce %d: reported as accepted but not pooled", tx.Nonce())
		case errs[i] != nil && pooled:
			t.Fatalf("nonce %d: rejected (%v) but still pooled", tx.Nonce(), errs[i])
		}
		if errs[i] == nil {
			accepted[key] = true
		}
	}
}

// Tests that a burst of executable transactions is admitted in full even when
// it is longer than AccountQueue: during the batch they still sit in the queue,
// but each one fills or extends the run from the pending nonce.
func TestQueueAdmissionAllowsExecutableBurst(t *testing.T) {
	t.Parallel()

	pool := setupQueueLimitPool(t, 2)
	key := fundedKey(t, pool)

	// The burst is longer than AccountQueue: at admission every transaction
	// fills or extends the contiguous run from the pending nonce, so only the
	// gapped part counts against the queue limit.
	txs := make(types.Transactions, 0, 10)
	for nonce := uint64(0); nonce < 10; nonce++ {
		txs = append(txs, pricedTransaction(nonce, 100000, big.NewInt(300000000), key))
	}
	for i, err := range pool.Add(txs, true) {
		if err != nil {
			t.Fatalf("tx %d rejected: %v", i, err)
		}
	}
	if pending, queued := pool.Stats(); pending != len(txs) || queued != 0 {
		t.Fatalf("pool stats = (%d pending, %d queued), want (%d, 0)", pending, queued, len(txs))
	}
}

// Tests the out-of-order burst from the review: 100 transactions added in
// reverse nonce order carry their own gap filler, so the batch produces one
// executable run and promotion takes it in full. AccountQueue bounds the future
// queue, not the executable run.
func TestQueueAdmissionReverseBurstKeepsExecutableRun(t *testing.T) {
	t.Parallel()

	pool := setupQueueLimitPool(t, 64)
	key := fundedKey(t, pool)

	txs := make(types.Transactions, 0, 100)
	for nonce := 99; nonce >= 0; nonce-- {
		txs = append(txs, pricedTransaction(uint64(nonce), 100000, big.NewInt(300000000), key))
	}
	for i, err := range pool.Add(txs, true) {
		if err != nil {
			t.Fatalf("tx %d (nonce %d) rejected: %v", i, 99-i, err)
		}
	}
	if pending, queued := pool.Stats(); pending != 100 || queued != 0 {
		t.Fatalf("pool stats = (%d pending, %d queued), want (100, 0)", pending, queued)
	}
	if got := pool.all.Count(); got != 100 {
		t.Fatalf("total transaction mismatch: have %d, want 100", got)
	}
}

// Tests that a transaction that fills the gap at the head of a full queue is
// admitted: it is executable and unblocks the whole queue.
func TestQueueAdmissionAllowsGapFill(t *testing.T) {
	t.Parallel()

	pool := setupQueueLimitPool(t, 4)
	key := fundedKey(t, pool)

	for nonce := uint64(1); nonce <= 4; nonce++ {
		if err := pool.addRemoteSync(pricedTransaction(nonce, 100000, big.NewInt(300000000), key)); err != nil {
			t.Fatalf("tx %d: failed to add transaction: %v", nonce, err)
		}
	}
	if err := pool.addRemoteSync(pricedTransaction(0, 100000, big.NewInt(300000000), key)); err != nil {
		t.Fatalf("gap filler rejected: %v", err)
	}
	if pending, queued := pool.Stats(); pending != 5 || queued != 0 {
		t.Fatalf("pool stats = (%d pending, %d queued), want (5, 0)", pending, queued)
	}
}

// Tests that replacing a queued transaction is admitted even when the queue is
// at its limit, because it does not grow the queue.
func TestQueueAdmissionAllowsReplacement(t *testing.T) {
	t.Parallel()

	pool := setupQueueLimitPool(t, 4)
	key := fundedKey(t, pool)

	price := big.NewInt(300000000)
	for nonce := uint64(1); nonce <= 4; nonce++ {
		if err := pool.addRemoteSync(pricedTransaction(nonce, 100000, price, key)); err != nil {
			t.Fatalf("tx %d: failed to add transaction: %v", nonce, err)
		}
	}
	replacement := pricedTransaction(1, 100000, new(big.Int).Mul(price, big.NewInt(2)), key)
	if err := pool.addRemoteSync(replacement); err != nil {
		t.Fatalf("replacement rejected: %v", err)
	}
	list, _ := pool.queue.get(crypto.PubkeyToAddress(key.PublicKey))
	if list.Len() != 4 {
		t.Fatalf("queue size mismatch: have %d, want %d", list.Len(), 4)
	}
}

// Tests that the admission bound is per account: a full queue for one sender
// does not reject another sender.
func TestQueueAdmissionPerAccount(t *testing.T) {
	t.Parallel()

	pool := setupQueueLimitPool(t, 4)
	full := fundedKey(t, pool)
	other := fundedKey(t, pool)

	for nonce := uint64(1); nonce <= 4; nonce++ {
		if err := pool.addRemoteSync(pricedTransaction(nonce, 100000, big.NewInt(300000000), full)); err != nil {
			t.Fatalf("tx %d: failed to add transaction: %v", nonce, err)
		}
	}
	if err := pool.addRemoteSync(pricedTransaction(1, 100000, big.NewInt(300000000), other)); err != nil {
		t.Fatalf("second account rejected: %v", err)
	}
}

// Tests that a gap filler below the highest queued nonce is admitted into a
// full queue by evicting the highest nonce, so an account whose transactions
// arrive out of order keeps moving instead of stalling behind a gap.
func TestQueueAdmissionEvictsHighestForGapFiller(t *testing.T) {
	t.Parallel()

	pool := setupQueueLimitPool(t, 4)
	key := fundedKey(t, pool)

	for nonce := uint64(2); nonce <= 5; nonce++ {
		if err := pool.addRemoteSync(pricedTransaction(nonce, 100000, big.NewInt(300000000), key)); err != nil {
			t.Fatalf("tx %d: failed to add transaction: %v", nonce, err)
		}
	}
	if err := pool.addRemoteSync(pricedTransaction(1, 100000, big.NewInt(300000000), key)); err != nil {
		t.Fatalf("gap filler rejected: %v", err)
	}
	list, _ := pool.queue.get(crypto.PubkeyToAddress(key.PublicKey))
	if list.Len() != 4 {
		t.Fatalf("queue size mismatch: have %d, want %d", list.Len(), 4)
	}
	if !list.Contains(1) {
		t.Fatalf("gap filler was not queued")
	}
	if list.Contains(5) {
		t.Fatalf("highest nonce was not evicted")
	}
	if pool.all.Count() != 4 {
		t.Fatalf("total transaction mismatch: have %d, want %d", pool.all.Count(), 4)
	}
	if err := pool.addRemoteSync(pricedTransaction(0, 100000, big.NewInt(300000000), key)); err != nil {
		t.Fatalf("head nonce rejected: %v", err)
	}
	if pending, queued := pool.Stats(); pending != 5 || queued != 0 {
		t.Fatalf("pool stats = (%d pending, %d queued), want (5, 0)", pending, queued)
	}
}

// Tests that a transaction above everything queued is still refused when the
// queue is full: the promote-time trim would have dropped it as the highest
// nonce, so the caller observes the rejection instead.
func TestQueueAdmissionRejectsNonceAboveQueue(t *testing.T) {
	t.Parallel()

	pool := setupQueueLimitPool(t, 4)
	key := fundedKey(t, pool)

	for nonce := uint64(1); nonce <= 4; nonce++ {
		if err := pool.addRemoteSync(pricedTransaction(nonce, 100000, big.NewInt(300000000), key)); err != nil {
			t.Fatalf("tx %d: failed to add transaction: %v", nonce, err)
		}
	}
	err := pool.addRemoteSync(pricedTransaction(9, 100000, big.NewInt(300000000), key))
	if !errors.Is(err, txpool.ErrAccountLimitExceeded) {
		t.Fatalf("tx above the queue: err = %v, want %v", err, txpool.ErrAccountLimitExceeded)
	}
	list, _ := pool.queue.get(crypto.PubkeyToAddress(key.PublicKey))
	if list.Len() != 4 {
		t.Fatalf("queue size mismatch: have %d, want %d", list.Len(), 4)
	}
	if !list.Contains(4) {
		t.Fatalf("accepted transaction at nonce 4 was evicted")
	}
	if pool.all.Count() != 4 {
		t.Fatalf("total transaction mismatch: have %d, want %d", pool.all.Count(), 4)
	}
}

// Tests that a transaction refused by the admission bound is still validated: a
// permanent state failure has to reach the submitter as such, because the local
// tracker treats the capacity error as temporary, journals the transaction and
// the submitting RPC reports success. Only a valid transaction is refused for
// lack of room.
func TestQueueAdmissionValidatesRejectedTx(t *testing.T) {
	t.Parallel()

	pool := setupQueueLimitPool(t, 4)
	key := fundedKey(t, pool)
	addr := crypto.PubkeyToAddress(key.PublicKey)

	for nonce := uint64(2); nonce <= 5; nonce++ {
		if err := pool.addRemoteSync(pricedTransaction(nonce, 100000, big.NewInt(300000000), key)); err != nil {
			t.Fatalf("tx %d: failed to add transaction: %v", nonce, err)
		}
	}
	// The value alone spends the whole balance, so add would reject the
	// transaction with a permanent error.
	unaffordable, err := types.SignTx(
		types.NewTransaction(9, common.Address{}, big.NewInt(1_000_000_000_000_000), 100000, big.NewInt(300000000), nil),
		types.HomesteadSigner{}, key)
	if err != nil {
		t.Fatalf("failed to sign transaction: %v", err)
	}
	if err := pool.addRemoteSync(unaffordable); !errors.Is(err, core.ErrInsufficientFunds) {
		t.Fatalf("unaffordable tx above the queue: err = %v, want %v", err, core.ErrInsufficientFunds)
	}
	list, _ := pool.queue.get(addr)
	if list.Len() != 4 {
		t.Fatalf("queue size mismatch: have %d, want %d", list.Len(), 4)
	}
	if pool.all.Count() != 4 {
		t.Fatalf("total transaction mismatch: have %d, want %d", pool.all.Count(), 4)
	}
	// A valid transaction above the queue is still refused for lack of room.
	err = pool.addRemoteSync(pricedTransaction(9, 100000, big.NewInt(300000000), key))
	if !errors.Is(err, txpool.ErrAccountLimitExceeded) {
		t.Fatalf("valid tx above the queue: err = %v, want %v", err, txpool.ErrAccountLimitExceeded)
	}
}

// Tests that a batch is still allowed to fill the head gap and the nonces above
// it: both the gap filler and the extender are promoted after the batch.
func TestQueueAdmissionAllowsInBatchGapFill(t *testing.T) {
	t.Parallel()

	pool := setupQueueLimitPool(t, 4)
	key := fundedKey(t, pool)

	for nonce := uint64(2); nonce <= 5; nonce++ {
		if err := pool.addRemoteSync(pricedTransaction(nonce, 100000, big.NewInt(300000000), key)); err != nil {
			t.Fatalf("tx %d: failed to add transaction: %v", nonce, err)
		}
	}
	batch := types.Transactions{
		pricedTransaction(0, 100000, big.NewInt(300000000), key),
		pricedTransaction(1, 100000, big.NewInt(300000000), key),
	}
	for i, err := range pool.Add(batch, true) {
		if err != nil {
			t.Fatalf("tx %d rejected: %v", i, err)
		}
	}
	if pending, queued := pool.Stats(); pending != 6 || queued != 0 {
		t.Fatalf("pool stats = (%d pending, %d queued), want (6, 0)", pending, queued)
	}
}

// Tests that one batch of consecutive gapped nonces cannot use its own growth
// to widen the admission window past AccountQueue.
func TestQueueAdmissionBatchDoesNotGrowPastLimit(t *testing.T) {
	t.Parallel()

	pool := setupQueueLimitPool(t, 4)
	key := fundedKey(t, pool)

	for nonce := uint64(7); nonce <= 10; nonce++ {
		if err := pool.addRemoteSync(pricedTransaction(nonce, 100000, big.NewInt(300000000), key)); err != nil {
			t.Fatalf("tx %d: failed to add transaction: %v", nonce, err)
		}
	}
	gapped := make(types.Transactions, 0, 6)
	for nonce := uint64(1); nonce <= 6; nonce++ {
		gapped = append(gapped, pricedTransaction(nonce, 100000, big.NewInt(300000000), key))
	}
	for i, err := range pool.Add(gapped, true) {
		nonce := uint64(i + 1)
		if nonce <= 4 {
			if err != nil {
				t.Fatalf("tx %d rejected: %v", nonce, err)
			}
			continue
		}
		if !errors.Is(err, txpool.ErrAccountLimitExceeded) {
			t.Fatalf("tx %d: err = %v, want %v", nonce, err, txpool.ErrAccountLimitExceeded)
		}
	}
	list, _ := pool.queue.get(crypto.PubkeyToAddress(key.PublicKey))
	if list.Len() != 4 {
		t.Fatalf("queue size mismatch: have %d, want %d", list.Len(), 4)
	}
	for nonce := uint64(1); nonce <= 4; nonce++ {
		if !list.Contains(nonce) {
			t.Fatalf("accepted transaction at nonce %d was evicted", nonce)
		}
	}
	if pool.all.Count() != 4 {
		t.Fatalf("total transaction mismatch: have %d, want %d", pool.all.Count(), 4)
	}
}

// Tests that a batch may deliver the executable nonces and a higher nonce
// before the transaction that closes the gap. The executable prefix is promoted
// right after the batch, so it must not count against AccountQueue.
func TestQueueAdmissionBatchOutOfOrderExecutablePrefix(t *testing.T) {
	t.Parallel()

	pool := setupQueueLimitPool(t, 4)
	key := fundedKey(t, pool)

	nonces := []uint64{0, 1, 2, 3, 5, 4}
	batch := make(types.Transactions, 0, len(nonces))
	for _, nonce := range nonces {
		batch = append(batch, pricedTransaction(nonce, 100000, big.NewInt(300000000), key))
	}
	for i, err := range pool.Add(batch, true) {
		if err != nil {
			t.Fatalf("tx %d: rejected: %v", nonces[i], err)
		}
	}
	if pending, queued := pool.Stats(); pending != 6 || queued != 0 {
		t.Fatalf("pool stats = (%d pending, %d queued), want (6, 0)", pending, queued)
	}
}

// Tests that admission counts the capacity the projected run frees when it is
// promoted: the batch fills the executable prefix and carries two gapped
// transactions above it, which fit once the prefix is gone.
func TestQueueAdmissionProjectedRunFreesCapacity(t *testing.T) {
	t.Parallel()

	pool := setupQueueLimitPool(t, 2)
	key := fundedKey(t, pool)
	addr := crypto.PubkeyToAddress(key.PublicKey)

	// Nonce 0 arrives last, so while 4 and 5 are admitted the queue still looks
	// full: 1 and 2 are queued and nonce 0 is only a candidate of the batch.
	// Promoting 0, 1 and 2 empties the queue, and 4 and 5 fit exactly.
	nonces := []uint64{1, 2, 4, 5, 0}
	batch := make(types.Transactions, 0, len(nonces))
	for _, nonce := range nonces {
		batch = append(batch, pricedTransaction(nonce, 100000, big.NewInt(300000000), key))
	}
	errs := pool.Add(batch, true)
	for i, err := range errs {
		if err != nil {
			t.Fatalf("tx %d rejected: %v", batch[i].Nonce(), err)
		}
	}
	checkQueueAdmissionResults(t, pool, batch, errs)
	if pending, queued := pool.Stats(); pending != 3 || queued != 2 {
		t.Fatalf("pool stats = (%d pending, %d queued), want (3, 2)", pending, queued)
	}
	list, ok := pool.queue.get(addr)
	if !ok || list.Len() != 2 || !list.Contains(4) || !list.Contains(5) {
		t.Fatalf("queue mismatch: want the gapped transactions at nonce 4 and 5")
	}
}

// Tests that a transaction rejected by a later validation step does not evict
// the queued transaction that was only going to make room for it.
func TestQueueAdmissionKeepsVictimWhenAddFails(t *testing.T) {
	t.Parallel()

	pool := setupQueueLimitPool(t, 4)
	key := fundedKey(t, pool)
	addr := crypto.PubkeyToAddress(key.PublicKey)

	for nonce := uint64(2); nonce <= 5; nonce++ {
		if err := pool.addRemoteSync(pricedTransaction(nonce, 100000, big.NewInt(300000000), key)); err != nil {
			t.Fatalf("tx %d: failed to add transaction: %v", nonce, err)
		}
	}
	// The value alone exceeds the funded balance, so the stateful balance
	// check inside add rejects the transaction after admission accepted it.
	tx, err := types.SignTx(
		types.NewTransaction(1, common.Address{}, big.NewInt(1_000_000_000_000_000), 100000, big.NewInt(300000000), nil),
		types.HomesteadSigner{}, key)
	if err != nil {
		t.Fatalf("failed to sign transaction: %v", err)
	}
	if err := pool.addRemoteSync(tx); !errors.Is(err, core.ErrInsufficientFunds) {
		t.Fatalf("gap filler error mismatch: have %v, want %v", err, core.ErrInsufficientFunds)
	}
	list, _ := pool.queue.get(addr)
	if list.Len() != 4 {
		t.Fatalf("queue size mismatch: have %d, want %d", list.Len(), 4)
	}
	if !list.Contains(5) {
		t.Fatalf("nonce 5 was evicted by a rejected insertion")
	}
	if pool.all.Count() != 4 {
		t.Fatalf("total transaction mismatch: have %d, want %d", pool.all.Count(), 4)
	}
}

// Tests that the saved victim is only evicted when the account queue is still
// over the bound after insertion: a globally full pool may already have
// discarded another queued transaction while making room for the gap filler.
func TestQueueAdmissionRechecksQueueAfterEviction(t *testing.T) {
	t.Parallel()

	// Two executable slots plus four queued slots: the account queue fills the
	// global queue on its own, and admitting one more transaction overflows the
	// pool.
	pool := setupQueueAdmissionPool(t, 4, 2, 4)
	key := fundedKey(t, pool)
	other := fundedKey(t, pool)
	addr := crypto.PubkeyToAddress(key.PublicKey)

	// Queue nonces 2..5 with increasing prices, so the globally full pool
	// discards the cheapest one (nonce 2) when the gap filler is admitted.
	for nonce := uint64(2); nonce <= 5; nonce++ {
		price := big.NewInt(300000000 + int64(nonce))
		if err := pool.addRemoteSync(pricedTransaction(nonce, 100000, price, key)); err != nil {
			t.Fatalf("tx %d: failed to add transaction: %v", nonce, err)
		}
	}
	// Fill the remaining global slots with executable transactions.
	for nonce := uint64(0); nonce < 2; nonce++ {
		if err := pool.addRemoteSync(pricedTransaction(nonce, 100000, big.NewInt(500000000), other)); err != nil {
			t.Fatalf("filler tx %d: failed to add transaction: %v", nonce, err)
		}
	}
	if err := pool.addRemoteSync(pricedTransaction(1, 100000, big.NewInt(400000000), key)); err != nil {
		t.Fatalf("gap filler rejected: %v", err)
	}
	list, _ := pool.queue.get(addr)
	if list.Len() != 4 {
		t.Fatalf("queue size mismatch: have %d, want %d", list.Len(), 4)
	}
	if !list.Contains(1) {
		t.Fatalf("gap filler was not queued")
	}
	if !list.Contains(5) {
		t.Fatalf("victim was evicted twice")
	}
	if list.Contains(2) {
		t.Fatalf("globally full pool did not discard the cheapest queued transaction")
	}
	if pool.all.Count() != 6 {
		t.Fatalf("total transaction mismatch: have %d, want %d", pool.all.Count(), 6)
	}
}

// Tests that a transaction admitted below the highest queued nonce survives the
// insertion even when a globally full pool discards the executable prefix of its
// own account. The prefix is what the admission decision discounted, so losing
// it pushes the queue over AccountQueue again; the trim must evict transactions
// accepted earlier instead of reversing the admission decision.
func TestQueueAdmissionKeepsAdmittedWhenPrefixEvicted(t *testing.T) {
	t.Parallel()

	// One executable slot plus four queued slots: the batch fills the pool and
	// the last transaction makes the pool discard the cheapest one, nonce 0.
	pool := setupQueueAdmissionPool(t, 4, 1, 4)
	key := fundedKey(t, pool)
	addr := crypto.PubkeyToAddress(key.PublicKey)

	// Nonce 0 makes the queue executable and 9 lifts its maximum, so the last
	// transaction, nonce 6, is admitted below the highest queued nonce once the
	// gapped part has reached the bound.
	nonces := []uint64{0, 9, 3, 4, 5, 6}
	batch := make(types.Transactions, 0, len(nonces))
	for _, nonce := range nonces {
		// Increasing prices: nonce 0 is the cheapest, nonce 9 the priciest.
		price := big.NewInt(300000000 + int64(nonce)*1000000)
		batch = append(batch, pricedTransaction(nonce, 100000, price, key))
	}
	// The last insertion discards nonce 0 to make room in the full pool, which
	// breaks the executable run and pushes the queue over the bound: the interim
	// trim then withdraws nonce 9, the highest accepted above the one just
	// admitted, and has to report it.
	errs := pool.Add(batch, true)
	for i, tx := range batch {
		if nonce := tx.Nonce(); nonce == 9 {
			if !errors.Is(errs[i], txpool.ErrAccountLimitExceeded) {
				t.Fatalf("nonce %d: err = %v, want %v", nonce, errs[i], txpool.ErrAccountLimitExceeded)
			}
			continue
		}
		if errs[i] != nil {
			t.Fatalf("nonce %d: rejected: %v", tx.Nonce(), errs[i])
		}
	}
	if pool.all.Get(batch[0].Hash()) != nil {
		t.Fatal("globally full pool did not discard the cheapest transaction")
	}
	list, ok := pool.queue.get(addr)
	if !ok || !list.Contains(6) {
		t.Fatalf("admitted transaction at nonce 6 was evicted")
	}
	if list.Contains(9) {
		t.Fatalf("trim victim at nonce 9 is still queued")
	}
	if list.Len() != 4 {
		t.Fatalf("queue size mismatch: have %d, want %d", list.Len(), 4)
	}
	if nonce := pool.pendingNonces.get(addr); nonce != 0 {
		t.Fatalf("pending nonce = %d, want 0", nonce)
	}
}

// Tests that queued transactions already covered by a pending transaction at
// the same nonce do not consume future-queue capacity. A signer special
// transaction can take a pending nonce while the ordinary transaction at that
// nonce is still queued; without pruning, the dead entry pushes the admission
// bound over the limit and rejects a valid future transaction.
func TestQueueAdmissionPrunesStaleQueued(t *testing.T) {
	t.Parallel()

	pool := setupQueueLimitPool(t, 4)
	key := fundedKey(t, pool)
	addr := crypto.PubkeyToAddress(key.PublicKey)

	// Nonce 2 is superseded by a pending transaction at the same nonce, so the
	// gapped part is nonce 3 and the future transactions 5..7.
	stale := pricedTransaction(2, 100000, big.NewInt(300000000), key)
	pendingTx := pricedTransaction(2, 100000, big.NewInt(400000000), key)
	queuedTxs := []*types.Transaction{
		stale,
		pricedTransaction(3, 100000, big.NewInt(300000000), key),
		pricedTransaction(5, 100000, big.NewInt(300000000), key),
		pricedTransaction(6, 100000, big.NewInt(300000000), key),
		pricedTransaction(7, 100000, big.NewInt(300000000), key),
	}

	pool.mu.Lock()
	queued := newList(false)
	for _, tx := range queuedTxs {
		queued.Add(tx, 0)
		pool.all.Add(tx)
		pool.priced.Put(tx)
	}
	pool.queue.queued[addr] = queued
	pool.queue.beats[addr] = time.Now()

	pending := newList(true)
	pending.Add(pendingTx, 0)
	pool.all.Add(pendingTx)
	pool.priced.Put(pendingTx)
	pool.pending[addr] = pending
	pool.pendingNonces.set(addr, 3)
	pool.mu.Unlock()

	// The stale entry would make len(queue)-run == 4 and reject nonce 8; after
	// pruning, the gapped part is 3 and still fits AccountQueue.
	if err := pool.addRemoteSync(pricedTransaction(8, 100000, big.NewInt(300000000), key)); err != nil {
		t.Fatalf("future transaction rejected: %v", err)
	}
	list, _ := pool.queue.get(addr)
	if list.Contains(2) {
		t.Fatalf("stale queued transaction was not pruned")
	}
	if !list.Contains(8) {
		t.Fatalf("admitted transaction was dropped by the promote-time cap")
	}
	if pool.all.Get(stale.Hash()) != nil {
		t.Fatalf("stale transaction still in the pool lookup")
	}
}

// Tests that a replacement accepted into a queue over the admission bound stays
// in the pool. A replacement does not consume a new slot, so trimming has to
// evict the highest gapped transaction instead, and promotion must not drop the
// replacement afterwards.
func TestQueueAdmissionKeepsReplacementWhenTrimming(t *testing.T) {
	t.Parallel()

	pool := setupQueueLimitPool(t, 4)
	key := fundedKey(t, pool)
	addr := crypto.PubkeyToAddress(key.PublicKey)

	// Seed a queue of six gapped transactions with no executable prefix, so the
	// account is over AccountQueue before the replacement arrives.
	pool.mu.Lock()
	queued := newList(false)
	for _, nonce := range []uint64{3, 5, 6, 7, 8, 9} {
		tx := pricedTransaction(nonce, 100000, big.NewInt(300000000), key)
		queued.Add(tx, 0)
		pool.all.Add(tx)
		pool.priced.Put(tx)
	}
	pool.queue.queued[addr] = queued
	pool.queue.beats[addr] = time.Now()
	pool.mu.Unlock()

	replacement := pricedTransaction(9, 100000, big.NewInt(900000000), key)
	if err := pool.addRemoteSync(replacement); err != nil {
		t.Fatalf("replacement rejected: %v", err)
	}
	// A replacement is not added to the dirty set, so run the promotion pass a
	// subsequent pool maintenance would perform.
	pool.mu.Lock()
	pool.promoteExecutables([]common.Address{addr})
	pool.mu.Unlock()

	list, _ := pool.queue.get(addr)
	if !list.Contains(9) {
		t.Fatalf("admitted replacement was dropped by the promote-time cap")
	}
	if list.Len() != 4 {
		t.Fatalf("queue size mismatch: have %d, want %d", list.Len(), 4)
	}
}

// Tests that admissions made on the projection of a gap filler are settled as
// soon as the batch has no candidate left for that filler: the speculative
// entry the projection kept alive must not justify a later admission that
// evicts a transaction accepted earlier.
func TestQueueAdmissionSettlesProjectionAfterFailedFiller(t *testing.T) {
	t.Parallel()

	pool := setupQueueLimitPool(t, 4)
	key := fundedKey(t, pool)
	addr := crypto.PubkeyToAddress(key.PublicKey)

	// The queue is full above a missing nonce 0, so nonce 100 is admitted only
	// because the batch still carries nonce 0.
	for nonce := uint64(1); nonce <= 4; nonce++ {
		if err := pool.addRemoteSync(pricedTransaction(nonce, 100000, big.NewInt(300000000), key)); err != nil {
			t.Fatalf("tx %d: failed to add transaction: %v", nonce, err)
		}
	}
	batch := types.Transactions{
		pricedTransaction(100, 100000, big.NewInt(900000000), key),
		unaffordableTransaction(t, key, 0),
		pricedTransaction(99, 100000, big.NewInt(900000000), key),
	}
	errs := pool.Add(batch, true)
	if !errors.Is(errs[0], txpool.ErrAccountLimitExceeded) {
		t.Fatalf("nonce 100: err = %v, want %v", errs[0], txpool.ErrAccountLimitExceeded)
	}
	if !errors.Is(errs[1], core.ErrInsufficientFunds) {
		t.Fatalf("gap filler: err = %v, want %v", errs[1], core.ErrInsufficientFunds)
	}
	// With the projection settled, nonce 99 is above everything still queued.
	if !errors.Is(errs[2], txpool.ErrAccountLimitExceeded) {
		t.Fatalf("nonce 99: err = %v, want %v", errs[2], txpool.ErrAccountLimitExceeded)
	}
	list, ok := pool.queue.get(addr)
	if !ok || list.Len() != 4 {
		t.Fatalf("queue size mismatch: have %v, want %d", list, 4)
	}
	for nonce := uint64(1); nonce <= 4; nonce++ {
		if !list.Contains(nonce) {
			t.Fatalf("accepted transaction at nonce %d was evicted", nonce)
		}
	}
	if got := pool.all.Count(); got != 4 {
		t.Fatalf("total transaction mismatch: have %d, want %d", got, 4)
	}
}

// Tests that a transaction refused at admission is never handed to add: a
// globally full pool would otherwise discard an unrelated cheaper transaction
// just to make room for a transaction that is rejected anyway.
func TestQueueAdmissionRejectsBeforeAdd(t *testing.T) {
	t.Parallel()

	// One executable slot plus six queued slots: the account queue takes four,
	// and the other account fills the rest.
	pool := setupQueueAdmissionPool(t, 4, 1, 6)
	key := fundedKey(t, pool)
	other := fundedKey(t, pool)
	addr := crypto.PubkeyToAddress(key.PublicKey)

	// Queue four gapped transactions at the higher price, so a pool that is
	// given the chance to make room discards the cheaper ones below.
	for nonce := uint64(2); nonce <= 5; nonce++ {
		if err := pool.addRemoteSync(pricedTransaction(nonce, 100000, big.NewInt(400000000), key)); err != nil {
			t.Fatalf("tx %d: failed to add transaction: %v", nonce, err)
		}
	}
	// The other account takes the executable slot and queues two cheaper gapped
	// transactions. They are not pending, so the future-transaction guard in add
	// would not protect them from the discard.
	if err := pool.addRemoteSync(pricedTransaction(0, 100000, big.NewInt(500000000), other)); err != nil {
		t.Fatalf("pending filler: failed to add transaction: %v", err)
	}
	var cheap types.Transactions
	for nonce := uint64(2); nonce <= 3; nonce++ {
		tx := pricedTransaction(nonce, 100000, big.NewInt(300000000), other)
		if err := pool.addRemoteSync(tx); err != nil {
			t.Fatalf("filler tx %d: failed to add transaction: %v", nonce, err)
		}
		cheap = append(cheap, tx)
	}
	if count := pool.all.Count(); count != 7 {
		t.Fatalf("pool size mismatch: have %d, want 7", count)
	}
	// A transaction above everything queued is refused before it is inserted.
	err := pool.addRemoteSync(pricedTransaction(6, 100000, big.NewInt(400000000), key))
	if !errors.Is(err, txpool.ErrAccountLimitExceeded) {
		t.Fatalf("tx above the queue: err = %v, want %v", err, txpool.ErrAccountLimitExceeded)
	}
	// The rejection must not have cost the pool an unrelated transaction.
	for _, tx := range cheap {
		if pool.all.Get(tx.Hash()) == nil {
			t.Fatalf("transaction at nonce %d was discarded to make room for a rejected transaction", tx.Nonce())
		}
	}
	if list, _ := pool.queue.get(addr); list.Len() != 4 {
		t.Fatalf("queue size mismatch: have %d, want 4", list.Len())
	}
}

// Tests that promotion prunes queue entries already covered by a pending
// transaction at the same nonce, instead of letting the queue entry replace the
// pending transaction on its way through promotion.
func TestPromotePrunesStaleQueued(t *testing.T) {
	t.Parallel()

	pool := setupQueueLimitPool(t, 4)
	key := fundedKey(t, pool)
	addr := crypto.PubkeyToAddress(key.PublicKey)

	// The pending and the queued transaction share nonce 2; the queued one is
	// priced higher, so promotion would replace the pending one without the prune.
	queuedTx := pricedTransaction(2, 100000, big.NewInt(900000000), key)
	pendingTx := pricedTransaction(2, 100000, big.NewInt(400000000), key)
	queuedTxs := []*types.Transaction{
		queuedTx,
		pricedTransaction(3, 100000, big.NewInt(300000000), key),
		pricedTransaction(5, 100000, big.NewInt(300000000), key),
	}

	pool.mu.Lock()
	queued := newList(false)
	for _, tx := range queuedTxs {
		queued.Add(tx, 0)
		pool.all.Add(tx)
		pool.priced.Put(tx)
	}
	pool.queue.queued[addr] = queued
	pool.queue.beats[addr] = time.Now()

	pending := newList(true)
	pending.Add(pendingTx, 0)
	pool.all.Add(pendingTx)
	pool.priced.Put(pendingTx)
	pool.pending[addr] = pending
	pool.pendingNonces.set(addr, 3)
	pool.mu.Unlock()

	pool.mu.Lock()
	promoted := pool.promoteExecutables([]common.Address{addr})
	pool.mu.Unlock()

	if len(promoted) != 1 || promoted[0].Nonce() != 3 {
		t.Fatalf("promoted %d transactions, want only nonce 3", len(promoted))
	}
	if pool.all.Get(queuedTx.Hash()) != nil {
		t.Fatalf("stale queued transaction was not pruned")
	}
	if current := pool.pending[addr].txs.Get(2); current == nil || current.Hash() != pendingTx.Hash() {
		t.Fatalf("pending transaction at nonce 2 was replaced by the stale queued one")
	}
	list, ok := pool.queue.get(addr)
	if !ok || list.Len() != 1 || !list.Contains(5) {
		t.Fatalf("queue mismatch after promotion: %v", list)
	}
}

// Tests that one admission can trim many entries after the pool discarded the
// account's executable prefix. The discarded pending transactions are postponed
// back into the queue, so the trim has to walk a queue far above AccountQueue;
// the survivors must be the lowest nonces plus the protected replacement, and
// the queue must end exactly at the bound.
func TestQueueAdmissionTrimsAfterPrefixEviction(t *testing.T) {
	t.Parallel()

	// 256 executable slots, 256 queued slots, 8 queued slots per account.
	pool := setupQueueAdmissionPool(t, 8, 256, 256)
	key := fundedKey(t, pool)
	addr := crypto.PubkeyToAddress(key.PublicKey)
	testAddBalance(pool, addr, big.NewInt(1_000_000_000_000_000_000))

	// The sender fills the executable slots; strictly increasing prices make
	// nonce 0 the cheapest transaction in the pool.
	batch := make(types.Transactions, 0, 256)
	for nonce := uint64(0); nonce < 256; nonce++ {
		batch = append(batch, pricedTransaction(nonce, 100000, big.NewInt(300000000+int64(nonce)), key))
	}
	for i, err := range pool.Add(batch, true) {
		if err != nil {
			t.Fatalf("tx %d: rejected: %v", i, err)
		}
	}
	// Fill the global queue with gapped transactions from other accounts, each
	// below AccountQueue.
	for left := 241; left > 0; {
		filler, _ := crypto.GenerateKey()
		testAddBalance(pool, crypto.PubkeyToAddress(filler.PublicKey), big.NewInt(1_000_000_000_000_000_000))
		count := 8
		if left < count {
			count = left
		}
		for nonce := uint64(1000); nonce < uint64(1000+count); nonce++ {
			if err := pool.addRemoteSync(pricedTransaction(nonce, 100000, big.NewInt(600000000), filler)); err != nil {
				t.Fatalf("filler tx %d: %v", nonce, err)
			}
		}
		left -= count
	}
	// The continuation of the executable run plus a better-priced replacement
	// of its first nonce. The last insertion makes the full pool discard nonce
	// 0, which postpones 1..255 back into the queue.
	batch = batch[:0]
	for nonce := uint64(256); nonce < 271; nonce++ {
		batch = append(batch, pricedTransaction(nonce, 100000, big.NewInt(500000000), key))
	}
	replacement := pricedTransaction(256, 100000, big.NewInt(700000000), key)
	batch = append(batch, replacement)

	// The insertions push the account far past the bound, so the trim withdraws
	// most of the batch: every withdrawal has to be reported, and the
	// transactions reported as accepted have to stay.
	errs := pool.Add(batch, true)
	checkQueueAdmissionResults(t, pool, batch, errs)
	list, ok := pool.queue.get(addr)
	if !ok || list.Len() != 8 {
		t.Fatalf("queue size mismatch: have %d, want %d", list.Len(), 8)
	}
	for nonce := uint64(1); nonce <= 7; nonce++ {
		if !list.Contains(nonce) {
			t.Fatalf("nonce %d was evicted", nonce)
		}
	}
	if queued := list.txs.Get(256); queued == nil || queued.Hash() != replacement.Hash() {
		t.Fatalf("nonce 256 does not hold the protected replacement")
	}
	if _, ok := pool.pending[addr]; ok {
		t.Fatalf("executable prefix was not evicted")
	}
	if nonce := pool.pendingNonces.get(addr); nonce != 0 {
		t.Fatalf("pending nonce = %d, want 0", nonce)
	}
}

// Tests that a special transaction taking the pending nonce of a queued regular
// transaction does not make the trim evict a legitimate gapped transaction: the
// stale queue entry is pruned first, so it is the one that goes.
func TestQueueAdmissionPrunesStaleBeforeTrim(t *testing.T) {
	t.Parallel()

	pool := setupQueueLimitPool(t, 1)
	pool.SetSigner(func(common.Address) bool { return true })
	key := fundedKey(t, pool)
	addr := crypto.PubkeyToAddress(key.PublicKey)

	stale := pricedTransaction(0, 100000, big.NewInt(300000000), key)
	special, err := types.SignTx(
		types.NewTransaction(0, common.BlockSignersBinary, big.NewInt(0), 100000, big.NewInt(common.DefaultMinGasPrice+1), []byte{0x01}),
		types.HomesteadSigner{}, key)
	if err != nil {
		t.Fatalf("failed to sign special transaction: %v", err)
	}
	gapped := pricedTransaction(3, 100000, big.NewInt(300000000), key)

	// The special transaction claims pending nonce 0 while the regular one at
	// that nonce is still queued, so the queue is one entry over the bound once
	// it lands.
	batch := types.Transactions{stale, gapped, special}
	for i, err := range pool.Add(batch, true) {
		if err != nil {
			t.Fatalf("tx %d (nonce %d): rejected: %v", i, batch[i].Nonce(), err)
		}
	}
	list, ok := pool.queue.get(addr)
	if !ok || list.Len() != 1 || !list.Contains(3) {
		t.Fatalf("queue mismatch: %v", list)
	}
	if pool.all.Get(gapped.Hash()) == nil {
		t.Fatal("gapped transaction was evicted by the trim")
	}
	if pool.all.Get(stale.Hash()) != nil {
		t.Fatal("stale queued transaction was not pruned")
	}
	if pool.all.Get(special.Hash()) == nil {
		t.Fatal("special transaction was dropped")
	}
}

// Tests the admission and trim rules that only matter when the queue holds
// entries below the pending nonce: a transaction extending the contiguous run
// is admitted even though the gapped part is at the bound, and the trim never
// evicts the executable prefix.
func TestQueueAdmissionExtendsRunAboveStaleLow(t *testing.T) {
	t.Parallel()

	pool := setupQueueLimitPool(t, 1)
	key := fundedKey(t, pool)
	addr := crypto.PubkeyToAddress(key.PublicKey)

	// Seed nonces 0..2 with the pending nonce already at 2 and no pending list:
	// 0 and 1 sit below the pending nonce, 2 starts the executable run.
	pool.mu.Lock()
	queued := newList(false)
	for nonce := uint64(0); nonce <= 2; nonce++ {
		tx := pricedTransaction(nonce, 100000, big.NewInt(300000000), key)
		queued.Add(tx, 0)
		pool.all.Add(tx)
		pool.priced.Put(tx)
	}
	pool.queue.queued[addr] = queued
	pool.queue.beats[addr] = time.Now()
	pool.pendingNonces.set(addr, 2)

	// The gapped part is 2 at a bound of 1. Nonce 3 extends the run, so
	// admission has to accept it, and the trim has to drop nonce 1 rather than
	// the executable nonce 2.
	tx := pricedTransaction(3, 100000, big.NewInt(300000000), key)
	if err := pool.ValidateTxBasics(tx); err != nil {
		pool.mu.Unlock()
		t.Fatalf("failed to validate transaction: %v", err)
	}
	errs := make([]error, 1)
	pool.addTxsLocked(types.Transactions{tx}, errs, true)
	list, _ := pool.queue.get(addr)
	pool.mu.Unlock()

	if errs[0] != nil {
		t.Fatalf("extending transaction rejected: %v", errs[0])
	}
	if list == nil || list.Len() != 3 || !list.Contains(0) || !list.Contains(2) || !list.Contains(3) {
		t.Fatalf("queue mismatch: %v", list)
	}
	if list.Contains(1) {
		t.Fatal("trim did not evict the gapped transaction below the pending nonce")
	}
}

// Tests that a batch which delivers the gap filler after the transactions above
// the gap is admitted in full: the decision must not depend on the order the
// reply happens to list the hashes in.
func TestQueueAdmissionBatchKeepsGapFillLast(t *testing.T) {
	t.Parallel()

	pool := setupQueueLimitPool(t, 64)
	key := fundedKey(t, pool)

	batch := make(types.Transactions, 0, 66)
	for nonce := uint64(1); nonce <= 65; nonce++ {
		batch = append(batch, pricedTransaction(nonce, 100000, big.NewInt(300000000), key))
	}
	filler := pricedTransaction(0, 100000, big.NewInt(300000000), key)
	batch = append(batch, filler)

	for i, err := range pool.Add(batch, true) {
		if err != nil {
			t.Fatalf("tx %d (nonce %d) rejected: %v", i, batch[i].Nonce(), err)
		}
	}
	if pending, queued := pool.Stats(); pending != 66 || queued != 0 {
		t.Fatalf("pool stats = (%d pending, %d queued), want (66, 0)", pending, queued)
	}
	if pool.all.Get(filler.Hash()) == nil {
		t.Fatal("gap filler was dropped")
	}
	if got := pool.all.Count(); got != 66 {
		t.Fatalf("total transaction mismatch: have %d, want 66", got)
	}
}

// Tests that a transaction accepted before the batch's gap filler arrives is
// not evicted while the batch is still being applied.
func TestQueueAdmissionReverseBurstKeepsGapFill(t *testing.T) {
	t.Parallel()

	pool := setupQueueLimitPool(t, 64)
	key := fundedKey(t, pool)

	highest := pricedTransaction(65, 100000, big.NewInt(300000000), key)
	batch := make(types.Transactions, 0, 66)
	batch = append(batch, highest)
	for nonce := uint64(64); nonce > 0; nonce-- {
		batch = append(batch, pricedTransaction(nonce, 100000, big.NewInt(300000000), key))
	}
	batch = append(batch, pricedTransaction(0, 100000, big.NewInt(300000000), key))

	for i, err := range pool.Add(batch, true) {
		if err != nil {
			t.Fatalf("tx %d (nonce %d) rejected: %v", i, batch[i].Nonce(), err)
		}
	}
	if pending, queued := pool.Stats(); pending != 66 || queued != 0 {
		t.Fatalf("pool stats = (%d pending, %d queued), want (66, 0)", pending, queued)
	}
	if pool.all.Get(highest.Hash()) == nil {
		t.Fatal("transaction accepted before the gap filler was evicted")
	}
}

// Tests that an optimistic admission is withdrawn when the gap filler it relied
// on never enters the pool: the highest transaction is reported as over the
// limit and the transactions accepted below it stay.
func TestQueueAdmissionRevokesWhenGapFillFails(t *testing.T) {
	t.Parallel()

	pool := setupQueueLimitPool(t, 64)
	key := fundedKey(t, pool)
	addr := crypto.PubkeyToAddress(key.PublicKey)

	batch := make(types.Transactions, 0, 66)
	for nonce := uint64(1); nonce <= 65; nonce++ {
		batch = append(batch, pricedTransaction(nonce, 100000, big.NewInt(300000000), key))
	}
	// The gap filler alone spends more than the funded balance, so add rejects
	// it and the run the admission promise assumed never materialises.
	batch = append(batch, unaffordableTransaction(t, key, 0))

	for i, err := range pool.Add(batch, true) {
		switch {
		case i == len(batch)-1:
			if !errors.Is(err, core.ErrInsufficientFunds) {
				t.Fatalf("gap filler: err = %v, want %v", err, core.ErrInsufficientFunds)
			}
		case batch[i].Nonce() == 65:
			if !errors.Is(err, txpool.ErrAccountLimitExceeded) {
				t.Fatalf("tx 65: err = %v, want %v", err, txpool.ErrAccountLimitExceeded)
			}
		default:
			if err != nil {
				t.Fatalf("tx %d rejected: %v", batch[i].Nonce(), err)
			}
		}
	}
	list, _ := pool.queue.get(addr)
	if list.Len() != 64 {
		t.Fatalf("queue size mismatch: have %d, want 64", list.Len())
	}
	for nonce := uint64(1); nonce <= 64; nonce++ {
		if !list.Contains(nonce) {
			t.Fatalf("accepted transaction at nonce %d was evicted", nonce)
		}
	}
	if got := pool.all.Count(); got != 64 {
		t.Fatalf("total transaction mismatch: have %d, want 64", got)
	}
}

// Tests that the final trim reports every transaction it withdraws, not only
// the last one the batch accepted. A batch that arrives highest nonce first is
// trimmed from the top, so the victim is the transaction it accepted first.
func TestQueueAdmissionRevokesHighestWhenGapFillFails(t *testing.T) {
	t.Parallel()

	pool := setupQueueLimitPool(t, 64)
	key := fundedKey(t, pool)
	addr := crypto.PubkeyToAddress(key.PublicKey)

	batch := make(types.Transactions, 0, 66)
	for nonce := uint64(65); nonce > 0; nonce-- {
		batch = append(batch, pricedTransaction(nonce, 100000, big.NewInt(300000000), key))
	}
	batch = append(batch, unaffordableTransaction(t, key, 0))

	for i, err := range pool.Add(batch, true) {
		switch nonce := batch[i].Nonce(); {
		case nonce == 0:
			if !errors.Is(err, core.ErrInsufficientFunds) {
				t.Fatalf("gap filler: err = %v, want %v", err, core.ErrInsufficientFunds)
			}
		case nonce == 65:
			if !errors.Is(err, txpool.ErrAccountLimitExceeded) {
				t.Fatalf("tx 65: err = %v, want %v", err, txpool.ErrAccountLimitExceeded)
			}
		default:
			if err != nil {
				t.Fatalf("tx %d rejected: %v", nonce, err)
			}
		}
	}
	list, _ := pool.queue.get(addr)
	if list.Len() != 64 {
		t.Fatalf("queue size mismatch: have %d, want 64", list.Len())
	}
	for nonce := uint64(1); nonce <= 64; nonce++ {
		if !list.Contains(nonce) {
			t.Fatalf("accepted transaction at nonce %d was evicted", nonce)
		}
	}
	if got := pool.all.Count(); got != 64 {
		t.Fatalf("total transaction mismatch: have %d, want 64", got)
	}
}

// Tests that a gap filler the batch fails to deliver stops justifying the
// transactions above it. A globally full pool would otherwise evict another
// sender's transaction to make room for an admission the final recheck then
// revokes, and that eviction is never paid back.
func TestQueueAdmissionFailedGapFillerDoesNotEvict(t *testing.T) {
	t.Parallel()

	// Sixteen pending slots and eight queued slots, all taken when the batch
	// arrives.
	pool := setupQueueAdmissionPool(t, 4, 16, 8)
	key := fundedKey(t, pool)

	filler := fundedKey(t, pool)
	pending := make(types.Transactions, 0, 16)
	for nonce := uint64(0); nonce < 16; nonce++ {
		pending = append(pending, pricedTransaction(nonce, 100000, big.NewInt(400000000), filler))
	}
	for i, err := range pool.Add(pending, true) {
		if err != nil {
			t.Fatalf("pending tx %d: rejected: %v", i, err)
		}
	}
	// The account queue is filled to the bound above a missing nonce 0.
	fill := make(types.Transactions, 0, 4)
	for nonce := uint64(1); nonce <= 4; nonce++ {
		fill = append(fill, pricedTransaction(nonce, 100000, big.NewInt(900000000), key))
	}
	for i, err := range pool.Add(fill, true) {
		if err != nil {
			t.Fatalf("fill tx %d: rejected: %v", i, err)
		}
	}
	// A second account fills the global queue with cheaper transactions, the
	// eviction candidates of a full pool.
	cheap := fundedKey(t, pool)
	victims := make(types.Transactions, 0, 4)
	for nonce := uint64(1); nonce <= 4; nonce++ {
		tx := pricedTransaction(nonce, 100000, big.NewInt(300000000), cheap)
		if err := pool.Add(types.Transactions{tx}, true)[0]; err != nil {
			t.Fatalf("cheap tx %d: rejected: %v", nonce, err)
		}
		victims = append(victims, tx)
	}
	if slots, limit := uint64(pool.all.Slots()), pool.config.GlobalSlots+pool.config.GlobalQueue; slots != limit {
		t.Fatalf("pool not full: %d of %d slots", slots, limit)
	}
	// The gap filler cannot be paid for, so nonce 5 has no run to belong to.
	// Admitting it would discard a cheap transaction for an admission the final
	// recheck revokes.
	batch := types.Transactions{
		unaffordableTransaction(t, key, 0),
		pricedTransaction(5, 100000, big.NewInt(900000000), key),
	}
	errs := pool.Add(batch, true)
	if !errors.Is(errs[0], core.ErrInsufficientFunds) {
		t.Fatalf("gap filler: err = %v, want %v", errs[0], core.ErrInsufficientFunds)
	}
	if !errors.Is(errs[1], txpool.ErrAccountLimitExceeded) {
		t.Fatalf("nonce 5: err = %v, want %v", errs[1], txpool.ErrAccountLimitExceeded)
	}
	for _, tx := range victims {
		if pool.all.Get(tx.Hash()) == nil {
			t.Fatalf("cheap transaction at nonce %d was evicted for a revoked admission", tx.Nonce())
		}
	}
	if got := pool.all.Count(); got != 24 {
		t.Fatalf("total transaction mismatch: have %d, want 24", got)
	}
}

// Tests that a nonce whose first candidate fails still backs the transactions
// above it while another candidate of the same batch can fill it.
func TestQueueAdmissionLateCandidateFillsGap(t *testing.T) {
	t.Parallel()

	pool := setupQueueLimitPool(t, 4)
	key := fundedKey(t, pool)
	addr := crypto.PubkeyToAddress(key.PublicKey)

	fill := make(types.Transactions, 0, 4)
	for nonce := uint64(1); nonce <= 4; nonce++ {
		fill = append(fill, pricedTransaction(nonce, 100000, big.NewInt(300000000), key))
	}
	for i, err := range pool.Add(fill, true) {
		if err != nil {
			t.Fatalf("fill tx %d: rejected: %v", i, err)
		}
	}
	// The first candidate at nonce 0 cannot be paid for, the second one can, so
	// nonce 5 still belongs to the run the batch completes.
	batch := types.Transactions{
		unaffordableTransaction(t, key, 0),
		pricedTransaction(5, 100000, big.NewInt(300000000), key),
		pricedTransaction(0, 100000, big.NewInt(300000000), key),
	}
	errs := pool.Add(batch, true)
	if !errors.Is(errs[0], core.ErrInsufficientFunds) {
		t.Fatalf("gap filler: err = %v, want %v", errs[0], core.ErrInsufficientFunds)
	}
	for _, i := range []int{1, 2} {
		if errs[i] != nil {
			t.Fatalf("nonce %d: rejected: %v", batch[i].Nonce(), errs[i])
		}
	}
	if got := pool.all.Count(); got != 6 {
		t.Fatalf("total transaction mismatch: have %d, want 6", got)
	}
	list, ok := pool.pending[addr]
	if !ok || list.Len() != 6 {
		t.Fatalf("pending list mismatch: want nonces 0 to 5 pooled")
	}
}

// Tests that a final trim which withdraws several admissions reports all of
// them, in either arrival order: an accepted transaction must never be dropped
// without its submitter learning about it.
func TestQueueAdmissionRevokesEveryTrimmedAdmission(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name  string
		order []uint64
	}{
		{"ascending", []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}},
		{"descending", []uint64{10, 9, 8, 7, 6, 5, 4, 3, 2, 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			pool := setupQueueLimitPool(t, 4)
			key := fundedKey(t, pool)
			addr := crypto.PubkeyToAddress(key.PublicKey)

			batch := make(types.Transactions, 0, len(tc.order)+1)
			for _, nonce := range tc.order {
				batch = append(batch, pricedTransaction(nonce, 100000, big.NewInt(300000000), key))
			}
			batch = append(batch, unaffordableTransaction(t, key, 0))

			for i, err := range pool.Add(batch, true) {
				switch nonce := batch[i].Nonce(); {
				case nonce == 0:
					if !errors.Is(err, core.ErrInsufficientFunds) {
						t.Fatalf("gap filler: err = %v, want %v", err, core.ErrInsufficientFunds)
					}
				case nonce > 4:
					if !errors.Is(err, txpool.ErrAccountLimitExceeded) {
						t.Fatalf("tx %d: err = %v, want %v", nonce, err, txpool.ErrAccountLimitExceeded)
					}
				default:
					if err != nil {
						t.Fatalf("tx %d rejected: %v", nonce, err)
					}
				}
			}
			list, _ := pool.queue.get(addr)
			if list.Len() != 4 {
				t.Fatalf("queue size mismatch: have %d, want 4", list.Len())
			}
			for nonce := uint64(1); nonce <= 4; nonce++ {
				if !list.Contains(nonce) {
					t.Fatalf("accepted transaction at nonce %d was evicted", nonce)
				}
			}
			if got := pool.all.Count(); got != 4 {
				t.Fatalf("total transaction mismatch: have %d, want 4", got)
			}
		})
	}
}

// Tests that a transaction this call accepted and an interim trim then withdrew
// is reported: the trim runs after every insertion, so it can shed a transaction
// of the same batch long before the final recheck, which then has nothing left to
// report.
func TestQueueAdmissionRevokesInterimTrim(t *testing.T) {
	t.Parallel()

	pool := setupQueueLimitPool(t, 2)
	key := fundedKey(t, pool)
	addr := crypto.PubkeyToAddress(key.PublicKey)

	// Inserting nonce 1 makes the queue three transactions deep while nonce 0 is
	// still missing, so the interim trim drops nonce 3 to keep the bound.
	batch := types.Transactions{
		pricedTransaction(3, 100000, big.NewInt(300000000), key),
		pricedTransaction(2, 100000, big.NewInt(300000000), key),
		pricedTransaction(1, 100000, big.NewInt(300000000), key),
	}
	errs := pool.Add(batch, true)
	if !errors.Is(errs[0], txpool.ErrAccountLimitExceeded) {
		t.Fatalf("nonce 3: err = %v, want %v", errs[0], txpool.ErrAccountLimitExceeded)
	}
	for _, i := range []int{1, 2} {
		if errs[i] != nil {
			t.Fatalf("nonce %d: rejected: %v", batch[i].Nonce(), errs[i])
		}
	}
	list, ok := pool.queue.get(addr)
	if !ok || list.Len() != 2 || !list.Contains(1) || !list.Contains(2) || list.Contains(3) {
		t.Fatalf("queue mismatch: want the transactions at nonce 1 and 2 only")
	}
	if got := pool.all.Count(); got != 2 {
		t.Fatalf("total transaction mismatch: have %d, want 2", got)
	}
}

// Tests that a transaction an earlier call admitted is not reported as rejected
// by the batch whose trim happens to withdraw it: the submitter of that
// transaction was already told it was pooled, and this call is not the one
// answering for it.
func TestQueueAdmissionDoesNotReportEarlierVictim(t *testing.T) {
	t.Parallel()

	pool := setupQueueLimitPool(t, 2)
	key := fundedKey(t, pool)
	addr := crypto.PubkeyToAddress(key.PublicKey)

	prefill := types.Transactions{pricedTransaction(3, 100000, big.NewInt(300000000), key)}
	if err := pool.Add(prefill, true)[0]; err != nil {
		t.Fatalf("failed to pre-fill the queue: %v", err)
	}
	// Inserting nonce 1 brings the queue to three transactions with nonce 0
	// still missing, so the interim trim withdraws nonce 3, admitted above.
	batch := types.Transactions{
		pricedTransaction(2, 100000, big.NewInt(300000000), key),
		pricedTransaction(1, 100000, big.NewInt(300000000), key),
	}
	for i, err := range pool.Add(batch, true) {
		if err != nil {
			t.Fatalf("nonce %d: rejected: %v", batch[i].Nonce(), err)
		}
	}
	list, ok := pool.queue.get(addr)
	if !ok || list.Len() != 2 || !list.Contains(1) || !list.Contains(2) || list.Contains(3) {
		t.Fatalf("queue mismatch: want the transactions at nonce 1 and 2 only")
	}
}

// Tests that a queued transaction an earlier call admitted survives the interim
// trim when the batch's projected run frees enough capacity for it.
func TestQueueAdmissionTrimsAfterProjectedPromotion(t *testing.T) {
	t.Parallel()

	pool := setupQueueLimitPool(t, 2)
	key := fundedKey(t, pool)
	addr := crypto.PubkeyToAddress(key.PublicKey)

	prefill := types.Transactions{
		pricedTransaction(4, 100000, big.NewInt(300000000), key),
		pricedTransaction(5, 100000, big.NewInt(300000000), key),
	}
	for i, err := range pool.Add(prefill, true) {
		if err != nil {
			t.Fatalf("prefill tx %d: rejected: %v", prefill[i].Nonce(), err)
		}
	}
	// The batch promotes 0, 1 and 2, which leaves only the pre-filled 4 and 5
	// in the queue: together they are exactly AccountQueue, so the interim trim
	// must not withdraw either of them.
	batch := types.Transactions{
		pricedTransaction(1, 100000, big.NewInt(300000000), key),
		pricedTransaction(2, 100000, big.NewInt(300000000), key),
		pricedTransaction(0, 100000, big.NewInt(300000000), key),
	}
	errs := pool.Add(batch, true)
	for i, err := range errs {
		if err != nil {
			t.Fatalf("tx %d rejected: %v", batch[i].Nonce(), err)
		}
	}
	checkQueueAdmissionResults(t, pool, batch, errs)
	if pending, queued := pool.Stats(); pending != 3 || queued != 2 {
		t.Fatalf("pool stats = (%d pending, %d queued), want (3, 2)", pending, queued)
	}
	list, ok := pool.queue.get(addr)
	if !ok || list.Len() != 2 || !list.Contains(4) || !list.Contains(5) {
		t.Fatalf("queue mismatch: want the pre-filled nonce 4 and 5")
	}
	for _, tx := range prefill {
		if pool.all.Get(tx.Hash()) == nil {
			t.Fatalf("pre-filled nonce %d was evicted", tx.Nonce())
		}
	}
}

// BenchmarkQueueAdmissionBatch measures one large batch from a single account,
// the shape a peer response can deliver. The ordered burst is the case where
// neither admission nor the trim may walk the rest of the batch: the queue's
// cached run already covers every insertion.
func BenchmarkQueueAdmissionBatch(b *testing.B) {
	for _, size := range []uint64{512, 4096} {
		for _, order := range []string{"ordered", "gapfill-last"} {
			b.Run(fmt.Sprintf("%s/%d", order, size), func(b *testing.B) {
				key, _ := crypto.GenerateKey()
				for i := 0; i < b.N; i++ {
					b.StopTimer()
					pool := newQueueLimitPool(b, 64)
					testAddBalance(pool, crypto.PubkeyToAddress(key.PublicKey), new(big.Int).Exp(big.NewInt(10), big.NewInt(22), nil))

					batch := make(types.Transactions, 0, size)
					if order == "ordered" {
						for nonce := uint64(0); nonce < size; nonce++ {
							batch = append(batch, pricedTransaction(nonce, 100000, big.NewInt(300000000), key))
						}
					} else {
						for nonce := uint64(1); nonce < size; nonce++ {
							batch = append(batch, pricedTransaction(nonce, 100000, big.NewInt(300000000), key))
						}
						batch = append(batch, pricedTransaction(0, 100000, big.NewInt(300000000), key))
					}
					b.StartTimer()

					pool.Add(batch, true)

					b.StopTimer()
					pool.Close()
				}
			})
		}
	}
}

// Tests that a burst that leaves the head nonce missing is still bounded: the
// highest nonces are refused at admission, matching the promote-time trim.
func TestQueueAdmissionGappedBurstRejectsHighest(t *testing.T) {
	t.Parallel()

	pool := setupQueueLimitPool(t, 64)
	key := fundedKey(t, pool)

	batch := make(types.Transactions, 0, 100)
	for nonce := uint64(1); nonce <= 100; nonce++ {
		batch = append(batch, pricedTransaction(nonce, 100000, big.NewInt(300000000), key))
	}
	for i, err := range pool.Add(batch, true) {
		nonce := batch[i].Nonce()
		if nonce <= 64 {
			if err != nil {
				t.Fatalf("tx %d rejected: %v", nonce, err)
			}
			continue
		}
		if !errors.Is(err, txpool.ErrAccountLimitExceeded) {
			t.Fatalf("tx %d: err = %v, want %v", nonce, err, txpool.ErrAccountLimitExceeded)
		}
	}
	list, _ := pool.queue.get(crypto.PubkeyToAddress(key.PublicKey))
	if list.Len() != 64 {
		t.Fatalf("queue size mismatch: have %d, want 64", list.Len())
	}
	for nonce := uint64(1); nonce <= 64; nonce++ {
		if !list.Contains(nonce) {
			t.Fatalf("accepted transaction at nonce %d is missing", nonce)
		}
	}
	if got := pool.all.Count(); got != 64 {
		t.Fatalf("total transaction mismatch: have %d, want 64", got)
	}
}

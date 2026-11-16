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
	"math/big"
	"testing"

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
func setupQueueLimitPool(t *testing.T, accountQueue uint64) *LegacyPool {
	t.Helper()

	return setupQueueAdmissionPool(t, accountQueue, testTxPoolConfig.GlobalSlots, testTxPoolConfig.GlobalQueue)
}

// setupQueueAdmissionPool creates a pool with custom per-account and global
// limits.
func setupQueueAdmissionPool(t *testing.T, accountQueue, globalSlots, globalQueue uint64) *LegacyPool {
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
	t.Cleanup(func() { pool.Close() })
	<-pool.initDoneCh

	return pool
}

func fundedKey(t *testing.T, pool *LegacyPool) *ecdsa.PrivateKey {
	t.Helper()

	key, _ := crypto.GenerateKey()
	testAddBalance(pool, crypto.PubkeyToAddress(key.PublicKey), big.NewInt(1_000_000_000_000_000))
	return key
}

// Tests that a burst of executable transactions is admitted in full even when
// it is longer than AccountQueue: during the batch they still sit in the queue,
// but each one fills or extends the run from the pending nonce.
func TestQueueAdmissionAllowsExecutableBurst(t *testing.T) {
	t.Parallel()

	pool := setupQueueLimitPool(t, 2)
	key := fundedKey(t, pool)

	// The burst is longer than AccountQueue but still inside this branch's
	// admission nonce window; the bound under test is the queue limit.
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

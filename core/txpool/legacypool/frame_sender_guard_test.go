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
	"errors"
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/tracing"
	"github.com/XinFinOrg/XDPoSChain/core/txpool"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/crypto"
)

// The specification admits at most one PENDING frame transaction per sender.
// The guard must be PENDING-only: a gapped (queued) frame transaction holds a
// payer reservation but must NOT refuse the sender's further admissions, and
// promotion is the point where the one-pending invariant is enforced. These
// tests pin that design (QUEUED_GUARD_REVIEW §5).

// pendingFrameCount returns how many frame transactions the sender currently
// has in the pending pool.
func pendingFrameCount(pool *LegacyPool, sender common.Address) int {
	list := pool.pending[sender]
	if list == nil {
		return 0
	}
	count := 0
	for _, tx := range list.Flatten() {
		if tx.Type() == types.FrameTxType {
			count++
		}
	}
	return count
}

// queuedTxns returns the sender's queued (gapped) transactions, if any.
func queuedTxns(pool *LegacyPool, sender common.Address) types.Transactions {
	if list, ok := pool.queue.get(sender); ok {
		return list.Flatten()
	}
	return nil
}

// TestFrameSenderGuard_QueuedDoesNotBlockAdmit: a sender with a gapped
// (queued) frame transaction must still be able to admit an executable frame
// transaction at the fillable nonce; the new tx promotes to pending while the
// gapped one stays queued. (RED before the PENDING-only guard: the bySender
// reservation taken at queued admission refused the second admission.)
func TestFrameSenderGuard_QueuedDoesNotBlockAdmit(t *testing.T) {
	pool, statedb := setupFramePool(t)
	key, _ := crypto.GenerateKey()
	sender := crypto.PubkeyToAddress(key.PublicKey)
	fund(statedb, sender, 10_000_000_000)

	gap := signedPayTx(t, key, 1, 100, common.Address{}, key)
	if err := pool.addRemoteSync(gap); err != nil {
		t.Fatalf("gapped frame tx rejected: %v", err)
	}
	if n := pendingFrameCount(pool, sender); n != 0 {
		t.Fatalf("gapped tx landed in pending (count %d)", n)
	}
	if q := queuedTxns(pool, sender); len(q) != 1 || q[0].Hash() != gap.Hash() {
		t.Fatalf("gapped tx not queued: %v", q)
	}

	fill := signedPayTx(t, key, 0, 100, common.Address{}, key)
	if err := pool.addRemoteSync(fill); err != nil {
		t.Fatalf("executable frame tx refused behind queued one: %v", err)
	}
	if n := pendingFrameCount(pool, sender); n != 1 {
		t.Fatalf("pending frame count %d, want 1", n)
	}
	if pool.pending[sender].Flatten()[0].Hash() != fill.Hash() {
		t.Fatal("wrong frame transaction in pending")
	}
	if q := queuedTxns(pool, sender); len(q) != 1 || q[0].Hash() != gap.Hash() {
		t.Fatalf("queued frame tx displaced: %v", q)
	}
}

// TestFrameSenderGuard_OnePendingAtPromotion: two frame txs of one sender
// becoming executable in one cycle keep exactly one pending; the second stays
// queued until the first leaves pending, then promotes.
func TestFrameSenderGuard_OnePendingAtPromotion(t *testing.T) {
	pool, statedb := setupFramePool(t)
	key, _ := crypto.GenerateKey()
	sender := crypto.PubkeyToAddress(key.PublicKey)
	fund(statedb, sender, 10_000_000_000)

	second := signedPayTx(t, key, 1, 100, common.Address{}, key)
	if err := pool.addRemoteSync(second); err != nil {
		t.Fatalf("queued frame tx rejected: %v", err)
	}
	first := signedPayTx(t, key, 0, 100, common.Address{}, key)
	if err := pool.addRemoteSync(first); err != nil {
		t.Fatalf("executable frame tx refused behind queued one: %v", err)
	}
	if n := pendingFrameCount(pool, sender); n != 1 {
		t.Fatalf("pending frame count %d, want 1 (one must stay queued)", n)
	}
	if pool.pending[sender].Flatten()[0].Hash() != first.Hash() {
		t.Fatal("the executable nonce did not promote first")
	}
	if q := queuedTxns(pool, sender); len(q) != 1 || q[0].Hash() != second.Hash() {
		t.Fatalf("second frame tx not held in queue: %v", q)
	}

	// First leaves pending via inclusion; the queued one must then promote.
	statedb.SetNonce(sender, 1, tracing.NonceChangeUnspecified)
	pool.demoteUnexecutables()
	pool.promoteExecutables([]common.Address{sender})
	if n := pendingFrameCount(pool, sender); n != 1 {
		t.Fatalf("pending frame count %d after promotion, want 1", n)
	}
	if pool.pending[sender].Flatten()[0].Hash() != second.Hash() {
		t.Fatal("queued frame tx did not promote after the first left pending")
	}
}

// TestFrameSenderGuard_ReorgDemote: a demote (reorg) that places the sender's
// frame txs back into executable position must not create two pending frame
// txs — the next promote cycle keeps exactly one pending.
func TestFrameSenderGuard_ReorgDemote(t *testing.T) {
	pool, statedb := setupFramePool(t)
	key, _ := crypto.GenerateKey()
	sender := crypto.PubkeyToAddress(key.PublicKey)
	fund(statedb, sender, 10_000_000_000)

	f0 := signedPayTx(t, key, 1, 100, common.Address{}, key)
	f1 := signedPayTx(t, key, 2, 100, common.Address{}, key)
	for _, tx := range []*types.Transaction{f0, f1} {
		if err := pool.addRemoteSync(tx); err != nil {
			t.Fatalf("setup admission rejected: %v", err)
		}
	}
	// Simulate the state a reorg can resurrect (e.g. reinjection after a
	// deep reorg): both frame txs sitting in pending at once. The promotion
	// gate makes this unreachable by construction at admission time, but a
	// demote cycle must repair it if it ever arises.
	pool.mu.Lock()
	pool.promoteTx(sender, f0.Hash(), f0)
	pool.promoteTx(sender, f1.Hash(), f1)
	pool.mu.Unlock()
	if n := pendingFrameCount(pool, sender); n != 2 {
		t.Fatalf("setup pending frame count %d, want 2", n)
	}
	// Reorg rolls the head back to nonce 0: both demote into the queue.
	statedb.SetNonce(sender, 0, tracing.NonceChangeUnspecified)
	pool.demoteUnexecutables()
	if n := pendingFrameCount(pool, sender); n != 0 {
		t.Fatalf("pending frame count %d after demote, want 0", n)
	}
	if q := queuedTxns(pool, sender); len(q) != 2 {
		t.Fatalf("both frame txs must sit in the queue after demote, have %d", len(q))
	}
	// Head returns to nonce 1: the promote cycle keeps exactly one pending.
	statedb.SetNonce(sender, 1, tracing.NonceChangeUnspecified)
	pool.promoteExecutables([]common.Address{sender})
	if n := pendingFrameCount(pool, sender); n != 1 {
		t.Fatalf("pending frame count %d after re-promote, want 1", n)
	}
	if q := queuedTxns(pool, sender); len(q) != 1 {
		t.Fatalf("held-back frame tx must stay queued, have %d", len(q))
	}
}

// TestFrameSenderGuard_ReservationFollowsAccounting: the PENDING-only sender
// guard must not weaken payer accounting — a queued frame tx still reserves
// its max_fee alongside a pending one, and take/release idempotency holds
// through the removeTx, replacement and expiry removal paths.
func TestFrameSenderGuard_ReservationFollowsAccounting(t *testing.T) {
	pool, statedb := setupFramePool(t)
	key, _ := crypto.GenerateKey()
	sender := crypto.PubkeyToAddress(key.PublicKey)
	fund(statedb, sender, 10_000_000_000)

	// One pending + one queued frame tx from the same sender: both max_fees
	// must be reserved against the payer.
	gap := signedPayTx(t, key, 1, 100, common.Address{}, key)
	if err := pool.addRemoteSync(gap); err != nil {
		t.Fatalf("queued frame tx rejected: %v", err)
	}
	fill := signedPayTx(t, key, 0, 100, common.Address{}, key)
	if err := pool.addRemoteSync(fill); err != nil {
		t.Fatalf("executable frame tx refused behind queued one: %v", err)
	}
	both := new(big.Int).Add(maxFeeOf(t, gap), maxFeeOf(t, fill))
	if got := reservedOf(pool, sender); got.Cmp(both) != 0 {
		t.Fatalf("reserved %v, want pending+queued max_fees %v", got, both)
	}

	// removeTx path: dropping the queued tx releases exactly its reservation.
	pool.removeTx(gap.Hash(), true, true)
	if got := reservedOf(pool, sender); got.Cmp(maxFeeOf(t, fill)) != 0 {
		t.Fatalf("reserved %v after queued removal, want %v", got, maxFeeOf(t, fill))
	}
	// Idempotent release: removing the same tx again changes nothing.
	pool.removeTx(gap.Hash(), true, true)
	if got := reservedOf(pool, sender); got.Cmp(maxFeeOf(t, fill)) != 0 {
		t.Fatalf("reserved %v after idempotent re-removal, want %v", got, maxFeeOf(t, fill))
	}

	// Replacement path: same-nonce replacement of the pending tx shifts the
	// reservation atomically.
	repl := signedPayTxTip(t, key, 0, 111, 2, common.Address{}, key)
	if err := pool.addRemoteSync(repl); err != nil {
		t.Fatalf("replacement rejected: %v", err)
	}
	if got := reservedOf(pool, sender); got.Cmp(maxFeeOf(t, repl)) != 0 {
		t.Fatalf("reserved %v after replacement, want %v", got, maxFeeOf(t, repl))
	}

	// Expiry path: an expired pending frame tx is evicted and its reservation
	// released, leaving the pool accounting empty.
	pool2, statedb2 := setupFramePool(t)
	key2, _ := crypto.GenerateKey()
	sender2 := crypto.PubkeyToAddress(key2.PublicKey)
	fund(statedb2, sender2, 10_000_000_000)
	expiring := signedExpiryPayTx(t, key2, 0, 100, common.Address{}, key2, 5)
	if err := pool2.addRemoteSync(expiring); err != nil {
		t.Fatalf("expiry tx rejected: %v", err)
	}
	if got := reservedOf(pool2, sender2); got.Cmp(maxFeeOf(t, expiring)) != 0 {
		t.Fatalf("reserved %v, want %v", got, maxFeeOf(t, expiring))
	}
	head := pool2.currentHead.Load()
	later := *types.CopyHeader(head)
	later.Time = 6 // deadline 5 is expired at time 6 (expiration is now > deadline)
	pool2.Reset(&later, &later)
	pool2.evictExpiredFrameTxs()
	if pool2.all.Get(expiring.Hash()) != nil {
		t.Fatal("expired frame tx not evicted")
	}
	if got := reservedOf(pool2, sender2); got.Sign() != 0 {
		t.Fatalf("expiry path leaked reservation: %v", got)
	}
}

// TestFrameSenderGuard_LegacyUnaffected: legacy transactions from the same
// sender are never gated by the frame invariant, and pure-legacy senders keep
// their existing multi-tx behavior.
func TestFrameSenderGuard_LegacyUnaffected(t *testing.T) {
	pool, statedb := setupFramePool(t)
	key, _ := crypto.GenerateKey()
	sender := crypto.PubkeyToAddress(key.PublicKey)
	legacyKey, _ := crypto.GenerateKey()
	legacySender := crypto.PubkeyToAddress(legacyKey.PublicKey)
	fund(statedb, sender, 10_000_000_000)
	fund(statedb, legacySender, 10_000_000_000)

	// Frame tx pending; legacy txs at later nonces flow normally.
	if err := pool.addRemoteSync(signedPayTx(t, key, 0, 100, common.Address{}, key)); err != nil {
		t.Fatalf("frame tx rejected: %v", err)
	}
	if err := pool.addRemoteSync(transaction(1, 21000, key)); err != nil {
		t.Fatalf("legacy tx behind pending frame rejected: %v", err)
	}
	if err := pool.addRemoteSync(transaction(2, 21000, key)); err != nil {
		t.Fatalf("second legacy tx rejected: %v", err)
	}
	if n := len(pool.pending[sender].Flatten()); n != 3 {
		t.Fatalf("mixed sender pending count %d, want 3", n)
	}

	// Pure legacy sender: a burst of executable and gapped txs is untouched.
	for i := uint64(0); i < 3; i++ {
		if err := pool.addRemoteSync(transaction(i, 21000, legacyKey)); err != nil {
			t.Fatalf("legacy burst tx %d rejected: %v", i, err)
		}
	}
	if n := len(pool.pending[legacySender].Flatten()); n != 3 {
		t.Fatalf("legacy sender pending count %d, want 3", n)
	}

	// A second frame tx from the mixed sender is still refused while one is
	// pending: the invariant itself is intact (now enforced PENDING-only).
	err := pool.addRemoteSync(signedPayTx(t, key, 3, 100, common.Address{}, key))
	if !errors.Is(err, ErrFrameSenderPendingLimit) {
		t.Fatalf("second pending frame tx accepted: %v", err)
	}
}

// TestFrameSenderGuard_SameNonceReplacementStillWorks: the pending and queued
// same-nonce replacement paths keep enforcing the price bump on both declared
// fee fields and shift the reservation atomically (no regression of the
// checkReplace/applyReplacement flow).
func TestFrameSenderGuard_SameNonceReplacementStillWorks(t *testing.T) {
	pool, statedb := setupFramePool(t)
	key, _ := crypto.GenerateKey()
	sender := crypto.PubkeyToAddress(key.PublicKey)
	fund(statedb, sender, 10_000_000_000)

	// Pending replacement path.
	old := signedPayTx(t, key, 0, 100, common.Address{}, key)
	if err := pool.addRemoteSync(old); err != nil {
		t.Fatalf("initial admission failed: %v", err)
	}
	under := signedPayTxTip(t, key, 0, 111, 1, common.Address{}, key) // feeCap bumped, tip not
	if err := pool.addRemoteSync(under); !errors.Is(err, txpool.ErrReplaceUnderpriced) {
		t.Fatalf("under-bumped pending replacement accepted: %v", err)
	}
	if got := reservedOf(pool, sender); got.Cmp(maxFeeOf(t, old)) != 0 {
		t.Fatalf("pending reservation disturbed by rejected replacement: %v", got)
	}
	repl := signedPayTxTip(t, key, 0, 111, 2, common.Address{}, key)
	if err := pool.addRemoteSync(repl); err != nil {
		t.Fatalf("valid pending replacement rejected: %v", err)
	}
	if got := reservedOf(pool, sender); got.Cmp(maxFeeOf(t, repl)) != 0 {
		t.Fatalf("pending reservation not shifted: %v, want %v", got, maxFeeOf(t, repl))
	}

	// Queued replacement path: the gapped frame tx is replaced in place and
	// its reservation shifts without touching the pending one.
	key2, _ := crypto.GenerateKey()
	sender2 := crypto.PubkeyToAddress(key2.PublicKey)
	fund(statedb, sender2, 10_000_000_000)
	queued := signedPayTx(t, key2, 1, 100, common.Address{}, key2)
	if err := pool.addRemoteSync(queued); err != nil {
		t.Fatalf("queued admission failed: %v", err)
	}
	qunder := signedPayTxTip(t, key2, 1, 111, 1, common.Address{}, key2)
	if err := pool.addRemoteSync(qunder); !errors.Is(err, txpool.ErrReplaceUnderpriced) {
		t.Fatalf("under-bumped queued replacement accepted: %v", err)
	}
	qrepl := signedPayTxTip(t, key2, 1, 111, 2, common.Address{}, key2)
	if err := pool.addRemoteSync(qrepl); err != nil {
		t.Fatalf("valid queued replacement rejected: %v", err)
	}
	q := queuedTxns(pool, sender2)
	if len(q) != 1 || q[0].Hash() != qrepl.Hash() {
		t.Fatalf("queued replacement not in place: %v", q)
	}
	if got := reservedOf(pool, sender2); got.Cmp(maxFeeOf(t, qrepl)) != 0 {
		t.Fatalf("queued reservation not shifted: %v, want %v", got, maxFeeOf(t, qrepl))
	}
}

// TestFrameSenderGuard_ReplacementKeepsSiblingQueuedReservation: replacing
// the sender's PENDING frame transaction must shift only the same-(sender,
// nonce) reservation. A sibling QUEUED frame reservation admitted under the
// QUEUED guard must survive the replacement with its payer accounting intact
// (independent review finding B1).
func TestFrameSenderGuard_ReplacementKeepsSiblingQueuedReservation(t *testing.T) {
	pool, statedb := setupFramePool(t)
	key, _ := crypto.GenerateKey()
	sender := crypto.PubkeyToAddress(key.PublicKey)
	fund(statedb, sender, 10_000_000_000)

	// Mixed state introduced by the QUEUED guard: one queued (gapped) frame
	// tx at nonce 1 and one pending frame tx at nonce 0 from one sender.
	gap := signedPayTx(t, key, 1, 100, common.Address{}, key)
	if err := pool.addRemoteSync(gap); err != nil {
		t.Fatalf("queued frame tx rejected: %v", err)
	}
	pending := signedPayTx(t, key, 0, 100, common.Address{}, key)
	if err := pool.addRemoteSync(pending); err != nil {
		t.Fatalf("pending frame tx rejected: %v", err)
	}
	both := new(big.Int).Add(maxFeeOf(t, gap), maxFeeOf(t, pending))
	if got := reservedOf(pool, sender); got.Cmp(both) != 0 {
		t.Fatalf("reserved %v, want pending+queued max_fees %v", got, both)
	}

	// Replace the PENDING tx at nonce 0 (both declared fee fields bumped).
	repl := signedPayTxTip(t, key, 0, 111, 2, common.Address{}, key)
	if err := pool.addRemoteSync(repl); err != nil {
		t.Fatalf("pending replacement rejected: %v", err)
	}

	// B1 regression: the sibling queued reservation entry must remain...
	pool.frameRes.mu.Lock()
	_, siblingOK := pool.frameRes.bySender[sender][gap.Nonce()]
	pool.frameRes.mu.Unlock()
	if !siblingOK {
		t.Fatal("sibling queued reservation entry dropped by pending replacement")
	}
	// ...both physically queued and fully accounted against the payer.
	if q := queuedTxns(pool, sender); len(q) != 1 || q[0].Hash() != gap.Hash() {
		t.Fatalf("sibling queued tx displaced: %v", q)
	}
	want := new(big.Int).Add(maxFeeOf(t, gap), maxFeeOf(t, repl))
	if got := reservedOf(pool, sender); got.Cmp(want) != 0 {
		t.Fatalf("reserved %v after pending replacement, want %v (replacement + sibling)", got, want)
	}

	// Cleanup path A: removing the sibling leaves exactly the replacement's
	// reservation; a second removal is idempotent.
	pool.removeTx(gap.Hash(), true, true)
	if got := reservedOf(pool, sender); got.Cmp(maxFeeOf(t, repl)) != 0 {
		t.Fatalf("reserved %v after sibling removal, want %v", got, maxFeeOf(t, repl))
	}
	pool.removeTx(gap.Hash(), true, true)
	if got := reservedOf(pool, sender); got.Cmp(maxFeeOf(t, repl)) != 0 {
		t.Fatalf("reserved %v after idempotent sibling re-removal, want %v", got, maxFeeOf(t, repl))
	}

	// Cleanup path B (fresh pool): inclusion of the replacement lets the
	// sibling promote; its reservation follows it into pending untouched.
	pool2, statedb2 := setupFramePool(t)
	key2, _ := crypto.GenerateKey()
	sender2 := crypto.PubkeyToAddress(key2.PublicKey)
	fund(statedb2, sender2, 10_000_000_000)
	gap2 := signedPayTx(t, key2, 1, 100, common.Address{}, key2)
	if err := pool2.addRemoteSync(gap2); err != nil {
		t.Fatalf("cleanup-B queued frame tx rejected: %v", err)
	}
	pending2 := signedPayTx(t, key2, 0, 100, common.Address{}, key2)
	if err := pool2.addRemoteSync(pending2); err != nil {
		t.Fatalf("cleanup-B pending frame tx rejected: %v", err)
	}
	repl2 := signedPayTxTip(t, key2, 0, 111, 2, common.Address{}, key2)
	if err := pool2.addRemoteSync(repl2); err != nil {
		t.Fatalf("cleanup-B pending replacement rejected: %v", err)
	}
	want2 := new(big.Int).Add(maxFeeOf(t, gap2), maxFeeOf(t, repl2))
	if got := reservedOf(pool2, sender2); got.Cmp(want2) != 0 {
		t.Fatalf("cleanup-B reserved %v after replacement, want %v", got, want2)
	}
	// Nonce 0 included: the replacement leaves the pool and the sibling
	// promotes; only the sibling reservation remains.
	statedb2.SetNonce(sender2, 1, tracing.NonceChangeUnspecified)
	pool2.demoteUnexecutables()
	pool2.promoteExecutables([]common.Address{sender2})
	if n := pendingFrameCount(pool2, sender2); n != 1 {
		t.Fatalf("cleanup-B pending frame count %d, want 1", n)
	}
	if pool2.pending[sender2].Flatten()[0].Hash() != gap2.Hash() {
		t.Fatal("cleanup-B sibling did not promote after replacement inclusion")
	}
	if got := reservedOf(pool2, sender2); got.Cmp(maxFeeOf(t, gap2)) != 0 {
		t.Fatalf("cleanup-B reserved %v after sibling promotion, want %v", got, maxFeeOf(t, gap2))
	}
}

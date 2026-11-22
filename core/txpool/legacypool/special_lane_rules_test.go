// Copyright 2026 The XDPoSChain Authors
// This file is part of the XDPoSChain library.
//
// The XDPoSChain library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The XDPoSChain library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the XDPoSChain library. If not, see <http://www.gnu.org/licenses/>.

package legacypool

import (
	"errors"
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/txpool"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/crypto"
)

// TestSpecialLaneFloodAtCap checks that many candidates, each at the special
// transaction cap, neither stop regular transactions from being admitted up to
// the pool limit nor get regular transactions evicted, and that each of them
// is held to the cap.
func TestSpecialLaneFloodAtCap(t *testing.T) {
	t.Parallel()

	pool, _ := setupPool()
	defer pool.Close()
	pool.SetSigner(func(common.Address) bool { return true })
	pool.config.GlobalSlots = 4
	pool.config.GlobalQueue = 0

	const candidates = 10
	for i := 0; i < candidates; i++ {
		key := laneKey(pool)
		for nonce := uint64(0); nonce < maxSpecialTxsPerAccount; nonce++ {
			if err := pool.addRemoteSync(laneRandomizeTx(t, key, nonce, byte(nonce))); err != nil {
				t.Fatalf("candidate %d: special tx %d rejected: %v", i, nonce, err)
			}
		}
		if err := pool.addRemoteSync(laneRandomizeTx(t, key, maxSpecialTxsPerAccount, 0xff)); !errors.Is(err, ErrSpecialTxLimit) {
			t.Fatalf("candidate %d: special tx past the cap: err = %v, want %v", i, err, ErrSpecialTxLimit)
		}
	}
	user := laneKey(pool)
	var regular []*types.Transaction
	for nonce := uint64(0); nonce < 4; nonce++ {
		tx := pricedTransaction(nonce, 100000, big.NewInt(common.DefaultMinGasPrice), user)
		if err := pool.addRemoteSync(tx); err != nil {
			t.Fatalf("regular tx %d rejected next to the special txs: %v", nonce, err)
		}
		regular = append(regular, tx)
	}
	for _, tx := range regular {
		if pool.all.Get(tx.Hash()) == nil {
			t.Fatalf("regular tx %d was evicted", tx.Nonce())
		}
	}
	if pending, _ := pool.Stats(); pending != candidates*maxSpecialTxsPerAccount+4 {
		t.Fatalf("pending = %d, want %d", pending, candidates*maxSpecialTxsPerAccount+4)
	}
	if err := validatePoolInternals(pool); err != nil {
		t.Fatalf("pool internal state corrupted: %v", err)
	}
}

// TestSpecialLaneSignTxReplacement checks that a pooled sign transaction,
// pending or queued, is replaced only by a sign transaction for a strictly
// newer block: a randomize transaction, a regular transaction, or a sign
// transaction for the same or an older block is refused.
func TestSpecialLaneSignTxReplacement(t *testing.T) {
	t.Parallel()

	pool, _ := setupPool()
	defer pool.Close()
	pool.SetSigner(func(common.Address) bool { return true })
	// At head 60 the merge blocks 0 to 75 can be signed.
	<-pool.requestReset(nil, newTestHeader(60))

	key := laneKey(pool)
	pending := laneSignTx(t, key, 0, 30, 1)
	queued := laneSignTx(t, key, 5, 15, 1)
	for _, tx := range []*types.Transaction{pending, queued} {
		if err := pool.addRemoteSync(tx); err != nil {
			t.Fatalf("failed to add sign tx %d: %v", tx.Nonce(), err)
		}
	}
	for _, tc := range []struct {
		name string
		tx   *types.Transaction
		want error
	}{
		{"pending, same block", laneSignTx(t, key, 0, 30, 2), ErrSignTxNotNewer},
		{"pending, older block", laneSignTx(t, key, 0, 0, 2), ErrSignTxNotNewer},
		{"pending, randomize", laneRandomizeTx(t, key, 0, 2), ErrSignTxNotNewer},
		{"pending, regular", pricedTransaction(0, 100000, big.NewInt(2*common.DefaultMinGasPrice), key), txpool.ErrReplaceUnderpriced},
		{"queued, same block", laneSignTx(t, key, 5, 15, 2), ErrSignTxNotNewer},
		{"queued, older block", laneSignTx(t, key, 5, 0, 2), ErrSignTxNotNewer},
		{"queued, randomize", laneRandomizeTx(t, key, 5, 2), ErrSignTxNotNewer},
		{"queued, regular", pricedTransaction(5, 100000, big.NewInt(2*common.DefaultMinGasPrice), key), txpool.ErrReplaceUnderpriced},
	} {
		if err := pool.addRemoteSync(tc.tx); !errors.Is(err, tc.want) {
			t.Fatalf("%s: err = %v, want %v", tc.name, err, tc.want)
		}
		if pool.all.Get(tc.tx.Hash()) != nil {
			t.Fatalf("%s: the refused replacement is pooled", tc.name)
		}
	}
	if pool.all.Get(pending.Hash()) == nil || pool.all.Get(queued.Hash()) == nil {
		t.Fatal("a refused replacement evicted the pooled sign tx")
	}
	// Newer blocks replace, any number of times.
	for _, signed := range []uint64{45, 60, 75} {
		tx := laneSignTx(t, key, 0, signed, 3)
		if err := pool.addRemoteSync(tx); err != nil {
			t.Fatalf("pending sign tx for block %d rejected: %v", signed, err)
		}
		if pool.all.Get(tx.Hash()) == nil {
			t.Fatalf("pending sign tx for block %d not pooled", signed)
		}
	}
	if err := pool.addRemoteSync(laneSignTx(t, key, 5, 30, 3)); err != nil {
		t.Fatalf("queued sign tx for a newer block rejected: %v", err)
	}
	if pool.all.Get(pending.Hash()) != nil || pool.all.Get(queued.Hash()) != nil {
		t.Fatal("replaced sign txs are still pooled")
	}
	if err := validatePoolInternals(pool); err != nil {
		t.Fatalf("pool internal state corrupted: %v", err)
	}
}

// TestSpecialLaneRandomizeReplacement checks that a pooled randomize
// transaction, pending or queued, is replaced by any transaction at its nonce:
// another randomize transaction (any number of times), a sign transaction, or
// a regular one without a price bump. A regular replacement moves the slot
// from the special budget to the regular one. Replacements by special
// transactions still work on a full pool.
func TestSpecialLaneRandomizeReplacement(t *testing.T) {
	t.Parallel()

	pool, _ := setupPool()
	defer pool.Close()
	pool.SetSigner(func(common.Address) bool { return true })
	pool.config.GlobalSlots = 2
	pool.config.GlobalQueue = 0
	<-pool.requestReset(nil, newTestHeader(60))

	key := laneKey(pool)
	addr := crypto.PubkeyToAddress(key.PublicKey)
	for _, tx := range []*types.Transaction{laneSignTx(t, key, 0, 60, 1), laneRandomizeTx(t, key, 1, 1), laneRandomizeTx(t, key, 2, 1), laneRandomizeTx(t, key, 6, 1)} {
		if err := pool.addRemoteSync(tx); err != nil {
			t.Fatalf("failed to add special tx %d: %v", tx.Nonce(), err)
		}
	}
	// Fill the pool with regular transactions from another sender.
	user := laneKey(pool)
	for nonce := uint64(0); nonce < 2; nonce++ {
		if err := pool.addRemoteSync(pricedTransaction(nonce, 100000, big.NewInt(common.DefaultMinGasPrice), user)); err != nil {
			t.Fatalf("failed to fill the pool, tx %d: %v", nonce, err)
		}
	}
	// Randomize replaced by randomize, repeatedly, on the full pool.
	for tag := byte(2); tag <= 4; tag++ {
		tx := laneRandomizeTx(t, key, 1, tag)
		if err := pool.addRemoteSync(tx); err != nil {
			t.Fatalf("randomize replacing randomize (tag %d) rejected: %v", tag, err)
		}
		if pool.all.Get(tx.Hash()) == nil {
			t.Fatalf("randomize replacement (tag %d) not pooled", tag)
		}
	}
	// Randomize replaced by a sign tx, on the full pool.
	bySign := laneSignTx(t, key, 1, 45, 1)
	if err := pool.addRemoteSync(bySign); err != nil {
		t.Fatalf("sign tx replacing randomize rejected: %v", err)
	}
	if pool.all.Get(bySign.Hash()) == nil {
		t.Fatal("sign tx replacing randomize not pooled")
	}
	// Make room for regular transactions, then replace a pending and a queued
	// randomize tx by regular ones at the minimum price, without a price bump.
	pool.config.GlobalSlots = 16
	specialsBefore := len(pool.pooledSpecials(addr))
	slotsBefore := pool.all.Slots()
	for _, nonce := range []uint64{2, 6} {
		tx := pricedTransaction(nonce, 100000, big.NewInt(common.DefaultMinGasPrice), key)
		if err := pool.addRemoteSync(tx); err != nil {
			t.Fatalf("regular tx replacing the randomize tx at nonce %d rejected: %v", nonce, err)
		}
		if pool.all.Get(tx.Hash()) == nil {
			t.Fatalf("regular replacement at nonce %d not pooled", nonce)
		}
	}
	if have := len(pool.pooledSpecials(addr)); have != specialsBefore-2 {
		t.Fatalf("pooled special txs = %d, want %d", have, specialsBefore-2)
	}
	if have := pool.all.Slots(); have != slotsBefore+2 {
		t.Fatalf("regular slots = %d, want %d", have, slotsBefore+2)
	}
	if err := validatePoolInternals(pool); err != nil {
		t.Fatalf("pool internal state corrupted: %v", err)
	}
}

// TestSpecialLaneSenderCap checks that one sender may pool at most
// maxSpecialTxsPerAccount special transactions, pending and queued together,
// that replacing one of them at the same nonce is still accepted at the cap,
// and that the cap does not apply to the sender's regular transactions.
func TestSpecialLaneSenderCap(t *testing.T) {
	t.Parallel()

	pool, _ := setupPool()
	defer pool.Close()
	pool.SetSigner(func(common.Address) bool { return true })

	key := laneKey(pool)
	first := laneSignTx(t, key, 0, 0, 1)
	if err := pool.addRemoteSync(first); err != nil {
		t.Fatalf("failed to add the sign tx: %v", err)
	}
	// Nonces 1-9 pending, 11-16 queued behind a gap at 10: 16 special txs.
	for nonce := uint64(1); nonce <= 16; nonce++ {
		if nonce == 10 {
			continue
		}
		if err := pool.addRemoteSync(laneRandomizeTx(t, key, nonce, byte(nonce))); err != nil {
			t.Fatalf("special tx %d rejected below the cap: %v", nonce, err)
		}
	}
	if pending, queued := pool.Stats(); pending != 10 || queued != 6 {
		t.Fatalf("pool stats = (%d pending, %d queued), want (10, 6)", pending, queued)
	}
	for _, nonce := range []uint64{10, 20} {
		if err := pool.addRemoteSync(laneRandomizeTx(t, key, nonce, byte(nonce))); !errors.Is(err, ErrSpecialTxLimit) {
			t.Fatalf("17th special tx at nonce %d: err = %v, want %v", nonce, err, ErrSpecialTxLimit)
		}
	}
	// A replacement at the cap does not grow the count.
	newer := laneSignTx(t, key, 0, 15, 2)
	if err := pool.addRemoteSync(newer); err != nil {
		t.Fatalf("replacement at the cap rejected: %v", err)
	}
	if pool.all.Get(first.Hash()) != nil || pool.all.Get(newer.Hash()) == nil {
		t.Fatal("the sign tx was not replaced")
	}
	// The sender's regular transactions are not capped.
	if err := pool.addRemoteSync(pricedTransaction(10, 100000, big.NewInt(common.DefaultMinGasPrice), key)); err != nil {
		t.Fatalf("regular tx from a sender at the special cap rejected: %v", err)
	}
	if err := validatePoolInternals(pool); err != nil {
		t.Fatalf("pool internal state corrupted: %v", err)
	}
}

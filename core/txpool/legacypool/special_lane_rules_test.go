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
	"github.com/XinFinOrg/XDPoSChain/core/types"
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

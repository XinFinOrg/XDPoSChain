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
	"crypto/ecdsa"
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/crypto"
)

// laneSignTx builds a well-formed sign transaction that signs block signed.
func laneSignTx(t *testing.T, key *ecdsa.PrivateKey, nonce, signed uint64, tag byte) *types.Transaction {
	t.Helper()
	data := common.Hex2Bytes(common.HexSignMethod)
	data = append(data, common.LeftPadBytes(new(big.Int).SetUint64(signed).Bytes(), 32)...)
	data = append(data, common.Hash{tag, 0x5a}.Bytes()...)
	tx, err := types.SignTx(types.NewTransaction(nonce, common.BlockSignersBinary, big.NewInt(0), 200000, big.NewInt(0), data), types.HomesteadSigner{}, key)
	if err != nil {
		t.Fatalf("failed to sign sign tx: %v", err)
	}
	return tx
}

// laneRandomizeTx builds a transaction to the randomize contract.
func laneRandomizeTx(t *testing.T, key *ecdsa.PrivateKey, nonce uint64, tag byte) *types.Transaction {
	t.Helper()
	data := append(common.Hex2Bytes(common.HexSetSecret), common.Hash{tag}.Bytes()...)
	tx, err := types.SignTx(types.NewTransaction(nonce, common.RandomizeSMCBinary, big.NewInt(0), 200000, big.NewInt(0), data), types.HomesteadSigner{}, key)
	if err != nil {
		t.Fatalf("failed to sign randomize tx: %v", err)
	}
	return tx
}

// laneKey returns a funded key.
func laneKey(pool *LegacyPool) *ecdsa.PrivateKey {
	key, _ := crypto.GenerateKey()
	testAddBalance(pool, crypto.PubkeyToAddress(key.PublicKey), big.NewInt(1_000_000_000_000_000))
	return key
}

// TestSpecialLaneSurvivesRegularFlood checks that better-paying regular
// transactions never evict an honest pending sign transaction from a full
// pool, also after the price heap is rebuilt.
func TestSpecialLaneSurvivesRegularFlood(t *testing.T) {
	t.Parallel()

	pool, _ := setupPool()
	defer pool.Close()
	pool.SetSigner(func(common.Address) bool { return true })
	pool.config.GlobalSlots = 4
	pool.config.GlobalQueue = 0

	sign := laneSignTx(t, laneKey(pool), 0, 0, 1)
	if err := pool.addRemoteSync(sign); err != nil {
		t.Fatalf("failed to add sign tx: %v", err)
	}
	user := laneKey(pool)
	for nonce := uint64(0); nonce < 4; nonce++ {
		if err := pool.addRemoteSync(pricedTransaction(nonce, 100000, big.NewInt(common.DefaultMinGasPrice), user)); err != nil {
			t.Fatalf("failed to fill the pool, tx %d: %v", nonce, err)
		}
	}
	for round := int64(2); round <= 4; round++ {
		pool.mu.Lock()
		pool.priced.Reheap()
		pool.mu.Unlock()

		other := laneKey(pool)
		for nonce := uint64(0); nonce < 4; nonce++ {
			if err := pool.addRemoteSync(pricedTransaction(nonce, 100000, big.NewInt(round*common.DefaultMinGasPrice), other)); err != nil {
				t.Fatalf("round %d: failed to add better-paying tx %d: %v", round, nonce, err)
			}
		}
		if pool.all.Get(sign.Hash()) == nil {
			t.Fatalf("round %d: the sign tx was evicted by regular txs", round)
		}
	}
	if err := validatePoolInternals(pool); err != nil {
		t.Fatalf("pool internal state corrupted: %v", err)
	}
}

// TestSpecialLaneQueuedNotPricedOut checks that a special transaction that
// entered the pool through the normal path, here queued behind a nonce gap, is
// not tracked by the price heap either, so better-paying regular transactions
// on a full pool cannot evict it.
func TestSpecialLaneQueuedNotPricedOut(t *testing.T) {
	t.Parallel()

	pool, _ := setupPool()
	defer pool.Close()
	pool.SetSigner(func(common.Address) bool { return true })
	pool.config.GlobalSlots = 2
	pool.config.GlobalQueue = 2

	queued := laneRandomizeTx(t, laneKey(pool), 3, 1)
	if err := pool.addRemoteSync(queued); err != nil {
		t.Fatalf("failed to queue the special tx: %v", err)
	}
	user := laneKey(pool)
	for nonce := uint64(0); nonce < 4; nonce++ {
		if err := pool.addRemoteSync(pricedTransaction(nonce, 100000, big.NewInt(common.DefaultMinGasPrice), user)); err != nil {
			t.Fatalf("failed to fill the pool, tx %d: %v", nonce, err)
		}
	}
	other := laneKey(pool)
	for nonce := uint64(0); nonce < 4; nonce++ {
		if err := pool.addRemoteSync(pricedTransaction(nonce, 100000, big.NewInt(3*common.DefaultMinGasPrice), other)); err != nil {
			t.Fatalf("failed to add better-paying tx %d: %v", nonce, err)
		}
	}
	if pool.all.Get(queued.Hash()) == nil {
		t.Fatal("the queued special tx was priced out")
	}
}

// TestSpecialLaneTakesNoRegularRoom checks that special transactions do not
// count toward the pool capacity: a pool holding many of them still admits
// regular transactions up to its limit without evicting any.
func TestSpecialLaneTakesNoRegularRoom(t *testing.T) {
	t.Parallel()

	pool, _ := setupPool()
	defer pool.Close()
	pool.SetSigner(func(common.Address) bool { return true })
	pool.config.GlobalSlots = 4
	pool.config.GlobalQueue = 0

	user := laneKey(pool)
	var regular []*types.Transaction
	for nonce := uint64(0); nonce < 3; nonce++ {
		tx := pricedTransaction(nonce, 100000, big.NewInt(common.DefaultMinGasPrice), user)
		if err := pool.addRemoteSync(tx); err != nil {
			t.Fatalf("failed to add regular tx %d: %v", nonce, err)
		}
		regular = append(regular, tx)
	}
	// Twenty signers, each with a sign tx and a randomize tx.
	for i := 0; i < 20; i++ {
		key := laneKey(pool)
		for _, tx := range []*types.Transaction{laneSignTx(t, key, 0, 0, byte(i)), laneRandomizeTx(t, key, 1, byte(i))} {
			if err := pool.addRemoteSync(tx); err != nil {
				t.Fatalf("signer %d: failed to add special tx %d: %v", i, tx.Nonce(), err)
			}
		}
	}
	// The fourth regular tx still fits.
	last := pricedTransaction(3, 100000, big.NewInt(common.DefaultMinGasPrice), user)
	if err := pool.addRemoteSync(last); err != nil {
		t.Fatalf("regular tx refused although the pool holds only 3 regular txs: %v", err)
	}
	for _, tx := range append(regular, last) {
		if pool.all.Get(tx.Hash()) == nil {
			t.Fatalf("regular tx %d was evicted", tx.Nonce())
		}
	}
	if pending, _ := pool.Stats(); pending != 44 {
		t.Fatalf("pending = %d, want 44 (4 regular + 40 special)", pending)
	}
	if err := validatePoolInternals(pool); err != nil {
		t.Fatalf("pool internal state corrupted: %v", err)
	}
}

// TestSpecialLaneSurvivesGasTipRaise checks that raising the pool's minimum tip
// does not drop special transactions, which carry no price.
func TestSpecialLaneSurvivesGasTipRaise(t *testing.T) {
	t.Parallel()

	pool, _ := setupPool()
	defer pool.Close()
	pool.SetSigner(func(common.Address) bool { return true })

	sign := laneSignTx(t, laneKey(pool), 0, 0, 1)
	if err := pool.addRemoteSync(sign); err != nil {
		t.Fatalf("failed to add sign tx: %v", err)
	}
	if err := pool.SetGasTip(big.NewInt(2 * common.DefaultMinGasPrice)); err != nil {
		t.Fatalf("failed to raise the gas tip: %v", err)
	}
	if pool.all.Get(sign.Hash()) == nil {
		t.Fatal("raising the gas tip dropped the sign tx")
	}
}

// TestSpecialLaneNotTruncated checks that the pending and queued limits count
// and evict regular transactions only.
func TestSpecialLaneNotTruncated(t *testing.T) {
	t.Parallel()

	pool, _ := setupPool()
	defer pool.Close()
	pool.SetSigner(func(common.Address) bool { return true })
	pool.config.GlobalSlots = 2
	pool.config.AccountSlots = 1
	pool.config.GlobalQueue = 1
	pool.queue.config.GlobalQueue = 1

	signer := laneKey(pool)
	specials := []*types.Transaction{
		laneSignTx(t, signer, 0, 0, 1),
		laneRandomizeTx(t, signer, 1, 1),
		laneRandomizeTx(t, signer, 2, 2),
		// Queued behind a nonce gap.
		laneRandomizeTx(t, signer, 5, 5),
		laneRandomizeTx(t, signer, 6, 6),
	}
	for _, tx := range specials {
		if err := pool.addRemoteSync(tx); err != nil {
			t.Fatalf("failed to add special tx %d: %v", tx.Nonce(), err)
		}
	}
	user := laneKey(pool)
	for nonce := uint64(0); nonce < 2; nonce++ {
		if err := pool.addRemoteSync(pricedTransaction(nonce, 100000, big.NewInt(common.DefaultMinGasPrice), user)); err != nil {
			t.Fatalf("failed to add regular tx %d: %v", nonce, err)
		}
	}
	<-pool.requestPromoteExecutables(newAccountSet(pool.signer, crypto.PubkeyToAddress(signer.PublicKey)))
	for _, tx := range specials {
		if pool.all.Get(tx.Hash()) == nil {
			t.Fatalf("special tx at nonce %d was truncated", tx.Nonce())
		}
	}
	if pending, queued := pool.Stats(); pending != 5 || queued != 2 {
		t.Fatalf("pool stats = (%d pending, %d queued), want (5, 2)", pending, queued)
	}
	if err := validatePoolInternals(pool); err != nil {
		t.Fatalf("pool internal state corrupted: %v", err)
	}
}

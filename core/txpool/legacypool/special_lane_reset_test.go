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
	"math/big"
	"sync"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// signWindowConfig is the test chain config with an XDPoS epoch of 30 blocks,
// so a sign transaction may sign a block at most 60 blocks back.
func signWindowConfig() *params.ChainConfig {
	cfg := *params.TestChainConfig
	cfg.XDPoS = &params.XDPoSConfig{Epoch: 30}
	return &cfg
}

// TestSpecialLaneResetDropsOutOfWindow checks that a pooled sign transaction,
// pending or queued, is dropped at the first reset after the block it signs
// leaves the signing window, that the sender's later transactions go back to
// the queue rather than being dropped, and that a sign transaction still in
// the window stays.
func TestSpecialLaneResetDropsOutOfWindow(t *testing.T) {
	t.Parallel()

	pool, _ := setupPoolWithConfig(signWindowConfig())
	defer pool.Close()
	pool.SetSigner(func(common.Address) bool { return true })
	<-pool.requestReset(nil, newTestHeader(100))

	stale := laneKey(pool)
	stalePending := laneSignTx(t, stale, 0, 90, 1)
	staleRandomize := laneRandomizeTx(t, stale, 1, 1)
	staleQueued := laneSignTx(t, stale, 5, 75, 1)
	honest := laneSignTx(t, laneKey(pool), 0, 105, 1)
	for _, tx := range []*types.Transaction{stalePending, staleRandomize, staleQueued, honest} {
		if err := pool.addRemoteSync(tx); err != nil {
			t.Fatalf("failed to add tx %d: %v", tx.Nonce(), err)
		}
	}
	// Next block 161: block 90 and 75 are more than 60 blocks back, 105 is not.
	<-pool.requestReset(nil, newTestHeader(160))

	for _, tx := range []*types.Transaction{stalePending, staleQueued} {
		if pool.all.Get(tx.Hash()) != nil {
			t.Fatalf("sign tx at nonce %d left the window but is still pooled", tx.Nonce())
		}
	}
	if pool.all.Get(honest.Hash()) == nil {
		t.Fatal("sign tx still in the window was dropped")
	}
	if pool.all.Get(staleRandomize.Hash()) == nil {
		t.Fatal("the sender's later randomize tx was dropped, want it queued")
	}
	if list, ok := pool.queue.get(crypto.PubkeyToAddress(stale.PublicKey)); !ok || list.txs.Get(1) == nil {
		t.Fatal("the sender's later randomize tx is not queued")
	}
	if err := validatePoolInternals(pool); err != nil {
		t.Fatalf("pool internal state corrupted: %v", err)
	}
}

// TestSpecialLaneResetDropsNonCandidate checks that a pooled sign transaction
// is dropped at the next reset once its sender stops being a candidate, while
// a candidate's sign transaction stays.
func TestSpecialLaneResetDropsNonCandidate(t *testing.T) {
	t.Parallel()

	pool, _ := setupPool()
	defer pool.Close()
	var (
		mu         sync.Mutex
		candidates = make(map[common.Address]bool)
	)
	pool.SetSigner(func(addr common.Address) bool {
		mu.Lock()
		defer mu.Unlock()
		return candidates[addr]
	})
	leaving, staying := laneKey(pool), laneKey(pool)
	mu.Lock()
	candidates[crypto.PubkeyToAddress(leaving.PublicKey)] = true
	candidates[crypto.PubkeyToAddress(staying.PublicKey)] = true
	mu.Unlock()

	left := laneSignTx(t, leaving, 0, 0, 1)
	stays := laneSignTx(t, staying, 0, 0, 2)
	for _, tx := range []*types.Transaction{left, stays} {
		if err := pool.addRemoteSync(tx); err != nil {
			t.Fatalf("failed to add sign tx: %v", err)
		}
	}
	mu.Lock()
	delete(candidates, crypto.PubkeyToAddress(leaving.PublicKey))
	mu.Unlock()
	<-pool.requestReset(nil, newTestHeader(1))

	if pool.all.Get(left.Hash()) != nil {
		t.Fatal("sign tx from a sender no longer a candidate is still pooled")
	}
	if pool.all.Get(stays.Hash()) == nil {
		t.Fatal("candidate's sign tx was dropped")
	}
	if err := validatePoolInternals(pool); err != nil {
		t.Fatalf("pool internal state corrupted: %v", err)
	}
}

// TestSpecialLaneResetSkipsMinedSignTx checks that the reset re-check leaves
// alone a sign transaction already mined, nonce below the state nonce, so
// dropping it cannot demote the sender's next executable transaction.
func TestSpecialLaneResetSkipsMinedSignTx(t *testing.T) {
	t.Parallel()

	pool, _ := setupPool()
	defer pool.Close()
	var (
		mu        sync.Mutex
		candidate = true
	)
	pool.SetSigner(func(common.Address) bool {
		mu.Lock()
		defer mu.Unlock()
		return candidate
	})
	key := laneKey(pool)
	addr := crypto.PubkeyToAddress(key.PublicKey)
	for _, tx := range []*types.Transaction{laneSignTx(t, key, 0, 0, 1), pricedTransaction(1, 100000, big.NewInt(common.DefaultMinGasPrice), key)} {
		if err := pool.addRemoteSync(tx); err != nil {
			t.Fatalf("failed to add tx %d: %v", tx.Nonce(), err)
		}
	}
	// The sign tx is mined, then its sender stops being a candidate.
	testSetNonce(pool, addr, 1)
	mu.Lock()
	candidate = false
	mu.Unlock()
	<-pool.requestReset(nil, newTestHeader(1))

	if pending, queued := pool.Stats(); pending != 1 || queued != 0 {
		t.Fatalf("pool stats = (%d pending, %d queued), want (1, 0)", pending, queued)
	}
	if err := validatePoolInternals(pool); err != nil {
		t.Fatalf("pool internal state corrupted: %v", err)
	}
}

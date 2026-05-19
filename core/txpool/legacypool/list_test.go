// Copyright 2016 The go-ethereum Authors
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
	"math/big"
	"math/rand"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/holiman/uint256"
)

// Tests that transactions can be added to strict lists and list contents and
// nonce boundaries are correctly maintained.
func TestStrictListAdd(t *testing.T) {
	// Generate a list of transactions to insert
	key, _ := crypto.GenerateKey()

	txs := make(types.Transactions, 1024)
	for i := 0; i < len(txs); i++ {
		txs[i] = transaction(uint64(i), 0, key)
	}
	// Insert the transactions in a random order
	list := newList(true)
	for _, v := range rand.Perm(len(txs)) {
		list.Add(txs[v], DefaultConfig.PriceBump)
	}
	// Verify internal state
	if len(list.txs.items) != len(txs) {
		t.Errorf("transaction count mismatch: have %d, want %d", len(list.txs.items), len(txs))
	}
	for i, tx := range txs {
		if list.txs.items[tx.Nonce()] != tx {
			t.Errorf("item %d: transaction mismatch: have %v, want %v", i, list.txs.items[tx.Nonce()], tx)
		}
	}
}

// TestListAddVeryExpensive tests adding txs which exceed 256 bits in cost. It is
// expected that the list does not panic.
func TestListAddVeryExpensive(t *testing.T) {
	key, _ := crypto.GenerateKey()
	list := newList(true)
	for i := 0; i < 3; i++ {
		value := big.NewInt(100)
		gasprice, _ := new(big.Int).SetString("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 0)
		gaslimit := uint64(i)
		tx, _ := types.SignTx(types.NewTransaction(uint64(i), common.Address{}, value, gaslimit, gasprice, nil), types.HomesteadSigner{}, key)
		t.Logf("cost: %x bitlen: %d\n", tx.Cost(), tx.Cost().BitLen())
		list.Add(tx, DefaultConfig.PriceBump)
	}
}

// TestPricedListSetBaseFeeNilPreserved tests priced list set base fee nil preserved.
func TestPricedListSetBaseFeeNilPreserved(t *testing.T) {
	pl := newPricedList(newLookup())

	pl.SetBaseFee(nil)
	if pl.urgent.baseFee != nil {
		t.Fatalf("unexpected non-nil base fee after nil input")
	}
}

// TestPricedListSetBaseFeeOverflowClearsBaseFee tests priced list set base fee overflow clears base fee.
func TestPricedListSetBaseFeeOverflowClearsBaseFee(t *testing.T) {
	pl := newPricedList(newLookup())

	pl.SetBaseFee(big.NewInt(1))
	if pl.urgent.baseFee == nil {
		t.Fatalf("expected non-nil base fee after valid input")
	}

	overflow := new(big.Int).Lsh(big.NewInt(1), 300)
	pl.SetBaseFee(overflow)
	if pl.urgent.baseFee != nil {
		t.Fatalf("expected nil base fee when input overflows uint256")
	}
}

// TestPriceHeapCmp tests that the price heap comparison function works as intended.
// It also tests combinations where the basefee is higher than the gas fee cap, which
// are useful to sort in the mempool to support basefee changes.
func TestPriceHeapCmp(t *testing.T) {
	key, _ := crypto.GenerateKey()
	txs := []*types.Transaction{
		// nonce, gaslimit, gasfee, gastip
		dynamicFeeTx(0, 1000, big.NewInt(2), big.NewInt(1), key),
		dynamicFeeTx(0, 1000, big.NewInt(1), big.NewInt(2), key),
		dynamicFeeTx(0, 1000, big.NewInt(1), big.NewInt(1), key),
		dynamicFeeTx(0, 1000, big.NewInt(1), big.NewInt(0), key),
	}

	// create priceHeap
	ph := &priceHeap{}

	// now set the basefee on the heap
	for _, basefee := range []uint64{0, 1, 2, 3} {
		ph.baseFee = uint256.NewInt(basefee)

		for i := 0; i < len(txs); i++ {
			for j := 0; j < len(txs); j++ {
				switch {
				case i == j:
					if c := ph.cmp(txs[i], txs[j]); c != 0 {
						t.Errorf("tx %d should be equal priority to tx %d with basefee %d (cmp=%d)", i, j, basefee, c)
					}
				case i < j:
					if c := ph.cmp(txs[i], txs[j]); c != 1 {
						t.Errorf("tx %d vs tx %d comparison inconsistent with basefee %d (cmp=%d)", i, j, basefee, c)
					}
				}
			}
		}
	}
}

// TestListFilterUsesGas50xBlockForTokenFeeTransactions tests list filtering
// uses TxCost(number, cfg) instead of the legacy tx gas price when a
// token-fee transaction is evaluated after the Gas50x fork.
func TestListFilterUsesGas50xBlockForTokenFeeTransactions(t *testing.T) {
	to := common.HexToAddress("0x1000000000000000000000000000000000000001")
	tx := types.NewTransaction(0, to, big.NewInt(0), 1, big.NewInt(1), nil)
	list := newList(true)
	list.Add(tx, DefaultConfig.PriceBump)
	cfg := &params.ChainConfig{Gas50xBlock: big.NewInt(0)}

	removed, invalids := list.Filter(big.NewInt(0), tx.Gas(), map[common.Address]*big.Int{to: big.NewInt(1)}, big.NewInt(0), cfg)
	if len(invalids) != 0 {
		t.Fatalf("expected no invalids, got %d", len(invalids))
	}
	if len(removed) != 1 || removed[0].Hash() != tx.Hash() {
		t.Fatalf("expected transaction to be removed by Gas50x pricing, got %d removed", len(removed))
	}
	if list.Len() != 0 {
		t.Fatalf("expected list to be empty after filtering, have %d items", list.Len())
	}

	legacyCost := tx.Cost()
	if legacyCost.Cmp(big.NewInt(1)) != 0 {
		t.Fatalf("unexpected legacy tx cost: have %v want 1", legacyCost)
	}
	gas50xCost := tx.TxCost(big.NewInt(0), cfg)
	if gas50xCost.Cmp(big.NewInt(1)) <= 0 {
		t.Fatalf("expected gas50x tx cost to exceed legacy cost: have %v legacy %v", gas50xCost, legacyCost)
	}
	if gas50xCost.Cmp(big.NewInt(1)) <= 0 {
		t.Fatalf("expected gas50x tx cost to exceed legacy balance plus capacity: have %v threshold %v", gas50xCost, big.NewInt(1))
	}
	if legacyCost.Cmp(big.NewInt(1)) > 0 {
		t.Fatalf("expected legacy tx cost to remain within balance plus capacity: have %v threshold %v", legacyCost, big.NewInt(1))
	}
}

// TestListFilterDoesNotShortCircuitTokenFeeTransactions tests the cached
// early-return path does not keep underfunded TRC21 transactions when the
// runtime TxCost(number, cfg) exceeds the balance plus issuer fee capacity.
func TestListFilterDoesNotShortCircuitTokenFeeTransactions(t *testing.T) {
	to := common.HexToAddress("0x1000000000000000000000000000000000000002")
	tx := types.NewTransaction(0, to, big.NewInt(0), 1, big.NewInt(1), nil)
	list := newList(true)
	list.Add(tx, DefaultConfig.PriceBump)
	cfg := &params.ChainConfig{Gas50xBlock: big.NewInt(0)}

	removed, invalids := list.Filter(big.NewInt(1), tx.Gas(), map[common.Address]*big.Int{to: big.NewInt(0)}, big.NewInt(0), cfg)
	if len(invalids) != 0 {
		t.Fatalf("expected no invalids, got %d", len(invalids))
	}
	if len(removed) != 1 || removed[0].Hash() != tx.Hash() {
		t.Fatalf("expected transaction to be removed despite matching legacy cost cap, got %d removed", len(removed))
	}
}

func TestListHasTRC21ReceiverCacheTracksMutations(t *testing.T) {
	issuer := common.HexToAddress("0x1000000000000000000000000000000000000010")
	other := common.HexToAddress("0x1000000000000000000000000000000000000020")
	issuers := map[common.Address]*big.Int{issuer: big.NewInt(0)}

	list := newList(false)
	txIssuer := types.NewTransaction(0, issuer, big.NewInt(0), 1, big.NewInt(1), nil)
	if ok, _ := list.Add(txIssuer, DefaultConfig.PriceBump); !ok {
		t.Fatalf("failed to add issuer transaction")
	}
	if !list.hasTRC21Receiver(issuers) {
		t.Fatalf("expected issuer receiver to be cached")
	}

	txOtherReplacement := types.NewTransaction(0, other, big.NewInt(0), 1, big.NewInt(2), nil)
	if ok, _ := list.Add(txOtherReplacement, DefaultConfig.PriceBump); !ok {
		t.Fatalf("failed to replace issuer transaction")
	}
	if list.hasTRC21Receiver(issuers) {
		t.Fatalf("expected issuer receiver cache to clear after replacement")
	}

	txIssuerA := types.NewTransaction(1, issuer, big.NewInt(0), 1, big.NewInt(1), nil)
	txIssuerB := types.NewTransaction(2, issuer, big.NewInt(0), 1, big.NewInt(1), nil)
	if ok, _ := list.Add(txIssuerA, DefaultConfig.PriceBump); !ok {
		t.Fatalf("failed to add first issuer transaction")
	}
	if ok, _ := list.Add(txIssuerB, DefaultConfig.PriceBump); !ok {
		t.Fatalf("failed to add second issuer transaction")
	}
	if !list.hasTRC21Receiver(issuers) {
		t.Fatalf("expected issuer receiver cache to be restored")
	}

	if removed, _ := list.Remove(txIssuerA); !removed {
		t.Fatalf("failed to remove first issuer transaction")
	}
	if !list.hasTRC21Receiver(issuers) {
		t.Fatalf("expected issuer receiver cache to remain set while one tx remains")
	}

	if removed, _ := list.Remove(txIssuerB); !removed {
		t.Fatalf("failed to remove second issuer transaction")
	}
	if list.hasTRC21Receiver(issuers) {
		t.Fatalf("expected issuer receiver cache to clear when issuer txs are gone")
	}
}

// BenchmarkListAdd benchmarks list add.
func BenchmarkListAdd(t *testing.B) {
	// Generate a list of transactions to insert
	key, _ := crypto.GenerateKey()

	txs := make(types.Transactions, 100000)
	for i := 0; i < len(txs); i++ {
		txs[i] = transaction(uint64(i), 0, key)
	}
	// Insert the transactions in a random order
	list := newList(true)
	priceLimit := big.NewInt(int64(DefaultConfig.PriceLimit))
	t.ResetTimer()
	for _, v := range rand.Perm(len(txs)) {
		list.Add(txs[v], DefaultConfig.PriceBump)
		list.Filter(priceLimit, DefaultConfig.PriceBump, nil, nil, nil)
	}
}

// BenchmarkListCapOneTx benchmarks list cap one tx.
func BenchmarkListCapOneTx(b *testing.B) {
	// Generate a list of transactions to insert
	key, _ := crypto.GenerateKey()

	txs := make(types.Transactions, 32)
	for i := 0; i < len(txs); i++ {
		txs[i] = transaction(uint64(i), 0, key)
	}

	for b.Loop() {
		list := newList(true)
		// Insert the transactions in a random order
		for _, v := range rand.Perm(len(txs)) {
			list.Add(txs[v], DefaultConfig.PriceBump)
		}
		b.StartTimer()
		list.Cap(list.Len() - 1)
		b.StopTimer()
	}
}

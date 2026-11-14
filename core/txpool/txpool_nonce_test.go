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

package txpool_test

import (
	"math/big"
	"testing"
	"time"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// TestNonceAccessors pins which nonce each TxPool accessor returns. The names
// are easy to mix up: upstream go-ethereum #31496 (ported as #2183) renamed the
// old pending-nonce TxPool.Nonce to PoolNonce and reused Nonce for the on-chain
// nonce, while SubPool.Nonce kept returning the pending nonce. The sign tx in
// contracts.CreateTransactionSign silently changed meaning with that rename and
// has flipped between the two since, so the meaning is tested, not only
// documented.
func TestNonceAccessors(t *testing.T) {
	const mined = 10 // newHeadTestEnv mines one tx per block from headTestAddress
	chain, pool := newHeadTestEnv(t, mined)
	defer chain.Stop()
	defer pool.Close()

	// Wait until the pool has applied the head the chain was built up to.
	deadline := time.Now().Add(5 * time.Second)
	for pool.PoolNonce(headTestAddress) != mined || pool.Nonce(headTestAddress) != mined {
		if time.Now().After(deadline) {
			t.Fatalf("pool never reached head nonce %d: Nonce %d, PoolNonce %d", mined, pool.Nonce(headTestAddress), pool.PoolNonce(headTestAddress))
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Put three executable transactions in the pool on top of the chain.
	const pooled = 3
	gasPrice := big.NewInt(params.InitialBaseFee)
	if baseFee := chain.CurrentBlock().BaseFee; baseFee != nil {
		gasPrice = new(big.Int).Set(baseFee)
	}
	txs := make([]*types.Transaction, pooled)
	for i := range txs {
		tx, err := types.SignTx(types.NewTransaction(mined+uint64(i), common.Address{0x00}, big.NewInt(1000), params.TxGas, gasPrice, nil), headTestSigner, headTestKey)
		if err != nil {
			t.Fatalf("failed to sign tx %d: %v", i, err)
		}
		txs[i] = tx
	}
	for i, err := range pool.Add(txs, true) {
		if err != nil {
			t.Fatalf("failed to add tx %d: %v", i, err)
		}
	}

	// Nonce is the on-chain nonce: it ignores the pooled transactions.
	if got := pool.Nonce(headTestAddress); got != mined {
		t.Fatalf("TxPool.Nonce = %d, want the on-chain nonce %d", got, mined)
	}
	// PoolNonce is the pending nonce: the pooled transactions are applied on top.
	// With a single subpool it is also that subpool's SubPool.Nonce.
	if got := pool.PoolNonce(headTestAddress); got != mined+pooled {
		t.Fatalf("TxPool.PoolNonce = %d, want the pending nonce %d", got, mined+pooled)
	}
}

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
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/txpool"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/crypto"
)

// TestSignTxAdmissionRules checks that the pool admits only sign transactions
// that are valid for the next block: well-formed calls from a signer.
func TestSignTxAdmissionRules(t *testing.T) {
	t.Parallel()

	candidateKey, _ := crypto.GenerateKey()
	outsiderKey, _ := crypto.GenerateKey()
	candidate := crypto.PubkeyToAddress(candidateKey.PublicKey)

	tests := []struct {
		name string
		tx   func(signer types.Signer) *types.Transaction
		want error
	}{
		{"well-formed from a signer", func(signer types.Signer) *types.Transaction {
			return types.MustSignNewTx(candidateKey, signer, &types.LegacyTx{To: &common.BlockSignersBinary, Gas: 200000, GasPrice: big.NewInt(0), Value: big.NewInt(0), Data: signTxData(0)})
		}, nil},
		{"malformed call", func(signer types.Signer) *types.Transaction {
			return types.MustSignNewTx(candidateKey, signer, &types.LegacyTx{To: &common.BlockSignersBinary, Gas: 200000, GasPrice: big.NewInt(0), Value: big.NewInt(0), Data: make([]byte, 100)})
		}, core.ErrSignTxData},
		{"value", func(signer types.Signer) *types.Transaction {
			return types.MustSignNewTx(candidateKey, signer, &types.LegacyTx{To: &common.BlockSignersBinary, Gas: 200000, GasPrice: big.NewInt(0), Value: big.NewInt(1), Data: signTxData(0)})
		}, core.ErrSignTxValue},
		{"typed transaction", func(signer types.Signer) *types.Transaction {
			return types.MustSignNewTx(candidateKey, signer, &types.DynamicFeeTx{ChainID: signer.ChainID(), To: &common.BlockSignersBinary, Gas: 200000, GasFeeCap: big.NewInt(0), GasTipCap: big.NewInt(0), Value: big.NewInt(0), Data: signTxData(0)})
		}, core.ErrSignTxType},
		{"from a non-signer", func(signer types.Signer) *types.Transaction {
			return types.MustSignNewTx(outsiderKey, signer, &types.LegacyTx{To: &common.BlockSignersBinary, Gas: 200000, GasPrice: big.NewInt(0), Value: big.NewInt(0), Data: signTxData(0)})
		}, txpool.ErrSpecialTxNotFromSigner},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pool, _ := setupPool()
			defer pool.Close()
			pool.SetSigner(func(addr common.Address) bool { return addr == candidate })
			testAddBalance(pool, candidate, big.NewInt(1_000_000_000_000_000))

			tx := tt.tx(pool.signer)
			err := pool.addRemoteSync(tx)
			if !errors.Is(err, tt.want) || (tt.want == nil && err != nil) {
				t.Fatalf("add: err = %v, want %v", err, tt.want)
			}
			if inPool := pool.all.Get(tx.Hash()) != nil; inPool != (tt.want == nil) {
				t.Fatalf("in pool = %v, want %v", inPool, tt.want == nil)
			}
		})
	}
}

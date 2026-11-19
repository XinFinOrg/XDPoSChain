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

package txpool

import (
	"errors"
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/tracing"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// TestValidateTransactionWithStateTRC21Value checks that the TRC21 fee capacity
// pays for gas only: execution takes the value from the sender's own balance, so
// a sponsored transaction whose value the sender cannot hold is not admitted.
func TestValidateTransactionWithStateTRC21Value(t *testing.T) {
	cfg := &params.ChainConfig{}
	token := common.HexToAddress("0x00000000000000000000000000000000000000cc")
	// Far more fee capacity than the transaction cost, value included.
	capacity := new(big.Int).Mul(big.NewInt(params.Ether), big.NewInt(1000))

	for _, tc := range []struct {
		name    string
		balance int64
		value   int64
		wantErr error
	}{
		{name: "no value, no balance", balance: 0, value: 0},
		{name: "value held by sender", balance: 5, value: 5},
		{name: "value above sender balance", balance: 4, value: 5, wantErr: core.ErrInsufficientFundsForTransfer},
		{name: "value with empty sender", balance: 0, value: 1, wantErr: core.ErrInsufficientFundsForTransfer},
	} {
		t.Run(tc.name, func(t *testing.T) {
			statedb, err := state.NewWithChainConfig(types.EmptyRootHash, state.NewDatabase(rawdb.NewMemoryDatabase()), cfg)
			if err != nil {
				t.Fatalf("failed to create state: %v", err)
			}
			key, err := crypto.GenerateKey()
			if err != nil {
				t.Fatalf("failed to generate key: %v", err)
			}
			from := crypto.PubkeyToAddress(key.PublicKey)
			statedb.AddBalance(from, big.NewInt(tc.balance), tracing.BalanceChangeUnspecified)

			tx, err := types.SignTx(
				types.NewTransaction(0, token, big.NewInt(tc.value), params.TxGas, big.NewInt(common.DefaultMinGasPrice*1000), []byte{0x01, 0x02, 0x03, 0x04}),
				types.HomesteadSigner{},
				key,
			)
			if err != nil {
				t.Fatalf("failed to sign tx: %v", err)
			}
			opts := &ValidationOptionsWithState{
				Config:              cfg,
				State:               statedb,
				Trc21FeeCapacity:    map[common.Address]*big.Int{token: capacity},
				ExistingExpenditure: func(common.Address) *big.Int { return new(big.Int) },
				ExistingCost:        func(common.Address, uint64) *big.Int { return nil },
				PendingNonce:        func(common.Address) uint64 { return 0 },
				CurrentNumber:       func() *big.Int { return big.NewInt(1) },
			}
			err = ValidateTransactionWithState(tx, types.HomesteadSigner{}, opts)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("unexpected error: have %v want %v", err, tc.wantErr)
			}
		})
	}
}

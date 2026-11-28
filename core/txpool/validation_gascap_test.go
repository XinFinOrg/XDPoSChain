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
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// TestValidateTransactionGasCapAcrossAmsterdam checks the stateless gas cap on
// both sides of Amsterdam: before it the EIP-7825 cap applies, from Amsterdam
// on the EIP-8037 total cap replaces it.
func TestValidateTransactionGasCapAcrossAmsterdam(t *testing.T) {
	t.Parallel()

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	osaka := params.TestChainConfig.Clone()
	osaka.AmsterdamBlock = nil
	amsterdam := params.TestChainConfig.Clone()

	for _, tt := range []struct {
		name    string
		config  *params.ChainConfig
		gas     uint64
		wantErr error
	}{
		{"osaka at cap", osaka, params.MaxTxGas, nil},
		{"osaka above cap", osaka, params.MaxTxGas + 1, core.ErrGasLimitTooHigh},
		{"amsterdam above osaka cap", amsterdam, params.MaxTxGas + 1, nil},
		{"amsterdam at total cap", amsterdam, 1<<32 - 1, nil},
		{"amsterdam above total cap", amsterdam, 1 << 32, core.ErrGasLimitTooHigh},
	} {
		t.Run(tt.name, func(t *testing.T) {
			signer := types.LatestSigner(tt.config)
			tx, err := types.SignTx(types.NewTransaction(0, common.Address{0x01}, big.NewInt(1), tt.gas, big.NewInt(1), nil), signer, key)
			if err != nil {
				t.Fatalf("failed to sign tx: %v", err)
			}
			head := &types.Header{Number: big.NewInt(1), GasLimit: params.MaxTxTotalGas}
			err = ValidateTransaction(tx, head, signer, &ValidationOptions{
				Config:  tt.config,
				Accept:  1 << types.LegacyTxType,
				MaxSize: tx.Size(),
				MinTip:  big.NewInt(0),
				NotSigner: func(common.Address) bool {
					return false
				},
			})
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

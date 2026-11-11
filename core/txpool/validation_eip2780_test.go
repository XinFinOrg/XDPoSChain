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

// TestValidateTransactionEIP2780Base checks that the pool accepts transactions
// down to the EIP-2780 intrinsic base and rejects one gas unit below it, while
// the flat 21,000 stays in force on the forks before Amsterdam.
func TestValidateTransactionEIP2780Base(t *testing.T) {
	t.Parallel()

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	sender := crypto.PubkeyToAddress(key.PublicKey)

	amsterdam := params.TestChainConfig.Clone()
	prague := params.TestChainConfig.Clone()
	prague.AmsterdamBlock = nil

	to := common.Address{0x01}

	for _, tt := range []struct {
		name    string
		config  *params.ChainConfig
		to      common.Address
		value   *big.Int
		gas     uint64
		wantErr error
	}{
		// A zero-value call pays 12,000 for the sender and 3,000 for the cold recipient.
		{"amsterdam at zero-value call base", amsterdam, to, big.NewInt(0), 15_000, nil},
		{"amsterdam below zero-value call base", amsterdam, to, big.NewInt(0), 14_999, core.ErrIntrinsicGas},
		// A self-transfer pays only the sender part.
		{"amsterdam self-transfer", amsterdam, sender, big.NewInt(1), 12_000, nil},
		{"prague keeps the flat base", prague, to, big.NewInt(0), 15_000, core.ErrIntrinsicGas},
	} {
		t.Run(tt.name, func(t *testing.T) {
			signer := types.LatestSigner(tt.config)
			tx, err := types.SignTx(types.NewTransaction(0, tt.to, tt.value, tt.gas, big.NewInt(1), nil), signer, key)
			if err != nil {
				t.Fatalf("failed to sign tx: %v", err)
			}
			head := &types.Header{Number: big.NewInt(1), GasLimit: 8_000_000}
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

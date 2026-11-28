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
	"github.com/holiman/uint256"
)

// TestValidateSetCodeTxEmptyAuthList checks the empty-authorization-list rule on
// the regular pool path, which shares validateSetCodeAuthorizations with the
// special path.
func TestValidateSetCodeTxEmptyAuthList(t *testing.T) {
	t.Parallel()

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	config := params.TestChainConfig.Clone()
	config.PragueBlock = big.NewInt(0)
	config.AmsterdamBlock = nil
	config.TIPSigningBlock = nil
	signer := types.LatestSigner(config)
	head := &types.Header{Number: big.NewInt(1), GasLimit: 8_000_000}
	to := common.Address{1}

	for _, tt := range []struct {
		name     string
		authList []types.SetCodeAuthorization
		wantErr  bool
	}{
		{"empty auth list", []types.SetCodeAuthorization{}, true},
		{"with auth list", []types.SetCodeAuthorization{{}}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tx, err := types.SignNewTx(key, signer, &types.SetCodeTx{
				ChainID:   uint256.MustFromBig(config.ChainID),
				GasTipCap: uint256.NewInt(1),
				GasFeeCap: uint256.NewInt(1),
				Gas:       200_000,
				To:        to,
				Value:     uint256.NewInt(0),
				AuthList:  tt.authList,
			})
			if err != nil {
				t.Fatalf("failed to sign tx: %v", err)
			}
			err = ValidateTransaction(tx, head, signer, &ValidationOptions{
				Config:    config,
				Accept:    1 << types.SetCodeTxType,
				MaxSize:   tx.Size(),
				MinTip:    big.NewInt(0),
				NotSigner: func(common.Address) bool { return false },
			})
			if tt.wantErr {
				if err == nil || err.Error() != "set code tx must have at least one authorization tuple" {
					t.Fatalf("error = %v, want empty auth list rejection", err)
				}
			} else if err != nil {
				t.Fatalf("error = %v, want nil", err)
			}
		})
	}
}

// TestValidateSetCodeTxAuthListIntrinsicGas pins the authorization-list part of
// the intrinsic gas on both pool paths, so the shared helper cannot silently
// price set-code transactions below what the execution side charges.
func TestValidateSetCodeTxAuthListIntrinsicGas(t *testing.T) {
	t.Parallel()

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	config := params.TestChainConfig.Clone()
	config.PragueBlock = big.NewInt(0)
	config.AmsterdamBlock = nil
	config.TIPSigningBlock = nil
	signer := types.LatestSigner(config)
	head := &types.Header{Number: big.NewInt(1), GasLimit: 8_000_000}

	// TxGas 21000 plus one authorization tuple at CallNewAccountGas 25000.
	const authIntrinsic = 21_000 + 25_000

	for _, tt := range []struct {
		name    string
		to      common.Address
		gas     uint64
		wantErr error
	}{
		{"regular below auth intrinsic", common.Address{1}, authIntrinsic - 1, core.ErrIntrinsicGas},
		{"regular at auth intrinsic", common.Address{1}, authIntrinsic, nil},
		{"special below auth intrinsic", common.RandomizeSMCBinary, authIntrinsic - 1, core.ErrIntrinsicGas},
		{"special at auth intrinsic", common.RandomizeSMCBinary, authIntrinsic, nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tx, err := types.SignNewTx(key, signer, &types.SetCodeTx{
				ChainID:   uint256.MustFromBig(config.ChainID),
				GasTipCap: uint256.NewInt(1),
				GasFeeCap: uint256.NewInt(1),
				Gas:       tt.gas,
				To:        tt.to,
				Value:     uint256.NewInt(0),
				AuthList:  []types.SetCodeAuthorization{{}},
			})
			if err != nil {
				t.Fatalf("failed to sign tx: %v", err)
			}
			err = ValidateTransaction(tx, head, signer, &ValidationOptions{
				Config:    config,
				Accept:    1 << types.SetCodeTxType,
				MaxSize:   tx.Size(),
				MinTip:    big.NewInt(0),
				NotSigner: func(common.Address) bool { return false },
			})
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

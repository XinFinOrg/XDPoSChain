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
	"bytes"
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

// TestValidateSpecialTx checks that special transactions the execution side runs
// through the EVM are held to the same intrinsic gas and calldata floor checks,
// while the sign route and the gas price exemptions keep working.
func TestValidateSpecialTx(t *testing.T) {
	t.Parallel()

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	var (
		head        = &types.Header{Number: big.NewInt(1), GasLimit: 8_000_000}
		data        = bytes.Repeat([]byte{0xff}, 100)
		zeroData    = make([]byte, 100)
		secretData  = append(common.Hex2Bytes(common.HexSetSecret), make([]byte, 96)...)
		openingData = append(common.Hex2Bytes(common.HexSetOpening), make([]byte, 32)...)
	)
	amsterdam := params.TestChainConfig.Clone()
	amsterdam.PragueBlock = big.NewInt(0)
	amsterdam.AmsterdamBlock = big.NewInt(0)
	amsterdam.TIPSigningBlock = big.NewInt(0)

	prague := amsterdam.Clone()
	prague.AmsterdamBlock = nil

	prePrague := amsterdam.Clone()
	prePrague.PragueBlock = nil
	prePrague.AmsterdamBlock = nil

	amsterdamNoSigning := amsterdam.Clone()
	amsterdamNoSigning.TIPSigningBlock = nil

	// TIPSigning lands one block past the head: the sign route predicate is
	// resolved at the earliest block a transaction can be included in.
	signingNext := amsterdam.Clone()
	signingNext.TIPSigningBlock = big.NewInt(2)

	// TIPSigning lands two blocks past the head: the earliest block a
	// transaction can be included in still runs the EVM route, so the gas
	// checks apply even though the sign route turns on later.
	signingLater := amsterdam.Clone()
	signingLater.TIPSigningBlock = big.NewInt(3)

	// Prague lands one block past the head: the pool prices a transaction with
	// the head rules, so the floor must not gate it yet.
	pragueNext := amsterdam.Clone()
	pragueNext.PragueBlock = big.NewInt(2)
	pragueNext.AmsterdamBlock = nil

	// Pin the gas schedule the hard-coded expectations below derive from, so a
	// parameter change fails here instead of silently shifting the cases.
	for _, tt := range []struct {
		name  string
		rules params.Rules
		intr  uint64
		floor uint64
	}{
		{"amsterdam", amsterdam.Rules(head.Number), 22_600, 27_400},
		{"prague", prague.Rules(head.Number), 22_600, 25_000},
		{"pre-prague", prePrague.Rules(head.Number), 27_800, 0},
	} {
		intr, err := core.IntrinsicGas(data, nil, nil, false, true, tt.rules.IsPrague, tt.rules.IsEIP1559, tt.rules.IsAmsterdam)
		if err != nil {
			t.Fatalf("%s: failed to compute intrinsic gas: %v", tt.name, err)
		}
		if intr != tt.intr {
			t.Fatalf("%s intrinsic gas = %d, want %d", tt.name, intr, tt.intr)
		}
		if !tt.rules.IsPrague {
			continue
		}
		floor, err := core.FloorDataGas(tt.rules, data, nil)
		if err != nil {
			t.Fatalf("%s: failed to compute floor data gas: %v", tt.name, err)
		}
		if floor != tt.floor {
			t.Fatalf("%s floor data gas = %d, want %d", tt.name, floor, tt.floor)
		}
	}

	tests := []struct {
		name      string
		config    *params.ChainConfig
		to        common.Address
		data      []byte
		gas       uint64
		gasPrice  int64
		minTip    int64
		notSigner bool
		wantErr   error
	}{
		{"amsterdam below floor", amsterdam, common.RandomizeSMCBinary, data, 27_399, 1, 0, false, core.ErrFloorDataGas},
		{"amsterdam at floor", amsterdam, common.RandomizeSMCBinary, data, 27_400, 1, 0, false, nil},
		{"sign route skips gas checks", amsterdam, common.BlockSignersBinary, data, 27_399, 0, 0, false, nil},
		{"prague below intrinsic", prague, common.RandomizeSMCBinary, data, 21_000, 1, 0, false, core.ErrIntrinsicGas},
		{"prague between intrinsic and floor", prague, common.RandomizeSMCBinary, data, 24_000, 1, 0, false, core.ErrFloorDataGas},
		{"pre-prague below intrinsic", prePrague, common.RandomizeSMCBinary, data, 21_000, 1, 0, false, core.ErrIntrinsicGas},
		{"pre-prague empty data", prePrague, common.RandomizeSMCBinary, nil, 21_000, 1, 0, false, nil},
		{"zero gas price", amsterdam, common.RandomizeSMCBinary, data, 200_000, 0, 0, false, nil},
		{"special tx ignores mintip", amsterdam, common.RandomizeSMCBinary, data, 200_000, 0, 1, false, nil},
		{"regular tx below mintip", amsterdam, common.Address{}, nil, 21_000, 1, 2, false, ErrTxGasPriceTooLow},
		{"secret randomize", amsterdam, common.RandomizeSMCBinary, secretData, 200_000, 0, 0, false, nil},
		{"opening randomize", amsterdam, common.RandomizeSMCBinary, openingData, 200_000, 0, 0, false, nil},
		{"block signers without signing fork", amsterdamNoSigning, common.BlockSignersBinary, data, 27_399, 1, 0, false, core.ErrFloorDataGas},
		{"sign route activates at next block", signingNext, common.BlockSignersBinary, zeroData, 21_000, 0, 0, false, nil},
		{"sign route not active at next block", signingLater, common.BlockSignersBinary, zeroData, 21_000, 0, 0, false, core.ErrIntrinsicGas},
		{"head rules gate the floor", pragueNext, common.RandomizeSMCBinary, zeroData, 21_500, 1, 0, false, nil},
		{"special tx from non-signer", amsterdam, common.BlockSignersBinary, data, 200_000, 0, 0, true, ErrSpecialTxNotFromSigner},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			signer := types.LatestSigner(tt.config)
			tx, err := types.SignTx(types.NewTransaction(0, tt.to, big.NewInt(0), tt.gas, big.NewInt(tt.gasPrice), tt.data), signer, key)
			if err != nil {
				t.Fatalf("failed to sign tx: %v", err)
			}
			err = ValidateTransaction(tx, head, signer, &ValidationOptions{
				Config:  tt.config,
				Accept:  1 << types.LegacyTxType,
				MaxSize: tx.Size(),
				MinTip:  big.NewInt(tt.minTip),
				NotSigner: func(common.Address) bool {
					return tt.notSigner
				},
			})
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateSpecialSetCodeTxRejectsEmptyAuthList(t *testing.T) {
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

	for _, tt := range []struct {
		name     string
		to       common.Address
		authList []types.SetCodeAuthorization
		wantErr  bool
	}{
		{"randomize empty auth list", common.RandomizeSMCBinary, []types.SetCodeAuthorization{}, true},
		{"block signers empty auth list", common.BlockSignersBinary, []types.SetCodeAuthorization{}, true},
		{"randomize with auth list", common.RandomizeSMCBinary, []types.SetCodeAuthorization{{}}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tx, err := types.SignNewTx(key, signer, &types.SetCodeTx{
				ChainID:   uint256.MustFromBig(config.ChainID),
				GasTipCap: uint256.NewInt(1),
				GasFeeCap: uint256.NewInt(1),
				Gas:       200_000,
				To:        tt.to,
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

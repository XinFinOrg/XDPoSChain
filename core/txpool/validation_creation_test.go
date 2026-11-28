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
)

// TestValidateContractCreationIntrinsicGas pins the creation charge of the
// shared intrinsic helper on both fork tiers: the flat TxGasContractCreation
// before Amsterdam and the EIP-2780 creation base from Amsterdam on, plus the
// calldata floor anchored to the creation base.
func TestValidateContractCreationIntrinsicGas(t *testing.T) {
	t.Parallel()

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	amsterdam := params.TestChainConfig.Clone()
	prague := params.TestChainConfig.Clone()
	prague.AmsterdamBlock = nil

	initcode := bytes.Repeat([]byte{0xff}, 100)

	for _, tt := range []struct {
		name    string
		config  *params.ChainConfig
		data    []byte
		gas     uint64
		wantErr error
	}{
		{"prague below creation intrinsic", prague, nil, 52_999, core.ErrIntrinsicGas},
		{"prague at creation intrinsic", prague, nil, 53_000, nil},
		{"amsterdam below creation base", amsterdam, nil, 23_999, core.ErrIntrinsicGas},
		{"amsterdam at creation base", amsterdam, nil, 24_000, nil},
		{"amsterdam initcode below floor", amsterdam, initcode, 25_608, core.ErrFloorDataGas},
		{"amsterdam initcode at floor", amsterdam, initcode, 30_400, nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			signer := types.LatestSigner(tt.config)
			tx, err := types.SignTx(types.NewContractCreation(0, big.NewInt(0), tt.gas, big.NewInt(1), tt.data), signer, key)
			if err != nil {
				t.Fatalf("failed to sign tx: %v", err)
			}
			head := &types.Header{Number: big.NewInt(1), GasLimit: 8_000_000}
			err = ValidateTransaction(tx, head, signer, &ValidationOptions{
				Config:    tt.config,
				Accept:    1 << types.LegacyTxType,
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

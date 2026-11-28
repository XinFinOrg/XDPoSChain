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
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// TestValidateSpecialTxGasCap checks that a special tx the EVM runs is capped at
// common.SpecialTxGasLimit, since its gas is free, while the sign route, which
// runs no EVM and uses no block gas, is not.
func TestValidateSpecialTxGasCap(t *testing.T) {
	t.Parallel()

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	signing := params.TestChainConfig.Clone()
	signing.TIPSigningBlock = big.NewInt(0) // BlockSigners takes the sign route
	preSigning := signing.Clone()
	preSigning.TIPSigningBlock = nil // BlockSigners still runs through the EVM

	for _, tt := range []struct {
		name    string
		config  *params.ChainConfig
		to      common.Address
		gas     uint64
		wantErr error
	}{
		{"randomize tx at the cap", signing, common.RandomizeSMCBinary, common.SpecialTxGasLimit, nil},
		{"randomize tx above the cap", signing, common.RandomizeSMCBinary, common.SpecialTxGasLimit + 1, ErrSpecialTxGasLimit},
		{"sign tx above the cap, sign route", signing, common.BlockSignersBinary, 2 * common.SpecialTxGasLimit, nil},
		{"sign tx above the cap, before TIPSigning", preSigning, common.BlockSignersBinary, common.SpecialTxGasLimit + 1, ErrSpecialTxGasLimit},
	} {
		t.Run(tt.name, func(t *testing.T) {
			signer := types.LatestSigner(tt.config)
			tx, err := types.SignTx(types.NewTransaction(0, tt.to, big.NewInt(0), tt.gas, big.NewInt(0), nil), signer, key)
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

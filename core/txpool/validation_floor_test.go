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

// TestValidateTransactionCalldataFloor checks that the pool prices the calldata
// floor with the rules of the head block: Amsterdam charges 64 gas per byte, so
// a transaction whose gas limit only covers the Prague floor must be rejected.
func TestValidateTransactionCalldataFloor(t *testing.T) {
	t.Parallel()

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	var (
		data           = bytes.Repeat([]byte{0xff}, 100)
		amsterdamFloor = uint64(27_400) // 21000 + 100*4*16
	)
	amsterdam := params.TestChainConfig.Clone()
	prague := params.TestChainConfig.Clone()
	prague.AmsterdamBlock = nil

	for _, tt := range []struct {
		name    string
		config  *params.ChainConfig
		gas     uint64
		wantErr error
	}{
		{"amsterdam below floor", amsterdam, amsterdamFloor - 1, core.ErrFloorDataGas},
		{"amsterdam at floor", amsterdam, amsterdamFloor, nil},
		{"prague below amsterdam floor", prague, amsterdamFloor - 1, nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			signer := types.LatestSigner(tt.config)
			tx, err := types.SignTx(types.NewTransaction(0, common.Address{0x01}, big.NewInt(1), tt.gas, big.NewInt(1), data), signer, key)
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

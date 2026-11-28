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

// TestValidateTransactionAccessListAmsterdam checks that the pool prices the
// EIP-7981 access list data under Amsterdam: on top of the EIP-2930 charge, one
// address and one storage key add (20+32)*4*16 = 3328 gas. With enough
// calldata the floor is the binding cost and it has to price the access list
// the same way.
func TestValidateTransactionAccessListAmsterdam(t *testing.T) {
	t.Parallel()

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	var (
		to         = common.Address{0x01}
		accessList = types.AccessList{{
			Address:     common.HexToAddress("0x1111111111111111111111111111111111111111"),
			StorageKeys: []common.Hash{common.HexToHash("0xaa")},
		}}
		berlinGas = params.TxGas + params.TxAccessListAddressGas + params.TxAccessListStorageKeyGas
		// EIP-7981 adds (20 + 32) bytes * 4 tokens * 16 gas.
		amsterdamGas = berlinGas + (common.AddressLength+common.HashLength)*params.TxTokenPerNonZeroByte*params.TxCostFloorPerToken7976
		// 100 non-zero calldata bytes put the floor above the intrinsic cost,
		// so the access-list tokens in the floor have to be priced.
		data      = bytes.Repeat([]byte{0xff}, 100)
		dataGas   = amsterdamGas + uint64(len(data))*params.TxDataNonZeroGasEIP2028
		dataFloor = params.TxGas + (uint64(len(data))+uint64(common.AddressLength+common.HashLength))*params.TxTokenPerNonZeroByte*params.TxCostFloorPerToken7976
	)
	amsterdam := params.TestChainConfig.Clone()
	prague := params.TestChainConfig.Clone()
	prague.AmsterdamBlock = nil

	for _, tt := range []struct {
		name    string
		config  *params.ChainConfig
		data    []byte
		gas     uint64
		wantErr error
	}{
		{"amsterdam below intrinsic gas", amsterdam, nil, amsterdamGas - 1, core.ErrIntrinsicGas},
		{"amsterdam at intrinsic gas", amsterdam, nil, amsterdamGas, nil},
		{"prague access list price", prague, nil, berlinGas, nil},
		{"amsterdam below floor with calldata", amsterdam, data, dataFloor - 1, core.ErrFloorDataGas},
		{"amsterdam at intrinsic gas with calldata", amsterdam, data, dataGas, core.ErrFloorDataGas},
		{"amsterdam at floor with calldata", amsterdam, data, dataFloor, nil},
		{"prague below the amsterdam floor with calldata", prague, data, dataFloor - 1, nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			signer := types.LatestSigner(tt.config)
			tx, err := types.SignTx(types.NewTx(&types.AccessListTx{
				ChainID:    tt.config.ChainID,
				Nonce:      0,
				GasPrice:   big.NewInt(1),
				Gas:        tt.gas,
				To:         &to,
				Value:      big.NewInt(1),
				Data:       tt.data,
				AccessList: accessList,
			}), signer, key)
			if err != nil {
				t.Fatalf("failed to sign tx: %v", err)
			}
			head := &types.Header{Number: big.NewInt(1), GasLimit: 8_000_000}
			err = ValidateTransaction(tx, head, signer, &ValidationOptions{
				Config:  tt.config,
				Accept:  1 << types.AccessListTxType,
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

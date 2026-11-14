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

// TestValidateTransactionTIPRandomizeDisable checks the pool side of the fork. A
// tx is judged at the block after head, the earliest one it can land in: from
// then on a tx to the randomize contract goes through the regular checks, so a
// zero gas price is rejected and the sender need not be a signer, while txs to
// BlockSigners keep their special treatment.
func TestValidateTransactionTIPRandomizeDisable(t *testing.T) {
	t.Parallel()

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	const fork = 10
	config := params.TestChainConfig.Clone()
	config.TIPRandomizeDisableBlock = big.NewInt(fork)

	for _, tt := range []struct {
		name      string
		head      int64 // the tx is judged at head+1
		to        common.Address
		price     int64
		notSigner bool
		wantErr   error
	}{
		{"randomize, zero price, before the fork", fork - 2, common.RandomizeSMCBinary, 0, false, nil},
		{"randomize, zero price, next block is the fork", fork - 1, common.RandomizeSMCBinary, 0, false, ErrZeroGasPrice},
		{"randomize, priced, non-signer, after the fork", fork, common.RandomizeSMCBinary, 1, true, nil},
		{"randomize, non-signer, before the fork", fork - 2, common.RandomizeSMCBinary, 0, true, ErrSpecialTxNotFromSigner},
		{"block signers, zero price, after the fork", fork, common.BlockSignersBinary, 0, false, nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			signer := types.LatestSigner(config)
			tx, err := types.SignTx(types.NewTransaction(0, tt.to, big.NewInt(0), 100_000, big.NewInt(tt.price), nil), signer, key)
			if err != nil {
				t.Fatalf("failed to sign tx: %v", err)
			}
			head := &types.Header{Number: big.NewInt(tt.head), GasLimit: 8_000_000}
			err = ValidateTransaction(tx, head, signer, &ValidationOptions{
				Config:    config,
				Accept:    1 << types.LegacyTxType,
				MaxSize:   tx.Size(),
				MinTip:    big.NewInt(0),
				NotSigner: func(common.Address) bool { return tt.notSigner },
			})
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

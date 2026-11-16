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

package core

import (
	"errors"
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/tracing"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// TestTIPRandomizeDisableFeeCheck pins the consensus side of TIPRandomizeDisable:
// from the fork block on, a tx to the randomize contract is a regular tx, so a
// zero fee cap below the base fee is invalid, while txs to BlockSigners stay
// special and exempt.
func TestTIPRandomizeDisableFeeCheck(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	from := crypto.PubkeyToAddress(key.PublicKey)

	const fork = 10
	config := params.TestChainConfig.Clone()
	config.TIPRandomizeDisableBlock = big.NewInt(fork)

	for _, tt := range []struct {
		name    string
		number  int64
		to      common.Address
		wantErr error
	}{
		{"randomize before the fork", fork - 1, common.RandomizeSMCBinary, nil},
		{"randomize at the fork", fork, common.RandomizeSMCBinary, ErrFeeCapTooLow},
		{"block signers at the fork", fork, common.BlockSignersBinary, nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			statedb, err := state.New(types.EmptyRootHash, state.NewDatabase(rawdb.NewMemoryDatabase()))
			if err != nil {
				t.Fatalf("failed to create state: %v", err)
			}
			statedb.AddBalance(from, big.NewInt(1e18), tracing.BalanceChangeUnspecified)

			blockCtx := vm.BlockContext{
				CanTransfer: CanTransfer,
				Transfer:    Transfer,
				GetHash:     func(uint64) common.Hash { return common.Hash{} },
				GasLimit:    10_000_000,
				BlockNumber: big.NewInt(tt.number),
				Difficulty:  big.NewInt(1),
				BaseFee:     big.NewInt(params.InitialBaseFee),
			}
			evm := vm.NewEVM(blockCtx, statedb, nil, config, vm.Config{})
			to := tt.to
			msg := &Message{
				From:      from,
				To:        &to,
				Value:     new(big.Int),
				GasLimit:  200_000,
				GasPrice:  new(big.Int),
				GasFeeCap: new(big.Int),
				GasTipCap: new(big.Int),
			}
			_, err = ApplyMessage(evm, msg, new(GasPool).AddGas(blockCtx.GasLimit), common.Address{})
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

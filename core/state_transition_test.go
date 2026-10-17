// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package core

import (
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// TestPreCheckRejectsTransactionTypesBeforeTheirFork checks that a message which
// was not derived from a signed transaction is rejected when the transaction
// type it stands for is not enabled at that block yet. The transaction pool
// already rejects those types (see txpool.ValidateTransaction), so this only
// covers the entry points that build messages without a signer, like eth_call
// and the simulation methods.
func TestPreCheckRejectsTransactionTypesBeforeTheirFork(t *testing.T) {
	t.Parallel()

	var (
		from = common.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1")
		to   = common.HexToAddress("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	)
	// The gas fields are left at zero, but not nil: without the guards the
	// message keeps going until buyGas, which is where an unsupported type
	// would otherwise surface as a panic instead of an error.
	newMessage := func() *Message {
		return &Message{
			From:                  from,
			To:                    &to,
			GasLimit:              100000,
			GasPrice:              new(big.Int),
			GasFeeCap:             new(big.Int),
			GasTipCap:             new(big.Int),
			Value:                 new(big.Int),
			SkipNonceChecks:       true,
			SkipTransactionChecks: true,
		}
	}
	tests := []struct {
		name        string
		blockNumber *big.Int
		msg         *Message
		want        string
	}{
		{
			// Berlin is scheduled long before EIP-1559 on the XDC networks, so
			// this block carries no base fee and the fee caps are not examined.
			name:        "access list before Berlin",
			blockNumber: new(big.Int).Sub(params.XDCMainnetChainConfig.BerlinBlock, common.Big1),
			msg: func() *Message {
				msg := newMessage()
				msg.AccessList = types.AccessList{{Address: to}}
				return msg
			}(),
			want: "access list tx",
		},
		{
			// The first block with a base fee, Prague still unscheduled: the
			// shape eth_simulateV1 accepts an authorization list on and hands
			// back a set-code transaction that cannot be replayed.
			name:        "set code authorization list before Prague",
			blockNumber: params.XDCMainnetChainConfig.EIP1559Block,
			msg: func() *Message {
				msg := newMessage()
				msg.SetCodeAuthorizations = []types.SetCodeAuthorization{{Address: to}}
				return msg
			}(),
			want: "setcode tx",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var (
				config = params.XDCMainnetChainConfig.Clone()
				db     = rawdb.NewMemoryDatabase()
			)
			statedb, err := state.New(types.EmptyRootHash, state.NewDatabase(db))
			if err != nil {
				t.Fatalf("failed to open state: %v", err)
			}
			blockContext := vm.BlockContext{BlockNumber: test.blockNumber}
			evm := vm.NewEVM(blockContext, statedb, nil, config, vm.Config{NoBaseFee: true})
			st := newStateTransition(evm, test.msg, new(GasPool).AddGas(test.msg.GasLimit))

			err = st.preCheck(config.Rules(test.blockNumber))
			if err == nil {
				t.Fatalf("preCheck accepted the %q case, want an error mentioning %q", test.name, test.want)
			}
			if !errors.Is(err, ErrTxTypeNotSupported) {
				t.Fatalf("preCheck error: %v, want %v", err, ErrTxTypeNotSupported)
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("preCheck error: %v, want it to mention %q", err, test.want)
			}
		})
	}
}

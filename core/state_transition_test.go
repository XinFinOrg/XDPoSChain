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

var (
	testSender   = common.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1")
	testReceiver = common.HexToAddress("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
)

// newTestMessage returns a message without access or authorization lists. The
// fee fields are zero but not nil: the && chain only short-circuits when
// NoBaseFee is false, so the bit lengths are still evaluated when it is set.
func newTestMessage() *Message {
	return &Message{
		From:                  testSender,
		To:                    &testReceiver,
		GasLimit:              100000,
		GasPrice:              new(big.Int),
		GasFeeCap:             new(big.Int),
		GasTipCap:             new(big.Int),
		Value:                 new(big.Int),
		SkipNonceChecks:       true,
		SkipTransactionChecks: true,
	}
}

// TestPreCheckRejectsTransactionTypesBeforeTheirFork checks both sides of each
// fork. The pool already rejects those types; this covers the entry points that
// build messages without a signer.
func TestPreCheckRejectsTransactionTypesBeforeTheirFork(t *testing.T) {
	t.Parallel()

	var (
		// Mainnet leaves Prague unscheduled, so schedule it to test the accepted case.
		pragueBlock = big.NewInt(100000000)
		accessList  = types.AccessList{{Address: testReceiver}}
		authList    = []types.SetCodeAuthorization{{Address: testReceiver}}
	)
	tests := []struct {
		name        string
		blockNumber *big.Int
		pragueBlock *big.Int
		msg         *Message
		want        string // empty if the message must be accepted
	}{
		{
			// The block just below EIP-1559 already has Berlin, yet type-1 is
			// still rejected there because that is where the pool gates it.
			name:        "access list before EIP-1559",
			blockNumber: new(big.Int).Sub(params.XDCMainnetChainConfig.EIP1559Block, common.Big1),
			msg: func() *Message {
				msg := newTestMessage()
				msg.AccessList = accessList
				return msg
			}(),
			want: "access list tx",
		},
		{
			name:        "access list at EIP-1559",
			blockNumber: params.XDCMainnetChainConfig.EIP1559Block,
			msg: func() *Message {
				msg := newTestMessage()
				msg.AccessList = accessList
				return msg
			}(),
		},
		{
			// The block just below Prague: the shape eth_simulateV1 used to hand
			// back a set-code transaction that cannot be replayed.
			name:        "set code authorization list before Prague",
			blockNumber: new(big.Int).Sub(pragueBlock, common.Big1),
			pragueBlock: pragueBlock,
			msg: func() *Message {
				msg := newTestMessage()
				msg.SetCodeAuthorizations = authList
				return msg
			}(),
			want: "setcode tx",
		},
		{
			name:        "set code authorization list at Prague",
			blockNumber: pragueBlock,
			pragueBlock: pragueBlock,
			msg: func() *Message {
				msg := newTestMessage()
				msg.SetCodeAuthorizations = authList
				return msg
			}(),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var (
				config = params.XDCMainnetChainConfig.Clone()
				db     = rawdb.NewMemoryDatabase()
			)
			if test.pragueBlock != nil {
				config.PragueBlock = test.pragueBlock
			}
			statedb, err := state.New(types.EmptyRootHash, state.NewDatabase(db))
			if err != nil {
				t.Fatalf("failed to open state: %v", err)
			}
			blockContext := vm.BlockContext{BlockNumber: test.blockNumber}
			evm := vm.NewEVM(blockContext, statedb, nil, config, vm.Config{NoBaseFee: true})
			st := newStateTransition(evm, test.msg, new(GasPool).AddGas(test.msg.GasLimit))

			err = st.preCheck(config.Rules(test.blockNumber))
			if test.want == "" {
				if err != nil {
					t.Fatalf("preCheck rejected the %q case: %v", test.name, err)
				}
				return
			}
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

// TestApplyMessageRejectsAccessListBeforeEIP1559 checks the guard through the
// production path, where execute resolves the fork rules.
func TestApplyMessageRejectsAccessListBeforeEIP1559(t *testing.T) {
	t.Parallel()

	config := params.XDCMainnetChainConfig.Clone()
	statedb, err := state.New(types.EmptyRootHash, state.NewDatabase(rawdb.NewMemoryDatabase()))
	if err != nil {
		t.Fatalf("failed to open state: %v", err)
	}
	blockNumber := new(big.Int).Sub(config.EIP1559Block, common.Big1)
	evm := vm.NewEVM(vm.BlockContext{BlockNumber: blockNumber}, statedb, nil, config, vm.Config{NoBaseFee: true})

	msg := newTestMessage()
	msg.AccessList = types.AccessList{{Address: testReceiver}}
	if _, err := ApplyMessage(evm, msg, new(GasPool).AddGas(msg.GasLimit), common.Address{}); !errors.Is(err, ErrTxTypeNotSupported) {
		t.Fatalf("ApplyMessage error: %v, want %v", err, ErrTxTypeNotSupported)
	}
}

// TestApplyMessageAcceptsAccessListAtEIP1559 checks the accepting side through
// the production path, where execute resolves the fork rules.
func TestApplyMessageAcceptsAccessListAtEIP1559(t *testing.T) {
	t.Parallel()

	config := params.XDCMainnetChainConfig.Clone()
	statedb, err := state.New(types.EmptyRootHash, state.NewDatabase(rawdb.NewMemoryDatabase()))
	if err != nil {
		t.Fatalf("failed to open state: %v", err)
	}
	header := &types.Header{
		Number:     config.EIP1559Block,
		Difficulty: new(big.Int),
		GasLimit:   8_000_000,
		BaseFee:    new(big.Int),
	}
	author := common.Address{}
	blockContext := NewEVMBlockContext(header, nil, &author)
	evm := vm.NewEVM(blockContext, statedb, nil, config, vm.Config{NoBaseFee: true})

	msg := newTestMessage()
	msg.AccessList = types.AccessList{{Address: testReceiver}}
	if _, err := ApplyMessage(evm, msg, new(GasPool).AddGas(msg.GasLimit), common.Address{}); err != nil {
		t.Fatalf("ApplyMessage rejected the access list at EIP-1559: %v", err)
	}
}

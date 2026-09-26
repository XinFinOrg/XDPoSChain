// Copyright 2024 The go-ethereum Authors
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

package native_test

import (
	"encoding/json"
	"errors"
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/common/hexutil"
	"github.com/XinFinOrg/XDPoSChain/core/tracing"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/eth/tracers"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/stretchr/testify/require"
)

func TestCallFlatStop(t *testing.T) {
	tracer, err := tracers.DefaultDirectory.New("flatCallTracer", &tracers.Context{}, nil, params.MainnetChainConfig)
	require.NoError(t, err)

	// this error should be returned by GetResult
	stopError := errors.New("stop error")

	// simulate a transaction
	tx := types.NewTx(&types.LegacyTx{
		Nonce:    0,
		To:       &common.Address{},
		Value:    big.NewInt(0),
		Gas:      0,
		GasPrice: big.NewInt(0),
		Data:     nil,
	})

	tracer.OnTxStart(&tracing.VMContext{}, tx, common.Address{})

	tracer.OnEnter(0, byte(vm.CALL), common.Address{}, common.Address{}, nil, 0, big.NewInt(0))

	// stop before the transaction is finished
	tracer.Stop(stopError)

	tracer.OnTxEnd(&types.Receipt{GasUsed: 0}, nil)

	// check that the error is returned by GetResult
	_, tracerError := tracer.GetResult()
	require.Equal(t, stopError, tracerError)
}

// flatFrame is the subset of the flat trace output the tests below assert on.
type flatFrame struct {
	Type      string `json:"type"`
	Subtraces int    `json:"subtraces"`
	Action    struct {
		To *common.Address `json:"to"`
	} `json:"action"`
	Result struct {
		GasUsed *hexutil.Uint64 `json:"gasUsed"`
	} `json:"result"`
}

// TestFlatCallTracerNonEVMTx covers a transaction that block processing routes to
// ApplyEmptyTransaction (transaction to a XDCX system address, receiver fork active) or to
// ApplySignTransaction: it never enters the EVM, so no frame is pushed onto the callstack.
// GetResult must still return the synthetic top-level frame instead of failing, otherwise
// debug_traceBlock* aborts the whole block with "invalid number of calls".
func TestFlatCallTracerNonEVMTx(t *testing.T) {
	tracer, err := tracers.DefaultDirectory.New("flatCallTracer", &tracers.Context{}, nil, params.TestChainConfig)
	require.NoError(t, err)

	to := common.TradingStateAddrBinary
	tx := types.NewTx(&types.LegacyTx{
		Nonce:    0,
		To:       &to,
		Value:    big.NewInt(1000),
		Gas:      params.TxGas,
		GasPrice: big.NewInt(1),
	})
	require.True(t, tx.IsNonEVMTx(), "premise: the trading state address must be a non-EVM transaction")

	tracer.OnTxStart(&tracing.VMContext{BlockNumber: common.Big1}, tx, common.HexToAddress("0x1234"))
	tracer.OnTxEnd(&types.Receipt{GasUsed: 0}, nil)

	res, err := tracer.GetResult()
	require.NoError(t, err)

	var frames []flatFrame
	require.NoError(t, json.Unmarshal(res, &frames))
	require.Len(t, frames, 1)
	require.Equal(t, "call", frames[0].Type)
	require.Equal(t, 0, frames[0].Subtraces)
	require.NotNil(t, frames[0].Action.To)
	require.Equal(t, to, *frames[0].Action.To)
	require.NotNil(t, frames[0].Result.GasUsed)
	require.Zero(t, *frames[0].Result.GasUsed)
}

// TestFlatCallTracerKeepsRealFrame checks the other half of the same decision: the call
// tracer flags a transaction to a system address as non-EVM even when the fork that routes
// it away from the EVM is not active and the EVM does execute it. The real top-level frame
// must win over the synthetic one, and its gas must stay in step with the receipt.
func TestFlatCallTracerKeepsRealFrame(t *testing.T) {
	tracer, err := tracers.DefaultDirectory.New("flatCallTracer", &tracers.Context{}, nil, params.TestChainConfig)
	require.NoError(t, err)

	to := common.TradingStateAddrBinary
	from := common.HexToAddress("0x1234")
	tx := types.NewTx(&types.LegacyTx{To: &to, Gas: params.TxGas})
	require.True(t, tx.IsNonEVMTx(), "premise: the call tracer flags this transaction as non-EVM")

	tracer.OnTxStart(&tracing.VMContext{BlockNumber: common.Big1}, tx, from)
	tracer.OnEnter(0, byte(vm.CALL), from, to, nil, params.TxGas, big.NewInt(0))
	tracer.OnExit(0, nil, params.TxGas, nil, false)
	tracer.OnTxEnd(&types.Receipt{GasUsed: params.TxGas}, nil)

	res, err := tracer.GetResult()
	require.NoError(t, err)

	var frames []flatFrame
	require.NoError(t, json.Unmarshal(res, &frames))
	require.Len(t, frames, 1)
	require.Equal(t, "call", frames[0].Type)
	require.NotNil(t, frames[0].Action.To)
	require.Equal(t, to, *frames[0].Action.To)
	require.NotNil(t, frames[0].Result.GasUsed)
	require.Equal(t, params.TxGas, uint64(*frames[0].Result.GasUsed))
}

// TestFlatCallTracerUnbalancedCallstack covers the remaining branch of GetResult: more
// than one frame left on the callstack means the tracer stopped hearing from the EVM in
// the middle of the transaction, for example after Stop. The root frame is still
// reported, together with the interruption reason, and the frames left open by the
// interrupted execution are dropped, as in the upstream implementation.
func TestFlatCallTracerUnbalancedCallstack(t *testing.T) {
	tracer, err := tracers.DefaultDirectory.New("flatCallTracer", &tracers.Context{}, nil, params.TestChainConfig)
	require.NoError(t, err)

	to := common.TradingStateAddrBinary
	from := common.HexToAddress("0x1234")
	tx := types.NewTx(&types.LegacyTx{To: &to, Gas: params.TxGas})

	tracer.OnTxStart(&tracing.VMContext{BlockNumber: common.Big1}, tx, from)
	// Two frames, neither of them closed: an execution timeout interrupts the tracer in
	// the middle of a nested call, and flatCallTracer swallows the remaining callbacks
	// once the interrupt flag is set, so both frames stay on the callstack.
	tracer.OnEnter(0, byte(vm.CALL), from, to, nil, params.TxGas, big.NewInt(0))
	tracer.OnEnter(1, byte(vm.CALL), from, to, nil, params.TxGas, big.NewInt(0))
	stopError := errors.New("execution timeout")
	tracer.Stop(stopError)
	tracer.OnExit(1, nil, params.TxGas, nil, false)
	tracer.OnExit(0, nil, params.TxGas, nil, false)
	tracer.OnTxEnd(&types.Receipt{GasUsed: params.TxGas}, nil)

	res, err := tracer.GetResult()
	require.Equal(t, stopError, err)

	var frames []flatFrame
	require.NoError(t, json.Unmarshal(res, &frames))
	require.Len(t, frames, 1)
	require.Equal(t, 0, frames[0].Subtraces)
}

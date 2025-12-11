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

// TestCallTracerNonEVMTx tests the call tracer with non-EVM special transactions
// to ensure it returns a synthetic top-level callFrame.
func TestCallTracerNonEVMTx(t *testing.T) {
	tests := []struct {
		name     string
		to       common.Address
		isNonEVM bool
	}{
		{
			name:     "BlockSignersBinary transaction",
			to:       common.BlockSignersBinary,
			isNonEVM: true,
		},
		{
			name:     "XDCXAddrBinary transaction",
			to:       common.XDCXAddrBinary,
			isNonEVM: true,
		},
		{
			name:     "TradingStateAddrBinary transaction",
			to:       common.TradingStateAddrBinary,
			isNonEVM: true,
		},
		{
			name:     "XDCXLendingAddressBinary transaction",
			to:       common.XDCXLendingAddressBinary,
			isNonEVM: true,
		},
		{
			name:     "XDCXLendingFinalizedTradeAddressBinary transaction",
			to:       common.XDCXLendingFinalizedTradeAddressBinary,
			isNonEVM: true,
		},
		{
			name:     "Regular transaction",
			to:       common.HexToAddress("0x1234567890123456789012345678901234567890"),
			isNonEVM: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tracer, err := tracers.DefaultDirectory.New("callTracer", &tracers.Context{}, nil, params.MainnetChainConfig)
			require.NoError(t, err)

			from := common.HexToAddress("0xabcdef1234567890abcdef1234567890abcdef12")
			gasLimit := uint64(100000)
			value := big.NewInt(1000)
			data := []byte{0x01, 0x02, 0x03}

			tx := types.NewTx(&types.LegacyTx{
				Nonce:    0,
				To:       &tt.to,
				Value:    value,
				Gas:      gasLimit,
				GasPrice: big.NewInt(1),
				Data:     data,
			})

			vmContext := &tracing.VMContext{
				BlockNumber: big.NewInt(1),
			}

			// Start transaction tracing
			tracer.OnTxStart(vmContext, tx, from)

			if tt.isNonEVM {
				// For non-EVM transactions, we don't call OnEnter/OnExit
				// because the EVM doesn't execute. We only call OnTxEnd.
				receipt := &types.Receipt{
					GasUsed: 21000,
				}
				tracer.OnTxEnd(receipt, nil)

				// Get the result
				result, err := tracer.GetResult()
				require.NoError(t, err)

				// Parse the result
				var callFrame map[string]interface{}
				err = json.Unmarshal(result, &callFrame)
				require.NoError(t, err)

				// Verify the synthetic callFrame
				require.Equal(t, "CALL", callFrame["type"])
				// Just verify addresses are present and not empty
				fromStr, ok := callFrame["from"].(string)
				require.True(t, ok, "from field should be a string")
				require.NotEmpty(t, fromStr, "from address should not be empty")

				toStr, ok := callFrame["to"].(string)
				require.True(t, ok, "to field should be a string")
				require.NotEmpty(t, toStr, "to address should not be empty")

				require.Equal(t, hexutil.Uint64(gasLimit).String(), callFrame["gas"])
				require.Equal(t, (*hexutil.Big)(value).String(), callFrame["value"])
				require.Equal(t, hexutil.Uint64(21000).String(), callFrame["gasUsed"])
				require.Equal(t, hexutil.Bytes(data).String(), callFrame["input"])
				require.Nil(t, callFrame["output"])
				// error field should be nil (no error) for non-EVM transactions
				if callFrame["error"] != nil {
					require.Equal(t, "", callFrame["error"])
				}
			} else {
				// For regular transactions, simulate normal EVM execution
				tracer.OnEnter(0, byte(vm.CALL), from, tt.to, data, gasLimit, value)
				tracer.OnExit(0, []byte{0x04, 0x05}, 50000, nil, false)

				receipt := &types.Receipt{
					GasUsed: 50000,
				}
				tracer.OnTxEnd(receipt, nil)

				// Get the result
				result, err := tracer.GetResult()
				require.NoError(t, err)

				// Verify we got a proper result
				var callFrame map[string]interface{}
				err = json.Unmarshal(result, &callFrame)
				require.NoError(t, err)
				require.NotNil(t, callFrame)
			}
		})
	}
}

// TestCallTracerEmptyCallstack tests that OnLog and OnTxEnd don't panic
// when the callstack is empty (guards against issue #1863).
func TestCallTracerEmptyCallstack(t *testing.T) {
	tracer, err := tracers.DefaultDirectory.New("callTracer", &tracers.Context{}, nil, params.MainnetChainConfig)
	require.NoError(t, err)

	from := common.HexToAddress("0xabcdef1234567890abcdef1234567890abcdef12")
	to := common.BlockSignersBinary

	tx := types.NewTx(&types.LegacyTx{
		Nonce:    0,
		To:       &to,
		Value:    big.NewInt(0),
		Gas:      100000,
		GasPrice: big.NewInt(1),
		Data:     nil,
	})

	vmContext := &tracing.VMContext{
		BlockNumber: big.NewInt(1),
	}

	// Start non-EVM transaction
	tracer.OnTxStart(vmContext, tx, from)

	// Try to call OnLog with empty callstack - should not panic
	log := &types.Log{
		Address: to,
		Topics:  []common.Hash{common.HexToHash("0x1234")},
		Data:    []byte{0x01, 0x02},
	}
	require.NotPanics(t, func() {
		tracer.OnLog(log)
	})

	// Try to call OnTxEnd with empty callstack - should not panic
	receipt := &types.Receipt{
		GasUsed: 21000,
	}
	require.NotPanics(t, func() {
		tracer.OnTxEnd(receipt, nil)
	})

	// Verify we can still get a result
	result, err := tracer.GetResult()
	require.NoError(t, err)
	require.NotNil(t, result)
}

// TestCallTracerStateReset tests that tracer state is properly reset
// between transactions to prevent state leakage.
func TestCallTracerStateReset(t *testing.T) {
	tracer, err := tracers.DefaultDirectory.New("callTracer", &tracers.Context{}, nil, params.MainnetChainConfig)
	require.NoError(t, err)

	from := common.HexToAddress("0xabcdef1234567890abcdef1234567890abcdef12")
	nonEVMTo := common.BlockSignersBinary
	regularTo := common.HexToAddress("0x1234567890123456789012345678901234567890")

	// First transaction: non-EVM
	tx1 := types.NewTx(&types.LegacyTx{
		Nonce:    0,
		To:       &nonEVMTo,
		Value:    big.NewInt(0),
		Gas:      100000,
		GasPrice: big.NewInt(1),
		Data:     nil,
	})

	vmContext := &tracing.VMContext{
		BlockNumber: big.NewInt(1),
	}

	tracer.OnTxStart(vmContext, tx1, from)
	receipt1 := &types.Receipt{
		GasUsed: 21000,
	}
	tracer.OnTxEnd(receipt1, nil)

	result1, err := tracer.GetResult()
	require.NoError(t, err)
	require.NotNil(t, result1)

	// Second transaction: regular EVM transaction
	tx2 := types.NewTx(&types.LegacyTx{
		Nonce:    1,
		To:       &regularTo,
		Value:    big.NewInt(1000),
		Gas:      100000,
		GasPrice: big.NewInt(1),
		Data:     []byte{0x01},
	})

	tracer.OnTxStart(vmContext, tx2, from)
	tracer.OnEnter(0, byte(vm.CALL), from, regularTo, []byte{0x01}, 100000, big.NewInt(1000))
	tracer.OnExit(0, []byte{0x02}, 50000, nil, false)
	receipt2 := &types.Receipt{
		GasUsed: 50000,
	}
	tracer.OnTxEnd(receipt2, nil)

	result2, err := tracer.GetResult()
	require.NoError(t, err)
	require.NotNil(t, result2)

	// Verify that the results are different
	require.NotEqual(t, string(result1), string(result2))
}

// TestCallTracerNilTransaction tests that OnTxStart handles nil transaction gracefully.
func TestCallTracerNilTransaction(t *testing.T) {
	tracer, err := tracers.DefaultDirectory.New("callTracer", &tracers.Context{}, nil, params.MainnetChainConfig)
	require.NoError(t, err)

	vmContext := &tracing.VMContext{
		BlockNumber: big.NewInt(1),
	}
	from := common.HexToAddress("0xabcdef1234567890abcdef1234567890abcdef12")

	// Should not panic with nil transaction
	require.NotPanics(t, func() {
		tracer.OnTxStart(vmContext, nil, from)
	})
}

// TestCallTracerNonEVMTxWithLog tests that the call tracer correctly captures logs
// for non-EVM transactions when WithLog configuration is enabled.
// This test verifies:
// 1. Logs are captured when WithLog=true
// 2. Logs are not captured when WithLog=false
// 3. Log position tracking is correct for non-EVM transactions
// 4. No log duplication occurs between transactions
func TestCallTracerNonEVMTxWithLog(t *testing.T) {
	tests := []struct {
		name               string
		withLog            bool
		to                 common.Address
		logCount           int
		expectLogsInResult bool
	}{
		{
			name:               "BlockSignersBinary with WithLog=true",
			withLog:            true,
			to:                 common.BlockSignersBinary,
			logCount:           3,
			expectLogsInResult: true,
		},
		{
			name:               "BlockSignersBinary with WithLog=false",
			withLog:            false,
			to:                 common.BlockSignersBinary,
			logCount:           3,
			expectLogsInResult: false,
		},
		{
			name:               "XDCXAddrBinary with WithLog=true",
			withLog:            true,
			to:                 common.XDCXAddrBinary,
			logCount:           2,
			expectLogsInResult: true,
		},
		{
			name:               "TradingStateAddrBinary with WithLog=true",
			withLog:            true,
			to:                 common.TradingStateAddrBinary,
			logCount:           1,
			expectLogsInResult: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create tracer with WithLog configuration
			config := json.RawMessage(`{"withLog":` + func() string {
				if tt.withLog {
					return "true"
				}
				return "false"
			}() + `}`)

			tracer, err := tracers.DefaultDirectory.New("callTracer", &tracers.Context{}, config, params.MainnetChainConfig)
			require.NoError(t, err)

			from := common.HexToAddress("0xabcdef1234567890abcdef1234567890abcdef12")
			gasLimit := uint64(100000)
			value := big.NewInt(0)
			data := []byte{0x01, 0x02, 0x03}

			tx := types.NewTx(&types.LegacyTx{
				Nonce:    0,
				To:       &tt.to,
				Value:    value,
				Gas:      gasLimit,
				GasPrice: big.NewInt(1),
				Data:     data,
			})

			vmContext := &tracing.VMContext{
				BlockNumber: big.NewInt(1),
			}

			// Start transaction tracing
			tracer.OnTxStart(vmContext, tx, from)

			// Simulate log events for non-EVM transaction
			for i := 0; i < tt.logCount; i++ {
				log := &types.Log{
					Address: tt.to,
					Topics: []common.Hash{
						common.HexToHash("0x1234"),
						common.BigToHash(big.NewInt(int64(i))),
					},
					Data: []byte{byte(i), 0xff},
				}
				tracer.OnLog(log)
			}

			receipt := &types.Receipt{
				GasUsed: 21000,
			}
			tracer.OnTxEnd(receipt, nil)

			// Get the result
			result, err := tracer.GetResult()
			require.NoError(t, err)

			// Parse the result
			var callFrame map[string]interface{}
			err = json.Unmarshal(result, &callFrame)
			require.NoError(t, err)

			// Verify logs are included or excluded based on WithLog config
			logs, logsExist := callFrame["logs"]
			if tt.expectLogsInResult {
				require.True(t, logsExist, "logs field should exist when WithLog=true")
				logArray, ok := logs.([]interface{})
				require.True(t, ok, "logs should be an array")
				require.Len(t, logArray, tt.logCount, "should have correct number of logs")

				// Verify log structure and position tracking
				for _, logItem := range logArray {
					logMap, ok := logItem.(map[string]interface{})
					require.True(t, ok, "each log should be a map")

					// Verify required log fields
					require.NotNil(t, logMap["address"], "log should have address")
					require.NotNil(t, logMap["topics"], "log should have topics")
					require.NotNil(t, logMap["data"], "log should have data")

					// Verify position tracking (should be 0 for non-EVM tx with no sub-calls)
					position, ok := logMap["position"].(string)
					require.True(t, ok, "position should be a string")
					require.Equal(t, "0x0", position, "log position should be 0x0 for non-EVM tx")

					// Verify topics array contains expected values
					topics, ok := logMap["topics"].([]interface{})
					require.True(t, ok, "topics should be an array")
					require.Len(t, topics, 2, "should have 2 topics")

					// Verify log data is correctly captured
					data, ok := logMap["data"].(string)
					require.True(t, ok, "data should be a string")
					require.NotEmpty(t, data, "data should not be empty")
				}
			} else {
				// When WithLog=false, logs field may not exist or should be empty
				if logsExist {
					logArray, ok := logs.([]interface{})
					if ok {
						require.Len(t, logArray, 0, "logs array should be empty when WithLog=false")
					}
				}
			}
		})
	}
}

// TestCallTracerNonEVMTxLogNoDuplication tests that logs from one non-EVM
// transaction don't leak into the next transaction.
func TestCallTracerNonEVMTxLogNoDuplication(t *testing.T) {
	config := json.RawMessage(`{"withLog":true}`)
	tracer, err := tracers.DefaultDirectory.New("callTracer", &tracers.Context{}, config, params.MainnetChainConfig)
	require.NoError(t, err)

	from := common.HexToAddress("0xabcdef1234567890abcdef1234567890abcdef12")
	to := common.BlockSignersBinary

	vmContext := &tracing.VMContext{
		BlockNumber: big.NewInt(1),
	}

	// First transaction: non-EVM with 2 logs
	tx1 := types.NewTx(&types.LegacyTx{
		Nonce:    0,
		To:       &to,
		Value:    big.NewInt(0),
		Gas:      100000,
		GasPrice: big.NewInt(1),
		Data:     nil,
	})

	tracer.OnTxStart(vmContext, tx1, from)

	// Add 2 logs to first transaction
	for i := 0; i < 2; i++ {
		log := &types.Log{
			Address: to,
			Topics:  []common.Hash{common.HexToHash("0xaaaa")},
			Data:    []byte{0xaa},
		}
		tracer.OnLog(log)
	}

	receipt1 := &types.Receipt{GasUsed: 21000}
	tracer.OnTxEnd(receipt1, nil)

	result1, err := tracer.GetResult()
	require.NoError(t, err)

	var callFrame1 map[string]interface{}
	err = json.Unmarshal(result1, &callFrame1)
	require.NoError(t, err)

	logs1, ok := callFrame1["logs"].([]interface{})
	require.True(t, ok)
	require.Len(t, logs1, 2, "first transaction should have 2 logs")

	// Second transaction: non-EVM with 1 log
	tx2 := types.NewTx(&types.LegacyTx{
		Nonce:    1,
		To:       &to,
		Value:    big.NewInt(0),
		Gas:      100000,
		GasPrice: big.NewInt(1),
		Data:     nil,
	})

	tracer.OnTxStart(vmContext, tx2, from)

	// Add only 1 log to second transaction
	log := &types.Log{
		Address: to,
		Topics:  []common.Hash{common.HexToHash("0xbbbb")},
		Data:    []byte{0xbb},
	}
	tracer.OnLog(log)

	receipt2 := &types.Receipt{GasUsed: 21000}
	tracer.OnTxEnd(receipt2, nil)

	result2, err := tracer.GetResult()
	require.NoError(t, err)

	var callFrame2 map[string]interface{}
	err = json.Unmarshal(result2, &callFrame2)
	require.NoError(t, err)

	logs2, ok := callFrame2["logs"].([]interface{})
	require.True(t, ok)
	require.Len(t, logs2, 1, "second transaction should have only 1 log (no duplication from first tx)")

	// Verify the log in second transaction is different from first
	log2Map := logs2[0].(map[string]interface{})
	topics2 := log2Map["topics"].([]interface{})
	require.Contains(t, topics2[0].(string), "bbbb", "second transaction should have different log topics")
}

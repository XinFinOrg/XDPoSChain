// Copyright 2015 The go-ethereum Authors
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

package tests

import (
	"bufio"
	"bytes"
	"fmt"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/core/vm"
)

func TestState(t *testing.T) {
	t.Parallel()

	st := new(testMatcher)
	// Long tests:
	st.skipShortMode(`^stQuadraticComplexityTest/`)

	// Broken tests:
	st.skipLoad(`^stTransactionTest/OverflowGasRequire\.json`) // gasLimit > 256 bits
	st.skipLoad(`^stTransactionTest/zeroSigTransa[^/]*\.json`) // EIP-86 is not supported yet

	// Uses 1GB RAM per tested fork
	st.skipLoad(`^stStaticCall/static_Call1MB`)
	// Un-skip this when https://github.com/ethereum/tests/issues/908 is closed
	st.skipLoad(`^stQuadraticComplexityTest/QuadraticComplexitySolidity_CallDataCopy`)

	// Expected failures:
	st.fails(`^stRevertTest/RevertPrecompiledTouch\.json/EIP158`, "bug in test")
	st.fails(`^stRevertTest/RevertPrefoundEmptyOOG\.json/EIP158`, "bug in test")
	st.fails(`^stRevertTest/RevertPrecompiledTouch\.json/Byzantium`, "bug in test")
	st.fails(`^stRevertTest/RevertPrefoundEmptyOOG\.json/Byzantium`, "bug in test")
	st.fails(`^stRandom2/randomStatetest64[45]\.json/(EIP150|Frontier|Homestead)/.*`, "known bug #15119")
	st.fails(`^stCreateTest/TransactionCollisionToEmpty\.json/EIP158/2`, "known bug ")
	st.fails(`^stCreateTest/TransactionCollisionToEmpty\.json/EIP158/3`, "known bug ")
	st.fails(`^stCreateTest/TransactionCollisionToEmpty\.json/Byzantium/2`, "known bug ")
	st.fails(`^stCreateTest/TransactionCollisionToEmpty\.json/Byzantium/3`, "known bug ")

	st.walk(t, stateTestDir, func(t *testing.T, name string, test *StateTest) {
		fmt.Println("name", name)
		for _, subtest := range test.Subtests() {
			key := fmt.Sprintf("%s/%d", subtest.Fork, subtest.Index)
			name := name + "/" + key
			t.Run(key, func(t *testing.T) {
				if subtest.Fork == "Constantinople" {
					t.Skip("constantinople not supported yet")
				}
				withTrace(t, test.gasLimit(subtest), func(vmconfig vm.Config) error {
					_, err := test.Run(subtest, vmconfig)
					return st.checkFailure(t, name, err)
				})
			})
		}
	})
}

// Transactions with gasLimit above this value will not get a VM trace on failure.
const traceErrorLimit = 40000000

func withTrace(t *testing.T, gasLimit uint64, test func(vm.Config) error) {
	// Use config from command line arguments.
	config := vm.Config{}
	err := test(config)
	if err == nil {
		return
	}

	// Test failed, re-run with tracing enabled.
	t.Error(err)
	if gasLimit > traceErrorLimit {
		t.Log("gas limit too high for EVM trace")
		return
	}
	buf := new(bytes.Buffer)
	w := bufio.NewWriter(buf)
	// config.Tracer = logger.NewJSONLogger(&logger.Config{}, w)
	err2 := test(config)
	if !reflect.DeepEqual(err, err2) {
		t.Errorf("different error for second run: %v", err2)
	}
	w.Flush()
	if buf.Len() == 0 {
		t.Log("no EVM operation logs generated")
	} else {
		t.Log("EVM operation log:\n" + buf.String())
	}
	// t.Logf("EVM output: 0x%x", tracer.Output())
	// t.Logf("EVM error: %v", tracer.Error())
}

func TestExecutionSpecState(t *testing.T) {
	executionSpecStateTestDir := filepath.Join("/Users/wp/Git/go/src/github.com/XinFinOrg/XDPoSChain", "tests", "fixtures-frontier", "state_tests")
	st := new(testMatcher)

	st.walk(t, executionSpecStateTestDir, func(t *testing.T, name string, test *StateTest) {
		fmt.Println("Executing:", name)
		execStateTest(t, st, test, name)
	})
}

func execStateTest(t *testing.T, st *testMatcher, test *StateTest, name string) {
	fmt.Println(test.Subtests())
	for _, subtest := range test.Subtests() {
		key := fmt.Sprintf("%s/%d", subtest.Fork, subtest.Index)
		t.Run(key+"/hash/trie", func(t *testing.T) {
			withTrace(t, test.gasLimit(subtest), func(vmconfig vm.Config) error {
				fmt.Println(vmconfig)
				_, err := test.Run(subtest, vmconfig)
				if err != nil {
					fmt.Println("/hash/trie error:", st.checkFailure(t, name, err), "test name", name)
				} else {
					fmt.Println("/hash/trie success", "test name", name)
				}
				return st.checkFailure(t, name, err)
			})
		})
		// t.Run(key+"/hash/snap", func(t *testing.T) {
		// 	withTrace(t, test.gasLimit(subtest), func(vmconfig vm.Config) error {
		// 		var result error
		// 		test.Run(subtest, vmconfig, true, rawdb.HashScheme, func(err error, state *StateTestState) {
		// 			if state.Snapshots != nil && state.StateDB != nil {
		// 				if _, err := state.Snapshots.Journal(state.StateDB.IntermediateRoot(false)); err != nil {
		// 					result = err
		// 					return
		// 				}
		// 			}
		// 			result = st.checkFailure(t, err)
		// 		})
		// 		return result
		// 	})
		// })
		t.Run(key+"/path/trie", func(t *testing.T) {
			withTrace(t, test.gasLimit(subtest), func(vmconfig vm.Config) error {
				_, err := test.Run(subtest, vmconfig)
				if err != nil {
					fmt.Println("/path/trie error:", st.checkFailure(t, name, err), "test name", name)
				} else {
					fmt.Println("/path/trie success", "test name", name)
				}
				return st.checkFailure(t, name, err)
			})
		})
		// t.Run(key+"/path/snap", func(t *testing.T) {
		// 	withTrace(t, test.gasLimit(subtest), func(vmconfig vm.Config) error {
		// 		var result error
		// 		test.Run(subtest, vmconfig, true, rawdb.PathScheme, func(err error, state *StateTestState) {
		// 			if state.Snapshots != nil && state.StateDB != nil {
		// 				if _, err := state.Snapshots.Journal(state.StateDB.IntermediateRoot(false)); err != nil {
		// 					result = err
		// 					return
		// 				}
		// 			}
		// 			result = st.checkFailure(t, err)
		// 		})
		// 		return result
		// 	})
		// })
	}
}

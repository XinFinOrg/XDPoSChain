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
	"fmt"
	"path/filepath"
	"testing"
)

func TestBlockchain(t *testing.T) {
	t.Parallel()

	bt := new(testMatcher)
	// General state tests are 'exported' as blockchain tests, but we can run them natively.
	bt.skipLoad(`^GeneralStateTests/`)
	// Skip random failures due to selfish mining test.
	bt.skipLoad(`^bcForgedTest/bcForkUncle\.json`)
	bt.skipLoad(`^bcMultiChainTest/(ChainAtoChainB_blockorder|CallContractFromNotBestBlock)`)
	bt.skipLoad(`^bcTotalDifficultyTest/(lotsOfLeafs|lotsOfBranches|sideChainWithMoreTransactions)`)
	// Constantinople is not implemented yet.
	bt.skipLoad(`(?i)(constantinople)`)

	// Still failing tests
	bt.skipLoad(`^bcWalletTest.*_Byzantium$`)

	bt.walk(t, blockTestDir, func(t *testing.T, name string, test *BlockTest) {
		if err := bt.checkFailure(t, name, test.Run()); err != nil {
			t.Error(err)
		}
	})
}
func TestExecutionSpecBlocktests(t *testing.T) {
	executionSpecBlockchainTestDir := filepath.Join("/Users/wp/Git/XDPoSChain", "tests", "fixtures-frontier", "blockchain_tests")

	bt := new(testMatcher)

	bt.skipLoad(".*prague/eip7251_consolidations/contract_deployment/system_contract_deployment.json")
	bt.skipLoad(".*prague/eip7002_el_triggerable_withdrawals/contract_deployment/system_contract_deployment.json")

	bt.walk(t, executionSpecBlockchainTestDir, func(t *testing.T, name string, test *BlockTest) {
		fmt.Println("executing", name)
		execBlockTest(t, bt, test, name)
	})
}

func execBlockTest(t *testing.T, bt *testMatcher, test *BlockTest, name string) {
	// Define all the different flag combinations we should run the tests with,
	// picking only one for short tests.
	//
	// Note, witness building and self-testing is always enabled as it's a very
	// good test to ensure that we don't break it.

	if err := bt.checkFailure(t, name, test.Run()); err != nil {
		t.Errorf("test failed: %v", err)
		return
	} else {
		fmt.Println("test success:", name)
	}
}

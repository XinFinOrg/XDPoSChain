// Copyright 2016 The go-ethereum Authors
// This file is part of go-ethereum.
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with go-ethereum. If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
)

const daoFutureForkConfig = `
		"eip150Block" : 1000000000,
		"eip155Block" : 1000000000,
		"eip158Block" : 1000000000,
		"byzantiumBlock" : 1000000000,
		"constantinopleBlock" : 1000000000,
		"petersburgBlock" : 1000000000,
		"istanbulBlock" : 1000000000,
		"tipSigningBlock" : 1000000000,
		"tipRandomizeBlock" : 1000000000,
		"tipIncreaseMasternodesBlock" : 1000000000,
		"denylistBlock" : 1000000000,
		"tipNoHalvingMNRewardBlock" : 1000000000,
		"tipXDCXBlock" : 1000000000,
		"tipXDCXLendingBlock" : 1000000000,
		"tipXDCXCancellationFeeBlock" : 1000000000,
		"tipTRC21FeeBlock" : 1000000000,
		"gas50xBlock" : 1000000000,
		"berlinBlock" : 1000000000,
		"londonBlock" : 1000000000,
		"mergeBlock" : 1000000000,
		"shanghaiBlock" : 1000000000,
		"tipXDCXMinerDisableBlock" : 1000000000,
		"tipXDCXReceiverDisableBlock" : 1000000000,
		"eip1559Block" : 1000000000,
		"cancunBlock" : 1000000000,
		"pragueBlock" : 1000000000,
		"osakaBlock" : 1000000000,
		"dynamicGasLimitBlock" : 1000000000,
		"tipUpgradeRewardBlock" : 1000000000,
		"tipUpgradePenaltyBlock" : 1000000000,
		"tipEpochHalvingBlock" : 1000000000,
		"trc21IssuerSMC" : "0x8c0faeb5C6bEd2129b8674F262Fd45c4e9468bee",
		"xdcxListingSMC" : "0xDE34dD0f536170993E8CFF639DdFfCF1A85D3E53",
		"relayerRegistrationSMC" : "0x16c63b79f9C8784168103C0b74E6A59EC2de4a02",
		"lendingRegistrationSMC" : "0x7d761afd7ff65a79e4173897594a194e3c506e57",`

const daoXDPoSConfig = `
		"XDPoS": {
			"period": 2,
			"epoch": 900,
			"reward": 5000,
			"rewardCheckpoint": 900,
			"gap": 450,
			"foundationWalletAddr": "0x0000000000000000000000000000000000000068",
			"maxMasternodesV2": 108,
			"v2": {
				"switchEpoch": 1111111,
				"switchBlock": 999999900,
				"config": {
					"maxMasternodes": 108,
					"switchRound": 0,
					"minePeriod": 2,
					"timeoutSyncThreshold": 3,
					"timeoutPeriod": 10,
					"certificateThreshold": 0.667,
					"expTimeoutConfig": {
						"base": 1,
						"maxExponent": 0
					}
				},
				"allConfigs": {
					"0": {
						"maxMasternodes": 108,
						"switchRound": 0,
						"minePeriod": 2,
						"timeoutSyncThreshold": 3,
						"timeoutPeriod": 10,
						"certificateThreshold": 0.667,
						"expTimeoutConfig": {
							"base": 1,
							"maxExponent": 0
						}
					}
				}
			}
		}`

// Genesis block for nodes which don't care about the DAO fork (i.e. not configured)
var daoOldGenesis = `{
	"alloc"      : {},
	"coinbase"   : "0x0000000000000000000000000000000000000000",
	"difficulty" : "0x20000",
	"extraData"  : "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	"gasLimit"   : "0x2fefd8",
	"nonce"      : "0x0000000000000042",
	"mixhash"    : "0x0000000000000000000000000000000000000000000000000000000000000000",
	"parentHash" : "0x0000000000000000000000000000000000000000000000000000000000000000",
	"timestamp"  : "0x00",
	"config"     : {
		"chainId" : 1337,
	` + daoFutureForkConfig + `
	` + daoXDPoSConfig + `
	}
}`

// Genesis block for nodes which actively oppose the DAO fork
var daoNoForkGenesis = `{
	"alloc"      : {},
	"coinbase"   : "0x0000000000000000000000000000000000000000",
	"difficulty" : "0x20000",
	"extraData"  : "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	"gasLimit"   : "0x2fefd8",
	"nonce"      : "0x0000000000000042",
	"mixhash"    : "0x0000000000000000000000000000000000000000000000000000000000000000",
	"parentHash" : "0x0000000000000000000000000000000000000000000000000000000000000000",
	"timestamp"  : "0x00",
	"config"     : {
		"chainId" : 1337,
	` + daoFutureForkConfig + `
		"daoForkBlock"   : 314,
		"daoForkSupport" : false,
	` + daoXDPoSConfig + `
	}
}`

// Genesis block for nodes which actively support the DAO fork
var daoProForkGenesis = `{
	"alloc"      : {},
	"coinbase"   : "0x0000000000000000000000000000000000000000",
	"difficulty" : "0x20000",
	"extraData"  : "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	"gasLimit"   : "0x2fefd8",
	"nonce"      : "0x0000000000000042",
	"mixhash"    : "0x0000000000000000000000000000000000000000000000000000000000000000",
	"parentHash" : "0x0000000000000000000000000000000000000000000000000000000000000000",
	"timestamp"  : "0x00",
	"config"     : {
		"chainId" : 1337,
	` + daoFutureForkConfig + `
		"daoForkBlock"   : 314,
		"daoForkSupport" : true,
	` + daoXDPoSConfig + `
	}
}`

var daoGenesisForkBlock = big.NewInt(314)

// TestDAOForkBlockNewChain tests that the DAO hard-fork number and the nodes support/opposition is correctly
// set in the database after various initialization procedures and invocations.
func TestDAOForkBlockNewChain(t *testing.T) {
	for i, arg := range []struct {
		genesis     string
		expectBlock *big.Int
		expectVote  bool
	}{
		// Test DAO Default Mainnet
		// {"", params.XDCMainnetChainConfig.DAOForkBlock, false},
		// test DAO Init Old Privnet
		{daoOldGenesis, nil, false},
		// test DAO Default No Fork Privnet
		{daoNoForkGenesis, daoGenesisForkBlock, false},
		// test DAO Default Pro Fork Privnet
		{daoProForkGenesis, daoGenesisForkBlock, true},
	} {
		testDAOForkBlockNewChain(t, i, arg.genesis, arg.expectBlock, arg.expectVote)
	}
}

func testDAOForkBlockNewChain(t *testing.T, test int, genesis string, expectBlock *big.Int, expectVote bool) {
	// Create a temporary data directory to use and inspect later
	datadir := t.TempDir()

	// Start a XDC instance with the requested flags set and immediately terminate
	if genesis != "" {
		json := filepath.Join(datadir, "genesis.json")
		if err := os.WriteFile(json, []byte(genesis), 0600); err != nil {
			t.Fatalf("test %d: failed to write genesis file: %v", test, err)
		}
		runXDC(t, "init", "--datadir", datadir, json).WaitExit()
	} else {
		// Force chain initialization
		XDC := runXDC(t, "console", "--port", "0", "--maxpeers", "0", "--nodiscover", "--nat", "none", "--ipcdisable", "--datadir", datadir, "--exec", "2+2")
		XDC.WaitExit()
	}
	// Retrieve the DAO config flag from the database
	path := filepath.Join(datadir, "XDC", "chaindata")
	db, err := rawdb.NewLevelDBDatabase(path, 0, 0, "", false)
	if err != nil {
		t.Fatalf("test %d: failed to open test database: %v", test, err)
	}
	defer db.Close()

	genesisHash := rawdb.ReadCanonicalHash(db, 0)
	if genesisHash == (common.Hash{}) {
		t.Errorf("test %d: failed to read canonical genesis hash", test)
		return
	}
	config, err := rawdb.ReadChainConfig(db, genesisHash)
	if err != nil {
		t.Errorf("test %d: failed to read chain config: %v", test, err)
		return
	}
	if config == nil {
		t.Errorf("test %d: failed to retrieve chain config", test)
		return
	}
	// Validate the DAO hard-fork block number against the expected value
	if config.DAOForkBlock == nil {
		if expectBlock != nil {
			t.Errorf("test %d: dao hard-fork block mismatch: have nil, want %v", test, expectBlock)
		}
	} else if expectBlock == nil {
		t.Errorf("test %d: dao hard-fork block mismatch: have %v, want nil", test, config.DAOForkBlock)
	} else if config.DAOForkBlock.Cmp(expectBlock) != 0 {
		t.Errorf("test %d: dao hard-fork block mismatch: have %v, want %v", test, config.DAOForkBlock, expectBlock)
	}
	if config.DAOForkSupport != expectVote {
		t.Errorf("test %d: dao hard-fork support mismatch: have %v, want %v", test, config.DAOForkSupport, expectVote)
	}
}

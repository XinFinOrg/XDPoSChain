// Copyright 2016 The go-ethereum Authors
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
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// Tests that DAO-fork enabled clients can properly filter out fork-commencing
// blocks based on their extradata fields.
func TestDAOForkRangeExtradata(t *testing.T) {
	forkBlock := big.NewInt(32)
	futureFork := big.NewInt(1_000_000_000)
	setFutureXinFinForks := func(cfg *params.ChainConfig) {
		set := func() *big.Int { return new(big.Int).Set(futureFork) }
		cfg.TIPSigningBlock = set()
		cfg.TIPRandomizeBlock = set()
		cfg.TIPIncreaseMasternodesBlock = set()
		cfg.DenylistBlock = set()
		cfg.TIPNoHalvingMNRewardBlock = set()
		cfg.TIPXDCXBlock = set()
		cfg.TIPXDCXLendingBlock = set()
		cfg.TIPXDCXCancellationFeeBlock = set()
		cfg.TIPTRC21FeeBlock = set()
		cfg.Gas50xBlock = set()
		cfg.BerlinBlock = set()
		cfg.LondonBlock = set()
		cfg.MergeBlock = set()
		cfg.ShanghaiBlock = set()
		cfg.TIPXDCXMinerDisableBlock = set()
		cfg.TIPXDCXReceiverDisableBlock = set()
		cfg.EIP1559Block = set()
		cfg.CancunBlock = set()
		cfg.PragueBlock = set()
		cfg.OsakaBlock = set()
		cfg.DynamicGasLimitBlock = set()
		cfg.TIPUpgradeRewardBlock = set()
		cfg.TIPUpgradePenaltyBlock = set()
		cfg.TIPEpochHalvingBlock = set()
		cfg.TRC21IssuerSMC = params.XDCMainnetChainConfig.TRC21IssuerSMC
		cfg.XDCXListingSMC = params.XDCMainnetChainConfig.XDCXListingSMC
		cfg.RelayerRegistrationSMC = params.XDCMainnetChainConfig.RelayerRegistrationSMC
		cfg.LendingRegistrationSMC = params.XDCMainnetChainConfig.LendingRegistrationSMC
	}
	chainConfig := *params.MainnetChainConfig
	chainConfig.HomesteadBlock = big.NewInt(0)
	setFutureXinFinForks(&chainConfig)

	// Generate a common prefix for both pro-forkers and non-forkers
	gspec := &Genesis{
		BaseFee: big.NewInt(params.InitialBaseFee),
		Config:  &chainConfig,
	}
	genDb, prefix, _ := GenerateChainWithGenesis(gspec, ethash.NewFaker(), int(forkBlock.Int64()-1), func(i int, gen *BlockGen) {})

	// Create the concurrent, conflicting two nodes
	proDb := rawdb.NewMemoryDatabase()
	proConf := *params.MainnetChainConfig
	proConf.HomesteadBlock = big.NewInt(0)
	proConf.DAOForkBlock = forkBlock
	proConf.DAOForkSupport = true
	setFutureXinFinForks(&proConf)
	progspec := &Genesis{
		BaseFee: big.NewInt(params.InitialBaseFee),
		Config:  &proConf,
	}
	proBc, err := NewBlockChain(proDb, nil, progspec, ethash.NewFaker(), vm.Config{})
	if err != nil {
		t.Fatalf("failed to create pro-fork blockchain: %v", err)
	}
	defer proBc.Stop()

	conDb := rawdb.NewMemoryDatabase()
	conConf := *params.MainnetChainConfig
	conConf.HomesteadBlock = big.NewInt(0)
	conConf.DAOForkBlock = forkBlock
	conConf.DAOForkSupport = false
	setFutureXinFinForks(&conConf)
	congspec := &Genesis{
		BaseFee: big.NewInt(params.InitialBaseFee),
		Config:  &conConf,
	}
	conBc, err := NewBlockChain(conDb, nil, congspec, ethash.NewFaker(), vm.Config{})
	if err != nil {
		t.Fatalf("failed to create con-fork blockchain: %v", err)
	}
	defer conBc.Stop()

	if _, err := proBc.InsertChain(prefix); err != nil {
		t.Fatalf("pro-fork: failed to import chain prefix: %v", err)
	}
	if _, err := conBc.InsertChain(prefix); err != nil {
		t.Fatalf("con-fork: failed to import chain prefix: %v", err)
	}
	// Try to expand both pro-fork and non-fork chains iteratively with other camp's blocks
	for i := int64(0); i < params.DAOForkExtraRange.Int64(); i++ {
		// Create a pro-fork block, and try to feed into the no-fork chain
		bc, err := NewBlockChain(rawdb.NewMemoryDatabase(), nil, congspec, ethash.NewFaker(), vm.Config{})
		if err != nil {
			t.Fatalf("failed to create contra-fork expansion chain: %v", err)
		}

		blocks := conBc.GetBlocksFromHash(conBc.CurrentBlock().Hash(), int(conBc.CurrentBlock().Number.Uint64()))
		for j := 0; j < len(blocks)/2; j++ {
			blocks[j], blocks[len(blocks)-1-j] = blocks[len(blocks)-1-j], blocks[j]
		}
		if _, err := bc.InsertChain(blocks); err != nil {
			t.Fatalf("failed to import contra-fork chain for expansion: %v", err)
		}
		if err := bc.stateCache.TrieDB().Commit(bc.CurrentHeader().Root, false); err != nil {
			t.Fatalf("failed to commit contra-fork head for expansion: %v", err)
		}
		bc.Stop()
		blocks, _ = GenerateChain(&proConf, conBc.GetBlockByHash(conBc.CurrentBlock().Hash()), ethash.NewFaker(), genDb, 1, func(i int, gen *BlockGen) {})
		if _, err := conBc.InsertChain(blocks); err == nil {
			t.Fatalf("contra-fork chain accepted pro-fork block: %v", blocks[0])
		}
		// Create a proper no-fork block for the contra-forker
		blocks, _ = GenerateChain(&conConf, conBc.GetBlockByHash(conBc.CurrentBlock().Hash()), ethash.NewFaker(), genDb, 1, func(i int, gen *BlockGen) {})
		if _, err := conBc.InsertChain(blocks); err != nil {
			t.Fatalf("contra-fork chain didn't accepted no-fork block: %v", err)
		}
		// Create a no-fork block, and try to feed into the pro-fork chain
		bc, err = NewBlockChain(rawdb.NewMemoryDatabase(), nil, progspec, ethash.NewFaker(), vm.Config{})
		if err != nil {
			t.Fatalf("failed to create pro-fork expansion chain: %v", err)
		}

		blocks = proBc.GetBlocksFromHash(proBc.CurrentBlock().Hash(), int(proBc.CurrentBlock().Number.Uint64()))
		for j := 0; j < len(blocks)/2; j++ {
			blocks[j], blocks[len(blocks)-1-j] = blocks[len(blocks)-1-j], blocks[j]
		}
		if _, err := bc.InsertChain(blocks); err != nil {
			t.Fatalf("failed to import pro-fork chain for expansion: %v", err)
		}
		if err := bc.stateCache.TrieDB().Commit(bc.CurrentHeader().Root, false); err != nil {
			t.Fatalf("failed to commit pro-fork head for expansion: %v", err)
		}
		bc.Stop()
		blocks, _ = GenerateChain(&conConf, proBc.GetBlockByHash(proBc.CurrentBlock().Hash()), ethash.NewFaker(), genDb, 1, func(i int, gen *BlockGen) {})
		if _, err := proBc.InsertChain(blocks); err == nil {
			t.Fatalf("pro-fork chain accepted contra-fork block: %v", blocks[0])
		}
		// Create a proper pro-fork block for the pro-forker
		blocks, _ = GenerateChain(&proConf, proBc.GetBlockByHash(proBc.CurrentBlock().Hash()), ethash.NewFaker(), genDb, 1, func(i int, gen *BlockGen) {})
		if _, err := proBc.InsertChain(blocks); err != nil {
			t.Fatalf("pro-fork chain didn't accepted pro-fork block: %v", err)
		}
	}
	// Verify that contra-forkers accept pro-fork extra-datas after forking finishes
	bc, _ := NewBlockChain(rawdb.NewMemoryDatabase(), nil, congspec, ethash.NewFaker(), vm.Config{})
	defer bc.Stop()

	blocks := conBc.GetBlocksFromHash(conBc.CurrentBlock().Hash(), int(conBc.CurrentBlock().Number.Uint64()))
	for j := 0; j < len(blocks)/2; j++ {
		blocks[j], blocks[len(blocks)-1-j] = blocks[len(blocks)-1-j], blocks[j]
	}
	if _, err := bc.InsertChain(blocks); err != nil {
		t.Fatalf("failed to import contra-fork chain for expansion: %v", err)
	}
	if err := bc.stateCache.TrieDB().Commit(bc.CurrentHeader().Root, false); err != nil {
		t.Fatalf("failed to commit contra-fork head for expansion: %v", err)
	}
	blocks, _ = GenerateChain(&proConf, conBc.GetBlockByHash(conBc.CurrentBlock().Hash()), ethash.NewFaker(), genDb, 1, func(i int, gen *BlockGen) {})
	if _, err := conBc.InsertChain(blocks); err != nil {
		t.Fatalf("contra-fork chain didn't accept pro-fork block post-fork: %v", err)
	}
	// Verify that pro-forkers accept contra-fork extra-datas after forking finishes
	bc, _ = NewBlockChain(rawdb.NewMemoryDatabase(), nil, progspec, ethash.NewFaker(), vm.Config{})
	defer bc.Stop()

	blocks = proBc.GetBlocksFromHash(proBc.CurrentBlock().Hash(), int(proBc.CurrentBlock().Number.Uint64()))
	for j := 0; j < len(blocks)/2; j++ {
		blocks[j], blocks[len(blocks)-1-j] = blocks[len(blocks)-1-j], blocks[j]
	}
	if _, err := bc.InsertChain(blocks); err != nil {
		t.Fatalf("failed to import pro-fork chain for expansion: %v", err)
	}
	if err := bc.stateCache.TrieDB().Commit(bc.CurrentHeader().Root, false); err != nil {
		t.Fatalf("failed to commit pro-fork head for expansion: %v", err)
	}
	blocks, _ = GenerateChain(&conConf, proBc.GetBlockByHash(proBc.CurrentBlock().Hash()), ethash.NewFaker(), genDb, 1, func(i int, gen *BlockGen) {})
	if _, err := proBc.InsertChain(blocks); err != nil {
		t.Fatalf("pro-fork chain didn't accept contra-fork block post-fork: %v", err)
	}
}

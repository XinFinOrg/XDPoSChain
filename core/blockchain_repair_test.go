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
	"math/big"
	"strings"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// TestStartupRepairReportsMissingAncestor pins XDC-23/XDC-24: a head block
// whose state is missing, and whose parent body is missing too, used to panic
// at startup instead of reporting the corruption.
func TestStartupRepairReportsMissingAncestor(t *testing.T) {
	var (
		engine  = ethash.NewFaker()
		genesis = &Genesis{BaseFee: big.NewInt(params.InitialBaseFee), Config: params.TestChainConfig}
		db      = rawdb.NewMemoryDatabase()
	)
	chain, err := NewBlockChain(db, nil, genesis, engine, vm.Config{})
	if err != nil {
		t.Fatalf("failed to create chain: %v", err)
	}
	_, blocks, _ := GenerateChainWithGenesis(genesis, engine, 3, nil)
	if _, err := chain.InsertChain(blocks); err != nil {
		chain.Stop()
		t.Fatalf("failed to insert blocks: %v", err)
	}
	// Persist the state, then drop the head's state root and the parent body:
	// startup finds the head block but cannot open its state, and the rewind
	// runs out of ancestors before it finds one.
	if err := chain.triedb.Commit(blocks[2].Root(), false); err != nil {
		chain.Stop()
		t.Fatalf("failed to commit state: %v", err)
	}
	chain.Stop()
	rawdb.DeleteLegacyTrieNode(db, blocks[2].Root())
	rawdb.DeleteBody(db, blocks[1].Hash(), blocks[1].NumberU64())

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("startup repair panicked instead of returning an error: %v", r)
		}
	}()
	if _, err := NewBlockChain(db, nil, genesis, engine, vm.Config{}); err == nil {
		t.Fatal("startup repair did not report the missing ancestor")
	} else if !strings.Contains(err.Error(), "missing ancestor block") {
		t.Fatalf("startup repair error = %v, want it to name the missing ancestor", err)
	}
	if head := rawdb.ReadHeadBlockHash(db); head != blocks[2].Hash() {
		t.Fatalf("startup repair rewrote the head marker: have %s want %s", head.Hex(), blocks[2].Hash().Hex())
	}
}

// TestRepairReportsMissingGenesisState pins the 0 boundary: rewinding past
// block 0 used to wrap NumberU64()-1 around and panic on a GetBlock miss.
func TestRepairReportsMissingGenesisState(t *testing.T) {
	var (
		engine  = ethash.NewFaker()
		genesis = &Genesis{BaseFee: big.NewInt(params.InitialBaseFee), Config: params.TestChainConfig}
		db      = rawdb.NewMemoryDatabase()
	)
	chain, err := NewBlockChain(db, nil, genesis, engine, vm.Config{})
	if err != nil {
		t.Fatalf("failed to create chain: %v", err)
	}
	defer chain.Stop()

	head := types.NewBlockWithHeader(&types.Header{
		Number:     new(big.Int),
		Difficulty: new(big.Int),
		GasLimit:   1,
		Time:       1,
		Root:       common.HexToHash("0xdead"),
	})
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("repair panicked on the genesis boundary: %v", r)
		}
	}()
	if err := chain.repair(&head); err == nil {
		t.Fatal("repair did not report the missing genesis state")
	} else if !strings.Contains(err.Error(), "genesis state missing") {
		t.Fatalf("repair error = %v, want it to name the missing genesis state", err)
	}
}

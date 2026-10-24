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

package eth

import (
	"context"
	"errors"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/eth/ethconfig"
	"github.com/XinFinOrg/XDPoSChain/ethdb/memorydb"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/XinFinOrg/XDPoSChain/rpc"
)

func TestSetupHistoryMode(t *testing.T) {
	db := rawdb.NewMemoryDatabase()

	// A fresh datadir in full mode stays full, without recording anything.
	if err := setupHistoryMode(db, &ethconfig.Config{}); err != nil {
		t.Fatalf("full mode on a fresh datadir: %v", err)
	}
	if has, _ := db.Has([]byte("HistoryMode")); has {
		t.Fatal("full mode recorded on a fresh datadir")
	}
	// Minimal mode contradicts an archive node.
	if err := setupHistoryMode(db, &ethconfig.Config{HistoryMode: rawdb.HistoryModeMinimal, NoPruning: true}); !errors.Is(err, errHistoryModeArchive) {
		t.Fatalf("minimal archive node: got %v, want %v", err, errHistoryModeArchive)
	}
	if mode := rawdb.ReadHistoryMode(db); mode != rawdb.HistoryModeFull {
		t.Fatalf("refused configuration changed the stored mode to %v", mode)
	}
	if err := setupHistoryMode(db, &ethconfig.Config{HistoryMode: rawdb.HistoryMode(9)}); err == nil {
		t.Fatal("invalid history mode accepted")
	}
	// Switching to minimal mode is allowed and recorded.
	if err := setupHistoryMode(db, &ethconfig.Config{HistoryMode: rawdb.HistoryModeMinimal}); err != nil {
		t.Fatalf("switching to minimal mode: %v", err)
	}
	if mode := rawdb.ReadHistoryMode(db); mode != rawdb.HistoryModeMinimal {
		t.Fatalf("stored mode: got %v, want minimal", mode)
	}
	// Restarting in minimal mode is fine.
	if err := setupHistoryMode(db, &ethconfig.Config{HistoryMode: rawdb.HistoryModeMinimal}); err != nil {
		t.Fatalf("restarting in minimal mode: %v", err)
	}
}

// TestHistoryModeDowngradeRefused checks that a minimal datadir, whose history
// is pruned, cannot be started in full mode.
func TestHistoryModeDowngradeRefused(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	rawdb.WriteHistoryMode(db, rawdb.HistoryModeMinimal)

	if err := setupHistoryMode(db, &ethconfig.Config{}); !errors.Is(err, errHistoryModeDowngrade) {
		t.Fatalf("got %v, want %v", err, errHistoryModeDowngrade)
	}
	if mode := rawdb.ReadHistoryMode(db); mode != rawdb.HistoryModeMinimal {
		t.Fatalf("refused downgrade changed the stored mode to %v", mode)
	}
}

// TestAPIBackendPrunedHistory checks that the API backend reports block data
// pruned by minimal history mode as rawdb.ErrPrunedHistory, keeps serving what
// was retained, and that the chain refuses to rewind below the pruned tail.
func TestAPIBackendPrunedHistory(t *testing.T) {
	defer func(v uint64) { params.FullImmutabilityThreshold = v }(params.FullImmutabilityThreshold)
	params.FullImmutabilityThreshold = 3

	engine := ethash.NewFaker()
	_, blocks, _ := core.GenerateChainWithGenesis(gspec, engine, 10, nil)

	db, err := rawdb.Open(memorydb.New(), rawdb.OpenOptions{Ancient: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	chain, err := core.NewBlockChain(db, nil, gspec, engine, vm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := chain.InsertChain(blocks); err != nil {
		t.Fatal(err)
	}
	if err := db.(interface{ Freeze() error }).Freeze(); err != nil {
		t.Fatal(err)
	}
	chain.Stop()
	if frozen, _ := db.Ancients(); frozen != 8 {
		t.Fatalf("frozen: got %d, want 8", frozen)
	}
	const tail = 5
	if _, err := db.TruncateTail(rawdb.ChainFreezerBlockDataGroup, tail); err != nil {
		t.Fatal(err)
	}
	// Reopen the chain, so that no cache still holds the pruned blocks.
	chain, err = core.NewBlockChain(db, nil, gspec, engine, vm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer chain.Stop()
	backend := &EthAPIBackend{eth: &Ethereum{blockchain: chain, chainDb: db}}
	ctx := context.Background()

	pruned := blocks[2] // block 3
	checks := map[string]func() (any, error){
		"BlockByNumber": func() (any, error) { return backend.BlockByNumber(ctx, rpc.BlockNumber(pruned.NumberU64())) },
		"BlockByHash":   func() (any, error) { return backend.BlockByHash(ctx, pruned.Hash()) },
		"GetBlock":      func() (any, error) { return backend.GetBlock(ctx, pruned.Hash()) },
		"BlockByNumberOrHash": func() (any, error) {
			return backend.BlockByNumberOrHash(ctx, rpc.BlockNumberOrHashWithHash(pruned.Hash(), false))
		},
		"GetBody": func() (any, error) {
			return backend.GetBody(ctx, pruned.Hash(), rpc.BlockNumber(pruned.NumberU64()))
		},
		"GetReceipts": func() (any, error) { return backend.GetReceipts(ctx, pruned.Hash()) },
		"GetLogs":     func() (any, error) { return backend.GetLogs(ctx, pruned.Hash(), pruned.NumberU64()) },
	}
	for name, check := range checks {
		if _, err := check(); !errors.Is(err, rawdb.ErrPrunedHistory) {
			t.Errorf("%s on a pruned block: got err %v, want %v", name, err, rawdb.ErrPrunedHistory)
		}
	}
	// The header chain is complete, and retained blocks are served as before.
	if header, err := backend.HeaderByNumber(ctx, rpc.BlockNumber(pruned.NumberU64())); err != nil || header == nil || header.Hash() != pruned.Hash() {
		t.Fatalf("header of a pruned block: got %v, %v", header, err)
	}
	for _, kept := range []uint64{tail, 7, 10} {
		block, err := backend.BlockByNumber(ctx, rpc.BlockNumber(kept))
		if err != nil || block == nil || block.Hash() != blocks[kept-1].Hash() {
			t.Fatalf("retained block %d: got %v, %v", kept, block, err)
		}
	}
	// A block that does not exist is still reported as missing, not pruned.
	if block, err := backend.BlockByNumber(ctx, 100); block != nil || err != nil {
		t.Fatalf("unknown block: got %v, %v", block, err)
	}
	// Rewinding below the tail would need the pruned bodies.
	if err := chain.SetHead(tail - 3); err == nil {
		t.Fatal("rewind below the pruned tail accepted")
	}
	if head := chain.CurrentBlock().Number.Uint64(); head != 10 {
		t.Fatalf("refused rewind moved the head to %d", head)
	}
}

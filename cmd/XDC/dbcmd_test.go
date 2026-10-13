// Copyright 2025 The XDPoSChain Authors
// This file is part of XDPoSChain.
//
// XDPoSChain is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// XDPoSChain is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with XDPoSChain. If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/rlp"
)

// freezeGenesis moves the genesis block of an initialised datadir into the
// ancient store, so the db commands have frozen data to report.
func freezeGenesis(t *testing.T, datadir, ancient string) {
	t.Helper()

	kv, err := rawdb.NewLevelDBDatabase(filepath.Join(datadir, "XDC", "chaindata"), 0, 0, "", false)
	if err != nil {
		t.Fatalf("failed to open key-value store: %v", err)
	}
	db, err := rawdb.NewDatabaseWithFreezer(kv, ancient, "", false)
	if err != nil {
		kv.Close()
		t.Fatalf("failed to open freezer: %v", err)
	}
	defer db.Close()

	hash := rawdb.ReadCanonicalHash(db, 0)
	genesis := rawdb.ReadBlock(db, hash, 0)
	if genesis == nil {
		t.Fatal("genesis block missing after init")
	}
	receipts, err := rlp.EncodeToBytes([]*types.ReceiptForStorage{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rawdb.WriteAncientBlocks(db, []*types.Block{genesis}, []rlp.RawValue{receipts}); err != nil {
		t.Fatalf("failed to freeze genesis: %v", err)
	}
}

// TestDBCommandsWithAncient runs init, db inspect, db freezer-index and
// removedb against a datadir whose ancient store lives outside chaindata.
func TestDBCommandsWithAncient(t *testing.T) {
	datadir := t.TempDir()
	ancient := filepath.Join(t.TempDir(), "ancient")
	json := filepath.Join(datadir, "genesis.json")
	if err := os.WriteFile(json, []byte(startupTestGenesis(daoFutureForkConfig)), 0600); err != nil {
		t.Fatalf("failed to write genesis file: %v", err)
	}

	// init must open the database with the freezer at the requested location.
	assertCommandSucceeds(t, runXDC(t, "init", "--datadir", datadir, "--datadir.ancient", ancient, json))
	chainFreezer := filepath.Join(ancient, rawdb.ChainFreezerName)
	if !common.FileExist(chainFreezer) {
		t.Fatalf("init did not create the chain freezer at %s", chainFreezer)
	}
	freezeGenesis(t, datadir, ancient)

	inspect := runXDC(t, "db", "inspect", "--datadir", datadir, "--datadir.ancient", ancient)
	inspect.ExpectRegexp(`Ancient store \(chain\) \| Headers .*\| 1 \(#0-#0\)`)
	assertCommandSucceeds(t, inspect)

	index := runXDC(t, "db", "freezer-index", "--datadir", datadir, "--datadir.ancient", ancient, "chain", "headers", "0", "1")
	assertCommandSucceeds(t, index)

	bad := runXDC(t, "db", "freezer-index", "--datadir", datadir, "--datadir.ancient", ancient, "chain", "nosuchtable", "0", "1")
	assertCommandFailsWithChainConfigError(t, bad, "unknown table")

	// The ancient chain and the key-value store are removed independently.
	chaindata := filepath.Join(datadir, "XDC", "chaindata", "CURRENT")
	assertCommandSucceeds(t, runXDC(t, "removedb", "--datadir", datadir, "--datadir.ancient", ancient,
		"--remove.state=false", "--remove.chain=true"))
	if !common.FileExist(chaindata) {
		t.Fatal("removedb deleted the key-value store although --remove.state=false")
	}
	if entries, _ := os.ReadDir(chainFreezer); hasFiles(entries) {
		t.Fatal("removedb kept ancient chain files although --remove.chain=true")
	}
	assertCommandSucceeds(t, runXDC(t, "removedb", "--datadir", datadir, "--datadir.ancient", ancient,
		"--remove.state=true", "--remove.chain=false"))
	if common.FileExist(chaindata) {
		t.Fatal("removedb kept the key-value store although --remove.state=true")
	}
}

func hasFiles(entries []os.DirEntry) bool {
	for _, entry := range entries {
		if !entry.IsDir() {
			return true
		}
	}
	return false
}

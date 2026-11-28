// Copyright 2019 The go-ethereum Authors
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

package eth

import (
	"math/big"
	"testing"
	"time"

	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/forkid"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/p2p/enode"
	"github.com/XinFinOrg/XDPoSChain/p2p/enr"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// TestENREntry checks the discovery record the wire layer advertises for the
// capability: its key and the fork id it carries.
func TestENREntry(t *testing.T) {
	backend := newTestBackend(t, 1, nil)

	entry := currentENREntry(backend.chain)
	if key := entry.ENRKey(); key != "eth" {
		t.Fatalf("ENR key mismatch: have %q, want %q", key, "eth")
	}
	head := backend.chain.CurrentHeader()
	want := forkid.NewID(backend.chain.Config(), backend.chain.Genesis(), head.Number.Uint64())
	if entry.ForkID != want {
		t.Fatalf("fork id mismatch: have %v, want %v", entry.ForkID, want)
	}
	// The entry must survive an ENR record round trip unchanged.
	record := new(enr.Record)
	record.Set(entry)

	var decoded enrEntry
	if err := record.Load(&decoded); err != nil {
		t.Fatalf("failed to load the eth entry back: %v", err)
	}
	if decoded.ForkID != entry.ForkID {
		t.Fatalf("fork id mismatch after round trip: have %v, want %v", decoded.ForkID, entry.ForkID)
	}
}

// TestENRUpdater checks that the updater the node layer starts keeps the local
// node's eth entry current as the chain head moves, and stops with the chain.
func TestENRUpdater(t *testing.T) {
	var (
		engine = ethash.NewFaker()
		db     = rawdb.NewMemoryDatabase()
		gspec  = &core.Genesis{
			Alloc:  types.GenesisAlloc{testBank: {Balance: new(big.Int).SetUint64(10000000000000000000)}},
			Config: params.TestChainConfig,
		}
		genesis       = gspec.MustCommit(db)
		blockchain, _ = core.NewBlockChain(db, nil, gspec, engine, vm.Config{})
	)
	t.Cleanup(func() { blockchain.Stop() })

	blocks, _ := core.GenerateChain(gspec.Config, genesis, engine, db, 2, nil)
	if _, err := blockchain.InsertChain(blocks[:1]); err != nil {
		t.Fatalf("failed to insert the first block: %v", err)
	}
	nodeDB, err := enode.OpenDB("")
	if err != nil {
		t.Fatalf("failed to open the node database: %v", err)
	}
	t.Cleanup(nodeDB.Close)

	ln := enode.NewLocalNode(nodeDB, testBankKey)
	StartENRUpdater(blockchain, ln)

	// Move the head: the updater must pick the new fork id up from the event.
	if _, err := blockchain.InsertChain(blocks[1:2]); err != nil {
		t.Fatalf("failed to insert the second block: %v", err)
	}
	head := blockchain.CurrentHeader()
	want := forkid.NewID(blockchain.Config(), blockchain.Genesis(), head.Number.Uint64())

	deadline := time.Now().Add(2 * time.Second)
	for {
		var entry enrEntry
		if err := ln.Node().Record().Load(&entry); err == nil && entry.ForkID == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("local node eth entry was not updated to fork id %v within 2 seconds", want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

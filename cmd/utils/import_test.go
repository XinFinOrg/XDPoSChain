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

package utils

import (
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// TestImportChainReportsInterruption covers the file importer: a chain that is stopping, or an
// import that was cut short, says nothing about the blocks in the file, so the failure has to
// be reported as an interruption instead of blaming the file with "invalid block N".
func TestImportChainReportsInterruption(t *testing.T) {
	key, _ := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	gspec := &core.Genesis{
		Alloc:   core.GenesisAlloc{crypto.PubkeyToAddress(key.PublicKey): {Balance: big.NewInt(1000000000000000)}},
		BaseFee: big.NewInt(params.InitialBaseFee),
		Config:  params.TestChainConfig,
	}
	// Export a few blocks out of a chain that has them.
	db := rawdb.NewMemoryDatabase()
	gspec.MustCommit(db)
	source, err := core.NewBlockChain(db, nil, gspec, ethash.NewFaker(), vm.Config{})
	if err != nil {
		t.Fatalf("failed to create the source chain: %v", err)
	}
	defer source.Stop()

	head := source.CurrentBlock()
	parent := source.GetBlock(head.Hash(), head.Number.Uint64())
	if parent == nil {
		t.Fatalf("failed to load the head block #%d", head.Number.Uint64())
	}
	blocks, _ := core.GenerateChain(gspec.Config, parent, ethash.NewFaker(), db, 3, nil)
	if _, err := source.InsertChain(blocks); err != nil {
		t.Fatalf("failed to import the blocks into the source chain: %v", err)
	}
	file := filepath.Join(t.TempDir(), "chain.rlp")
	f, err := os.Create(file)
	if err != nil {
		t.Fatalf("failed to create the export file: %v", err)
	}
	if err := source.Export(f); err != nil {
		t.Fatalf("failed to export the chain: %v", err)
	}
	f.Close()

	// Import the file into a fresh chain that is told to stop before it starts.
	db2 := rawdb.NewMemoryDatabase()
	gspec.MustCommit(db2)
	target, err := core.NewBlockChain(db2, nil, gspec, ethash.NewFaker(), vm.Config{})
	if err != nil {
		t.Fatalf("failed to create the target chain: %v", err)
	}
	defer target.Stop()
	target.InterruptInsert(true)
	defer target.InterruptInsert(false)

	// The reason has to survive: an import that was cut short is not the same as one whose
	// blocks are already on disk, and collapsing both into "interrupted" leaves the operator
	// no way to tell whether rerunning the same file can help.
	err = ImportChain(target, file)
	if err == nil || !strings.HasPrefix(err.Error(), "interrupted during import: ") {
		t.Fatalf("unexpected error: have %v want the interruption and its reason", err)
	}
	if !strings.Contains(err.Error(), core.ErrInsertionInterrupted.Error()) {
		t.Fatalf("the interruption must keep its cause: have %v want %q", err, core.ErrInsertionInterrupted.Error())
	}
}

// TestImportChainReasonsComeFromTheClassifier pins the reasons this importer prints against the
// classification core owns. The importer deliberately keeps no list of its own: a local sentinel
// that is not registered there falls through to the "invalid block" branch and reports a condition
// of this node as a bad file, which is what this test exists to catch.
//
// ErrLocalInsertRefused is pinned here rather than end to end: reaching it takes a reorg the chain
// refuses, which the XDPoS committed-block guard raises, and the chains of this package are ethash.
func TestImportChainReasonsComeFromTheClassifier(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{
		{core.ErrLocalInsertRefused, "cannot be imported"},
		{core.ErrLocalInsertCondition, "cannot be imported"},
		{core.ErrKnownBlock, "already imported"},
		{consensus.ErrPrunedAncestor, "ancestor state is pruned"},
		{core.ErrInsertionInterrupted, "interrupted during import"},
		{core.ErrChainStopped, "interrupted during import"},
	} {
		reason, ok := core.DescribeLocalInsertFailure(tc.err)
		if !ok {
			t.Fatalf("%v is a local condition: the importer would report it as an invalid block", tc.err)
		}
		if reason != tc.want {
			t.Fatalf("unexpected reason for %v: have %q want %q", tc.err, reason, tc.want)
		}
	}
	// A wrapped cause keeps its reason.
	if reason, ok := core.DescribeLocalInsertFailure(fmt.Errorf("batch 1: %w", core.ErrKnownBlock)); !ok || reason != "already imported" {
		t.Fatalf("a wrapped sentinel must keep its reason: have %q ok=%v", reason, ok)
	}
	// Anything that is not local stays the file's own failure.
	if _, ok := core.DescribeLocalInsertFailure(errors.New("boom")); ok {
		t.Fatal("an unclassified failure is the file's, not this node's")
	}
}

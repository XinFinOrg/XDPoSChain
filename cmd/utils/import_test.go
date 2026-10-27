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

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// TestImportChainReportsInterruption covers the file importer: a chain that is stopping, or an import
// that was cut short, says nothing about the blocks in the file, so the failure is reported as an
// interruption instead of blaming the file with "invalid block N".
func TestImportChainReportsInterruption(t *testing.T) {
	gspec := newTestGenesis()
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

	// The reason has to survive: an import that was cut short is not the same as one whose blocks are
	// already on disk, and collapsing both into "interrupted" leaves the operator no way to tell
	// whether rerunning the same file can help.
	err = ImportChain(target, file)
	if err == nil || !strings.HasPrefix(err.Error(), "interrupted during import: ") {
		t.Fatalf("unexpected error: have %v want the interruption and its reason", err)
	}
	if !strings.Contains(err.Error(), core.ErrInsertionInterrupted.Error()) {
		t.Fatalf("the interruption must keep its cause: have %v want %q", err, core.ErrInsertionInterrupted.Error())
	}
}

// TestImportChainReasonsComeFromTheClassifier pins the reasons this importer prints against the
// classification core owns. The importer keeps no list of its own: a local sentinel not registered
// there falls through to the "invalid block" branch and reports a condition of this node as a bad
// file.
//
// ErrLocalInsertRefused is pinned here rather than end to end: reaching it takes an XDPoS committed-
// block guard, and this package's chains are ethash.
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

// newTestGenesis returns the genesis block the importer tests run on.
func newTestGenesis() *core.Genesis {
	key, _ := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	return &core.Genesis{
		Alloc:   types.GenesisAlloc{crypto.PubkeyToAddress(key.PublicKey): {Balance: big.NewInt(1000000000000000)}},
		BaseFee: big.NewInt(params.InitialBaseFee),
		Config:  params.TestChainConfig,
	}
}

// newTargetChain returns a fresh ethash chain sitting on its genesis block.
func newTargetChain(t *testing.T) *core.BlockChain {
	t.Helper()

	gspec := newTestGenesis()
	db := rawdb.NewMemoryDatabase()
	gspec.MustCommit(db)
	chain, err := core.NewBlockChain(db, nil, gspec, ethash.NewFaker(), vm.Config{})
	if err != nil {
		t.Fatalf("failed to create the target chain: %v", err)
	}
	t.Cleanup(chain.Stop)
	return chain
}

// TestImportChainReportsTheFailingBlockPosition pins that a parse error names the position in the
// file: the stream opens with the dropped genesis block, so the block after it is block 1.
func TestImportChainReportsTheFailingBlockPosition(t *testing.T) {
	target := newTargetChain(t)

	// The shape BlockChain.Export writes, cut short behind the genesis block it opens with.
	path := filepath.Join(t.TempDir(), "truncated.rlp")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("failed to create the export file: %v", err)
	}
	if err := target.Genesis().EncodeRLP(f); err != nil {
		t.Fatalf("failed to encode the genesis block: %v", err)
	}
	if _, err := f.Write([]byte{0xff}); err != nil {
		t.Fatalf("failed to cut the export short: %v", err)
	}
	f.Close()

	err = ImportChain(target, path)
	if err == nil {
		t.Fatal("ImportChain(a truncated export) = nil, want an error")
	}
	if want := "at block 1:"; !strings.HasPrefix(err.Error(), want) {
		t.Fatalf("the malformed block must be reported as %q, have %v", want, err)
	}
}

// TestImportChainReportsThePositionAcrossBatches pins the position across the batch boundary: the
// file holds importBatchSize blocks on the genesis block, so the cut lands in the second batch.
func TestImportChainReportsThePositionAcrossBatches(t *testing.T) {
	target := newTargetChain(t)

	// importBatchSize blocks on this chain's genesis: the cut lands in the second batch.
	_, blocks, _ := core.GenerateChainWithGenesis(newTestGenesis(), ethash.NewFaker(), importBatchSize, nil)

	path := filepath.Join(t.TempDir(), "truncated-second-batch.rlp")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("failed to create the export file: %v", err)
	}
	if err := target.Genesis().EncodeRLP(f); err != nil {
		t.Fatalf("failed to encode the genesis block: %v", err)
	}
	for _, block := range blocks {
		if err := block.EncodeRLP(f); err != nil {
			t.Fatalf("failed to encode block #%d: %v", block.NumberU64(), err)
		}
	}
	if _, err := f.Write([]byte{0xff}); err != nil {
		t.Fatalf("failed to cut the export short: %v", err)
	}
	f.Close()

	err = ImportChain(target, path)
	if err == nil {
		t.Fatal("ImportChain(an export cut short in the second batch) = nil, want an error")
	}
	// Genesis is record 0 and block #N sits at record N, so the malformed record behind
	// importBatchSize blocks is importBatchSize+1.
	if want := fmt.Sprintf("at block %d:", importBatchSize+1); !strings.HasPrefix(err.Error(), want) {
		t.Fatalf("the malformed block must be reported as %q, have %v", want, err)
	}
}

// TestImportChainAcceptsAForeignGenesisOnlyExport pins the other side of the skip: a file holding
// nothing but a foreign genesis block has nothing to run, so the import reports success.
func TestImportChainAcceptsAForeignGenesisOnlyExport(t *testing.T) {
	target := newTargetChain(t)

	foreign := (&core.Genesis{
		BaseFee: big.NewInt(params.InitialBaseFee),
		Config:  params.AllEthashProtocolChanges,
	}).ToBlock()

	path := filepath.Join(t.TempDir(), "foreign.rlp")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("failed to create the export file: %v", err)
	}
	if err := foreign.EncodeRLP(f); err != nil {
		t.Fatalf("failed to encode the foreign genesis block: %v", err)
	}
	f.Close()

	if err := ImportChain(target, path); err != nil {
		t.Fatalf("ImportChain(a foreign genesis-only export) = %v, want nil", err)
	}
}

// TestImportChainReportsTheBlockTheInsertFailedOn pins that an insertion failure names the block
// the insert stopped on, not the end of the batch: a three block batch whose second block carries
// a state root execution cannot produce has to blame block 2.
func TestImportChainReportsTheBlockTheInsertFailedOn(t *testing.T) {
	target := newTargetChain(t)

	// Three blocks, the second one broken and the third re-linked so the batch stays contiguous.
	_, blocks, _ := core.GenerateChainWithGenesis(newTestGenesis(), ethash.NewFaker(), 3, nil)
	broken := *blocks[1].Header()
	broken.Root = common.Hash{0xde, 0xad, 0xbe, 0xef}
	blocks[1] = types.NewBlockWithHeader(&broken).WithBody(*blocks[1].Body())

	next := *blocks[2].Header()
	next.ParentHash = blocks[1].Hash()
	blocks[2] = types.NewBlockWithHeader(&next).WithBody(*blocks[2].Body())

	// The shape BlockChain.Export writes: the genesis block, then the batch.
	path := filepath.Join(t.TempDir(), "bad-middle.rlp")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("failed to create the export file: %v", err)
	}
	if err := target.Genesis().EncodeRLP(f); err != nil {
		t.Fatalf("failed to encode the genesis block: %v", err)
	}
	for _, block := range blocks {
		if err := block.EncodeRLP(f); err != nil {
			t.Fatalf("failed to encode block #%d: %v", block.NumberU64(), err)
		}
	}
	f.Close()

	err = ImportChain(target, path)
	if err == nil {
		t.Fatal("ImportChain(a batch with a bad middle block) = nil, want an error")
	}
	if want := "invalid block 2:"; !strings.HasPrefix(err.Error(), want) {
		t.Fatalf("the failing block must be reported as %q, have %v", want, err)
	}
	// A root mismatch with no database error must not print the nil one through %w.
	if strings.Contains(err.Error(), "%!w") {
		t.Fatalf("the message must not carry a nil formatting verb: have %v", err)
	}
}

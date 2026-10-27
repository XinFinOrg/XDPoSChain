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

package eth

import (
	"bytes"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// newMissingBlocksChain returns a chain whose head is the second of three generated blocks,
// together with the three blocks. The third one is the caller's to store however it likes.
func newMissingBlocksChain(t *testing.T) (*core.BlockChain, types.Blocks) {
	t.Helper()

	key, _ := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	gspec := &core.Genesis{
		Alloc:   types.GenesisAlloc{crypto.PubkeyToAddress(key.PublicKey): {Balance: big.NewInt(1000000000000000)}},
		BaseFee: big.NewInt(params.InitialBaseFee),
		Config:  params.TestChainConfig,
	}
	db := rawdb.NewMemoryDatabase()
	genesis := gspec.MustCommit(db)
	engine := ethash.NewFaker()
	blocks, _ := core.GenerateChain(gspec.Config, genesis, engine, db, 3, nil)

	chain, err := core.NewBlockChain(db, nil, gspec, engine, vm.Config{})
	if err != nil {
		t.Fatalf("failed to create tester chain: %v", err)
	}
	t.Cleanup(chain.Stop)
	if _, err := chain.InsertChain(blocks[:2]); err != nil {
		t.Fatalf("failed to seed the chain: %v", err)
	}
	return chain, blocks
}

// newUnmarkedBatchChain returns a chain sitting on block 1 whose executed markers have been
// removed - the state of a database written before the marker existed, where the block, its
// receipts and its state are on disk but nothing records that this node ran it. It also returns the
// genesis block and block 1: the batch an export of that chain starts with.
func newUnmarkedBatchChain(t *testing.T) (*core.BlockChain, *types.Block, *types.Block) {
	t.Helper()

	key, _ := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	gspec := &core.Genesis{
		Alloc:   types.GenesisAlloc{crypto.PubkeyToAddress(key.PublicKey): {Balance: big.NewInt(1000000000000000)}},
		BaseFee: big.NewInt(params.InitialBaseFee),
		Config:  params.TestChainConfig,
	}
	db := rawdb.NewMemoryDatabase()
	genesis := gspec.MustCommit(db)
	engine := ethash.NewFaker()
	blocks, _ := core.GenerateChain(gspec.Config, genesis, engine, db, 1, nil)

	chain, err := core.NewBlockChain(db, nil, gspec, engine, vm.Config{})
	if err != nil {
		t.Fatalf("failed to create tester chain: %v", err)
	}
	t.Cleanup(chain.Stop)
	if _, err := chain.InsertChain(blocks); err != nil {
		t.Fatalf("failed to seed the chain: %v", err)
	}
	// A database that predates the marker holds none of them: the head block the import has to
	// run again is the one the marker would have vouched for.
	for _, b := range append(types.Blocks{genesis}, blocks...) {
		if err := rawdb.DeleteExecutedMarker(chain.ChainDb(), b.Hash(), b.NumberU64()); err != nil {
			t.Fatalf("block %d: failed to drop the executed marker: %v", b.NumberU64(), err)
		}
	}
	if head := chain.CurrentBlock(); head == nil || head.Number.Uint64() != 1 {
		t.Fatalf("the chain must be sitting on block 1, have %v", head)
	}
	return chain, genesis, blocks[0]
}

// foreignGenesis returns a genesis block of another chain: block 0 the importers drop while
// decoding, and the one the precheck still has to answer for once a batch is handed over.
func foreignGenesis() *types.Block {
	return (&core.Genesis{
		BaseFee:   big.NewInt(params.InitialBaseFee),
		Config:    params.AllEthashProtocolChanges,
		ExtraData: []byte("another chain"),
	}).ToBlock()
}

// TestMissingBlocksAsksForAnExecutedBlock pins the check AdminAPI.ImportChain makes before it skips a
// batch. The precheck used to answer on the body alone, so a block this node had only written as a
// side entry - stored by writeBlockWithoutState, without the receipts and the state its execution
// leaves behind - was reported as already imported and the whole batch was skipped.
//
// The precondition is what makes the assertion say something: the block is on disk, so an empty
// answer can only come from this node not having executed it. Answering on the body is what the
// check did before, and what this test keeps it from going back to.
func TestMissingBlocksAsksForAnExecutedBlock(t *testing.T) {
	chain, blocks := newMissingBlocksChain(t)
	side := blocks[2]

	// Store the block the way writeBlockWithoutState does: the body is on disk and neither
	// the receipts nor the state of its execution are.
	rawdb.WriteBlock(chain.ChainDb(), side)

	if !chain.HasBlock(side.Hash(), side.NumberU64()) {
		t.Fatalf("precondition: block #%d must be on disk", side.NumberU64())
	}
	if chain.HasExecutedBlock(side.Hash(), side.NumberU64()) {
		t.Fatalf("precondition: block #%d must not have been executed by this node", side.NumberU64())
	}
	if missing := missingBlocks(chain, types.Blocks{side}); len(missing) == 0 {
		t.Fatalf("missingBlocks(%d) must return the block: it is a side entry this node never executed", side.NumberU64())
	}
}

// TestMissingBlocksAcceptsAnImportedBatch is the other side of the same check: once this node
// has run the block itself, the batch it belongs to is one the import can skip.
func TestMissingBlocksAcceptsAnImportedBatch(t *testing.T) {
	chain, blocks := newMissingBlocksChain(t)
	batch := blocks[2:]

	if _, err := chain.InsertChain(batch); err != nil {
		t.Fatalf("failed to import block #%d: %v", batch[0].NumberU64(), err)
	}
	if !chain.HasExecutedBlock(batch[0].Hash(), batch[0].NumberU64()) {
		t.Fatalf("precondition: block #%d must have been executed by this node", batch[0].NumberU64())
	}
	if missing := missingBlocks(chain, batch); len(missing) != 0 {
		t.Fatalf("missingBlocks(%d) = %v, want nothing: the block was executed by this node", batch[0].NumberU64(), missing)
	}
}

// TestMissingBlocksAcceptsTheGenesisAtAGenesisHead pins the line's own answer for a batch that
// carries the genesis block of this node: it counts as imported, answered by its own hash on disk
// with its state rather than by the marker block 0 never grows, and a block 0 of another chain is
// still reported as one this node does not hold.
//
// Both importers keep block 0 out of the batches they decode, so this is the line's contract for a
// batch that still carries one; ValidateBody answers the same block by the same rule, for the batch
// verifiers that can reject it before ValidateBody is reached.
func TestMissingBlocksAcceptsTheGenesisAtAGenesisHead(t *testing.T) {
	key, _ := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	gspec := &core.Genesis{
		Alloc:   types.GenesisAlloc{crypto.PubkeyToAddress(key.PublicKey): {Balance: big.NewInt(1000000000000000)}},
		BaseFee: big.NewInt(params.InitialBaseFee),
		Config:  params.TestChainConfig,
	}
	db := rawdb.NewMemoryDatabase()
	genesis := gspec.MustCommit(db)

	// The plain faker, as in the core test of the same shape: its batch verifier resolves the
	// parent of block 0, so a line that reported the genesis block as still to run would fail
	// this import rather than pass it by some other path.
	chain, err := core.NewBlockChain(db, nil, gspec, ethash.NewFaker(), vm.Config{})
	if err != nil {
		t.Fatalf("failed to create tester chain: %v", err)
	}
	t.Cleanup(chain.Stop)

	if head := chain.CurrentBlock(); head == nil || head.Hash() != genesis.Hash() {
		t.Fatalf("the chain must be sitting on its genesis block, have %v", head)
	}
	if missing := missingBlocks(chain, types.Blocks{genesis}); len(missing) != 0 {
		t.Fatal("missingBlocks(genesis) must be empty: the node holds its own genesis block")
	}
	// A block 0 of another chain is not one this node holds, so it is not skipped either.
	foreign := foreignGenesis()
	if missing := missingBlocks(chain, types.Blocks{foreign}); len(missing) == 0 {
		t.Fatal("missingBlocks(a genesis block of another chain) must not be empty")
	}
}

// TestMissingBlocksStartsAtTheUnmarkedHead pins the shape the importers need on a database that
// predates the marker: the genesis block of the batch is imported - this node holds it - so what is
// left to run is the head block alone, and no prefix of the batch comes back with it.
func TestMissingBlocksStartsAtTheUnmarkedHead(t *testing.T) {
	chain, genesis, block := newUnmarkedBatchChain(t)

	missing := missingBlocks(chain, types.Blocks{genesis, block})
	if len(missing) != 1 || missing[0].Hash() != block.Hash() {
		t.Fatalf("missingBlocks(genesis, block #%d) = %v, want block #%d alone", block.NumberU64(), missing, block.NumberU64())
	}
	// Running that suffix is what the importer does, and it has to leave nothing behind: the head
	// block is executed again, which is what writes the marker this database never had.
	if _, err := chain.InsertChain(missing); err != nil {
		t.Fatalf("InsertChain(missingBlocks(...)) = %v, want nil", err)
	}
	if bb := rawdb.ReadBadBlock(chain.ChainDb(), genesis.Hash()); bb != nil {
		t.Fatalf("the genesis block must not be recorded as a bad block, have %v", bb)
	}
}

// TestTheUnmarkedBatchWholeIsRejectedOnItsGenesis is the other side of the same shape: handing the
// importers' batch to InsertChain from the top is what the suffix keeps out. Its batch verifier -
// the plain faker resolves the parent of block 0 - rejects this node's own genesis block before
// ValidateBody can answer it, and the rejection lands in the bad block database.
func TestTheUnmarkedBatchWholeIsRejectedOnItsGenesis(t *testing.T) {
	chain, genesis, block := newUnmarkedBatchChain(t)

	if _, err := chain.InsertChain(types.Blocks{genesis, block}); !errors.Is(err, consensus.ErrUnknownAncestor) {
		t.Fatalf("InsertChain(genesis, block #%d) = %v, want %v", block.NumberU64(), err, consensus.ErrUnknownAncestor)
	}
	if bb := rawdb.ReadBadBlock(chain.ChainDb(), genesis.Hash()); bb == nil {
		t.Fatal("the rejected genesis block must be recorded as a bad block")
	}
}

// TestImportChainSkipsTheGenesisOfAnUnmarkedBatch runs the importer over the file an upgraded node
// exports of itself: genesis and head, the head without the marker its execution would have left.
// The file's genesis block must not be handed to InsertChain with the rest, and the head block must
// come out executed rather than blamed.
func TestImportChainSkipsTheGenesisOfAnUnmarkedBatch(t *testing.T) {
	source, _, _ := newUnmarkedBatchChain(t)
	target, genesis, block := newUnmarkedBatchChain(t)

	file := filepath.Join(t.TempDir(), "chain.rlp")
	f, err := os.Create(file)
	if err != nil {
		t.Fatalf("failed to create the export file: %v", err)
	}
	if err := source.Export(f); err != nil {
		t.Fatalf("failed to export the chain: %v", err)
	}
	f.Close()

	// The importer reaches the chain through the API backend, and this is all of it the file
	// importers ask for.
	api := &AdminAPI{eth: &Ethereum{blockchain: target}}
	ok, err := api.ImportChain(file)
	if err != nil || !ok {
		t.Fatalf("ImportChain = %v, %v, want true, nil", ok, err)
	}
	if bb := rawdb.ReadBadBlock(target.ChainDb(), genesis.Hash()); bb != nil {
		t.Fatalf("the import must not blame this node's own genesis block, have %v", bb)
	}
	if head := target.CurrentBlock(); head == nil || head.Hash() != block.Hash() {
		t.Fatalf("the head must still be block #%d, have %v", block.NumberU64(), head)
	}
	// The head block was the one left to run, so the import has to have run it: the marker is what
	// running it leaves behind, and skipping the batch would leave none.
	if !target.HasExecutedBlock(block.Hash(), block.NumberU64()) {
		t.Fatalf("block #%d must have been executed by the import", block.NumberU64())
	}
}

// TestImportChainReportsTheFailingBlockPosition pins the position a malformed block is reported at.
// The stream the importer reads starts with the exporting node's genesis block, which it drops, so
// the block after it is block 1: a parse error has to name it as block 1 rather than as block 0.
func TestImportChainReportsTheFailingBlockPosition(t *testing.T) {
	target, genesis, _ := newUnmarkedBatchChain(t)
	api := &AdminAPI{eth: &Ethereum{blockchain: target}}

	// The shape BlockChain.ExportN writes - one RLP encoded block after another - cut short
	// behind the genesis block this file opens with.
	var file bytes.Buffer
	if err := genesis.EncodeRLP(&file); err != nil {
		t.Fatalf("failed to encode the genesis block: %v", err)
	}
	file.Write([]byte{0xff})
	path := filepath.Join(t.TempDir(), "truncated.rlp")
	if err := os.WriteFile(path, file.Bytes(), 0o600); err != nil {
		t.Fatalf("failed to write the export file: %v", err)
	}

	ok, err := api.ImportChain(path)
	if ok || err == nil {
		t.Fatalf("ImportChain(a truncated export) = %v, %v, want false and an error", ok, err)
	}
	if want := "block 1: failed to parse"; !strings.Contains(err.Error(), want) {
		t.Fatalf("the malformed block must be reported as %q, have %v", want, err)
	}
}

// TestImportChainAcceptsAForeignGenesisOnlyExport is the other side of the skip: a file holding
// nothing but a genesis block of another chain has nothing left for this node to run. Handing that
// block over instead - the shape the skip keeps out - is rejected by the batch verifier that
// resolves the parent of block 0, and the rejection lands in the bad block database.
func TestImportChainAcceptsAForeignGenesisOnlyExport(t *testing.T) {
	target, _, _ := newUnmarkedBatchChain(t)
	api := &AdminAPI{eth: &Ethereum{blockchain: target}}

	foreign := foreignGenesis()

	var file bytes.Buffer
	if err := foreign.EncodeRLP(&file); err != nil {
		t.Fatalf("failed to encode the foreign genesis block: %v", err)
	}
	path := filepath.Join(t.TempDir(), "foreign.rlp")
	if err := os.WriteFile(path, file.Bytes(), 0o600); err != nil {
		t.Fatalf("failed to write the export file: %v", err)
	}

	if ok, err := api.ImportChain(path); !ok || err != nil {
		t.Fatalf("ImportChain(a foreign genesis-only export) = %v, %v, want true, nil", ok, err)
	}
	if bb := rawdb.ReadBadBlock(target.ChainDb(), foreign.Hash()); bb != nil {
		t.Fatalf("a block 0 the importer drops must not be recorded as a bad block, have %v", bb)
	}
}

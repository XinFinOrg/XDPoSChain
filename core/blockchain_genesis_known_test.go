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
	"errors"
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// TestGenesisIsAnsweredAsKnownWithoutAMarker pins the one block the executed marker never applies
// to. The genesis block is not executed: core/genesis.go writes its state and its block without a
// marker, and SetupGenesisBlock does not rewrite the genesis of a database that already holds one,
// so HasExecutedBlock answers no for block 0 on every node.
//
// Answered by the marker, block 0 would fall through to the parent lookup below the classification,
// which asks for number 0-1 and reports consensus.ErrUnknownAncestor, and the import records that as
// a bad block: importing a chain this node exported itself would fail on block 0, the header it was
// started from. Block 0 is answered by its own hash, on disk together with its state, instead; a
// block 0 of another chain still reaches ErrUnknownAncestor.
//
// The chain below runs on the full faker rather than the faker the other fixtures use. The XDPoS
// engines answer nil for block 0 ("the genesis block is the always valid dead-end"), so on a node
// running one of them this classification decides an import whose first block is the genesis, while
// the plain faker's own batch verifier answers ErrUnknownAncestor for block 0 before it, where the
// fix could not be told apart from it.
func TestGenesisIsAnsweredAsKnownWithoutAMarker(t *testing.T) {
	chain, _ := newInsertChainTester(t, ethash.NewFullFaker(), 1, 0)

	genesis := chain.GetBlock(chain.genesisBlock.Hash(), 0)
	if genesis == nil {
		t.Fatal("the chain must hold its genesis block")
	}
	requireGenesisOnDiskWithoutMarker(t, chain, genesis)
	if err := chain.validator.ValidateBody(genesis); !errors.Is(err, ErrKnownBlock) {
		t.Fatalf("the genesis block of this node must be answered as known, have %v", err)
	}
	// Re-delivering it is what an import of this node's own export does with its first block.
	if _, err := chain.InsertChain(types.Blocks{genesis}); err != nil {
		t.Fatalf("re-delivering the genesis block must not fail: %v", err)
	}
	if bad := rawdb.ReadAllBadBlocks(chain.ChainDb()); len(bad) != 0 {
		t.Fatalf("the genesis block of this node was recorded as a bad block: %v", bad)
	}
	if head := chain.CurrentBlock(); head.Hash() != genesis.Hash() {
		t.Fatalf("the head must stay on the same block, have #%d %s", head.Number.Uint64(), head.Hash())
	}
	// A block 0 that is not the genesis of this node is not known, and is still reported the
	// way it was before: as a batch that cannot be linked to this chain.
	foreign := foreignGenesis(t, genesis)
	if err := chain.validator.ValidateBody(foreign); !errors.Is(err, consensus.ErrUnknownAncestor) {
		t.Fatalf("a genesis block this node does not hold must not be reported as known, have %v", err)
	}
}

// TestFirstMissingImportedBlockAnswersTheGenesisBlock pins the line the two importers draw with
// the same block the classification above covers. The genesis block is on disk with its state and
// without a marker, so the marker alone reports it as one the import still has to run - and on a
// batch verifier that resolves the parent of block 0 the rejection lands on this node's own
// genesis before ValidateBody can answer it (see TestGenesisIsAnsweredAsKnownWithoutAMarker).
//
// The chain runs on the plain faker on purpose: the answer has to come from the precheck, not from
// a chain whose batch verifier accepts block 0 whatever it is.
func TestFirstMissingImportedBlockAnswersTheGenesisBlock(t *testing.T) {
	chain, _ := newInsertChainTester(t, ethash.NewFaker(), 1, 0)

	genesis := chain.genesisBlock
	if head := chain.CurrentBlock(); head == nil || head.Number.Uint64() != 0 {
		t.Fatalf("the chain must be sitting on its genesis block, have %v", head)
	}
	requireGenesisOnDiskWithoutMarker(t, chain, genesis)
	if first := chain.FirstMissingImportedBlock(types.Blocks{genesis}); first != -1 {
		t.Fatalf("FirstMissingImportedBlock(genesis) = %d, want -1: this node holds the block", first)
	}
	// What answers it is the block's own hash, not its number: a block 0 of another chain is
	// still reported as one this node has not imported.
	foreign := foreignGenesis(t, genesis)
	if first := chain.FirstMissingImportedBlock(types.Blocks{foreign}); first != 0 {
		t.Fatalf("FirstMissingImportedBlock(a genesis block of another chain) = %d, want 0", first)
	}
}

// requireGenesisOnDiskWithoutMarker pins the two preconditions the genesis exception is written
// against: block 0 is on disk with its state, and carries no executed marker.
func requireGenesisOnDiskWithoutMarker(t *testing.T, chain *BlockChain, genesis *types.Block) {
	t.Helper()

	if !chain.HasBlockAndFullState(genesis.Hash(), 0) {
		t.Fatal("the genesis block must be stored with its state, otherwise the shape is not covered")
	}
	if rawdb.HasExecutedMarker(chain.ChainDb(), genesis.Hash(), 0) {
		t.Fatal("the genesis block must carry no marker, it is not executed")
	}
}

// foreignGenesis returns a genesis block that is not the one chain holds: what answers block 0 is
// its own hash, so the block 0 of another chain has to be told apart from the one on disk.
func foreignGenesis(t *testing.T, held *types.Block) *types.Block {
	t.Helper()

	foreign := (&Genesis{
		BaseFee:   big.NewInt(params.InitialBaseFee),
		Config:    params.AllEthashProtocolChanges,
		ExtraData: []byte("another chain"),
	}).ToBlock()
	if foreign.Hash() == held.Hash() {
		t.Fatal("precondition: the two genesis blocks must differ")
	}
	return foreign
}

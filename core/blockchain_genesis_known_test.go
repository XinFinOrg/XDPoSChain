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

// TestGenesisIsAnsweredAsKnownWithoutAMarker pins the one block the executed marker never
// applies to. The genesis block is not executed: core/genesis.go writes its state and its block
// without a marker, and SetupGenesisBlock does not rewrite the genesis of a database that
// already holds one, so a database this node has been running on holds none for block 0 either.
// Asking HasExecutedBlock for it answers no, on every node, for good.
//
// Answered by the marker, block 0 falls through to the parent lookup below the classification,
// which asks for the parent of block 0 - number 0-1 - and reports consensus.ErrUnknownAncestor.
// The import records that failure as a bad block and hands it back to the caller, so importing
// a chain this node exported itself failed on block 0, the header it was started from: Export
// is ExportN(0, head), and the admin importer does not skip block 0 the way cmd/utils does.
//
// Block 0 is answered by the question these paths asked before the marker existed instead: its
// own hash, on disk together with its state. A block 0 of another chain does not pass it - its
// hash is not the one on disk - and still reaches ErrUnknownAncestor.
//
// The chain below runs on the full faker rather than the faker the other fixtures use. The
// XDPoS engines answer nil for block 0 - "the genesis block is the always valid dead-end", see
// verifyCascadingFields of engine_v1 - so on a node running one of them it is this
// classification that decides an import whose first block is the genesis. The faker's own batch
// verifier reports ErrUnknownAncestor for block 0 instead, asking the chain for the parent of
// block 0, which is number 0-1: the same answer this case is about, but reached before the
// classification under test, where the fix could not be told apart from it.
func TestGenesisIsAnsweredAsKnownWithoutAMarker(t *testing.T) {
	chain, _ := newInsertChainTester(t, ethash.NewFullFaker(), 1, 0)

	genesis := chain.GetBlock(chain.genesisBlock.Hash(), 0)
	if genesis == nil {
		t.Fatal("the chain must hold its genesis block")
	}
	// The two preconditions the exception is written against: block 0 is on disk with its
	// state, and carries no marker.
	if !chain.HasBlockAndFullState(genesis.Hash(), 0) {
		t.Fatal("the genesis block must be stored with its state, otherwise the shape is not covered")
	}
	if rawdb.HasExecutedMarker(chain.ChainDb(), genesis.Hash(), 0) {
		t.Fatal("the genesis block must carry no marker, it is not executed")
	}
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
	foreign := (&Genesis{
		BaseFee:   big.NewInt(params.InitialBaseFee),
		Config:    params.AllEthashProtocolChanges,
		ExtraData: []byte("another chain"),
	}).ToBlock()
	if foreign.Hash() == genesis.Hash() {
		t.Fatal("precondition: the two genesis blocks must differ")
	}
	if err := chain.validator.ValidateBody(foreign); !errors.Is(err, consensus.ErrUnknownAncestor) {
		t.Fatalf("a genesis block this node does not hold must not be reported as known, have %v", err)
	}
}

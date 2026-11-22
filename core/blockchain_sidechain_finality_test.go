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

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS"
	"github.com/XinFinOrg/XDPoSChain/core/types"
)

// newFinalityGateChain opens an XDPoS chain with its head at #2 and returns it with a side
// block at #2 that forks off #1. The side block is handed straight to insertSideChain, so it
// only has to link, not to verify.
func newFinalityGateChain(t *testing.T) (*BlockChain, *XDPoS.XDPoS, *types.Block) {
	t.Helper()

	chain, genesis, cfg, engine := newShortEpochXDPoSChain(t)
	t.Cleanup(chain.Stop)

	blocks := makeSealedChain(t, cfg, genesis, engine, 2)
	if n, err := chain.InsertChain(blocks); err != nil {
		t.Fatalf("block %d: failed to insert into chain: %v", n, err)
	}
	side := types.NewBlockWithHeader(&types.Header{
		ParentHash: blocks[0].Hash(),
		Number:     big.NewInt(2),
		Difficulty: big.NewInt(1),
		GasLimit:   blocks[0].GasLimit(),
		Coinbase:   common.Address{9}, // keeps the side block apart from the canonical #2
		Extra:      make([]byte, 32+65),
	})
	return chain, engine, side
}

// TestSideChainBelowCommittedIsNotStored covers the finality gate of insertSideChain: a side
// block at or below the committed block can never become canonical, since reorg refuses to
// cross that block, so it has to be refused before it reaches the disk. The refusal is this
// node's verdict and must not drop the peer.
func TestSideChainBelowCommittedIsNotStored(t *testing.T) {
	chain, engine, side := newFinalityGateChain(t)
	head := chain.CurrentBlock()
	engine.EngineV2.SetHighestCommitBlockFaker(&types.BlockInfo{Number: head.Number, Hash: head.Hash()})

	block, it := sidechainSegmentIterator(t, chain, types.Blocks{side})
	n, _, _, err := chain.insertSideChain(block, it, true)
	if !errors.Is(err, ErrLocalInsertRefused) || !errors.Is(err, errSideChainBelowFinality) {
		t.Fatalf("unexpected error: have %v want %v wrapping %v", err, ErrLocalInsertRefused, errSideChainBelowFinality)
	}
	if want := 0; n != want {
		t.Fatalf("unexpected failing index: have %d want %d", n, want)
	}
	if chain.HasBlock(side.Hash(), side.NumberU64()) {
		t.Fatal("the side block below the committed block was stored")
	}
	if h := chain.CurrentBlock(); h.Hash() != head.Hash() {
		t.Fatalf("unexpected head: have #%d want the unchanged #%d", h.Number.Uint64(), head.Number.Uint64())
	}
}

// TestSideChainWithOffCanonicalCommittedIsStored covers a committed block that is not on the
// canonical chain, which a QC for another fork produces: processQC looks the certified header up
// by hash. reorg does not stop a node from moving to that fork, so the gate must not either, or a
// node left on a minority fork could never follow the fork the network finalised.
func TestSideChainWithOffCanonicalCommittedIsStored(t *testing.T) {
	chain, engine, side := newFinalityGateChain(t)
	head := chain.CurrentBlock()
	// The engine committed the side fork's block at the head height, not the canonical one.
	engine.EngineV2.SetHighestCommitBlockFaker(&types.BlockInfo{Number: side.Number(), Hash: side.Hash()})
	if chain.GetCanonicalHash(side.NumberU64()) == side.Hash() {
		t.Fatal("precondition: the committed block is canonical")
	}

	block, it := sidechainSegmentIterator(t, chain, types.Blocks{side})
	if _, _, _, err := chain.insertSideChain(block, it, true); errors.Is(err, errSideChainBelowFinality) {
		t.Fatalf("the gate refused a side block below an off-canonical committed block: %v", err)
	}
	if !chain.HasBlock(side.Hash(), side.NumberU64()) {
		t.Fatal("the side block was not stored")
	}
	if h := chain.CurrentBlock(); h.Hash() != head.Hash() {
		t.Fatalf("unexpected head: have #%d want the unchanged #%d", h.Number.Uint64(), head.Number.Uint64())
	}
}

// TestSideChainWithoutCommittedIsStored covers the gate staying out of the way while the engine
// knows no committed block: the side block is stored as before, and the head comparison is what
// keeps the head in place.
func TestSideChainWithoutCommittedIsStored(t *testing.T) {
	chain, engine, side := newFinalityGateChain(t)
	head := chain.CurrentBlock()
	if info := engine.EngineV2.GetLatestCommittedBlockInfo(); info != nil {
		t.Fatalf("precondition: the engine already knows committed block #%v", info.Number)
	}

	block, it := sidechainSegmentIterator(t, chain, types.Blocks{side})
	if _, _, _, err := chain.insertSideChain(block, it, true); errors.Is(err, errSideChainBelowFinality) {
		t.Fatalf("the gate refused a side block without a committed block: %v", err)
	}
	if !chain.HasBlock(side.Hash(), side.NumberU64()) {
		t.Fatal("the side block was not stored")
	}
	if h := chain.CurrentBlock(); h.Hash() != head.Hash() {
		t.Fatalf("unexpected head: have #%d want the unchanged #%d", h.Number.Uint64(), head.Number.Uint64())
	}
}

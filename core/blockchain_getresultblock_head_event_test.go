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
	"time"

	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// TestInsertBlockAnnouncesTheHeadItsNestedRebuildMoved covers the head event of the re-import
// getResultBlock runs to make a competing block calculable. That import is a batch of its own:
// the blocks below the one that fails are executed and promoted, so the head can be left
// above the head the call started from even though the call reports an error. insertBlock has
// to post the events of that import whether or not it succeeded, and it can only do so
// because getResultBlock hands them back - a nested insertChain raises them to its own caller
// and to nobody else, so dropping them there leaves the subscribers that follow the head on a
// head the chain has already left.
//
// The shape is the one getResultBlock takes for a competing block whose ancestors are stored
// without their state: ValidateBody answers the pruned ancestor, #4..#11 sit on disk as side
// entries with their total difficulties, and the segment the call rebuilds is exactly those
// blocks. #9 fails execution, so the segment stops after #8 has been promoted.
func TestInsertBlockAnnouncesTheHeadItsNestedRebuildMoved(t *testing.T) {
	failErr := errors.New("state root mismatch after execution")

	engine := ethash.NewFaker()
	gspec := &Genesis{
		Alloc:   types.GenesisAlloc{},
		BaseFee: big.NewInt(params.InitialBaseFee),
		Config:  params.TestChainConfig,
	}
	genDb := rawdb.NewMemoryDatabase()
	if _, err := gspec.Commit(genDb); err != nil {
		t.Fatalf("failed to commit genesis: %v", err)
	}
	// 12 blocks of which the first three are imported: the head sits at #3 while the
	// competing branch #4..#12 is only handed to the chain below.
	blocks, _ := GenerateChain(gspec.Config, gspec.ToBlock(), engine, genDb, 12, nil)
	chain, err := NewBlockChain(rawdb.NewMemoryDatabase(), nil, gspec, engine, vm.Config{})
	if err != nil {
		t.Fatalf("failed to create the chain: %v", err)
	}
	defer chain.Stop()

	if n, err := chain.InsertChain(blocks[:3]); err != nil {
		t.Fatalf("block %d: failed to insert the canonical prefix: %v", n, err)
	}
	// #4..#11 the way writeBlockWithoutState leaves a block: header, body and total
	// difficulty on disk, no state and no canonical mapping. #12 is the competing block and
	// stays out of the database, so that its parent is the last stored one.
	td := chain.GetTd(blocks[2].Hash(), blocks[2].NumberU64())
	if td == nil {
		t.Fatal("precondition: the canonical head has no total difficulty")
	}
	for i := 3; i < len(blocks)-1; i++ {
		td = new(big.Int).Add(td, blocks[i].Difficulty())
		if err := chain.writeBlockWithoutState(blocks[i], td); err != nil {
			t.Fatalf("failed to store block %d without its state: %v", blocks[i].NumberU64(), err)
		}
	}
	chain.validator = &failStateValidator{
		Validator:  chain.validator,
		failNumber: 9,
		failErr:    failErr,
	}
	headCh := make(chan ChainHeadEvent, 8)
	sub := chain.SubscribeChainHeadEvent(headCh)
	defer sub.Unsubscribe()

	if err := chain.InsertBlock(blocks[11]); !errors.Is(err, failErr) {
		t.Fatalf("unexpected error: have %v want %v", err, failErr)
	}
	// The rebuild promoted #4..#8 and stopped on #9: the head moved even though the call
	// that moved it failed.
	if head := chain.CurrentBlock().Number.Uint64(); head != 8 {
		t.Fatalf("unexpected head: have %d want 8", head)
	}
	select {
	case ev := <-headCh:
		if want := blocks[7].Hash(); ev.Block.Hash() != want {
			t.Fatalf("unexpected head event: have #%d %v, want #%d %v",
				ev.Block.NumberU64(), ev.Block.Hash(), blocks[7].NumberU64(), want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no head event was posted for the head the nested rebuild moved")
	}
}

// TestPrepareBlockAnnouncesTheHeadItsNestedRebuildMoved covers the same nested rebuild as the
// test above, reached through the other caller of getResultBlock: the fetcher prepares a
// propagated block before its validator signature is appended, and the rebuild of that block's
// stored ancestors can promote them to the head even though the preparation fails. The events
// of that rebuild are raised by an insertChain of its own and reach its caller only, so the
// preparation has to post them - the same contract the insertion side keeps, for the same
// subscribers that follow the head.
func TestPrepareBlockAnnouncesTheHeadItsNestedRebuildMoved(t *testing.T) {
	failErr := errors.New("state root mismatch after execution")

	engine := ethash.NewFaker()
	gspec := &Genesis{
		Alloc:   types.GenesisAlloc{},
		BaseFee: big.NewInt(params.InitialBaseFee),
		Config:  params.TestChainConfig,
	}
	genDb := rawdb.NewMemoryDatabase()
	if _, err := gspec.Commit(genDb); err != nil {
		t.Fatalf("failed to commit genesis: %v", err)
	}
	// 12 blocks of which the first three are imported: the head sits at #3 while the
	// competing branch #4..#12 is only handed to the chain below.
	blocks, _ := GenerateChain(gspec.Config, gspec.ToBlock(), engine, genDb, 12, nil)
	chain, err := NewBlockChain(rawdb.NewMemoryDatabase(), nil, gspec, engine, vm.Config{})
	if err != nil {
		t.Fatalf("failed to create the chain: %v", err)
	}
	defer chain.Stop()

	if n, err := chain.InsertChain(blocks[:3]); err != nil {
		t.Fatalf("block %d: failed to insert the canonical prefix: %v", n, err)
	}
	// #4..#11 the way writeBlockWithoutState leaves a block: header, body and total
	// difficulty on disk, no state and no canonical mapping. #12 is the competing block and
	// stays out of the database, so that its parent is the last stored one.
	td := chain.GetTd(blocks[2].Hash(), blocks[2].NumberU64())
	if td == nil {
		t.Fatal("precondition: the canonical head has no total difficulty")
	}
	for i := 3; i < len(blocks)-1; i++ {
		td = new(big.Int).Add(td, blocks[i].Difficulty())
		if err := chain.writeBlockWithoutState(blocks[i], td); err != nil {
			t.Fatalf("failed to store block %d without its state: %v", blocks[i].NumberU64(), err)
		}
	}
	chain.validator = &failStateValidator{
		Validator:  chain.validator,
		failNumber: 9,
		failErr:    failErr,
	}
	headCh := make(chan ChainHeadEvent, 8)
	sub := chain.SubscribeChainHeadEvent(headCh)
	defer sub.Unsubscribe()

	// The preparation takes the same rebuild the insertion does and reports the failure of
	// its segment; the head has still moved to the last block it promoted.
	if err := chain.PrepareBlock(blocks[11]); !errors.Is(err, failErr) {
		t.Fatalf("unexpected error: have %v want %v", err, failErr)
	}
	if head := chain.CurrentBlock().Number.Uint64(); head != 8 {
		t.Fatalf("unexpected head: have %d want 8", head)
	}
	select {
	case ev := <-headCh:
		if want := blocks[7].Hash(); ev.Block.Hash() != want {
			t.Fatalf("unexpected head event: have #%d %v, want #%d %v",
				ev.Block.NumberU64(), ev.Block.Hash(), blocks[7].NumberU64(), want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no head event was posted for the head the nested rebuild moved")
	}
}

// TestInsertBlockAnnouncesTheHeadItsNestedRebuildMovedPastTheRebuild covers the same nested
// rebuild as the tests above, carried past its own success: the segment completes here - every
// stored ancestor is executed and the head ends on the last of them - and the block the call is
// about fails state validation afterwards. getResultBlock has four such exits past the rebuild
// (the parent state, the trading and lending states, the execution, the validation), and each of
// them has to hand the events of the segment back to its caller for the same reason the failing
// segment does: the head has already moved. The validation exit is the one a test can drive
// without an injection point into the state database, the executor or the validator.
func TestInsertBlockAnnouncesTheHeadItsNestedRebuildMovedPastTheRebuild(t *testing.T) {
	failErr := errors.New("state root mismatch after execution")

	engine := ethash.NewFaker()
	gspec := &Genesis{
		Alloc:   types.GenesisAlloc{},
		BaseFee: big.NewInt(params.InitialBaseFee),
		Config:  params.TestChainConfig,
	}
	genDb := rawdb.NewMemoryDatabase()
	if _, err := gspec.Commit(genDb); err != nil {
		t.Fatalf("failed to commit genesis: %v", err)
	}
	// 12 blocks of which the first three are imported: the head sits at #3 while the
	// competing branch #4..#12 is only handed to the chain below.
	blocks, _ := GenerateChain(gspec.Config, gspec.ToBlock(), engine, genDb, 12, nil)
	chain, err := NewBlockChain(rawdb.NewMemoryDatabase(), nil, gspec, engine, vm.Config{})
	if err != nil {
		t.Fatalf("failed to create the chain: %v", err)
	}
	defer chain.Stop()

	if n, err := chain.InsertChain(blocks[:3]); err != nil {
		t.Fatalf("block %d: failed to insert the canonical prefix: %v", n, err)
	}
	// #4..#11 the way writeBlockWithoutState leaves a block: header, body and total
	// difficulty on disk, no state and no canonical mapping. #12 is the competing block and
	// stays out of the database, so that its parent is the last stored one.
	td := chain.GetTd(blocks[2].Hash(), blocks[2].NumberU64())
	if td == nil {
		t.Fatal("precondition: the canonical head has no total difficulty")
	}
	for i := 3; i < len(blocks)-1; i++ {
		td = new(big.Int).Add(td, blocks[i].Difficulty())
		if err := chain.writeBlockWithoutState(blocks[i], td); err != nil {
			t.Fatalf("failed to store block %d without its state: %v", blocks[i].NumberU64(), err)
		}
	}
	// The competing block is the one that fails, so none of the rebuilt ancestors does: the
	// segment is promoted in full and the head is on #11 when the call reports its error.
	chain.validator = &failStateValidator{
		Validator:  chain.validator,
		failNumber: 12,
		failErr:    failErr,
	}
	headCh := make(chan ChainHeadEvent, 8)
	sub := chain.SubscribeChainHeadEvent(headCh)
	defer sub.Unsubscribe()

	if err := chain.InsertBlock(blocks[11]); !errors.Is(err, failErr) {
		t.Fatalf("unexpected error: have %v want %v", err, failErr)
	}
	// The rebuild moved the head to the last block it promoted and the call failed after
	// that: subscribers still have to hear about the head, not only about the error.
	if head := chain.CurrentBlock().Number.Uint64(); head != 11 {
		t.Fatalf("unexpected head: have %d want 11", head)
	}
	select {
	case ev := <-headCh:
		if want := blocks[10].Hash(); ev.Block.Hash() != want {
			t.Fatalf("unexpected head event: have #%d %v, want #%d %v",
				ev.Block.NumberU64(), ev.Block.Hash(), blocks[10].NumberU64(), want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no head event was posted for the head the nested rebuild moved")
	}
}

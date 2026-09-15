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
	"testing"

	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/types"
)

// TestInsertChainReportsBadBlockBehindKnownPrefix pins that a batch stopped by an invalid
// block directly behind a prefix this node already has is recorded like every other stop on
// an invalid block: the failure is reported, it blames the block rather than this node, and
// the invalid block lands in the bad-block database instead of only in a log line.
func TestInsertChainReportsBadBlockBehindKnownPrefix(t *testing.T) {
	chain, blocks := newInsertChainTester(t, nil, 5, 3) // #1..#3 are imported, the head is #3
	invalid := errors.New("transaction root hash mismatch")
	chain.validator = &failBodyValidator{Validator: chain.validator, failNumber: 4, failErr: invalid}

	n, err := chain.InsertChain(blocks[2:]) // #3 is known, #4 fails body validation
	if !errors.Is(err, invalid) {
		t.Fatalf("block %d: have %v want %v", n, err, invalid)
	}
	// n is the index of blocks[3] (#4) within the batch handed in, not its number.
	if want := 1; n != want {
		t.Fatalf("unexpected failing index: have %d want %d", n, want)
	}
	if IsLocalInsertError(err) {
		t.Fatalf("an invalid block is a consensus failure, not a local condition: %v", err)
	}
	if rawdb.ReadBadBlock(chain.ChainDb(), blocks[3].Hash()) == nil {
		t.Fatal("the invalid block behind a known prefix was not recorded as a bad block")
	}
	if want := uint64(3); chain.CurrentBlock().Number.Uint64() != want {
		t.Fatalf("unexpected head number: have %d want %d", chain.CurrentBlock().Number.Uint64(), want)
	}
}

// TestInsertChainReportsMidBatchFailure guards against reporting a partially
// imported batch as a success, which lets the downloader advance past blocks the
// node never imported.
func TestInsertChainReportsMidBatchFailure(t *testing.T) {
	failErr := errors.New("simulated mid-batch verification failure")
	engine := &failVerifyEngine{Engine: ethash.NewFaker(), failNumber: 3, failErr: failErr}
	chain, blocks := newInsertChainTester(t, engine, 5, 0)

	n, err := chain.InsertChain(blocks)
	if err == nil {
		t.Fatal("InsertChain reported success for a partially imported batch")
	}
	if !errors.Is(err, failErr) {
		t.Fatalf("unexpected error: have %v want %v", err, failErr)
	}
	if want := uint64(2); chain.CurrentBlock().Number.Uint64() != want {
		t.Fatalf("unexpected head number: have %d want %d", chain.CurrentBlock().Number.Uint64(), want)
	}
	if want := 2; n != want {
		t.Fatalf("unexpected failing index: have %d want %d", n, want)
	}
	for i := 2; i < len(blocks); i++ {
		if block := chain.GetBlockByNumber(blocks[i].NumberU64()); block != nil {
			t.Fatalf("block #%d was written although the batch reported failure", blocks[i].NumberU64())
		}
	}
}

// TestInsertChainReportsMidBatchBodyFailure is the body-validation counterpart of
// TestInsertChainReportsMidBatchFailure. Body validation errors are the other trigger
// class named by the fix (the loop stops on them too), and they run on the import
// goroutine, so this exercises the abort at the following loop head instead of through
// the header verifier results channel.
func TestInsertChainReportsMidBatchBodyFailure(t *testing.T) {
	// A body that disagrees with its header is the invalidity this test is named after.
	// ErrPrunedAncestor would be a local state-availability signal instead, and pinning it
	// here would also pin the wrong reading that the peer is to blame for it.
	failErr := errors.New("transaction root hash mismatch")
	chain, blocks := newInsertChainTester(t, nil, 5, 0)
	chain.validator = &failBodyValidator{
		Validator:  chain.validator,
		failNumber: 3,
		failErr:    failErr,
	}

	n, err := chain.InsertChain(blocks)
	if err == nil {
		t.Fatal("InsertChain reported success for a batch whose body validation failed mid-batch")
	}
	if !errors.Is(err, failErr) {
		t.Fatalf("unexpected error: have %v want %v", err, failErr)
	}
	if want := 2; n != want {
		t.Fatalf("unexpected failing index: have %d want %d", n, want)
	}
	if want := uint64(2); chain.CurrentBlock().Number.Uint64() != want {
		t.Fatalf("unexpected head number: have %d want %d", chain.CurrentBlock().Number.Uint64(), want)
	}
	for i := 2; i < len(blocks); i++ {
		if block := chain.GetBlockByNumber(blocks[i].NumberU64()); block != nil {
			t.Fatalf("block #%d was written although body validation failed mid-batch", blocks[i].NumberU64())
		}
	}
}

// TestInsertChainSucceedsForFullBatch is the counterpart of the mid-batch failure
// guard: a batch that verifies end to end must still report success.
func TestInsertChainSucceedsForFullBatch(t *testing.T) {
	chain, blocks := newInsertChainTester(t, nil, 5, 0)

	if n, err := chain.InsertChain(blocks); err != nil {
		t.Fatalf("block %d: failed to insert into chain: %v", n, err)
	}
	if want := uint64(5); chain.CurrentBlock().Number.Uint64() != want {
		t.Fatalf("unexpected head number: have %d want %d", chain.CurrentBlock().Number.Uint64(), want)
	}
}

// interruptInsertEngine interrupts chain insertion while the body of the block at
// interruptAt is validated. Body validation runs on the import goroutine itself,
// so the interruption is visible deterministically at the loop head of that block,
// without racing against the header verifier of the embedded engine.
type interruptInsertEngine struct {
	consensus.Engine
	chain       *BlockChain
	interruptAt uint64
}

func (e *interruptInsertEngine) VerifyUncles(chain consensus.ChainReader, block *types.Block) error {
	if block.NumberU64() == e.interruptAt {
		e.chain.InterruptInsert(true)
	}
	return e.Engine.VerifyUncles(chain, block)
}

// TestInsertChainReportsInterruptedInsertion guards the documented contract of
// BlockChain.InterruptInsert ("causing them to return ErrInsertionInterrupted as
// soon as possible"): a batch that was cut short must not be reported as a success.
func TestInsertChainReportsInterruptedInsertion(t *testing.T) {
	engine := &interruptInsertEngine{Engine: ethash.NewFaker(), interruptAt: 2}
	chain, blocks := newInsertChainTester(t, engine, 5, 0)
	engine.chain = chain

	n, err := chain.InsertChain(blocks)
	if err == nil {
		t.Fatal("InsertChain reported success although the insertion was interrupted")
	}
	if !errors.Is(err, ErrInsertionInterrupted) {
		t.Fatalf("unexpected error: have %v want %v", err, ErrInsertionInterrupted)
	}
	if want := 1; n != want {
		t.Fatalf("unexpected failing index: have %d want %d", n, want)
	}
	if want := uint64(1); chain.CurrentBlock().Number.Uint64() != want {
		t.Fatalf("unexpected head number: have %d want %d", chain.CurrentBlock().Number.Uint64(), want)
	}
	for i := 1; i < len(blocks); i++ {
		if block := chain.GetBlockByNumber(blocks[i].NumberU64()); block != nil {
			t.Fatalf("block #%d was written although the insertion was interrupted", blocks[i].NumberU64())
		}
	}
}

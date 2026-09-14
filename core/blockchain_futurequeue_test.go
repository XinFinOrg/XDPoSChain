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
)

// TestInsertChainQueuesFutureTailOfBatch covers a batch whose middle block is in the
// future: the whole tail is parked in the future queue and the import reports success,
// because procFutureBlocks imports the parked blocks once their timestamps are reached.
func TestInsertChainQueuesFutureTailOfBatch(t *testing.T) {
	engine := &failFromEngine{Engine: ethash.NewFaker(), fromNumber: 3, failErr: consensus.ErrFutureBlock}
	chain, blocks := newInsertChainTester(t, engine, 5, 0)

	headCh := make(chan ChainHeadEvent, 8)
	sub := chain.SubscribeChainHeadEvent(headCh)
	defer sub.Unsubscribe()

	n, err := chain.InsertChain(blocks)
	if err != nil {
		t.Fatalf("block %d: a future tail must not fail the batch: %v", n, err)
	}
	if want := uint64(2); chain.CurrentBlock().Number.Uint64() != want {
		t.Fatalf("unexpected head number: have %d want %d", chain.CurrentBlock().Number.Uint64(), want)
	}
	for i := 2; i < len(blocks); i++ {
		if !chain.futureBlocks.Contains(blocks[i].Hash()) {
			t.Fatalf("block #%d was not parked in the future queue", blocks[i].NumberU64())
		}
	}
	// The progress made before the future block is still announced.
	select {
	case ev := <-headCh:
		if ev.Block.NumberU64() != 2 {
			t.Fatalf("unexpected head event for #%d, want #2", ev.Block.NumberU64())
		}
	default:
		t.Fatal("no head event for the imported prefix")
	}
}

// TestInsertChainQueuesFutureBatch is the first-block counterpart: a batch that starts
// with a future block is parked whole instead of stopping at its second block.
func TestInsertChainQueuesFutureBatch(t *testing.T) {
	engine := &failFromEngine{Engine: ethash.NewFaker(), fromNumber: 1, failErr: consensus.ErrFutureBlock}
	chain, blocks := newInsertChainTester(t, engine, 5, 0)

	n, err := chain.InsertChain(blocks)
	if err != nil {
		t.Fatalf("block %d: a batch of future blocks must not fail: %v", n, err)
	}
	if want := len(blocks); n != want {
		t.Fatalf("unexpected failing index: have %d want %d", n, want)
	}
	if want := uint64(0); chain.CurrentBlock().Number.Uint64() != want {
		t.Fatalf("unexpected head number: have %d want %d", chain.CurrentBlock().Number.Uint64(), want)
	}
	for _, block := range blocks {
		if !chain.futureBlocks.Contains(block.Hash()) {
			t.Fatalf("block #%d was not parked in the future queue", block.NumberU64())
		}
	}
}

// TestInsertChainFailsOnInvalidBlockBehindFutureTail pins that queueing a future tail
// does not swallow a verification error behind it: the parked prefix stays queued, the
// invalid block is not parked, and the failure keeps blaming the peer.
func TestInsertChainFailsOnInvalidBlockBehindFutureTail(t *testing.T) {
	engine := &failVerifyEngine{Engine: ethash.NewFaker(), failNumber: 3, failErr: consensus.ErrFutureBlock}
	chain, blocks := newInsertChainTester(t, engine, 5, 0)
	invalid := errors.New("transaction root hash mismatch")
	chain.validator = &failBodyValidator{Validator: chain.validator, failNumber: 4, failErr: invalid}

	n, err := chain.InsertChain(blocks)
	if !errors.Is(err, invalid) {
		t.Fatalf("block %d: an invalid block behind a future tail must fail: have %v want %v", n, err, invalid)
	}
	if !chain.futureBlocks.Contains(blocks[2].Hash()) {
		t.Fatal("the future block ahead of the invalid one must stay parked")
	}
	if chain.futureBlocks.Contains(blocks[3].Hash()) {
		t.Fatal("the block that stopped the queueing must not be parked")
	}
	if IsLocalInsertError(err) {
		t.Fatalf("an invalid block is a consensus failure, not a local condition: %v", err)
	}
	if want := uint64(2); chain.CurrentBlock().Number.Uint64() != want {
		t.Fatalf("unexpected head number: have %d want %d", chain.CurrentBlock().Number.Uint64(), want)
	}
}

// TestInsertChainReportsUnknownAncestorTail pins the tail contract: an unknown ancestor in
// the middle of a batch is reported rather than swallowed, it stays non-local so the
// downloader may hold the peer to it, and the prefix that did import stays on the chain.
func TestInsertChainReportsUnknownAncestorTail(t *testing.T) {
	engine := &failFromEngine{Engine: ethash.NewFaker(), fromNumber: 3, failErr: consensus.ErrUnknownAncestor}
	chain, blocks := newInsertChainTester(t, engine, 5, 0)

	n, err := chain.InsertChain(blocks)
	if !errors.Is(err, consensus.ErrUnknownAncestor) {
		t.Fatalf("block %d: have %v want %v", n, err, consensus.ErrUnknownAncestor)
	}
	if want := 2; n != want { // n is the 0-based index of blocks[2] (#3), not its number
		t.Fatalf("unexpected failing index: have %d want %d", n, want)
	}
	if want := uint64(2); chain.CurrentBlock().Number.Uint64() != want {
		t.Fatalf("unexpected head number: have %d want %d", chain.CurrentBlock().Number.Uint64(), want)
	}
	if chain.futureBlocks.Contains(blocks[2].Hash()) {
		t.Fatal("a block that failed with an unknown ancestor must not be parked")
	}
	if IsLocalInsertError(err) {
		t.Fatal("an unknown ancestor is not a local condition, the peer can be held to it")
	}
}

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

	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/types"
)

// failStateValidator fails state validation for a single block number, so a batch can be made
// to fail inside processBlock - after the blocks below it were imported and the head moved -
// while the header verifier and body validation of the embedded validator still accept every
// block.
type failStateValidator struct {
	Validator
	failNumber uint64
	failErr    error
}

func (v *failStateValidator) ValidateState(block *types.Block, statedb *state.StateDB, receipts types.Receipts, usedGas uint64) error {
	if block.NumberU64() == v.failNumber {
		return v.failErr
	}
	return v.Validator.ValidateState(block, statedb, receipts, usedGas)
}

// TestInsertChainAnnouncesThePrefixOfAFailedBatch covers the head event of a batch that fails
// after it has already moved the head. A block that fails execution is the reachable shape of
// that: the blocks below it are imported and become canonical, so their ChainEvents are posted
// with this call, and the failing block returns from inside the import loop instead of from
// the tail. Raising the head event at the tail only left subscribers following the head - the
// tx pool and the miner - on a head the chain had already left, while the prefix had been
// announced as canonical. go-ethereum #19396 (fc7e0fe6c7) fires the event from a defer for the
// same reason; this fork queues it into the events the caller posts.
//
// TestInsertChainReportsMidBatchFailure does not cover this: it fails the batch in the header
// verifier, so the loop ends on its own condition and reaches the tail.
func TestInsertChainAnnouncesThePrefixOfAFailedBatch(t *testing.T) {
	failErr := errors.New("state root mismatch after execution")
	chain, blocks := newInsertChainTester(t, nil, 5, 0)
	chain.validator = &failStateValidator{
		Validator:  chain.validator,
		failNumber: 4,
		failErr:    failErr,
	}

	headCh := make(chan ChainHeadEvent, 8)
	sub := chain.SubscribeChainHeadEvent(headCh)
	defer sub.Unsubscribe()

	n, err := chain.InsertChain(blocks)
	if err == nil {
		t.Fatal("InsertChain reported success for a batch that failed execution mid-batch")
	}
	if !errors.Is(err, failErr) {
		t.Fatalf("unexpected error: have %v want %v", err, failErr)
	}
	if want := 3; n != want {
		t.Fatalf("unexpected failing index: have %d want %d", n, want)
	}
	if want := uint64(3); chain.CurrentBlock().Number.Uint64() != want {
		t.Fatalf("unexpected head number: have %d want %d", chain.CurrentBlock().Number.Uint64(), want)
	}
	// #3 moved the head before the batch failed on #4, so #3 is the block subscribers have to
	// learn about.
	select {
	case ev := <-headCh:
		if ev.Block.NumberU64() != 3 {
			t.Fatalf("head event is for #%d, want the highest block that made it in, #3", ev.Block.NumberU64())
		}
	default:
		t.Fatal("no head event for the prefix that became canonical")
	}
	// One batch raises one head event, the failing one included.
	select {
	case ev := <-headCh:
		t.Fatalf("a second head event was raised for #%d", ev.Block.NumberU64())
	default:
	}
}

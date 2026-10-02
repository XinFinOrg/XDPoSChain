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
	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// numberErrEngine fails each header with the error registered for its number, so that a
// batch can be shaped block by block: a future block whose successor the validator calls
// known is the shape the file importers have to carry on from, and it cannot be produced
// with a real engine (it needs the block's timestamp ahead of the local clock while the
// block behind it is already executed).
type numberErrEngine struct {
	consensus.Engine
	errs map[uint64]error
}

func (e *numberErrEngine) VerifyHeaders(chain consensus.ChainReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
	abort := make(chan struct{})
	results := make(chan error, len(headers))
	go func() {
		for _, header := range headers {
			select {
			case <-abort:
				return
			case results <- e.errs[header.Number.Uint64()]:
			}
		}
	}()
	return abort, results
}

// TestInsertChainStopsTheBatchOnAKnownBlock pins the one shape in which a batch runs into a
// block this node already executed: it stops the queueing, the tail that accumulated in
// front of it stays parked for a later retry, and the index handed back is that known
// block's, so a caller that can carry on hands the rest of the batch back in from there -
// lead by the known block, which is adopted or skipped - instead of reporting a batch that
// is being imported as a failure. Reaching the shape takes a block dated ahead of the local
// clock, so the downloader meets it and cancels the content processing, while the file
// importers replay historical blocks and do not.
func TestInsertChainStopsTheBatchOnAKnownBlock(t *testing.T) {
	engine := &numberErrEngine{
		Engine: ethash.NewFaker(),
		errs: map[uint64]error{
			3: consensus.ErrFutureBlock, // ahead of the clock, so it is parked
			4: ErrKnownBlock,            // already executed, so it stops the queueing
		},
	}
	chain, blocks := newInsertChainTester(t, engine, 5, 0)

	n, _ := chain.InsertChain(blocks)
	if want := 3; n != want { // 0-based index of #4
		t.Fatalf("unexpected stopping index: have %d want %d", n, want)
	}
	if !chain.futureBlocks.Contains(blocks[2].Hash()) {
		t.Fatal("the future block before the known one has to stay parked for a later retry")
	}
}

// TestInsertSideChainReportsInvalidBlockInSegment covers the scan of a pruned sidechain
// segment: when it stops on a block whose body does not match its header, that error has
// to be reported instead of being dropped in favour of the result of re-importing the
// prefix - re-importing the prefix succeeded, so returning it reported a partial import
// as a success while nothing after the failing block was even looked at.
func TestInsertSideChainReportsInvalidBlockInSegment(t *testing.T) {
	chain, blocks := newInsertChainTester(t, nil, 7, 2) // head at #2

	// #3 is on disk but without its state, which is what makes #4 the first block of a
	// pruned sidechain segment: its parent is known, but the state to execute it is gone.
	td := new(big.Int).Add(chain.GetTd(blocks[1].Hash(), 2), blocks[2].Difficulty())
	if err := chain.writeBlockWithoutState(blocks[2], td); err != nil {
		t.Fatalf("failed to write the pruned block: %v", err)
	}
	// #6 keeps a valid header, so the scan reaches it, but its body does not match it.
	tx := types.NewTransaction(0, common.Address{}, big.NewInt(1), params.TxGas, big.NewInt(1), nil)
	invalid := types.NewBlockWithHeader(blocks[5].Header()).WithBody(types.Body{Transactions: types.Transactions{tx}})

	n, err := chain.InsertChain(types.Blocks{blocks[3], blocks[4], invalid})
	if err == nil {
		t.Fatalf("block %d: sidechain segment holding an invalid block reported as success", n)
	}
	// Re-importing the prefix of the segment must not make it canonical behind the back
	// of the block that stopped the import.
	if want := uint64(2); chain.CurrentBlock().Number.Uint64() != want {
		t.Fatalf("unexpected head number: have %d want %d", chain.CurrentBlock().Number.Uint64(), want)
	}
}

// knownBlockSegmentValidator answers ValidateBody with a canned error per block number
// and leaves the rest to the validator it embeds: scanning a sidechain segment only runs
// body validation, so that is the only method the scan reaches. It lets a test place a
// known block in the middle of a pruned segment without having to prune state.
type knownBlockSegmentValidator struct {
	*BlockValidator
	bodyErrors map[uint64]error
}

func (v *knownBlockSegmentValidator) ValidateBody(block *types.Block) error {
	return v.bodyErrors[block.NumberU64()]
}

// TestInsertSideChainReportsSegmentStoppedByKnownBlock pins the defensive guard of
// insertSideChain: a pruned sidechain segment that stops on a block reported as known
// while nothing of it is stored has no prefix to adopt, so the batch is a local condition
// rather than a consensus failure - the downloader must not blame (or drop) the peer for
// blocks this node only scanned - and the head stays where it was.
//
// The state is built through knownBlockSegmentValidator, which answers ValidateBody by
// block number and so bypasses the BlockValidator contract (ValidateBody reports
// ErrKnownBlock only for a block whose full state is stored). The guard is unreachable on
// a real chain; this test keeps its behaviour pinned should that ever change.
func TestInsertSideChainReportsSegmentStoppedByKnownBlock(t *testing.T) {
	chain, blocks := newInsertChainTester(t, nil, 5, 3) // head at #3, #4 and #5 are unknown

	// #4 is a pruned sidechain block: its parent is known but the state to execute it is
	// gone, so the scan writes #4 out and then stops on #5, which the segment reports as
	// already known although nothing of it is stored.
	batch := blocks[3:5] // #4 and #5
	validator := &knownBlockSegmentValidator{
		BlockValidator: chain.validator.(*BlockValidator),
		bodyErrors:     map[uint64]error{batch[1].NumberU64(): ErrKnownBlock},
	}
	results := make(chan error, len(batch))
	results <- consensus.ErrPrunedAncestor
	for i := 1; i < len(batch); i++ {
		results <- nil
	}
	it := newInsertIterator(batch, results, validator)

	n, _, _, err := chain.insertSideChain(batch[0], it, true)
	if !errors.Is(err, ErrLocalInsertCondition) {
		t.Fatalf("unexpected error: have %v want %v", err, ErrLocalInsertCondition)
	}
	if !IsLocalInsertError(err) {
		t.Fatalf("a segment this node never stored says nothing about the peer: %v", err)
	}
	if want := 1; n != want {
		t.Fatalf("unexpected failing index: have %d want %d", n, want)
	}
	if want := uint64(3); chain.CurrentBlock().Number.Uint64() != want {
		t.Fatalf("unexpected head number: have %d want %d", chain.CurrentBlock().Number.Uint64(), want)
	}
}

// TestInsertSideChainAdoptsSegmentStoppedByKnownBlock is the other half: the same scan
// stops on a known block, but the rest of the segment is on disk too, so the segment was
// imported and only the head did not follow. Adopting it is what keeps the following
// syncs from asking for the same range again.
func TestInsertSideChainAdoptsSegmentStoppedByKnownBlock(t *testing.T) {
	chain, blocks := newInsertChainTester(t, nil, 5, 5)
	rewindHeadMarkers(chain, blocks[1]) // head stops at #2, #3..#5 stay on disk

	batch := blocks[2:5] // #3, #4 and #5, all of them on disk with their state
	validator := &knownBlockSegmentValidator{
		BlockValidator: chain.validator.(*BlockValidator),
		bodyErrors:     map[uint64]error{batch[1].NumberU64(): ErrKnownBlock},
	}
	results := make(chan error, len(batch))
	results <- consensus.ErrPrunedAncestor
	for i := 1; i < len(batch); i++ {
		results <- nil
	}
	it := newInsertIterator(batch, results, validator)

	n, events, _, err := chain.insertSideChain(batch[0], it, true)
	if err != nil {
		t.Fatalf("block %d: segment that is on disk reported as failure: %v", n, err)
	}
	if want := uint64(5); chain.CurrentBlock().Number.Uint64() != want {
		t.Fatalf("unexpected head number: have %d want %d", chain.CurrentBlock().Number.Uint64(), want)
	}
	var head *types.Block
	for _, event := range events {
		if ev, ok := event.(ChainHeadEvent); ok {
			head = ev.Block
		}
	}
	if head == nil || head.Hash() != blocks[4].Hash() {
		t.Fatal("adopting the segment did not announce the new head")
	}
}

// recordingVerifySealsEngine records the verifySeals flags of every VerifyHeaders call, so a
// test can pin at which level a batch was imported. The embedded engine does the actual
// verification.
type recordingVerifySealsEngine struct {
	consensus.Engine
	calls [][]bool
}

func (e *recordingVerifySealsEngine) VerifyHeaders(chain consensus.ChainReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
	e.calls = append(e.calls, append([]bool(nil), seals...))
	return e.Engine.VerifyHeaders(chain, headers, seals)
}

// TestInsertSideChainImportsPastKnownBlock is the half neither of the two tests above
// covers: the scan stops on a stored block while the blocks above it were never imported,
// so the stored prefix is adopted and the rest is imported on top of it. Giving up here
// instead would leave the node asking for the same range on every sync.
//
// The tail is remote data the scan never pulled a verification result for, so it must be
// imported at the level of the batch it came from: XDPoS reads the flag as full verification
// and a batch imported without it skips checks the engine knows how to make.
func TestInsertSideChainImportsPastKnownBlock(t *testing.T) {
	engine := &recordingVerifySealsEngine{Engine: ethash.NewFaker()}
	chain, blocks := newInsertChainTester(t, engine, 7, 6) // head at #6
	rewindHeadMarkers(chain, blocks[2])                    // head stops at #3, #4..#6 stay on disk

	batch := blocks[3:7] // #4..#6 on disk with their state, #7 never imported
	validator := &knownBlockSegmentValidator{
		BlockValidator: chain.validator.(*BlockValidator),
		bodyErrors:     map[uint64]error{batch[1].NumberU64(): ErrKnownBlock},
	}
	results := make(chan error, len(batch))
	results <- consensus.ErrPrunedAncestor
	for i := 1; i < len(batch); i++ {
		results <- nil
	}
	it := newInsertIterator(batch, results, validator)
	// The batch that built the chain was verified too; this case is about the tail.
	engine.calls = nil

	n, events, _, err := chain.insertSideChain(batch[0], it, true)
	if err != nil {
		t.Fatalf("block %d: segment with an unstored tail reported as failure: %v", n, err)
	}
	tip := blocks[len(blocks)-1]
	if want := tip.NumberU64(); chain.CurrentBlock().Number.Uint64() != want {
		t.Fatalf("unexpected head number: have %d want %d", chain.CurrentBlock().Number.Uint64(), want)
	}
	if block := chain.GetBlockByNumber(tip.NumberU64()); block == nil || block.Hash() != tip.Hash() {
		t.Fatal("the block above the adopted one was not imported")
	}
	var head *types.Block
	for _, event := range events {
		if ev, ok := event.(ChainHeadEvent); ok {
			head = ev.Block
		}
	}
	if head == nil || head.Hash() != tip.Hash() {
		t.Fatal("importing past the known block did not announce the new head")
	}
	// Only the tail is imported here: the prefix was on disk already.
	if len(engine.calls) != 1 {
		t.Fatalf("verified %d batch(es), want exactly the unstored tail", len(engine.calls))
	}
	for i, full := range engine.calls[0] {
		if !full {
			t.Fatalf("tail block %d was imported without full verification", i)
		}
	}
}

// TestInsertSideChainAdoptsSegmentAnnouncesTip pins how an adopted sidechain segment
// reaches subscribers: the tip moves the head, so it raises a ChainEvent and the single
// ChainHeadEvent of the adoption, exactly like an adopted known block of the canonical
// import path. The blocks reorg rewrote on the way are announced through its rebirth logs
// instead, so they must not raise a ChainEvent of their own.
func TestInsertSideChainAdoptsSegmentAnnouncesTip(t *testing.T) {
	chain, blocks := newInsertChainTester(t, nil, 5, 5)
	rewindHeadMarkers(chain, blocks[1]) // head stops at #2, #3..#5 stay on disk

	batch := blocks[2:5] // #3, #4 and #5, all of them on disk with their state
	validator := &knownBlockSegmentValidator{
		BlockValidator: chain.validator.(*BlockValidator),
		bodyErrors:     map[uint64]error{batch[1].NumberU64(): ErrKnownBlock},
	}
	results := make(chan error, len(batch))
	results <- consensus.ErrPrunedAncestor
	for i := 1; i < len(batch); i++ {
		results <- nil
	}
	it := newInsertIterator(batch, results, validator)

	tip := blocks[4]
	n, events, logs, err := chain.insertSideChain(batch[0], it, true)
	if err != nil {
		t.Fatalf("block %d: segment that is on disk reported as failure: %v", n, err)
	}
	if want := uint64(5); chain.CurrentBlock().Number.Uint64() != want {
		t.Fatalf("unexpected head number: have %d want %d", chain.CurrentBlock().Number.Uint64(), want)
	}
	var chained, headed int
	for _, event := range events {
		switch ev := event.(type) {
		case ChainEvent:
			chained++
			if ev.Block.Hash() != tip.Hash() {
				t.Fatalf("ChainEvent is for #%d, want only the tip #%d", ev.Block.NumberU64(), tip.NumberU64())
			}
		case ChainHeadEvent:
			headed++
			if ev.Block.Hash() != tip.Hash() {
				t.Fatalf("ChainHeadEvent is for #%d, want the tip #%d", ev.Block.NumberU64(), tip.NumberU64())
			}
		}
	}
	if chained != 1 {
		t.Fatalf("delivered %d ChainEvent(s), want exactly one for the tip", chained)
	}
	if headed != 1 {
		t.Fatalf("delivered %d ChainHeadEvent(s), want exactly one for the tip", headed)
	}
	// The tip was canonical before the head was rewound, so its logs were delivered when
	// it was first imported and must not be sent again.
	if len(logs) != 0 {
		t.Fatalf("a rollback re-import re-delivered %d log(s), want none", len(logs))
	}
}

// TestInsertSideChainAdoptsSegmentAndImportsTheRestAnnouncesOneHead covers the adoption
// shape that still has blocks above it: the scan stops on a block this node already
// executed, insertSideChain adopts it and imports the rest of the batch on top. The batch
// must keep the single-head-event contract - one event, for the highest block that moved
// the head, not one for the adopted block and another for the block above it.
func TestInsertSideChainAdoptsSegmentAndImportsTheRestAnnouncesOneHead(t *testing.T) {
	chain, blocks := newInsertChainTester(t, nil, 6, 5) // head at #5, #6 not imported
	rewindHeadMarkers(chain, blocks[2])                 // head stops at #3, #4 and #5 stay on disk

	batch := blocks[3:6] // #4 and #5 on disk with their state, #6 not imported
	validator := &knownBlockSegmentValidator{
		BlockValidator: chain.validator.(*BlockValidator),
		bodyErrors:     map[uint64]error{batch[1].NumberU64(): ErrKnownBlock},
	}
	results := make(chan error, len(batch))
	results <- consensus.ErrPrunedAncestor
	for i := 1; i < len(batch); i++ {
		results <- nil
	}
	it := newInsertIterator(batch, results, validator)

	tip := blocks[5]
	n, events, _, err := chain.insertSideChain(batch[0], it, true)
	if err != nil {
		t.Fatalf("block %d: segment that is on disk reported as failure: %v", n, err)
	}
	if want := uint64(6); chain.CurrentBlock().Number.Uint64() != want {
		t.Fatalf("unexpected head number: have %d want %d", chain.CurrentBlock().Number.Uint64(), want)
	}
	var headed int
	for _, event := range events {
		switch ev := event.(type) {
		case ChainEvent:
			if ev.Block.NumberU64() < 5 {
				t.Fatalf("ChainEvent is for the adopted block #%d, want the imported blocks", ev.Block.NumberU64())
			}
		case ChainHeadEvent:
			headed++
			if ev.Block.Hash() != tip.Hash() {
				t.Fatalf("ChainHeadEvent is for #%d, want the tip %d", ev.Block.NumberU64(), tip.NumberU64())
			}
		}
	}
	if headed != 1 {
		t.Fatalf("delivered %d ChainHeadEvent(s), want exactly one for the tip", headed)
	}
}

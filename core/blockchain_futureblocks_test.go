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
	"fmt"
	"math/big"
	"sync/atomic"
	"testing"
	"time"

	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/ethdb"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// failRangeEngine fails header verification for every block from failFrom on
// (0 disables the range), and for the single block badNumber with a distinct
// error, so a batch can mix future rejections with a genuine failure. All
// knobs are atomic because the chain's future-block loop calls VerifyHeaders
// concurrently with the test goroutine, so tests may retarget them mid-run.
type failRangeEngine struct {
	consensus.Engine
	failFrom  atomic.Uint64
	failErr   atomic.Pointer[error]
	badNumber atomic.Uint64
	badErr    atomic.Pointer[error]
}

func (e *failRangeEngine) VerifyHeaders(chain consensus.ChainReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
	abort := make(chan struct{})
	results := make(chan error, len(headers))
	go func() {
		for _, header := range headers {
			var err error
			number := header.Number.Uint64()
			if e.badNumber.Load() != 0 && number == e.badNumber.Load() {
				if stored := e.badErr.Load(); stored != nil {
					err = *stored
				}
			} else if e.failFrom.Load() != 0 && number >= e.failFrom.Load() {
				if stored := e.failErr.Load(); stored != nil {
					err = *stored
				}
			}
			select {
			case <-abort:
				return
			case results <- err:
			}
		}
	}()
	return abort, results
}

// newFutureBlockChain builds a chain whose headers verify with ethash but fail
// as consensus.ErrFutureBlock for every block from failFrom on, and returns
// the tester chain, its blocks, the database and the test engine.
func newFutureBlockChain(t *testing.T, failFrom uint64) (*BlockChain, *failRangeEngine, []*types.Block, ethdb.Database) {
	return newFutureBlockChainAt(t, failFrom, 0, nil)
}

// newFutureBlockChainAt is newFutureBlockChain with a custom genesis timestamp
// and per-block generator.
func newFutureBlockChainAt(t *testing.T, failFrom, genesisTime uint64, gen func(int, *BlockGen)) (*BlockChain, *failRangeEngine, []*types.Block, ethdb.Database) {
	t.Helper()

	key, _ := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	gspec := &Genesis{
		Alloc:     types.GenesisAlloc{crypto.PubkeyToAddress(key.PublicKey): {Balance: big.NewInt(1000000000000000)}},
		BaseFee:   big.NewInt(params.InitialBaseFee),
		Timestamp: genesisTime,
		Config:    params.TestChainConfig,
	}
	_, blocks, _ := GenerateChainWithGenesis(gspec, ethash.NewFaker(), 5, gen)

	engine := &failRangeEngine{Engine: ethash.NewFaker()}
	engine.failErr.Store(&consensus.ErrFutureBlock)
	engine.failFrom.Store(failFrom)

	db := rawdb.NewMemoryDatabase()
	chain, err := NewBlockChain(db, nil, gspec, engine, vm.Config{})
	if err != nil {
		t.Fatalf("failed to create tester chain: %v", err)
	}
	t.Cleanup(chain.Stop)
	return chain, engine, blocks, db
}

// TestInsertChainQueuesMidBatchFutureBlocks verifies that a batch rejected as
// future mid-way has its whole tail queued instead of failing the import:
// children of a future block fail the timestamp check before the parent lookup
// so they surface as ErrFutureBlock too, and returning that error would make
// the downloader drop the peer on a valid delivery.
func TestInsertChainQueuesMidBatchFutureBlocks(t *testing.T) {
	chain, _, blocks, db := newFutureBlockChain(t, 3)

	if n, err := chain.InsertChain(blocks); err != nil || n != len(blocks) {
		t.Fatalf("failed to insert into chain: index %d err %v", n, err)
	}
	if want := uint64(2); chain.CurrentBlock().Number.Uint64() != want {
		t.Fatalf("unexpected head number: have %d want %d", chain.CurrentBlock().Number.Uint64(), want)
	}
	for _, block := range blocks[2:] {
		if !chain.futureBlocks.Contains(block.Hash()) {
			t.Fatalf("block %d not queued as future block", block.NumberU64())
		}
		if bad := rawdb.ReadBadBlock(db, block.Hash()); bad != nil {
			t.Fatalf("future block %d recorded as bad block", block.NumberU64())
		}
	}
}

// TestInsertChainQueuesFutureBatchFromFirstBlock verifies that a batch whose
// first block is already in the future is queued in full instead of failing at
// its second block, which made the downloader drop the delivering peer.
func TestInsertChainQueuesFutureBatchFromFirstBlock(t *testing.T) {
	chain, _, blocks, db := newFutureBlockChain(t, 1)

	if n, err := chain.InsertChain(blocks); err != nil || n != len(blocks) {
		t.Fatalf("failed to insert into chain: index %d err %v", n, err)
	}
	if want := uint64(0); chain.CurrentBlock().Number.Uint64() != want {
		t.Fatalf("unexpected head number: have %d want %d", chain.CurrentBlock().Number.Uint64(), want)
	}
	for _, block := range blocks {
		if !chain.futureBlocks.Contains(block.Hash()) {
			t.Fatalf("block %d not queued as future block", block.NumberU64())
		}
		if bad := rawdb.ReadBadBlock(db, block.Hash()); bad != nil {
			t.Fatalf("future block %d recorded as bad block", block.NumberU64())
		}
	}
}

// TestInsertChainProcFutureBlocksResumesImport proves the queued tail is not
// dropped: once headers verify again, the queued blocks import and the head
// advances to the batch tip.
func TestInsertChainProcFutureBlocksResumesImport(t *testing.T) {
	chain, engine, blocks, _ := newFutureBlockChain(t, 3)

	if _, err := chain.InsertChain(blocks); err != nil {
		t.Fatalf("failed to insert into chain: %v", err)
	}
	if want := uint64(2); chain.CurrentBlock().Number.Uint64() != want {
		t.Fatalf("unexpected head number: have %d want %d", chain.CurrentBlock().Number.Uint64(), want)
	}

	// InsertChain uses TryLock, so the explicit call may skip a block the
	// background future-block loop is importing at that moment; both paths
	// converge on the same head, so poll for it.
	engine.failFrom.Store(0)
	chain.procFutureBlocks()

	want := uint64(5)
	deadline := time.Now().Add(2 * time.Second)
	for chain.CurrentBlock().Number.Uint64() != want && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if have := chain.CurrentBlock().Number.Uint64(); have != want {
		t.Fatalf("unexpected head number: have %d want %d", have, want)
	}
}

// subscribeHeadEvents returns a buffered channel receiving the chain's head
// events. PostChainEvents fires inside InsertChain, so the buffered events can
// be consumed after the call returns.
func subscribeHeadEvents(t *testing.T, chain *BlockChain) chan ChainHeadEvent {
	t.Helper()
	heads := make(chan ChainHeadEvent, 8)
	sub := chain.SubscribeChainHeadEvent(heads)
	t.Cleanup(sub.Unsubscribe)
	return heads
}

// TestInsertChainReportsTailFailureAfterFutureBlocks verifies that a genuine
// verification error on a block after the queued future tail still surfaces
// and is recorded as a bad block, instead of the batch being reported as
// successful with its suffix silently skipped. The head advanced over the
// processed prefix, so its ChainHeadEvent must still be broadcast.
func TestInsertChainReportsTailFailureAfterFutureBlocks(t *testing.T) {
	chain, engine, blocks, db := newFutureBlockChain(t, 3)
	heads := subscribeHeadEvents(t, chain)

	badErr := consensus.ErrNoValidatorSignatureV2
	engine.badErr.Store(&badErr)
	engine.badNumber.Store(5)

	if n, err := chain.InsertChain(blocks); !errors.Is(err, badErr) {
		t.Fatalf("tail verification error not surfaced: index %d err %v", n, err)
	} else if n != 4 {
		t.Fatalf("unexpected failing index: have %d want 4", n)
	}
	if want := uint64(2); chain.CurrentBlock().Number.Uint64() != want {
		t.Fatalf("unexpected head number: have %d want %d", chain.CurrentBlock().Number.Uint64(), want)
	}
	for _, block := range blocks[2:4] {
		if !chain.futureBlocks.Contains(block.Hash()) {
			t.Fatalf("block %d not queued as future block", block.NumberU64())
		}
		if bad := rawdb.ReadBadBlock(db, block.Hash()); bad != nil {
			t.Fatalf("future block %d recorded as bad block", block.NumberU64())
		}
	}
	if bad := rawdb.ReadBadBlock(db, blocks[4].Hash()); bad == nil {
		t.Fatalf("invalid block %d not recorded as bad block", blocks[4].NumberU64())
	}
	select {
	case ev := <-heads:
		if ev.Block.Hash() != blocks[1].Hash() {
			t.Fatalf("unexpected head event block: have %d want %d", ev.Block.NumberU64(), blocks[1].NumberU64())
		}
	default:
		t.Fatal("no ChainHeadEvent broadcast for the advanced head")
	}
}

// TestInsertChainReportsMidBatchFailureWithoutFutureBlocks verifies that a
// genuine verification error on a block mid-batch, with no future blocks
// involved, surfaces and is recorded as a bad block. The unified exit must not
// swallow the error that terminated the processing loop, and the head event
// for the processed prefix must still be broadcast.
func TestInsertChainReportsMidBatchFailureWithoutFutureBlocks(t *testing.T) {
	chain, engine, blocks, db := newFutureBlockChain(t, 0)
	heads := subscribeHeadEvents(t, chain)

	badErr := consensus.ErrNoValidatorSignatureV2
	engine.badErr.Store(&badErr)
	engine.badNumber.Store(3)

	if n, err := chain.InsertChain(blocks); !errors.Is(err, badErr) {
		t.Fatalf("mid-batch verification error not surfaced: index %d err %v", n, err)
	} else if n != 2 {
		t.Fatalf("unexpected failing index: have %d want 2", n)
	}
	if want := uint64(2); chain.CurrentBlock().Number.Uint64() != want {
		t.Fatalf("unexpected head number: have %d want %d", chain.CurrentBlock().Number.Uint64(), want)
	}
	for _, block := range blocks[:2] {
		if bad := rawdb.ReadBadBlock(db, block.Hash()); bad != nil {
			t.Fatalf("valid block %d recorded as bad block", block.NumberU64())
		}
	}
	if bad := rawdb.ReadBadBlock(db, blocks[2].Hash()); bad == nil {
		t.Fatalf("invalid block %d not recorded as bad block", blocks[2].NumberU64())
	}
	if have := chain.futureBlocks.Len(); have != 0 {
		t.Fatalf("unexpected future blocks queued: %d", have)
	}
	select {
	case ev := <-heads:
		if ev.Block.Hash() != blocks[1].Hash() {
			t.Fatalf("unexpected head event block: have %d want %d", ev.Block.NumberU64(), blocks[1].NumberU64())
		}
	default:
		t.Fatal("no ChainHeadEvent broadcast for the advanced head")
	}
}

// TestInsertChainReportsFirstPathFailureAfterFuturePrefix verifies that a
// genuine verification error on a block after the queued future prefix (batch
// starting with a future block) is recorded as a bad block and surfaces, just
// like the tail path does.
func TestInsertChainReportsFirstPathFailureAfterFuturePrefix(t *testing.T) {
	chain, engine, blocks, db := newFutureBlockChain(t, 1)

	badErr := consensus.ErrNoValidatorSignatureV2
	engine.badErr.Store(&badErr)
	engine.badNumber.Store(3)

	if n, err := chain.InsertChain(blocks); !errors.Is(err, badErr) {
		t.Fatalf("prefix verification error not surfaced: index %d err %v", n, err)
	} else if n != 2 {
		t.Fatalf("unexpected failing index: have %d want 2", n)
	}
	if want := uint64(0); chain.CurrentBlock().Number.Uint64() != want {
		t.Fatalf("unexpected head number: have %d want %d", chain.CurrentBlock().Number.Uint64(), want)
	}
	for _, block := range blocks[0:2] {
		if !chain.futureBlocks.Contains(block.Hash()) {
			t.Fatalf("block %d not queued as future block", block.NumberU64())
		}
		if bad := rawdb.ReadBadBlock(db, block.Hash()); bad != nil {
			t.Fatalf("future block %d recorded as bad block", block.NumberU64())
		}
	}
	if bad := rawdb.ReadBadBlock(db, blocks[2].Hash()); bad == nil {
		t.Fatalf("invalid block %d not recorded as bad block", blocks[2].NumberU64())
	}
}

// futureWindowChain timestamps its blocks now+1, +11, +21, +91, +101 so that
// queuing stops at the maxTimeFutureBlocks window boundary.
func futureWindowChain(t *testing.T, failFrom uint64) (*BlockChain, *failRangeEngine, []*types.Block, ethdb.Database) {
	t.Helper()

	gen := func(i int, gen *BlockGen) {
		if i == 3 {
			gen.OffsetTime(60)
		}
	}
	return newFutureBlockChainAt(t, failFrom, uint64(time.Now().Unix())-9, gen)
}

// TestInsertChainStopsQueuingBeyondWindowFromFirstBlock verifies that a batch
// whose future tail reaches past the maxTimeFutureBlocks window keeps its
// queued prefix but surfaces the window error, since a block more than 30s
// ahead only comes from a skewed local clock or a misbehaving peer.
func TestInsertChainStopsQueuingBeyondWindowFromFirstBlock(t *testing.T) {
	chain, _, blocks, db := futureWindowChain(t, 1)

	if n, err := chain.InsertChain(blocks); err == nil || n != 3 {
		t.Fatalf("unexpected import result: index %d err %v", n, err)
	}
	if want := uint64(0); chain.CurrentBlock().Number.Uint64() != want {
		t.Fatalf("unexpected head number: have %d want %d", chain.CurrentBlock().Number.Uint64(), want)
	}
	for i, block := range blocks {
		if queued := chain.futureBlocks.Contains(block.Hash()); queued != (i < 3) {
			t.Fatalf("block %d future queue membership: have %t", block.NumberU64(), queued)
		}
		if bad := rawdb.ReadBadBlock(db, block.Hash()); bad != nil {
			t.Fatalf("future block %d recorded as bad block", block.NumberU64())
		}
	}
}

// TestInsertChainStopsQueuingBeyondWindowAfterPrefix verifies the same window
// behaviour for a batch whose future tail starts mid-way: the error surfaces
// without dropping the already broadcast head event for the processed prefix.
func TestInsertChainStopsQueuingBeyondWindowAfterPrefix(t *testing.T) {
	chain, _, blocks, db := futureWindowChain(t, 2)
	heads := subscribeHeadEvents(t, chain)

	if n, err := chain.InsertChain(blocks); err == nil || n != 3 {
		t.Fatalf("unexpected import result: index %d err %v", n, err)
	}
	if want := uint64(1); chain.CurrentBlock().Number.Uint64() != want {
		t.Fatalf("unexpected head number: have %d want %d", chain.CurrentBlock().Number.Uint64(), want)
	}
	for i, block := range blocks {
		if queued := chain.futureBlocks.Contains(block.Hash()); queued != (i >= 1 && i < 3) {
			t.Fatalf("block %d future queue membership: have %t", block.NumberU64(), queued)
		}
		if bad := rawdb.ReadBadBlock(db, block.Hash()); bad != nil {
			t.Fatalf("future block %d recorded as bad block", block.NumberU64())
		}
	}
	select {
	case ev := <-heads:
		if ev.Block.Hash() != blocks[0].Hash() {
			t.Fatalf("unexpected head event block: have %d want %d", ev.Block.NumberU64(), blocks[0].NumberU64())
		}
	default:
		t.Fatal("no ChainHeadEvent broadcast for the advanced head")
	}
}

// TestInsertChainRejectsBatchWhenFirstBlockBeyondWindow covers the degenerate
// window case: when the very first block of the batch lies beyond the
// maxTimeFutureBlocks window, nothing is queued and the error is returned with
// index 0 so the delivering peer cannot pass off an unusable delivery.
func TestInsertChainRejectsBatchWhenFirstBlockBeyondWindow(t *testing.T) {
	gen := func(i int, gen *BlockGen) {
		if i == 0 {
			gen.OffsetTime(60)
		}
	}
	// Genesis at now-9 puts the first block at now+61, past the 30s window.
	chain, _, blocks, db := newFutureBlockChainAt(t, 1, uint64(time.Now().Unix())-9, gen)

	if n, err := chain.InsertChain(blocks); err == nil || n != 0 {
		t.Fatalf("unexpected import result: index %d err %v", n, err)
	}
	if want := uint64(0); chain.CurrentBlock().Number.Uint64() != want {
		t.Fatalf("unexpected head number: have %d want %d", chain.CurrentBlock().Number.Uint64(), want)
	}
	if have := chain.futureBlocks.Len(); have != 0 {
		t.Fatalf("unexpected future blocks queued: %d", have)
	}
	for _, block := range blocks {
		if bad := rawdb.ReadBadBlock(db, block.Hash()); bad != nil {
			t.Fatalf("future block %d recorded as bad block", block.NumberU64())
		}
	}
}

// TestInsertChainDoesNotRecordBadBlockForNonSentinelError verifies that
// verification errors without a consensus-violation sentinel - such as the
// v2 engine's state-dependent QC failures - are returned to the caller but
// kept out of the bad-block table, for both the first-block and the unified
// exit path. An unknown ancestor on the first block, whose parent is not
// queued, gets the same treatment.
func TestInsertChainDoesNotRecordBadBlockForNonSentinelError(t *testing.T) {
	stateErr := fmt.Errorf("fail to verify QC due to failure in getting epoch switch info: header not found")
	tests := map[string]struct {
		badNumber uint64
		badErr    *error
		wantIndex int
	}{
		"first block":      {badNumber: 1, badErr: &stateErr, wantIndex: 0},
		"mid batch":        {badNumber: 3, badErr: &stateErr, wantIndex: 2},
		"unknown ancestor": {badNumber: 1, badErr: &consensus.ErrUnknownAncestor, wantIndex: 0},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			chain, engine, blocks, db := newFutureBlockChain(t, 0)
			heads := subscribeHeadEvents(t, chain)
			engine.badErr.Store(tc.badErr)
			engine.badNumber.Store(tc.badNumber)

			if n, err := chain.InsertChain(blocks); !errors.Is(err, *tc.badErr) || n != tc.wantIndex {
				t.Fatalf("unexpected import result: index %d err %v", n, err)
			}
			if want := uint64(tc.wantIndex); chain.CurrentBlock().Number.Uint64() != want {
				t.Fatalf("unexpected head number: have %d want %d", chain.CurrentBlock().Number.Uint64(), want)
			}
			for _, block := range blocks {
				if bad := rawdb.ReadBadBlock(db, block.Hash()); bad != nil {
					t.Fatalf("block %d recorded as bad block", block.NumberU64())
				}
			}
			if tc.wantIndex > 0 {
				select {
				case ev := <-heads:
					if ev.Block.Hash() != blocks[tc.wantIndex-1].Hash() {
						t.Fatalf("unexpected head event block: have %d want %d", ev.Block.NumberU64(), tc.wantIndex)
					}
				default:
					t.Fatal("no ChainHeadEvent broadcast for the advanced head")
				}
			}
		})
	}
}

// TestInsertChainIgnoresUnknownAncestorTail verifies that ErrUnknownAncestor
// on a tail block is treated as a transient link failure, not an invalid
// block: no bad-block record and a successful import result.
func TestInsertChainIgnoresUnknownAncestorTail(t *testing.T) {
	chain, engine, blocks, db := newFutureBlockChain(t, 4)
	engine.failErr.Store(&consensus.ErrUnknownAncestor)

	if n, err := chain.InsertChain(blocks); err != nil || n != 3 {
		t.Fatalf("unexpected import result: index %d err %v", n, err)
	}
	if want := uint64(3); chain.CurrentBlock().Number.Uint64() != want {
		t.Fatalf("unexpected head number: have %d want %d", chain.CurrentBlock().Number.Uint64(), want)
	}
	if bad := rawdb.ReadBadBlock(db, blocks[3].Hash()); bad != nil {
		t.Fatalf("block %d recorded as bad block", blocks[3].NumberU64())
	}
	if have := chain.futureBlocks.Len(); have != 0 {
		t.Fatalf("unexpected future blocks queued: %d", have)
	}
}

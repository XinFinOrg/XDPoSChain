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
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/XinFinOrg/XDPoSChain/XDCx/tradingstate"
	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// newDownloadingMarkTester builds a chain and a batch of blocks that have not been
// imported yet, which is the state insertChain has to leave the downloading marks in.
func newDownloadingMarkTester(t *testing.T, total int) (*BlockChain, types.Blocks) {
	t.Helper()

	gspec := &Genesis{
		Config:  params.TestChainConfig,
		BaseFee: big.NewInt(params.InitialBaseFee),
	}
	db := rawdb.NewMemoryDatabase()
	gspec.MustCommit(db)

	chain, err := NewBlockChain(db, nil, gspec, ethash.NewFaker(), vm.Config{})
	if err != nil {
		t.Fatalf("failed to create the chain: %v", err)
	}
	t.Cleanup(chain.Stop)

	_, blocks, _ := GenerateChainWithGenesis(gspec, ethash.NewFaker(), total, nil)
	return chain, blocks
}

// assertNotMarkedAsDownloading fails for every block the chain still considers to be
// downloading.
func assertNotMarkedAsDownloading(t *testing.T, chain *BlockChain, blocks types.Blocks) {
	t.Helper()

	for _, block := range blocks {
		if chain.downloadingBlock.Contains(block.Hash()) {
			t.Fatalf("block #%d is still marked as downloading after insertChain returned", block.NumberU64())
		}
	}
}

// TestInsertChainClearsDownloadingBlockMarks pins the lifetime of the marks insertChain
// puts on the blocks it is handed. They keep the fetcher from touching a block the
// downloader is importing, so they cover that call and nothing else: a block that left
// insertChain - imported or not - is no longer being downloaded.
//
// Without the cleanup the mark outlives the call by the whole LRU window, and insertBlock
// answers a later delivery of that block from the mark alone: success, no head movement,
// no error. That is how a block this node already executed can keep a head that sits
// below it from advancing, for as long as the entry survives.
func TestInsertChainClearsDownloadingBlockMarks(t *testing.T) {
	chain, blocks := newDownloadingMarkTester(t, 4)

	if _, err := chain.InsertChain(blocks[:2]); err != nil {
		t.Fatalf("failed to import the batch: %v", err)
	}
	assertNotMarkedAsDownloading(t, chain, blocks[:2])

	// A batch that only partly succeeds must not keep its marks either: the third block
	// goes through processing and is made canonical, the fourth fails inside processing,
	// and by the time insertChain returns the import is over for both of them. The
	// fourth block is broken in the one place only processing looks at - its state root -
	// so that it clears header and body validation and really fails there.
	fourth := *blocks[3].Header()
	fourth.Root = common.HexToHash("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
	bad := types.NewBlockWithHeader(&fourth).WithBody(*blocks[3].Body())

	if _, err := chain.InsertChain(types.Blocks{blocks[2], bad}); err == nil {
		t.Fatal("a block whose state root does not match the executed one must fail the import")
	}
	// The third block was imported before the batch failed, which is what makes this a
	// partial failure rather than a batch that never got anywhere.
	if have := chain.CurrentBlock().Hash(); have != blocks[2].Hash() {
		t.Fatalf("head did not reach the third block: have %x, want %x", have, blocks[2].Hash())
	}
	assertNotMarkedAsDownloading(t, chain, types.Blocks{blocks[2], bad})
}

// pausingProcessor counts how often each block is executed and holds the first execution
// of one target block, which leaves a batch in flight with its marks readable.
type pausingProcessor struct {
	Processor
	target  common.Hash
	entered chan struct{} // closed when the target's first execution starts
	release chan struct{} // closed to let that execution continue

	mu     sync.Mutex
	counts map[common.Hash]int
}

func (p *pausingProcessor) record(block *types.Block) {
	p.mu.Lock()
	p.counts[block.Hash()]++
	calls := p.counts[block.Hash()]
	p.mu.Unlock()

	if block.Hash() == p.target && calls == 1 {
		close(p.entered)
		<-p.release
	}
}

func (p *pausingProcessor) count(hash common.Hash) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.counts[hash]
}

func (p *pausingProcessor) Process(block *types.Block, statedb *state.StateDB, tradingState *tradingstate.TradingStateDB, cfg vm.Config, balanceFee map[common.Address]*big.Int) (types.Receipts, []*types.Log, uint64, error) {
	p.record(block)
	return p.Processor.Process(block, statedb, tradingState, cfg, balanceFee)
}

func (p *pausingProcessor) ProcessBlockNoValidator(block *CalculatedBlock, statedb *state.StateDB, tradingState *tradingstate.TradingStateDB, cfg vm.Config, balanceFee map[common.Address]*big.Int) (types.Receipts, []*types.Log, uint64, error) {
	p.record(block.block)
	return p.Processor.ProcessBlockNoValidator(block, statedb, tradingState, cfg, balanceFee)
}

// TestInsertBlockSkipsABlockAnInFlightBatchIsImporting pins that the marks insertChain puts
// on its whole batch survive it: a batch larger than the 256-entry cache the marks used to
// share with the block caches lost the marks of the blocks it executed last, and a fetcher
// delivery of one of them ran the block a second time before the import made the same check
// answer "already imported".
func TestInsertBlockSkipsABlockAnInFlightBatchIsImporting(t *testing.T) {
	t.Parallel()

	// More blocks than the old cache held: the first block is the one a too small cache
	// evicts first.
	chain, blocks := newDownloadingMarkTester(t, 300)
	target := blocks[0].Hash()

	proc := &pausingProcessor{
		Processor: chain.processor,
		target:    target,
		entered:   make(chan struct{}),
		release:   make(chan struct{}),
		counts:    make(map[common.Hash]int),
	}
	chain.processor = proc

	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(proc.release) }) }
	defer release()

	batchDone := make(chan error, 1)
	go func() {
		_, err := chain.InsertChain(blocks)
		batchDone <- err
	}()
	select {
	case <-proc.entered:
	case <-time.After(30 * time.Second):
		t.Fatal("timed out waiting for the batch to execute its first block")
	}
	// The marks cover the whole batch before any of it is executed, so the first block is
	// still marked here when the cache holds the batch.
	if !chain.downloadingBlock.Contains(target) {
		t.Fatal("the batch lost the mark of a block it has not imported yet")
	}
	// A fetcher delivery of the same block is answered by the mark, without executing it
	// and without waiting for the batch.
	insertDone := make(chan error, 1)
	go func() {
		insertDone <- chain.InsertBlock(blocks[0])
	}()
	select {
	case err := <-insertDone:
		if err != nil {
			t.Fatalf("delivery of a downloading block failed: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the fetcher path did not answer the downloading mark")
	}
	if calls := proc.count(target); calls != 1 {
		t.Fatalf("block was executed %d times, want 1", calls)
	}

	release()
	select {
	case err := <-batchDone:
		if err != nil {
			t.Fatalf("batch import failed: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("timed out waiting for the batch to finish")
	}
}

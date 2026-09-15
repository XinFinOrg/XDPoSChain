package core

import (
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// futureVerifyEngine fails header verification for a single block number, or for
// every block from failFrom on (0 disables the range), so a batch can be made
// to fail in the middle instead of at its first block. failFrom is atomic
// because the chain's future-block loop calls VerifyHeaders concurrently.
type futureVerifyEngine struct {
	consensus.Engine
	failNumber uint64
	failFrom   atomic.Uint64
	failErr    error

	// handleMu guards handleCalls: the chain's background future-block loop
	// invokes HandleProposedBlock concurrently with the test goroutine.
	handleMu    sync.Mutex
	handleCalls []*types.Header
}

func (e *futureVerifyEngine) VerifyHeaders(chain consensus.ChainReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
	abort := make(chan struct{})
	results := make(chan error, len(headers))
	go func() {
		for _, header := range headers {
			var err error
			number := header.Number.Uint64()
			failFrom := e.failFrom.Load()
			if number == e.failNumber || (failFrom != 0 && number >= failFrom) {
				err = e.failErr
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

// HandleProposedBlock records the compensated header so tests can assert which
// block the future-block loop hands to the consensus engine after an import.
// It also makes futureVerifyEngine satisfy the proposedBlockHandler interface
// that procFutureBlocks asserts on the chain engine.
func (e *futureVerifyEngine) HandleProposedBlock(chain consensus.ChainReader, header *types.Header) error {
	e.handleMu.Lock()
	defer e.handleMu.Unlock()
	e.handleCalls = append(e.handleCalls, header)
	return nil
}

func (e *futureVerifyEngine) lastHandled() *types.Header {
	e.handleMu.Lock()
	defer e.handleMu.Unlock()
	if len(e.handleCalls) == 0 {
		return nil
	}
	return e.handleCalls[len(e.handleCalls)-1]
}

func (e *futureVerifyEngine) handleSnapshot() []*types.Header {
	e.handleMu.Lock()
	defer e.handleMu.Unlock()
	return append([]*types.Header(nil), e.handleCalls...)
}

// TestInsertChainQueuesMidBatchFutureBlocks verifies that a batch rejected as
// future mid-way has its whole tail queued instead of failing the import:
// children of a future block fail the timestamp check before the parent lookup
// so they surface as ErrFutureBlock too, and returning that error would make
// the downloader drop the peer on a valid delivery.
func TestInsertChainQueuesMidBatchFutureBlocks(t *testing.T) {
	var (
		key, _  = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		address = crypto.PubkeyToAddress(key.PublicKey)
		funds   = big.NewInt(1000000000000000)
		gspec   = &Genesis{
			Alloc:   types.GenesisAlloc{address: {Balance: funds}},
			BaseFee: big.NewInt(params.InitialBaseFee),
			Config:  params.TestChainConfig,
		}
	)
	_, blocks, _ := GenerateChainWithGenesis(gspec, ethash.NewFaker(), 5, nil)

	engine := &futureVerifyEngine{Engine: ethash.NewFaker(), failErr: consensus.ErrFutureBlock}
	engine.failFrom.Store(3)

	db := rawdb.NewMemoryDatabase()
	chain, err := NewBlockChain(db, nil, gspec, engine, vm.Config{})
	if err != nil {
		t.Fatalf("failed to create tester chain: %v", err)
	}
	defer chain.Stop()

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
	var (
		key, _  = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		address = crypto.PubkeyToAddress(key.PublicKey)
		funds   = big.NewInt(1000000000000000)
		gspec   = &Genesis{
			Alloc:   types.GenesisAlloc{address: {Balance: funds}},
			BaseFee: big.NewInt(params.InitialBaseFee),
			Config:  params.TestChainConfig,
		}
	)
	_, blocks, _ := GenerateChainWithGenesis(gspec, ethash.NewFaker(), 5, nil)

	engine := &futureVerifyEngine{Engine: ethash.NewFaker(), failErr: consensus.ErrFutureBlock}
	engine.failFrom.Store(1)

	db := rawdb.NewMemoryDatabase()
	chain, err := NewBlockChain(db, nil, gspec, engine, vm.Config{})
	if err != nil {
		t.Fatalf("failed to create tester chain: %v", err)
	}
	defer chain.Stop()

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
	}
}

// TestInsertChainQueuesWrappedFutureError guards the errors.Is comparisons on
// the future-block paths: header verification may hand back a %w-wrapped
// ErrFutureBlock, and bare == comparisons would then abort the import (or
// skip the tail queueing) instead of parking the batch for procFutureBlocks.
func TestInsertChainQueuesWrappedFutureError(t *testing.T) {
	var (
		key, _  = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		address = crypto.PubkeyToAddress(key.PublicKey)
		funds   = big.NewInt(1000000000000000)
		gspec   = &Genesis{
			Alloc:   types.GenesisAlloc{address: {Balance: funds}},
			BaseFee: big.NewInt(params.InitialBaseFee),
			Config:  params.TestChainConfig,
		}
	)
	_, blocks, _ := GenerateChainWithGenesis(gspec, ethash.NewFaker(), 5, nil)

	wrapped := fmt.Errorf("verification: %w", consensus.ErrFutureBlock)
	if !errors.Is(wrapped, consensus.ErrFutureBlock) {
		t.Fatalf("test setup: error must wrap ErrFutureBlock")
	}

	// failFrom=1 rejects the whole batch at its first block (first-block queue
	// path), failFrom=3 rejects it mid-way after blocks 1 and 2 imported (tail
	// queue path). Either way the wrapped sentinel must still park the tail.
	for _, tc := range []struct {
		name     string
		failFrom uint64
		head     uint64
		queued   int // number of tail blocks that must end up in the future queue
	}{
		{name: "first-block", failFrom: 1, head: 0, queued: 5},
		{name: "mid-batch", failFrom: 3, head: 2, queued: 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			engine := &futureVerifyEngine{Engine: ethash.NewFaker(), failErr: wrapped}
			engine.failFrom.Store(tc.failFrom)

			db := rawdb.NewMemoryDatabase()
			chain, err := NewBlockChain(db, nil, gspec, engine, vm.Config{})
			if err != nil {
				t.Fatalf("failed to create tester chain: %v", err)
			}
			defer chain.Stop()

			if n, err := chain.InsertChain(blocks); err != nil || n != len(blocks) {
				t.Fatalf("failed to insert into chain: index %d err %v", n, err)
			}
			if head := chain.CurrentBlock().Number.Uint64(); head != tc.head {
				t.Fatalf("unexpected head number: have %d want %d", head, tc.head)
			}
			for i, block := range blocks {
				if queued, want := chain.futureBlocks.Contains(block.Hash()), i >= len(blocks)-tc.queued; queued != want {
					t.Fatalf("block %d queued = %v, want %v", block.NumberU64(), queued, want)
				}
				if bad := rawdb.ReadBadBlock(db, block.Hash()); bad != nil {
					t.Fatalf("block %d recorded as bad block", block.NumberU64())
				}
			}
		})
	}
}

// TestInsertChainFutureBlocksBeyondEnqueueWindow pins the maxTimeFutureBlocks
// boundary of the tail queueing: blocks are only parked while their timestamps
// stay within maxTimeFutureBlocks (30s) of the wall clock. Once the tail spans
// past the window, addFutureBlock rejects the first out-of-window block and
// InsertChain fails with that non-sentinel error — the same visible outcome as
// before queueing was extended — while the in-window prefix stays queued for
// procFutureBlocks.
func TestInsertChainFutureBlocksBeyondEnqueueWindow(t *testing.T) {
	var (
		key, _  = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		address = crypto.PubkeyToAddress(key.PublicKey)
		funds   = big.NewInt(1000000000000000)
		gspec   = &Genesis{
			Alloc:   types.GenesisAlloc{address: {Balance: funds}},
			BaseFee: big.NewInt(params.InitialBaseFee),
			Config:  params.TestChainConfig,
		}
		now = uint64(time.Now().Unix())
	)
	// Simulate a 2s block period with the batch starting 18s ahead of the
	// clock: blocks 0..5 sit inside the 30s enqueue window, blocks 6.. jump
	// past it by a wide margin. The last in-window block stops 2s short of
	// the boundary, so a backward wall-clock step (e.g. an NTP correction)
	// between the now capture and addFutureBlock's own time.Now read cannot
	// push it out of the window; the out-of-window tail would need a 30s
	// forward jump to sneak in, which cannot happen within a test run.
	_, blocks, _ := GenerateChainWithGenesis(gspec, ethash.NewFaker(), 12, func(i int, gen *BlockGen) {
		if i < 6 {
			gen.header.Time = now + 18 + uint64(2*i)
		} else {
			gen.header.Time = now + 60 + uint64(i-6)
		}
	})

	engine := &futureVerifyEngine{Engine: ethash.NewFaker(), failErr: consensus.ErrFutureBlock}
	engine.failFrom.Store(1)

	db := rawdb.NewMemoryDatabase()
	chain, err := NewBlockChain(db, nil, gspec, engine, vm.Config{})
	if err != nil {
		t.Fatalf("failed to create tester chain: %v", err)
	}
	defer chain.Stop()

	n, err := chain.InsertChain(blocks)
	if n != 6 {
		t.Fatalf("unexpected failing index: have %d want 6", n)
	}
	if err == nil || !strings.Contains(err.Error(), "future block timestamp") || errors.Is(err, consensus.ErrFutureBlock) {
		t.Fatalf("unexpected error for block %d: %v", n, err)
	}
	if head := chain.CurrentBlock().Number.Uint64(); head != 0 {
		t.Fatalf("unexpected head number: have %d want 0", head)
	}
	for i, block := range blocks {
		if queued, want := chain.futureBlocks.Contains(block.Hash()), i < 6; queued != want {
			t.Fatalf("block %d queued = %v, want %v", block.NumberU64(), queued, want)
		}
		if bad := rawdb.ReadBadBlock(db, block.Hash()); bad != nil {
			t.Fatalf("block %d recorded as bad block", block.NumberU64())
		}
	}
}

// TestInsertChainProcFutureBlocksResumesImport proves the queued tail is not
// dropped: once headers verify again, the queued blocks import and the head
// advances to the batch tip.
func TestInsertChainProcFutureBlocksResumesImport(t *testing.T) {
	var (
		key, _  = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		address = crypto.PubkeyToAddress(key.PublicKey)
		funds   = big.NewInt(1000000000000000)
		gspec   = &Genesis{
			Alloc:   types.GenesisAlloc{address: {Balance: funds}},
			BaseFee: big.NewInt(params.InitialBaseFee),
			Config:  params.TestChainConfig,
		}
	)
	_, blocks, _ := GenerateChainWithGenesis(gspec, ethash.NewFaker(), 5, nil)

	engine := &futureVerifyEngine{Engine: ethash.NewFaker(), failErr: consensus.ErrFutureBlock}
	engine.failFrom.Store(3)

	chain, err := NewBlockChain(rawdb.NewMemoryDatabase(), nil, gspec, engine, vm.Config{})
	if err != nil {
		t.Fatalf("failed to create tester chain: %v", err)
	}
	defer chain.Stop()

	if _, err := chain.InsertChain(blocks); err != nil {
		t.Fatalf("failed to insert into chain: %v", err)
	}
	if want := uint64(2); chain.CurrentBlock().Number.Uint64() != want {
		t.Fatalf("unexpected head number: have %d want %d", chain.CurrentBlock().Number.Uint64(), want)
	}

	// The background future-block loop may drain the queue first; the explicit
	// call is then a no-op and the head assertion still holds.
	engine.failFrom.Store(0)
	// The 100ms futureBlocksLoop also drains the queue; retry until it settles.
	for i := 0; i < 100 && chain.CurrentBlock().Number.Uint64() != 5; i++ {
		chain.procFutureBlocks()
		time.Sleep(10 * time.Millisecond)
	}
	if want := uint64(5); chain.CurrentBlock().Number.Uint64() != want {
		t.Fatalf("unexpected head number: have %d want %d", chain.CurrentBlock().Number.Uint64(), want)
	}
}

// TestProcFutureBlocksHandlesHighestImportedCanonicalBlock verifies that the
// consensus-engine compensation after a future-queue drain targets the highest
// block that actually advanced the canonical head. The historical code only
// compensated the sorted tail of the queue when its own import succeeded, so a
// tail that failed to import (bad block, or still in the future) silently
// skipped the engine hook for the lower blocks that did import, dropping their
// processQC and vote handling.
func TestProcFutureBlocksHandlesHighestImportedCanonicalBlock(t *testing.T) {
	var (
		key, _  = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		address = crypto.PubkeyToAddress(key.PublicKey)
		funds   = big.NewInt(1000000000000000)
		gspec   = &Genesis{
			Alloc:   types.GenesisAlloc{address: {Balance: funds}},
			BaseFee: big.NewInt(params.InitialBaseFee),
			Config:  params.TestChainConfig,
		}
	)
	_, blocks, _ := GenerateChainWithGenesis(gspec, ethash.NewFaker(), 5, nil)

	for _, tc := range []struct {
		name       string
		failNumber uint64 // block number that must fail to import (0 = none)
		failErr    error
		head       uint64 // canonical head after the drain, and hook target
	}{
		{name: "tail-rejected", failNumber: 5, failErr: errors.New("simulated bad tail block"), head: 4},
		{name: "tail-still-future", failNumber: 5, failErr: consensus.ErrFutureBlock, head: 4},
		{name: "whole-queue-imported", head: 5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			engine := &futureVerifyEngine{Engine: ethash.NewFaker(), failNumber: tc.failNumber, failErr: tc.failErr}

			chain, err := NewBlockChain(rawdb.NewMemoryDatabase(), nil, gspec, engine, vm.Config{})
			if err != nil {
				t.Fatalf("failed to create tester chain: %v", err)
			}
			defer chain.Stop()

			// Park the whole batch as future blocks, as a failed import would have.
			for _, block := range blocks {
				chain.futureBlocks.Add(block.Hash(), block)
			}
			// The background 100ms future-block loop drains the queue too, so keep
			// prodding until the hook has fired for the expected head.
			deadline := time.Now().Add(2 * time.Second)
			for chain.CurrentBlock().Number.Uint64() != tc.head && time.Now().Before(deadline) {
				chain.procFutureBlocks()
				time.Sleep(10 * time.Millisecond)
			}
			if last := engine.lastHandled(); last == nil || last.Number.Uint64() != tc.head {
				t.Fatalf("consensus hook not called for imported head %d", tc.head)
			}
			if head := chain.CurrentBlock().Number.Uint64(); head != tc.head {
				t.Fatalf("unexpected head number: have %d want %d", head, tc.head)
			}
			wantHash := blocks[tc.head-1].Hash()
			for _, handled := range engine.handleSnapshot() {
				if handled.Number.Uint64() > tc.head {
					t.Fatalf("consensus hook called for block %d beyond the imported head %d", handled.Number.Uint64(), tc.head)
				}
				if handled.Number.Uint64() == tc.head && handled.Hash() != wantHash {
					t.Fatalf("consensus hook called for the wrong block at height %d", tc.head)
				}
			}
		})
	}
}

// mutableErrEngine is a verification stub whose injected error can be switched
// at runtime, modelling a future block whose timestamp expires between the
// original park in the future queue and the queue retry.
type mutableErrEngine struct {
	consensus.Engine
	verifyErr atomic.Value // error
}

func (e *mutableErrEngine) setErr(err error) { e.verifyErr.Store(err) }

func (e *mutableErrEngine) VerifyHeaders(chain consensus.ChainReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
	abort := make(chan struct{})
	results := make(chan error, len(headers))
	err, _ := e.verifyErr.Load().(error)
	go func() {
		for range headers {
			select {
			case <-abort:
				return
			case results <- err:
			}
		}
	}()
	return abort, results
}

// TestProcFutureBlocksEvictsUnretryableFutureBlocks pins the eviction rule of
// the future-block drain: a queued block is retried only while it is still in
// the future, or while its parent is itself parked in the queue. A poison batch
// of garbage blocks — delivered while its timestamps sat inside the future
// window and therefore parked in full — must drain from the queue once those
// timestamps expire, instead of being re-verified and re-reported as bad
// blocks on every futureBlocksLoop tick forever.
func TestProcFutureBlocksEvictsUnretryableFutureBlocks(t *testing.T) {
	var (
		key, _  = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		address = crypto.PubkeyToAddress(key.PublicKey)
		funds   = big.NewInt(1000000000000000)
		gspec   = &Genesis{
			Alloc:   types.GenesisAlloc{address: {Balance: funds}},
			BaseFee: big.NewInt(params.InitialBaseFee),
			Config:  params.TestChainConfig,
		}
		now = uint64(time.Now().Unix())
	)

	// buildPoisonChain returns a contiguous run of count blocks starting at
	// height 1 whose root's parent is an unresolvable hash: once their
	// timestamps expire, the root is a permanent orphan and every child hangs
	// off a still-parked parent, so no block of the chain can ever import.
	buildPoisonChain := func(count int) types.Blocks {
		blocks := make(types.Blocks, 0, count)
		parent := common.Hash{0xde, 0xad}
		for i := 0; i < count; i++ {
			header := &types.Header{
				ParentHash: parent,
				Number:     big.NewInt(int64(i + 1)),
				GasLimit:   params.GenesisGasLimit,
				Time:       now + 10,
				Difficulty: common.Big1,
			}
			block := types.NewBlockWithHeader(header)
			blocks = append(blocks, block)
			parent = block.Hash()
		}
		return blocks
	}

	for _, tc := range []struct {
		name   string
		poison bool // garbage chain with an unresolvable root parent
		count  int  // blocks delivered in a single batch
		expire bool // switch the verification error to ErrUnknownAncestor
	}{
		{name: "small-orphaned-chain-drains", poison: true, count: 5, expire: true},
		{name: "still-future-retained", count: 5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var blocks types.Blocks
			if tc.poison {
				blocks = buildPoisonChain(tc.count)
			} else {
				_, blocks, _ = GenerateChainWithGenesis(gspec, ethash.NewFaker(), tc.count, nil)
			}

			engine := &mutableErrEngine{Engine: ethash.NewFaker()}
			engine.setErr(consensus.ErrFutureBlock) // every timestamp sits inside the future window

			db := rawdb.NewMemoryDatabase()
			chain, err := NewBlockChain(db, nil, gspec, engine, vm.Config{})
			if err != nil {
				t.Fatalf("failed to create tester chain: %v", err)
			}
			defer chain.Stop()

			// Deliver the batch while every block is future: the import reports
			// success with the whole batch parked in the queue.
			if n, err := chain.InsertChain(blocks); err != nil || n != len(blocks) {
				t.Fatalf("failed to deliver batch: index %d err %v", n, err)
			}
			if have := chain.futureBlocks.Len(); have != tc.count {
				t.Fatalf("unexpected queue length after delivery: have %d want %d", have, tc.count)
			}

			if !tc.expire {
				// The blocks are still in the future: retrying must keep them
				// parked, and must not report them as bad.
				deadline := time.Now().Add(300 * time.Millisecond)
				for time.Now().Before(deadline) {
					chain.procFutureBlocks()
					time.Sleep(10 * time.Millisecond)
				}
				if have := chain.futureBlocks.Len(); have != tc.count {
					t.Fatalf("future blocks evicted while still in the future: have %d want %d", have, tc.count)
				}
				for _, block := range blocks {
					if bad := rawdb.ReadBadBlock(db, block.Hash()); bad != nil {
						t.Fatalf("future block %d reported as bad", block.NumberU64())
					}
				}
				return
			}

			// Phase 2: the timestamps expired, so verification now fails on the
			// unresolvable ancestor. The queue must drain instead of retrying
			// and re-reporting the poison forever.
			engine.setErr(consensus.ErrUnknownAncestor)
			deadline := time.Now().Add(2 * time.Second)
			for chain.futureBlocks.Len() > 0 && time.Now().Before(deadline) {
				chain.procFutureBlocks()
				time.Sleep(10 * time.Millisecond)
			}
			if have := chain.futureBlocks.Len(); have != 0 {
				t.Fatalf("poisoned queue did not drain: %d blocks still queued", have)
			}
			if head := chain.CurrentBlock().Number.Uint64(); head != 0 {
				t.Fatalf("garbage block imported, head at %d", head)
			}
			// Every parked block was reported as bad once, during the drain.
			for _, block := range blocks {
				if bad := rawdb.ReadBadBlock(db, block.Hash()); bad == nil {
					t.Fatalf("garbage block %d not reported as bad", block.NumberU64())
				}
			}
		})
	}
}

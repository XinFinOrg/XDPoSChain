// Copyright 2015 The go-ethereum Authors
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

package fetcher

import (
	"errors"
	"math/big"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/trie"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/params"
)

var (
	testdb      = rawdb.NewMemoryDatabase()
	testKey, _  = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	testAddress = crypto.PubkeyToAddress(testKey.PublicKey)

	gspec = core.Genesis{
		Alloc:   types.GenesisAlloc{testAddress: {Balance: big.NewInt(1000000000000000000)}},
		BaseFee: big.NewInt(params.InitialBaseFee),
		Config:  params.TestChainConfig,
	}
	genesis = gspec.MustCommit(testdb)

	unknownBlock = types.NewBlock(&types.Header{Root: types.EmptyRootHash, GasLimit: params.GenesisGasLimit}, nil, nil, trie.NewStackTrie(nil))
)

// makeChain creates a chain of n blocks starting at and including parent.
// the returned hash chain is ordered head->parent. In addition, every 3rd block
// contains a transaction and every 5th an uncle to allow testing correct block
// reassembly.
func makeChain(n int, seed byte, parent *types.Block) ([]common.Hash, map[common.Hash]*types.Block) {
	blocks, _ := core.GenerateChain(params.TestChainConfig, parent, ethash.NewFaker(), testdb, n, func(i int, block *core.BlockGen) {
		block.SetCoinbase(common.Address{seed})

		// If the block number is multiple of 3, send a bonus transaction to the miner
		if parent == genesis && i%3 == 0 {
			signer := types.MakeSigner(params.TestChainConfig, block.Number())
			fee := block.BaseFee()
			if fee == nil {
				fee = big.NewInt(params.InitialBaseFee)
			}
			tx, err := types.SignTx(types.NewTransaction(block.TxNonce(testAddress), common.Address{seed}, big.NewInt(1000), params.TxGas, fee, nil), signer, testKey)
			if err != nil {
				panic(err)
			}
			block.AddTx(tx)
		}
		// If the block number is a multiple of 5, add a bonus uncle to the block
		if i%5 == 0 {
			block.AddUncle(&types.Header{ParentHash: block.PrevBlock(i - 1).Hash(), Number: big.NewInt(int64(i - 1))})
		}
	})
	hashes := make([]common.Hash, n+1)
	hashes[len(hashes)-1] = parent.Hash()
	blockm := make(map[common.Hash]*types.Block, n+1)
	blockm[parent.Hash()] = parent
	for i, b := range blocks {
		hashes[len(hashes)-i-2] = b.Hash()
		blockm[b.Hash()] = b
	}
	return hashes, blockm
}

// fetcherTester is a test simulator for mocking out local block chain.
type fetcherTester struct {
	fetcher *BlockFetcher

	hashes []common.Hash                // Hash chain belonging to the tester
	blocks map[common.Hash]*types.Block // Blocks belonging to the tester
	drops  map[string]bool              // Map of peers dropped by the fetcher

	syncing atomic.Bool // Reports snap sync in progress to the fetcher

	lock sync.RWMutex
}

// newTester creates a new fetcher test mocker.
func newTester() *fetcherTester {
	tester := &fetcherTester{
		hashes: []common.Hash{genesis.Hash()},
		blocks: map[common.Hash]*types.Block{genesis.Hash(): genesis},
		drops:  make(map[string]bool),
	}
	tester.fetcher = NewBlockFetcher(tester.getBlock, tester.verifyHeader, tester.handleProposedBlock, tester.broadcastBlock, tester.chainHeight, tester.insertBlock, tester.prepareBlock, tester.dropPeer, tester.canonicalHash, func() bool { return tester.syncing.Load() })
	tester.fetcher.Start()

	return tester
}

func (f *fetcherTester) canonicalHash(number uint64) common.Hash {
	f.lock.RLock()
	defer f.lock.RUnlock()

	for _, hash := range f.hashes {
		if block := f.blocks[hash]; block != nil && block.NumberU64() == number {
			return hash
		}
	}
	return common.Hash{}
}

// getBlock retrieves a block from the tester's block chain.
func (f *fetcherTester) getBlock(hash common.Hash) *types.Block {
	f.lock.RLock()
	defer f.lock.RUnlock()

	return f.blocks[hash]
}

// verifyHeader is a nop placeholder for the block header verification.
func (f *fetcherTester) verifyHeader(header *types.Header) error {
	return nil
}

func (f *fetcherTester) handleProposedBlock(header *types.Header) error {
	return nil
}

// broadcastBlock is a nop placeholder for the block broadcasting.
func (f *fetcherTester) broadcastBlock(block *types.Block, propagate bool) {
}

// chainHeight retrieves the current height (block number) of the chain.
func (f *fetcherTester) chainHeight() uint64 {
	f.lock.RLock()
	defer f.lock.RUnlock()

	return f.blocks[f.hashes[len(f.hashes)-1]].NumberU64()
}

// insertBlock injects a new blocks into the simulated chain.
func (f *fetcherTester) insertChain(blocks types.Blocks) (int, error) {
	f.lock.Lock()
	defer f.lock.Unlock()

	for i, block := range blocks {
		// Make sure the parent in known
		if _, ok := f.blocks[block.ParentHash()]; !ok {
			return i, errors.New("unknown parent")
		}
		// Discard any new blocks if the same height already exists
		if block.NumberU64() <= f.blocks[f.hashes[len(f.hashes)-1]].NumberU64() {
			return i, nil
		}
		// Otherwise build our current chain
		f.hashes = append(f.hashes, block.Hash())
		f.blocks[block.Hash()] = block
	}
	return 0, nil
}

// insertBlock injects a new blocks into the simulated chain.
func (f *fetcherTester) insertBlock(block *types.Block) error {
	f.lock.Lock()
	defer f.lock.Unlock()

	// Make sure the parent in known
	if _, ok := f.blocks[block.ParentHash()]; !ok {
		return errors.New("unknown parent")
	}
	// Discard any new blocks if the same height already exists
	if block.NumberU64() <= f.blocks[f.hashes[len(f.hashes)-1]].NumberU64() {
		return nil
	}
	// Otherwise build our current chain
	f.hashes = append(f.hashes, block.Hash())
	f.blocks[block.Hash()] = block

	return nil
}

func (f *fetcherTester) watchImports(imported chan *types.Block) {
	insertBlock := f.fetcher.insertBlock
	f.fetcher.insertBlock = func(block *types.Block) error {
		err := insertBlock(block)
		if err == nil {
			imported <- block
		}
		return err
	}
}

// insertBlock injects a new blocks into the simulated chain.
func (f *fetcherTester) prepareBlock(block *types.Block) error {
	return nil
}

// dropPeer is an emulator for the peer removal, simply accumulating the various
// peers dropped by the fetcher.
func (f *fetcherTester) dropPeer(peer string) {
	f.lock.Lock()
	defer f.lock.Unlock()

	f.drops[peer] = true
}

// makeHeaderFetcher retrieves a block header fetcher associated with a simulated peer.
func (f *fetcherTester) makeHeaderFetcher(peer string, blocks map[common.Hash]*types.Block, drift time.Duration) headerRequesterFn {
	closure := make(map[common.Hash]*types.Block)
	for hash, block := range blocks {
		closure[hash] = block
	}
	// Create a function that return a header from the closure
	return func(hash common.Hash) error {
		// Gather the blocks to return
		headers := make([]*types.Header, 0, 1)
		if block, ok := closure[hash]; ok {
			headers = append(headers, block.Header())
		}
		// Return on a new thread
		go f.fetcher.FilterHeaders(peer, headers, time.Now().Add(drift))

		return nil
	}
}

// makeBodyFetcher retrieves a block body fetcher associated with a simulated peer.
func (f *fetcherTester) makeBodyFetcher(peer string, blocks map[common.Hash]*types.Block, drift time.Duration) bodyRequesterFn {
	closure := make(map[common.Hash]*types.Block)
	for hash, block := range blocks {
		closure[hash] = block
	}
	// Create a function that returns blocks from the closure
	return func(hashes []common.Hash) error {
		// Gather the block bodies to return
		transactions := make([][]*types.Transaction, 0, len(hashes))
		uncles := make([][]*types.Header, 0, len(hashes))

		for _, hash := range hashes {
			if block, ok := closure[hash]; ok {
				transactions = append(transactions, block.Transactions())
				uncles = append(uncles, block.Uncles())
			}
		}
		// Return on a new thread
		go f.fetcher.FilterBodies(peer, transactions, uncles, time.Now().Add(drift))

		return nil
	}
}

// verifyFetchingEvent verifies that one single event arrive on an fetching channel.
func verifyFetchingEvent(t *testing.T, fetching chan []common.Hash, arrive bool) {
	if arrive {
		select {
		case <-fetching:
		case <-time.After(time.Second):
			t.Fatalf("fetching timeout")
		}
	} else {
		select {
		case <-fetching:
			t.Fatalf("fetching invoked")
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// verifyCompletingEvent verifies that one single event arrive on an completing channel.
func verifyCompletingEvent(t *testing.T, completing chan []common.Hash, arrive bool) {
	if arrive {
		select {
		case <-completing:
		case <-time.After(time.Second):
			t.Fatalf("completing timeout")
		}
	} else {
		select {
		case <-completing:
			t.Fatalf("completing invoked")
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// verifyImportEvent verifies that one single event arrive on an import channel.
func verifyImportEvent(t *testing.T, imported chan *types.Block, arrive bool) {
	if arrive {
		select {
		case <-imported:
		case <-time.After(time.Second):
			t.Fatalf("import timeout")
		}
	} else {
		select {
		case <-imported:
			t.Fatalf("import invoked")
		case <-time.After(20 * time.Millisecond):
		}
	}
}

// verifyImportCount verifies that exactly count number of events arrive on an
// import hook channel.
func verifyImportCount(t *testing.T, imported chan *types.Block, count int) {
	for i := 0; i < count; i++ {
		select {
		case <-imported:
		case <-time.After(time.Second):
			t.Fatalf("block %d: import timeout", i+1)
		}
	}
	verifyImportDone(t, imported)
}

// verifyImportDone verifies that no more events are arriving on an import channel.
func verifyImportDone(t *testing.T, imported chan *types.Block) {
	select {
	case <-imported:
		t.Fatalf("extra block imported")
	case <-time.After(50 * time.Millisecond):
	}
}

func verifyProposeBlockHandlerCalled(t *testing.T, proposedBlockChan chan *types.Header) {
	select {
	case <-proposedBlockChan:
	case <-time.After(50 * time.Millisecond):
		t.Fatalf("did not call propose block handler")
	}
}

// Tests that a fetcher accepts block announcements and initiates retrievals for
// them, successfully importing into the local chain.
func TestSequentialAnnouncements62(t *testing.T) { testSequentialAnnouncements(t, 62) }
func TestSequentialAnnouncements63(t *testing.T) { testSequentialAnnouncements(t, 63) }
func TestSequentialAnnouncements64(t *testing.T) { testSequentialAnnouncements(t, 64) }

func testSequentialAnnouncements(t *testing.T, protocol int) {
	// Create a chain of blocks to import
	targetBlocks := 4 * hashLimit
	hashes, blocks := makeChain(targetBlocks, 0, genesis)

	tester := newTester()
	headerFetcher := tester.makeHeaderFetcher("valid", blocks, -gatherSlack)
	bodyFetcher := tester.makeBodyFetcher("valid", blocks, 0)

	// Iteratively announce blocks until all are imported.
	imported := make(chan *types.Block)
	tester.watchImports(imported)
	handleProposedBlockChan := make(chan *types.Header)
	tester.fetcher.handleProposedBlock = func(header *types.Header) error {
		go func() { handleProposedBlockChan <- header }()
		return nil
	}

	for i := len(hashes) - 2; i >= 0; i-- {
		tester.fetcher.Notify("valid", hashes[i], uint64(len(hashes)-i-1), time.Now().Add(-arriveTimeout), headerFetcher, bodyFetcher)
		verifyImportEvent(t, imported, true)
	}
	verifyImportDone(t, imported)
	verifyProposeBlockHandlerCalled(t, handleProposedBlockChan)
}

// Tests that if blocks are announced by multiple peers (or even the same buggy
// peer), they will only get downloaded at most once.
func TestConcurrentAnnouncements62(t *testing.T) { testConcurrentAnnouncements(t, 62) }
func TestConcurrentAnnouncements63(t *testing.T) { testConcurrentAnnouncements(t, 63) }
func TestConcurrentAnnouncements64(t *testing.T) { testConcurrentAnnouncements(t, 64) }

func testConcurrentAnnouncements(t *testing.T, protocol int) {
	// Create a chain of blocks to import
	targetBlocks := 4 * hashLimit
	hashes, blocks := makeChain(targetBlocks, 0, genesis)

	// Assemble a tester with a built in counter for the requests
	tester := newTester()
	firstHeaderFetcher := tester.makeHeaderFetcher("first", blocks, -gatherSlack)
	firstBodyFetcher := tester.makeBodyFetcher("first", blocks, 0)
	secondHeaderFetcher := tester.makeHeaderFetcher("second", blocks, -gatherSlack)
	secondBodyFetcher := tester.makeBodyFetcher("second", blocks, 0)

	counter := uint32(0)
	firstHeaderWrapper := func(hash common.Hash) error {
		atomic.AddUint32(&counter, 1)
		return firstHeaderFetcher(hash)
	}
	secondHeaderWrapper := func(hash common.Hash) error {
		atomic.AddUint32(&counter, 1)
		return secondHeaderFetcher(hash)
	}
	// Iteratively announce blocks until all are imported.
	imported := make(chan *types.Block)
	tester.watchImports(imported)

	for i := len(hashes) - 2; i >= 0; i-- {
		tester.fetcher.Notify("first", hashes[i], uint64(len(hashes)-i-1), time.Now().Add(-arriveTimeout), firstHeaderWrapper, firstBodyFetcher)
		tester.fetcher.Notify("second", hashes[i], uint64(len(hashes)-i-1), time.Now().Add(-arriveTimeout+time.Millisecond), secondHeaderWrapper, secondBodyFetcher)
		tester.fetcher.Notify("second", hashes[i], uint64(len(hashes)-i-1), time.Now().Add(-arriveTimeout-time.Millisecond), secondHeaderWrapper, secondBodyFetcher)
		verifyImportEvent(t, imported, true)
	}
	verifyImportDone(t, imported)

	// Make sure no blocks were retrieved twice
	if int(counter) != targetBlocks {
		t.Fatalf("retrieval count mismatch: have %v, want %v", counter, targetBlocks)
	}
}

// Tests that announcements arriving while a previous is being fetched still
// results in a valid import.
func TestOverlappingAnnouncements62(t *testing.T) { testOverlappingAnnouncements(t, 62) }
func TestOverlappingAnnouncements63(t *testing.T) { testOverlappingAnnouncements(t, 63) }
func TestOverlappingAnnouncements64(t *testing.T) { testOverlappingAnnouncements(t, 64) }

func testOverlappingAnnouncements(t *testing.T, protocol int) {
	// Create a chain of blocks to import
	targetBlocks := 4 * hashLimit
	hashes, blocks := makeChain(targetBlocks, 0, genesis)

	tester := newTester()
	headerFetcher := tester.makeHeaderFetcher("valid", blocks, -gatherSlack)
	bodyFetcher := tester.makeBodyFetcher("valid", blocks, 0)

	// Iteratively announce blocks, but overlap them continuously
	overlap := 16
	imported := make(chan *types.Block, len(hashes)-1)
	for i := 0; i < overlap; i++ {
		imported <- nil
	}
	tester.watchImports(imported)

	for i := len(hashes) - 2; i >= 0; i-- {
		tester.fetcher.Notify("valid", hashes[i], uint64(len(hashes)-i-1), time.Now().Add(-arriveTimeout), headerFetcher, bodyFetcher)
		select {
		case <-imported:
		case <-time.After(time.Second):
			t.Fatalf("block %d: import timeout", len(hashes)-i)
		}
	}
	// Wait for all the imports to complete and check count
	verifyImportCount(t, imported, overlap)
}

// Tests that announces already being retrieved will not be duplicated.
func TestPendingDeduplication62(t *testing.T) { testPendingDeduplication(t, 62) }
func TestPendingDeduplication63(t *testing.T) { testPendingDeduplication(t, 63) }
func TestPendingDeduplication64(t *testing.T) { testPendingDeduplication(t, 64) }

func testPendingDeduplication(t *testing.T, protocol int) {
	// Create a hash and corresponding block
	hashes, blocks := makeChain(1, 0, genesis)

	// Assemble a tester with a built in counter and delayed fetcher
	tester := newTester()
	headerFetcher := tester.makeHeaderFetcher("repeater", blocks, -gatherSlack)
	bodyFetcher := tester.makeBodyFetcher("repeater", blocks, 0)

	delay := 50 * time.Millisecond
	counter := uint32(0)
	headerWrapper := func(hash common.Hash) error {
		atomic.AddUint32(&counter, 1)

		// Simulate a long running fetch
		go func() {
			time.Sleep(delay)
			headerFetcher(hash)
		}()
		return nil
	}
	// Announce the same block many times until it's fetched (wait for any pending ops)
	for tester.getBlock(hashes[0]) == nil {
		tester.fetcher.Notify("repeater", hashes[0], 1, time.Now().Add(-arriveTimeout), headerWrapper, bodyFetcher)
		time.Sleep(time.Millisecond)
	}
	time.Sleep(delay)

	// Check that all blocks were imported and none fetched twice
	if imported := len(tester.blocks); imported != 2 {
		t.Fatalf("synchronised block mismatch: have %v, want %v", imported, 2)
	}
	if int(counter) != 1 {
		t.Fatalf("retrieval count mismatch: have %v, want %v", counter, 1)
	}
}

// Tests that announcements retrieved in a random order are cached and eventually
// imported when all the gaps are filled in.
func TestRandomArrivalImport62(t *testing.T) { testRandomArrivalImport(t, 62) }
func TestRandomArrivalImport63(t *testing.T) { testRandomArrivalImport(t, 63) }
func TestRandomArrivalImport64(t *testing.T) { testRandomArrivalImport(t, 64) }

func testRandomArrivalImport(t *testing.T, protocol int) {
	// Create a chain of blocks to import, and choose one to delay
	targetBlocks := maxQueueDist
	hashes, blocks := makeChain(targetBlocks, 0, genesis)
	skip := targetBlocks / 2

	tester := newTester()
	headerFetcher := tester.makeHeaderFetcher("valid", blocks, -gatherSlack)
	bodyFetcher := tester.makeBodyFetcher("valid", blocks, 0)

	// Iteratively announce blocks, skipping one entry
	imported := make(chan *types.Block, len(hashes)-1)
	tester.watchImports(imported)

	for i := len(hashes) - 1; i >= 0; i-- {
		if i != skip {
			tester.fetcher.Notify("valid", hashes[i], uint64(len(hashes)-i-1), time.Now().Add(-arriveTimeout), headerFetcher, bodyFetcher)
			time.Sleep(time.Millisecond)
		}
	}
	// Finally announce the skipped entry and check full import
	tester.fetcher.Notify("valid", hashes[skip], uint64(len(hashes)-skip-1), time.Now().Add(-arriveTimeout), headerFetcher, bodyFetcher)
	verifyImportCount(t, imported, len(hashes)-1)
}

// Tests that direct block enqueues (due to block propagation vs. hash announce)
// are correctly schedule, filling and import queue gaps.
func TestQueueGapFill62(t *testing.T) { testQueueGapFill(t, 62) }
func TestQueueGapFill63(t *testing.T) { testQueueGapFill(t, 63) }
func TestQueueGapFill64(t *testing.T) { testQueueGapFill(t, 64) }

func testQueueGapFill(t *testing.T, protocol int) {
	// Create a chain of blocks to import, and choose one to not announce at all
	targetBlocks := maxQueueDist
	hashes, blocks := makeChain(targetBlocks, 0, genesis)
	skip := targetBlocks / 2

	tester := newTester()
	headerFetcher := tester.makeHeaderFetcher("valid", blocks, -gatherSlack)
	bodyFetcher := tester.makeBodyFetcher("valid", blocks, 0)

	// Iteratively announce blocks, skipping one entry
	imported := make(chan *types.Block, len(hashes)-1)
	tester.watchImports(imported)

	for i := len(hashes) - 1; i >= 0; i-- {
		if i != skip {
			tester.fetcher.Notify("valid", hashes[i], uint64(len(hashes)-i-1), time.Now().Add(-arriveTimeout), headerFetcher, bodyFetcher)
			time.Sleep(time.Millisecond)
		}
	}
	// Fill the missing block directly as if propagated
	tester.fetcher.Enqueue("valid", blocks[hashes[skip]])
	verifyImportCount(t, imported, len(hashes)-1)
}

// Tests that blocks arriving from various sources (multiple propagations, hash
// announces, etc) do not get scheduled for import multiple times.
func TestImportDeduplication62(t *testing.T) { testImportDeduplication(t, 62) }
func TestImportDeduplication63(t *testing.T) { testImportDeduplication(t, 63) }
func TestImportDeduplication64(t *testing.T) { testImportDeduplication(t, 64) }

func testImportDeduplication(t *testing.T, protocol int) {
	// Create two blocks to import (one for duplication, the other for stalling)
	hashes, blocks := makeChain(2, 0, genesis)

	// Create the tester and wrap the importer with a counter
	tester := newTester()
	headerFetcher := tester.makeHeaderFetcher("valid", blocks, -gatherSlack)
	bodyFetcher := tester.makeBodyFetcher("valid", blocks, 0)

	counter := uint32(0)
	tester.fetcher.insertBlock = func(block *types.Block) error {
		atomic.AddUint32(&counter, uint32(1))
		return tester.insertBlock(block)
	}
	// Instrument the fetching and imported events
	fetching := make(chan []common.Hash)
	imported := make(chan *types.Block, len(hashes)-1)
	tester.fetcher.fetchingHook = func(hashes []common.Hash) { fetching <- hashes }
	tester.watchImports(imported)

	// Announce the duplicating block, wait for retrieval, and also propagate directly
	tester.fetcher.Notify("valid", hashes[0], 1, time.Now().Add(-arriveTimeout), headerFetcher, bodyFetcher)
	<-fetching

	tester.fetcher.Enqueue("valid", blocks[hashes[0]])
	tester.fetcher.Enqueue("valid", blocks[hashes[0]])
	tester.fetcher.Enqueue("valid", blocks[hashes[0]])

	// Fill the missing block directly as if propagated, and check import uniqueness
	tester.fetcher.Enqueue("valid", blocks[hashes[1]])
	verifyImportCount(t, imported, 2)

	if counter != 2 {
		t.Fatalf("import invocation count mismatch: have %v, want %v", counter, 2)
	}
}

// Tests that blocks with numbers much lower or higher than out current head get
// discarded to prevent wasting resources on useless blocks from faulty peers.
func TestDistantPropagationDiscarding(t *testing.T) {
	// Create a long chain to import and define the discard boundaries
	hashes, blocks := makeChain(3*maxQueueDist, 0, genesis)
	head := hashes[len(hashes)/2]

	low, high := len(hashes)/2+maxUncleDist+1, len(hashes)/2-maxQueueDist-1

	// Create a tester and simulate a head block being the middle of the above chain
	tester := newTester()

	tester.lock.Lock()
	tester.hashes = []common.Hash{head}
	tester.blocks = map[common.Hash]*types.Block{head: blocks[head]}
	tester.lock.Unlock()

	// Ensure that a block with a lower number than the threshold is discarded
	tester.fetcher.Enqueue("lower", blocks[hashes[low]])
	time.Sleep(10 * time.Millisecond)
	if !tester.fetcher.queue.Empty() {
		t.Fatalf("fetcher queued stale block")
	}
	// Ensure that a block with a higher number than the threshold is discarded
	tester.fetcher.Enqueue("higher", blocks[hashes[high]])
	time.Sleep(10 * time.Millisecond)
	if !tester.fetcher.queue.Empty() {
		t.Fatalf("fetcher queued future block")
	}
}

// Tests that a far-future block whose number overflows int64 (e.g. MaxUint64)
// is discarded by enqueue, matching IsPlausibleAnnouncement, instead of being
// wrapped to a negative distance and accepted into the import queue.
func TestMaxUint64PropagationDiscarding(t *testing.T) {
	// Build a low chain so the wrapped distance of a MaxUint64 block (-1) minus
	// the head would fall inside the acceptance window under the old signed
	// subtraction (height <= maxUncleDist).
	hashes, blocks := makeChain(6, 0, genesis)
	head := hashes[2] // block #4

	tester := newTester()
	tester.lock.Lock()
	tester.hashes = []common.Hash{head}
	tester.blocks = map[common.Hash]*types.Block{head: blocks[head]}
	tester.lock.Unlock()

	// A far-future block must be discarded rather than queued.
	maxFuture := types.NewBlockWithHeader(&types.Header{
		Number:     new(big.Int).SetUint64(^uint64(0)),
		Difficulty: big.NewInt(1),
	})
	tester.fetcher.Enqueue("maxfuture", maxFuture)
	time.Sleep(10 * time.Millisecond)
	if !tester.fetcher.queue.Empty() {
		t.Fatalf("fetcher queued far-future block")
	}
}

// Tests that IsPlausibleAnnouncement accepts announcements within the fetcher's
// plausibility window and rejects those too far from the local chain head.
func TestIsPlausibleAnnouncement(t *testing.T) {
	height := uint64(1000)
	tests := []struct {
		number uint64
		want   bool
	}{
		{number: 0, want: true},                          // Unknown height, always plausible
		{number: height - maxUncleDist, want: true},      // Backward window edge
		{number: height - maxUncleDist - 1, want: false}, // Too far behind
		{number: height + maxQueueDist, want: true},      // Forward window edge
		{number: height + maxQueueDist + 1, want: false}, // Too far ahead
		{number: ^uint64(0), want: false},                // Far future
	}
	for i, tt := range tests {
		if got := IsPlausibleAnnouncement(tt.number, height); got != tt.want {
			t.Fatalf("case %d: number=%d got %v, want %v", i, tt.number, got, tt.want)
		}
	}
}

// Tests that announcements with numbers much lower or higher than out current
// head get discarded to prevent wasting resources on useless blocks from faulty
// peers.
func TestDistantAnnouncementDiscarding62(t *testing.T) { testDistantAnnouncementDiscarding(t, 62) }
func TestDistantAnnouncementDiscarding63(t *testing.T) { testDistantAnnouncementDiscarding(t, 63) }
func TestDistantAnnouncementDiscarding64(t *testing.T) { testDistantAnnouncementDiscarding(t, 64) }

func testDistantAnnouncementDiscarding(t *testing.T, protocol int) {
	// Create a long chain to import and define the discard boundaries
	hashes, blocks := makeChain(3*maxQueueDist, 0, genesis)
	head := hashes[len(hashes)/2]

	low, high := len(hashes)/2+maxUncleDist+1, len(hashes)/2-maxQueueDist-1

	// Create a tester and simulate a head block being the middle of the above chain
	tester := newTester()

	tester.lock.Lock()
	tester.hashes = []common.Hash{head}
	tester.blocks = map[common.Hash]*types.Block{head: blocks[head]}
	tester.lock.Unlock()

	headerFetcher := tester.makeHeaderFetcher("lower", blocks, -gatherSlack)
	bodyFetcher := tester.makeBodyFetcher("lower", blocks, 0)

	fetching := make(chan struct{}, 2)
	tester.fetcher.fetchingHook = func(hashes []common.Hash) { fetching <- struct{}{} }

	// Ensure that a block with a lower number than the threshold is discarded
	tester.fetcher.Notify("lower", hashes[low], blocks[hashes[low]].NumberU64(), time.Now().Add(-arriveTimeout), headerFetcher, bodyFetcher)
	select {
	case <-time.After(50 * time.Millisecond):
	case <-fetching:
		t.Fatalf("fetcher requested stale header")
	}
	// Ensure that a block with a higher number than the threshold is discarded
	tester.fetcher.Notify("higher", hashes[high], blocks[hashes[high]].NumberU64(), time.Now().Add(-arriveTimeout), headerFetcher, bodyFetcher)
	select {
	case <-time.After(50 * time.Millisecond):
	case <-fetching:
		t.Fatalf("fetcher requested future header")
	}
}

// Tests that peers announcing blocks with invalid numbers (i.e. not matching
// the headers provided afterwards) get dropped as malicious.
func TestInvalidNumberAnnouncement62(t *testing.T) { testInvalidNumberAnnouncement(t, 62) }
func TestInvalidNumberAnnouncement63(t *testing.T) { testInvalidNumberAnnouncement(t, 63) }
func TestInvalidNumberAnnouncement64(t *testing.T) { testInvalidNumberAnnouncement(t, 64) }

func testInvalidNumberAnnouncement(t *testing.T, protocol int) {
	// Create a single block to import and check numbers against
	hashes, blocks := makeChain(1, 0, genesis)

	tester := newTester()
	badHeaderFetcher := tester.makeHeaderFetcher("bad", blocks, -gatherSlack)
	badBodyFetcher := tester.makeBodyFetcher("bad", blocks, 0)

	imported := make(chan *types.Block)
	announced := make(chan interface{})
	tester.watchImports(imported)

	// Announce a block with a bad number, check for immediate drop
	tester.fetcher.announceChangeHook = func(hash common.Hash, b bool) {
		announced <- nil
	}
	tester.fetcher.Notify("bad", hashes[0], 2, time.Now().Add(-arriveTimeout), badHeaderFetcher, badBodyFetcher)
	verifyAnnounce := func() {
		for i := 0; i < 2; i++ {
			select {
			case <-announced:
				continue
			case <-time.After(1 * time.Second):
				t.Fatal("announce timeout")
				return
			}
		}
	}
	verifyAnnounce()
	verifyImportEvent(t, imported, false)
	tester.lock.RLock()
	dropped := tester.drops["bad"]
	tester.lock.RUnlock()

	if !dropped {
		t.Fatalf("peer with invalid numbered announcement not dropped")
	}

	goodHeaderFetcher := tester.makeHeaderFetcher("good", blocks, -gatherSlack)
	goodBodyFetcher := tester.makeBodyFetcher("good", blocks, 0)
	// Make sure a good announcement passes without a drop
	tester.fetcher.Notify("good", hashes[0], 1, time.Now().Add(-arriveTimeout), goodHeaderFetcher, goodBodyFetcher)
	verifyAnnounce()
	verifyImportEvent(t, imported, true)

	tester.lock.RLock()
	dropped = tester.drops["good"]
	tester.lock.RUnlock()

	if dropped {
		t.Fatalf("peer with valid numbered announcement dropped")
	}
	verifyImportDone(t, imported)
}

// Tests that if a block is empty (i.e. header only), no body request should be
// made, and instead the header should be assembled into a whole block in itself.
func TestEmptyBlockShortCircuit62(t *testing.T) { testEmptyBlockShortCircuit(t, 62) }
func TestEmptyBlockShortCircuit63(t *testing.T) { testEmptyBlockShortCircuit(t, 63) }
func TestEmptyBlockShortCircuit64(t *testing.T) { testEmptyBlockShortCircuit(t, 64) }

func testEmptyBlockShortCircuit(t *testing.T, protocol int) {
	// Create a chain of blocks to import
	hashes, blocks := makeChain(32, 0, genesis)

	tester := newTester()
	headerFetcher := tester.makeHeaderFetcher("valid", blocks, -gatherSlack)
	bodyFetcher := tester.makeBodyFetcher("valid", blocks, 0)

	// Add a monitoring hook for all internal events
	fetching := make(chan []common.Hash)
	tester.fetcher.fetchingHook = func(hashes []common.Hash) { fetching <- hashes }

	completing := make(chan []common.Hash)
	tester.fetcher.completingHook = func(hashes []common.Hash) { completing <- hashes }

	imported := make(chan *types.Block)
	tester.watchImports(imported)

	// Iteratively announce blocks until all are imported
	for i := len(hashes) - 2; i >= 0; i-- {
		tester.fetcher.Notify("valid", hashes[i], uint64(len(hashes)-i-1), time.Now().Add(-arriveTimeout), headerFetcher, bodyFetcher)

		// All announces should fetch the header
		verifyFetchingEvent(t, fetching, true)

		// Only blocks with data contents should request bodies
		verifyCompletingEvent(t, completing, len(blocks[hashes[i]].Transactions()) > 0 || len(blocks[hashes[i]].Uncles()) > 0)

		// Irrelevant of the construct, import should succeed
		verifyImportEvent(t, imported, true)
	}
	verifyImportDone(t, imported)
}

// Tests that a peer is unable to use unbounded memory with sending infinite
// block announcements to a node, but that even in the face of such an attack,
// the fetcher remains operational.
func TestHashMemoryExhaustionAttack62(t *testing.T) { testHashMemoryExhaustionAttack(t, 62) }
func TestHashMemoryExhaustionAttack63(t *testing.T) { testHashMemoryExhaustionAttack(t, 63) }
func TestHashMemoryExhaustionAttack64(t *testing.T) { testHashMemoryExhaustionAttack(t, 64) }

func testHashMemoryExhaustionAttack(t *testing.T, protocol int) {
	// Create a tester with instrumented import hooks
	tester := newTester()

	imported, announces := make(chan *types.Block), int32(0)
	tester.watchImports(imported)
	tester.fetcher.announceChangeHook = func(hash common.Hash, added bool) {
		if added {
			atomic.AddInt32(&announces, 1)
		} else {
			atomic.AddInt32(&announces, -1)
		}
	}
	// Create a valid chain and an infinite junk chain
	targetBlocks := hashLimit + 2*maxQueueDist
	hashes, blocks := makeChain(targetBlocks, 0, genesis)
	validHeaderFetcher := tester.makeHeaderFetcher("valid", blocks, -gatherSlack)
	validBodyFetcher := tester.makeBodyFetcher("valid", blocks, 0)

	attack, _ := makeChain(targetBlocks, 0, unknownBlock)
	attackerHeaderFetcher := tester.makeHeaderFetcher("attacker", nil, -gatherSlack)
	attackerBodyFetcher := tester.makeBodyFetcher("attacker", nil, 0)

	// Feed the tester a huge hashset from the attacker, and a limited from the valid peer
	for i := 0; i < len(attack); i++ {
		if i < maxQueueDist {
			tester.fetcher.Notify("valid", hashes[len(hashes)-2-i], uint64(i+1), time.Now(), validHeaderFetcher, validBodyFetcher)
		}
		tester.fetcher.Notify("attacker", attack[i], 1 /* don't distance drop */, time.Now(), attackerHeaderFetcher, attackerBodyFetcher)
	}
	if count := atomic.LoadInt32(&announces); count != hashLimit+maxQueueDist {
		t.Fatalf("queued announce count mismatch: have %d, want %d", count, hashLimit+maxQueueDist)
	}
	// Wait for fetches to complete
	verifyImportCount(t, imported, maxQueueDist)

	// Feed the remaining valid hashes to ensure DOS protection state remains clean
	for i := len(hashes) - maxQueueDist - 2; i >= 0; i-- {
		tester.fetcher.Notify("valid", hashes[i], uint64(len(hashes)-i-1), time.Now().Add(-arriveTimeout), validHeaderFetcher, validBodyFetcher)
		verifyImportEvent(t, imported, true)
	}
	verifyImportDone(t, imported)
}

// Tests that blocks sent to the fetcher (either through propagation or via hash
// announces and retrievals) don't pile up indefinitely, exhausting available
// system memory.
func TestBlockMemoryExhaustionAttack(t *testing.T) {
	// Create a tester with instrumented import hooks
	tester := newTester()

	imported, enqueued := make(chan *types.Block), int32(0)
	tester.watchImports(imported)
	tester.fetcher.queueChangeHook = func(hash common.Hash, added bool) {
		if added {
			atomic.AddInt32(&enqueued, 1)
		} else {
			atomic.AddInt32(&enqueued, -1)
		}
	}
	// Create a valid chain and a batch of dangling (but in range) blocks
	targetBlocks := hashLimit + 2*maxQueueDist
	hashes, blocks := makeChain(targetBlocks, 0, genesis)
	attack := make(map[common.Hash]*types.Block)
	for i := byte(0); len(attack) < blockLimit+2*maxQueueDist; i++ {
		hashes, blocks := makeChain(maxQueueDist-1, i, unknownBlock)
		for _, hash := range hashes[:maxQueueDist-2] {
			attack[hash] = blocks[hash]
		}
	}
	// Try to feed all the attacker blocks make sure only a limited batch is accepted
	for _, block := range attack {
		tester.fetcher.Enqueue("attacker", block)
	}
	time.Sleep(200 * time.Millisecond)
	if queued := atomic.LoadInt32(&enqueued); queued != blockLimit {
		t.Fatalf("queued block count mismatch: have %d, want %d", queued, blockLimit)
	}
	// Queue up a batch of valid blocks, and check that a new peer is allowed to do so
	for i := 0; i < maxQueueDist-1; i++ {
		tester.fetcher.Enqueue("valid", blocks[hashes[len(hashes)-3-i]])
	}
	time.Sleep(100 * time.Millisecond)
	if queued := atomic.LoadInt32(&enqueued); queued != blockLimit+maxQueueDist-1 {
		t.Fatalf("queued block count mismatch: have %d, want %d", queued, blockLimit+maxQueueDist-1)
	}
	// Insert the missing piece (and sanity check the import)
	tester.fetcher.Enqueue("valid", blocks[hashes[len(hashes)-2]])
	verifyImportCount(t, imported, maxQueueDist)

	// Insert the remaining blocks in chunks to ensure clean DOS protection
	for i := maxQueueDist; i < len(hashes)-1; i++ {
		tester.fetcher.Enqueue("valid", blocks[hashes[len(hashes)-2-i]])
		verifyImportEvent(t, imported, true)
	}
	verifyImportDone(t, imported)
}

func TestUnimportedBlockSkipsConsensusHandling(t *testing.T) {
	block := newParkedTestBlock(0x01)

	tester := newTester()
	testSkipConsensusHandlingForUnimportedBlock(t, tester, block)

	tester = newTester()
	defer tester.fetcher.Stop() // the second tester is stopped nowhere else
	testConsensusHandlingForImportedBlock(t, tester, block)
}

// testSkipConsensusHandlingForUnimportedBlock asserts that neither hook runs for an unimported block.
func testSkipConsensusHandlingForUnimportedBlock(t *testing.T, tester *fetcherTester, block *types.Block) {
	stop := sync.OnceFunc(tester.fetcher.Stop)
	defer stop()

	imported := make(chan *types.Block, 1)
	tester.fetcher.insertBlock = func(block *types.Block) error {
		imported <- block
		return nil
	}
	signed := hookSigning(tester.fetcher)
	proposed := make(chan *types.Header, 1)
	tester.fetcher.handleProposedBlock = func(header *types.Header) error {
		proposed <- header
		return nil
	}
	tester.fetcher.Enqueue("test", block)

	select {
	case <-imported:
	case <-time.After(5 * time.Second):
		t.Fatalf("import of the unimported block never finished")
	}
	// Stop the fetcher: the waiter exits with it, so no signature can run.
	stop()
	select {
	case b := <-signed:
		t.Fatalf("sign hook ran for unimported block %v", b.Hash())
	case <-time.After(100 * time.Millisecond):
	}
	select {
	case header := <-proposed:
		t.Fatalf("consensus handler ran for unimported block %v", header.Hash())
	case <-time.After(100 * time.Millisecond):
	}
}

// testConsensusHandlingForImportedBlock asserts both hooks run for an imported block.
func testConsensusHandlingForImportedBlock(t *testing.T, tester *fetcherTester, block *types.Block) {
	signed := hookSigning(tester.fetcher)
	proposed := make(chan *types.Header, 1)
	tester.fetcher.handleProposedBlock = func(header *types.Header) error {
		proposed <- header
		return nil
	}
	tester.fetcher.Enqueue("test", block)

	select {
	case b := <-signed:
		if b.Hash() != block.Hash() {
			t.Fatalf("sign hook ran for block %v, want %v", b.Hash(), block.Hash())
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("sign hook never ran for the imported block")
	}
	select {
	case header := <-proposed:
		if header.Hash() != block.Hash() {
			t.Fatalf("consensus handler ran for block %v, want %v", header.Hash(), block.Hash())
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("consensus handler never ran for the imported block")
	}
}

func TestM2BlockSignatureUsesOnchainHash(t *testing.T) {
	original := types.NewBlockWithHeader(&types.Header{
		ParentHash: genesis.Hash(),
		Number:     common.Big1,
		Difficulty: common.Big1,
		GasLimit:   params.GenesisGasLimit,
		Extra:      []byte{0x31},
	}).WithBody(types.Body{})
	m2 := types.NewBlockWithHeader(&types.Header{
		ParentHash: genesis.Hash(),
		Number:     common.Big1,
		Difficulty: common.Big1,
		GasLimit:   params.GenesisGasLimit,
		Extra:      []byte{0x31, 0x2d},
	}).WithBody(types.Body{})
	if original.Hash() == m2.Hash() {
		t.Fatalf("the M2 rewrite must change the block hash")
	}
	wireM2 := func(tester *fetcherTester) {
		tester.fetcher.verifyHeader = func(header *types.Header) error {
			if header.Hash() == original.Hash() {
				return consensus.ErrNoValidatorSignature
			}
			return nil
		}
		tester.fetcher.appendM2HeaderHook = func(*types.Block) (*types.Block, bool, error) {
			return m2, true, nil
		}
	}
	watchRelay := func(tester *fetcherTester) chan *types.Block {
		relayed := make(chan *types.Block, 1)
		tester.fetcher.broadcastBlock = func(block *types.Block, propagate bool) {
			if propagate {
				select {
				case relayed <- block:
				default:
				}
			}
		}
		return relayed
	}

	t.Run("not stored", func(t *testing.T) {
		tester := newTester()
		defer tester.fetcher.Stop()
		wireM2(tester)

		imported := make(chan *types.Block, 1)
		tester.fetcher.insertBlock = func(block *types.Block) error {
			imported <- block
			return nil // another importer stores it later, nothing stored here
		}
		var signs int32
		signed := make(chan *types.Block, 1)
		tester.fetcher.signHook = func(block *types.Block) error {
			atomic.AddInt32(&signs, 1)
			select {
			case signed <- block:
			default:
			}
			return nil
		}
		relayed := watchRelay(tester)
		tester.fetcher.Enqueue("test", original)

		select {
		case block := <-imported:
			if block.Hash() != m2.Hash() {
				t.Fatalf("import saw block %v, want the M2 rewrite %v", block.Hash(), m2.Hash())
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("import of the M2 block never ran")
		}
		select {
		case block := <-relayed:
			if block.Hash() != m2.Hash() {
				t.Fatalf("relay carried block %v, want the M2 rewrite %v", block.Hash(), m2.Hash())
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("M2 block was never relayed")
		}
		tester.fetcher.parkedMu.Lock()
		_, parked := tester.fetcher.parked[m2.Hash()]
		_, parkedByDelivery := tester.fetcher.parked[original.Hash()]
		tester.fetcher.parkedMu.Unlock()
		if !parked {
			t.Fatalf("M2 block is not parked under its on-chain hash")
		}
		if parkedByDelivery {
			t.Fatalf("M2 block is parked under its delivery hash")
		}
		if n := atomic.LoadInt32(&signs); n != 0 {
			t.Fatalf("sign hook ran %d times before the block was stored", n)
		}

		tester.insertChain(types.Blocks{m2})
		select {
		case block := <-signed:
			if block.Hash() != m2.Hash() {
				t.Fatalf("sign hook ran for block %v, want the M2 rewrite %v", block.Hash(), m2.Hash())
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("parked M2 block was never signed after it was stored")
		}
		waitParkedCount(t, tester.fetcher, 0)
		if n := atomic.LoadInt32(&signs); n != 1 {
			t.Fatalf("sign hook ran %d times, want 1", n)
		}
	})

	t.Run("stored", func(t *testing.T) {
		tester := newTester()
		defer tester.fetcher.Stop()
		wireM2(tester)

		tester.fetcher.insertBlock = func(block *types.Block) error {
			if _, err := tester.insertChain(types.Blocks{block}); err != nil {
				return err
			}
			return nil
		}
		var signs int32
		signed := make(chan *types.Block, 1)
		tester.fetcher.signHook = func(block *types.Block) error {
			atomic.AddInt32(&signs, 1)
			select {
			case signed <- block:
			default:
			}
			return nil
		}
		relayed := watchRelay(tester)
		tester.fetcher.Enqueue("test", original)

		// A signature present when the relay arrives proves the immediate path ran.
		select {
		case block := <-relayed:
			if block.Hash() != m2.Hash() {
				t.Fatalf("relay carried block %v, want the M2 rewrite %v", block.Hash(), m2.Hash())
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("M2 block was never relayed")
		}
		select {
		case block := <-signed:
			if block.Hash() != m2.Hash() {
				t.Fatalf("sign hook ran for block %v, want the M2 rewrite %v", block.Hash(), m2.Hash())
			}
		default:
			t.Fatalf("stored M2 block was not signed at delivery, only a later parked scan could sign it")
		}
		if n := atomic.LoadInt32(&signs); n != 1 {
			t.Fatalf("sign hook ran %d times, want 1", n)
		}
		if n := parkedCount(tester.fetcher); n != 0 {
			t.Fatalf("parked count = %d for a stored M2 block, want 0", n)
		}
	})
}

func TestParkedBlockSignsAfterFutureImport(t *testing.T) {
	block := newParkedTestBlock(0x01)

	tester := newTester()
	defer tester.fetcher.Stop()

	imported := make(chan *types.Block, 1)
	tester.fetcher.insertBlock = func(block *types.Block) error {
		imported <- block
		return nil // block parked, nothing stored
	}
	signed := hookSigning(tester.fetcher)
	proposed := make(chan *types.Header, 1)
	tester.fetcher.handleProposedBlock = func(header *types.Header) error {
		proposed <- header
		return nil
	}
	// Only the park path's relay carries propagate=false.
	relayed := make(chan *types.Block, 1)
	tester.fetcher.broadcastBlock = func(block *types.Block, propagate bool) {
		if !propagate {
			relayed <- block
		}
	}
	tester.fetcher.Enqueue("test", block)

	select {
	case <-imported:
	case <-time.After(5 * time.Second):
		t.Fatalf("import of the parked block never finished")
	}
	select {
	case b := <-signed:
		t.Fatalf("sign hook ran before the block was imported: %v", b.Hash())
	case <-time.After(100 * time.Millisecond):
	}
	select {
	case b := <-relayed:
		if b.Hash() != block.Hash() {
			t.Fatalf("relay ran for block %v, want %v", b.Hash(), block.Hash())
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("parked block was never relayed")
	}

	tester.insertChain(types.Blocks{block})

	select {
	case b := <-signed:
		if b.Hash() != block.Hash() {
			t.Fatalf("sign hook ran for block %v, want %v", b.Hash(), block.Hash())
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("sign hook never ran for the imported parked block")
	}
	select {
	case header := <-proposed:
		t.Fatalf("consensus handler ran for parked block %v", header.Hash())
	case <-time.After(100 * time.Millisecond):
	}
}

func parkedCount(f *BlockFetcher) int {
	f.parkedMu.Lock()
	defer f.parkedMu.Unlock()
	return len(f.parked)
}

func signingCount(f *BlockFetcher) int {
	f.parkedMu.Lock()
	defer f.parkedMu.Unlock()
	return len(f.signing)
}

func waitSigningCount(t *testing.T, f *BlockFetcher, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if n := signingCount(f); n == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("in-flight signature count = %d, want %d", signingCount(f), want)
		}
		time.Sleep(time.Millisecond)
	}
}

// waitParkedCount waits for the parked set to reach want; the waiter may own an entry meanwhile.
func waitParkedCount(t *testing.T, f *BlockFetcher, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if n := parkedCount(f); n == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("parked count = %d, want %d", parkedCount(f), want)
		}
		time.Sleep(time.Millisecond)
	}
}

func waiterRunning(f *BlockFetcher) bool {
	f.parkedMu.Lock()
	defer f.parkedMu.Unlock()
	return f.parkedWaiter
}

func parkedDeadline(f *BlockFetcher, hash common.Hash) time.Time {
	f.parkedMu.Lock()
	defer f.parkedMu.Unlock()
	if parked := f.parked[hash]; parked != nil {
		return parked.deadline
	}
	return time.Time{}
}

func newParkedTestBlock(extra byte) *types.Block {
	return types.NewBlockWithHeader(&types.Header{
		ParentHash: genesis.Hash(),
		Number:     common.Big1,
		Difficulty: common.Big1,
		GasLimit:   params.GenesisGasLimit,
		Extra:      []byte{extra},
	}).WithBody(types.Body{})
}

// hookSigning reports signatures on a buffered channel without blocking.
func hookSigning(f *BlockFetcher) chan *types.Block {
	signed := make(chan *types.Block, 1)
	f.signHook = func(b *types.Block) error {
		select {
		case signed <- b:
		default:
		}
		return nil
	}
	return signed
}

// parkTestEntry installs a parked entry directly, so no waiter competes.
func parkTestEntry(t *testing.T, f *BlockFetcher, block *types.Block, deadline time.Time, claimed bool) {
	t.Helper()

	f.parkedMu.Lock()
	defer f.parkedMu.Unlock()
	f.parked[block.Hash()] = &parkedBlock{block: block, deadline: deadline, claimed: claimed}
}

func adoptCanonical(t *testing.T, tester *fetcherTester, block *types.Block) {
	t.Helper()

	tester.lock.Lock()
	defer tester.lock.Unlock()
	tester.hashes = append(tester.hashes, block.Hash())
}

// reorgAfterCollect makes the first canonicalHash call pass and later ones fail.
func reorgAfterCollect(t *testing.T, tester *fetcherTester, block *types.Block) {
	t.Helper()

	tester.lock.Lock()
	for i, hash := range tester.hashes {
		if hash == block.Hash() {
			tester.hashes = append(tester.hashes[:i], tester.hashes[i+1:]...)
			break
		}
	}
	tester.lock.Unlock()

	var calls int32
	tester.fetcher.canonicalHash = func(number uint64) common.Hash {
		if atomic.AddInt32(&calls, 1) == 1 {
			return block.Hash()
		}
		return tester.canonicalHash(number)
	}
}

// stopAndDrainWaiter stops the fetcher and waits until no signature can run.
func stopAndDrainWaiter(t *testing.T, f *BlockFetcher) {
	t.Helper()

	f.Stop()
	deadline := time.Now().Add(2 * time.Second)
	for {
		f.parkedMu.Lock()
		drained := !f.parkedWaiter && len(f.signing) == 0
		f.parkedMu.Unlock()
		if drained {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("parked waiter or its in-flight signature did not stop after the fetcher was stopped")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestParkedSignatureSkippedWhileSyncing(t *testing.T) {
	block := newParkedTestBlock(0x01)

	tester := newTester()
	defer tester.fetcher.Stop()
	tester.syncing.Store(true)

	tester.fetcher.insertBlock = func(*types.Block) error {
		return nil // discarded while syncing, nothing stored
	}
	signed := hookSigning(tester.fetcher)
	relayed := make(chan *types.Block, 1)
	tester.fetcher.broadcastBlock = func(block *types.Block, propagate bool) {
		if !propagate {
			relayed <- block
		}
	}
	tester.fetcher.Enqueue("test", block)

	select {
	case <-relayed:
	case <-time.After(5 * time.Second):
		t.Fatalf("discarded block was never relayed")
	}
	if n := parkedCount(tester.fetcher); n != 0 {
		t.Fatalf("parked %d signatures while snap syncing, want 0", n)
	}
	select {
	case b := <-signed:
		t.Fatalf("sign hook ran for a block discarded while syncing: %v", b.Hash())
	case <-time.After(100 * time.Millisecond):
	}
}

func TestStoredBlockSignatureRespectsSnapSync(t *testing.T) {
	for _, tt := range []struct {
		name    string
		syncing bool
		want    int32
	}{
		{"syncing", true, 0},
		{"synced", false, 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			block := newParkedTestBlock(0x19)

			tester := newTester()
			defer tester.fetcher.Stop()
			tester.syncing.Store(tt.syncing)

			tester.fetcher.insertBlock = func(b *types.Block) error {
				_, err := tester.insertChain(types.Blocks{b})
				return err
			}
			var signs int32
			signed := make(chan *types.Block, 1)
			tester.fetcher.signHook = func(b *types.Block) error {
				atomic.AddInt32(&signs, 1)
				select {
				case signed <- b:
				default:
				}
				return nil
			}
			proposed := make(chan struct{}, 1)
			tester.fetcher.handleProposedBlock = func(*types.Header) error {
				proposed <- struct{}{}
				return nil
			}
			tester.fetcher.Enqueue("test", block)

			select {
			case <-proposed:
			case <-time.After(5 * time.Second):
				t.Fatalf("delivery never finished")
			}
			if n := atomic.LoadInt32(&signs); n != tt.want {
				t.Fatalf("sign hook ran %d times while syncing=%v, want %d", n, tt.syncing, tt.want)
			}
			if tt.want == 0 {
				select {
				case b := <-signed:
					t.Fatalf("sign hook ran for block %v while syncing", b.Hash())
				default:
				}
				return
			}
			select {
			case b := <-signed:
				if b.Hash() != block.Hash() {
					t.Fatalf("sign hook ran for block %v, want %v", b.Hash(), block.Hash())
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("sign hook never ran after sync")
			}
		})
	}
}

func TestParkedSignatureWithoutSignHook(t *testing.T) {
	block := newParkedTestBlock(0x01)

	tester := newTester()
	defer tester.fetcher.Stop()

	tester.fetcher.insertBlock = func(*types.Block) error {
		return nil // never stored
	}
	broadcast := make(chan *types.Block, 1)
	tester.fetcher.broadcastBlock = func(block *types.Block, propagate bool) {
		if !propagate {
			broadcast <- block
		}
	}
	tester.fetcher.Enqueue("test", block)

	select {
	case <-broadcast:
	case <-time.After(5 * time.Second):
		t.Fatalf("never-stored block was never broadcast")
	}
	if n := parkedCount(tester.fetcher); n != 0 {
		t.Fatalf("parked %d signatures without a sign hook, want 0", n)
	}
}

func TestParkedSignatureTimeoutDropsBlock(t *testing.T) {
	block := newParkedTestBlock(0x01)

	tester := newTester()
	defer tester.fetcher.Stop()
	tester.fetcher.parkedTimeout = 200 * time.Millisecond

	tester.fetcher.insertBlock = func(*types.Block) error {
		return nil // never stored
	}
	deadlineMeter := blockParkedDeadlineMeter.Snapshot().Count()
	signed := hookSigning(tester.fetcher)
	broadcast := make(chan *types.Block, 1)
	tester.fetcher.broadcastBlock = func(block *types.Block, propagate bool) {
		if !propagate {
			broadcast <- block
		}
	}
	tester.fetcher.Enqueue("test", block)

	select {
	case <-broadcast:
	case <-time.After(5 * time.Second):
		t.Fatalf("never-stored block was never broadcast")
	}
	if n := parkedCount(tester.fetcher); n != 1 {
		t.Fatalf("parked count = %d, want 1 for the never-stored block", n)
	}
	deadline := time.After(3 * time.Second)
	for parkedCount(tester.fetcher) != 0 {
		select {
		case <-deadline:
			t.Fatalf("parked block was never dropped after its timeout")
		case <-time.After(10 * time.Millisecond):
		}
	}
	if n := blockParkedDeadlineMeter.Snapshot().Count() - deadlineMeter; n != 1 {
		t.Fatalf("deadline meter moved by %d, want 1", n)
	}
	select {
	case b := <-signed:
		t.Fatalf("sign hook ran for a never-imported block: %v", b.Hash())
	case <-time.After(100 * time.Millisecond):
	}
}

func TestParkedSignatureTimeoutDropsStoredButNeverSignable(t *testing.T) {
	block := newParkedTestBlock(0x03)

	tester := newTester()
	defer tester.fetcher.Stop()
	tester.fetcher.parkedTimeout = 200 * time.Millisecond

	tester.lock.Lock()
	tester.blocks[block.Hash()] = block
	tester.lock.Unlock()

	deadlineMeter := blockParkedDeadlineMeter.Snapshot().Count()
	signed := hookSigning(tester.fetcher)
	tester.fetcher.parkForSignature(block)
	if n := parkedCount(tester.fetcher); n != 1 {
		t.Fatalf("parked count = %d, want 1 for the stored-but-not-canonical block", n)
	}
	deadline := time.After(3 * time.Second)
	for parkedCount(tester.fetcher) != 0 {
		select {
		case <-deadline:
			t.Fatalf("parked block was never dropped after its timeout")
		case <-time.After(10 * time.Millisecond):
		}
	}
	if n := blockParkedDeadlineMeter.Snapshot().Count() - deadlineMeter; n != 1 {
		t.Fatalf("deadline meter moved by %d, want 1", n)
	}
	select {
	case b := <-signed:
		t.Fatalf("sign hook ran for a stored-but-never-signable block: %v", b.Hash())
	case <-time.After(100 * time.Millisecond):
	}
}

func TestParkedSignatureExpiredBeforeReadyIsDropped(t *testing.T) {
	block := types.NewBlockWithHeader(&types.Header{
		ParentHash: genesis.Hash(),
		Number:     common.Big1,
		Difficulty: common.Big1,
		GasLimit:   params.GenesisGasLimit,
		Extra:      []byte{0x16},
	}).WithBody(types.Body{})

	tester := newTester()
	defer tester.fetcher.Stop()

	if _, err := tester.insertChain(types.Blocks{block}); err != nil {
		t.Fatalf("failed to store the parked block: %v", err)
	}
	tester.fetcher.parkedMu.Lock()
	tester.fetcher.parked[block.Hash()] = &parkedBlock{block: block, deadline: time.Now().Add(-time.Second)}
	tester.fetcher.parkedMu.Unlock()

	var signs int32
	tester.fetcher.signHook = func(*types.Block) error {
		atomic.AddInt32(&signs, 1)
		return nil
	}
	tester.fetcher.scanParkedSignatures()

	if n := atomic.LoadInt32(&signs); n != 0 {
		t.Fatalf("sign hook ran %d times for an entry past its deadline, want 0", n)
	}
	if n := parkedCount(tester.fetcher); n != 0 {
		t.Fatalf("parked count = %d after the deadline, want 0", n)
	}
}

func TestParkedSignatureDroppedWhenStale(t *testing.T) {
	hashes, blocks := makeChain(maxUncleDist+5, 0, genesis)

	tester := newTester()
	defer tester.fetcher.Stop()

	signed := hookSigning(tester.fetcher)
	for i := len(hashes) - 2; i >= 0; i-- {
		if _, err := tester.insertChain(types.Blocks{blocks[hashes[i]]}); err != nil {
			t.Fatalf("failed to advance the chain: %v", err)
		}
	}
	stale := newParkedTestBlock(0x01)

	tester.fetcher.parkForSignature(stale)
	if n := parkedCount(tester.fetcher); n != 1 {
		t.Fatalf("parked count = %d, want 1", n)
	}
	tester.fetcher.scanParkedSignatures()
	if n := parkedCount(tester.fetcher); n != 0 {
		t.Fatalf("stale parked block was not dropped")
	}
	select {
	case b := <-signed:
		t.Fatalf("sign hook ran for a stale block: %v", b.Hash())
	case <-time.After(100 * time.Millisecond):
	}
}

func TestParkedSignatureStaleBoundary(t *testing.T) {
	const headNumber = maxUncleDist + 4
	hashes, blocks := makeChain(headNumber, 0, genesis)

	tester := newTester()
	defer tester.fetcher.Stop()
	for i := len(hashes) - 2; i >= 0; i-- {
		if _, err := tester.insertChain(types.Blocks{blocks[hashes[i]]}); err != nil {
			t.Fatalf("failed to advance the chain: %v", err)
		}
	}

	for _, tt := range []struct {
		name   string
		number uint64
		parked bool
	}{
		{"at the bound", headNumber - maxUncleDist, true},
		{"one below the bound", headNumber - maxUncleDist - 1, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			block := types.NewBlockWithHeader(&types.Header{
				ParentHash: hashes[tt.number-1],
				Number:     new(big.Int).SetUint64(tt.number),
				Difficulty: common.Big1,
				GasLimit:   params.GenesisGasLimit,
				Extra:      []byte{0x21},
			}).WithBody(types.Body{})
			parkTestEntry(t, tester.fetcher, block, time.Now().Add(time.Minute), false)
			tester.fetcher.scanParkedSignatures()

			tester.fetcher.parkedMu.Lock()
			_, ok := tester.fetcher.parked[block.Hash()]
			tester.fetcher.parkedMu.Unlock()
			if ok != tt.parked {
				t.Fatalf("parked = %v after the scan at distance %d, want %v", ok, headNumber-tt.number, tt.parked)
			}
		})
	}
}

func TestParkedSignatureWaitsForCanonical(t *testing.T) {
	block := newParkedTestBlock(0x03)

	tester := newTester()
	defer tester.fetcher.Stop()

	signed := hookSigning(tester.fetcher)
	tester.fetcher.parkForSignature(block)
	if n := parkedCount(tester.fetcher); n != 1 {
		t.Fatalf("parked count = %d, want 1", n)
	}
	tester.lock.Lock()
	tester.blocks[block.Hash()] = block
	tester.lock.Unlock()

	tester.fetcher.scanParkedSignatures()
	if n := parkedCount(tester.fetcher); n != 1 {
		t.Fatalf("stored-but-not-canonical block must stay parked, parked count = %d", n)
	}
	select {
	case b := <-signed:
		t.Fatalf("sign hook ran for a stored non-canonical block: %v", b.Hash())
	case <-time.After(100 * time.Millisecond):
	}

	// Wait for the entry to be removed: the hook sends before resolveParked.
	tester.insertChain(types.Blocks{block})
	tester.fetcher.scanParkedSignatures()
	waitParkedCount(t, tester.fetcher, 0)
	select {
	case b := <-signed:
		if b.Hash() != block.Hash() {
			t.Fatalf("sign hook ran for %v, want %v", b.Hash(), block.Hash())
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("sign hook never ran for the now-canonical block")
	}
}

func TestParkedSignatureWaiterStopsWhenEmpty(t *testing.T) {
	block := newParkedTestBlock(0x01)

	tester := newTester()
	defer tester.fetcher.Stop()
	tester.fetcher.parkedTimeout = 50 * time.Millisecond
	tester.fetcher.signHook = func(*types.Block) error { return nil }

	if waiterRunning(tester.fetcher) {
		t.Fatalf("waiter is running before any block is parked")
	}
	tester.fetcher.parkForSignature(block)
	if !waiterRunning(tester.fetcher) {
		t.Fatalf("the first park did not start the waiter")
	}
	deadline := time.Now().Add(2 * time.Second)
	for parkedCount(tester.fetcher) != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := parkedCount(tester.fetcher); n != 0 {
		t.Fatalf("parked block was never dropped")
	}
	deadline = time.Now().Add(2 * time.Second)
	for waiterRunning(tester.fetcher) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if waiterRunning(tester.fetcher) {
		t.Fatalf("waiter did not stop after the parked set drained")
	}
}

func TestParkedSignatureLimit(t *testing.T) {
	tester := newTester()
	defer tester.fetcher.Stop()
	tester.fetcher.signHook = func(*types.Block) error { return nil }

	full := blockParkedFullMeter.Snapshot().Count()
	for i := 0; i < maxParkedSignatures+8; i++ {
		tester.fetcher.parkForSignature(newParkedTestBlock(byte(i)))
	}
	if n := parkedCount(tester.fetcher); n != maxParkedSignatures {
		t.Fatalf("parked count = %d, want %d", n, maxParkedSignatures)
	}
	if n := blockParkedFullMeter.Snapshot().Count() - full; n != 8 {
		t.Fatalf("full meter moved by %d, want 8 for the overflow", n)
	}
}

func TestImportedNonCanonicalBlockIsNotSigned(t *testing.T) {
	block := newParkedTestBlock(0x02)

	tester := newTester()
	defer tester.fetcher.Stop()

	tester.fetcher.insertBlock = func(b *types.Block) error {
		tester.lock.Lock()
		tester.blocks[b.Hash()] = b
		tester.lock.Unlock()
		return nil
	}
	signed := hookSigning(tester.fetcher)
	proposed := make(chan *types.Header, 1)
	tester.fetcher.handleProposedBlock = func(h *types.Header) error {
		proposed <- h
		return nil
	}
	tester.fetcher.Enqueue("test", block)

	select {
	case h := <-proposed:
		if h.Hash() != block.Hash() {
			t.Fatalf("consensus handler ran for %v, want %v", h.Hash(), block.Hash())
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("consensus handler never ran for the stored side block")
	}
	select {
	case b := <-signed:
		t.Fatalf("sign hook ran for a non-canonical block: %v", b.Hash())
	case <-time.After(200 * time.Millisecond):
	}
	if n := parkedCount(tester.fetcher); n != 1 {
		t.Fatalf("parked count = %d, want 1 for the refused side block", n)
	}

	// A reorg adopts the branch: the scan revives the signature, exactly once.
	adoptCanonical(t, tester, block)

	tester.fetcher.scanParkedSignatures()
	select {
	case b := <-signed:
		if b.Hash() != block.Hash() {
			t.Fatalf("sign hook ran for block %v, want %v", b.Hash(), block.Hash())
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("parked signature was never revived after the block turned canonical")
	}
	waitParkedCount(t, tester.fetcher, 0)
	tester.fetcher.scanParkedSignatures()
	select {
	case b := <-signed:
		t.Fatalf("sign hook ran twice for block %v", b.Hash())
	case <-time.After(100 * time.Millisecond):
	}
}

func TestParkedSignaturePutsBackWhenNoLongerSignable(t *testing.T) {
	block := newParkedTestBlock(0x06)

	tester := newTester()
	signed := hookSigning(tester.fetcher)
	tester.fetcher.parkForSignature(block)
	// Stop the waiter so the test drives the scan and owns the single canSign call.
	stopAndDrainWaiter(t, tester.fetcher)

	// Flip canonicality after the collect: the first canSign passes, later ones fail.
	tester.insertChain(types.Blocks{block})
	reorgAfterCollect(t, tester, block)

	tester.fetcher.scanParkedSignatures()
	select {
	case b := <-signed:
		t.Fatalf("sign hook ran for a block that stopped being signable: %v", b.Hash())
	case <-time.After(100 * time.Millisecond):
	}
	if n := parkedCount(tester.fetcher); n != 1 {
		t.Fatalf("block unready at signing time must be put back, parked count = %d", n)
	}

	// The branch is re-adopted: the parked signature is created exactly once.
	tester.fetcher.canonicalHash = tester.canonicalHash
	adoptCanonical(t, tester, block)
	tester.fetcher.scanParkedSignatures()
	if n := parkedCount(tester.fetcher); n != 0 {
		t.Fatalf("re-adopted block was not cleared from the parked set, parked count = %d", n)
	}
	select {
	case b := <-signed:
		if b.Hash() != block.Hash() {
			t.Fatalf("sign hook ran for %v, want %v", b.Hash(), block.Hash())
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("sign hook never ran for the re-adopted block")
	}
}

func TestRedeliveredParkedBlockIsSignedOnce(t *testing.T) {
	block := newParkedTestBlock(0x08)

	tester := newTester()
	defer tester.fetcher.Stop()

	tester.lock.Lock()
	tester.blocks[block.Hash()] = block
	tester.lock.Unlock()
	parkTestEntry(t, tester.fetcher, block, time.Now().Add(time.Minute), false)

	adoptCanonical(t, tester, block)

	var signs int32
	tester.fetcher.signHook = func(*types.Block) error {
		atomic.AddInt32(&signs, 1)
		return nil
	}
	proposed := make(chan struct{}, 1)
	tester.fetcher.handleProposedBlock = func(*types.Header) error {
		proposed <- struct{}{}
		return nil
	}
	tester.fetcher.insertBlock = func(*types.Block) error { return nil }
	tester.fetcher.insert("test", block)

	select {
	case <-proposed:
	case <-time.After(5 * time.Second):
		t.Fatalf("delivery of the re-delivered block never finished")
	}
	tester.fetcher.scanParkedSignatures()
	if n := atomic.LoadInt32(&signs); n != 1 {
		t.Fatalf("sign hook ran %d times for the re-delivered block, want 1", n)
	}
	if n := parkedCount(tester.fetcher); n != 0 {
		t.Fatalf("parked count = %d after the signature was created, want 0", n)
	}
}

func TestClaimedParkedSignatureRechecksCanonicality(t *testing.T) {
	block := newParkedTestBlock(0x0a)

	tester := newTester()
	defer tester.fetcher.Stop()

	tester.lock.Lock()
	tester.blocks[block.Hash()] = block
	tester.lock.Unlock()
	adoptCanonical(t, tester, block)
	deadline := time.Now().Add(time.Minute)
	parkTestEntry(t, tester.fetcher, block, deadline, false)

	// The claim-time verdict passes; the post-claim re-check fails.
	reorgAfterCollect(t, tester, block)
	var signs int32
	tester.fetcher.signHook = func(*types.Block) error {
		atomic.AddInt32(&signs, 1)
		return nil
	}
	proposed := make(chan struct{}, 1)
	tester.fetcher.handleProposedBlock = func(*types.Header) error {
		proposed <- struct{}{}
		return nil
	}
	tester.fetcher.insertBlock = func(*types.Block) error { return nil }
	tester.fetcher.insert("test", block)

	select {
	case <-proposed:
	case <-time.After(5 * time.Second):
		t.Fatalf("delivery of the claimed block never finished")
	}
	if n := atomic.LoadInt32(&signs); n != 0 {
		t.Fatalf("sign hook ran %d times for a block that stopped being canonical, want 0", n)
	}
	tester.fetcher.parkedMu.Lock()
	parked, ok := tester.fetcher.parked[block.Hash()]
	claimed := ok && parked.claimed
	tester.fetcher.parkedMu.Unlock()
	if !ok {
		t.Fatalf("entry was dropped instead of being put back")
	}
	if claimed {
		t.Fatalf("entry stayed claimed after the re-check failed")
	}
	if got := parkedDeadline(tester.fetcher, block.Hash()); !got.Equal(deadline) {
		t.Fatalf("entry deadline = %v, want the original %v", got, deadline)
	}

	// The branch is re-adopted: the parked signature is created exactly once.
	tester.fetcher.canonicalHash = tester.canonicalHash
	adoptCanonical(t, tester, block)
	tester.fetcher.scanParkedSignatures()
	if n := atomic.LoadInt32(&signs); n != 1 {
		t.Fatalf("sign hook ran %d times after the block became canonical again, want 1", n)
	}
	if n := parkedCount(tester.fetcher); n != 0 {
		t.Fatalf("parked count = %d after the signature was created, want 0", n)
	}
}

func TestClaimedParkedSignatureStartsParkWhenRefused(t *testing.T) {
	block := newParkedTestBlock(0x15)

	tester := newTester()
	defer tester.fetcher.Stop()

	tester.lock.Lock()
	tester.blocks[block.Hash()] = block
	tester.lock.Unlock()
	adoptCanonical(t, tester, block)

	// The claim-time verdict passes; the post-claim re-check fails.
	reorgAfterCollect(t, tester, block)

	var signs int32
	tester.fetcher.signHook = func(*types.Block) error {
		atomic.AddInt32(&signs, 1)
		return nil
	}
	proposed := make(chan struct{}, 1)
	tester.fetcher.handleProposedBlock = func(*types.Header) error {
		proposed <- struct{}{}
		return nil
	}
	tester.fetcher.insertBlock = func(*types.Block) error { return nil }
	refused := blockParkedRefusedMeter.Snapshot().Count()
	tester.fetcher.insert("test", block)

	select {
	case <-proposed:
	case <-time.After(5 * time.Second):
		t.Fatalf("delivery of the refused block never finished")
	}
	if n := atomic.LoadInt32(&signs); n != 0 {
		t.Fatalf("sign hook ran %d times for a block that stopped being canonical, want 0", n)
	}
	if n := blockParkedRefusedMeter.Snapshot().Count() - refused; n != 1 {
		t.Fatalf("refused meter moved by %d, want 1", n)
	}
	if n := parkedCount(tester.fetcher); n != 1 {
		t.Fatalf("parked count = %d for the refused block, want 1 (a fresh entry)", n)
	}
	tester.fetcher.parkedMu.Lock()
	parked, ok := tester.fetcher.parked[block.Hash()]
	claimed := ok && parked.claimed
	tester.fetcher.parkedMu.Unlock()
	if !ok {
		t.Fatalf("the refused signature was not parked")
	}
	if claimed {
		t.Fatalf("the fresh entry stayed claimed")
	}

	// The branch is re-adopted: the parked signature is created exactly once.
	// The waiter this test started can own the entry, and the sign hook sends
	// before resolveParked removes it, so wait for the removal before counting.
	adoptCanonical(t, tester, block)
	tester.fetcher.scanParkedSignatures()
	waitParkedCount(t, tester.fetcher, 0)
	if n := atomic.LoadInt32(&signs); n != 1 {
		t.Fatalf("sign hook ran %d times after the block became canonical again, want 1", n)
	}
}

func TestParkedSignatureNotSignedTwiceByInsert(t *testing.T) {
	block := newParkedTestBlock(0x09)

	tester := newTester()
	defer tester.fetcher.Stop()

	tester.lock.Lock()
	tester.blocks[block.Hash()] = block
	tester.lock.Unlock()
	parkTestEntry(t, tester.fetcher, block, time.Now().Add(time.Minute), false)
	adoptCanonical(t, tester, block)
	tester.fetcher.insertBlock = func(*types.Block) error { return nil }

	var signs int32
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	// sync.OnceFunc: the deferred and explicit cleanup must not double-close.
	unblock := sync.OnceFunc(func() { close(release) })
	defer unblock()
	tester.fetcher.signHook = func(*types.Block) error {
		// Only the first call blocks, so a second signature is counted.
		if atomic.AddInt32(&signs, 1) == 1 {
			entered <- struct{}{}
			<-release
		}
		return nil
	}
	scanDone := make(chan struct{})
	go func() {
		tester.fetcher.scanParkedSignatures()
		close(scanDone)
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatalf("the scan never started the parked signature")
	}
	// The scan holds the claim while signing, so a re-delivery stands down.
	proposed := make(chan struct{}, 1)
	tester.fetcher.handleProposedBlock = func(*types.Header) error {
		proposed <- struct{}{}
		return nil
	}
	tester.fetcher.insert("test", block)
	select {
	case <-proposed:
	case <-time.After(5 * time.Second):
		t.Fatalf("delivery of the claimed block never finished")
	}
	if n := atomic.LoadInt32(&signs); n != 1 {
		t.Fatalf("sign hook ran %d times while the scan was signing, want 1", n)
	}
	unblock()
	<-scanDone
	if n := atomic.LoadInt32(&signs); n != 1 {
		t.Fatalf("sign hook ran %d times in total, want 1", n)
	}
	if n := parkedCount(tester.fetcher); n != 0 {
		t.Fatalf("parked count = %d after the signature was created, want 0", n)
	}
}

func TestImportedBlockRefusalReasons(t *testing.T) {
	t.Run("not canonical", func(t *testing.T) {
		block := newParkedTestBlock(0x0a)

		tester := newTester()
		defer tester.fetcher.Stop()

		tester.fetcher.insertBlock = func(b *types.Block) error {
			tester.lock.Lock()
			tester.blocks[b.Hash()] = b
			tester.lock.Unlock()
			return nil
		}
		signed := hookSigning(tester.fetcher)
		proposed := make(chan struct{}, 1)
		tester.fetcher.handleProposedBlock = func(*types.Header) error {
			proposed <- struct{}{}
			return nil
		}
		refused, stale := blockParkedRefusedMeter.Snapshot().Count(), blockParkedStaleMeter.Snapshot().Count()
		tester.fetcher.Enqueue("test", block)

		select {
		case <-proposed:
		case <-time.After(5 * time.Second):
			t.Fatalf("consensus handling never ran for the refused block")
		}
		if n := blockParkedRefusedMeter.Snapshot().Count() - refused; n != 1 {
			t.Fatalf("refused meter moved by %d, want 1", n)
		}
		if n := blockParkedStaleMeter.Snapshot().Count() - stale; n != 0 {
			t.Fatalf("stale meter moved by %d for a non-canonical block, want 0", n)
		}
		if n := parkedCount(tester.fetcher); n != 1 {
			t.Fatalf("parked count = %d, want 1 for the refused block", n)
		}
		select {
		case b := <-signed:
			t.Fatalf("sign hook ran for a non-canonical block: %v", b.Hash())
		case <-time.After(100 * time.Millisecond):
		}
	})
	t.Run("below the uncle distance", func(t *testing.T) {
		hashes, blocks := makeChain(maxUncleDist+5, 0, genesis)

		tester := newTester()
		defer tester.fetcher.Stop()

		for i := len(hashes) - 2; i >= 0; i-- {
			if _, err := tester.insertChain(types.Blocks{blocks[hashes[i]]}); err != nil {
				t.Fatalf("failed to advance the chain: %v", err)
			}
		}
		block := blocks[hashes[len(hashes)-2]]
		signed := hookSigning(tester.fetcher)
		proposed := make(chan struct{}, 1)
		tester.fetcher.handleProposedBlock = func(*types.Header) error {
			proposed <- struct{}{}
			return nil
		}
		refused, stale := blockParkedRefusedMeter.Snapshot().Count(), blockParkedStaleMeter.Snapshot().Count()
		tester.fetcher.insert("test", block)

		select {
		case <-proposed:
		case <-time.After(5 * time.Second):
			t.Fatalf("consensus handling never ran for the stale block")
		}
		if n := blockParkedStaleMeter.Snapshot().Count() - stale; n != 1 {
			t.Fatalf("stale meter moved by %d, want 1", n)
		}
		if n := blockParkedRefusedMeter.Snapshot().Count() - refused; n != 0 {
			t.Fatalf("refused meter moved by %d for a stale block, want 0", n)
		}
		if n := parkedCount(tester.fetcher); n != 0 {
			t.Fatalf("parked count = %d for a stale block, want 0", n)
		}
		select {
		case b := <-signed:
			t.Fatalf("sign hook ran for a stale block: %v", b.Hash())
		case <-time.After(100 * time.Millisecond):
		}
	})
	t.Run("not canonical and below the uncle distance", func(t *testing.T) {
		hashes, blocks := makeChain(maxUncleDist+5, 0, genesis)

		tester := newTester()
		defer tester.fetcher.Stop()

		for i := len(hashes) - 2; i >= 0; i-- {
			if _, err := tester.insertChain(types.Blocks{blocks[hashes[i]]}); err != nil {
				t.Fatalf("failed to advance the chain: %v", err)
			}
		}
		// Off the chain and far below the head: reported stale, so it takes no slot.
		block := newParkedTestBlock(0x0f)
		tester.lock.Lock()
		tester.blocks[block.Hash()] = block
		tester.lock.Unlock()

		signed := hookSigning(tester.fetcher)
		proposed := make(chan struct{}, 1)
		tester.fetcher.handleProposedBlock = func(*types.Header) error {
			proposed <- struct{}{}
			return nil
		}
		tester.fetcher.insertBlock = func(*types.Block) error { return nil }
		refused, stale := blockParkedRefusedMeter.Snapshot().Count(), blockParkedStaleMeter.Snapshot().Count()
		tester.fetcher.insert("test", block)

		select {
		case <-proposed:
		case <-time.After(5 * time.Second):
			t.Fatalf("consensus handling never ran for the stale side block")
		}
		if n := blockParkedStaleMeter.Snapshot().Count() - stale; n != 1 {
			t.Fatalf("stale meter moved by %d, want 1", n)
		}
		if n := blockParkedRefusedMeter.Snapshot().Count() - refused; n != 0 {
			t.Fatalf("refused meter moved by %d for a stale side block, want 0", n)
		}
		if n := parkedCount(tester.fetcher); n != 0 {
			t.Fatalf("parked count = %d for a stale side block, want 0", n)
		}
		select {
		case b := <-signed:
			t.Fatalf("sign hook ran for a stale side block: %v", b.Hash())
		case <-time.After(100 * time.Millisecond):
		}
	})
}

func TestParkedSignatureRedeliveryKeepsDeadline(t *testing.T) {
	block := newParkedTestBlock(0x0b)

	tester := newTester()
	defer tester.fetcher.Stop()
	tester.fetcher.signHook = func(*types.Block) error { return nil }

	tester.fetcher.parkForSignature(block)
	first := parkedDeadline(tester.fetcher, block.Hash())
	if first.IsZero() {
		t.Fatalf("block was not parked")
	}
	tester.fetcher.parkForSignature(block)

	if n := parkedCount(tester.fetcher); n != 1 {
		t.Fatalf("parked count = %d after a re-delivery, want 1", n)
	}
	if second := parkedDeadline(tester.fetcher, block.Hash()); !second.Equal(first) {
		t.Fatalf("re-delivery moved the deadline from %v to %v", first, second)
	}
}

func TestParkedSignatureIgnoredAfterStop(t *testing.T) {
	tester := newTester()
	tester.fetcher.signHook = func(*types.Block) error { return nil }
	tester.fetcher.Stop()

	tester.fetcher.parkForSignature(newParkedTestBlock(0x0c))

	if n := parkedCount(tester.fetcher); n != 0 {
		t.Fatalf("parked count = %d after Stop, want 0", n)
	}
	if waiterRunning(tester.fetcher) {
		t.Fatalf("parked waiter was started after Stop")
	}
}

func TestParkedSignatureFailureIsNotRetried(t *testing.T) {
	block := newParkedTestBlock(0x0d)

	tester := newTester()
	var signs int32
	tester.fetcher.signHook = func(*types.Block) error {
		atomic.AddInt32(&signs, 1)
		return errors.New("signing backend unavailable")
	}
	tester.fetcher.parkForSignature(block)
	stopAndDrainWaiter(t, tester.fetcher)
	if _, err := tester.insertChain(types.Blocks{block}); err != nil {
		t.Fatalf("failed to store the parked block: %v", err)
	}

	tester.fetcher.scanParkedSignatures()
	if n := atomic.LoadInt32(&signs); n != 1 {
		t.Fatalf("sign hook ran %d times, want 1", n)
	}
	if n := parkedCount(tester.fetcher); n != 0 {
		t.Fatalf("parked count = %d after a failed signature, want 0", n)
	}
	tester.fetcher.scanParkedSignatures()
	if n := atomic.LoadInt32(&signs); n != 1 {
		t.Fatalf("sign hook ran %d times after the retry scan, want 1", n)
	}
}

func TestDeliverySignatureFailureIsNotRetried(t *testing.T) {
	block := newParkedTestBlock(0x0e)

	tester := newTester()
	defer tester.fetcher.Stop()

	tester.lock.Lock()
	tester.blocks[block.Hash()] = block
	tester.lock.Unlock()
	adoptCanonical(t, tester, block)
	tester.fetcher.insertBlock = func(*types.Block) error { return nil }

	var signs int32
	signed := make(chan struct{}, 1)
	tester.fetcher.signHook = func(*types.Block) error {
		// Only the first call signals, so a second is counted without blocking.
		if atomic.AddInt32(&signs, 1) == 1 {
			signed <- struct{}{}
		}
		return errors.New("signing backend unavailable")
	}
	proposed := make(chan struct{}, 1)
	tester.fetcher.handleProposedBlock = func(*types.Header) error {
		proposed <- struct{}{}
		return nil
	}

	tester.fetcher.insert("test", block)
	select {
	case <-signed:
	case <-time.After(5 * time.Second):
		t.Fatalf("the delivery never attempted a signature")
	}
	// A failed signature returns before the consensus handler runs.
	select {
	case <-proposed:
		t.Fatalf("consensus handling ran after a failed signature")
	case <-time.After(50 * time.Millisecond):
	}
	if n := atomic.LoadInt32(&signs); n != 1 {
		t.Fatalf("sign hook ran %d times, want 1", n)
	}
	tester.fetcher.scanParkedSignatures()
	if n := atomic.LoadInt32(&signs); n != 1 {
		t.Fatalf("sign hook ran %d times after a scan, want 1", n)
	}
	if n := parkedCount(tester.fetcher); n != 0 {
		t.Fatalf("parked count = %d after a failed signature, want 0", n)
	}
}

func TestClaimedParkedSignatureFallsBelowUncleDist(t *testing.T) {
	block := newParkedTestBlock(0x10)

	tester := newTester()
	defer tester.fetcher.Stop()

	tester.lock.Lock()
	tester.blocks[block.Hash()] = block
	tester.lock.Unlock()
	adoptCanonical(t, tester, block)
	parkTestEntry(t, tester.fetcher, block, time.Now().Add(time.Minute), false)

	// The head overtakes the block while the delivery waits for its claim.
	firstVerdict := make(chan struct{}, 1)
	tester.fetcher.canonicalHash = func(uint64) common.Hash {
		select {
		case firstVerdict <- struct{}{}:
		default:
		}
		return block.Hash()
	}
	far := types.NewBlockWithHeader(&types.Header{
		ParentHash: block.Hash(),
		Number:     new(big.Int).SetUint64(block.NumberU64() + maxUncleDist + 1),
		Difficulty: common.Big1,
		GasLimit:   params.GenesisGasLimit,
		Extra:      []byte{0x11},
	}).WithBody(types.Body{})

	var signs int32
	tester.fetcher.signHook = func(*types.Block) error {
		atomic.AddInt32(&signs, 1)
		return nil
	}
	proposed := make(chan struct{}, 1)
	tester.fetcher.handleProposedBlock = func(*types.Header) error {
		proposed <- struct{}{}
		return nil
	}
	tester.fetcher.insertBlock = func(*types.Block) error { return nil }
	stale := blockParkedStaleMeter.Snapshot().Count()

	// Hold parkedMu so the delivery waits for its claim while the head moves.
	tester.fetcher.parkedMu.Lock()
	tester.fetcher.insert("test", block)
	select {
	case <-firstVerdict:
	case <-time.After(5 * time.Second):
		tester.fetcher.parkedMu.Unlock()
		t.Fatalf("the delivery never took the first verdict")
	}
	tester.lock.Lock()
	tester.blocks[far.Hash()] = far
	tester.lock.Unlock()
	adoptCanonical(t, tester, far)
	tester.fetcher.parkedMu.Unlock()

	select {
	case <-proposed:
	case <-time.After(5 * time.Second):
		t.Fatalf("delivery of the claimed block never finished")
	}
	if n := atomic.LoadInt32(&signs); n != 0 {
		t.Fatalf("sign hook ran %d times for a block that fell below the uncle distance, want 0", n)
	}
	if n := blockParkedStaleMeter.Snapshot().Count() - stale; n != 0 {
		t.Fatalf("stale meter moved by %d on the delivery re-check, want 0 (the scan counts it once)", n)
	}
	tester.fetcher.parkedMu.Lock()
	parked, ok := tester.fetcher.parked[block.Hash()]
	claimed := ok && parked.claimed
	tester.fetcher.parkedMu.Unlock()
	if !ok {
		t.Fatalf("entry was dropped instead of being released")
	}
	if claimed {
		t.Fatalf("entry stayed claimed after the re-check refused the signature")
	}
	// The scan drops the released entry on the stale bound and counts it.
	tester.fetcher.scanParkedSignatures()
	if n := parkedCount(tester.fetcher); n != 0 {
		t.Fatalf("parked count = %d after the stale bound, want 0", n)
	}
	if n := blockParkedStaleMeter.Snapshot().Count() - stale; n != 1 {
		t.Fatalf("stale meter moved by %d after the scan dropped the entry, want 1", n)
	}
}

func TestClaimedParkedSignatureEvictedAtDeadline(t *testing.T) {
	block := newParkedTestBlock(0x12)

	tester := newTester()
	defer tester.fetcher.Stop()

	// A claimed entry past its deadline, installed directly; the marker models the hook.
	parkTestEntry(t, tester.fetcher, block, time.Now().Add(-time.Second), true)
	tester.fetcher.parkedMu.Lock()
	tester.fetcher.signing[block.Hash()] = struct{}{}
	tester.fetcher.parkedMu.Unlock()

	deadline := blockParkedDeadlineMeter.Snapshot().Count()
	tester.fetcher.scanParkedSignatures()

	if n := blockParkedDeadlineMeter.Snapshot().Count() - deadline; n != 1 {
		t.Fatalf("deadline meter moved by %d, want 1", n)
	}
	if n := parkedCount(tester.fetcher); n != 0 {
		t.Fatalf("parked count = %d for a claimed entry past its deadline, want 0", n)
	}
	if n := signingCount(tester.fetcher); n != 1 {
		t.Fatalf("in-flight signature count = %d after the slot was freed, want 1", n)
	}

	tester.fetcher.resolveParked(block.Hash(), true)
	if n := signingCount(tester.fetcher); n != 0 {
		t.Fatalf("in-flight signature count = %d after settle, want 0", n)
	}
}

func TestRedeliveryDuringPendingClaimedSignatureIsNotSigned(t *testing.T) {
	block := newParkedTestBlock(0x16)

	tester := newTester()
	defer tester.fetcher.Stop()

	tester.lock.Lock()
	tester.blocks[block.Hash()] = block
	tester.lock.Unlock()
	adoptCanonical(t, tester, block)
	parkTestEntry(t, tester.fetcher, block, time.Now().Add(time.Minute), false)

	var signs int32
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseSigner := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseSigner()

	tester.fetcher.signHook = func(*types.Block) error {
		if atomic.AddInt32(&signs, 1) == 1 {
			entered <- struct{}{}
			<-release
		}
		return nil
	}
	scanDone := make(chan struct{})
	go func() {
		tester.fetcher.scanParkedSignatures()
		close(scanDone)
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatalf("the scan never started the parked signature")
	}

	// The deadline passes while the signature is blocked: the slot frees, the marker stays.
	tester.fetcher.parkedMu.Lock()
	if parked := tester.fetcher.parked[block.Hash()]; parked != nil {
		parked.deadline = time.Now().Add(-time.Second)
	}
	tester.fetcher.parkedMu.Unlock()
	tester.fetcher.scanParkedSignatures()
	evicted := parkedCount(tester.fetcher) == 0
	marked := signingCount(tester.fetcher) == 1

	tester.fetcher.insertBlock = func(*types.Block) error { return nil }
	proposed := make(chan struct{}, 1)
	tester.fetcher.handleProposedBlock = func(*types.Header) error {
		proposed <- struct{}{}
		return nil
	}
	tester.fetcher.insert("test", block)
	select {
	case <-proposed:
	case <-time.After(5 * time.Second):
		t.Fatalf("redelivery of the claimed block never finished")
	}
	releaseSigner()
	<-scanDone
	waitSigningCount(t, tester.fetcher, 0)

	if !evicted {
		t.Fatalf("the claimed entry was not evicted at its deadline")
	}
	if !marked {
		t.Fatalf("the in-flight marker was lost when the parked slot was freed")
	}
	if n := atomic.LoadInt32(&signs); n != 1 {
		t.Fatalf("sign hook ran %d times while the first signature was pending, want 1", n)
	}
	if n := parkedCount(tester.fetcher); n != 0 {
		t.Fatalf("parked count = %d after settle, want 0", n)
	}
}

func TestRedeliveryOfExpiredParkedEntryIsNotSigned(t *testing.T) {
	block := newParkedTestBlock(0x18)

	tester := newTester()
	defer tester.fetcher.Stop()

	tester.lock.Lock()
	tester.blocks[block.Hash()] = block
	tester.lock.Unlock()
	adoptCanonical(t, tester, block)
	parkTestEntry(t, tester.fetcher, block, time.Now().Add(-time.Second), false)

	var signs int32
	tester.fetcher.signHook = func(*types.Block) error {
		atomic.AddInt32(&signs, 1)
		return nil
	}
	tester.fetcher.insertBlock = func(*types.Block) error { return nil }
	proposed := make(chan struct{}, 1)
	tester.fetcher.handleProposedBlock = func(*types.Header) error {
		proposed <- struct{}{}
		return nil
	}
	deadline := blockParkedDeadlineMeter.Snapshot().Count()
	tester.fetcher.insert("test", block)

	select {
	case <-proposed:
	case <-time.After(5 * time.Second):
		t.Fatalf("redelivery of the expired entry never finished")
	}
	if n := atomic.LoadInt32(&signs); n != 0 {
		t.Fatalf("sign hook ran %d times for an expired entry, want 0", n)
	}
	if n := blockParkedDeadlineMeter.Snapshot().Count() - deadline; n != 1 {
		t.Fatalf("deadline meter moved by %d, want 1", n)
	}
	if n := parkedCount(tester.fetcher); n != 0 {
		t.Fatalf("parked count = %d for the expired entry, want 0", n)
	}
	if n := signingCount(tester.fetcher); n != 0 {
		t.Fatalf("in-flight signature count = %d for the expired entry, want 0", n)
	}
}

func TestParkedSignatureInFlightBlocksRestore(t *testing.T) {
	block := newParkedTestBlock(0x17)

	tester := newTester()
	defer tester.fetcher.Stop()
	tester.fetcher.signHook = func(*types.Block) error { return nil }

	if ok, _ := tester.fetcher.claimParkedSignature(block.Hash()); !ok {
		t.Fatalf("the empty parked set refused a claim")
	}
	if n := signingCount(tester.fetcher); n != 1 {
		t.Fatalf("in-flight signature count = %d after the claim, want 1", n)
	}
	tester.fetcher.parkForSignature(block)
	if n := parkedCount(tester.fetcher); n != 0 {
		t.Fatalf("parked count = %d for a hash whose signature is in flight, want 0", n)
	}

	tester.fetcher.resolveParked(block.Hash(), false)
	if n := signingCount(tester.fetcher); n != 0 {
		t.Fatalf("in-flight signature count = %d after settle, want 0", n)
	}
	tester.fetcher.parkForSignature(block)
	if n := parkedCount(tester.fetcher); n != 1 {
		t.Fatalf("parked count = %d after the signature settled, want 1", n)
	}
}

func TestParkedSignatureScanSkippedWhileSyncing(t *testing.T) {
	block := newParkedTestBlock(0x13)

	tester := newTester()
	defer tester.fetcher.Stop()

	tester.lock.Lock()
	tester.blocks[block.Hash()] = block
	tester.lock.Unlock()
	adoptCanonical(t, tester, block)
	parkTestEntry(t, tester.fetcher, block, time.Now().Add(time.Minute), false)

	var signs int32
	tester.fetcher.signHook = func(*types.Block) error {
		atomic.AddInt32(&signs, 1)
		return nil
	}
	tester.syncing.Store(true)
	tester.fetcher.scanParkedSignatures()
	if n := atomic.LoadInt32(&signs); n != 0 {
		t.Fatalf("sign hook ran %d times while snap syncing, want 0", n)
	}
	if n := parkedCount(tester.fetcher); n != 1 {
		t.Fatalf("parked count = %d while snap syncing, want 1", n)
	}

	tester.syncing.Store(false)
	tester.fetcher.scanParkedSignatures()
	if n := atomic.LoadInt32(&signs); n != 1 {
		t.Fatalf("sign hook ran %d times after the sync, want 1", n)
	}
	if n := parkedCount(tester.fetcher); n != 0 {
		t.Fatalf("parked count = %d after the signature, want 0", n)
	}
}

func TestParkedSignatureScanBoundsFrozenWhileSyncing(t *testing.T) {
	block := newParkedTestBlock(0x27)

	tester := newTester()
	defer tester.fetcher.Stop()

	parkTestEntry(t, tester.fetcher, block, time.Now().Add(-time.Second), false)
	tester.syncing.Store(true)
	tester.fetcher.scanParkedSignatures()
	if n := parkedCount(tester.fetcher); n != 1 {
		t.Fatalf("parked count = %d while snap syncing, want 1: the scan must not evaluate the bounds during the sync", n)
	}

	tester.syncing.Store(false)
	tester.fetcher.scanParkedSignatures()
	if n := parkedCount(tester.fetcher); n != 0 {
		t.Fatalf("parked count = %d after the sync, want 0 for the expired entry", n)
	}
}

func TestParkedSignatureWaiterDoesNotSignAfterStop(t *testing.T) {
	block := newParkedTestBlock(0x14)

	tester := newTester()
	tester.fetcher.parkedTimeout = time.Minute

	tester.lock.Lock()
	tester.blocks[block.Hash()] = block
	tester.lock.Unlock()
	adoptCanonical(t, tester, block)
	var signs int32
	tester.fetcher.signHook = func(*types.Block) error {
		atomic.AddInt32(&signs, 1)
		return nil
	}
	tester.fetcher.parkForSignature(block)
	tester.fetcher.Stop()

	deadline := time.Now().Add(2 * time.Second)
	for waiterRunning(tester.fetcher) {
		if time.Now().After(deadline) {
			t.Fatalf("parked waiter did not stop after the fetcher was stopped")
		}
		time.Sleep(time.Millisecond)
	}
	// Two tick periods past the stop: a slipped scan would have signed by now.
	time.Sleep(2 * parkedImportPollInterval)
	if n := atomic.LoadInt32(&signs); n != 0 {
		t.Fatalf("sign hook ran %d times after Stop, want 0", n)
	}
}

func TestParkedSignatureStopsBetweenReadyBlocks(t *testing.T) {
	blockA := newParkedTestBlock(0x1a)
	blockB := types.NewBlockWithHeader(&types.Header{
		ParentHash: blockA.Hash(),
		Number:     common.Big2,
		Difficulty: common.Big1,
		GasLimit:   params.GenesisGasLimit,
		Extra:      []byte{0x1b},
	}).WithBody(types.Body{})

	tester := newTester()
	stop := sync.OnceFunc(func() { tester.fetcher.Stop() })
	defer stop()

	tester.lock.Lock()
	tester.blocks[blockA.Hash()] = blockA
	tester.blocks[blockB.Hash()] = blockB
	tester.lock.Unlock()
	adoptCanonical(t, tester, blockA)
	adoptCanonical(t, tester, blockB)

	var signs int32
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	defer unblock()
	tester.fetcher.signHook = func(block *types.Block) error {
		atomic.AddInt32(&signs, 1)
		if block.Hash() == blockA.Hash() {
			entered <- struct{}{}
			<-release
		}
		return nil
	}
	parkTestEntry(t, tester.fetcher, blockA, time.Now().Add(time.Minute), true)
	parkTestEntry(t, tester.fetcher, blockB, time.Now().Add(time.Minute), true)
	tester.fetcher.parkedMu.Lock()
	tester.fetcher.signing[blockA.Hash()] = struct{}{}
	tester.fetcher.signing[blockB.Hash()] = struct{}{}
	tester.fetcher.parkedMu.Unlock()

	done := make(chan struct{})
	go func() {
		tester.fetcher.signReadyParked([]readySignature{
			{block: blockA, deadline: time.Now().Add(time.Minute)},
			{block: blockB, deadline: time.Now().Add(time.Minute)},
		}, tester.fetcher.quit)
		close(done)
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatalf("sign hook never ran for the first ready block")
	}
	stop()
	unblock()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("signing did not return after Stop")
	}

	if n := atomic.LoadInt32(&signs); n != 1 {
		t.Fatalf("sign hook ran %d times, want 1: the block after the stopped one must not be signed", n)
	}
	tester.fetcher.parkedMu.Lock()
	parked, ok := tester.fetcher.parked[blockB.Hash()]
	_, inFlight := tester.fetcher.signing[blockB.Hash()]
	tester.fetcher.parkedMu.Unlock()
	if !ok {
		t.Fatalf("the unattempted entry was dropped instead of released")
	}
	if parked.claimed {
		t.Fatalf("the unattempted entry stayed claimed after Stop")
	}
	if inFlight {
		t.Fatalf("the unattempted entry kept its in-flight marker after Stop")
	}
}

func TestParkedSignatureRecheckRespectsSnapSync(t *testing.T) {
	block := newParkedTestBlock(0x1d)

	tester := newTester()
	defer tester.fetcher.Stop()

	tester.lock.Lock()
	tester.blocks[block.Hash()] = block
	tester.lock.Unlock()
	adoptCanonical(t, tester, block)

	var signs int32
	tester.fetcher.signHook = func(*types.Block) error {
		atomic.AddInt32(&signs, 1)
		return nil
	}
	parkTestEntry(t, tester.fetcher, block, time.Now().Add(time.Minute), true)
	tester.fetcher.parkedMu.Lock()
	tester.fetcher.signing[block.Hash()] = struct{}{}
	tester.fetcher.parkedMu.Unlock()

	tester.syncing.Store(true)
	tester.fetcher.signReadyParked([]readySignature{{block: block, deadline: time.Now().Add(time.Minute)}}, tester.fetcher.quit)
	if n := atomic.LoadInt32(&signs); n != 0 {
		t.Fatalf("sign hook ran %d times during a snap sync, want 0", n)
	}
	tester.fetcher.parkedMu.Lock()
	parked, ok := tester.fetcher.parked[block.Hash()]
	claimed := parked != nil && parked.claimed
	_, inFlight := tester.fetcher.signing[block.Hash()]
	tester.fetcher.parkedMu.Unlock()
	if !ok {
		t.Fatalf("the entry was dropped instead of released")
	}
	if claimed {
		t.Fatalf("the entry stayed claimed during the sync")
	}
	if inFlight {
		t.Fatalf("the entry kept its in-flight marker during the sync")
	}
	// The entry is still usable: once the sync ends, a scan signs it.
	tester.syncing.Store(false)
	tester.fetcher.scanParkedSignatures()
	if n := atomic.LoadInt32(&signs); n != 1 {
		t.Fatalf("sign hook ran %d times after the sync ended, want 1", n)
	}
}

func TestParkedSignatureWaiterStopsMidBatch(t *testing.T) {
	blockA := newParkedTestBlock(0x1e)
	blockB := types.NewBlockWithHeader(&types.Header{
		ParentHash: blockA.Hash(),
		Number:     common.Big2,
		Difficulty: common.Big1,
		GasLimit:   params.GenesisGasLimit,
		Extra:      []byte{0x1f},
	}).WithBody(types.Body{})

	tester := newTester()
	stop := sync.OnceFunc(func() { tester.fetcher.Stop() })
	defer stop()

	tester.lock.Lock()
	tester.blocks[blockA.Hash()] = blockA
	tester.blocks[blockB.Hash()] = blockB
	tester.lock.Unlock()
	adoptCanonical(t, tester, blockA)
	adoptCanonical(t, tester, blockB)

	var signs int32
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	defer unblock()
	tester.fetcher.signHook = func(*types.Block) error {
		// Only the first call blocks, so a second signature is counted.
		if atomic.AddInt32(&signs, 1) == 1 {
			entered <- struct{}{}
			<-release
		}
		return nil
	}
	// Both entries are installed under one lock before the waiter starts, so its
	// first tick collects one batch; two parks could split it.
	tester.fetcher.parkedMu.Lock()
	tester.fetcher.parkLocked(blockA)
	tester.fetcher.parkLocked(blockB)
	tester.fetcher.parkedMu.Unlock()
	go tester.fetcher.waitParkedSignatures()
	waitSigningCount(t, tester.fetcher, 2)

	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatalf("the waiter never started a signature")
	}
	stop()
	unblock()
	waitSigningCount(t, tester.fetcher, 0)

	if n := atomic.LoadInt32(&signs); n != 1 {
		t.Fatalf("sign hook ran %d times, want 1: the block after the stopped one must not be signed", n)
	}
	if n := parkedCount(tester.fetcher); n != 1 {
		t.Fatalf("parked count = %d after the stop, want 1: the unattempted entry must survive", n)
	}
	tester.fetcher.parkedMu.Lock()
	var surviving *parkedBlock
	for _, parked := range tester.fetcher.parked {
		surviving = parked
	}
	tester.fetcher.parkedMu.Unlock()
	if surviving == nil {
		t.Fatalf("the unattempted entry was dropped instead of kept")
	}
	if surviving.claimed {
		t.Fatalf("the unattempted entry stayed claimed after the stop")
	}
}

func TestParkedSignatureEvictionContinuesWhileHookBlocked(t *testing.T) {
	blockA := newParkedTestBlock(0x1c)
	blockB := newParkedTestBlock(0x1d)

	tester := newTester()
	defer tester.fetcher.Stop()

	tester.lock.Lock()
	tester.blocks[blockA.Hash()] = blockA
	tester.lock.Unlock()
	adoptCanonical(t, tester, blockA)

	var inHook int32
	release := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	defer unblock()
	tester.fetcher.signHook = func(*types.Block) error {
		atomic.StoreInt32(&inHook, 1)
		<-release
		atomic.StoreInt32(&inHook, 0)
		return nil
	}
	// A blocks the hook; B is never stored, so only its deadline can remove it.
	tester.fetcher.parkForSignature(blockA)
	parkTestEntry(t, tester.fetcher, blockB, time.Now().Add(150*time.Millisecond), false)

	timeout := time.Now().Add(5 * time.Second)
	for atomic.LoadInt32(&inHook) == 0 || parkedCount(tester.fetcher) != 1 {
		if time.Now().After(timeout) {
			t.Fatalf("the expired entry was not evicted while the hook was blocked: parked count = %d", parkedCount(tester.fetcher))
		}
		time.Sleep(time.Millisecond)
	}
	unblock()
	waitParkedCount(t, tester.fetcher, 0)
}

func TestParkedSignatureBatchBoundWhileHookBlocked(t *testing.T) {
	blockA := newParkedTestBlock(0x21)
	blockB := types.NewBlockWithHeader(&types.Header{
		ParentHash: blockA.Hash(),
		Number:     common.Big2,
		Difficulty: common.Big1,
		GasLimit:   params.GenesisGasLimit,
		Extra:      []byte{0x22},
	}).WithBody(types.Body{})

	tester := newTester()
	defer tester.fetcher.Stop()

	tester.lock.Lock()
	tester.blocks[blockA.Hash()] = blockA
	tester.blocks[blockB.Hash()] = blockB
	tester.lock.Unlock()
	adoptCanonical(t, tester, blockA)
	adoptCanonical(t, tester, blockB)

	var signs int32
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	defer unblock()
	tester.fetcher.signHook = func(block *types.Block) error {
		atomic.AddInt32(&signs, 1)
		if block.Hash() == blockA.Hash() {
			entered <- struct{}{}
			<-release
		}
		return nil
	}
	tester.fetcher.parkForSignature(blockA)
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatalf("the first parked signature never ran")
	}
	tester.fetcher.parkForSignature(blockB)
	time.Sleep(3 * parkedImportPollInterval)

	if n := signingCount(tester.fetcher); n != 1 {
		t.Fatalf("in-flight signature count = %d while the hook is blocked, want 1", n)
	}
	if n := atomic.LoadInt32(&signs); n != 1 {
		t.Fatalf("sign hook ran %d times while blocked, want 1", n)
	}
	tester.fetcher.parkedMu.Lock()
	parked, ok := tester.fetcher.parked[blockB.Hash()]
	claimed := ok && parked.claimed
	tester.fetcher.parkedMu.Unlock()
	if !ok {
		t.Fatalf("the second block was dropped instead of parked")
	}
	if claimed {
		t.Fatalf("the second block was claimed while an earlier batch was still running")
	}

	unblock()
	waitParkedCount(t, tester.fetcher, 0)
	if n := atomic.LoadInt32(&signs); n != 2 {
		t.Fatalf("sign hook ran %d times after the blocked batch finished, want 2", n)
	}
}

func TestRefusedClaimKeepsParkedDeadline(t *testing.T) {
	block := newParkedTestBlock(0x23)

	tester := newTester()
	defer tester.fetcher.Stop()

	parkTestEntry(t, tester.fetcher, block, time.Now().Add(20*time.Millisecond), false)
	ok, tookEntry := tester.fetcher.claimParkedSignature(block.Hash())
	if !ok || !tookEntry {
		t.Fatalf("claim = (%v, %v), want (true, true)", ok, tookEntry)
	}
	time.Sleep(40 * time.Millisecond)

	expired := blockParkedDeadlineMeter.Snapshot().Count()
	tester.fetcher.settleRefusedClaim(block, tookEntry)

	if n := parkedCount(tester.fetcher); n != 0 {
		t.Fatalf("parked count = %d after an expired claim was refused, want 0 (no recreated entry)", n)
	}
	if n := signingCount(tester.fetcher); n != 0 {
		t.Fatalf("in-flight signature count = %d after the refused claim, want 0", n)
	}
	if n := blockParkedDeadlineMeter.Snapshot().Count() - expired; n != 1 {
		t.Fatalf("deadline meter moved by %d, want 1", n)
	}
}

func TestRefusedClaimParksEntrylessClaim(t *testing.T) {
	block := newParkedTestBlock(0x24)

	tester := newTester()
	defer tester.fetcher.Stop()
	tester.fetcher.signHook = func(*types.Block) error { return nil }

	ok, tookEntry := tester.fetcher.claimParkedSignature(block.Hash())
	if !ok || tookEntry {
		t.Fatalf("claim = (%v, %v), want (true, false)", ok, tookEntry)
	}
	before := time.Now()
	tester.fetcher.settleRefusedClaim(block, tookEntry)

	if n := parkedCount(tester.fetcher); n != 1 {
		t.Fatalf("parked count = %d for an entry-less refused claim, want 1", n)
	}
	deadline := parkedDeadline(tester.fetcher, block.Hash())
	if deadline.Before(before.Add(tester.fetcher.parkedTimeout - time.Second)) {
		t.Fatalf("recreated entry deadline = %v, want a fresh bound", deadline)
	}
	if n := signingCount(tester.fetcher); n != 0 {
		t.Fatalf("in-flight signature count = %d, want 0", n)
	}
}

func TestStoredBlockSignatureRespectsSnapSyncAfterClaim(t *testing.T) {
	block := newParkedTestBlock(0x25)

	tester := newTester()
	defer tester.fetcher.Stop()

	tester.lock.Lock()
	tester.blocks[block.Hash()] = block
	tester.lock.Unlock()
	adoptCanonical(t, tester, block)
	tester.fetcher.insertBlock = func(*types.Block) error { return nil }

	var signs int32
	tester.fetcher.signHook = func(*types.Block) error {
		atomic.AddInt32(&signs, 1)
		return nil
	}
	// The claim-time gate sees a synced node; the re-check sees the sync starting.
	var syncCalls int32
	tester.fetcher.syncing = func() bool {
		return atomic.AddInt32(&syncCalls, 1) > 1
	}
	proposed := make(chan struct{}, 1)
	tester.fetcher.handleProposedBlock = func(*types.Header) error {
		proposed <- struct{}{}
		return nil
	}
	tester.fetcher.insert("test", block)

	select {
	case <-proposed:
	case <-time.After(5 * time.Second):
		t.Fatalf("delivery of the deferred-signature block never finished")
	}
	if n := atomic.LoadInt32(&signs); n != 0 {
		t.Fatalf("sign hook ran %d times for a block whose claim overlapped snap sync, want 0", n)
	}
	if n := signingCount(tester.fetcher); n != 0 {
		t.Fatalf("in-flight signature count = %d after the deferred signature, want 0", n)
	}
}

func TestParkedSignatureDroppedWhenDeadlinePassesDuringBlockedHook(t *testing.T) {
	blockA := newParkedTestBlock(0x26)
	blockB := types.NewBlockWithHeader(&types.Header{
		ParentHash: blockA.Hash(),
		Number:     common.Big2,
		Difficulty: common.Big1,
		GasLimit:   params.GenesisGasLimit,
		Extra:      []byte{0x27},
	}).WithBody(types.Body{})

	tester := newTester()
	defer tester.fetcher.Stop()

	tester.lock.Lock()
	tester.blocks[blockA.Hash()] = blockA
	tester.blocks[blockB.Hash()] = blockB
	tester.lock.Unlock()
	adoptCanonical(t, tester, blockA)
	adoptCanonical(t, tester, blockB)

	var signs int32
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	defer unblock()
	tester.fetcher.signHook = func(block *types.Block) error {
		atomic.AddInt32(&signs, 1)
		if block.Hash() == blockA.Hash() {
			entered <- struct{}{}
			<-release
		}
		return nil
	}
	deadlineB := time.Now().Add(80 * time.Millisecond)
	parkTestEntry(t, tester.fetcher, blockA, time.Now().Add(time.Minute), true)
	parkTestEntry(t, tester.fetcher, blockB, deadlineB, true)
	tester.fetcher.parkedMu.Lock()
	tester.fetcher.signing[blockA.Hash()] = struct{}{}
	tester.fetcher.signing[blockB.Hash()] = struct{}{}
	tester.fetcher.parkedMu.Unlock()

	ready := []readySignature{
		{block: blockA, deadline: time.Now().Add(time.Minute)},
		{block: blockB, deadline: deadlineB},
	}
	done := make(chan struct{})
	go func() {
		tester.fetcher.signReadyParked(ready, nil)
		close(done)
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatalf("the first ready block was never signed")
	}
	for time.Now().Before(deadlineB) {
		time.Sleep(time.Millisecond)
	}
	unblock()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("signing did not return after the blocked hook was released")
	}

	if n := atomic.LoadInt32(&signs); n != 1 {
		t.Fatalf("sign hook ran %d times, want 1: a block whose deadline passed during the batch must not be signed", n)
	}
	tester.fetcher.parkedMu.Lock()
	_, inFlight := tester.fetcher.signing[blockB.Hash()]
	_, parked := tester.fetcher.parked[blockB.Hash()]
	tester.fetcher.parkedMu.Unlock()
	if inFlight {
		t.Fatalf("the expired block's in-flight marker was not released")
	}
	if !parked {
		t.Fatalf("the expired entry was dropped instead of left to the scan's bound")
	}
}

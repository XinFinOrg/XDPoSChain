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

package downloader

import (
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ethereum "github.com/XinFinOrg/XDPoSChain"
	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/ethdb"
	"github.com/XinFinOrg/XDPoSChain/event"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/XinFinOrg/XDPoSChain/trie"
)

// Reduce some of the parameters to make the tester faster.
func init() {
	MaxForkAncestry = uint64(10000)
	blockCacheMaxItems = 1024
	fsHeaderContCheck = 500 * time.Millisecond
}

// downloadTester is a test simulator for mocking out local block chain.
// TODO(daniel): remove field triedb
type downloadTester struct {
	downloader *Downloader
	triedb     *trie.Database

	genesis *types.Block   // Genesis blocks used by the tester and peers
	stateDb ethdb.Database // Database used by the tester for syncing from peers
	peerDb  ethdb.Database // Database of the peers containing all data
	peers   map[string]*downloadTesterPeer

	ownHashes   []common.Hash                  // Hash chain belonging to the tester
	ownHeaders  map[common.Hash]*types.Header  // Headers belonging to the tester
	ownBlocks   map[common.Hash]*types.Block   // Blocks belonging to the tester
	ownReceipts map[common.Hash]types.Receipts // Receipts belonging to the tester
	ownChainTd  map[common.Hash]*big.Int       // Total difficulties of the blocks in the local chain

	insertHeaderChainHook func([]*types.Header) error

	lock sync.RWMutex
}

// newTester creates a new downloader test mocker.
func newTester() *downloadTester {
	tester := &downloadTester{
		genesis:     testGenesis,
		peerDb:      testDB,
		peers:       make(map[string]*downloadTesterPeer),
		ownHashes:   []common.Hash{testGenesis.Hash()},
		ownHeaders:  map[common.Hash]*types.Header{testGenesis.Hash(): testGenesis.Header()},
		ownBlocks:   map[common.Hash]*types.Block{testGenesis.Hash(): testGenesis},
		ownReceipts: map[common.Hash]types.Receipts{testGenesis.Hash(): nil},
		ownChainTd:  map[common.Hash]*big.Int{testGenesis.Hash(): testGenesis.Difficulty()},
	}
	tester.stateDb = rawdb.NewMemoryDatabase()
	tester.triedb = trie.NewDatabase(tester.stateDb)
	tester.stateDb.Put(testGenesis.Root().Bytes(), []byte{0x00})
	tester.downloader = New(tester.stateDb, new(event.TypeMux), tester, nil, tester.dropPeer, tester.handleProposedBlock)
	return tester
}

func (dl *downloadTester) TrieDB() *trie.Database {
	return dl.triedb
}

// terminate aborts any operations on the embedded downloader and releases all
// held resources.
func (dl *downloadTester) terminate() {
	dl.downloader.Terminate()
}

// sync starts synchronizing with a remote peer, blocking until it completes.
func (dl *downloadTester) sync(id string, td *big.Int, mode SyncMode) error {
	dl.lock.RLock()
	hash := dl.peers[id].chain.headBlock().Hash()
	// If no particular TD was requested, load from the peer's blockchain
	if td == nil {
		td = dl.peers[id].chain.td(hash)
	}
	dl.lock.RUnlock()

	// Synchronise with the chosen peer and ensure proper cleanup afterwards
	err := dl.downloader.synchronise(id, hash, td, mode)
	select {
	case <-dl.downloader.cancelCh:
		// Ok, downloader fully cancelled after sync cycle
	default:
		// Downloader is still accepting packets, can block a peer up
		panic("downloader active post sync cycle") // panic will be caught by tester
	}
	return err
}

// HasHeader checks if a header is present in the testers canonical chain.
func (dl *downloadTester) HasHeader(hash common.Hash, number uint64) bool {
	return dl.GetHeaderByHash(hash) != nil
}

// HasBlock checks if a block is present in the testers canonical chain.
func (dl *downloadTester) HasBlock(hash common.Hash, number uint64) bool {
	return dl.GetBlockByHash(hash) != nil
}

// HasFastBlock checks if a block is present in the testers canonical chain.
func (dl *downloadTester) HasFastBlock(hash common.Hash, number uint64) bool {
	dl.lock.RLock()
	defer dl.lock.RUnlock()

	_, ok := dl.ownReceipts[hash]
	return ok
}

// GetHeader retrieves a header from the testers canonical chain.
func (dl *downloadTester) GetHeaderByHash(hash common.Hash) *types.Header {
	dl.lock.RLock()
	defer dl.lock.RUnlock()
	return dl.getHeaderByHash(hash)
}

// getHeaderByHash returns the header if found either within ancients or own blocks)
// This method assumes that the caller holds at least the read-lock (dl.lock)
func (dl *downloadTester) getHeaderByHash(hash common.Hash) *types.Header {
	return dl.ownHeaders[hash]
}

// GetBlock retrieves a block from the testers canonical chain.
func (dl *downloadTester) GetBlockByHash(hash common.Hash) *types.Block {
	dl.lock.RLock()
	defer dl.lock.RUnlock()

	return dl.ownBlocks[hash]
}

// CurrentHeader retrieves the current head header from the canonical chain.
func (dl *downloadTester) CurrentHeader() *types.Header {
	dl.lock.RLock()
	defer dl.lock.RUnlock()

	for i := len(dl.ownHashes) - 1; i >= 0; i-- {
		if header := dl.ownHeaders[dl.ownHashes[i]]; header != nil {
			return header
		}
	}
	return dl.genesis.Header()
}

// CurrentBlock retrieves the current head block from the canonical chain.
func (dl *downloadTester) CurrentBlock() *types.Header {
	dl.lock.RLock()
	defer dl.lock.RUnlock()

	for i := len(dl.ownHashes) - 1; i >= 0; i-- {
		if block := dl.ownBlocks[dl.ownHashes[i]]; block != nil {
			if _, err := dl.stateDb.Get(block.Root().Bytes()); err == nil {
				return block.Header()
			}
		}
	}
	return dl.genesis.Header()
}

// CurrentFastBlock retrieves the current head fast-sync block from the canonical chain.
func (dl *downloadTester) CurrentSnapBlock() *types.Header {
	dl.lock.RLock()
	defer dl.lock.RUnlock()

	for i := len(dl.ownHashes) - 1; i >= 0; i-- {
		if block := dl.ownBlocks[dl.ownHashes[i]]; block != nil {
			return block.Header()
		}
	}
	return dl.genesis.Header()
}

// FastSyncCommitHead manually sets the head block to a given hash.
func (dl *downloadTester) FastSyncCommitHead(hash common.Hash) error {
	// For now only check that the state trie is correct
	if block := dl.GetBlockByHash(hash); block != nil {
		_, err := trie.NewStateTrie(trie.StateTrieID(block.Root()), trie.NewDatabase(dl.stateDb))
		return err
	}
	return fmt.Errorf("non existent block: %x", hash[:4])
}

// GetTd retrieves the block's total difficulty from the canonical chain.
func (dl *downloadTester) GetTd(hash common.Hash, number uint64) *big.Int {
	dl.lock.RLock()
	defer dl.lock.RUnlock()
	return dl.getTd(hash)
}

// getTd retrieves the block's total difficulty if found either within
// ancients or own blocks).
// This method assumes that the caller holds at least the read-lock (dl.lock)
func (dl *downloadTester) getTd(hash common.Hash) *big.Int {
	return dl.ownChainTd[hash]
}

// InsertHeaderChain injects a new batch of headers into the simulated chain.
func (dl *downloadTester) InsertHeaderChain(headers []*types.Header, checkFreq int) (i int, err error) {
	dl.lock.Lock()
	defer dl.lock.Unlock()
	if dl.insertHeaderChainHook != nil {
		if err := dl.insertHeaderChainHook(headers); err != nil {
			return 0, err
		}
	}
	// Do a quick check, as the blockchain.InsertHeaderChain doesn't insert anything in case of errors
	if dl.getHeaderByHash(headers[0].ParentHash) == nil {
		return 0, fmt.Errorf("InsertHeaderChain: unknown parent at first position, parent of number %d", headers[0].Number)
	}
	var hashes []common.Hash
	for i := 1; i < len(headers); i++ {
		hash := headers[i-1].Hash()
		if headers[i].ParentHash != headers[i-1].Hash() {
			return i, fmt.Errorf("non-contiguous import at position %d", i)
		}
		hashes = append(hashes, hash)
	}
	hashes = append(hashes, headers[len(headers)-1].Hash())
	// Do a full insert if pre-checks passed
	for i, header := range headers {
		hash := hashes[i]
		if dl.getHeaderByHash(hash) != nil {
			continue
		}
		if dl.getHeaderByHash(header.ParentHash) == nil {
			// This _should_ be impossible, due to precheck and induction
			return i, fmt.Errorf("InsertHeaderChain: unknown parent at position %d", i)
		}
		dl.ownHashes = append(dl.ownHashes, hash)
		dl.ownHeaders[hash] = header

		td := dl.getTd(header.ParentHash)
		dl.ownChainTd[hash] = new(big.Int).Add(td, header.Difficulty)
	}
	return len(headers), nil
}

// InsertChain injects a new batch of blocks into the simulated chain.
func (dl *downloadTester) InsertChain(blocks types.Blocks) (i int, err error) {
	dl.lock.Lock()
	defer dl.lock.Unlock()

	for i, block := range blocks {
		if parent, ok := dl.ownBlocks[block.ParentHash()]; !ok {
			return i, fmt.Errorf("InsertChain: unknown parent at position %d / %d", i, len(blocks))
		} else if _, err := dl.stateDb.Get(parent.Root().Bytes()); err != nil {
			return i, fmt.Errorf("InsertChain: unknown parent state %x: %v", parent.Root(), err)
		}
		if _, ok := dl.ownHeaders[block.Hash()]; !ok {
			dl.ownHashes = append(dl.ownHashes, block.Hash())
			dl.ownHeaders[block.Hash()] = block.Header()
		}
		dl.ownBlocks[block.Hash()] = block
		dl.stateDb.Put(block.Root().Bytes(), []byte{0x00})
		dl.ownChainTd[block.Hash()] = new(big.Int).Add(dl.ownChainTd[block.ParentHash()], block.Difficulty())
	}
	return len(blocks), nil
}

// InsertReceiptChain injects a new batch of receipts into the simulated chain.
func (dl *downloadTester) InsertReceiptChain(blocks types.Blocks, receipts []types.Receipts) (i int, err error) {
	dl.lock.Lock()
	defer dl.lock.Unlock()

	for i := 0; i < len(blocks) && i < len(receipts); i++ {
		if _, ok := dl.ownHeaders[blocks[i].Hash()]; !ok {
			return i, errors.New("unknown owner")
		}
		if _, ok := dl.ownBlocks[blocks[i].ParentHash()]; !ok {
			return i, errors.New("InsertReceiptChain: unknown parent")
		}
		dl.ownBlocks[blocks[i].Hash()] = blocks[i]
		dl.ownReceipts[blocks[i].Hash()] = receipts[i]
	}
	return len(blocks), nil
}

// Rollback removes some recently added elements from the chain.
func (dl *downloadTester) Rollback(hashes []common.Hash) {
	dl.lock.Lock()
	defer dl.lock.Unlock()

	for i := len(hashes) - 1; i >= 0; i-- {
		if dl.ownHashes[len(dl.ownHashes)-1] == hashes[i] {
			dl.ownHashes = dl.ownHashes[:len(dl.ownHashes)-1]
		}
		delete(dl.ownChainTd, hashes[i])
		delete(dl.ownHeaders, hashes[i])
		delete(dl.ownReceipts, hashes[i])
		delete(dl.ownBlocks, hashes[i])
	}
}

// newPeer registers a new block download source into the downloader.
func (dl *downloadTester) newPeer(id string, version int, chain *testChain) error {
	dl.lock.Lock()
	defer dl.lock.Unlock()

	peer := &downloadTesterPeer{dl: dl, id: id, chain: chain}
	dl.peers[id] = peer
	return dl.downloader.RegisterPeer(id, version, peer)
}

// dropPeer simulates a hard peer removal from the connection pool.
func (dl *downloadTester) dropPeer(id string) {
	dl.lock.Lock()
	defer dl.lock.Unlock()

	delete(dl.peers, id)
	dl.downloader.UnregisterPeer(id)
}

// an empty handleProposedBlock function
func (dl *downloadTester) handleProposedBlock(header *types.Header) error {
	return nil
}

// Config retrieves the blockchain's chain configuration.
func (dl *downloadTester) Config() *params.ChainConfig {
	config := *testChainConfig
	return &config
}

func (dl *downloadTester) InterruptInsert(on bool) {
}

type downloadTesterPeer struct {
	dl            *downloadTester
	id            string
	chain         *testChain
	missingStates map[common.Hash]bool // State entries that fast sync should not return
}

// Head constructs a function to retrieve a peer's current head hash
// and total difficulty.
func (dlp *downloadTesterPeer) Head() (common.Hash, *big.Int) {
	b := dlp.chain.headBlock()
	return b.Hash(), dlp.chain.td(b.Hash())
}

// RequestHeadersByHash constructs a GetBlockHeaders function based on a hashed
// origin; associated with a particular peer in the download tester. The returned
// function can be used to retrieve batches of headers from the particular peer.
func (dlp *downloadTesterPeer) RequestHeadersByHash(origin common.Hash, amount int, skip int, reverse bool) error {
	if reverse {
		panic("reverse header requests not supported")
	}

	result := dlp.chain.headersByHash(origin, amount, skip)
	go dlp.dl.downloader.DeliverHeaders(dlp.id, result)
	return nil
}

// RequestHeadersByNumber constructs a GetBlockHeaders function based on a numbered
// origin; associated with a particular peer in the download tester. The returned
// function can be used to retrieve batches of headers from the particular peer.
func (dlp *downloadTesterPeer) RequestHeadersByNumber(origin uint64, amount int, skip int, reverse bool) error {
	if reverse {
		panic("reverse header requests not supported")
	}

	result := dlp.chain.headersByNumber(origin, amount, skip)
	go dlp.dl.downloader.DeliverHeaders(dlp.id, result)
	return nil
}

// RequestBodies constructs a getBlockBodies method associated with a particular
// peer in the download tester. The returned function can be used to retrieve
// batches of block bodies from the particularly requested peer.
func (dlp *downloadTesterPeer) RequestBodies(hashes []common.Hash) error {
	txs, uncles := dlp.chain.bodies(hashes)
	go dlp.dl.downloader.DeliverBodies(dlp.id, txs, uncles)
	return nil
}

// RequestReceipts constructs a getReceipts method associated with a particular
// peer in the download tester. The returned function can be used to retrieve
// batches of block receipts from the particularly requested peer.
func (dlp *downloadTesterPeer) RequestReceipts(hashes []common.Hash) error {
	receipts := dlp.chain.receipts(hashes)
	go dlp.dl.downloader.DeliverReceipts(dlp.id, receipts)
	return nil
}

// RequestNodeData constructs a getNodeData method associated with a particular
// peer in the download tester. The returned function can be used to retrieve
// batches of node state data from the particularly requested peer.
func (dlp *downloadTesterPeer) RequestNodeData(hashes []common.Hash) error {
	dlp.dl.lock.RLock()
	defer dlp.dl.lock.RUnlock()

	results := make([][]byte, 0, len(hashes))
	for _, hash := range hashes {
		if data, err := dlp.dl.peerDb.Get(hash.Bytes()); err == nil {
			if !dlp.missingStates[hash] {
				results = append(results, data)
			}
		}
	}
	go dlp.dl.downloader.DeliverNodeData(dlp.id, results)
	return nil
}

// assertOwnChain checks if the local chain contains the correct number of items
// of the various chain components.
func assertOwnChain(t *testing.T, tester *downloadTester, length int) {
	assertOwnForkedChain(t, tester, 1, []int{length})
}

// assertOwnForkedChain checks if the local forked chain contains the correct
// number of items of the various chain components.
func assertOwnForkedChain(t *testing.T, tester *downloadTester, common int, lengths []int) {
	// Initialize the counters for the first fork
	headers, blocks, receipts := lengths[0], lengths[0], lengths[0]-fsMinFullBlocks

	if receipts < 0 {
		receipts = 1
	}
	// Update the counters for each subsequent fork
	for _, length := range lengths[1:] {
		headers += length - common
		blocks += length - common
		receipts += length - common - fsMinFullBlocks
	}
	switch SyncMode(tester.downloader.mode) {
	case FullSync:
		receipts = 1
	case LightSync:
		blocks, receipts = 1, 1
	}
	if hs := len(tester.ownHeaders); hs != headers {
		t.Fatalf("synchronised headers mismatch: have %v, want %v", hs, headers)
	}
	if bs := len(tester.ownBlocks); bs != blocks {
		t.Fatalf("synchronised blocks mismatch: have %v, want %v", bs, blocks)
	}
	if rs := len(tester.ownReceipts); rs != receipts {
		t.Fatalf("synchronised receipts mismatch: have %v, want %v", rs, receipts)
	}
}

// Tests that simple synchronization against a canonical chain works correctly.
// In this test common ancestor lookup should be short circuited and not require
// binary searching.
func TestCanonicalSynchronisation62(t *testing.T) { testCanonicalSynchronisation(t, 62, FullSync) }

// TestCanonicalSynchronisation63Full tests canonical synchronisation 63 full.
func TestCanonicalSynchronisation63Full(t *testing.T) { testCanonicalSynchronisation(t, 63, FullSync) }

// TestCanonicalSynchronisation63Fast tests canonical synchronisation 63 fast.
func TestCanonicalSynchronisation63Fast(t *testing.T) { testCanonicalSynchronisation(t, 63, FastSync) }

// TestCanonicalSynchronisation64Full tests canonical synchronisation 64 full.
func TestCanonicalSynchronisation64Full(t *testing.T) { testCanonicalSynchronisation(t, 64, FullSync) }

// TestCanonicalSynchronisation64Fast tests canonical synchronisation 64 fast.
func TestCanonicalSynchronisation64Fast(t *testing.T) { testCanonicalSynchronisation(t, 64, FastSync) }

// TestCanonicalSynchronisation64Light tests canonical synchronisation 64 light.
func TestCanonicalSynchronisation64Light(t *testing.T) {
	testCanonicalSynchronisation(t, 64, LightSync)
}

func testCanonicalSynchronisation(t *testing.T, protocol int, mode SyncMode) {
	t.Parallel()

	tester := newTester()
	defer tester.terminate()

	// Create a small enough block chain to download
	chain := testChainBase.shorten(blockCacheMaxItems - 15)
	tester.newPeer("peer", protocol, chain)

	// Synchronise with the peer and make sure all relevant data was retrieved
	if err := tester.sync("peer", nil, mode); err != nil {
		t.Fatalf("failed to synchronise blocks: %v", err)
	}
	assertOwnChain(t, tester, chain.len())
}

// Tests that if a large batch of blocks are being downloaded, it is throttled
// until the cached blocks are retrieved.
func TestThrottling62(t *testing.T) { testThrottling(t, 62, FullSync) }

// TestThrottling63Full tests throttling 63 full.
func TestThrottling63Full(t *testing.T) { testThrottling(t, 63, FullSync) }

// TestThrottling63Fast tests throttling 63 fast.
func TestThrottling63Fast(t *testing.T) { testThrottling(t, 63, FastSync) }

// TestThrottling64Full tests throttling 64 full.
func TestThrottling64Full(t *testing.T) { testThrottling(t, 64, FullSync) }

// TestThrottling64Fast tests throttling 64 fast.
func TestThrottling64Fast(t *testing.T) { testThrottling(t, 64, FastSync) }

func testThrottling(t *testing.T, protocol int, mode SyncMode) {
	t.Parallel()
	tester := newTester()

	// Create a long block chain to download and the tester
	targetBlocks := testChainBase.len() - 1
	tester.newPeer("peer", protocol, testChainBase)

	// Wrap the importer to allow stepping
	blocked, proceed := uint32(0), make(chan struct{})
	tester.downloader.chainInsertHook = func(results []*fetchResult) {
		atomic.StoreUint32(&blocked, uint32(len(results)))
		<-proceed
	}
	// Start a synchronisation concurrently
	errc := make(chan error)
	go func() {
		errc <- tester.sync("peer", nil, mode)
	}()
	// Iteratively take some blocks, always checking the retrieval count
	for {
		// Check the retrieval count synchronously (! reason for this ugly block)
		tester.lock.RLock()
		retrieved := len(tester.ownBlocks)
		tester.lock.RUnlock()
		if retrieved >= targetBlocks+1 {
			break
		}
		// Wait a bit for sync to throttle itself
		var cached, frozen int
		for start := time.Now(); time.Since(start) < 3*time.Second; {
			time.Sleep(25 * time.Millisecond)

			tester.lock.Lock()
			{
				tester.downloader.queue.resultCache.lock.Lock()
				cached = tester.downloader.queue.resultCache.countCompleted()
				tester.downloader.queue.resultCache.lock.Unlock()
				frozen = int(atomic.LoadUint32(&blocked))
				retrieved = len(tester.ownBlocks)
			}
			tester.lock.Unlock()

			if cached == blockCacheMaxItems ||
				cached == blockCacheMaxItems-reorgProtHeaderDelay ||
				retrieved+cached+frozen == targetBlocks+1 ||
				retrieved+cached+frozen == targetBlocks+1-reorgProtHeaderDelay {
				break
			}
		}
		// Make sure we filled up the cache, then exhaust it
		time.Sleep(25 * time.Millisecond) // give it a chance to screw up
		tester.lock.RLock()
		retrieved = len(tester.ownBlocks)
		tester.lock.RUnlock()
		if cached != blockCacheMaxItems && cached != blockCacheMaxItems-reorgProtHeaderDelay && retrieved+cached+frozen != targetBlocks+1 && retrieved+cached+frozen != targetBlocks+1-reorgProtHeaderDelay {
			t.Fatalf("block count mismatch: have %v, want %v (owned %v, blocked %v, target %v)", cached, blockCacheMaxItems, retrieved, frozen, targetBlocks+1)
		}

		// Permit the blocked blocks to import
		if atomic.LoadUint32(&blocked) > 0 {
			atomic.StoreUint32(&blocked, uint32(0))
			proceed <- struct{}{}
		}
	}
	// Check that we haven't pulled more blocks than available
	assertOwnChain(t, tester, targetBlocks+1)
	if err := <-errc; err != nil {
		t.Fatalf("block synchronization failed: %v", err)
	}
	tester.terminate()
}

// Tests that simple synchronization against a forked chain works correctly. In
// this test common ancestor lookup should *not* be short circuited, and a full
// binary search should be executed.
func TestForkedSync62(t *testing.T) { testForkedSync(t, 62, FullSync) }

// TestForkedSync63Full tests forked sync 63 full.
func TestForkedSync63Full(t *testing.T) { testForkedSync(t, 63, FullSync) }

// TestForkedSync63Fast tests forked sync 63 fast.
func TestForkedSync63Fast(t *testing.T) { testForkedSync(t, 63, FastSync) }

// TestForkedSync64Full tests forked sync 64 full.
func TestForkedSync64Full(t *testing.T) { testForkedSync(t, 64, FullSync) }

// TestForkedSync64Fast tests forked sync 64 fast.
func TestForkedSync64Fast(t *testing.T) { testForkedSync(t, 64, FastSync) }

// TestForkedSync64Light tests forked sync 64 light.
func TestForkedSync64Light(t *testing.T) { testForkedSync(t, 64, LightSync) }

func testForkedSync(t *testing.T, protocol int, mode SyncMode) {
	t.Parallel()

	tester := newTester()
	defer tester.terminate()

	chainA := testChainForkLightA.shorten(testChainBase.len() + 80)
	chainB := testChainForkLightB.shorten(testChainBase.len() + 80)
	tester.newPeer("fork A", protocol, chainA)
	tester.newPeer("fork B", protocol, chainB)
	// Synchronise with the peer and make sure all blocks were retrieved
	if err := tester.sync("fork A", nil, mode); err != nil {
		t.Fatalf("failed to synchronise blocks: %v", err)
	}
	assertOwnChain(t, tester, chainA.len())

	// Synchronise with the second peer and make sure that fork is pulled too
	if err := tester.sync("fork B", nil, mode); err != nil {
		t.Fatalf("failed to synchronise blocks: %v", err)
	}
	assertOwnForkedChain(t, tester, testChainBase.len(), []int{chainA.len(), chainB.len()})
}

// Tests that synchronising against a much shorter but much heavyer fork works
// corrently and is not dropped.
func TestHeavyForkedSync62(t *testing.T) { testHeavyForkedSync(t, 62, FullSync) }

// TestHeavyForkedSync63Full tests heavy forked sync 63 full.
func TestHeavyForkedSync63Full(t *testing.T) { testHeavyForkedSync(t, 63, FullSync) }

// TestHeavyForkedSync63Fast tests heavy forked sync 63 fast.
func TestHeavyForkedSync63Fast(t *testing.T) { testHeavyForkedSync(t, 63, FastSync) }

// TestHeavyForkedSync64Full tests heavy forked sync 64 full.
func TestHeavyForkedSync64Full(t *testing.T) { testHeavyForkedSync(t, 64, FullSync) }

// TestHeavyForkedSync64Fast tests heavy forked sync 64 fast.
func TestHeavyForkedSync64Fast(t *testing.T) { testHeavyForkedSync(t, 64, FastSync) }

// TestHeavyForkedSync64Light tests heavy forked sync 64 light.
func TestHeavyForkedSync64Light(t *testing.T) { testHeavyForkedSync(t, 64, LightSync) }

func testHeavyForkedSync(t *testing.T, protocol int, mode SyncMode) {
	t.Parallel()

	tester := newTester()
	defer tester.terminate()

	chainA := testChainForkLightA.shorten(testChainBase.len() + 80)
	chainB := testChainForkHeavy.shorten(testChainBase.len() + 80)
	tester.newPeer("light", protocol, chainA)
	tester.newPeer("heavy", protocol, chainB)

	// Synchronise with the peer and make sure all blocks were retrieved
	if err := tester.sync("light", nil, mode); err != nil {
		t.Fatalf("failed to synchronise blocks: %v", err)
	}
	assertOwnChain(t, tester, chainA.len())

	// Synchronise with the second peer and make sure that fork is pulled too
	if err := tester.sync("heavy", nil, mode); err != nil {
		t.Fatalf("failed to synchronise blocks: %v", err)
	}
	assertOwnForkedChain(t, tester, testChainBase.len(), []int{chainA.len(), chainB.len()})
}

// Tests that chain forks are contained within a certain interval of the current
// chain head, ensuring that malicious peers cannot waste resources by feeding
// long dead chains.
func TestBoundedForkedSync62(t *testing.T) { testBoundedForkedSync(t, 62, FullSync) }

// TestBoundedForkedSync63Full tests bounded forked sync 63 full.
func TestBoundedForkedSync63Full(t *testing.T) { testBoundedForkedSync(t, 63, FullSync) }

// TestBoundedForkedSync63Fast tests bounded forked sync 63 fast.
func TestBoundedForkedSync63Fast(t *testing.T) { testBoundedForkedSync(t, 63, FastSync) }

// TestBoundedForkedSync64Full tests bounded forked sync 64 full.
func TestBoundedForkedSync64Full(t *testing.T) { testBoundedForkedSync(t, 64, FullSync) }

// TestBoundedForkedSync64Fast tests bounded forked sync 64 fast.
func TestBoundedForkedSync64Fast(t *testing.T) { testBoundedForkedSync(t, 64, FastSync) }

// TestBoundedForkedSync64Light tests bounded forked sync 64 light.
func TestBoundedForkedSync64Light(t *testing.T) { testBoundedForkedSync(t, 64, LightSync) }

func testBoundedForkedSync(t *testing.T, protocol int, mode SyncMode) {
	t.Parallel()

	tester := newTester()
	defer tester.terminate()

	chainA := testChainForkLightA
	chainB := testChainForkLightB
	tester.newPeer("original", protocol, chainA)
	tester.newPeer("rewriter", protocol, chainB)

	// Synchronise with the peer and make sure all blocks were retrieved
	if err := tester.sync("original", nil, mode); err != nil {
		t.Fatalf("failed to synchronise blocks: %v", err)
	}
	assertOwnChain(t, tester, chainA.len())

	// Synchronise with the second peer and ensure that the fork is rejected to being too old
	if err := tester.sync("rewriter", nil, mode); err != errInvalidAncestor {
		t.Fatalf("sync failure mismatch: have %v, want %v", err, errInvalidAncestor)
	}
}

// Tests that chain forks are contained within a certain interval of the current
// chain head for short but heavy forks too. These are a bit special because they
// take different ancestor lookup paths.
func TestBoundedHeavyForkedSync62(t *testing.T) { testBoundedHeavyForkedSync(t, 62, FullSync) }

// TestBoundedHeavyForkedSync63Full tests bounded heavy forked sync 63 full.
func TestBoundedHeavyForkedSync63Full(t *testing.T) { testBoundedHeavyForkedSync(t, 63, FullSync) }

// TestBoundedHeavyForkedSync63Fast tests bounded heavy forked sync 63 fast.
func TestBoundedHeavyForkedSync63Fast(t *testing.T) { testBoundedHeavyForkedSync(t, 63, FastSync) }

// TestBoundedHeavyForkedSync64Full tests bounded heavy forked sync 64 full.
func TestBoundedHeavyForkedSync64Full(t *testing.T) { testBoundedHeavyForkedSync(t, 64, FullSync) }

// TestBoundedHeavyForkedSync64Fast tests bounded heavy forked sync 64 fast.
func TestBoundedHeavyForkedSync64Fast(t *testing.T) { testBoundedHeavyForkedSync(t, 64, FastSync) }

// TestBoundedHeavyForkedSync64Light tests bounded heavy forked sync 64 light.
func TestBoundedHeavyForkedSync64Light(t *testing.T) { testBoundedHeavyForkedSync(t, 64, LightSync) }

func testBoundedHeavyForkedSync(t *testing.T, protocol int, mode SyncMode) {
	t.Parallel()
	tester := newTester()

	// Create a long enough forked chain
	chainA := testChainForkLightA
	chainB := testChainForkHeavy
	tester.newPeer("original", protocol, chainA)

	// Synchronise with the peer and make sure all blocks were retrieved
	if err := tester.sync("original", nil, mode); err != nil {
		t.Fatalf("failed to synchronise blocks: %v", err)
	}
	assertOwnChain(t, tester, chainA.len())

	tester.newPeer("heavy-rewriter", protocol, chainB)
	// Synchronise with the second peer and ensure that the fork is rejected to being too old
	if err := tester.sync("heavy-rewriter", nil, mode); err != errInvalidAncestor {
		t.Fatalf("sync failure mismatch: have %v, want %v", err, errInvalidAncestor)
	}
	tester.terminate()
}

// Tests that an inactive downloader will not accept incoming block headers and
// bodies.
func TestInactiveDownloader62(t *testing.T) {
	t.Parallel()

	tester := newTester()
	defer tester.terminate()

	// Check that neither block headers nor bodies are accepted
	if err := tester.downloader.DeliverHeaders("bad peer", []*types.Header{}); err != errNoSyncActive {
		t.Errorf("error mismatch: have %v, want %v", err, errNoSyncActive)
	}
	if err := tester.downloader.DeliverBodies("bad peer", [][]*types.Transaction{}, [][]*types.Header{}); err != errNoSyncActive {
		t.Errorf("error mismatch: have %v, want %v", err, errNoSyncActive)
	}
}

// Tests that an inactive downloader will not accept incoming block headers,
// bodies and receipts.
func TestInactiveDownloader63(t *testing.T) {
	t.Parallel()

	tester := newTester()
	defer tester.terminate()

	// Check that neither block headers nor bodies are accepted
	if err := tester.downloader.DeliverHeaders("bad peer", []*types.Header{}); err != errNoSyncActive {
		t.Errorf("error mismatch: have %v, want %v", err, errNoSyncActive)
	}
	if err := tester.downloader.DeliverBodies("bad peer", [][]*types.Transaction{}, [][]*types.Header{}); err != errNoSyncActive {
		t.Errorf("error mismatch: have %v, want %v", err, errNoSyncActive)
	}
	if err := tester.downloader.DeliverReceipts("bad peer", [][]*types.Receipt{}); err != errNoSyncActive {
		t.Errorf("error mismatch: have %v, want %v", err, errNoSyncActive)
	}
}

// Tests that a canceled download wipes all previously accumulated state.
func TestCancel62(t *testing.T) { testCancel(t, 62, FullSync) }

// TestCancel63Full tests cancel 63 full.
func TestCancel63Full(t *testing.T) { testCancel(t, 63, FullSync) }

// TestCancel63Fast tests cancel 63 fast.
func TestCancel63Fast(t *testing.T) { testCancel(t, 63, FastSync) }

// TestCancel64Full tests cancel 64 full.
func TestCancel64Full(t *testing.T) { testCancel(t, 64, FullSync) }

// TestCancel64Fast tests cancel 64 fast.
func TestCancel64Fast(t *testing.T) { testCancel(t, 64, FastSync) }

// TestCancel64Light tests cancel 64 light.
func TestCancel64Light(t *testing.T) { testCancel(t, 64, LightSync) }

func testCancel(t *testing.T, protocol int, mode SyncMode) {
	t.Parallel()

	tester := newTester()
	defer tester.terminate()

	chain := testChainBase.shorten(MaxHeaderFetch)
	tester.newPeer("peer", protocol, chain)

	// Make sure canceling works with a pristine downloader
	tester.downloader.Cancel()
	if !tester.downloader.queue.Idle() {
		t.Errorf("download queue not idle")
	}
	// Synchronise with the peer, but cancel afterwards
	if err := tester.sync("peer", nil, mode); err != nil {
		t.Fatalf("failed to synchronise blocks: %v", err)
	}
	tester.downloader.Cancel()
	if !tester.downloader.queue.Idle() {
		t.Errorf("download queue not idle")
	}
}

// Tests that synchronisation from multiple peers works as intended (multi thread sanity test).
func TestMultiSynchronisation62(t *testing.T) { testMultiSynchronisation(t, 62, FullSync) }

// TestMultiSynchronisation63Full tests multi synchronisation 63 full.
func TestMultiSynchronisation63Full(t *testing.T) { testMultiSynchronisation(t, 63, FullSync) }

// TestMultiSynchronisation63Fast tests multi synchronisation 63 fast.
func TestMultiSynchronisation63Fast(t *testing.T) { testMultiSynchronisation(t, 63, FastSync) }

// TestMultiSynchronisation64Full tests multi synchronisation 64 full.
func TestMultiSynchronisation64Full(t *testing.T) { testMultiSynchronisation(t, 64, FullSync) }

// TestMultiSynchronisation64Fast tests multi synchronisation 64 fast.
func TestMultiSynchronisation64Fast(t *testing.T) { testMultiSynchronisation(t, 64, FastSync) }

// TestMultiSynchronisation64Light tests multi synchronisation 64 light.
func TestMultiSynchronisation64Light(t *testing.T) { testMultiSynchronisation(t, 64, LightSync) }

func testMultiSynchronisation(t *testing.T, protocol int, mode SyncMode) {
	t.Parallel()

	tester := newTester()
	defer tester.terminate()

	// Create various peers with various parts of the chain
	targetPeers := 8
	chain := testChainBase.shorten(targetPeers * 100)

	for i := 0; i < targetPeers; i++ {
		id := fmt.Sprintf("peer #%d", i)
		tester.newPeer(id, protocol, chain.shorten(chain.len()/(i+1)))
	}
	if err := tester.sync("peer #0", nil, mode); err != nil {
		t.Fatalf("failed to synchronise blocks: %v", err)
	}
	assertOwnChain(t, tester, chain.len())
}

// Tests that synchronisations behave well in multi-version protocol environments
// and not wreak havoc on other nodes in the network.
func TestMultiProtoSynchronisation62(t *testing.T) { testMultiProtoSync(t, 62, FullSync) }

// TestMultiProtoSynchronisation63Full tests multi proto synchronisation 63 full.
func TestMultiProtoSynchronisation63Full(t *testing.T) { testMultiProtoSync(t, 63, FullSync) }

// TestMultiProtoSynchronisation63Fast tests multi proto synchronisation 63 fast.
func TestMultiProtoSynchronisation63Fast(t *testing.T) { testMultiProtoSync(t, 63, FastSync) }

// TestMultiProtoSynchronisation64Full tests multi proto synchronisation 64 full.
func TestMultiProtoSynchronisation64Full(t *testing.T) { testMultiProtoSync(t, 64, FullSync) }

// TestMultiProtoSynchronisation64Fast tests multi proto synchronisation 64 fast.
func TestMultiProtoSynchronisation64Fast(t *testing.T) { testMultiProtoSync(t, 64, FastSync) }

// TestMultiProtoSynchronisation64Light tests multi proto synchronisation 64 light.
func TestMultiProtoSynchronisation64Light(t *testing.T) { testMultiProtoSync(t, 64, LightSync) }

func testMultiProtoSync(t *testing.T, protocol int, mode SyncMode) {
	t.Parallel()

	tester := newTester()
	defer tester.terminate()

	// Create a small enough block chain to download
	chain := testChainBase.shorten(blockCacheMaxItems - 15)

	// Create peers of every type
	tester.newPeer("peer 62", 62, chain)
	tester.newPeer("peer 63", 63, chain)
	tester.newPeer("peer 64", 64, chain)

	// Synchronise with the requested peer and make sure all blocks were retrieved
	if err := tester.sync(fmt.Sprintf("peer %d", protocol), nil, mode); err != nil {
		t.Fatalf("failed to synchronise blocks: %v", err)
	}
	assertOwnChain(t, tester, chain.len())

	// Check that no peers have been dropped off
	for _, version := range []int{62, 63, 64} {
		peer := fmt.Sprintf("peer %d", version)
		if _, ok := tester.peers[peer]; !ok {
			t.Errorf("%s dropped", peer)
		}
	}
}

// Tests that if a block is empty (e.g. header only), no body request should be
// made, and instead the header should be assembled into a whole block in itself.
func TestEmptyShortCircuit62(t *testing.T) { testEmptyShortCircuit(t, 62, FullSync) }

// TestEmptyShortCircuit63Full tests empty short circuit 63 full.
func TestEmptyShortCircuit63Full(t *testing.T) { testEmptyShortCircuit(t, 63, FullSync) }

// TestEmptyShortCircuit63Fast tests empty short circuit 63 fast.
func TestEmptyShortCircuit63Fast(t *testing.T) { testEmptyShortCircuit(t, 63, FastSync) }

// TestEmptyShortCircuit64Full tests empty short circuit 64 full.
func TestEmptyShortCircuit64Full(t *testing.T) { testEmptyShortCircuit(t, 64, FullSync) }

// TestEmptyShortCircuit64Fast tests empty short circuit 64 fast.
func TestEmptyShortCircuit64Fast(t *testing.T) { testEmptyShortCircuit(t, 64, FastSync) }

// TestEmptyShortCircuit64Light tests empty short circuit 64 light.
func TestEmptyShortCircuit64Light(t *testing.T) { testEmptyShortCircuit(t, 64, LightSync) }

func testEmptyShortCircuit(t *testing.T, protocol int, mode SyncMode) {
	t.Parallel()

	tester := newTester()
	defer tester.terminate()

	// Create a block chain to download
	chain := testChainBase
	tester.newPeer("peer", protocol, chain)

	// Instrument the downloader to signal body requests
	bodiesHave, receiptsHave := int32(0), int32(0)
	tester.downloader.bodyFetchHook = func(headers []*types.Header) {
		atomic.AddInt32(&bodiesHave, int32(len(headers)))
	}
	tester.downloader.receiptFetchHook = func(headers []*types.Header) {
		atomic.AddInt32(&receiptsHave, int32(len(headers)))
	}
	// Synchronise with the peer and make sure all blocks were retrieved
	if err := tester.sync("peer", nil, mode); err != nil {
		t.Fatalf("failed to synchronise blocks: %v", err)
	}
	assertOwnChain(t, tester, chain.len())

	// Validate the number of block bodies that should have been requested
	bodiesNeeded, receiptsNeeded := 0, 0
	for _, block := range chain.blockm {
		if mode != LightSync && block != tester.genesis && (len(block.Transactions()) > 0 || len(block.Uncles()) > 0) {
			bodiesNeeded++
		}
	}
	for _, receipt := range chain.receiptm {
		if mode == FastSync && len(receipt) > 0 {
			receiptsNeeded++
		}
	}
	if int(bodiesHave) != bodiesNeeded {
		t.Errorf("body retrieval count mismatch: have %v, want %v", bodiesHave, bodiesNeeded)
	}
	if int(receiptsHave) != receiptsNeeded {
		t.Errorf("receipt retrieval count mismatch: have %v, want %v", receiptsHave, receiptsNeeded)
	}
}

// Tests that headers are enqueued continuously, preventing malicious nodes from
// stalling the downloader by feeding gapped header chains.
func TestMissingHeaderAttack62(t *testing.T) { testMissingHeaderAttack(t, 62, FullSync) }

// TestMissingHeaderAttack63Full tests missing header attack 63 full.
func TestMissingHeaderAttack63Full(t *testing.T) { testMissingHeaderAttack(t, 63, FullSync) }

// TestMissingHeaderAttack63Fast tests missing header attack 63 fast.
func TestMissingHeaderAttack63Fast(t *testing.T) { testMissingHeaderAttack(t, 63, FastSync) }

// TestMissingHeaderAttack64Full tests missing header attack 64 full.
func TestMissingHeaderAttack64Full(t *testing.T) { testMissingHeaderAttack(t, 64, FullSync) }

// TestMissingHeaderAttack64Fast tests missing header attack 64 fast.
func TestMissingHeaderAttack64Fast(t *testing.T) { testMissingHeaderAttack(t, 64, FastSync) }

// TestMissingHeaderAttack64Light tests missing header attack 64 light.
func TestMissingHeaderAttack64Light(t *testing.T) { testMissingHeaderAttack(t, 64, LightSync) }

func testMissingHeaderAttack(t *testing.T, protocol int, mode SyncMode) {
	t.Parallel()

	tester := newTester()
	defer tester.terminate()

	chain := testChainBase.shorten(blockCacheMaxItems - 15)
	brokenChain := chain.shorten(chain.len())
	delete(brokenChain.headerm, brokenChain.chain[brokenChain.len()/2])
	tester.newPeer("attack", protocol, brokenChain)

	if err := tester.sync("attack", nil, mode); err == nil {
		t.Fatalf("succeeded attacker synchronisation")
	}
	// Synchronise with the valid peer and make sure sync succeeds
	tester.newPeer("valid", protocol, chain)
	if err := tester.sync("valid", nil, mode); err != nil {
		t.Fatalf("failed to synchronise blocks: %v", err)
	}
	assertOwnChain(t, tester, chain.len())
}

// Tests that if requested headers are shifted (i.e. first is missing), the queue
// detects the invalid numbering.
func TestShiftedHeaderAttack62(t *testing.T) { testShiftedHeaderAttack(t, 62, FullSync) }

// TestShiftedHeaderAttack63Full tests shifted header attack 63 full.
func TestShiftedHeaderAttack63Full(t *testing.T) { testShiftedHeaderAttack(t, 63, FullSync) }

// TestShiftedHeaderAttack63Fast tests shifted header attack 63 fast.
func TestShiftedHeaderAttack63Fast(t *testing.T) { testShiftedHeaderAttack(t, 63, FastSync) }

// TestShiftedHeaderAttack64Full tests shifted header attack 64 full.
func TestShiftedHeaderAttack64Full(t *testing.T) { testShiftedHeaderAttack(t, 64, FullSync) }

// TestShiftedHeaderAttack64Fast tests shifted header attack 64 fast.
func TestShiftedHeaderAttack64Fast(t *testing.T) { testShiftedHeaderAttack(t, 64, FastSync) }

// TestShiftedHeaderAttack64Light tests shifted header attack 64 light.
func TestShiftedHeaderAttack64Light(t *testing.T) { testShiftedHeaderAttack(t, 64, LightSync) }

func testShiftedHeaderAttack(t *testing.T, protocol int, mode SyncMode) {
	t.Parallel()

	tester := newTester()
	defer tester.terminate()

	chain := testChainBase.shorten(blockCacheMaxItems - 15)

	// Attempt a full sync with an attacker feeding shifted headers
	brokenChain := chain.shorten(chain.len())
	delete(brokenChain.headerm, brokenChain.chain[1])
	delete(brokenChain.blockm, brokenChain.chain[1])
	delete(brokenChain.receiptm, brokenChain.chain[1])
	tester.newPeer("attack", protocol, brokenChain)
	if err := tester.sync("attack", nil, mode); err == nil {
		t.Fatalf("succeeded attacker synchronisation")
	}

	// Synchronise with the valid peer and make sure sync succeeds
	tester.newPeer("valid", protocol, chain)
	if err := tester.sync("valid", nil, mode); err != nil {
		t.Fatalf("failed to synchronise blocks: %v", err)
	}
	assertOwnChain(t, tester, chain.len())
}

// Tests that upon detecting an invalid header, the recent ones are rolled back
// for various failure scenarios. Afterwards a full sync is attempted to make
// sure no state was corrupted.
func TestInvalidHeaderRollback63Fast(t *testing.T) { testInvalidHeaderRollback(t, 63, FastSync) }

// TestInvalidHeaderRollback64Fast tests invalid header rollback 64 fast.
func TestInvalidHeaderRollback64Fast(t *testing.T) { testInvalidHeaderRollback(t, 64, FastSync) }

// TestInvalidHeaderRollback64Light tests invalid header rollback 64 light.
func TestInvalidHeaderRollback64Light(t *testing.T) { testInvalidHeaderRollback(t, 64, LightSync) }

func testInvalidHeaderRollback(t *testing.T, protocol int, mode SyncMode) {
	t.Parallel()

	tester := newTester()

	// Create a small enough block chain to download
	targetBlocks := 3*fsHeaderSafetyNet + 256 + fsMinFullBlocks
	chain := testChainBase.shorten(targetBlocks)

	// Attempt to sync with an attacker that feeds junk during the fast sync phase.
	// This should result in the last fsHeaderSafetyNet headers being rolled back.
	missing := fsHeaderSafetyNet + MaxHeaderFetch + 1
	fastAttackChain := chain.shorten(chain.len())
	delete(fastAttackChain.headerm, fastAttackChain.chain[missing])
	tester.newPeer("fast-attack", protocol, fastAttackChain)

	if err := tester.sync("fast-attack", nil, mode); err == nil {
		t.Fatalf("succeeded fast attacker synchronisation")
	}
	if head := tester.CurrentHeader().Number.Int64(); int(head) > MaxHeaderFetch {
		t.Errorf("rollback head mismatch: have %v, want at most %v", head, MaxHeaderFetch)
	}

	// Attempt to sync with an attacker that feeds junk during the block import phase.
	// This should result in both the last fsHeaderSafetyNet number of headers being
	// rolled back, and also the pivot point being reverted to a non-block status.
	missing = 3*fsHeaderSafetyNet + MaxHeaderFetch + 1
	blockAttackChain := chain.shorten(chain.len())
	delete(fastAttackChain.headerm, fastAttackChain.chain[missing]) // Make sure the fast-attacker doesn't fill in
	delete(blockAttackChain.headerm, blockAttackChain.chain[missing])
	tester.newPeer("block-attack", protocol, blockAttackChain)

	if err := tester.sync("block-attack", nil, mode); err == nil {
		t.Fatalf("succeeded block attacker synchronisation")
	}
	if head := tester.CurrentHeader().Number.Int64(); int(head) > 2*fsHeaderSafetyNet+MaxHeaderFetch {
		t.Errorf("rollback head mismatch: have %v, want at most %v", head, 2*fsHeaderSafetyNet+MaxHeaderFetch)
	}
	if mode == FastSync {
		if head := tester.CurrentBlock().Number.Uint64(); head != 0 {
			t.Errorf("fast sync pivot block #%d not rolled back", head)
		}
	}

	// Attempt to sync with an attacker that withholds promised blocks after the
	// fast sync pivot point. This could be a trial to leave the node with a bad
	// but already imported pivot block.
	withholdAttackChain := chain.shorten(chain.len())
	tester.newPeer("withhold-attack", protocol, withholdAttackChain)
	tester.downloader.syncInitHook = func(uint64, uint64) {
		for i := missing; i < withholdAttackChain.len(); i++ {
			delete(withholdAttackChain.headerm, withholdAttackChain.chain[i])
		}
		tester.downloader.syncInitHook = nil
	}
	if err := tester.sync("withhold-attack", nil, mode); err == nil {
		t.Fatalf("succeeded withholding attacker synchronisation")
	}
	if head := tester.CurrentHeader().Number.Int64(); int(head) > 2*fsHeaderSafetyNet+MaxHeaderFetch {
		t.Errorf("rollback head mismatch: have %v, want at most %v", head, 2*fsHeaderSafetyNet+MaxHeaderFetch)
	}
	if mode == FastSync {
		if head := tester.CurrentBlock().Number.Uint64(); head != 0 {
			t.Errorf("fast sync pivot block #%d not rolled back", head)
		}
	}

	// synchronise with the valid peer and make sure sync succeeds. Since the last rollback
	// should also disable fast syncing for this process, verify that we did a fresh full
	// sync. Note, we can't assert anything about the receipts since we won't purge the
	// database of them, hence we can't use assertOwnChain.
	tester.newPeer("valid", protocol, chain)
	if err := tester.sync("valid", nil, mode); err != nil {
		t.Fatalf("failed to synchronise blocks: %v", err)
	}
	if hs := len(tester.ownHeaders); hs != chain.len() {
		t.Fatalf("synchronised headers mismatch: have %v, want %v", hs, chain.len())
	}
	if mode != LightSync {
		if bs := len(tester.ownBlocks); bs != chain.len() {
			t.Fatalf("synchronised blocks mismatch: have %v, want %v", bs, chain.len())
		}
	}
	tester.terminate()
}

// Tests that a peer advertising an high TD doesn't get to stall the downloader
// afterwards by not sending any useful hashes.
func TestHighTDStarvationAttack62(t *testing.T) { testHighTDStarvationAttack(t, 62, FullSync) }

// TestHighTDStarvationAttack63Full tests high td starvation attack 63 full.
func TestHighTDStarvationAttack63Full(t *testing.T) { testHighTDStarvationAttack(t, 63, FullSync) }

// TestHighTDStarvationAttack63Fast tests high td starvation attack 63 fast.
func TestHighTDStarvationAttack63Fast(t *testing.T) { testHighTDStarvationAttack(t, 63, FastSync) }

// TestHighTDStarvationAttack64Full tests high td starvation attack 64 full.
func TestHighTDStarvationAttack64Full(t *testing.T) { testHighTDStarvationAttack(t, 64, FullSync) }

// TestHighTDStarvationAttack64Fast tests high td starvation attack 64 fast.
func TestHighTDStarvationAttack64Fast(t *testing.T) { testHighTDStarvationAttack(t, 64, FastSync) }

// TestHighTDStarvationAttack64Light tests high td starvation attack 64 light.
func TestHighTDStarvationAttack64Light(t *testing.T) { testHighTDStarvationAttack(t, 64, LightSync) }

func testHighTDStarvationAttack(t *testing.T, protocol int, mode SyncMode) {
	t.Parallel()

	tester := newTester()

	chain := testChainBase.shorten(1)
	tester.newPeer("attack", protocol, chain)
	if err := tester.sync("attack", big.NewInt(1000000), mode); err != errStallingPeer {
		t.Fatalf("synchronisation error mismatch: have %v, want %v", err, errStallingPeer)
	}
	tester.terminate()
}

// Tests that misbehaving peers are disconnected, whilst behaving ones are not.
func TestBlockHeaderAttackerDropping62(t *testing.T) { testBlockHeaderAttackerDropping(t, 62) }

// TestBlockHeaderAttackerDropping63 tests block header attacker dropping 63.
func TestBlockHeaderAttackerDropping63(t *testing.T) { testBlockHeaderAttackerDropping(t, 63) }

// TestBlockHeaderAttackerDropping64 tests block header attacker dropping 64.
func TestBlockHeaderAttackerDropping64(t *testing.T) { testBlockHeaderAttackerDropping(t, 64) }

func testBlockHeaderAttackerDropping(t *testing.T, protocol int) {
	t.Parallel()

	// Define the disconnection requirement for individual hash fetch errors
	tests := []struct {
		result error
		drop   bool
	}{
		{nil, false},                        // Sync succeeded, all is well
		{errBusy, false},                    // Sync is already in progress, no problem
		{errUnknownPeer, false},             // Peer is unknown, was already dropped, don't double drop
		{errBadPeer, true},                  // Peer was deemed bad for some reason, drop it
		{errStallingPeer, true},             // Peer was detected to be stalling, drop it
		{errNoPeers, false},                 // No peers to download from, soft race, no issue
		{errTimeout, true},                  // No hashes received in due time, drop the peer
		{errEmptyHeaderSet, true},           // No headers were returned as a response, drop as it's a dead end
		{errPeersUnavailable, true},         // Nobody had the advertised blocks, drop the advertiser
		{errInvalidAncestor, true},          // Agreed upon ancestor is not acceptable, drop the chain rewriter
		{errInvalidChain, true},             // Hash chain was detected as invalid, definitely drop
		{errInvalidBody, false},             // A bad peer was detected, but not the sync origin
		{errInvalidReceipt, false},          // A bad peer was detected, but not the sync origin
		{errCancelContentProcessing, false}, // Synchronisation was canceled, origin may be innocent, don't drop
	}
	// Run the tests and check disconnection status
	tester := newTester()
	defer tester.terminate()
	chain := testChainBase.shorten(1)

	for i, tt := range tests {
		// Register a new peer and ensure it's presence
		id := fmt.Sprintf("test %d", i)
		if err := tester.newPeer(id, protocol, chain); err != nil {
			t.Fatalf("test %d: failed to register new peer: %v", i, err)
		}
		if _, ok := tester.peers[id]; !ok {
			t.Fatalf("test %d: registered peer not found", i)
		}
		// Simulate a synchronisation and check the required result
		tester.downloader.synchroniseMock = func(string, common.Hash) error { return tt.result }

		tester.downloader.Synchronise(id, tester.genesis.Hash(), big.NewInt(1000), FullSync)
		if _, ok := tester.peers[id]; !ok != tt.drop {
			t.Errorf("test %d: peer drop mismatch for %v: have %v, want %v", i, tt.result, !ok, tt.drop)
		}
	}
}

// Tests that a sync-time unknown ancestor in header insertion is surfaced as
// invalid chain and causes peer dropping, matching bad-block handling flow.
func TestSyncBatchAncestorErrDropPeer(t *testing.T) {
	t.Parallel()
	for _, mode := range []SyncMode{LightSync, FastSync} {
		mode := mode
		t.Run(mode.String(), func(t *testing.T) {
			tester := newTester()
			defer tester.terminate()

			chain := testChainBase.shorten(blockCacheMaxItems - 15)
			if err := tester.newPeer("peer", 64, chain); err != nil {
				t.Fatalf("failed to register peer: %v", err)
			}

			tester.insertHeaderChainHook = func(headers []*types.Header) error {
				if len(headers) > 0 {
					return errors.New("unknown ancestor")
				}
				return nil
			}

			head := chain.headBlock()
			err := tester.downloader.Synchronise("peer", head.Hash(), chain.td(head.Hash()), mode)
			if !errors.Is(err, errInvalidChain) {
				t.Fatalf("sync error mismatch: have %v, want wrapped %v", err, errInvalidChain)
			}
			if !strings.Contains(err.Error(), "unknown ancestor") {
				t.Fatalf("sync error should contain root cause, have %v", err)
			}
			if _, ok := tester.peers["peer"]; ok {
				t.Fatalf("peer should be dropped on invalid chain")
			}
		})
	}
}

// Tests the control path for the same batch sync flow: without injected header
// insertion errors, sync succeeds and the origin peer is kept.
func TestSyncBatchNoAncestorErrKeepPeer(t *testing.T) {
	t.Parallel()
	for _, mode := range []SyncMode{LightSync, FastSync} {
		mode := mode
		t.Run(mode.String(), func(t *testing.T) {
			tester := newTester()
			defer tester.terminate()

			chain := testChainBase.shorten(blockCacheMaxItems - 15)
			if err := tester.newPeer("peer", 64, chain); err != nil {
				t.Fatalf("failed to register peer: %v", err)
			}

			head := chain.headBlock()
			err := tester.downloader.Synchronise("peer", head.Hash(), chain.td(head.Hash()), mode)
			if err != nil {
				t.Fatalf("sync should succeed without injected errors, have %v", err)
			}
			if _, ok := tester.peers["peer"]; !ok {
				t.Fatalf("peer should not be dropped on successful sync")
			}
		})
	}
}

// Tests that synchronisation progress (origin block number, current block number
// and highest block number) is tracked and updated correctly.
func TestSyncProgress62(t *testing.T) { testSyncProgress(t, 62, FullSync) }

// TestSyncProgress63Full tests sync progress 63 full.
func TestSyncProgress63Full(t *testing.T) { testSyncProgress(t, 63, FullSync) }

// TestSyncProgress63Fast tests sync progress 63 fast.
func TestSyncProgress63Fast(t *testing.T) { testSyncProgress(t, 63, FastSync) }

// TestSyncProgress64Full tests sync progress 64 full.
func TestSyncProgress64Full(t *testing.T) { testSyncProgress(t, 64, FullSync) }

// TestSyncProgress64Fast tests sync progress 64 fast.
func TestSyncProgress64Fast(t *testing.T) { testSyncProgress(t, 64, FastSync) }

// TestSyncProgress64Light tests sync progress 64 light.
func TestSyncProgress64Light(t *testing.T) { testSyncProgress(t, 64, LightSync) }

func testSyncProgress(t *testing.T, protocol int, mode SyncMode) {
	t.Parallel()

	tester := newTester()
	defer tester.terminate()
	chain := testChainBase.shorten(blockCacheMaxItems - 15)

	// Set a sync init hook to catch progress changes
	starting := make(chan struct{})
	progress := make(chan struct{})

	tester.downloader.syncInitHook = func(origin, latest uint64) {
		starting <- struct{}{}
		<-progress
	}
	checkProgress(t, tester.downloader, "pristine", ethereum.SyncProgress{})

	// Synchronise half the blocks and check initial progress
	tester.newPeer("peer-half", protocol, chain.shorten(chain.len()/2))
	pending := new(sync.WaitGroup)
	pending.Add(1)

	go func() {
		defer pending.Done()
		if err := tester.sync("peer-half", nil, mode); err != nil {
			panic(fmt.Sprintf("failed to synchronise blocks: %v", err))
		}
	}()
	<-starting
	checkProgress(t, tester.downloader, "initial", ethereum.SyncProgress{
		HighestBlock: uint64(chain.len()/2 - 1),
	})
	progress <- struct{}{}
	pending.Wait()

	// Synchronise all the blocks and check continuation progress
	tester.newPeer("peer-full", protocol, chain)
	pending.Add(1)
	go func() {
		defer pending.Done()
		if err := tester.sync("peer-full", nil, mode); err != nil {
			panic(fmt.Sprintf("failed to synchronise blocks: %v", err))
		}
	}()
	<-starting
	// TODO(daniel): set StartingBlock to `uint64(chain.len()/2 - 1)` for mode FastSync, ref: #17916
	var startingBlock = uint64(0)
	if mode != FastSync {
		startingBlock = uint64(chain.len()/2 - 1)
	}
	checkProgress(t, tester.downloader, "completing", ethereum.SyncProgress{
		StartingBlock: startingBlock,
		CurrentBlock:  uint64(chain.len()/2 - 1),
		HighestBlock:  uint64(chain.len() - 1),
	})

	// Check final progress after successful sync
	progress <- struct{}{}
	pending.Wait()
	checkProgress(t, tester.downloader, "final", ethereum.SyncProgress{
		StartingBlock: startingBlock,
		CurrentBlock:  uint64(chain.len() - 1),
		HighestBlock:  uint64(chain.len() - 1),
	})
}

func checkProgress(t *testing.T, d *Downloader, stage string, want ethereum.SyncProgress) {
	t.Helper()
	p := d.Progress()
	p.KnownStates, p.PulledStates = 0, 0
	want.KnownStates, want.PulledStates = 0, 0
	if p != want {
		t.Fatalf("%s progress mismatch:\nhave %+v\nwant %+v", stage, p, want)
	}
}

// Tests that synchronisation progress (origin block number and highest block
// number) is tracked and updated correctly in case of a fork (or manual head
// revertal).
func TestForkedSyncProgress62(t *testing.T) { testForkedSyncProgress(t, 62, FullSync) }

// TestForkedSyncProgress63Full tests forked sync progress 63 full.
func TestForkedSyncProgress63Full(t *testing.T) { testForkedSyncProgress(t, 63, FullSync) }

// TestForkedSyncProgress63Fast tests forked sync progress 63 fast.
func TestForkedSyncProgress63Fast(t *testing.T) { testForkedSyncProgress(t, 63, FastSync) }

// TestForkedSyncProgress64Full tests forked sync progress 64 full.
func TestForkedSyncProgress64Full(t *testing.T) { testForkedSyncProgress(t, 64, FullSync) }

// TestForkedSyncProgress64Fast tests forked sync progress 64 fast.
func TestForkedSyncProgress64Fast(t *testing.T) { testForkedSyncProgress(t, 64, FastSync) }

// TestForkedSyncProgress64Light tests forked sync progress 64 light.
func TestForkedSyncProgress64Light(t *testing.T) { testForkedSyncProgress(t, 64, LightSync) }

func testForkedSyncProgress(t *testing.T, protocol int, mode SyncMode) {
	t.Parallel()

	tester := newTester()
	defer tester.terminate()
	chainA := testChainForkLightA.shorten(testChainBase.len() + MaxHashFetch)
	chainB := testChainForkLightB.shorten(testChainBase.len() + MaxHashFetch)

	// Set a sync init hook to catch progress changes
	starting := make(chan struct{})
	progress := make(chan struct{})

	tester.downloader.syncInitHook = func(origin, latest uint64) {
		starting <- struct{}{}
		<-progress
	}
	checkProgress(t, tester.downloader, "pristine", ethereum.SyncProgress{})

	// Synchronise with one of the forks and check progress
	tester.newPeer("fork A", protocol, chainA)
	pending := new(sync.WaitGroup)
	pending.Add(1)
	go func() {
		defer pending.Done()
		if err := tester.sync("fork A", nil, mode); err != nil {
			panic(fmt.Sprintf("failed to synchronise blocks: %v", err))
		}
	}()
	<-starting

	checkProgress(t, tester.downloader, "initial", ethereum.SyncProgress{
		HighestBlock: uint64(chainA.len() - 1),
	})
	progress <- struct{}{}
	pending.Wait()

	// Simulate a successful sync above the fork
	tester.downloader.syncStatsChainOrigin = tester.downloader.syncStatsChainHeight

	// Synchronise with the second fork and check progress resets
	tester.newPeer("fork B", protocol, chainB)
	pending.Add(1)
	go func() {
		defer pending.Done()
		if err := tester.sync("fork B", nil, mode); err != nil {
			panic(fmt.Sprintf("failed to synchronise blocks: %v", err))
		}
	}()
	<-starting
	checkProgress(t, tester.downloader, "forking", ethereum.SyncProgress{
		StartingBlock: uint64(testChainBase.len()) - 1,
		CurrentBlock:  uint64(chainA.len() - 1),
		HighestBlock:  uint64(chainB.len() - 1),
	})

	// Check final progress after successful sync
	progress <- struct{}{}
	pending.Wait()
	checkProgress(t, tester.downloader, "final", ethereum.SyncProgress{
		StartingBlock: uint64(testChainBase.len()) - 1,
		CurrentBlock:  uint64(chainB.len() - 1),
		HighestBlock:  uint64(chainB.len() - 1),
	})
}

// Tests that if synchronisation is aborted due to some failure, then the progress
// origin is not updated in the next sync cycle, as it should be considered the
// continuation of the previous sync and not a new instance.
func TestFailedSyncProgress62(t *testing.T) { testFailedSyncProgress(t, 62, FullSync) }

// TestFailedSyncProgress63Full tests failed sync progress 63 full.
func TestFailedSyncProgress63Full(t *testing.T) { testFailedSyncProgress(t, 63, FullSync) }

// TestFailedSyncProgress63Fast tests failed sync progress 63 fast.
func TestFailedSyncProgress63Fast(t *testing.T) { testFailedSyncProgress(t, 63, FastSync) }

// TestFailedSyncProgress64Full tests failed sync progress 64 full.
func TestFailedSyncProgress64Full(t *testing.T) { testFailedSyncProgress(t, 64, FullSync) }

// TestFailedSyncProgress64Fast tests failed sync progress 64 fast.
func TestFailedSyncProgress64Fast(t *testing.T) { testFailedSyncProgress(t, 64, FastSync) }

// TestFailedSyncProgress64Light tests failed sync progress 64 light.
func TestFailedSyncProgress64Light(t *testing.T) { testFailedSyncProgress(t, 64, LightSync) }

func testFailedSyncProgress(t *testing.T, protocol int, mode SyncMode) {
	t.Parallel()

	tester := newTester()
	defer tester.terminate()
	chain := testChainBase.shorten(blockCacheMaxItems - 15)

	// Set a sync init hook to catch progress changes
	starting := make(chan struct{})
	progress := make(chan struct{})

	tester.downloader.syncInitHook = func(origin, latest uint64) {
		starting <- struct{}{}
		<-progress
	}
	checkProgress(t, tester.downloader, "pristine", ethereum.SyncProgress{})

	// Attempt a full sync with a faulty peer
	brokenChain := chain.shorten(chain.len())
	missing := brokenChain.len() / 2
	delete(brokenChain.headerm, brokenChain.chain[missing])
	delete(brokenChain.blockm, brokenChain.chain[missing])
	delete(brokenChain.receiptm, brokenChain.chain[missing])
	tester.newPeer("faulty", protocol, brokenChain)

	pending := new(sync.WaitGroup)
	pending.Add(1)
	go func() {
		defer pending.Done()
		if err := tester.sync("faulty", nil, mode); err == nil {
			panic("succeeded faulty synchronisation")
		}
	}()
	<-starting
	checkProgress(t, tester.downloader, "initial", ethereum.SyncProgress{
		HighestBlock: uint64(brokenChain.len() - 1),
	})
	progress <- struct{}{}
	pending.Wait()
	afterFailedSync := tester.downloader.Progress()

	// Synchronise with a good peer and check that the progress origin remind the same
	// after a failure
	tester.newPeer("valid", protocol, chain)
	pending.Add(1)
	go func() {
		defer pending.Done()
		if err := tester.sync("valid", nil, mode); err != nil {
			panic(fmt.Sprintf("failed to synchronise blocks: %v", err))
		}
	}()
	<-starting
	checkProgress(t, tester.downloader, "completing", afterFailedSync)

	// Check final progress after successful sync
	progress <- struct{}{}
	pending.Wait()
	checkProgress(t, tester.downloader, "final", ethereum.SyncProgress{
		CurrentBlock: uint64(chain.len() - 1),
		HighestBlock: uint64(chain.len() - 1),
	})
}

// Tests that if an attacker fakes a chain height, after the attack is detected,
// the progress height is successfully reduced at the next sync invocation.
func TestFakedSyncProgress62(t *testing.T) { testFakedSyncProgress(t, 62, FullSync) }

// TestFakedSyncProgress63Full tests faked sync progress 63 full.
func TestFakedSyncProgress63Full(t *testing.T) { testFakedSyncProgress(t, 63, FullSync) }

// TestFakedSyncProgress63Fast tests faked sync progress 63 fast.
func TestFakedSyncProgress63Fast(t *testing.T) { testFakedSyncProgress(t, 63, FastSync) }

// TestFakedSyncProgress64Full tests faked sync progress 64 full.
func TestFakedSyncProgress64Full(t *testing.T) { testFakedSyncProgress(t, 64, FullSync) }

// TestFakedSyncProgress64Fast tests faked sync progress 64 fast.
func TestFakedSyncProgress64Fast(t *testing.T) { testFakedSyncProgress(t, 64, FastSync) }

// TestFakedSyncProgress64Light tests faked sync progress 64 light.
func TestFakedSyncProgress64Light(t *testing.T) { testFakedSyncProgress(t, 64, LightSync) }

func testFakedSyncProgress(t *testing.T, protocol int, mode SyncMode) {
	t.Parallel()

	tester := newTester()
	defer tester.terminate()
	chain := testChainBase.shorten(blockCacheMaxItems - 15)

	// Set a sync init hook to catch progress changes
	starting := make(chan struct{})
	progress := make(chan struct{})
	tester.downloader.syncInitHook = func(origin, latest uint64) {
		starting <- struct{}{}
		<-progress
	}
	checkProgress(t, tester.downloader, "pristine", ethereum.SyncProgress{})

	// Create and sync with an attacker that promises a higher chain than available.
	brokenChain := chain.shorten(chain.len())
	numMissing := 5
	// Remove the advertised tail inclusively so the attacker is short by exactly
	// numMissing heights. The valid peer below is shortened by the same amount,
	// so both the reduced HighestBlock and the final CurrentBlock must converge
	// to chain.len()-numMissing-1.
	for i := brokenChain.len() - 2; i >= brokenChain.len()-numMissing; i-- {
		delete(brokenChain.headerm, brokenChain.chain[i])
	}
	tester.newPeer("attack", protocol, brokenChain)

	pending := new(sync.WaitGroup)
	pending.Add(1)
	go func() {
		defer pending.Done()
		if err := tester.sync("attack", nil, mode); err == nil {
			panic("succeeded attacker synchronisation")
		}
	}()
	<-starting
	checkProgress(t, tester.downloader, "initial", ethereum.SyncProgress{
		HighestBlock: uint64(brokenChain.len() - 1),
	})
	progress <- struct{}{}
	pending.Wait()
	afterFailedSync := tester.downloader.Progress()

	// Synchronise with a good peer and check that the progress height has been reduced to
	// the true value.
	validChain := chain.shorten(chain.len() - numMissing)
	tester.newPeer("valid", protocol, validChain)
	pending.Add(1)

	go func() {
		defer pending.Done()
		if err := tester.sync("valid", nil, mode); err != nil {
			panic(fmt.Sprintf("failed to synchronise blocks: %v", err))
		}
	}()
	<-starting
	checkProgress(t, tester.downloader, "completing", ethereum.SyncProgress{
		CurrentBlock: afterFailedSync.CurrentBlock,
		HighestBlock: uint64(validChain.len() - 1),
	})

	// Check final progress after successful sync.
	progress <- struct{}{}
	pending.Wait()
	checkProgress(t, tester.downloader, "final", ethereum.SyncProgress{
		CurrentBlock: uint64(validChain.len() - 1),
		HighestBlock: uint64(validChain.len() - 1),
	})
}

// TestStateSyncSpindownCompletedDoesNotBlock tests state sync spindown completed does not block.
func TestStateSyncSpindownCompletedDoesNotBlock(t *testing.T) {
	t.Parallel()

	tester := newTester()
	defer tester.terminate()

	if err := tester.newPeer("active", 63, testChainBase.shorten(8)); err != nil {
		t.Fatalf("failed to create peer: %v", err)
	}
	peer := tester.downloader.peers.Peer("active")
	if peer == nil {
		t.Fatal("peer not registered")
	}
	atomic.StoreInt32(&peer.stateIdle, 1)
	peer.stateStarted = time.Now()

	req := &stateReq{
		nItems: 1,
		peer:   peer,
		timer:  time.NewTimer(time.Hour),
	}
	defer req.timer.Stop()

	done := make(chan struct{})
	go func() {
		tester.downloader.spindownStateSync(
			map[string]*stateReq{peer.id: req},
			nil,
			make(chan *stateReq),
			make(chan *peerConnection),
			true,
		)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("state sync spindown blocked after completion")
	}
	if atomic.LoadInt32(&peer.stateIdle) != 0 {
		t.Fatal("peer was not marked idle after completed state sync")
	}
}

// This test reproduces an issue where unexpected deliveries would
// block indefinitely if they arrived at the right time.
func TestDeliverHeadersHang(t *testing.T) {
	t.Skip("This test failed sometimes and is inconsistent result. Disable for now.")
	t.Parallel()

	testCases := []struct {
		protocol int
		syncMode SyncMode
	}{
		{62, FullSync},
		{63, FullSync},
		{63, FastSync},
		{64, FullSync},
		{64, FastSync},
		{64, LightSync},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("protocol %d mode %v", tc.protocol, tc.syncMode), func(t *testing.T) {
			t.Parallel()
			testDeliverHeadersHang(t, tc.protocol, tc.syncMode)
		})
	}
}

func testDeliverHeadersHang(t *testing.T, protocol int, mode SyncMode) {
	master := newTester()
	defer master.terminate()
	chain := testChainBase.shorten(15)

	for i := 0; i < 200; i++ {
		tester := newTester()
		tester.peerDb = master.peerDb
		tester.newPeer("peer", protocol, chain)

		// Whenever the downloader requests headers, flood it with
		// a lot of unrequested header deliveries.
		tester.downloader.peers.peers["peer"].peer = &floodingTestPeer{
			peer:   tester.downloader.peers.peers["peer"].peer,
			tester: tester,
		}
		if err := tester.sync("peer", nil, mode); err != nil {
			t.Errorf("test %d: sync failed: %v", i, err)
		}
		tester.terminate()
	}
}

type floodingTestPeer struct {
	peer   Peer
	tester *downloadTester
}

func (ftp *floodingTestPeer) Head() (common.Hash, *big.Int) { return ftp.peer.Head() }
func (ftp *floodingTestPeer) RequestHeadersByHash(hash common.Hash, count int, skip int, reverse bool) error {
	return ftp.peer.RequestHeadersByHash(hash, count, skip, reverse)
}
func (ftp *floodingTestPeer) RequestBodies(hashes []common.Hash) error {
	return ftp.peer.RequestBodies(hashes)
}
func (ftp *floodingTestPeer) RequestReceipts(hashes []common.Hash) error {
	return ftp.peer.RequestReceipts(hashes)
}
func (ftp *floodingTestPeer) RequestNodeData(hashes []common.Hash) error {
	return ftp.peer.RequestNodeData(hashes)
}

func (ftp *floodingTestPeer) RequestHeadersByNumber(from uint64, count, skip int, reverse bool) error {
	deliveriesDone := make(chan struct{}, 500)
	for i := 0; i < cap(deliveriesDone)-1; i++ {
		peer := fmt.Sprintf("fake-peer%d", i)
		go func() {
			ftp.tester.downloader.DeliverHeaders(peer, []*types.Header{{}, {}, {}, {}})
			deliveriesDone <- struct{}{}
		}()
	}

	// None of the extra deliveries should block.
	timeout := time.After(60 * time.Second)
	launched := false
	for i := 0; i < cap(deliveriesDone); i++ {
		select {
		case <-deliveriesDone:
			if !launched {
				// Start delivering the requested headers
				// after one of the flooding responses has arrived.
				go func() {
					ftp.peer.RequestHeadersByNumber(from, count, skip, reverse)
					deliveriesDone <- struct{}{}
				}()
				launched = true
			}
		case <-timeout:
			panic("blocked")
		}
	}
	return nil
}

// TestRemoteHeaderRequestSpan tests remote header request span.
func TestRemoteHeaderRequestSpan(t *testing.T) {
	testCases := []struct {
		remoteHeight uint64
		localHeight  uint64
		expected     []int
	}{
		// Remote is way higher. We should ask for the remote head and go backwards
		{1500, 1000,
			[]int{1323, 1339, 1355, 1371, 1387, 1403, 1419, 1435, 1451, 1467, 1483, 1499},
		},
		{15000, 13006,
			[]int{14823, 14839, 14855, 14871, 14887, 14903, 14919, 14935, 14951, 14967, 14983, 14999},
		},
		//Remote is pretty close to us. We don't have to fetch as many
		{1200, 1150,
			[]int{1149, 1154, 1159, 1164, 1169, 1174, 1179, 1184, 1189, 1194, 1199},
		},
		// Remote is equal to us (so on a fork with higher td)
		// We should get the closest couple of ancestors
		{1500, 1500,
			[]int{1497, 1499},
		},
		// We're higher than the remote! Odd
		{1000, 1500,
			[]int{997, 999},
		},
		// Check some weird edgecases that it behaves somewhat rationally
		{0, 1500,
			[]int{0, 2},
		},
		{6000000, 0,
			[]int{5999823, 5999839, 5999855, 5999871, 5999887, 5999903, 5999919, 5999935, 5999951, 5999967, 5999983, 5999999},
		},
		{0, 0,
			[]int{0, 2},
		},
	}
	reqs := func(from, count, span int) []int {
		var r []int
		num := from
		for len(r) < count {
			r = append(r, num)
			num += span + 1
		}
		return r
	}
	for i, tt := range testCases {
		from, count, span, max := calculateRequestSpan(tt.remoteHeight, tt.localHeight)
		data := reqs(int(from), count, span)

		if max != uint64(data[len(data)-1]) {
			t.Errorf("test %d: wrong last value %d != %d", i, data[len(data)-1], max)
		}
		failed := false
		if len(data) != len(tt.expected) {
			failed = true
			t.Errorf("test %d: length wrong, expected %d got %d", i, len(tt.expected), len(data))
		} else {
			for j, n := range data {
				if n != tt.expected[j] {
					failed = true
					break
				}
			}
		}
		if failed {
			res := strings.Replace(fmt.Sprint(data), " ", ",", -1)
			exp := strings.Replace(fmt.Sprint(tt.expected), " ", ",", -1)
			fmt.Printf("got: %v\n", res)
			fmt.Printf("exp: %v\n", exp)
			t.Errorf("test %d: wrong values", i)
		}
	}
}

// Tests that synchronisation succeeds when the peer is slightly ahead but within
// a range that triggers reorg protection AND causes the skeleton to fail (so
// full-fetch mode is used, returning very few headers per request).
//
// This is a regression test for a bug introduced in ethereum/go-ethereum#17839:
// when the peer is between (reorgProtThreshold, MaxHeaderFetch) blocks ahead,
// the skeleton request returns 0 headers (peer doesn't have the skeleton range),
// the downloader falls back to full-fetch. On the last batch only 1-2 headers
// remain; the reorg-protection delay cuts ALL of them (delay=min(2,n)=n,
// remaining=0), and the downloader retries every fsHeaderContCheck forever
// without making progress.
//
// In production the bug manifested as a permanent stall because block insertion
// was blocked by the BFT consensus engine (which itself waited for sync to
// finish), keeping CurrentBlock low. We simulate that condition here by using
// chainInsertHook to pause insertion long enough that CurrentBlock cannot
// advance between header-fetch retries.
//
// Concretely: gap=51 matches the real-world scenario observed in production
// (local=3,807,570, peer=3,807,621, localHead+48=3,807,618 < 3,807,621).
func TestReorgProtectionDoesNotStallSync63Full(t *testing.T) {
	testReorgProtectionDoesNotStallSync(t, 63, FullSync)
}

// TestReorgProtectionDoesNotStallSync64Full tests reorg protection does not stall sync 64 full.
func TestReorgProtectionDoesNotStallSync64Full(t *testing.T) {
	testReorgProtectionDoesNotStallSync(t, 64, FullSync)
}

func testReorgProtectionDoesNotStallSync(t *testing.T, protocol int, mode SyncMode) {
	t.Parallel()

	// All gaps are > reorgProtThreshold (48) so reorg protection fires on the
	// last batch, but < MaxHeaderFetch (192) so the skeleton fails and
	// full-fetch is used. The critical cases are gap=49 and gap=50 where the
	// final batch has exactly 2 headers and delay=min(2,2)=2 cuts all of them.
	gaps := []int{
		reorgProtThreshold + 1,                        // 49: final batch = 2 headers, delay cuts all
		reorgProtThreshold + 2,                        // 50: final batch = 2 headers, delay cuts all
		reorgProtThreshold + reorgProtHeaderDelay + 1, // 51: the exact production scenario
		MaxHeaderFetch - 1,                            // 191: just below skeleton threshold
	}

	for _, gap := range gaps {
		gap := gap
		t.Run(fmt.Sprintf("gap=%d", gap), func(t *testing.T) {
			t.Parallel()

			tester := newTester()
			defer tester.terminate()

			baseLen := blockCacheMaxItems - 15
			peerChain := testChainBase.shorten(baseLen + gap)
			localChain := testChainBase.shorten(baseLen)

			// Pre-populate the tester's local chain with baseLen blocks so that
			// CurrentBlock() returns the block at height baseLen-1.
			tester.ownHashes = append(tester.ownHashes[:0], localChain.chain...)
			for hash, header := range localChain.headerm {
				tester.ownHeaders[hash] = header
			}
			for _, block := range localChain.blockm {
				tester.ownBlocks[block.Hash()] = block
				// Stub stateDb so CurrentBlock's lookup succeeds.
				tester.stateDb.Put(block.Root().Bytes(), []byte{0x00})
			}
			// Do not copy receipts: FullSync doesn't download receipts, so
			// assertOwnChain expects receipts == 1 (genesis only).
			for hash, td := range localChain.tdm {
				tester.ownChainTd[hash] = td
			}

			// Delay only the FIRST block-insertion call to keep CurrentBlock low
			// while fetchHeaders makes its second header request. This reproduces
			// the key condition of the bug:
			//
			//   1. fetchHeaders delivers a first batch (gap-2 headers).
			//   2. fetchHeaders immediately retries; the last batch has only 2
			//      headers. The reorg-protection check fires because
			//      localHead+threshold < peerHead, and delay=min(2,2)=2 would
			//      cut ALL remaining headers. Without the fix this causes a
			//      fsHeaderContCheck retry loop that resolves only once
			//      CurrentBlock advances – which requires the first insertion
			//      batch to finish.
			//   3. With insertDelay > fsHeaderContCheck the retry happens before
			//      CurrentBlock can advance, so the loop iterates at least once.
			//
			// Only the first hook call sleeps; subsequent calls are instant.
			// This avoids compounding delays when there are multiple insertion
			// batches (e.g. gap=191 may produce two batches: 189 then 2 blocks).
			//
			// Timeline (D = insertDelay, R = fsHeaderContCheck):
			//   WITHOUT fix: D (first insert) + R (one retry) = D + R
			//   WITH fix:    D (first insert, all headers already queued) ≈ D
			//
			// timeout = D + R/2 sits between the two, so fix passes, bug fails.
			insertDelay := 4 * fsHeaderContCheck         // e.g. 2 s
			timeout := insertDelay + fsHeaderContCheck/2 // e.g. 2.25 s

			var firstHookDone uint32
			tester.downloader.chainInsertHook = func(_ []*fetchResult) {
				if atomic.CompareAndSwapUint32(&firstHookDone, 0, 1) {
					time.Sleep(insertDelay)
				}
			}

			tester.newPeer("peer", protocol, peerChain)

			done := make(chan error, 1)
			go func() {
				done <- tester.sync("peer", nil, mode)
			}()

			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("sync failed (gap=%d, mode=%v): %v", gap, mode, err)
				}
			case <-time.After(timeout):
				t.Fatalf("sync timed out after %v (gap=%d, mode=%v): "+
					"reorg protection is cutting all headers on last batch and stalling the downloader",
					timeout, gap, mode)
			}

			assertOwnChain(t, tester, peerChain.len())
		})
	}
}

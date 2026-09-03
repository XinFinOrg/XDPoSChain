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
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ethereum "github.com/XinFinOrg/XDPoSChain"
	"github.com/XinFinOrg/XDPoSChain/common"
	engine_v2 "github.com/XinFinOrg/XDPoSChain/consensus/XDPoS/engines/engine_v2"
	"github.com/XinFinOrg/XDPoSChain/core"
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

// Protocol versions accepted by the downloader, mirroring the constants of the
// eth package, which cannot be imported here without creating an import cycle.
// xdc100 and xdc165 are the current minProtocolVer and maxProtocolVer bounds.
const (
	xdc100 = 100
	xdc164 = 164
	xdc165 = 165
)

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

	// headHeaderCap, when non-zero, caps the height reported by CurrentHeader.
	// It models the real chain, where importing blocks moves the header head
	// back to the block being inserted. It must be set below the length of the
	// peer chain being synced; a value at or above the chain head simply
	// disables the cap and no longer models the lagging head.
	//
	// The cap is static, while the real lag is a transient window around the
	// block being imported, but the simplified model is enough to reproduce
	// the stall misdetection in the terminating header batch.
	headHeaderCap uint64

	// configOverride, when non-nil, is returned by Config() instead of the
	// default TestChainConfig.  Used by tests that require XDPoS to be active.
	configOverride *params.ChainConfig

	lock sync.RWMutex
}

// newTester creates a new downloader test mocker.
func newTester() *downloadTester {
	return newTesterWithGenesis(testGenesis, testDB)
}

// newTesterWithGenesis creates a new downloader test mocker backed by a custom
// genesis and peer database, for tests whose chain state differs from the
// shared test genesis.
func newTesterWithGenesis(genesis *types.Block, peerDb ethdb.Database) *downloadTester {
	tester := &downloadTester{
		genesis:     genesis,
		peerDb:      peerDb,
		peers:       make(map[string]*downloadTesterPeer),
		ownHashes:   []common.Hash{genesis.Hash()},
		ownHeaders:  map[common.Hash]*types.Header{genesis.Hash(): genesis.Header()},
		ownBlocks:   map[common.Hash]*types.Block{genesis.Hash(): genesis},
		ownReceipts: map[common.Hash]types.Receipts{genesis.Hash(): nil},
		ownChainTd:  map[common.Hash]*big.Int{genesis.Hash(): genesis.Difficulty()},
	}
	tester.stateDb = rawdb.NewMemoryDatabase()
	tester.triedb = trie.NewDatabase(tester.stateDb)
	tester.stateDb.Put(genesis.Root().Bytes(), []byte{0x00})
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
			if dl.headHeaderCap != 0 && header.Number.Uint64() > dl.headHeaderCap {
				continue
			}
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

// writeBlockWithoutState mirrors core.BlockChain.writeBlockWithoutState: the block
// becomes known by hash, but without state it cannot become the chain head. The
// parent must have been imported first (e.g. via InsertChain), as the simulated
// chain only tracks the total difficulty of blocks it already knows.
//
// The block is deliberately kept out of ownHashes, the tester's canonical hash
// chain: a real node writes such blocks as non-canonical side blocks, so the
// head getters keep reporting the imported head. Raising CurrentSnapBlock in
// particular would inflate the local height findAncestor derives in fast sync
// and mask a sync that resumes above the head.
func (dl *downloadTester) writeBlockWithoutState(block *types.Block) error {
	dl.lock.Lock()
	defer dl.lock.Unlock()

	parentTd, ok := dl.ownChainTd[block.ParentHash()]
	if !ok {
		return fmt.Errorf("parent block %s not imported", block.ParentHash())
	}
	dl.ownHeaders[block.Hash()] = block.Header()
	dl.ownBlocks[block.Hash()] = block
	dl.ownChainTd[block.Hash()] = new(big.Int).Add(parentTd, block.Difficulty())
	return nil
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
	if dl.configOverride != nil {
		return dl.configOverride
	}
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
	// requestHook, when non-nil, observes every numbered header request just
	// before the fake peer serves it, letting tests assert which heights the
	// downloader actually probes.
	requestHook func(origin uint64, amount int, skip int, reverse bool)
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
	if dlp.requestHook != nil {
		dlp.requestHook(origin, amount, skip, reverse)
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
func TestCanonicalSynchronisation100Full(t *testing.T) {
	testCanonicalSynchronisation(t, xdc100, FullSync)
}
func TestCanonicalSynchronisation100Fast(t *testing.T) {
	testCanonicalSynchronisation(t, xdc100, FastSync)
}
func TestCanonicalSynchronisation164Full(t *testing.T) {
	testCanonicalSynchronisation(t, xdc164, FullSync)
}
func TestCanonicalSynchronisation164Fast(t *testing.T) {
	testCanonicalSynchronisation(t, xdc164, FastSync)
}
func TestCanonicalSynchronisation164Light(t *testing.T) {
	testCanonicalSynchronisation(t, xdc164, LightSync)
}
func TestCanonicalSynchronisation165Full(t *testing.T) {
	testCanonicalSynchronisation(t, xdc165, FullSync)
}
func TestCanonicalSynchronisation165Fast(t *testing.T) {
	testCanonicalSynchronisation(t, xdc165, FastSync)
}
func TestCanonicalSynchronisation165Light(t *testing.T) {
	testCanonicalSynchronisation(t, xdc165, LightSync)
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

// TestFindAncestorIgnoresBlocksAboveHead checks that blocks stored ahead of the
// chain head are not accepted as the common ancestor through the span search.
// Side chain blocks are written by hash without state, so accepting one
// resumes the sync above the head and leaves the range in between permanently
// unimported. The request span is capped at the local head, and any header it
// still samples past the requested top is rejected by the usableAsAncestor head
// guard, so the sync anchors at or below the head.
func TestFindAncestorIgnoresBlocksAboveHead(t *testing.T) {
	t.Parallel()
	testFindAncestorIgnoresBlocksAboveHead(t, FullSync, 64, 32, 32)
}

// TestFindAncestorIgnoresBlocksAboveHeadFast runs the blocks-above-head
// scenario in fast sync, where the ancestor search derives the local height
// from the snap block: stubs stored ahead of the head must neither raise the
// reported snap head nor be accepted as the common ancestor.
func TestFindAncestorIgnoresBlocksAboveHeadFast(t *testing.T) {
	t.Parallel()
	testFindAncestorIgnoresBlocksAboveHead(t, FastSync, 128, 32, 32)
}

// testFindAncestorIgnoresBlocksAboveHead runs the blocks-above-head scenario:
// the local head sits at headHeight while the rest of the chainLen-block chain
// is only known by hash (plus receipts on the fast sync path), the way a side
// chain segment is written, and the sync must resume from the head instead of
// resuming above it. A high head (headHeight 32) keeps the span window at or
// below the head: the span search never samples above it. A head of 1 is the
// one height where the clamped window {0, 2} tops the request out at the
// first block past the head; that header is served and rejected by
// usableAsAncestor's head guard, and the genesis hit the span still finds is
// refined over the unsampled gap, so the sync anchors at the head anyway.
// wantOrigin pins the expected anchor exactly: the head itself.
//
// The scenario runs in full and fast sync. FastSync derives the local height
// from the snap block, so it also pins that stubs stored ahead of the head do
// not raise the reported snap head. Fast sync knowledge is modeled through
// receipts, so the fast sync runs give the stubs receipts as well: the blocks
// above the head count as known, so usableAsAncestor's head guard is what keeps
// them out, not a missing-receipt lookup. Its chain is kept long enough
// (chainLen > headHeight+fsMinFullBlocks) for the fast sync pivot to land
// above the origin; a chain at or below fsMinFullBlocks would force the
// origin back to genesis instead.
func testFindAncestorIgnoresBlocksAboveHead(t *testing.T, mode SyncMode, chainLen int, headHeight, wantOrigin uint64) {
	t.Helper()

	tester := newTester()
	defer tester.terminate()

	chain := testChainBase.shorten(chainLen)
	tester.newPeer("peer", xdc165, chain)

	imported := make([]*types.Block, 0, headHeight)
	for i := uint64(1); i <= headHeight; i++ {
		imported = append(imported, chain.blockm[chain.chain[i]])
	}
	if _, err := tester.InsertChain(imported); err != nil {
		t.Fatalf("failed to import blocks: %v", err)
	}
	stubs := make(types.Blocks, 0, uint64(chain.len())-headHeight-1)
	for i := headHeight + 1; i < uint64(chain.len()); i++ {
		block := chain.blockm[chain.chain[i]]
		if err := tester.writeBlockWithoutState(block); err != nil {
			t.Fatalf("failed to write block without state: %v", err)
		}
		stubs = append(stubs, block)
	}
	if mode == FastSync {
		// The fake chain reports fast-sync knowledge through receipts, so the
		// whole stored prefix must carry them the way a fast-synced local chain
		// has them: the imported prefix keeps the head syncable, and the stubs
		// get receipts too so the blocks above the head count as known.
		// usableAsAncestor's head guard is then what keeps them out; receipt-less
		// stubs would be dropped as unknown instead, so a sync that lost the
		// guard would still anchor below the head and mask the regression.
		blocks := append(append(types.Blocks{}, imported...), stubs...)
		receipts := make([]types.Receipts, len(blocks))
		for i := range receipts {
			receipts[i] = types.Receipts{}
		}
		if _, err := tester.InsertReceiptChain(blocks, receipts); err != nil {
			t.Fatalf("failed to insert receipts: %v", err)
		}
	}
	if have := tester.CurrentBlock().Number.Uint64(); have != headHeight {
		t.Fatalf("unexpected head: have %d want %d", have, headHeight)
	}

	// Record the first numbered header request the sync issues: inside
	// findAncestor that is always the span search request. The requested
	// range must top out at the head, otherwise the span burns its samples
	// on blocks usableAsAncestor rejects anyway. Also record the very last
	// numbered request to pin the sync's completion: a graceful fetchHeaders
	// run terminates with an empty probe at the first height past the remote
	// head, so a run that silently stalls after the ancestor search stops
	// requesting earlier.
	var (
		spanRequested bool
		spanOrigin    uint64
		spanLast      uint64
		lastRequest   uint64
	)
	tester.peers["peer"].requestHook = func(origin uint64, amount int, skip int, reverse bool) {
		if !spanRequested {
			spanRequested = true
			spanOrigin = origin
			spanLast = origin + uint64((amount-1)*(skip+1))
		}
		lastRequest = origin
	}

	var origin uint64
	tester.downloader.syncInitHook = func(from, _ uint64) { origin = from }

	if err := tester.sync("peer", nil, mode); err != nil {
		t.Fatalf("failed to synchronise blocks: %v", err)
	}
	if !spanRequested {
		t.Fatalf("no numbered header request issued, span search not exercised")
	}
	// The span request must top out exactly at the head. The single
	// exception is the clamped window of calculateRequestSpan: with the
	// head at 0 or 1 the window is {0, 2} and tops the request out at the
	// first block past the head (pinned in TestRemoteHeaderRequestSpan);
	// those headers are served and considered, but rejected by usableAsAncestor's
	// head guard, so the exception is tied to the head while the request
	// stays anchored at genesis.
	wantSpanLast := max(headHeight, 2)
	if spanLast != wantSpanLast {
		t.Fatalf("span request tops out at the wrong height: last %d, want %d, head %d", spanLast, wantSpanLast, headHeight)
	}
	if spanLast > headHeight && spanOrigin != 0 {
		t.Fatalf("span request tops out above the head without a below-head anchor: origin %d, head %d", spanOrigin, headHeight)
	}
	// Whatever the head height, the sync must anchor at the head itself: the
	// span hit is refined over the unsampled gap below the next sample, so a
	// genesis hit with the head at 1 still converges on the head. Pin the
	// anchor exactly: an ancestor at or below the head is not enough, a
	// regression re-anchoring lower (e.g. at genesis) must fail as well.
	if origin != wantOrigin {
		t.Fatalf("sync resumed at the wrong ancestor: origin %d, want %d (head %d)", origin, wantOrigin, headHeight)
	}
	// Anchoring is not enough: the sync must actually reach the remote head.
	// fetchHeaders terminates with an empty numbered probe at the first
	// height past the remote head, so a run that silently stalls after the
	// ancestor search ends its request stream earlier and is caught here.
	// (CurrentBlock cannot serve this purpose: every header the sync fetches
	// is already stored by hash, so the simulated chain's head never moves.)
	if remoteHeight := uint64(chain.len() - 1); lastRequest != remoteHeight+1 {
		t.Fatalf("sync did not fetch up to the remote head: last numbered request at %d, want %d", lastRequest, remoteHeight+1)
	}
}

// TestFindAncestorSpanRejectsAboveHeadCandidate drives the one height where
// the clamped span window tops the request out at the first block past the
// head: with the local head at height 1 the peer is asked for
// block 2 as well, which the test stores by hash the way a side chain segment
// is written. The span's acceptance window follows the raw request top, so
// block 2 is served and considered; usableAsAncestor's head guard is what rejects
// it, and the genesis hit the span still finds is refined over the unsampled
// gap, so the sync anchors at the head.
func TestFindAncestorSpanRejectsAboveHeadCandidate(t *testing.T) {
	t.Parallel()
	testFindAncestorIgnoresBlocksAboveHead(t, FullSync, 64, 1, 1)
}

// TestFindAncestorSpanRejectsAboveHeadCandidateFast runs the same clamped
// window overshoot in fast sync: with the local head at height 1 the span
// request still tops out at the first block past the head, and that stub carries
// receipts, so it counts as known. usableAsAncestor's head guard is what rejects
// it, and the genesis hit the span still finds is refined over the unsampled
// gap: the sync must anchor at the head instead of resuming above it.
func TestFindAncestorSpanRejectsAboveHeadCandidateFast(t *testing.T) {
	t.Parallel()
	testFindAncestorIgnoresBlocksAboveHead(t, FastSync, 128, 1, 1)
}

// TestFindAncestorSpanAnchorsAtHeadZero pins the genesis boundary of the span
// search: with the local head at genesis, the genesis hit is the head itself
// and must be returned as is. Blocks stored above the head are rejected by
// usableAsAncestor's head guard, so the sync must neither resume above the head
// nor search below a hit that is already exact.
func TestFindAncestorSpanAnchorsAtHeadZero(t *testing.T) {
	t.Parallel()
	testFindAncestorIgnoresBlocksAboveHead(t, FullSync, 64, 0, 0)
}

// TestFindAncestorSpanAnchorsAtHeadTwo pins the first height where the span
// window {head-2, head} samples the head itself: the hit is exact, and
// the sync must anchor at the head instead of drifting to a lower sample.
func TestFindAncestorSpanAnchorsAtHeadTwo(t *testing.T) {
	t.Parallel()
	testFindAncestorIgnoresBlocksAboveHead(t, FullSync, 64, 2, 2)
}

// TestFindAncestorSpanRefinesBelowLowestSample drives the reorg boundary the
// head-capped span window creates: with the local head sitting on the first
// block the peer's fork replaces, the window {head-2, head} rejects the head
// sample and hits its lower sample, while the true common ancestor sits on
// the unsampled head-1. The span hit must be refined over the unsampled gap,
// so the sync anchors at head-1 instead of re-importing the head block it
// already has.
func TestFindAncestorSpanRefinesBelowLowestSample(t *testing.T) {
	t.Parallel()

	const (
		forkPoint  = 10 // first block the peer's chain replaces
		headHeight = 10 // the local head sits on the replaced block
		chainLen   = 64
	)

	tester := newTester()
	defer tester.terminate()

	// Peer on a heavy fork sharing blocks 0..forkPoint-1 with the base chain
	// and replacing everything from forkPoint up, so the sync must reorg onto
	// it from the common ancestor just below the local head.
	fork := testChainBase.shorten(forkPoint).makeFork(chainLen-forkPoint, true, 7)
	tester.newPeer("peer", xdc165, fork)

	// Sanity check the span window the call site issues: it samples the local
	// head (the fork replaced it) and head-2 (still common), leaving the true
	// ancestor at head-1 unsampled between the two samples. The remote head
	// is the top of the peer's chain; the function caps the sampling top at
	// the local head.
	from, count, skip, max := calculateRequestSpan(uint64(chainLen-1), headHeight)
	if from != int64(headHeight-2) || count != 2 || skip != 1 || max != headHeight {
		t.Fatalf("unexpected span window: from %d count %d skip %d max %d", from, count, skip, max)
	}

	// Import the common prefix plus the first replaced block, so the local
	// head sits exactly on a block the peer's chain no longer contains.
	imported := make([]*types.Block, 0, headHeight)
	for i := uint64(1); i <= headHeight; i++ {
		imported = append(imported, testChainBase.blockm[testChainBase.chain[i]])
	}
	if _, err := tester.InsertChain(imported); err != nil {
		t.Fatalf("failed to import blocks: %v", err)
	}
	if have := tester.CurrentBlock().Number.Uint64(); have != headHeight {
		t.Fatalf("unexpected head: have %d want %d", have, headHeight)
	}

	// Record every numbered header request the ancestor search issues: the
	// span window and the refinement probe must both stay at or below the
	// head, anything above can never be accepted as the common ancestor.
	var (
		searching = true
		origin    uint64
		requested []uint64
	)
	tester.peers["peer"].requestHook = func(from uint64, amount int, skip int, reverse bool) {
		if searching {
			requested = append(requested, from)
		}
	}
	tester.downloader.syncInitHook = func(from, _ uint64) {
		searching = false
		origin = from
	}

	if err := tester.sync("peer", nil, FullSync); err != nil {
		t.Fatalf("failed to synchronise blocks: %v", err)
	}
	if len(requested) < 2 {
		t.Fatalf("span search was not refined over the unsampled gap: %d request(s)", len(requested))
	}
	for i, probe := range requested {
		if probe > headHeight {
			t.Fatalf("ancestor search request #%d probes above the head: %d > %d", i, probe, headHeight)
		}
	}
	if origin != forkPoint-1 {
		t.Fatalf("sync resumed at the wrong ancestor: origin %d want %d", origin, forkPoint-1)
	}
	if have := tester.CurrentBlock().Number.Uint64(); have != uint64(chainLen-1) {
		t.Fatalf("unexpected head after sync: have %d want %d", have, chainLen-1)
	}
}

// TestFindAncestorSpanRemoteAtGenesis pins the remote-head clamp of the gap
// refinement: a peer whose head is the genesis block can only reach the sync
// through a direct Synchronise call (the sync entry gate requires a TD
// advantage), yet it exercises a real boundary of the ancestor search. Its
// clamped span window {0, 2} hits at genesis and refines to the interval
// [0, 1]; the refinement must stop at the peer's head instead of probing
// past it, because an empty reply to a probe above the head fails the whole
// sync rather than just burning a round trip.
func TestFindAncestorSpanRemoteAtGenesis(t *testing.T) {
	t.Parallel()

	tester := newTester()
	defer tester.terminate()

	// Peer holding nothing but the genesis block, sharing it with the base
	// chain the local chain extends.
	peerChain := testChainBase.shorten(1)
	tester.newPeer("peer", xdc165, peerChain)

	// Advance the local chain one block past the peer's head.
	imported := []*types.Block{testChainBase.blockm[testChainBase.chain[1]]}
	if _, err := tester.InsertChain(imported); err != nil {
		t.Fatalf("failed to import blocks: %v", err)
	}
	if have := tester.CurrentBlock().Number.Uint64(); have != 1 {
		t.Fatalf("unexpected head: have %d want 1", have)
	}

	// Record every numbered header request the ancestor search issues: the
	// span request at genesis is fine, but a second one could only be a
	// binary-search probe above the peer's head, which the peer cannot
	// serve and which fails the sync outright.
	var (
		searching = true
		origin    uint64
		requested []uint64
	)
	tester.peers["peer"].requestHook = func(from uint64, amount int, skip int, reverse bool) {
		if searching {
			requested = append(requested, from)
		}
	}
	tester.downloader.syncInitHook = func(from, _ uint64) {
		searching = false
		origin = from
	}

	if err := tester.sync("peer", nil, FullSync); err != nil {
		t.Fatalf("failed to synchronise blocks: %v", err)
	}
	// The genesis span hit must refine to [0, 1] without a single probe
	// past the peer's head: one request, then straight to the sync with
	// the genesis anchor.
	if len(requested) != 1 || requested[0] != 0 {
		t.Fatalf("ancestor search probed past the genesis peer: requests %v", requested)
	}
	if origin != 0 {
		t.Fatalf("sync resumed at the wrong ancestor: origin %d want 0", origin)
	}
}

// TestFindAncestorBinarySearchIgnoresBlocksAboveHead checks the same guarantee
// as TestFindAncestorIgnoresBlocksAboveHead, but through the binary search.
// The request span samples only at or below the local head, so with a peer
// whose chain forks below the sampled range the span search finds nothing and
// the binary search takes over: capped at the local head, it must stop at the
// true common ancestor instead of a side chain block stored ahead of the head.
// The search is also required to never request a height above the head: such
// a probe can never be accepted as the common ancestor and would only burn a
// round trip on every rejected candidate before converging on the same one.
func TestFindAncestorBinarySearchIgnoresBlocksAboveHead(t *testing.T) {
	t.Parallel()

	const (
		forkPoint  = 35 // first block the peer's chain replaces
		headHeight = 37
		chainLen   = 64
	)

	tester := newTester()
	defer tester.terminate()

	// Peer on a heavy fork sharing blocks 0..forkPoint-1 with the base chain
	// and replacing everything from forkPoint up, so the sync can reorg onto it.
	fork := testChainBase.shorten(forkPoint).makeFork(chainLen-forkPoint, true, 7)
	tester.newPeer("peer", xdc165, fork)

	// Sanity check the request span: the call site samples only at or below
	// the head, and every sample must be replaced by the fork, otherwise
	// the span search would resolve the ancestor itself. The remote head is
	// the top of the peer's chain; the function caps the sampling top at
	// the local head.
	from, count, skip, max := calculateRequestSpan(uint64(chainLen-1), headHeight)
	if max != headHeight {
		t.Fatalf("span search samples above the head: max %d want %d", max, headHeight)
	}
	for i := 0; i < count; i++ {
		num := int(from) + i*(skip+1)
		if num < 0 || num > int(headHeight) {
			t.Fatalf("span sample #%d out of the head-capped range: %d", i, num)
		}
		if fork.blockm[fork.chain[num]].Hash() == testChainBase.blockm[testChainBase.chain[num]].Hash() {
			t.Fatalf("span sample #%d is common to both chains, binary search not exercised", num)
		}
	}

	// Import the common prefix up to the head, then store the rest of the base
	// chain by hash without state, the way a side chain segment is written.
	imported := make([]*types.Block, 0, headHeight)
	for i := uint64(1); i <= headHeight; i++ {
		imported = append(imported, testChainBase.blockm[testChainBase.chain[i]])
	}
	if _, err := tester.InsertChain(imported); err != nil {
		t.Fatalf("failed to import blocks: %v", err)
	}
	for i := uint64(headHeight + 1); i < uint64(chainLen); i++ {
		if err := tester.writeBlockWithoutState(testChainBase.blockm[testChainBase.chain[i]]); err != nil {
			t.Fatalf("failed to write block without state: %v", err)
		}
	}
	if have := tester.CurrentBlock().Number.Uint64(); have != headHeight {
		t.Fatalf("unexpected head: have %d want %d", have, headHeight)
	}

	// Record every numbered header request issued while the ancestor search
	// runs, that is everything before the post-search init hook fires: the
	// span search samples only at or below the head and the binary search
	// probes below it, so any request above the head means one of the caps
	// regressed. Recording stops at the hook because the header fetch phase
	// that follows legitimately reaches above the head.
	var (
		searching = true
		origin    uint64
		requested []uint64
	)
	tester.peers["peer"].requestHook = func(from uint64, amount int, skip int, reverse bool) {
		if searching {
			requested = append(requested, from)
		}
	}
	tester.downloader.syncInitHook = func(from, _ uint64) {
		searching = false
		origin = from
	}

	if err := tester.sync("peer", nil, FullSync); err != nil {
		t.Fatalf("failed to synchronise blocks: %v", err)
	}
	if len(requested) < 2 {
		t.Fatalf("span search resolved the ancestor, binary search not exercised: %d request(s)", len(requested))
	}
	for i, probe := range requested {
		if probe > headHeight {
			t.Fatalf("ancestor search request #%d probes above the head: %d > %d", i, probe, headHeight)
		}
	}
	if origin != forkPoint-1 {
		t.Fatalf("sync resumed at the wrong ancestor: origin %d want %d", origin, forkPoint-1)
	}
	if have := tester.CurrentBlock().Number.Uint64(); have != uint64(chainLen-1) {
		t.Fatalf("unexpected head after sync: have %d want %d", have, chainLen-1)
	}
}

// TestWriteBlockWithoutStateRequiresImportedParent asserts that the helper
// reports an unimported parent instead of silently depending on call order
// and dereferencing a missing total difficulty.
func TestWriteBlockWithoutStateRequiresImportedParent(t *testing.T) {
	t.Parallel()

	tester := newTester()
	defer tester.terminate()

	chain := testChainBase.shorten(3)
	// Block at height 2 has an unimported parent, as only the genesis is
	// known to the simulated chain.
	block := chain.blockm[chain.chain[2]]
	if err := tester.writeBlockWithoutState(block); err == nil {
		t.Fatalf("writeBlockWithoutState accepted block %s with unimported parent %s", block.Hash(), block.ParentHash())
	}
	if _, ok := tester.ownChainTd[block.Hash()]; ok {
		t.Fatalf("writeBlockWithoutState recorded a total difficulty for block %s despite the unimported parent", block.Hash())
	}
}

// TestWriteBlockWithoutStateDoesNotAdvanceHeads pins the side chain semantics
// of the helper: a block stored by hash without state is known to the chain
// but never enters the canonical hash chain, so the head getters keep
// reporting the imported head. CurrentSnapBlock in particular feeds the local
// height findAncestor derives in fast sync; letting stubs raise it would mask
// a sync that resumes above the head.
func TestWriteBlockWithoutStateDoesNotAdvanceHeads(t *testing.T) {
	t.Parallel()

	tester := newTester()
	defer tester.terminate()

	const headHeight = uint64(4)
	chain := testChainBase.shorten(int(headHeight) + 4)

	imported := make([]*types.Block, 0, headHeight)
	for i := uint64(1); i <= headHeight; i++ {
		imported = append(imported, chain.blockm[chain.chain[i]])
	}
	if _, err := tester.InsertChain(imported); err != nil {
		t.Fatalf("failed to import blocks: %v", err)
	}
	for i := headHeight + 1; i < uint64(chain.len()); i++ {
		if err := tester.writeBlockWithoutState(chain.blockm[chain.chain[i]]); err != nil {
			t.Fatalf("failed to write block without state: %v", err)
		}
	}

	heads := []struct {
		name string
		have uint64
	}{
		{"CurrentHeader", tester.CurrentHeader().Number.Uint64()},
		{"CurrentBlock", tester.CurrentBlock().Number.Uint64()},
		{"CurrentSnapBlock", tester.CurrentSnapBlock().Number.Uint64()},
	}
	for _, head := range heads {
		if head.have != headHeight {
			t.Errorf("%s reports %d, want the imported head %d", head.name, head.have, headHeight)
		}
	}
}

// TestUsableAsAncestorBoundaries checks the head-height guard of usableAsAncestor in
// every sync mode: a block at the local head is an acceptable ancestor, while
// a block one above the head is rejected even when it is known by hash. Side
// chain blocks are written by hash without state, so knowledge above the head
// is exactly what used to let the sync resume above itself. The span search
// caps its acceptance window below the head, so this white-box pin is the
// guard's only coverage; the end-to-end tests exercise the cap instead.
func TestUsableAsAncestorBoundaries(t *testing.T) {
	t.Parallel()

	tester := newTester()
	defer tester.terminate()

	const headHeight = 4
	chain := testChainBase.shorten(headHeight + 2)

	imported := make([]*types.Block, 0, headHeight)
	for i := 1; i <= headHeight; i++ {
		imported = append(imported, chain.blockm[chain.chain[i]])
	}
	if _, err := tester.InsertChain(imported); err != nil {
		t.Fatalf("failed to import blocks: %v", err)
	}
	above := chain.blockm[chain.chain[headHeight+1]]
	if err := tester.writeBlockWithoutState(above); err != nil {
		t.Fatalf("failed to write block without state: %v", err)
	}

	// The fake chain reports fast-sync knowledge through receipts, so give the
	// head and the above-head block receipts the way a fast-synced segment
	// would have them. This makes the above-head block known in every mode, so
	// only the height guard can reject it.
	receiptBlocks := make(types.Blocks, 0, headHeight+1)
	receiptBlocks = append(receiptBlocks, imported...)
	receiptBlocks = append(receiptBlocks, above)
	receipts := make([]types.Receipts, 0, headHeight+1)
	for i := 0; i <= headHeight; i++ {
		receipts = append(receipts, types.Receipts{})
	}
	if _, err := tester.InsertReceiptChain(receiptBlocks, receipts); err != nil {
		t.Fatalf("failed to insert receipts: %v", err)
	}
	if have := tester.CurrentBlock().Number.Uint64(); have != headHeight {
		t.Fatalf("unexpected head: have %d want %d", have, headHeight)
	}

	downloader := tester.downloader
	head := chain.blockm[chain.chain[headHeight]]
	for _, mode := range []SyncMode{FullSync, FastSync, LightSync} {
		if !downloader.usableAsAncestor(mode, head.Hash(), headHeight, headHeight) {
			t.Errorf("mode %s: block at the head rejected as ancestor", mode)
		}
		if downloader.usableAsAncestor(mode, above.Hash(), headHeight+1, headHeight) {
			t.Errorf("mode %s: block above the head accepted as ancestor", mode)
		}
	}
}

// Tests that if a large batch of blocks are being downloaded, it is throttled
// until the cached blocks are retrieved.
func TestThrottling100Full(t *testing.T) { testThrottling(t, xdc100, FullSync) }
func TestThrottling100Fast(t *testing.T) { testThrottling(t, xdc100, FastSync) }
func TestThrottling164Full(t *testing.T) { testThrottling(t, xdc164, FullSync) }
func TestThrottling164Fast(t *testing.T) { testThrottling(t, xdc164, FastSync) }
func TestThrottling165Full(t *testing.T) { testThrottling(t, xdc165, FullSync) }
func TestThrottling165Fast(t *testing.T) { testThrottling(t, xdc165, FastSync) }

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
func TestForkedSync100Full(t *testing.T)  { testForkedSync(t, xdc100, FullSync) }
func TestForkedSync100Fast(t *testing.T)  { testForkedSync(t, xdc100, FastSync) }
func TestForkedSync164Full(t *testing.T)  { testForkedSync(t, xdc164, FullSync) }
func TestForkedSync164Fast(t *testing.T)  { testForkedSync(t, xdc164, FastSync) }
func TestForkedSync164Light(t *testing.T) { testForkedSync(t, xdc164, LightSync) }
func TestForkedSync165Full(t *testing.T)  { testForkedSync(t, xdc165, FullSync) }
func TestForkedSync165Fast(t *testing.T)  { testForkedSync(t, xdc165, FastSync) }
func TestForkedSync165Light(t *testing.T) { testForkedSync(t, xdc165, LightSync) }

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
func TestHeavyForkedSync100Full(t *testing.T)  { testHeavyForkedSync(t, xdc100, FullSync) }
func TestHeavyForkedSync100Fast(t *testing.T)  { testHeavyForkedSync(t, xdc100, FastSync) }
func TestHeavyForkedSync164Full(t *testing.T)  { testHeavyForkedSync(t, xdc164, FullSync) }
func TestHeavyForkedSync164Fast(t *testing.T)  { testHeavyForkedSync(t, xdc164, FastSync) }
func TestHeavyForkedSync164Light(t *testing.T) { testHeavyForkedSync(t, xdc164, LightSync) }
func TestHeavyForkedSync165Full(t *testing.T)  { testHeavyForkedSync(t, xdc165, FullSync) }
func TestHeavyForkedSync165Fast(t *testing.T)  { testHeavyForkedSync(t, xdc165, FastSync) }
func TestHeavyForkedSync165Light(t *testing.T) { testHeavyForkedSync(t, xdc165, LightSync) }

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
func TestBoundedForkedSync100Full(t *testing.T)  { testBoundedForkedSync(t, xdc100, FullSync) }
func TestBoundedForkedSync100Fast(t *testing.T)  { testBoundedForkedSync(t, xdc100, FastSync) }
func TestBoundedForkedSync164Full(t *testing.T)  { testBoundedForkedSync(t, xdc164, FullSync) }
func TestBoundedForkedSync164Fast(t *testing.T)  { testBoundedForkedSync(t, xdc164, FastSync) }
func TestBoundedForkedSync164Light(t *testing.T) { testBoundedForkedSync(t, xdc164, LightSync) }
func TestBoundedForkedSync165Full(t *testing.T)  { testBoundedForkedSync(t, xdc165, FullSync) }
func TestBoundedForkedSync165Fast(t *testing.T)  { testBoundedForkedSync(t, xdc165, FastSync) }
func TestBoundedForkedSync165Light(t *testing.T) { testBoundedForkedSync(t, xdc165, LightSync) }

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
func TestBoundedHeavyForkedSync100Full(t *testing.T) { testBoundedHeavyForkedSync(t, xdc100, FullSync) }
func TestBoundedHeavyForkedSync100Fast(t *testing.T) { testBoundedHeavyForkedSync(t, xdc100, FastSync) }
func TestBoundedHeavyForkedSync164Full(t *testing.T) { testBoundedHeavyForkedSync(t, xdc164, FullSync) }
func TestBoundedHeavyForkedSync164Fast(t *testing.T) { testBoundedHeavyForkedSync(t, xdc164, FastSync) }
func TestBoundedHeavyForkedSync164Light(t *testing.T) {
	testBoundedHeavyForkedSync(t, xdc164, LightSync)
}
func TestBoundedHeavyForkedSync165Full(t *testing.T) { testBoundedHeavyForkedSync(t, xdc165, FullSync) }
func TestBoundedHeavyForkedSync165Fast(t *testing.T) { testBoundedHeavyForkedSync(t, xdc165, FastSync) }
func TestBoundedHeavyForkedSync165Light(t *testing.T) {
	testBoundedHeavyForkedSync(t, xdc165, LightSync)
}

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

// Tests that an inactive downloader will not accept incoming block headers,
// bodies and receipts.
func TestInactiveDownloader100(t *testing.T) {
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
func TestCancel100Full(t *testing.T)  { testCancel(t, xdc100, FullSync) }
func TestCancel100Fast(t *testing.T)  { testCancel(t, xdc100, FastSync) }
func TestCancel164Full(t *testing.T)  { testCancel(t, xdc164, FullSync) }
func TestCancel164Fast(t *testing.T)  { testCancel(t, xdc164, FastSync) }
func TestCancel164Light(t *testing.T) { testCancel(t, xdc164, LightSync) }
func TestCancel165Full(t *testing.T)  { testCancel(t, xdc165, FullSync) }
func TestCancel165Fast(t *testing.T)  { testCancel(t, xdc165, FastSync) }
func TestCancel165Light(t *testing.T) { testCancel(t, xdc165, LightSync) }

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
func TestMultiSynchronisation100Full(t *testing.T)  { testMultiSynchronisation(t, xdc100, FullSync) }
func TestMultiSynchronisation100Fast(t *testing.T)  { testMultiSynchronisation(t, xdc100, FastSync) }
func TestMultiSynchronisation164Full(t *testing.T)  { testMultiSynchronisation(t, xdc164, FullSync) }
func TestMultiSynchronisation164Fast(t *testing.T)  { testMultiSynchronisation(t, xdc164, FastSync) }
func TestMultiSynchronisation164Light(t *testing.T) { testMultiSynchronisation(t, xdc164, LightSync) }
func TestMultiSynchronisation165Full(t *testing.T)  { testMultiSynchronisation(t, xdc165, FullSync) }
func TestMultiSynchronisation165Fast(t *testing.T)  { testMultiSynchronisation(t, xdc165, FastSync) }
func TestMultiSynchronisation165Light(t *testing.T) { testMultiSynchronisation(t, xdc165, LightSync) }

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
func TestMultiProtoSynchronisation100Full(t *testing.T)  { testMultiProtoSync(t, xdc100, FullSync) }
func TestMultiProtoSynchronisation100Fast(t *testing.T)  { testMultiProtoSync(t, xdc100, FastSync) }
func TestMultiProtoSynchronisation164Full(t *testing.T)  { testMultiProtoSync(t, xdc164, FullSync) }
func TestMultiProtoSynchronisation164Fast(t *testing.T)  { testMultiProtoSync(t, xdc164, FastSync) }
func TestMultiProtoSynchronisation164Light(t *testing.T) { testMultiProtoSync(t, xdc164, LightSync) }
func TestMultiProtoSynchronisation165Full(t *testing.T)  { testMultiProtoSync(t, xdc165, FullSync) }
func TestMultiProtoSynchronisation165Fast(t *testing.T)  { testMultiProtoSync(t, xdc165, FastSync) }
func TestMultiProtoSynchronisation165Light(t *testing.T) { testMultiProtoSync(t, xdc165, LightSync) }

func testMultiProtoSync(t *testing.T, protocol int, mode SyncMode) {
	t.Parallel()

	tester := newTester()
	defer tester.terminate()

	// Create a small enough block chain to download
	chain := testChainBase.shorten(blockCacheMaxItems - 15)

	// Create peers of every type
	tester.newPeer("peer 100", xdc100, chain)
	tester.newPeer("peer 164", xdc164, chain)
	tester.newPeer("peer 165", xdc165, chain)

	// Synchronise with the requested peer and make sure all blocks were retrieved
	if err := tester.sync(fmt.Sprintf("peer %d", protocol), nil, mode); err != nil {
		t.Fatalf("failed to synchronise blocks: %v", err)
	}
	assertOwnChain(t, tester, chain.len())

	// Check that no peers have been dropped off
	for _, version := range []int{xdc100, xdc164, xdc165} {
		peer := fmt.Sprintf("peer %d", version)
		if _, ok := tester.peers[peer]; !ok {
			t.Errorf("%s dropped", peer)
		}
	}
}

// Tests that if a block is empty (e.g. header only), no body request should be
// made, and instead the header should be assembled into a whole block in itself.
func TestEmptyShortCircuit100Full(t *testing.T)  { testEmptyShortCircuit(t, xdc100, FullSync) }
func TestEmptyShortCircuit100Fast(t *testing.T)  { testEmptyShortCircuit(t, xdc100, FastSync) }
func TestEmptyShortCircuit164Full(t *testing.T)  { testEmptyShortCircuit(t, xdc164, FullSync) }
func TestEmptyShortCircuit164Fast(t *testing.T)  { testEmptyShortCircuit(t, xdc164, FastSync) }
func TestEmptyShortCircuit164Light(t *testing.T) { testEmptyShortCircuit(t, xdc164, LightSync) }
func TestEmptyShortCircuit165Full(t *testing.T)  { testEmptyShortCircuit(t, xdc165, FullSync) }
func TestEmptyShortCircuit165Fast(t *testing.T)  { testEmptyShortCircuit(t, xdc165, FastSync) }
func TestEmptyShortCircuit165Light(t *testing.T) { testEmptyShortCircuit(t, xdc165, LightSync) }

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
func TestMissingHeaderAttack100Full(t *testing.T)  { testMissingHeaderAttack(t, xdc100, FullSync) }
func TestMissingHeaderAttack100Fast(t *testing.T)  { testMissingHeaderAttack(t, xdc100, FastSync) }
func TestMissingHeaderAttack164Full(t *testing.T)  { testMissingHeaderAttack(t, xdc164, FullSync) }
func TestMissingHeaderAttack164Fast(t *testing.T)  { testMissingHeaderAttack(t, xdc164, FastSync) }
func TestMissingHeaderAttack164Light(t *testing.T) { testMissingHeaderAttack(t, xdc164, LightSync) }
func TestMissingHeaderAttack165Full(t *testing.T)  { testMissingHeaderAttack(t, xdc165, FullSync) }
func TestMissingHeaderAttack165Fast(t *testing.T)  { testMissingHeaderAttack(t, xdc165, FastSync) }
func TestMissingHeaderAttack165Light(t *testing.T) { testMissingHeaderAttack(t, xdc165, LightSync) }

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
func TestShiftedHeaderAttack100Full(t *testing.T)  { testShiftedHeaderAttack(t, xdc100, FullSync) }
func TestShiftedHeaderAttack100Fast(t *testing.T)  { testShiftedHeaderAttack(t, xdc100, FastSync) }
func TestShiftedHeaderAttack164Full(t *testing.T)  { testShiftedHeaderAttack(t, xdc164, FullSync) }
func TestShiftedHeaderAttack164Fast(t *testing.T)  { testShiftedHeaderAttack(t, xdc164, FastSync) }
func TestShiftedHeaderAttack164Light(t *testing.T) { testShiftedHeaderAttack(t, xdc164, LightSync) }
func TestShiftedHeaderAttack165Full(t *testing.T)  { testShiftedHeaderAttack(t, xdc165, FullSync) }
func TestShiftedHeaderAttack165Fast(t *testing.T)  { testShiftedHeaderAttack(t, xdc165, FastSync) }
func TestShiftedHeaderAttack165Light(t *testing.T) { testShiftedHeaderAttack(t, xdc165, LightSync) }

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
func TestInvalidHeaderRollback100Fast(t *testing.T)  { testInvalidHeaderRollback(t, xdc100, FastSync) }
func TestInvalidHeaderRollback164Fast(t *testing.T)  { testInvalidHeaderRollback(t, xdc164, FastSync) }
func TestInvalidHeaderRollback164Light(t *testing.T) { testInvalidHeaderRollback(t, xdc164, LightSync) }
func TestInvalidHeaderRollback165Fast(t *testing.T)  { testInvalidHeaderRollback(t, xdc165, FastSync) }
func TestInvalidHeaderRollback165Light(t *testing.T) { testInvalidHeaderRollback(t, xdc165, LightSync) }

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
func TestHighTDStarvationAttack100Full(t *testing.T) { testHighTDStarvationAttack(t, xdc100, FullSync) }
func TestHighTDStarvationAttack100Fast(t *testing.T) { testHighTDStarvationAttack(t, xdc100, FastSync) }
func TestHighTDStarvationAttack164Full(t *testing.T) { testHighTDStarvationAttack(t, xdc164, FullSync) }
func TestHighTDStarvationAttack164Fast(t *testing.T) { testHighTDStarvationAttack(t, xdc164, FastSync) }
func TestHighTDStarvationAttack164Light(t *testing.T) {
	testHighTDStarvationAttack(t, xdc164, LightSync)
}
func TestHighTDStarvationAttack165Full(t *testing.T) { testHighTDStarvationAttack(t, xdc165, FullSync) }
func TestHighTDStarvationAttack165Fast(t *testing.T) { testHighTDStarvationAttack(t, xdc165, FastSync) }
func TestHighTDStarvationAttack165Light(t *testing.T) {
	testHighTDStarvationAttack(t, xdc165, LightSync)
}

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

// Tests that a header head lagging behind the headers the peer already delivered
// is not mistaken for a stalling peer. Importing the post-pivot blocks moves the
// header head back to the block being inserted, so it can trail the synced head
// while the terminating header batch is processed. Both fast and light sync run
// the lag-sensitive check, hence both modes are covered.
func TestFastSyncHeaderHeadLag100(t *testing.T)  { testHeaderHeadLag(t, xdc100, FastSync) }
func TestFastSyncHeaderHeadLag164(t *testing.T)  { testHeaderHeadLag(t, xdc164, FastSync) }
func TestFastSyncHeaderHeadLag165(t *testing.T)  { testHeaderHeadLag(t, xdc165, FastSync) }
func TestLightSyncHeaderHeadLag164(t *testing.T) { testHeaderHeadLag(t, xdc164, LightSync) }
func TestLightSyncHeaderHeadLag165(t *testing.T) { testHeaderHeadLag(t, xdc165, LightSync) }

func testHeaderHeadLag(t *testing.T, protocol int, mode SyncMode) {
	t.Parallel()

	tester := newTester()
	defer tester.terminate()

	chain := testChainBase.shorten(blockCacheMaxItems - 15)
	tester.headHeaderCap = uint64(chain.len()) - 4
	tester.newPeer("peer", protocol, chain)

	if err := tester.sync("peer", nil, mode); err != nil {
		t.Fatalf("failed to synchronise blocks: %v", err)
	}
	assertOwnChain(t, tester, chain.len())
}

// Tests that misbehaving peers are disconnected, whilst behaving ones are not.
func TestBlockHeaderAttackerDropping100(t *testing.T) { testBlockHeaderAttackerDropping(t, xdc100) }
func TestBlockHeaderAttackerDropping164(t *testing.T) { testBlockHeaderAttackerDropping(t, xdc164) }
func TestBlockHeaderAttackerDropping165(t *testing.T) { testBlockHeaderAttackerDropping(t, xdc165) }

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
			if err := tester.newPeer("peer", xdc164, chain); err != nil {
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
			if err := tester.newPeer("peer", xdc164, chain); err != nil {
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
func TestSyncProgress100Full(t *testing.T)  { testSyncProgress(t, xdc100, FullSync) }
func TestSyncProgress100Fast(t *testing.T)  { testSyncProgress(t, xdc100, FastSync) }
func TestSyncProgress164Full(t *testing.T)  { testSyncProgress(t, xdc164, FullSync) }
func TestSyncProgress164Fast(t *testing.T)  { testSyncProgress(t, xdc164, FastSync) }
func TestSyncProgress164Light(t *testing.T) { testSyncProgress(t, xdc164, LightSync) }
func TestSyncProgress165Full(t *testing.T)  { testSyncProgress(t, xdc165, FullSync) }
func TestSyncProgress165Fast(t *testing.T)  { testSyncProgress(t, xdc165, FastSync) }
func TestSyncProgress165Light(t *testing.T) { testSyncProgress(t, xdc165, LightSync) }

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
func TestForkedSyncProgress100Full(t *testing.T)  { testForkedSyncProgress(t, xdc100, FullSync) }
func TestForkedSyncProgress100Fast(t *testing.T)  { testForkedSyncProgress(t, xdc100, FastSync) }
func TestForkedSyncProgress164Full(t *testing.T)  { testForkedSyncProgress(t, xdc164, FullSync) }
func TestForkedSyncProgress164Fast(t *testing.T)  { testForkedSyncProgress(t, xdc164, FastSync) }
func TestForkedSyncProgress164Light(t *testing.T) { testForkedSyncProgress(t, xdc164, LightSync) }
func TestForkedSyncProgress165Full(t *testing.T)  { testForkedSyncProgress(t, xdc165, FullSync) }
func TestForkedSyncProgress165Fast(t *testing.T)  { testForkedSyncProgress(t, xdc165, FastSync) }
func TestForkedSyncProgress165Light(t *testing.T) { testForkedSyncProgress(t, xdc165, LightSync) }

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
func TestFailedSyncProgress100Full(t *testing.T)  { testFailedSyncProgress(t, xdc100, FullSync) }
func TestFailedSyncProgress100Fast(t *testing.T)  { testFailedSyncProgress(t, xdc100, FastSync) }
func TestFailedSyncProgress164Full(t *testing.T)  { testFailedSyncProgress(t, xdc164, FullSync) }
func TestFailedSyncProgress164Fast(t *testing.T)  { testFailedSyncProgress(t, xdc164, FastSync) }
func TestFailedSyncProgress164Light(t *testing.T) { testFailedSyncProgress(t, xdc164, LightSync) }
func TestFailedSyncProgress165Full(t *testing.T)  { testFailedSyncProgress(t, xdc165, FullSync) }
func TestFailedSyncProgress165Fast(t *testing.T)  { testFailedSyncProgress(t, xdc165, FastSync) }
func TestFailedSyncProgress165Light(t *testing.T) { testFailedSyncProgress(t, xdc165, LightSync) }

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
func TestFakedSyncProgress100Full(t *testing.T)  { testFakedSyncProgress(t, xdc100, FullSync) }
func TestFakedSyncProgress100Fast(t *testing.T)  { testFakedSyncProgress(t, xdc100, FastSync) }
func TestFakedSyncProgress164Full(t *testing.T)  { testFakedSyncProgress(t, xdc164, FullSync) }
func TestFakedSyncProgress164Fast(t *testing.T)  { testFakedSyncProgress(t, xdc164, FastSync) }
func TestFakedSyncProgress164Light(t *testing.T) { testFakedSyncProgress(t, xdc164, LightSync) }
func TestFakedSyncProgress165Full(t *testing.T)  { testFakedSyncProgress(t, xdc165, FullSync) }
func TestFakedSyncProgress165Fast(t *testing.T)  { testFakedSyncProgress(t, xdc165, FastSync) }
func TestFakedSyncProgress165Light(t *testing.T) { testFakedSyncProgress(t, xdc165, LightSync) }

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

	if err := tester.newPeer("active", xdc100, testChainBase.shorten(8)); err != nil {
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
		{xdc100, FullSync},
		{xdc100, FastSync},
		{xdc164, FullSync},
		{xdc164, FastSync},
		{xdc164, LightSync},
		{xdc165, FullSync},
		{xdc165, FastSync},
		{xdc165, LightSync},
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

// TestRemoteHeaderRequestSpan tests the header request span calculated from
// the remote head height and the local head, the exact pair of heights
// findAncestor passes, so the table pins the wire requests the call site can
// really issue, with the sampling top derived one below the remote head and
// capped at the local head.
func TestRemoteHeaderRequestSpan(t *testing.T) {
	testCases := []struct {
		remoteHeight uint64
		localHeight  uint64
		samples      []int
		max          uint64
	}{
		// The remote head height is the exact first argument findAncestor
		// passes, so every row is a call-site reachable input. The sampling
		// top is derived one block below it and capped at the local head
		// inside the function.
		// Remote is way higher: the cap pulls the request down to the two
		// blocks just below the local head.
		{remoteHeight: 1500, localHeight: 1000, samples: []int{998, 1000}, max: 1000},
		{remoteHeight: 15000, localHeight: 13006, samples: []int{13004, 13006}, max: 13006},
		//Remote is pretty close to us. We don't have to fetch as many
		{remoteHeight: 1200, localHeight: 1150, samples: []int{1148, 1150}, max: 1150},
		// Remote is equal to us (so on a fork with higher td)
		// We should get the closest couple of ancestors
		{remoteHeight: 1500, localHeight: 1500, samples: []int{1497, 1499}, max: 1499},
		// We're higher than the remote! Odd
		{remoteHeight: 1000, localHeight: 1500, samples: []int{997, 999}, max: 999},
		// Check some weird edgecases that it behaves somewhat rationally. When
		// the raw start is negative it is clamped up to zero while the count is
		// kept, so the wire request can top out past the sampling top and max
		// follows the raw window; candidates above the local head are rejected
		// by usableAsAncestor, not by the window.
		{remoteHeight: 1, localHeight: 1500, samples: []int{0, 2}, max: 2},
		// The cap pulls the sampling top all the way down to the genesis head.
		{remoteHeight: 6000000, localHeight: 0, samples: []int{0, 2}, max: 2},
		// A remote at genesis skips the below-head decrement and derives the
		// same clamped window.
		{remoteHeight: 0, localHeight: 0, samples: []int{0, 2}, max: 2},
		// The clamped window: with the remote head at 2 the sampling top
		// lands on 1, so the raw start is negative, 'from' pins to zero and
		// the kept count tops the window out one block past the sampling
		// top. max follows the raw window in that case; anything above the
		// local head is rejected by usableAsAncestor, not by the window. Note the
		// head-at-1 entry: the clamped window cannot sample the head itself,
		// so findAncestor recovers it by refining the genesis hit over the
		// unsampled gap (TestFindAncestorSpanRejectsAboveHeadCandidate).
		{remoteHeight: 2, localHeight: 1, samples: []int{0, 2}, max: 2},
		// The local head itself is a legitimate ancestor sample even when
		// the sampling top sits below it (here the top is head-1, as whenever
		// the remote is at the local height): the raw start is negative, and
		// keeping the count after clamping 'from' to zero is what tops the
		// window out at the head. Anything above the head is still rejected
		// by usableAsAncestor, not by the window.
		{remoteHeight: 2, localHeight: 2, samples: []int{0, 2}, max: 2},
		// With the remote exactly one block ahead the sampling top lands on
		// the head without the cap being involved: 'from' stays non-negative
		// and the window tops out at the head itself, so the head is a
		// direct sample.
		{remoteHeight: 3, localHeight: 2, samples: []int{0, 2}, max: 2},
		// The cap fires with room to spare: the top pins to the head with
		// 'from' landing exactly at zero, unclamped.
		{remoteHeight: 4, localHeight: 2, samples: []int{0, 2}, max: 2},
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

		// Cross-check the returned max against the request window itself:
		// max must stay in lockstep with from/count/skip, since findAncestor
		// uses it to accept or discard the served headers.
		if max != tt.max || max != uint64(data[len(data)-1]) {
			t.Errorf("test %d: wrong max %d != %d, last sample %d", i, max, tt.max, data[len(data)-1])
		}
		failed := false
		if len(data) != len(tt.samples) {
			failed = true
			t.Errorf("test %d: length wrong, expected %d got %d", i, len(tt.samples), len(data))
		} else {
			for j, n := range data {
				if n != tt.samples[j] {
					failed = true
					break
				}
			}
		}
		if failed {
			res := strings.Replace(fmt.Sprint(data), " ", ",", -1)
			exp := strings.Replace(fmt.Sprint(tt.samples), " ", ",", -1)
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
func TestReorgProtectionDoesNotStallSync100Full(t *testing.T) {
	testReorgProtectionDoesNotStallSync(t, xdc100, FullSync)
}
func TestReorgProtectionDoesNotStallSync164Full(t *testing.T) {
	testReorgProtectionDoesNotStallSync(t, xdc164, FullSync)
}
func TestReorgProtectionDoesNotStallSync165Full(t *testing.T) {
	testReorgProtectionDoesNotStallSync(t, xdc165, FullSync)
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

// TestSetPivotBlockStoresFields verifies that SetPivotBlock persists the pivot
// number, hash, and state root onto the downloader for later use during sync.
func TestSetPivotBlockStoresFields(t *testing.T) {
	t.Parallel()

	tester := newTester()
	// Provide an XDPoS config so SetPivotBlock does not short-circuit.
	tester.configOverride = params.TestXDPoSMockChainConfig
	defer tester.terminate()
	d := tester.downloader

	wantNumber := uint64(1000)
	wantHash := common.HexToHash("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
	wantRoot := common.HexToHash("0xcafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe")

	d.SetPivotBlock(wantNumber, wantHash, wantRoot)

	if d.pivotNumber != wantNumber {
		t.Errorf("pivotNumber mismatch: have %v, want %v", d.pivotNumber, wantNumber)
	}
	if d.pivotHash != wantHash {
		t.Errorf("pivotHash mismatch: have %v, want %v", d.pivotHash, wantHash)
	}
	if d.pivotRoot != wantRoot {
		t.Errorf("pivotRoot mismatch: have %v, want %v", d.pivotRoot, wantRoot)
	}
}

// TestSetPivotBlockGapCalculation verifies the gap pivot number derivation
// produced by SetPivotBlock for a range of primary pivot numbers.
//
// With TestXDPoSMockChainConfig (Epoch=900, Gap=450):
//
//	epochBase = pivot - pivot%900
//	baseGap   = epochBase-450  (or 900-450=450 when epochBase < 450)
//	gaps      = { baseGap + 900*i  |  i=0,1,…  while value < pivot }
func TestSetPivotBlockGapCalculation(t *testing.T) {
	t.Parallel()

	tester := newTester()
	// TestXDPoSMockChainConfig has Epoch=900, Gap=450.
	tester.configOverride = params.TestXDPoSMockChainConfig
	defer tester.terminate()
	d := tester.downloader

	tests := []struct {
		pivot    uint64
		wantGaps []uint64
	}{
		// pivot ≤ baseGap(450): no gap numbers are strictly less than pivot
		{pivot: 200, wantGaps: nil},
		{pivot: 450, wantGaps: nil},
		// first gap (450) is below pivot for the first time
		{pivot: 451, wantGaps: []uint64{450}},
		// pivot at exact epoch boundary (900): only gap at 450
		// epochBase=900, baseGap=900-450=450; 450<900→add, 1350≥900→stop
		{pivot: 900, wantGaps: []uint64{450}},
		// pivot at baseGap+epoch (1350): 450<1350→add, 1350≥1350→stop
		{pivot: 1350, wantGaps: []uint64{450}},
		// pivot just above 1350: both 450 and 1350 qualify
		// epochBase=900, baseGap=450; 450<1351→add, 1350<1351→add, 2250≥1351→stop
		{pivot: 1351, wantGaps: []uint64{450, 1350}},
		// pivot at 2*epoch (1800): epochBase=1800, baseGap=1800-450=1350;
		// 1350<1800→add, 2250≥1800→stop → only [1350]
		{pivot: 1800, wantGaps: []uint64{1350}},
		// pivot just above 2250 to get two gaps in a different epoch window:
		// epochBase=1800, baseGap=1350; 1350<2251→add, 2250<2251→add, 3150≥2251→stop
		{pivot: 2251, wantGaps: []uint64{1350, 2250}},
	}

	for _, tc := range tests {
		d.SetPivotBlock(tc.pivot, common.Hash{}, common.Hash{})

		d.pivotGapLock.RLock()
		got := make([]uint64, len(d.pivotGapNumbers))
		copy(got, d.pivotGapNumbers)
		d.pivotGapLock.RUnlock()

		if len(got) != len(tc.wantGaps) {
			t.Errorf("pivot %d: gap count mismatch: have %v, want %v", tc.pivot, got, tc.wantGaps)
			continue
		}
		for i, g := range got {
			if g != tc.wantGaps[i] {
				t.Errorf("pivot %d: gap[%d] = %v, want %v", tc.pivot, i, g, tc.wantGaps[i])
			}
		}
	}
}

// TestFastSyncPivotHashMismatch checks that processFastSyncContent returns a
// descriptive "pivot block hash mismatch" error when the configured pivot hash
// does not match the actual downloaded pivot block.
func TestFastSyncPivotHashMismatch(t *testing.T) {
	t.Parallel()

	tester := newTester()
	// XDPoS config is required so SetPivotBlock can compute gap numbers.
	// TestXDPoSMockChainConfig has Epoch=900, Gap=450.
	tester.configOverride = params.TestXDPoSMockChainConfig
	defer tester.terminate()

	// Use a chain short enough to be fast but long enough to trigger state sync.
	chainLen := 300
	chain := testChainBase.shorten(chainLen)
	tester.newPeer("peer", xdc100, chain)

	// Identify the natural pivot block so we can supply the correct state root
	// (so state sync succeeds) while feeding a wrong hash (so the check fires).
	// Natural pivot = headBlock().Number - fsMinFullBlocks = (chainLen-1) - fsMinFullBlocks.
	pivotNum := uint64(chainLen - 1 - fsMinFullBlocks) // = 235
	pivotRoot := chain.headerm[chain.chain[pivotNum]].Root

	wrongHash := common.HexToHash("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
	tester.downloader.SetPivotBlock(pivotNum, wrongHash, pivotRoot)

	err := tester.sync("peer", nil, FastSync)
	if err == nil {
		t.Fatal("expected pivot hash mismatch error, got nil")
	}
	if !strings.Contains(err.Error(), "pivot block hash mismatch") {
		t.Fatalf("unexpected error: %q (want substring %q)", err.Error(), "pivot block hash mismatch")
	}
}

// TestFastSyncConfiguredPivotHashMatch verifies that setting the correct pivot
// hash and state root allows fast sync to complete successfully.
func TestFastSyncConfiguredPivotHashMatch(t *testing.T) {
	t.Parallel()

	tester := newTester()
	// XDPoS config is required so SetPivotBlock can compute gap numbers.
	// TestXDPoSMockChainConfig has Epoch=900, Gap=450.
	tester.configOverride = params.TestXDPoSMockChainConfig
	defer tester.terminate()

	chainLen := 300
	chain := testChainBase.shorten(chainLen)
	tester.newPeer("peer", xdc100, chain)

	// Natural pivot = headBlock().Number - fsMinFullBlocks = (chainLen-1) - fsMinFullBlocks.
	pivotNum := uint64(chainLen - 1 - fsMinFullBlocks) // = 235
	pivotHash := chain.headerm[chain.chain[pivotNum]].Hash()
	pivotRoot := chain.headerm[chain.chain[pivotNum]].Root

	// With Epoch=900 and pivot=235 the calculated baseGap=450 > pivot, so
	// pivotGapNumbers will be empty – this test focuses purely on hash verification.
	tester.downloader.SetPivotBlock(pivotNum, pivotHash, pivotRoot)

	if err := tester.sync("peer", nil, FastSync); err != nil {
		t.Fatalf("fast sync with correct pivot hash failed: %v", err)
	}
	assertOwnChain(t, tester, chainLen)
}

// TestFastSyncGapPivotSync exercises the gap-pivot state-sync path: when the
// configured pivot is high enough that SetPivotBlock calculates one or more gap
// pivot numbers, processFastSyncContent must state-sync each gap block and
// generate a snapshot for it before committing the primary pivot.
//
// Chain layout (Epoch=900, Gap=450, pivot=535, gap pivot=[450]):
//
//	blocks 1-534  → fast-sync (receipts)
//	block  450    → gap pivot: state synced + snapshot generated
//	block  535    → primary pivot: state synced + committed
//	blocks 536-600 → full-sync
func TestFastSyncGapPivotSync(t *testing.T) {
	t.Parallel()

	tester := newTester()
	// XDPoS config is required so SetPivotBlock can compute gap numbers.
	// TestXDPoSMockChainConfig has Epoch=900, Gap=450.
	tester.configOverride = params.TestXDPoSMockChainConfig
	defer tester.terminate()

	// 600 blocks: natural pivot = 600-1-64 = 535, gap pivot = 450.
	chainLen := 600
	chain := testChainBase.shorten(chainLen)
	tester.newPeer("peer", xdc100, chain)

	// Natural pivot = headBlock().Number - fsMinFullBlocks = (chainLen-1) - fsMinFullBlocks.
	pivotNum := uint64(chainLen - 1 - fsMinFullBlocks) // = 535
	pivotHash := chain.headerm[chain.chain[pivotNum]].Hash()
	pivotRoot := chain.headerm[chain.chain[pivotNum]].Root

	tester.downloader.SetPivotBlock(pivotNum, pivotHash, pivotRoot)

	// After SetPivotBlock the gap list should contain exactly block 450:
	// epochBase=0 (535<900), baseGap=450, first gap=450 < 535.
	tester.downloader.pivotGapLock.RLock()
	gaps := make([]uint64, len(tester.downloader.pivotGapNumbers))
	copy(gaps, tester.downloader.pivotGapNumbers)
	tester.downloader.pivotGapLock.RUnlock()

	if len(gaps) != 1 || gaps[0] != 450 {
		t.Fatalf("expected gap pivots [450], got %v", gaps)
	}

	if err := tester.sync("peer", nil, FastSync); err != nil {
		t.Fatalf("fast sync with gap pivot failed: %v", err)
	}
	assertOwnChain(t, tester, chainLen)

	// After a successful sync the gap list should have been cleared.
	tester.downloader.pivotGapLock.RLock()
	remaining := len(tester.downloader.pivotGapNumbers)
	tester.downloader.pivotGapLock.RUnlock()
	if remaining != 0 {
		t.Errorf("pivotGapNumbers not cleared after sync: %d entries remain", remaining)
	}

	// Verify that the snapshot for the gap pivot block (450) was stored and can
	// be loaded back from the downloader's state database.
	gapBlockHash := chain.headerm[chain.chain[450]].Hash()
	blob, err := rawdb.ReadXdposV2Snapshot(tester.downloader.stateDB, gapBlockHash)
	if err != nil {
		t.Fatalf("snapshot for gap pivot block 450 not found in stateDB: %v", err)
	}
	if len(blob) == 0 {
		t.Fatal("snapshot blob for gap pivot block 450 is empty")
	}
	var snap engine_v2.SnapshotV2
	if err := json.Unmarshal(blob, &snap); err != nil {
		t.Fatalf("failed to unmarshal gap pivot snapshot: %v", err)
	}
	if snap.Number != 450 {
		t.Errorf("snapshot number mismatch: have %d, want 450", snap.Number)
	}
	if snap.Hash != gapBlockHash {
		t.Errorf("snapshot hash mismatch: have %v, want %v", snap.Hash, gapBlockHash)
	}
	if !slices.Equal(snap.NextEpochCandidates, testMasternodes) {
		t.Errorf("snapshot candidates mismatch: have %v, want %v", snap.NextEpochCandidates, testMasternodes)
	}
}

// TestFastSyncGapPivotEmptyCandidatesAborts verifies the downloader-boundary
// behavior of the gap-pivot snapshot derivation: when the voting-contract
// storage holds no candidates, fast sync must abort with
// engine_v2.ErrNoCandidates and must not persist any snapshot, proving the
// failure propagates before the pivot is committed.
func TestFastSyncGapPivotEmptyCandidatesAborts(t *testing.T) {
	// Genesis without any voting-contract storage: the gap block state holds
	// no masternode candidates.
	gspec := &core.Genesis{
		Alloc:   types.GenesisAlloc{testAddress: {Balance: big.NewInt(1000000000000000000)}},
		BaseFee: big.NewInt(params.InitialBaseFee),
		Config:  testChainConfig,
	}
	peerDb := rawdb.NewMemoryDatabase()
	genesis := gspec.MustCommit(peerDb)

	tester := newTesterWithGenesis(genesis, peerDb)
	// XDPoS config is required so SetPivotBlock can compute gap numbers.
	// TestXDPoSMockChainConfig has Epoch=900, Gap=450.
	tester.configOverride = params.TestXDPoSMockChainConfig
	defer tester.terminate()

	// 600 blocks: natural pivot = 600-1-64 = 535, gap pivot = 450.
	chainLen := 600
	chain := newTestChainWithDB(chainLen, genesis, peerDb)
	tester.newPeer("peer", xdc100, chain)

	pivotNum := uint64(chainLen - 1 - fsMinFullBlocks) // = 535
	pivotHash := chain.headerm[chain.chain[pivotNum]].Hash()
	pivotRoot := chain.headerm[chain.chain[pivotNum]].Root
	tester.downloader.SetPivotBlock(pivotNum, pivotHash, pivotRoot)

	// Same layout as TestFastSyncGapPivotSync: the fixed pivot derives exactly
	// one gap pivot, block 450, so the abort is exercised on the intended block
	// instead of passing because no gap pivot was scheduled at all.
	tester.downloader.pivotGapLock.RLock()
	gaps := make([]uint64, len(tester.downloader.pivotGapNumbers))
	copy(gaps, tester.downloader.pivotGapNumbers)
	tester.downloader.pivotGapLock.RUnlock()
	if len(gaps) != 1 || gaps[0] != 450 {
		t.Fatalf("expected gap pivots [450], got %v", gaps)
	}

	if err := tester.sync("peer", nil, FastSync); !errors.Is(err, engine_v2.ErrNoCandidates) {
		t.Fatalf("fast sync with empty gap-pivot candidates error = %v, want %v", err, engine_v2.ErrNoCandidates)
	}

	// The abort happens before commitPivotBlock, so the pivot block must not
	// be in the local chain.
	if _, ok := tester.ownBlocks[pivotHash]; ok {
		t.Errorf("pivot block %d committed despite ErrNoCandidates", pivotNum)
	}
	// No snapshot may have been persisted for the gap pivot block.
	gapBlockHash := chain.headerm[chain.chain[450]].Hash()
	has, hasErr := rawdb.HasXdposV2Snapshot(tester.downloader.stateDB, gapBlockHash)
	if hasErr != nil {
		t.Fatalf("failed to probe gap pivot snapshot %s: %v", gapBlockHash, hasErr)
	}
	if has {
		t.Errorf("snapshot persisted for gap pivot block 450 despite ErrNoCandidates")
	}
}

// TestRequestTTL verifies that the request timeout scales with the measured
// round-trip time instead of being pinned to a value so small that responsive
// peers are still reported as timing out and get dropped.
func TestRequestTTL(t *testing.T) {
	tests := []struct {
		name       string
		rtt        time.Duration
		confidence float64
		want       time.Duration
	}{
		{"minimum rtt", rttMinEstimate, 1, 6 * time.Second},
		{"maximum rtt", rttMaxEstimate, 1, time.Minute},
		{"halved confidence", 5 * time.Second, 0.5, 30 * time.Second},
		{"minimum confidence", rttMinEstimate, rttMinConfidence, time.Minute},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := new(Downloader)
			atomic.StoreUint64(&d.rttEstimate, uint64(tt.rtt))
			atomic.StoreUint64(&d.rttConfidence, uint64(tt.confidence*1000000))

			if got := d.requestTTL(); got != tt.want {
				t.Fatalf("request TTL mismatch: have %v, want %v", got, tt.want)
			}
		})
	}
	// A peer must always be granted at least one full worst case round trip
	// before the downloader gives up on it, otherwise a lagging node drops its
	// healthy peers faster than it can replace them.
	if ttlLimit < rttMaxEstimate {
		t.Fatalf("ttlLimit (%v) is below rttMaxEstimate (%v)", ttlLimit, rttMaxEstimate)
	}
}

// TestDownloaderUnregisterPeerTwice verifies that a second unregister of an
// already-removed peer returns errNotRegistered, per the exported contract.
func TestDownloaderUnregisterPeerTwice(t *testing.T) {
	dl := newTester()
	defer dl.terminate()

	chain := newTestChain(1, testGenesis)
	if err := dl.newPeer("unreg", 62, chain); err != nil {
		t.Fatalf("failed to register test peer: %v", err)
	}
	if err := dl.downloader.UnregisterPeer("unreg"); err != nil {
		t.Fatalf("first unregister failed: %v", err)
	}
	if err := dl.downloader.UnregisterPeer("unreg"); err != errNotRegistered {
		t.Fatalf("second unregister error mismatch: got %v want %v", err, errNotRegistered)
	}
}

// TestDownloaderUnregisterPeerNeverRegistered verifies that unregistering a
// peer that was never registered returns errNotRegistered.
func TestDownloaderUnregisterPeerNeverRegistered(t *testing.T) {
	dl := newTester()
	defer dl.terminate()

	if err := dl.downloader.UnregisterPeer("ghost"); err != errNotRegistered {
		t.Fatalf("unregistering a never-registered peer error mismatch: got %v want %v", err, errNotRegistered)
	}
}

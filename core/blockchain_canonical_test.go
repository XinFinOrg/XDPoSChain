package core

import (
	"crypto/ecdsa"
	"math/big"
	"testing"
	"time"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/ethdb"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// canonicalTestGenesis funds a single sender so every generated block can carry
// one transaction for the transaction-lookup assertions.
func canonicalTestGenesis(from common.Address) *Genesis {
	return &Genesis{
		Config: &params.ChainConfig{
			ChainID:        big.NewInt(1338),
			HomesteadBlock: new(big.Int),
			Ethash:         new(params.EthashConfig),
		},
		Alloc: types.GenesisAlloc{from: {Balance: big.NewInt(params.Ether)}},
	}
}

// generateCanonicalTestBlocks builds n blocks with one signed transaction each.
func generateCanonicalTestBlocks(t *testing.T, gspec *Genesis, key *ecdsa.PrivateKey, n int) types.Blocks {
	t.Helper()
	to := common.HexToAddress("0x00000000000000000000000000000000000000aa")
	_, blocks, _ := GenerateChainWithGenesis(gspec, ethash.NewFaker(), n, func(i int, b *BlockGen) {
		tx, err := types.SignTx(types.NewTransaction(uint64(i), to, big.NewInt(1), params.TxGas, big.NewInt(1), nil), types.HomesteadSigner{}, key)
		if err != nil {
			t.Fatalf("failed to sign tx: %v", err)
		}
		b.AddTx(tx)
	})
	return blocks
}

// openCanonicalTestChain opens an archive chain, so every state stays on disk
// and reopening after a marker rewind never triggers the head-state repair.
func openCanonicalTestChain(t *testing.T, db ethdb.Database, gspec *Genesis) *BlockChain {
	t.Helper()
	chain, err := NewBlockChain(db, &CacheConfig{TrieDirtyDisabled: true}, gspec, ethash.NewFaker(), vm.Config{})
	if err != nil {
		t.Fatalf("failed to create chain: %v", err)
	}
	return chain
}

// TestStartupDropsCanonicalAssignmentsAboveHead covers the state a crash leaves
// behind when a head rewind commits its markers first (SetHead, the startup
// repair and a reorg all do): the markers sit at a lower block while the
// canonical assignments of the abandoned blocks are still on disk.
func TestStartupDropsCanonicalAssignmentsAboveHead(t *testing.T) {
	key, err := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	if err != nil {
		t.Fatalf("failed to create test key: %v", err)
	}
	gspec := canonicalTestGenesis(crypto.PubkeyToAddress(key.PublicKey))

	db := rawdb.NewMemoryDatabase()
	chain := openCanonicalTestChain(t, db, gspec)
	blocks := generateCanonicalTestBlocks(t, gspec, key, 6)
	if _, err := chain.InsertChain(blocks); err != nil {
		chain.Stop()
		t.Fatalf("failed to insert chain: %v", err)
	}
	chain.Stop()

	head := blocks[2]
	rawdb.WriteHeadHeaderHash(db, head.Hash())
	rawdb.WriteHeadFastBlockHash(db, head.Hash())
	rawdb.WriteHeadBlockHash(db, head.Hash())

	reopened := openCanonicalTestChain(t, db, gspec)
	defer reopened.Stop()

	if got := reopened.CurrentBlock().Number.Uint64(); got != head.NumberU64() {
		t.Fatalf("unexpected head: have %d want %d", got, head.NumberU64())
	}
	for _, block := range blocks[3:] {
		number := block.NumberU64()
		if hash := rawdb.ReadCanonicalHash(db, number); hash != (common.Hash{}) {
			t.Errorf("canonical assignment at #%d kept: %s", number, hash)
		}
		if got := reopened.GetBlockByNumber(number); got != nil {
			t.Errorf("block #%d still served by number", number)
		}
		if !reopened.HasBlock(block.Hash(), number) {
			t.Errorf("block #%d content deleted, want kept for the re-import", number)
		}
		// The lookups of the dropped range stay: they are resolved through the
		// assignment at their height, so they are inert while it is gone, and a
		// range that is re-imported later finds them in place again.
		if entry := rawdb.ReadTxLookupEntry(db, block.Transactions()[0].Hash()); entry == nil {
			t.Errorf("transaction lookup of block #%d deleted, want kept for the re-import", number)
		}
	}
	// The canonical chain at or below the head is untouched, lookups included.
	for _, block := range blocks[:3] {
		number := block.NumberU64()
		if got := reopened.GetBlockByNumber(number); got == nil {
			t.Errorf("block #%d below the head missing", number)
		}
		if entry := rawdb.ReadTxLookupEntry(db, block.Transactions()[0].Hash()); entry == nil {
			t.Errorf("transaction lookup of block #%d deleted", number)
		}
	}
}

// TestStartupKeepsCanonicalAssignmentsBetweenBlockAndHeaderHead pins the
// reconcile boundary to the header head: while a node executes behind the
// headers it already stored, canonical assignments between the block head and
// the header head are legitimate and must survive a restart.
func TestStartupKeepsCanonicalAssignmentsBetweenBlockAndHeaderHead(t *testing.T) {
	key, err := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	if err != nil {
		t.Fatalf("failed to create test key: %v", err)
	}
	gspec := canonicalTestGenesis(crypto.PubkeyToAddress(key.PublicKey))

	db := rawdb.NewMemoryDatabase()
	chain := openCanonicalTestChain(t, db, gspec)
	blocks := generateCanonicalTestBlocks(t, gspec, key, 6)
	if _, err := chain.InsertChain(blocks); err != nil {
		chain.Stop()
		t.Fatalf("failed to insert chain: %v", err)
	}
	chain.Stop()

	// Lower the block head only; the header chain stays at block 6.
	rawdb.WriteHeadBlockHash(db, blocks[2].Hash())

	reopened := openCanonicalTestChain(t, db, gspec)
	defer reopened.Stop()

	if got := reopened.CurrentBlock().Number.Uint64(); got != blocks[2].NumberU64() {
		t.Fatalf("unexpected block head: have %d want %d", got, blocks[2].NumberU64())
	}
	if got := reopened.CurrentHeader().Number.Uint64(); got != blocks[5].NumberU64() {
		t.Fatalf("unexpected header head: have %d want %d", got, blocks[5].NumberU64())
	}
	for _, block := range blocks[3:] {
		number := block.NumberU64()
		if hash := rawdb.ReadCanonicalHash(db, number); hash != block.Hash() {
			t.Errorf("canonical assignment at #%d dropped: have %s want %s", number, hash, block.Hash())
		}
		if got := reopened.GetBlockByNumber(number); got == nil {
			t.Errorf("block #%d between the block head and the header head dropped", number)
		}
	}
}

// TestStartupKeepsLookupOfReincludedCanonicalTx pins the shape an interrupted
// reorg leaves: the promoted chain re-includes a transaction of the block it
// abandoned, so the transaction is canonical at the head while the abandoned
// assignment above the head still names it. Dropping that assignment must not
// take the canonical lookup with it.
func TestStartupKeepsLookupOfReincludedCanonicalTx(t *testing.T) {
	key, err := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	if err != nil {
		t.Fatalf("failed to create test key: %v", err)
	}
	gspec := canonicalTestGenesis(crypto.PubkeyToAddress(key.PublicKey))

	db := rawdb.NewMemoryDatabase()
	chain := openCanonicalTestChain(t, db, gspec)
	blocks := generateCanonicalTestBlocks(t, gspec, key, 6)
	if _, err := chain.InsertChain(blocks); err != nil {
		chain.Stop()
		t.Fatalf("failed to insert chain: %v", err)
	}
	chain.Stop()

	headTx := blocks[1].Transactions()[0]
	// The abandoned block above the head carries the head's transaction: the
	// block hash is the header's, so rewriting the body keeps the assignment
	// naming it.
	abandoned := types.NewBlockWithHeader(blocks[2].Header()).WithBody(types.Body{
		Transactions: []*types.Transaction{headTx},
	})
	rawdb.WriteBlock(db, abandoned)

	rawdb.WriteHeadHeaderHash(db, blocks[1].Hash())
	rawdb.WriteHeadFastBlockHash(db, blocks[1].Hash())
	rawdb.WriteHeadBlockHash(db, blocks[1].Hash())

	reopened := openCanonicalTestChain(t, db, gspec)
	defer reopened.Stop()

	if entry := rawdb.ReadTxLookupEntry(db, headTx.Hash()); entry == nil || *entry != 2 {
		t.Fatalf("lookup of the canonical head transaction dropped: have %v want 2", entry)
	}
	if block := reopened.GetBlockByNumber(2); block == nil {
		t.Fatal("canonical head block #2 not served")
	}
}

// TestStartupKeepsLookupOfCanonicallyIndexedTx covers the other order of the same
// shape: the abandoned block above the head wrote its lookup last, so the entry
// names a height the sweep is about to drop while the transaction still sits in a
// canonical block below the head. The sweep cannot tell that apart from a stale
// entry, so it must not delete either: the entry is inert while its height has no
// assignment, and it is the only record the canonical block has once the range is
// re-imported.
func TestStartupKeepsLookupOfCanonicallyIndexedTx(t *testing.T) {
	key, err := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	if err != nil {
		t.Fatalf("failed to create test key: %v", err)
	}
	gspec := canonicalTestGenesis(crypto.PubkeyToAddress(key.PublicKey))

	db := rawdb.NewMemoryDatabase()
	chain := openCanonicalTestChain(t, db, gspec)
	blocks := generateCanonicalTestBlocks(t, gspec, key, 6)
	if _, err := chain.InsertChain(blocks); err != nil {
		chain.Stop()
		t.Fatalf("failed to insert chain: %v", err)
	}
	chain.Stop()

	headTx := blocks[1].Transactions()[0]
	// The abandoned block above the head carries the transaction of block #2, and
	// its lookup is written last: the entry now names #3 while #2 stays canonical.
	abandoned := types.NewBlockWithHeader(blocks[2].Header()).WithBody(types.Body{
		Transactions: []*types.Transaction{headTx},
	})
	rawdb.WriteBlock(db, abandoned)
	rawdb.WriteTxLookupEntriesByBlock(db, abandoned)

	rawdb.WriteHeadHeaderHash(db, blocks[1].Hash())
	rawdb.WriteHeadFastBlockHash(db, blocks[1].Hash())
	rawdb.WriteHeadBlockHash(db, blocks[1].Hash())

	reopened := openCanonicalTestChain(t, db, gspec)
	defer reopened.Stop()

	if entry := rawdb.ReadTxLookupEntry(db, headTx.Hash()); entry == nil || *entry != 3 {
		t.Fatalf("lookup of the canonically indexed transaction dropped: have %v want 3", entry)
	}
	if block := reopened.GetBlockByNumber(2); block == nil {
		t.Fatal("canonical block #2 not served")
	}
	if block := reopened.GetBlockByNumber(3); block != nil {
		t.Fatalf("abandoned block #3 still served by number")
	}
}

// TestStartupReadOnlyLeavesCanonicalAssignmentsAboveHead pins that a read-only
// open writes nothing at all: the abandoned assignments and their lookups both
// have to survive it.
func TestStartupReadOnlyLeavesCanonicalAssignmentsAboveHead(t *testing.T) {
	key, err := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	if err != nil {
		t.Fatalf("failed to create test key: %v", err)
	}
	gspec := canonicalTestGenesis(crypto.PubkeyToAddress(key.PublicKey))

	db := rawdb.NewMemoryDatabase()
	chain := openCanonicalTestChain(t, db, gspec)
	blocks := generateCanonicalTestBlocks(t, gspec, key, 6)
	if _, err := chain.InsertChain(blocks); err != nil {
		chain.Stop()
		t.Fatalf("failed to insert chain: %v", err)
	}
	chain.Stop()

	rawdb.WriteHeadHeaderHash(db, blocks[1].Hash())
	rawdb.WriteHeadFastBlockHash(db, blocks[1].Hash())
	rawdb.WriteHeadBlockHash(db, blocks[1].Hash())

	reopened, err := NewBlockChainReadOnly(db, &CacheConfig{TrieDirtyDisabled: true}, gspec, ethash.NewFaker(), vm.Config{})
	if err != nil {
		t.Fatalf("failed to open the chain read-only: %v", err)
	}
	defer reopened.Stop()

	for _, block := range blocks[2:] {
		number := block.NumberU64()
		if hash := rawdb.ReadCanonicalHash(db, number); hash != block.Hash() {
			t.Fatalf("read-only open dropped the assignment at #%d", number)
		}
		if got := reopened.GetBlockByNumber(number); got == nil {
			t.Fatalf("block #%d not served by the read-only chain", number)
		}
		if entry := rawdb.ReadTxLookupEntry(db, block.Transactions()[0].Hash()); entry == nil {
			t.Fatalf("read-only open dropped the lookup of #%d", number)
		}
	}
}

// TestReimportKeepsLookupOfRetainedBlock pins that the sweep touches nothing but
// the assignments of the retained range: a crash-interrupted rewind leaves the
// content and the lookups above the head on disk, and the header import that
// restores the assignments makes those transactions readable again without any
// receipt delivery.
func TestReimportKeepsLookupOfRetainedBlock(t *testing.T) {
	key, err := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	if err != nil {
		t.Fatalf("failed to create test key: %v", err)
	}
	gspec := canonicalTestGenesis(crypto.PubkeyToAddress(key.PublicKey))

	db := rawdb.NewMemoryDatabase()
	chain := openCanonicalTestChain(t, db, gspec)
	blocks := generateCanonicalTestBlocks(t, gspec, key, 6)
	if _, err := chain.InsertChain(blocks); err != nil {
		chain.Stop()
		t.Fatalf("failed to insert chain: %v", err)
	}
	chain.Stop()

	// Crash window of a rewind to #3: the markers moved down, the content above
	// them is still on disk.
	rawdb.WriteHeadHeaderHash(db, blocks[2].Hash())
	rawdb.WriteHeadFastBlockHash(db, blocks[2].Hash())
	rawdb.WriteHeadBlockHash(db, blocks[2].Hash())

	reopened := openCanonicalTestChain(t, db, gspec)
	defer reopened.Stop()

	for _, block := range blocks[3:] {
		number := block.NumberU64()
		if hash := rawdb.ReadCanonicalHash(db, number); hash != (common.Hash{}) {
			t.Fatalf("probe setup: assignment at #%d survived the sweep: %s", number, hash)
		}
		if entry := rawdb.ReadTxLookupEntry(db, block.Transactions()[0].Hash()); entry == nil || *entry != number {
			t.Fatalf("probe setup: lookup of #%d dropped by the sweep: %v", number, entry)
		}
	}
	// A header on top of the retained chain restores the assignments through the
	// ancestor loop of WriteHeader, and the lookups the sweep kept resolve again.
	header := types.CopyHeader(blocks[5].Header())
	header.Number = big.NewInt(7)
	header.ParentHash = blocks[5].Hash()
	header.Time += 1
	if _, err := reopened.hc.WriteHeader(header); err != nil {
		t.Fatalf("failed to write the header above the retained range: %v", err)
	}
	for _, block := range blocks[3:] {
		number := block.NumberU64()
		if got := rawdb.ReadCanonicalHash(db, number); got != block.Hash() {
			t.Fatalf("assignment at #%d not restored: have %s want %s", number, got, block.Hash())
		}
		if got := reopened.GetBlockByNumber(number); got == nil {
			t.Fatalf("block #%d not served after the re-import", number)
		}
		tx, _, txNumber, _ := rawdb.ReadTransaction(db, block.Transactions()[0].Hash())
		if tx == nil || txNumber != number {
			t.Fatalf("transaction of #%d unreadable after the re-import: %v %d", number, tx, txNumber)
		}
	}
	// The canonical chain at or below the head is untouched.
	for _, block := range blocks[:3] {
		if entry := rawdb.ReadTxLookupEntry(db, block.Transactions()[0].Hash()); entry == nil || *entry != block.NumberU64() {
			t.Fatalf("lookup of block #%d below the head changed: %v", block.NumberU64(), entry)
		}
	}
}

// TestKnownHeaderReplayRestoresCanonicalAssignments covers the fast sync re-import
// of headers that are already on disk: the startup sweep dropped the canonical
// assignments above the head, InsertHeaderChain skips every replayed header, and
// only the receipt stage's lookup repair runs. The header import has to write the
// range back itself, or the blocks stay unreachable by number after the pivot
// commit.
func TestKnownHeaderReplayRestoresCanonicalAssignments(t *testing.T) {
	key, err := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	if err != nil {
		t.Fatalf("failed to create test key: %v", err)
	}
	gspec := canonicalTestGenesis(crypto.PubkeyToAddress(key.PublicKey))

	db := rawdb.NewMemoryDatabase()
	chain := openCanonicalTestChain(t, db, gspec)
	blocks := generateCanonicalTestBlocks(t, gspec, key, 7)
	if _, err := chain.InsertChain(blocks[:6]); err != nil {
		chain.Stop()
		t.Fatalf("failed to insert chain: %v", err)
	}
	chain.Stop()

	// Crash window of a rewind to #3: the markers moved down, the content above
	// them is still on disk.
	rawdb.WriteHeadHeaderHash(db, blocks[2].Hash())
	rawdb.WriteHeadFastBlockHash(db, blocks[2].Hash())
	rawdb.WriteHeadBlockHash(db, blocks[2].Hash())

	reopened := openCanonicalTestChain(t, db, gspec)
	defer reopened.Stop()

	for _, block := range blocks[3:6] {
		number := block.NumberU64()
		if hash := rawdb.ReadCanonicalHash(db, number); hash != (common.Hash{}) {
			t.Fatalf("probe setup: assignment at #%d survived the sweep: %s", number, hash)
		}
	}
	if got := reopened.CurrentHeader().Number.Uint64(); got != blocks[2].NumberU64() {
		t.Fatalf("probe setup: header head is %d, want %d", got, blocks[2].NumberU64())
	}
	// A fast sync replays headers that are already stored; InsertHeaderChain
	// skips every one of them.
	headers := []*types.Header{blocks[3].Header(), blocks[4].Header(), blocks[5].Header()}
	if _, err := reopened.InsertHeaderChain(headers, 0); err != nil {
		t.Fatalf("failed to replay the known headers: %v", err)
	}
	for _, block := range blocks[3:6] {
		number := block.NumberU64()
		if hash := rawdb.ReadCanonicalHash(db, number); hash != block.Hash() {
			t.Fatalf("assignment at #%d not restored: have %s want %s", number, hash, block.Hash())
		}
		if got := reopened.GetBlockByNumber(number); got == nil {
			t.Fatalf("block #%d not served after the known-header replay", number)
		}
	}
	if got := reopened.CurrentHeader().Number.Uint64(); got != blocks[5].NumberU64() {
		t.Fatalf("header head is %d after the replay, want %d", got, blocks[5].NumberU64())
	}
	// The receipt stage skips the retained blocks as known, the pivot commit moves
	// the block head, and the transactions of the replayed range stay reachable
	// through the lookups the sweep left in place.
	receipts := make([]types.Receipts, 3)
	for i := range receipts {
		receipts[i] = reopened.GetReceiptsByHash(blocks[3+i].Hash())
	}
	if _, err := reopened.InsertReceiptChain(blocks[3:6], receipts); err != nil {
		t.Fatalf("failed to re-deliver the retained range: %v", err)
	}
	if err := reopened.FastSyncCommitHead(blocks[5].Hash()); err != nil {
		t.Fatalf("failed to commit the pivot: %v", err)
	}
	tx, blockHash, number, index := rawdb.ReadTransaction(db, blocks[3].Transactions()[0].Hash())
	if tx == nil || blockHash != blocks[3].Hash() || number != blocks[3].NumberU64() || index != 0 {
		t.Fatalf("transaction of #%d unreadable after the pivot commit", blocks[3].NumberU64())
	}
	// A later full import writes only its own assignment; the replayed range is
	// already complete.
	if _, err := reopened.InsertChain(blocks[6:7]); err != nil {
		t.Fatalf("failed to import the next block: %v", err)
	}
	for _, block := range blocks[3:6] {
		if hash := rawdb.ReadCanonicalHash(db, block.NumberU64()); hash != block.Hash() {
			t.Fatalf("assignment at #%d changed by the next import: have %s want %s", block.NumberU64(), hash, block.Hash())
		}
	}
}

// TestKnownHeaderReplayReportsMissingParentTd covers the failure the restoration of
// a known header adds: the ancestor walk-back links through the parent, so a missing
// total difficulty there stops the replay. That record is this node's, not the
// peer's - the header itself is one the node already held - so the error has to be a
// local condition instead of the ErrUnknownAncestor the downloader reads as an
// invalid chain.
func TestKnownHeaderReplayReportsMissingParentTd(t *testing.T) {
	key, err := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	if err != nil {
		t.Fatalf("failed to create test key: %v", err)
	}
	gspec := canonicalTestGenesis(crypto.PubkeyToAddress(key.PublicKey))

	db := rawdb.NewMemoryDatabase()
	chain := openCanonicalTestChain(t, db, gspec)
	blocks := generateCanonicalTestBlocks(t, gspec, key, 6)
	if _, err := chain.InsertChain(blocks); err != nil {
		chain.Stop()
		t.Fatalf("failed to insert chain: %v", err)
	}
	chain.Stop()

	// Crash window of a rewind to #3: the markers moved down, the content above
	// them is still on disk.
	rawdb.WriteHeadHeaderHash(db, blocks[2].Hash())
	rawdb.WriteHeadFastBlockHash(db, blocks[2].Hash())
	rawdb.WriteHeadBlockHash(db, blocks[2].Hash())
	// The parent of the highest replayed header lost its total difficulty, the
	// record the ancestor walk-back links through.
	rawdb.DeleteTd(db, blocks[4].Hash(), blocks[4].NumberU64())

	reopened := openCanonicalTestChain(t, db, gspec)
	defer reopened.Stop()

	headers := []*types.Header{blocks[3].Header(), blocks[4].Header(), blocks[5].Header()}
	n, err := reopened.InsertHeaderChain(headers, 0)
	if err == nil {
		t.Fatalf("the replay of a known header with a missing parent total difficulty must fail (index %d)", n)
	}
	if !IsLocalInsertError(err) {
		t.Fatalf("a missing total difficulty is this node's condition, not the peer's: %v", err)
	}
}

// TestKnownHeaderReplayReportsMissingAncestor covers a dangling-hash sweep that
// committed only part of its batches: the retained tip and its parent are on disk
// while an earlier ancestor is gone. The restore walks that ancestry, so the gap
// has to stop the replay as a local condition instead of dereferencing the
// missing header, and the canonical assignments it was going to write must not be
// committed.
func TestKnownHeaderReplayReportsMissingAncestor(t *testing.T) {
	key, err := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	if err != nil {
		t.Fatalf("failed to create test key: %v", err)
	}
	gspec := canonicalTestGenesis(crypto.PubkeyToAddress(key.PublicKey))

	db := rawdb.NewMemoryDatabase()
	chain := openCanonicalTestChain(t, db, gspec)
	blocks := generateCanonicalTestBlocks(t, gspec, key, 6)
	if _, err := chain.InsertChain(blocks); err != nil {
		chain.Stop()
		t.Fatalf("failed to insert chain: %v", err)
	}
	chain.Stop()

	// Crash window of a rewind to #3: the markers moved down, the content above
	// them is still on disk.
	rawdb.WriteHeadHeaderHash(db, blocks[1].Hash())
	rawdb.WriteHeadFastBlockHash(db, blocks[1].Hash())
	rawdb.WriteHeadBlockHash(db, blocks[1].Hash())
	// The sweep committed the deletion of #3 but stopped before #4 and #5, so the
	// parent of the replayed tip is on disk and its own parent is not.
	rawdb.DeleteHeader(db, blocks[2].Hash(), blocks[2].NumberU64())
	rawdb.DeleteTd(db, blocks[2].Hash(), blocks[2].NumberU64())

	reopened := openCanonicalTestChain(t, db, gspec)
	defer reopened.Stop()

	n, err := reopened.InsertHeaderChain([]*types.Header{blocks[4].Header()}, 0)
	if err == nil {
		t.Fatalf("the replay of a known header above an ancestry gap must fail (index %d)", n)
	}
	if !IsLocalInsertError(err) {
		t.Fatalf("an ancestry gap is this node's condition, not the peer's: %v", err)
	}
	for _, block := range blocks[2:] {
		if hash := rawdb.ReadCanonicalHash(db, block.NumberU64()); hash != (common.Hash{}) {
			t.Errorf("canonical assignment at #%d committed by the failed restore: %s", block.NumberU64(), hash)
		}
	}
	if got := reopened.CurrentHeader().Number.Uint64(); got != blocks[1].NumberU64() {
		t.Errorf("header head is %d after the failed restore, want %d", got, blocks[1].NumberU64())
	}
}

// TestFailedCanonicalHeaderInsertPersistsNoHeader pins the state a failed
// canonical insertion must not leave behind: the ancestor walk stops at a gap in
// the swept range before the header is committed, so the replay after the gap is
// repaired still runs the insertion and advances the head. A header stored by
// the failed attempt is known to InsertHeaderChain, which skips known headers,
// so the replay would report success without promoting anything.
func TestFailedCanonicalHeaderInsertPersistsNoHeader(t *testing.T) {
	key, err := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	if err != nil {
		t.Fatalf("failed to create test key: %v", err)
	}
	gspec := canonicalTestGenesis(crypto.PubkeyToAddress(key.PublicKey))

	db := rawdb.NewMemoryDatabase()
	chain := openCanonicalTestChain(t, db, gspec)
	blocks := generateCanonicalTestBlocks(t, gspec, key, 6)
	if _, err := chain.InsertChain(blocks); err != nil {
		chain.Stop()
		t.Fatalf("failed to insert chain: %v", err)
	}
	td3 := chain.GetTd(blocks[2].Hash(), blocks[2].NumberU64())
	if td3 == nil {
		chain.Stop()
		t.Fatal("probe setup: total difficulty of #3 missing")
	}
	chain.Stop()

	// Crash window of a rewind to #2 that already deleted header #3 and its
	// total difficulty, while the headers above it are still on disk.
	rawdb.WriteHeadHeaderHash(db, blocks[1].Hash())
	rawdb.WriteHeadFastBlockHash(db, blocks[1].Hash())
	rawdb.WriteHeadBlockHash(db, blocks[1].Hash())
	rawdb.DeleteHeader(db, blocks[2].Hash(), blocks[2].NumberU64())
	rawdb.DeleteTd(db, blocks[2].Hash(), blocks[2].NumberU64())

	reopened := openCanonicalTestChain(t, db, gspec)
	defer reopened.Stop()
	if got := reopened.hc.sweptTo; got != blocks[5].NumberU64() {
		t.Fatalf("probe setup: sweptTo is %d, want %d", got, blocks[5].NumberU64())
	}
	// A fresh header above the swept range: #4..#6 are known, so only the gap at
	// #3 stops the walk.
	parent := blocks[5].Header()
	tip := types.CopyHeader(parent)
	tip.Number = new(big.Int).SetUint64(blocks[5].NumberU64() + 1)
	tip.ParentHash = parent.Hash()
	tip.Time = parent.Time + 1
	tip.Difficulty = ethash.CalcDifficulty(gspec.Config, tip.Time, parent)

	if n, err := reopened.InsertHeaderChain([]*types.Header{tip}, 0); !IsLocalInsertError(err) {
		t.Fatalf("the insert above the ancestry gap must fail as a local condition (index %d, err %v)", n, err)
	}
	// The failed insertion must leave nothing behind: a stored header would be
	// skipped by every later replay.
	if reopened.hc.HasHeader(tip.Hash(), tip.Number.Uint64()) {
		t.Fatalf("header #%d stored by the failed insert", tip.Number.Uint64())
	}
	if td := rawdb.ReadTd(db, tip.Hash(), tip.Number.Uint64()); td != nil {
		t.Fatalf("total difficulty of the failed header stored: %v", td)
	}
	if got := reopened.CurrentHeader().Number.Uint64(); got != blocks[1].NumberU64() {
		t.Fatalf("header head is %d after the failed insert, want %d", got, blocks[1].NumberU64())
	}

	// Repair the gap and replay: the insert has to run again and advance the head.
	rawdb.WriteHeader(db, blocks[2].Header())
	rawdb.WriteTd(db, blocks[2].Hash(), blocks[2].NumberU64(), td3)
	if n, err := reopened.InsertHeaderChain([]*types.Header{tip}, 0); err != nil {
		t.Fatalf("the replay after the repair failed (index %d): %v", n, err)
	}
	if got := reopened.CurrentHeader().Number.Uint64(); got != tip.Number.Uint64() {
		t.Fatalf("header head is %d after the replay, want %d", got, tip.Number.Uint64())
	}
	for _, block := range blocks[2:] {
		if hash := rawdb.ReadCanonicalHash(db, block.NumberU64()); hash != block.Hash() {
			t.Fatalf("assignment at #%d not restored: have %s want %s", block.NumberU64(), hash, block.Hash())
		}
	}
	if hash := rawdb.ReadCanonicalHash(db, tip.Number.Uint64()); hash != tip.Hash() {
		t.Fatalf("assignment at #%d is %s, want %s", tip.Number.Uint64(), hash, tip.Hash())
	}
	if got, err := rawdb.ReadSweptCanonicalBound(db); err != nil || got != 0 {
		t.Fatalf("bound after the restore: have #%d err %v, want zero", got, err)
	}
}

// TestKnownHeaderReplayReportsMissingHeadTd covers the other record the restore
// reads: WriteHeader compares the replayed header's total difficulty against the
// current head's. A head without one is this node's condition, so the replay has
// to report it instead of dereferencing the nil comparison.
func TestKnownHeaderReplayReportsMissingHeadTd(t *testing.T) {
	key, err := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	if err != nil {
		t.Fatalf("failed to create test key: %v", err)
	}
	gspec := canonicalTestGenesis(crypto.PubkeyToAddress(key.PublicKey))

	db := rawdb.NewMemoryDatabase()
	chain := openCanonicalTestChain(t, db, gspec)
	blocks := generateCanonicalTestBlocks(t, gspec, key, 6)
	if _, err := chain.InsertChain(blocks); err != nil {
		chain.Stop()
		t.Fatalf("failed to insert chain: %v", err)
	}
	chain.Stop()

	// Crash window of a rewind to #3: the markers moved down, the content above
	// them is still on disk.
	rawdb.WriteHeadHeaderHash(db, blocks[1].Hash())
	rawdb.WriteHeadFastBlockHash(db, blocks[1].Hash())
	rawdb.WriteHeadBlockHash(db, blocks[1].Hash())
	rawdb.DeleteTd(db, blocks[1].Hash(), blocks[1].NumberU64())

	reopened := openCanonicalTestChain(t, db, gspec)
	defer reopened.Stop()

	headers := []*types.Header{blocks[2].Header(), blocks[3].Header(), blocks[4].Header()}
	n, err := reopened.InsertHeaderChain(headers, 0)
	if err == nil {
		t.Fatalf("the replay of known headers with a head total difficulty missing must fail (index %d)", n)
	}
	if !IsLocalInsertError(err) {
		t.Fatalf("a missing head total difficulty is this node's condition, not the peer's: %v", err)
	}
	if got := reopened.CurrentHeader().Number.Uint64(); got != blocks[1].NumberU64() {
		t.Errorf("header head is %d after the failed replay, want %d", got, blocks[1].NumberU64())
	}
}

// TestKnownHeaderReplayDoesNotRewriteFreshHeaders pins the boundary of the
// restore: it exists for headers the loop skipped, not for the ones it just
// stored. Rewriting a freshly stored side header would repeat its fork-choice
// draw, so the callback must run once per header.
func TestKnownHeaderReplayDoesNotRewriteFreshHeaders(t *testing.T) {
	key, err := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	if err != nil {
		t.Fatalf("failed to create test key: %v", err)
	}
	gspec := canonicalTestGenesis(crypto.PubkeyToAddress(key.PublicKey))

	db := rawdb.NewMemoryDatabase()
	chain := openCanonicalTestChain(t, db, gspec)
	blocks := generateCanonicalTestBlocks(t, gspec, key, 6)
	if _, err := chain.InsertChain(blocks); err != nil {
		chain.Stop()
		t.Fatalf("failed to insert chain: %v", err)
	}
	if got := chain.CurrentHeader().Number.Uint64(); got != blocks[5].NumberU64() {
		chain.Stop()
		t.Fatalf("unexpected head: have %d want %d", got, blocks[5].NumberU64())
	}
	// A side segment above the head with zero difficulty: its total difficulty
	// stays below the head's, so every write is a side write.
	parent := blocks[3].Header()
	var side []*types.Header
	for i := uint64(5); i <= 7; i++ {
		header := types.CopyHeader(parent)
		header.Number = new(big.Int).SetUint64(i)
		header.ParentHash = parent.Hash()
		header.Difficulty = new(big.Int)
		header.Time = parent.Time + 1
		side = append(side, header)
		parent = header
	}
	calls := 0
	writeHeader := func(header *types.Header) error {
		calls++
		_, err := chain.hc.WriteHeader(header)
		return err
	}
	if _, err := chain.hc.InsertHeaderChain(side, writeHeader, time.Now()); err != nil {
		chain.Stop()
		t.Fatalf("failed to insert the side segment: %v", err)
	}
	if calls != len(side) {
		chain.Stop()
		t.Fatalf("writeHeader called %d times for %d headers", calls, len(side))
	}
	if got := chain.CurrentHeader().Number.Uint64(); got != blocks[5].NumberU64() {
		chain.Stop()
		t.Errorf("header head is %d after the side import, want %d", got, blocks[5].NumberU64())
	}
	chain.Stop()
}

// sideChainWithDifficulty builds a contiguous branch whose parent is parent and
// whose every header carries the given difficulty.
func sideChainWithDifficulty(parent *types.Header, from, to uint64, difficulty *big.Int) []*types.Header {
	var side []*types.Header
	for number := from; number <= to; number++ {
		header := types.CopyHeader(parent)
		header.Number = new(big.Int).SetUint64(number)
		header.ParentHash = parent.Hash()
		header.Difficulty = new(big.Int).Set(difficulty)
		header.Time = parent.Time + 1
		side = append(side, header)
		parent = header
	}
	return side
}

// zeroDifficultySideChain builds a contiguous branch whose parent is parent and
// whose difficulty is zero, so its total difficulty never grows past the
// parent's and no header of it can enter the canonical chain.
func zeroDifficultySideChain(parent *types.Header, from, to uint64) []*types.Header {
	return sideChainWithDifficulty(parent, from, to, new(big.Int))
}

// TestKnownHeaderReplaySkipsKnownSideHeader pins that a replay does not rewrite a
// header that lost the fork-choice when it was stored: this chain was opened
// without dropping anything, so re-entering WriteHeader would only repeat its
// draw.
func TestKnownHeaderReplaySkipsKnownSideHeader(t *testing.T) {
	key, err := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	if err != nil {
		t.Fatalf("failed to create test key: %v", err)
	}
	gspec := canonicalTestGenesis(crypto.PubkeyToAddress(key.PublicKey))

	db := rawdb.NewMemoryDatabase()
	chain := openCanonicalTestChain(t, db, gspec)
	defer chain.Stop()

	blocks := generateCanonicalTestBlocks(t, gspec, key, 7)
	if _, err := chain.InsertChain(blocks); err != nil {
		t.Fatalf("failed to insert chain: %v", err)
	}
	if got := chain.hc.sweptTo; got != 0 {
		t.Fatalf("probe setup: the chain was opened without a sweep, sweptTo=%d", got)
	}
	// A zero-difficulty branch from #5: its total difficulty stays at #5's, below
	// the head's, so it never enters the canonical chain.
	side := zeroDifficultySideChain(blocks[4].Header(), 6, 8)
	for _, header := range side {
		if status, err := chain.hc.WriteHeader(header); err != nil || status != SideStatTy {
			t.Fatalf("failed to store the side header #%d: status %v err %v", header.Number, status, err)
		}
	}
	last := side[len(side)-1]
	if got := rawdb.ReadCanonicalHash(db, last.Number.Uint64()); got != (common.Hash{}) {
		t.Fatalf("probe setup: assignment at #%d = %s", last.Number, got)
	}
	for i := 1; i <= 8; i++ {
		calls := 0
		writeHeader := func(header *types.Header) error {
			calls++
			_, err := chain.hc.WriteHeader(header)
			return err
		}
		if _, err := chain.hc.InsertHeaderChain([]*types.Header{last}, writeHeader, time.Now()); err != nil {
			t.Fatalf("replay %d failed: %v", i, err)
		}
		if calls != 0 {
			t.Fatalf("replay %d rewrote the known side header (%d calls)", i, calls)
		}
	}
	if got := chain.CurrentHeader().Number.Uint64(); got != blocks[6].NumberU64() {
		t.Fatalf("header head is %d after the replays, want %d", got, blocks[6].NumberU64())
	}
	if got := rawdb.ReadCanonicalHash(db, last.Number.Uint64()); got != (common.Hash{}) {
		t.Fatalf("assignment at #%d flipped to the side header: %s", last.Number, got)
	}
}

// openRewoundChainWithSideBranch inserts #1..#13, stores a zero-difficulty side
// branch from #2 above it, then reopens the chain with the markers rewound to #3,
// so the startup sweep drops #4..#13 while the side headers stay known.
func openRewoundChainWithSideBranch(t *testing.T) (*BlockChain, types.Blocks, []*types.Header) {
	return openRewoundChainWithSideBranchScale(t, 0)
}

// openRewoundChainWithSideBranchScale is openRewoundChainWithSideBranch with the
// side headers' difficulty set to scale times the canonical per-block one, so a
// test can place the branch's total difficulty between the rewound head's and
// the pre-rewind one.
func openRewoundChainWithSideBranchScale(t *testing.T, scale uint64) (*BlockChain, types.Blocks, []*types.Header) {
	t.Helper()
	key, err := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	if err != nil {
		t.Fatalf("failed to create test key: %v", err)
	}
	gspec := canonicalTestGenesis(crypto.PubkeyToAddress(key.PublicKey))
	db := rawdb.NewMemoryDatabase()
	chain := openCanonicalTestChain(t, db, gspec)
	blocks := generateCanonicalTestBlocks(t, gspec, key, 13)
	if _, err := chain.InsertChain(blocks); err != nil {
		chain.Stop()
		t.Fatalf("failed to insert chain: %v", err)
	}
	difficulty := new(big.Int).Mul(blocks[0].Difficulty(), new(big.Int).SetUint64(scale))
	side := sideChainWithDifficulty(blocks[1].Header(), 3, 8, difficulty)
	for _, header := range side {
		if status, err := chain.hc.WriteHeader(header); err != nil || status != SideStatTy {
			chain.Stop()
			t.Fatalf("failed to store the side header #%d: status %v err %v", header.Number, status, err)
		}
	}
	chain.Stop()

	// Crash window of a rewind to #3: the markers moved down, the content above
	// them is still on disk.
	rawdb.WriteHeadHeaderHash(db, blocks[2].Hash())
	rawdb.WriteHeadFastBlockHash(db, blocks[2].Hash())
	rawdb.WriteHeadBlockHash(db, blocks[2].Hash())

	reopened := openCanonicalTestChain(t, db, gspec)
	t.Cleanup(reopened.Stop)
	if got := reopened.hc.sweptTo; got != blocks[12].NumberU64() {
		t.Fatalf("probe setup: sweptTo is %d, want %d", got, blocks[12].NumberU64())
	}
	return reopened, blocks, side
}

// TestKnownHeaderReplayRestoresSweptRangeBehindHigherSideHeader pins the restore
// point to the highest known header of the swept range, not to the chunk's last
// one: the known side header above the swept range is not restored, while the
// dropped canonical headers behind it are.
func TestKnownHeaderReplayRestoresSweptRangeBehindHigherSideHeader(t *testing.T) {
	reopened, blocks, side := openRewoundChainWithSideBranch(t)
	db := reopened.db
	// The chunk ends on the known side header above the swept range and carries
	// the dropped canonical headers behind it: the restore point has to be the
	// highest dropped canonical header, not the chunk's last one.
	chunk := []*types.Header{blocks[3].Header(), blocks[4].Header(), blocks[5].Header(), side[5]}
	calls := 0
	writeHeader := func(header *types.Header) error {
		calls++
		_, err := reopened.hc.WriteHeader(header)
		return err
	}
	if _, err := reopened.hc.InsertHeaderChain(chunk, writeHeader, time.Now()); err != nil {
		t.Fatalf("failed to replay the known chunk: %v", err)
	}
	if calls != 1 {
		t.Fatalf("writeHeader called %d times, want 1 for the restore point", calls)
	}
	for _, block := range blocks[3:6] {
		if hash := rawdb.ReadCanonicalHash(db, block.NumberU64()); hash != block.Hash() {
			t.Fatalf("assignment at #%d not restored: have %s want %s", block.NumberU64(), hash, block.Hash())
		}
		if got := reopened.GetBlockByNumber(block.NumberU64()); got == nil {
			t.Fatalf("block #%d not served after the replay", block.NumberU64())
		}
	}
	if got := reopened.CurrentHeader().Number.Uint64(); got != blocks[5].NumberU64() {
		t.Fatalf("header head is %d after the replay, want %d", got, blocks[5].NumberU64())
	}
	if got := rawdb.ReadCanonicalHash(db, 8); got != (common.Hash{}) {
		t.Fatalf("side header above the swept range promoted: %s", got)
	}
	// The chunk stopped below the sweep's highest dropped height, so the bound
	// has to survive for a later chunk to finish the restore.
	if got, err := rawdb.ReadSweptCanonicalBound(db); err != nil || got != blocks[12].NumberU64() {
		t.Fatalf("bound after a partial restore: have #%d err %v, want #%d", got, err, blocks[12].NumberU64())
	}
}

// TestKnownHeaderReplaySkipsSideHeaderInsideSweptRange pins that a known side
// header inside the swept height range is not treated as a dropped assignment,
// so the restore stays off. The fixture's side headers are all below the rewound
// head's total difficulty, the one case a comparison against the head would
// reject by itself; the per-height record has to reject them regardless.
func TestKnownHeaderReplaySkipsSideHeaderInsideSweptRange(t *testing.T) {
	reopened, blocks, side := openRewoundChainWithSideBranch(t)
	db := reopened.db
	headTd := reopened.GetTd(reopened.hc.currentHeaderHash, blocks[2].NumberU64())
	if headTd == nil {
		t.Fatal("probe setup: head total difficulty missing")
	}
	for _, header := range side {
		if td := reopened.GetTd(header.Hash(), header.Number.Uint64()); td == nil || td.Cmp(headTd) >= 0 {
			t.Fatalf("probe setup: side header #%d td %v is not below the head's %v", header.Number, td, headTd)
		}
	}
	calls := 0
	writeHeader := func(header *types.Header) error {
		calls++
		_, err := reopened.hc.WriteHeader(header)
		return err
	}
	// The chunk holds only side headers inside the swept range: nothing was
	// dropped for them, so the restore must not rewrite them.
	if _, err := reopened.hc.InsertHeaderChain([]*types.Header{side[4], side[5]}, writeHeader, time.Now()); err != nil {
		t.Fatalf("failed to replay the side headers: %v", err)
	}
	if calls != 0 {
		t.Fatalf("writeHeader called %d times for side headers below the head difficulty, want 0", calls)
	}
	if got := reopened.CurrentHeader().Number.Uint64(); got != blocks[2].NumberU64() {
		t.Fatalf("header head is %d after the replay, want %d", got, blocks[2].NumberU64())
	}
	for _, header := range side {
		if header.Number.Uint64() <= blocks[2].NumberU64() {
			continue
		}
		if hash := rawdb.ReadCanonicalHash(db, header.Number.Uint64()); hash != (common.Hash{}) {
			t.Fatalf("assignment at #%d flipped to a side header: %s", header.Number, hash)
		}
	}
}

// TestKnownHeaderReplaySkipsSideHeaderAboveRewoundDifficulty covers the case a
// total-difficulty comparison against the current head cannot reject: a side
// branch stored below the pre-rewind head still carries more difficulty than the
// rewound head. Only the recorded ancestry tells it from a dropped canonical
// header; without that the restore would promote it and rewrite the assignments
// of the rewound range with header-only blocks.
func TestKnownHeaderReplaySkipsSideHeaderAboveRewoundDifficulty(t *testing.T) {
	reopened, blocks, side := openRewoundChainWithSideBranchScale(t, 1)
	db := reopened.db
	headTd := reopened.GetTd(reopened.hc.currentHeaderHash, blocks[2].NumberU64())
	if headTd == nil {
		t.Fatal("probe setup: head total difficulty missing")
	}
	if td := reopened.GetTd(side[len(side)-1].Hash(), 8); td == nil || td.Cmp(headTd) <= 0 {
		t.Fatalf("probe setup: side #8 td %v does not beat the rewound head's %v", td, headTd)
	}
	calls := 0
	writeHeader := func(header *types.Header) error {
		calls++
		_, err := reopened.hc.WriteHeader(header)
		return err
	}
	// The chunk carries the part of the side branch above the head.
	if _, err := reopened.hc.InsertHeaderChain(side[1:], writeHeader, time.Now()); err != nil {
		t.Fatalf("failed to replay the side branch: %v", err)
	}
	if calls != 0 {
		t.Fatalf("writeHeader called %d times for a known side branch, want 0", calls)
	}
	if got := reopened.CurrentHeader().Number.Uint64(); got != blocks[2].NumberU64() {
		t.Fatalf("header head is %d after the side replay, want %d", got, blocks[2].NumberU64())
	}
	for _, header := range side {
		if header.Number.Uint64() <= blocks[2].NumberU64() {
			continue
		}
		if hash := rawdb.ReadCanonicalHash(db, header.Number.Uint64()); hash != (common.Hash{}) {
			t.Fatalf("assignment at #%d flipped to a side header: %s", header.Number, hash)
		}
	}
	if bound, err := rawdb.ReadSweptCanonicalBound(db); err != nil || bound != blocks[12].NumberU64() {
		t.Fatalf("bound after the side replay: have #%d err %v, want #%d", bound, err, blocks[12].NumberU64())
	}
}

// TestKnownHeaderReplaySkipsEqualDifficultySideHeader pins that an equal-total-
// difficulty side header does not re-enter the fork-choice draw on every replay.
// Such a header ties with the rewound head, so a strict "below" comparison lets
// it through, and every rewrite draws again.
func TestKnownHeaderReplaySkipsEqualDifficultySideHeader(t *testing.T) {
	key, err := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	if err != nil {
		t.Fatalf("failed to create test key: %v", err)
	}
	gspec := canonicalTestGenesis(crypto.PubkeyToAddress(key.PublicKey))
	db := rawdb.NewMemoryDatabase()
	chain := openCanonicalTestChain(t, db, gspec)
	blocks := generateCanonicalTestBlocks(t, gspec, key, 13)
	if _, err := chain.InsertChain(blocks); err != nil {
		chain.Stop()
		t.Fatalf("failed to insert chain: %v", err)
	}
	// A side branch from #2 with zero difficulty up to #7 and one canonical-
	// difficulty block at #8: its total difficulty equals the rewound head's.
	side := zeroDifficultySideChain(blocks[1].Header(), 3, 7)
	last := types.CopyHeader(side[len(side)-1])
	last.Number = big.NewInt(8)
	last.ParentHash = side[len(side)-1].Hash()
	last.Difficulty = new(big.Int).Set(blocks[0].Difficulty())
	last.Time = side[len(side)-1].Time + 1
	side = append(side, last)
	for _, header := range side {
		if status, err := chain.hc.WriteHeader(header); err != nil || status != SideStatTy {
			chain.Stop()
			t.Fatalf("failed to store the side header #%d: status %v err %v", header.Number, status, err)
		}
	}
	chain.Stop()

	rawdb.WriteHeadHeaderHash(db, blocks[2].Hash())
	rawdb.WriteHeadFastBlockHash(db, blocks[2].Hash())
	rawdb.WriteHeadBlockHash(db, blocks[2].Hash())

	reopened := openCanonicalTestChain(t, db, gspec)
	defer reopened.Stop()

	headTd := reopened.GetTd(reopened.hc.currentHeaderHash, blocks[2].NumberU64())
	if td := reopened.GetTd(last.Hash(), 8); td == nil || headTd == nil || td.Cmp(headTd) != 0 {
		t.Fatalf("probe setup: side #8 td %v, rewound head td %v, want equal", td, headTd)
	}
	for i := 1; i <= 8; i++ {
		calls := 0
		writeHeader := func(header *types.Header) error {
			calls++
			_, err := reopened.hc.WriteHeader(header)
			return err
		}
		if _, err := reopened.hc.InsertHeaderChain([]*types.Header{last}, writeHeader, time.Now()); err != nil {
			t.Fatalf("replay %d failed: %v", i, err)
		}
		if calls != 0 {
			t.Fatalf("replay %d rewrote the equal-difficulty side header (%d calls)", i, calls)
		}
	}
	if got := rawdb.ReadCanonicalHash(db, 8); got != (common.Hash{}) {
		t.Fatalf("assignment at #8 flipped to the side header: %s", got)
	}
	if got := reopened.CurrentHeader().Number.Uint64(); got != blocks[2].NumberU64() {
		t.Fatalf("header head is %d after the replays, want %d", got, blocks[2].NumberU64())
	}
}

// TestRestartBeforeHeaderReplayRestoresSweptRange covers a node that stopped
// after the startup sweep committed but before any known header was replayed:
// the next start has no assignments left to delete, so the persisted bound alone
// has to keep the restore point alive.
func TestRestartBeforeHeaderReplayRestoresSweptRange(t *testing.T) {
	first, blocks, _ := openRewoundChainWithSideBranch(t)
	db := first.db
	first.Stop()

	key, err := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	if err != nil {
		t.Fatalf("failed to create test key: %v", err)
	}
	gspec := canonicalTestGenesis(crypto.PubkeyToAddress(key.PublicKey))

	reopened := openCanonicalTestChain(t, db, gspec)
	defer reopened.Stop()

	if got := reopened.hc.sweptTo; got != blocks[12].NumberU64() {
		t.Fatalf("sweptTo after the restart is %d, want %d from the persisted bound", got, blocks[12].NumberU64())
	}
	for _, block := range blocks[3:] {
		if hash := rawdb.ReadCanonicalHash(db, block.NumberU64()); hash != (common.Hash{}) {
			t.Fatalf("assignment at #%d survived the first sweep: %s", block.NumberU64(), hash)
		}
	}
	chunk := make([]*types.Header, 0, len(blocks)-3)
	for _, block := range blocks[3:] {
		chunk = append(chunk, block.Header())
	}
	calls := 0
	writeHeader := func(header *types.Header) error {
		calls++
		_, err := reopened.hc.WriteHeader(header)
		return err
	}
	if _, err := reopened.hc.InsertHeaderChain(chunk, writeHeader, time.Now()); err != nil {
		t.Fatalf("failed to replay the known range: %v", err)
	}
	if calls != 1 {
		t.Fatalf("writeHeader called %d times, want 1 for the restore point", calls)
	}
	for _, block := range blocks[3:] {
		if hash := rawdb.ReadCanonicalHash(db, block.NumberU64()); hash != block.Hash() {
			t.Fatalf("assignment at #%d not restored: have %s want %s", block.NumberU64(), hash, block.Hash())
		}
	}
	if got := reopened.CurrentHeader().Number.Uint64(); got != blocks[12].NumberU64() {
		t.Fatalf("header head is %d after the replay, want %d", got, blocks[12].NumberU64())
	}
	if got, err := rawdb.ReadSweptCanonicalBound(db); err != nil || got != 0 {
		t.Fatalf("bound after the restore: have #%d err %v, want zero", got, err)
	}
}

// TestRestartAfterPartialRestoreKeepsPendingBound covers a second crash-window
// rewind after a partial restore: the sweep of the next start drops only #4..#6,
// and overwriting the pending #13 with it would lose the restore point of
// #7..#13 before the range is complete.
func TestRestartAfterPartialRestoreKeepsPendingBound(t *testing.T) {
	first, blocks, _ := openRewoundChainWithSideBranch(t)
	db := first.db

	writeHeader := func(header *types.Header) error {
		_, err := first.hc.WriteHeader(header)
		return err
	}
	chunk := []*types.Header{blocks[3].Header(), blocks[4].Header(), blocks[5].Header()}
	if _, err := first.hc.InsertHeaderChain(chunk, writeHeader, time.Now()); err != nil {
		t.Fatalf("failed to restore the first part of the range: %v", err)
	}
	if got := first.CurrentHeader().Number.Uint64(); got != blocks[5].NumberU64() {
		t.Fatalf("head after the partial restore is %d, want %d", got, blocks[5].NumberU64())
	}
	first.Stop()

	// Crash window of another rewind to #3: the markers moved down, the restored
	// content above them is still on disk.
	rawdb.WriteHeadHeaderHash(db, blocks[2].Hash())
	rawdb.WriteHeadFastBlockHash(db, blocks[2].Hash())
	rawdb.WriteHeadBlockHash(db, blocks[2].Hash())

	key, err := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	if err != nil {
		t.Fatalf("failed to create test key: %v", err)
	}
	gspec := canonicalTestGenesis(crypto.PubkeyToAddress(key.PublicKey))
	reopened := openCanonicalTestChain(t, db, gspec)
	defer reopened.Stop()

	if got := reopened.hc.sweptTo; got != blocks[12].NumberU64() {
		t.Fatalf("sweptTo after the second sweep is %d, want %d", got, blocks[12].NumberU64())
	}
	bound, err := rawdb.ReadSweptCanonicalBound(db)
	if err != nil || bound != blocks[12].NumberU64() {
		t.Fatalf("bound after the second sweep: have #%d err %v, want #%d", bound, err, blocks[12].NumberU64())
	}
	// The rest of the swept range is still restorable.
	chunk = nil
	for _, block := range blocks[6:] {
		chunk = append(chunk, block.Header())
	}
	calls := 0
	writeHeader = func(header *types.Header) error {
		calls++
		_, err := reopened.hc.WriteHeader(header)
		return err
	}
	if _, err := reopened.hc.InsertHeaderChain(chunk, writeHeader, time.Now()); err != nil {
		t.Fatalf("failed to replay the rest of the range: %v", err)
	}
	if calls != 1 {
		t.Fatalf("writeHeader called %d times, want 1 for the restore point", calls)
	}
	for _, block := range blocks[3:] {
		if hash := rawdb.ReadCanonicalHash(db, block.NumberU64()); hash != block.Hash() {
			t.Fatalf("assignment at #%d not restored: have %s want %s", block.NumberU64(), hash, block.Hash())
		}
	}
	if got := reopened.CurrentHeader().Number.Uint64(); got != blocks[12].NumberU64() {
		t.Fatalf("header head is %d after the replay, want %d", got, blocks[12].NumberU64())
	}
	if got, err := rawdb.ReadSweptCanonicalBound(db); err != nil || got != 0 {
		t.Fatalf("bound after the restore: have #%d err %v, want zero", got, err)
	}
}

// TestStartupClearsSpentSweptBound covers a persisted bound the head already
// passed: the records are spent and must not survive the open.
func TestStartupClearsSpentSweptBound(t *testing.T) {
	key, err := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	if err != nil {
		t.Fatalf("failed to create test key: %v", err)
	}
	gspec := canonicalTestGenesis(crypto.PubkeyToAddress(key.PublicKey))
	db := rawdb.NewMemoryDatabase()
	chain := openCanonicalTestChain(t, db, gspec)
	blocks := generateCanonicalTestBlocks(t, gspec, key, 3)
	if _, err := chain.InsertChain(blocks); err != nil {
		chain.Stop()
		t.Fatalf("failed to insert chain: %v", err)
	}
	chain.Stop()

	// The head is #3 and the bound sits below it, so no height above the head
	// can need a restore. The record at the bound's own height is spent too.
	spent := blocks[1].NumberU64()
	if err := rawdb.WriteSweptCanonicalBound(db, spent); err != nil {
		t.Fatalf("failed to write the bound: %v", err)
	}
	if err := rawdb.WriteSweptCanonicalHash(db, spent, blocks[1].Hash()); err != nil {
		t.Fatalf("failed to write the record: %v", err)
	}
	reopened := openCanonicalTestChain(t, db, gspec)
	defer reopened.Stop()

	if got := reopened.hc.sweptTo; got != 0 {
		t.Fatalf("sweptTo after clearing a spent bound is %d, want 0", got)
	}
	if got, err := rawdb.ReadSweptCanonicalBound(db); err != nil || got != 0 {
		t.Fatalf("spent bound survived the open: have #%d err %v, want zero", got, err)
	}
	if _, ok, err := rawdb.ReadSweptCanonicalHash(db, spent); err != nil || ok {
		t.Fatalf("spent record survived the open: ok=%t err %v", ok, err)
	}
}

// TestKnownHeaderReplayRestoresBelowMissingBoundHeader covers a rewind that
// deleted the bound's own header while the lower dropped headers survived. The
// records are per height, so the replay matches the surviving header without
// walking any ancestry, and the walk-back of WriteHeader restores the range
// below it.
func TestKnownHeaderReplayRestoresBelowMissingBoundHeader(t *testing.T) {
	key, err := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	if err != nil {
		t.Fatalf("failed to create test key: %v", err)
	}
	gspec := canonicalTestGenesis(crypto.PubkeyToAddress(key.PublicKey))
	db := rawdb.NewMemoryDatabase()
	chain := openCanonicalTestChain(t, db, gspec)
	blocks := generateCanonicalTestBlocks(t, gspec, key, 6)
	if _, err := chain.InsertChain(blocks); err != nil {
		chain.Stop()
		t.Fatalf("failed to insert chain: %v", err)
	}
	chain.Stop()

	// A previous sweep dropped #4..#6 and recorded each height.
	for number := uint64(4); number <= 6; number++ {
		if err := rawdb.WriteSweptCanonicalHash(db, number, blocks[number-1].Hash()); err != nil {
			t.Fatalf("failed to write the record at #%d: %v", number, err)
		}
		rawdb.DeleteCanonicalHash(db, number)
	}
	if err := rawdb.WriteSweptCanonicalBound(db, 6); err != nil {
		t.Fatalf("failed to write the bound: %v", err)
	}
	// An interrupted rewind to #3 already deleted the bound's own header #6.
	rawdb.WriteHeadHeaderHash(db, blocks[2].Hash())
	rawdb.WriteHeadFastBlockHash(db, blocks[2].Hash())
	rawdb.WriteHeadBlockHash(db, blocks[2].Hash())
	rawdb.DeleteHeader(db, blocks[5].Hash(), 6)
	rawdb.DeleteTd(db, blocks[5].Hash(), 6)

	reopened := openCanonicalTestChain(t, db, gspec)
	defer reopened.Stop()

	if got := reopened.hc.sweptTo; got != 6 {
		t.Fatalf("sweptTo after the open is %d, want 6", got)
	}
	if _, err := reopened.InsertHeaderChain([]*types.Header{blocks[3].Header(), blocks[4].Header()}, 0); err != nil {
		t.Fatalf("failed to replay the known headers: %v", err)
	}
	if got := reopened.CurrentHeader().Number.Uint64(); got != blocks[4].NumberU64() {
		t.Fatalf("header head is %d after the replay, want %d", got, blocks[4].NumberU64())
	}
	for _, block := range blocks[3:5] {
		if hash := rawdb.ReadCanonicalHash(db, block.NumberU64()); hash != block.Hash() {
			t.Fatalf("assignment at #%d not restored: have %s want %s", block.NumberU64(), hash, block.Hash())
		}
	}
	// The restore spent the records it passed; the one of the deleted bound
	// header stays pending until the head reaches it.
	for _, number := range []uint64{4, 5} {
		if _, ok, err := rawdb.ReadSweptCanonicalHash(db, number); err != nil || ok {
			t.Fatalf("record at #%d survived the restore: ok=%t err %v", number, ok, err)
		}
	}
	if _, ok, err := rawdb.ReadSweptCanonicalHash(db, 6); err != nil || !ok {
		t.Fatalf("record at #6 dropped before the head reached it: ok=%t err %v", ok, err)
	}
}

// TestKnownHeaderReplayRestoresNewestSweptChainAfterForkSwitch covers a pending
// bound from chain A while the assignments on disk belong to a newer chain B:
// the per-height records name B's headers, so replaying B restores it instead of
// being rejected against A's recovery point.
func TestKnownHeaderReplayRestoresNewestSweptChainAfterForkSwitch(t *testing.T) {
	key, err := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	if err != nil {
		t.Fatalf("failed to create test key: %v", err)
	}
	gspec := canonicalTestGenesis(crypto.PubkeyToAddress(key.PublicKey))
	db := rawdb.NewMemoryDatabase()
	chain := openCanonicalTestChain(t, db, gspec)
	a := generateCanonicalTestBlocks(t, gspec, key, 13)
	if _, err := chain.InsertChain(a); err != nil {
		chain.Stop()
		t.Fatalf("failed to insert chain: %v", err)
	}
	chain.Stop()

	// The first sweep ran at head A#3: A lost the assignments above it, and each
	// dropped height was recorded.
	for number := uint64(4); number <= 13; number++ {
		if err := rawdb.WriteSweptCanonicalHash(db, number, a[number-1].Hash()); err != nil {
			t.Fatalf("failed to write the record at #%d: %v", number, err)
		}
		rawdb.DeleteCanonicalHash(db, number)
	}
	if err := rawdb.WriteSweptCanonicalBound(db, 13); err != nil {
		t.Fatalf("failed to write the bound: %v", err)
	}
	rawdb.WriteHeadHeaderHash(db, a[2].Hash())
	rawdb.WriteHeadFastBlockHash(db, a[2].Hash())
	rawdb.WriteHeadBlockHash(db, a[2].Hash())

	// Branch B forks at A#3 and becomes canonical through #6. Its headers reuse
	// A's difficulty and time so they pass verification, with a different hash.
	first := openCanonicalTestChain(t, db, gspec)
	var b []*types.Header
	for i := 3; i <= 5; i++ {
		header := types.CopyHeader(a[i].Header())
		header.Extra = append(append([]byte{}, header.Extra...), 0x42)
		if len(b) > 0 {
			header.ParentHash = b[len(b)-1].Hash()
		}
		b = append(b, header)
		if status, err := first.hc.WriteHeader(header); err != nil || status != CanonStatTy {
			first.Stop()
			t.Fatalf("failed to make B canonical at #%d: status %v err %v", header.Number, status, err)
		}
	}
	first.Stop()

	// Crash window of a rewind of B to #3: the markers moved down, B's content is
	// still on disk.
	rawdb.WriteHeadHeaderHash(db, a[2].Hash())
	rawdb.WriteHeadFastBlockHash(db, a[2].Hash())
	rawdb.WriteHeadBlockHash(db, a[2].Hash())

	reopened := openCanonicalTestChain(t, db, gspec)
	defer reopened.Stop()

	if got := reopened.hc.sweptTo; got != a[12].NumberU64() {
		t.Fatalf("sweptTo after the second sweep is %d, want %d", got, a[12].NumberU64())
	}
	// The second sweep dropped B's assignments and replaced their records, while
	// A's pending bound stayed.
	for _, header := range b {
		number := header.Number.Uint64()
		hash, ok, err := rawdb.ReadSweptCanonicalHash(db, number)
		if err != nil || !ok || hash != header.Hash() {
			t.Fatalf("record at #%d: have %s ok=%t err %v, want %s", number, hash, ok, err, header.Hash())
		}
	}
	if _, err := reopened.InsertHeaderChain(b, 0); err != nil {
		t.Fatalf("failed to replay chain B: %v", err)
	}
	if got := reopened.CurrentHeader().Number.Uint64(); got != b[2].Number.Uint64() {
		t.Fatalf("header head is %d after the replay, want %d", got, b[2].Number.Uint64())
	}
	for _, header := range b {
		if hash := rawdb.ReadCanonicalHash(db, header.Number.Uint64()); hash != header.Hash() {
			t.Fatalf("assignment at #%d not restored: have %s want %s", header.Number, hash, header.Hash())
		}
	}
	// A's records above B's head are still pending, so its bound survives.
	if bound, err := rawdb.ReadSweptCanonicalBound(db); err != nil || bound != a[12].NumberU64() {
		t.Fatalf("bound after the replay: have #%d err %v, want #%d", bound, err, a[12].NumberU64())
	}
}

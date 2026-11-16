package core

import (
	"crypto/ecdsa"
	"math/big"
	"testing"

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
		if entry := rawdb.ReadTxLookupEntry(db, block.Transactions()[0].Hash()); entry != nil {
			t.Errorf("transaction lookup of block #%d kept: %d", number, *entry)
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

// TestReimportRebuildsLookupOfRetainedBlock pins the lookup repair of a block
// the startup sweep kept: a crash-interrupted rewind leaves the content above
// the head on disk, the sweep drops its canonical assignment and its
// transaction lookups, and the header import above the retained range restores
// the assignments. The re-delivered body is skipped as already known, so
// nothing but the repair writes the lookups back.
func TestReimportRebuildsLookupOfRetainedBlock(t *testing.T) {
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
		if entry := rawdb.ReadTxLookupEntry(db, block.Transactions()[0].Hash()); entry != nil {
			t.Fatalf("probe setup: lookup of #%d survived the sweep: %d", number, *entry)
		}
	}
	// A header on top of the retained chain restores the assignments through the
	// ancestor loop of WriteHeader.
	header := types.CopyHeader(blocks[5].Header())
	header.Number = big.NewInt(7)
	header.ParentHash = blocks[5].Hash()
	header.Time += 1
	if _, err := reopened.hc.WriteHeader(header); err != nil {
		t.Fatalf("failed to write the header above the retained range: %v", err)
	}
	// The re-delivery skips every block whose body is on disk.
	receipts := make([]types.Receipts, 3)
	for i := range receipts {
		receipts[i] = reopened.GetReceiptsByHash(blocks[3+i].Hash())
	}
	if _, err := reopened.InsertReceiptChain(blocks[3:], receipts); err != nil {
		t.Fatalf("failed to re-deliver the retained range: %v", err)
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

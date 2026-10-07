package core

import (
	"math/big"
	"testing"
	"time"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// The answers the marker's lifetime is read through are pinned here: the write path's eviction,
// which takes the marker with the state it guards, the heights whose state is still readable when
// the eviction reaches them - the flush boundary, whose state the commit above the loop writes to
// disk, and a height naming that same root, which is the shape a block without transactions and
// without rewards leaves behind - and the shutdown drain, which leaves the markers of the state
// window behind. The drain's other arm - the delete below its line, reached when a head is adopted
// past the last block the write path executed - is not pinned: it takes a head pointer lowered
// below the deepest executed block with those blocks left in place, plus a re-delivery of the
// stored range above the hole, and no fixture in this package builds that. It is recorded in
// docs/adr/0001-bound-executed-marker-to-state-lifetime.md.
//
// TestExecutedMarkerIsEvictedWithTheState pins the lifetime the marker is given on a node that
// prunes: the marker of a block goes when the state it guards goes, and nothing inside the state
// window is touched.
func TestExecutedMarkerIsEvictedWithTheState(t *testing.T) {
	chain, blocks, _, _ := newPrunedCanonicalChain(t)

	// Outside the state window: the block is on disk and canonical, its state is gone, and the
	// marker has to be gone with it.
	outside := blocks[len(blocks)-TriesInMemory-1]
	if chain.HasBlockAndFullState(outside.Hash(), outside.NumberU64()) {
		t.Fatal("the block must be pruned, otherwise the shape is not covered")
	}
	if rawdb.HasExecutedMarker(chain.db, outside.Hash(), outside.NumberU64()) {
		t.Fatalf("marker for pruned block %d is still on disk", outside.NumberU64())
	}

	// The first block inside the window, one height above the eviction line: both halves of
	// HasExecutedBlock still hold, which is what makes the block above a boundary rather
	// than the end of a range.
	firstInside := blocks[len(blocks)-TriesInMemory]
	if !chain.HasBlockAndFullState(firstInside.Hash(), firstInside.NumberU64()) {
		t.Fatalf("block %d is inside the window and must keep its state", firstInside.NumberU64())
	}
	if !rawdb.HasExecutedMarker(chain.db, firstInside.Hash(), firstInside.NumberU64()) {
		t.Fatalf("marker for block %d, inside the window, was evicted", firstInside.NumberU64())
	}

	// Inside the window: the state is there, so the marker has to be there too - it is asked
	// together with the state, so both halves of HasExecutedBlock are checked.
	inside := blocks[len(blocks)-1]
	if head := chain.CurrentBlock(); inside.Hash() != head.Hash() {
		t.Fatalf("the fixture's tip %d is not the head %d", inside.NumberU64(), head.Number.Uint64())
	}
	if !chain.HasBlockAndFullState(inside.Hash(), inside.NumberU64()) {
		t.Fatal("the head must still have its state")
	}
	if !rawdb.HasExecutedMarker(chain.db, inside.Hash(), inside.NumberU64()) {
		t.Fatalf("marker for head %d was evicted", inside.NumberU64())
	}
	if !chain.HasExecutedBlock(inside.Hash(), inside.NumberU64()) {
		t.Fatal("the head must still answer as executed")
	}
}

// TestExecutedMarkerSurvivesOnTheFlushedHeight pins the rule at the height a flush writes. That
// commit puts the state of `chosen` on disk, so the second half of HasExecutedBlock is still true
// when the loop reaches that height: dereferencing a committed root takes nothing off disk, and
// the marker is then the half that decides. Taking it would turn the answer of a block this node
// ran, and whose state it still holds, into false.
//
// The fixture sets the commit time limit to zero, so every pass flushes the height its own cursor
// stands on and the loop never reaches a height it has to take a marker from: what it pins is the
// flush boundary, not the eviction below it. The eviction below is pinned by
// TestExecutedMarkerIsEvictedWithTheState, and the heights that name the flushed root without being
// it by TestExecutedMarkerSurvivesOnASharedRootHeight.
func TestExecutedMarkerSurvivesOnTheFlushedHeight(t *testing.T) {
	engine := ethash.NewFaker()
	gspec := &Genesis{
		Alloc:   types.GenesisAlloc{},
		BaseFee: big.NewInt(params.InitialBaseFee),
		Config:  params.TestChainConfig,
	}
	genDb := rawdb.NewMemoryDatabase()
	if _, err := gspec.Commit(genDb); err != nil {
		t.Fatalf("failed to commit genesis: %v", err)
	}
	blocks, _ := GenerateChain(gspec.Config, gspec.ToBlock(), engine, genDb, TriesInMemory+2, nil)
	chain, err := NewBlockChain(rawdb.NewMemoryDatabase(), &CacheConfig{TrieDirtyLimit: 256, TrieTimeLimit: 0}, gspec, engine, vm.Config{})
	if err != nil {
		t.Fatalf("failed to create tester chain: %v", err)
	}
	t.Cleanup(chain.Stop)
	if n, err := chain.InsertChain(blocks); err != nil {
		t.Fatalf("block %d: failed to insert into chain: %v", n, err)
	}

	// The height at the eviction line is the last one the write path flushed: its state is on
	// disk, so a marker that is gone there is the difference between "this node ran it" and
	// "run it again".
	flushed := blocks[len(blocks)-TriesInMemory-1]
	if !chain.HasBlockAndFullState(flushed.Hash(), flushed.NumberU64()) {
		t.Fatalf("the fixture's flush did not leave the state of block %d on disk", flushed.NumberU64())
	}
	if !rawdb.HasExecutedMarker(chain.db, flushed.Hash(), flushed.NumberU64()) {
		t.Fatalf("marker for the flushed height %d was taken with a state that stayed", flushed.NumberU64())
	}
	if !chain.HasExecutedBlock(flushed.Hash(), flushed.NumberU64()) {
		t.Fatalf("block %d must still answer as executed", flushed.NumberU64())
	}

	// One height deeper: also a flush boundary, also left alone by the loop.
	deeper := blocks[len(blocks)-TriesInMemory-2]
	if !chain.HasBlockAndFullState(deeper.Hash(), deeper.NumberU64()) {
		t.Fatalf("the fixture's flush did not leave the state of block %d on disk", deeper.NumberU64())
	}
	if !rawdb.HasExecutedMarker(chain.db, deeper.Hash(), deeper.NumberU64()) {
		t.Fatalf("marker for the flushed height %d was taken with a state that stayed", deeper.NumberU64())
	}

	// The first height inside the window: untouched by the loop either way, and the answers
	// above have to read as a boundary rather than as the end of a range.
	firstInside := blocks[len(blocks)-TriesInMemory]
	if !chain.HasBlockAndFullState(firstInside.Hash(), firstInside.NumberU64()) {
		t.Fatalf("block %d is inside the window and must keep its state", firstInside.NumberU64())
	}
	if !rawdb.HasExecutedMarker(chain.db, firstInside.Hash(), firstInside.NumberU64()) {
		t.Fatalf("marker for block %d, inside the window, was evicted", firstInside.NumberU64())
	}
}

// TestExecutedMarkerSurvivesOnAnArchiveNode pins the other half of the rule: a node that never
// dereferences state keeps every marker, because there the marker is the only thing separating a
// block this node ran from one whose root merely resolves.
func TestExecutedMarkerSurvivesOnAnArchiveNode(t *testing.T) {
	engine := ethash.NewFaker()
	gspec := &Genesis{
		Alloc:   types.GenesisAlloc{},
		BaseFee: big.NewInt(params.InitialBaseFee),
		Config:  params.TestChainConfig,
	}
	genDb := rawdb.NewMemoryDatabase()
	if _, err := gspec.Commit(genDb); err != nil {
		t.Fatalf("failed to commit genesis: %v", err)
	}
	blocks, _ := GenerateChain(gspec.Config, gspec.ToBlock(), engine, genDb, 2*TriesInMemory, nil)
	chain, err := NewBlockChain(rawdb.NewMemoryDatabase(), &CacheConfig{TrieDirtyDisabled: true}, gspec, engine, vm.Config{})
	if err != nil {
		t.Fatalf("failed to create tester chain: %v", err)
	}
	t.Cleanup(chain.Stop)
	if n, err := chain.InsertChain(blocks); err != nil {
		t.Fatalf("block %d: failed to insert into chain: %v", n, err)
	}

	// An archive node never enqueues state for eviction: its write path takes the branch
	// above the loop, so an empty queue is what the markers are left alone by. Asserted
	// here because an absent marker below would not be distinguishable from a marker the
	// archive branch had evicted - with an empty queue the loop has nothing to reach either
	// way, which is the reason the markers stay rather than a property of the loop.
	if !chain.triegc.Empty() {
		t.Fatalf("archive node queued %d entries for eviction", chain.triegc.Size())
	}

	// The same block the pruning fixture loses its state for keeps both here.
	outside := blocks[len(blocks)-TriesInMemory-1]
	if !chain.HasBlockAndFullState(outside.Hash(), outside.NumberU64()) {
		t.Fatal("an archive node must keep the state")
	}
	if !rawdb.HasExecutedMarker(chain.db, outside.Hash(), outside.NumberU64()) {
		t.Fatalf("marker for block %d was evicted on an archive node", outside.NumberU64())
	}
}

// TestExecutedMarkerSurvivesTheShutdownDrain pins the queue's other exit. saveData drains
// whatever the write path had not reached yet and dereferences those roots, but it takes no
// markers with it while the head sits at the last block the write path executed, which is
// this fixture's shape: every height still queued then sits inside the state window, where
// the marker still decides, so deleting one would cost an execution rather than save a key.
// The write path is what evicts, and the first test above is where that is pinned.
func TestExecutedMarkerSurvivesTheShutdownDrain(t *testing.T) {
	chain, blocks, _, _ := newPrunedCanonicalChain(t)

	// The head is still queued after the import: the write path breaks on the first entry
	// above its cursor, and the head sits TriesInMemory above it.
	head := blocks[len(blocks)-1]
	if !rawdb.HasExecutedMarker(chain.db, head.Hash(), head.NumberU64()) {
		t.Fatal("the fixture must start with the head's marker on disk")
	}
	chain.saveData()

	if !chain.triegc.Empty() {
		t.Fatalf("the shutdown drain left %d entries queued", chain.triegc.Size())
	}
	if !rawdb.HasExecutedMarker(chain.db, head.Hash(), head.NumberU64()) {
		t.Fatalf("marker for queued head %d was taken by the shutdown drain", head.NumberU64())
	}
	// HasExecutedBlock, not the marker alone: this height is inside the window, so its state
	// was committed to disk immediately above and the marker is the half that decides. The
	// answer here is the one a restarted node resumes from, and a drain that deleted the
	// marker would be what flips it to false.
	if !chain.HasExecutedBlock(head.Hash(), head.NumberU64()) {
		t.Fatal("the head must still answer as executed after the shutdown drain")
	}
}

// TestExecutedMarkerSurvivesOnASharedRootHeight pins the rule one height past the flush boundary.
// The eviction asks the trie database whether the state is gone rather than assuming it from the
// height, so a height that is not the one a flush committed, but whose header names the root that
// flush wrote, keeps its marker too. Blocks without transactions and without rewards leave exactly
// that behind - the shape makeSharedStateChain builds - and the entry the loop reaches one pass
// after the flush carries a root that is readable on disk by then. Taking its marker flips
// HasExecutedBlock for a block this node ran: its own state is on disk, and so is its parent's,
// both being the flushed root, so ValidateBody stops answering it as known while the parent check
// below still passes and the re-delivery runs Process over the block again.
//
// The single flush is forced through bc.gcproc rather than through the time limit, so the pass that
// writes a state out is named by the fixture instead of by the clock, and the fixture does not
// depend on the package-level lastWrite the throttle also compares against.
func TestExecutedMarkerSurvivesOnASharedRootHeight(t *testing.T) {
	var (
		key, _ = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		addr   = crypto.PubkeyToAddress(key.PublicKey)
		config = *params.TestChainConfig
		engine = sharedStateEngine{ethash.NewFaker()}
	)
	gspec := &Genesis{
		Alloc:   types.GenesisAlloc{addr: {Balance: big.NewInt(params.Ether)}},
		BaseFee: big.NewInt(params.InitialBaseFee),
		Config:  &config,
	}
	// Stay before Prague for the reason makeSharedStateChain does: EIP-2935 writes the parent hash
	// into the state of every block, which would keep the two heights from sharing a root.
	config.PragueBlock, config.OsakaBlock = nil, nil

	// The height the flush below writes is TriesInMemory+1, and the height above it is left without
	// a transaction, so it names the state root of its parent - the root that flush puts on disk.
	signer := types.LatestSigner(gspec.Config)
	genDb := rawdb.NewMemoryDatabase()
	if _, err := gspec.Commit(genDb); err != nil {
		t.Fatalf("failed to commit genesis: %v", err)
	}
	blocks, _ := GenerateChain(gspec.Config, gspec.ToBlock(), engine, genDb, 2*TriesInMemory+2, func(i int, b *BlockGen) {
		if i == TriesInMemory+1 {
			return
		}
		tx, err := types.SignTx(types.NewTransaction(b.TxNonce(addr), common.Address{0xaa}, big.NewInt(1), params.TxGas, b.BaseFee(), nil), signer, key)
		if err != nil {
			t.Fatalf("failed to sign tx: %v", err)
		}
		b.AddTx(tx)
	})
	if blocks[TriesInMemory+1].Root() != blocks[TriesInMemory].Root() {
		t.Fatal("the block above the flush boundary does not name the state root of its parent")
	}

	chain, err := NewBlockChain(rawdb.NewMemoryDatabase(), &CacheConfig{TrieDirtyLimit: 256, TrieTimeLimit: time.Hour}, gspec, engine, vm.Config{})
	if err != nil {
		t.Fatalf("failed to create tester chain: %v", err)
	}
	t.Cleanup(chain.Stop)

	// Up to the block below the one whose chosen is the boundary height. No pass here can flush:
	// chosen is at most TriesInMemory, and the throttle needs current > lastWrite+2*TriesInMemory,
	// whatever the package-level lastWrite is by now.
	if n, err := chain.InsertChain(blocks[:2*TriesInMemory]); err != nil {
		t.Fatalf("block %d: failed to insert into chain: %v", n, err)
	}
	// The height the eviction reached with no state left behind keeps nothing, which is the rule
	// the probe replaces: what it changes is which heights still have a state, not whether the
	// ones that have none are taken.
	if rawdb.HasExecutedMarker(chain.db, blocks[0].Hash(), blocks[0].NumberU64()) {
		t.Fatalf("marker for pruned block %d is still on disk", blocks[0].NumberU64())
	}

	// The one pass that writes a state out: it is the call whose chosen is height
	// TriesInMemory+1, which is the block at index TriesInMemory.
	chain.gcproc = 2 * time.Hour
	if n, err := chain.InsertChain(blocks[2*TriesInMemory : 2*TriesInMemory+1]); err != nil {
		t.Fatalf("block %d: failed to insert the boundary block: %v", n, err)
	}
	flushed := blocks[TriesInMemory]
	if !chain.HasBlockAndFullState(flushed.Hash(), flushed.NumberU64()) {
		t.Fatalf("the fixture's flush did not leave the state of block %d on disk", flushed.NumberU64())
	}
	if !rawdb.HasExecutedMarker(chain.db, flushed.Hash(), flushed.NumberU64()) {
		t.Fatalf("marker for the flushed height %d was taken with a state that stayed", flushed.NumberU64())
	}

	// The next pass reaches the height that names the flushed root. Its state is readable on disk,
	// so a marker taken here is the difference between "this node ran it" and "run it again"; the
	// parent's state is readable too, both heights being the root the flush wrote.
	if n, err := chain.InsertChain(blocks[2*TriesInMemory+1:]); err != nil {
		t.Fatalf("block %d: failed to insert into chain: %v", n, err)
	}
	above := blocks[TriesInMemory+1]
	if !chain.HasBlockAndFullState(above.Hash(), above.NumberU64()) {
		t.Fatalf("block %d must keep the state the flush wrote", above.NumberU64())
	}
	if !rawdb.HasExecutedMarker(chain.db, above.Hash(), above.NumberU64()) {
		t.Fatalf("marker for block %d, which names the flushed root, was taken with a state that stayed", above.NumberU64())
	}
	if !chain.HasExecutedBlock(above.Hash(), above.NumberU64()) {
		t.Fatalf("block %d must still answer as executed", above.NumberU64())
	}
	// The parent state survives with it, which is why a re-delivery of this height does not land
	// on the pruned-ancestor branch: it reaches execution instead.
	if !chain.HasBlockAndFullState(flushed.Hash(), flushed.NumberU64()) {
		t.Fatal("the parent state must survive as well")
	}
}

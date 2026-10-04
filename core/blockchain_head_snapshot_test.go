package core

import (
	"bytes"
	"errors"
	"math/big"
	"strings"
	"sync"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS/engines/engine_v2"
	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/ethdb"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// headWriteRecord captures one batch that the code under test flushed: the
// values it carried, and whether the snapshot under test was already readable
// from the database at the moment it was flushed.
type headWriteRecord struct {
	values [][]byte

	probeInDatabase bool
}

// headBatchRecorder wraps a database so a test can see how one logical write
// decomposes into database operations: which batches were flushed, what each of
// them carried, whether a given snapshot was already visible when a batch was
// flushed, and which keys were written straight to the database, bypassing a
// batch.
type headBatchRecorder struct {
	ethdb.Database

	// probe is the snapshot hash the test expects the code under test to write.
	probe common.Hash

	// hasErr, once set, is what every Has answers with, so a test can model a
	// database whose presence checks fail.
	hasErr error

	mu         sync.Mutex
	writes     []headWriteRecord
	directPuts []string
}

func (r *headBatchRecorder) Has(key []byte) (bool, error) {
	if r.hasErr != nil {
		return false, r.hasErr
	}
	return r.Database.Has(key)
}

func (r *headBatchRecorder) NewBatch() ethdb.Batch {
	return &headWriteBatch{Batch: r.Database.NewBatch(), rec: r}
}

func (r *headBatchRecorder) NewBatchWithSize(size int) ethdb.Batch {
	return &headWriteBatch{Batch: r.Database.NewBatchWithSize(size), rec: r}
}

func (r *headBatchRecorder) Put(key, value []byte) error {
	r.mu.Lock()
	r.directPuts = append(r.directPuts, string(key))
	r.mu.Unlock()
	return r.Database.Put(key, value)
}

func (r *headBatchRecorder) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.writes, r.directPuts = nil, nil
}

type headWriteBatch struct {
	ethdb.Batch

	rec    *headBatchRecorder
	values [][]byte
}

func (b *headWriteBatch) Put(key, value []byte) error {
	b.values = append(b.values, common.CopyBytes(value))
	return b.Batch.Put(key, value)
}

func (b *headWriteBatch) Delete(key []byte) error {
	b.values = append(b.values, nil)
	return b.Batch.Delete(key)
}

func (b *headWriteBatch) Write() error {
	// Probe before the batch is handed over: anything visible at this point was
	// written by an earlier, separate write rather than by this batch.
	has, err := rawdb.HasXdposV2Snapshot(b.rec.Database, b.rec.probe)

	b.rec.mu.Lock()
	b.rec.writes = append(b.rec.writes, headWriteRecord{
		values:          b.values,
		probeInDatabase: err == nil && has,
	})
	b.rec.mu.Unlock()

	return b.Batch.Write()
}

// newHeadWriteChain builds a short canonical chain on top of the recording
// database and returns it with the recording database itself.
func newHeadWriteChain(t *testing.T) (*headBatchRecorder, *BlockChain, *types.Block) {
	t.Helper()

	engine := ethash.NewFaker()
	genesis := &Genesis{
		BaseFee: big.NewInt(params.InitialBaseFee),
		Config:  params.AllEthashProtocolChanges,
	}
	recorder := &headBatchRecorder{Database: rawdb.NewMemoryDatabase()}
	blockchain, err := NewBlockChain(recorder, nil, genesis, engine, vm.Config{})
	if err != nil {
		t.Fatalf("failed to create the chain: %v", err)
	}
	t.Cleanup(blockchain.Stop)

	_, blocks := makeBlockChainWithGenesis(genesis, 2, engine, canonicalSeed)
	if _, err := blockchain.InsertChain(blocks); err != nil {
		t.Fatalf("failed to insert the chain: %v", err)
	}
	head := blockchain.GetBlockByNumber(2)
	if head == nil {
		t.Fatal("head block is missing")
	}
	return recorder, blockchain, head
}

func containsValue(values [][]byte, want []byte) bool {
	for _, value := range values {
		if bytes.Equal(value, want) {
			return true
		}
	}
	return false
}

// TestWriteHeadBlockStoresNextEpochSnapshotInSameBatch pins how a gap block and
// its next-epoch snapshot reach the database: the snapshot must travel in the
// very batch that carries the chain markers of the block it belongs to, so that
// a process exit cannot leave a canonical gap block without its snapshot.
//
// Splitting the write back into two flushes (or writing the snapshot straight to
// the database, as an engine-side store would) makes this test fail: the head
// batch would no longer carry the snapshot, or the snapshot would already be
// visible when that batch is flushed.
//
// The test drives writeHeadBlock directly with a fabricated snapshot. It pins
// the storage mechanics, not which blocks are gap blocks; that predicate and the
// derivation are covered by the engine_v2 tests.
//
// The engine cache is out of reach from here: the fixture runs on ethash, and
// XDPoS_v2.snapshots is unexported, so the "cached only once the batch is on
// disk" ordering is not asserted. It is also not observable through this code
// path at all: a failed batch.Write exits the process (log.Crit), so a snapshot
// cached a step too early cannot outlive the failure.
func TestWriteHeadBlockStoresNextEpochSnapshotInSameBatch(t *testing.T) {
	t.Run("with snapshot", func(t *testing.T) {
		recorder, blockchain, head := newHeadWriteChain(t)

		snap := engine_v2.NewSnapshot(head.NumberU64(), head.Hash(), []common.Address{{0x1}, {0x2}})
		blob, err := engine_v2.EncodeSnapshot(snap)
		if err != nil {
			t.Fatalf("failed to encode the snapshot: %v", err)
		}
		recorder.probe = snap.Hash
		recorder.reset()

		// writeHeadBlock expects the chain mutex to be held by its caller.
		blockchain.chainmu.MustLock()
		blockchain.writeHeadBlock(head, snap)
		blockchain.chainmu.Unlock()

		recorder.mu.Lock()
		writes, directPuts := recorder.writes, recorder.directPuts
		recorder.mu.Unlock()

		if len(writes) != 1 {
			t.Fatalf("writeHeadBlock flushed %d batches, want exactly 1", len(writes))
		}
		if len(directPuts) != 0 {
			t.Fatalf("writeHeadBlock wrote %d key(s) outside its batch: %v", len(directPuts), directPuts)
		}
		if writes[0].probeInDatabase {
			t.Fatal("the snapshot was already in the database when the head batch was flushed, so it was written separately")
		}
		if !containsValue(writes[0].values, blob) {
			t.Fatal("the head batch does not carry the next-epoch snapshot: the write was split")
		}
		if !containsValue(writes[0].values, head.Hash().Bytes()) {
			t.Fatal("the head batch does not carry the head block hash")
		}
		if has, err := rawdb.HasXdposV2Snapshot(recorder.Database, snap.Hash); err != nil || !has {
			t.Fatalf("snapshot missing from the database after the flush: has=%v err=%v", has, err)
		}
		if got, err := rawdb.ReadXdposV2Snapshot(recorder.Database, snap.Hash); err != nil || !bytes.Equal(got, blob) {
			t.Fatalf("the stored snapshot does not round-trip: err=%v", err)
		}
		if got := rawdb.ReadHeadBlockHash(recorder.Database); got != head.Hash() {
			t.Fatalf("head block hash is %s, want %s", got, head.Hash())
		}
	})

	// A block without a next-epoch snapshot (every non-gap block, and every v1
	// block) must not write one, and must still flush its markers exactly once.
	t.Run("without snapshot", func(t *testing.T) {
		recorder, blockchain, head := newHeadWriteChain(t)

		snap := engine_v2.NewSnapshot(head.NumberU64(), head.Hash(), []common.Address{{0x1}})
		recorder.probe = snap.Hash
		recorder.reset()

		blockchain.chainmu.MustLock()
		blockchain.writeHeadBlock(head, nil)
		blockchain.chainmu.Unlock()

		recorder.mu.Lock()
		writes, directPuts := recorder.writes, recorder.directPuts
		recorder.mu.Unlock()

		if len(writes) != 1 {
			t.Fatalf("writeHeadBlock flushed %d batches, want exactly 1", len(writes))
		}
		if len(directPuts) != 0 {
			t.Fatalf("writeHeadBlock wrote %d key(s) outside its batch: %v", len(directPuts), directPuts)
		}
		if has, err := rawdb.HasXdposV2Snapshot(recorder.Database, snap.Hash); err != nil || has {
			t.Fatalf("a snapshot was written for a block without one: has=%v err=%v", has, err)
		}
	})
}

// TestGapBlockSnapshotDerivationFailsBeforeAnythingIsWritten pins the failure
// mode of the derivation: a v2 gap block whose next-epoch set cannot be derived
// must be rejected before the block is stored, so that the chain keeps pointing
// at the previous head and the block can be delivered again. Storing the block
// first would make the insertion paths read it back as already known and never
// apply it again, and advancing the head would leave a canonical gap block
// without the snapshot its epoch switch reads.
func TestGapBlockSnapshotDerivationFailsBeforeAnythingIsWritten(t *testing.T) {
	recorder, blockchain, head := newHeadWriteChain(t)

	// Schedule the next block as a v2 gap block: 10-7 == 3, and the v2 era
	// starts after block 1. The state of that block holds no candidate, so the
	// derivation has to fail.
	cfg := params.AllEthashProtocolChanges.Clone()
	cfg.XDPoS = &params.XDPoSConfig{
		Epoch: 10,
		Gap:   7,
		V2:    &params.V2{SwitchBlock: big.NewInt(1)},
	}
	blockchain.SetChainConfig(cfg)

	state, err := blockchain.State()
	if err != nil {
		t.Fatalf("failed to open the head state: %v", err)
	}
	block := types.NewBlockWithHeader(&types.Header{
		ParentHash: head.Hash(),
		Number:     big.NewInt(3),
		Difficulty: new(big.Int).Add(head.Difficulty(), big.NewInt(1)),
		Root:       state.IntermediateRoot(false),
		Time:       head.Time() + 1,
	})

	recorder.reset()
	blockchain.chainmu.MustLock()
	_, err = blockchain.writeBlockWithState(block, nil, state, nil, nil)
	blockchain.chainmu.Unlock()
	if err == nil {
		t.Fatal("a gap block whose next-epoch set cannot be derived was accepted")
	}
	if got := blockchain.CurrentBlock().Hash(); got != head.Hash() {
		t.Fatalf("head moved to %s despite the failed derivation, want %s", got, head.Hash())
	}
	if blockchain.HasBlock(block.Hash(), 3) {
		t.Fatal("the block reached the database before its next-epoch set could be derived")
	}
	recorder.mu.Lock()
	writes, directPuts := recorder.writes, recorder.directPuts
	recorder.mu.Unlock()
	if len(writes) != 0 || len(directPuts) != 0 {
		t.Fatalf("the failed derivation wrote %d batch(es) and %d key(s) outside a batch, want none", len(writes), len(directPuts))
	}
}

// TestNeedsNextEpochSnapshot pins which blocks owe a v2 next-epoch snapshot: the
// gap block of the v2 era only. The v1 era keeps its own refresh path, and a
// schedule without a usable gap offset has no gap block at all - it must also
// not divide by zero.
func TestNeedsNextEpochSnapshot(t *testing.T) {
	_, blockchain, _ := newHeadWriteChain(t)

	v2Config := func() *params.ChainConfig {
		cfg := params.AllEthashProtocolChanges.Clone()
		cfg.XDPoS = &params.XDPoSConfig{
			Epoch: 10,
			Gap:   4,
			V2:    &params.V2{SwitchBlock: big.NewInt(1)},
		}
		return cfg
	}
	blockchain.SetChainConfig(v2Config())

	for _, tc := range []struct {
		number uint64
		want   bool
	}{
		{6, true},  // gap block of epoch 0
		{16, true}, // gap block of epoch 1
		{5, false}, // the block before the gap block
		{7, false}, // the block after the gap block
		{2, false}, // v2, but not a gap block
	} {
		if got := blockchain.needsNextEpochSnapshot(new(big.Int).SetUint64(tc.number)); got != tc.want {
			t.Fatalf("needsNextEpochSnapshot(%d) = %v, want %v", tc.number, got, tc.want)
		}
	}

	// The same schedule before the v2 switch keeps the v1 refresh path.
	v1Config := v2Config()
	v1Config.XDPoS.V2 = nil
	blockchain.SetChainConfig(v1Config)
	if blockchain.needsNextEpochSnapshot(big.NewInt(6)) {
		t.Fatal("a v1 gap block asked for a v2 snapshot")
	}

	// A schedule without a usable gap offset has no gap block and must not
	// divide by zero.
	for _, schedule := range []struct {
		epoch, gap uint64
	}{
		{0, 4},  // no epoch length
		{10, 0}, // no gap offset
		{10, 10},
		{10, 20},
	} {
		cfg := v2Config()
		cfg.XDPoS.Epoch, cfg.XDPoS.Gap = schedule.epoch, schedule.gap
		blockchain.SetChainConfig(cfg)
		if blockchain.isNextEpochGapBlock(6) {
			t.Fatalf("isNextEpochGapBlock(6) is true for epoch %d, gap %d", schedule.epoch, schedule.gap)
		}
		if blockchain.needsNextEpochSnapshot(big.NewInt(6)) {
			t.Fatalf("needsNextEpochSnapshot(6) is true for epoch %d, gap %d", schedule.epoch, schedule.gap)
		}
	}
}

// newReorgGapChain returns the recording database, a chain whose head is block 2,
// and a fabricated successor chain of two blocks. The schedule makes the first
// successor (number 3) the v2 gap block, and every successor carries a root no
// committed state can answer for, so nothing can be derived from their state.
// A set that the reorg is able to use therefore has to come from the database.
func newReorgGapChain(t *testing.T) (*headBatchRecorder, *BlockChain, []*types.Block) {
	t.Helper()
	recorder, blockchain, head := newHeadWriteChain(t)

	cfg := params.AllEthashProtocolChanges.Clone()
	cfg.XDPoS = &params.XDPoSConfig{
		Epoch: 10,
		Gap:   7, // 10-7 == 3, so block 3 is the gap block
		V2:    &params.V2{SwitchBlock: big.NewInt(1)},
	}
	blockchain.SetChainConfig(cfg)

	unreadableRoot := common.HexToHash("0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")

	parent, timestamp, difficulty := head.Hash(), head.Time(), head.Difficulty()
	headNumber := head.NumberU64()
	blocks := make([]*types.Block, 0, 2)
	for i := uint64(1); i <= 2; i++ {
		block := types.NewBlockWithHeader(&types.Header{
			ParentHash: parent,
			Number:     new(big.Int).SetUint64(headNumber + i),
			Difficulty: new(big.Int).Add(difficulty, big.NewInt(1)),
			Root:       unreadableRoot,
			Time:       timestamp + i,
		})
		rawdb.WriteBlock(recorder.Database, block)
		blocks = append(blocks, block)
		parent, timestamp, difficulty = block.Hash(), block.Time(), block.Difficulty()
	}
	return recorder, blockchain, blocks
}

// TestReorgGapSnapshotDerivationFailsBeforeAnySideEffect pins the failure mode
// of the reorg path: the next-epoch set of every v2 gap block of the new chain
// is derived before the first side effect, so a set that cannot be derived
// leaves the chain exactly where it was instead of advancing the head over a
// gap block that has none. A set derived after the head write would move the
// head first, and the block is already stored at that point, so redelivering it
// would not apply it again.
func TestReorgGapSnapshotDerivationFailsBeforeAnySideEffect(t *testing.T) {
	recorder, blockchain, blocks := newReorgGapChain(t)
	if !blockchain.needsNextEpochSnapshot(blocks[0].Number()) {
		t.Fatalf("block %d is not scheduled as a v2 gap block, so the test would not derive anything", blocks[0].NumberU64())
	}
	recorder.reset()

	oldHead := blockchain.CurrentHeader()
	// reorg expects the chain mutex to be held by its caller.
	blockchain.chainmu.MustLock()
	err := blockchain.reorg(oldHead, blocks[len(blocks)-1].Header(), nil)
	blockchain.chainmu.Unlock()

	if err == nil {
		t.Fatal("a reorg over a gap block whose set cannot be derived was accepted")
	}
	if !strings.Contains(err.Error(), "gap block 3") {
		t.Fatalf("the reorg failed for something other than the gap block set: %v", err)
	}
	if got := blockchain.CurrentBlock().Hash(); got != oldHead.Hash() {
		t.Fatalf("the head moved to %s despite the failed derivation, want %s", got, oldHead.Hash())
	}
	recorder.mu.Lock()
	writes, directPuts := recorder.writes, recorder.directPuts
	recorder.mu.Unlock()
	if len(writes) != 0 || len(directPuts) != 0 {
		t.Fatalf("the failed reorg wrote %d batch(es) and %d key(s) outside a batch, want none", len(writes), len(directPuts))
	}
}

// TestReorgTakesAGapSnapshotItAlreadyStored pins the two halves of the split
// between v1 and v2 on the reorg path. A set the database already holds is taken
// from there rather than derived again, which is observable here because the
// state of the fabricating chain cannot be opened at all. And a v2 gap block
// must not be mistaken for the v1 era just because no set travels with it: a
// refresh is what that would run, and it reads the state committed at the block,
// which this fixture leaves unreadable, so reaching it would stop the node.
func TestReorgTakesAGapSnapshotItAlreadyStored(t *testing.T) {
	recorder, blockchain, blocks := newReorgGapChain(t)

	// What a previous canonical pass over this gap block would have stored.
	snap := engine_v2.NewSnapshot(blocks[0].NumberU64(), blocks[0].Hash(), []common.Address{{0x1}, {0x2}})
	blob, err := engine_v2.EncodeSnapshot(snap)
	if err != nil {
		t.Fatalf("failed to encode the snapshot: %v", err)
	}
	rawdb.WriteXdposV2Snapshot(recorder.Database, snap.Hash, blob)
	recorder.reset()

	oldHead := blockchain.CurrentHeader()
	blockchain.chainmu.MustLock()
	err = blockchain.reorg(oldHead, blocks[len(blocks)-1].Header(), nil)
	blockchain.chainmu.Unlock()
	if err != nil {
		t.Fatalf("the stored set did not spare the unreadable state, so the reorg derived it again: %v", err)
	}

	want := blocks[len(blocks)-1].Hash()
	if got := blockchain.CurrentBlock().Hash(); got != want {
		t.Fatalf("head is %s after the reorg, want %s", got, want)
	}
	if got, err := rawdb.ReadXdposV2Snapshot(recorder.Database, snap.Hash); err != nil || !bytes.Equal(got, blob) {
		t.Fatalf("the reorg rewrote the set it took from the database: err=%v", err)
	}
}

// derivableGapCandidates is the candidate order the state of the derivable gap
// block stores, and derivableGapSet is the order the stakes written for it
// produce: the stakes grow over the stored order, so the set the derivation has
// to hand back is the exact reverse of it, and a derivation that read no stakes
// cannot produce it.
var (
	derivableGapCandidates = []common.Address{{0x11}, {0x22}}
	derivableGapSet        = []common.Address{{0x22}, {0x11}}
)

// candidatesLengthSlot and candidateSlot resolve the storage the voting contract
// keeps its candidate array in: `candidates` is slot 8, its length sits in the
// slot itself and its elements follow it, which is what StateDB.GetCandidates
// reads (core/state/statedb_utils.go).
func candidatesLengthSlot() common.Hash {
	return common.BigToHash(big.NewInt(8))
}

func candidateSlot(i uint64) common.Hash {
	return state.GetLocDynamicArrAtElement(candidatesLengthSlot(), i, 1)
}

// candidateCapSlot resolves the storage slot of ValidatorState.cap for a
// candidate: validatorsState is slot 1, the owner and the candidate flag share
// the first slot of the entry and cap follows it, which is what
// StateDB.GetCandidateCap reads (core/state/statedb_utils.go).
func candidateCapSlot(candidate common.Address) common.Hash {
	loc := state.GetLocMappingAtKey(candidate.Hash(), 1)
	loc.Add(loc, big.NewInt(1))
	return common.BigToHash(loc)
}

// newReorgDerivableGapChain is newReorgGapChain with a readable gap block state.
// The same schedule makes block 3 the v2 gap block, but its header names a
// committed state that holds masternode candidates and their stakes, so the
// next-epoch set of that block can be derived - where newReorgGapChain forces the
// derivation to fail.
func newReorgDerivableGapChain(t *testing.T) (*headBatchRecorder, *BlockChain, []*types.Block) {
	t.Helper()
	recorder, blockchain, head := newHeadWriteChain(t)

	cfg := params.AllEthashProtocolChanges.Clone()
	cfg.XDPoS = &params.XDPoSConfig{
		Epoch: 10,
		Gap:   7, // 10-7 == 3, so block 3 is the gap block
		V2:    &params.V2{SwitchBlock: big.NewInt(1)},
	}
	blockchain.SetChainConfig(cfg)

	// The candidates and their stakes go into the state of the head and are
	// committed, so the gap block below names a state that can still be opened
	// after whoever wrote it is gone, which is what the reorg reads.
	statedb, err := blockchain.StateAt(head.Root())
	if err != nil {
		t.Fatalf("failed to open the head state: %v", err)
	}
	statedb.SetState(common.MasternodeVotingSMCBinary, candidatesLengthSlot(),
		common.BigToHash(new(big.Int).SetUint64(uint64(len(derivableGapCandidates)))))
	for i, candidate := range derivableGapCandidates {
		statedb.SetState(common.MasternodeVotingSMCBinary, candidateSlot(uint64(i)), candidate.Hash())
		statedb.SetState(common.MasternodeVotingSMCBinary, candidateCapSlot(candidate),
			common.BigToHash(big.NewInt(int64(10*(i+1)))))
	}
	root, err := statedb.Commit(head.NumberU64()+1, false)
	if err != nil {
		t.Fatalf("failed to commit the candidate state: %v", err)
	}

	parent, timestamp, difficulty := head.Hash(), head.Time(), head.Difficulty()
	headNumber := head.NumberU64()
	blocks := make([]*types.Block, 0, 2)
	for i := uint64(1); i <= 2; i++ {
		block := types.NewBlockWithHeader(&types.Header{
			ParentHash: parent,
			Number:     new(big.Int).SetUint64(headNumber + i),
			Difficulty: new(big.Int).Add(difficulty, big.NewInt(1)),
			Root:       root,
			Time:       timestamp + i,
		})
		rawdb.WriteBlock(recorder.Database, block)
		blocks = append(blocks, block)
		parent, timestamp, difficulty = block.Hash(), block.Time(), block.Difficulty()
	}
	return recorder, blockchain, blocks
}

// TestReorgDerivesAGapSnapshotItDoesNotHave pins the successful branch of the
// reorg derivation: a v2 gap block of the new chain whose state can be read and
// whose set the database does not hold is derived before the first side effect,
// and that set travels in the very batch that carries the chain markers of the
// block it belongs to. The two branches either side of it are pinned by
// TestReorgGapSnapshotDerivationFailsBeforeAnySideEffect (unreadable state) and
// TestReorgTakesAGapSnapshotItAlreadyStored (set already stored), neither of
// which reaches this one.
//
// Losing the set between the derivation and the head write - a map keyed by
// number, a set dropped on the way into writeHeadBlock - is what this catches: it
// would leave the gap block canonical without the snapshot its epoch switch
// reads, which is the hole the batch is there to close.
func TestReorgDerivesAGapSnapshotItDoesNotHave(t *testing.T) {
	recorder, blockchain, blocks := newReorgDerivableGapChain(t)

	gap := blocks[0]
	if !blockchain.needsNextEpochSnapshot(gap.Number()) {
		t.Fatalf("block %d is not scheduled as a v2 gap block, so the test would not derive anything", gap.NumberU64())
	}
	blob, err := engine_v2.EncodeSnapshot(engine_v2.NewSnapshot(gap.NumberU64(), gap.Hash(), derivableGapSet))
	if err != nil {
		t.Fatalf("failed to encode the expected snapshot: %v", err)
	}
	// A set is stored under the hash of the block it belongs to, so this probe
	// tells whether the batch that carries the gap block's markers carried the
	// set too, or whether some other write stored it beforehand.
	recorder.probe = gap.Hash()
	recorder.reset()

	oldHead := blockchain.CurrentHeader()
	// reorg expects the chain mutex to be held by its caller.
	blockchain.chainmu.MustLock()
	err = blockchain.reorg(oldHead, blocks[len(blocks)-1].Header(), nil)
	blockchain.chainmu.Unlock()
	if err != nil {
		t.Fatalf("the reorg over a gap block with a derivable set failed: %v", err)
	}

	want := blocks[len(blocks)-1].Hash()
	if got := blockchain.CurrentBlock().Hash(); got != want {
		t.Fatalf("head is %s after the reorg, want %s", got, want)
	}
	recorder.mu.Lock()
	writes, directPuts := recorder.writes, recorder.directPuts
	recorder.mu.Unlock()
	if len(directPuts) != 0 {
		t.Fatalf("the reorg wrote %d key(s) outside a batch: %v", len(directPuts), directPuts)
	}
	carrying := 0
	for _, write := range writes {
		if !containsValue(write.values, blob) {
			continue
		}
		carrying++
		if !containsValue(write.values, gap.Hash().Bytes()) {
			t.Fatal("the batch carrying the derived set does not carry the markers of the gap block it belongs to")
		}
		if write.probeInDatabase {
			t.Fatal("the set was already in the database when its batch was flushed, so it was written separately")
		}
	}
	if carrying != 1 {
		t.Fatalf("%d batch(es) carried the derived set, want exactly 1", carrying)
	}
	if stored, err := rawdb.ReadXdposV2Snapshot(recorder.Database, gap.Hash()); err != nil || !bytes.Equal(stored, blob) {
		t.Fatalf("the set the gap block stored is not the one derived from its state: err=%v", err)
	}
}

// TestReorgFailsOnSnapshotProbeError pins what a reorg does when it cannot tell
// whether a set is already stored: it fails before any side effect instead of
// deriving over a set it cannot see. The gap block of this chain has readable
// state, so a reorg that read the failed probe as "not stored" would derive the
// set, overwrite whatever the key holds and succeed.
func TestReorgFailsOnSnapshotProbeError(t *testing.T) {
	recorder, blockchain, blocks := newReorgDerivableGapChain(t)

	probeErr := errors.New("injected snapshot probe failure")
	recorder.hasErr = probeErr
	recorder.reset()

	oldHead := blockchain.CurrentHeader()
	// reorg expects the chain mutex to be held by its caller.
	blockchain.chainmu.MustLock()
	err := blockchain.reorg(oldHead, blocks[len(blocks)-1].Header(), nil)
	blockchain.chainmu.Unlock()

	if err == nil {
		t.Fatal("the reorg went ahead although it could not tell whether the set was stored")
	}
	if !errors.Is(err, probeErr) {
		t.Fatalf("the reorg failed for something other than the failed probe: %v", err)
	}
	if got := blockchain.CurrentBlock().Hash(); got != oldHead.Hash() {
		t.Fatalf("the head moved to %s despite the failed probe, want %s", got, oldHead.Hash())
	}
	recorder.mu.Lock()
	writes, directPuts := recorder.writes, recorder.directPuts
	recorder.mu.Unlock()
	if len(writes) != 0 || len(directPuts) != 0 {
		t.Fatalf("the failed reorg wrote %d batch(es) and %d key(s) outside a batch, want none", len(writes), len(directPuts))
	}
	if has, err := rawdb.HasXdposV2Snapshot(recorder.Database, blocks[0].Hash()); err != nil || has {
		t.Fatalf("a set reached the database despite the failed probe: has=%v err=%v", has, err)
	}
}

// TestReorgTipGapSnapshotIsWrittenOnce pins the head write behind an insertion
// that reorgs: the set of a gap block that is itself the tip is stored by the
// reorg apply loop together with the markers of that block, and the head write
// that follows the reorg must not store and announce it a second time.
//
// The other cases do not reach that write: they drive the reorg directly, and
// the gap block they reorg over sits below the tip.
func TestReorgTipGapSnapshotIsWrittenOnce(t *testing.T) {
	recorder, blockchain, head := newHeadWriteChain(t)

	// 10-8 == 2, so block 2 is the v2 gap block.
	cfg := params.AllEthashProtocolChanges.Clone()
	cfg.XDPoS = &params.XDPoSConfig{
		Epoch: 10,
		Gap:   8,
		V2:    &params.V2{SwitchBlock: big.NewInt(1)},
	}
	blockchain.SetChainConfig(cfg)

	// The state handed to the insertion holds the candidates and their stakes,
	// so the set of the gap block can be derived from it.
	statedb, err := blockchain.State()
	if err != nil {
		t.Fatalf("failed to open the head state: %v", err)
	}
	statedb.SetState(common.MasternodeVotingSMCBinary, candidatesLengthSlot(),
		common.BigToHash(new(big.Int).SetUint64(uint64(len(derivableGapCandidates)))))
	for i, candidate := range derivableGapCandidates {
		statedb.SetState(common.MasternodeVotingSMCBinary, candidateSlot(uint64(i)), candidate.Hash())
		statedb.SetState(common.MasternodeVotingSMCBinary, candidateCapSlot(candidate),
			common.BigToHash(big.NewInt(int64(10*(i+1)))))
	}

	// A block at the head's own number, built on the block below it and with a
	// higher difficulty: the insertion reorgs and the tip itself is the gap
	// block.
	fork := blockchain.GetBlockByNumber(head.NumberU64() - 1)
	block := types.NewBlockWithHeader(&types.Header{
		ParentHash: fork.Hash(),
		Number:     new(big.Int).Set(head.Number()),
		Difficulty: new(big.Int).Add(head.Difficulty(), big.NewInt(1)),
		Root:       statedb.IntermediateRoot(false),
		Time:       head.Time() + 1,
	})
	if !blockchain.needsNextEpochSnapshot(block.Number()) {
		t.Fatalf("block %d is not scheduled as a v2 gap block, so no set would be derived", block.NumberU64())
	}
	blob, err := engine_v2.EncodeSnapshot(engine_v2.NewSnapshot(block.NumberU64(), block.Hash(), derivableGapSet))
	if err != nil {
		t.Fatalf("failed to encode the expected snapshot: %v", err)
	}
	recorder.reset()

	blockchain.chainmu.MustLock()
	_, err = blockchain.writeBlockWithState(block, nil, statedb, nil, nil)
	blockchain.chainmu.Unlock()
	if err != nil {
		t.Fatalf("the insertion of the gap block failed: %v", err)
	}
	if got := blockchain.CurrentBlock().Hash(); got != block.Hash() {
		t.Fatalf("the head is %s after the insertion, want the gap block %s", got, block.Hash())
	}

	recorder.mu.Lock()
	writes, directPuts := recorder.writes, recorder.directPuts
	recorder.mu.Unlock()
	if len(directPuts) != 0 {
		t.Fatalf("the insertion wrote %d key(s) outside a batch: %v", len(directPuts), directPuts)
	}
	carrying := 0
	for _, write := range writes {
		if !containsValue(write.values, blob) {
			continue
		}
		carrying++
		if !containsValue(write.values, block.Hash().Bytes()) {
			t.Fatal("the batch carrying the derived set does not carry the markers of the gap block it belongs to")
		}
	}
	if carrying != 1 {
		t.Fatalf("%d batch(es) carried the derived set, want exactly 1", carrying)
	}
	if stored, err := rawdb.ReadXdposV2Snapshot(recorder.Database, block.Hash()); err != nil || !bytes.Equal(stored, blob) {
		t.Fatalf("the set the gap block stored is not the one derived from its state: err=%v", err)
	}
}

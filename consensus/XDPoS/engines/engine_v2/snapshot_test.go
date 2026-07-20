package engine_v2

import (
	"errors"
	"fmt"
	"math/big"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/common/lru"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS/utils"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/ethdb"
	"github.com/XinFinOrg/XDPoSChain/ethdb/leveldb"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/stretchr/testify/assert"
)

func TestGetMasterNodes(t *testing.T) {
	masterNodes := []common.Address{{0x4}, {0x3}, {0x2}, {0x1}}
	snap := NewSnapshot(1, common.Hash{}, masterNodes)

	for _, address := range masterNodes {
		if _, ok := snap.GetMappedCandidates()[address]; !ok {
			t.Error("should get master node from map", address.Hex(), snap.GetMappedCandidates())
			return
		}
	}
}

// ============================================================================
// Snapshot persistence and recovery tests
// ============================================================================

func TestStoreLoadSnapshot(t *testing.T) {
	snap := NewSnapshot(1, common.Hash{0x1}, nil)
	dir := t.TempDir()
	db, err := leveldb.New(dir, 256, 0, "", false)
	if err != nil {
		panic(fmt.Sprintf("can't create temporary database: %v", err))
	}
	lddb := rawdb.NewDatabase(db)

	err = StoreSnapshot(snap, lddb)
	if err != nil {
		t.Error("store snapshot failed", err)
	}

	restoredSnapshot, err := loadSnapshot(lddb, snap.Hash)
	if err != nil || restoredSnapshot.Hash != snap.Hash {
		t.Error("load snapshot failed", err)
	}
}

type snapshotChainReader struct {
	headersByNumber map[uint64]*types.Header
	headersByHash   map[common.Hash]*types.Header
	blocksByHash    map[common.Hash]*types.Block
	statesByRoot    map[common.Hash]*state.StateDB
	currentHeader   *types.Header
}

func newSnapshotChainReader() *snapshotChainReader {
	return &snapshotChainReader{
		headersByNumber: make(map[uint64]*types.Header),
		headersByHash:   make(map[common.Hash]*types.Header),
		blocksByHash:    make(map[common.Hash]*types.Block),
		statesByRoot:    make(map[common.Hash]*state.StateDB),
	}
}

// addHeader registers a fully imported block: both the canonical header and the
// block body are visible, as they are once insertChain is done with it.
func (m *snapshotChainReader) addHeader(header *types.Header) {
	m.addHeaderOnly(header)
	m.blocksByHash[header.Hash()] = types.NewBlockWithHeader(header)
}

// addHeaderOnly registers a canonical header whose block is not imported yet,
// the state a node is in while headers run ahead of block import.
func (m *snapshotChainReader) addHeaderOnly(header *types.Header) {
	m.headersByNumber[header.Number.Uint64()] = header
	m.headersByHash[header.Hash()] = header
	if m.currentHeader == nil || m.currentHeader.Number.Cmp(header.Number) < 0 {
		m.currentHeader = header
	}
}

func (m *snapshotChainReader) setHead(number uint64) {
	m.currentHeader = &types.Header{Number: new(big.Int).SetUint64(number)}
}

func (m *snapshotChainReader) Config() *params.ChainConfig {
	return nil
}

func (m *snapshotChainReader) CurrentHeader() *types.Header {
	return m.currentHeader
}

func (m *snapshotChainReader) GetHeader(hash common.Hash, number uint64) *types.Header {
	header := m.headersByHash[hash]
	if header == nil || header.Number.Uint64() != number {
		return nil
	}
	return header
}

func (m *snapshotChainReader) GetHeaderByNumber(number uint64) *types.Header {
	return m.headersByNumber[number]
}

func (m *snapshotChainReader) GetHeaderByHash(hash common.Hash) *types.Header {
	return m.headersByHash[hash]
}

func (m *snapshotChainReader) GetBlock(hash common.Hash, number uint64) *types.Block {
	block := m.blocksByHash[hash]
	if block == nil || block.NumberU64() != number {
		return nil
	}
	return block
}

func (m *snapshotChainReader) StateAt(root common.Hash) (*state.StateDB, error) {
	st, ok := m.statesByRoot[root]
	if !ok {
		return nil, errors.New("state not found")
	}
	return st, nil
}

// headerOnlyChainReader is a consensus.ChainReader that deliberately does not
// implement GapStateReader, so snapshot self-healing cannot run.
type headerOnlyChainReader struct {
	inner *snapshotChainReader
}

func (m *headerOnlyChainReader) Config() *params.ChainConfig  { return m.inner.Config() }
func (m *headerOnlyChainReader) CurrentHeader() *types.Header { return m.inner.CurrentHeader() }
func (m *headerOnlyChainReader) GetHeader(hash common.Hash, number uint64) *types.Header {
	return m.inner.GetHeader(hash, number)
}
func (m *headerOnlyChainReader) GetHeaderByNumber(number uint64) *types.Header {
	return m.inner.GetHeaderByNumber(number)
}
func (m *headerOnlyChainReader) GetHeaderByHash(hash common.Hash) *types.Header {
	return m.inner.GetHeaderByHash(hash)
}
func (m *headerOnlyChainReader) GetBlock(hash common.Hash, number uint64) *types.Block {
	return m.inner.GetBlock(hash, number)
}

// testGapNumber is a V2-era gap block number for the config in newTestEngineV2:
// testGapNumber%Epoch == Epoch-Gap and testGapNumber > V2.SwitchBlock.
const testGapNumber = 1350

func newTestEngineV2(db ethdb.Database) *XDPoS_v2 {
	return &XDPoS_v2{
		config: &params.XDPoSConfig{
			Epoch: 900,
			Gap:   450,
			V2: &params.V2{
				SwitchBlock: big.NewInt(450),
			},
		},
		db:             db,
		snapshots:      lru.NewCache[common.Hash, *SnapshotV2](utils.InMemorySnapshots),
		failedRebuilds: lru.NewCache[common.Hash, struct{}](utils.InMemorySnapshots),
	}
}

type countingSnapshotChainReader struct {
	*snapshotChainReader
	hold         chan struct{} // when non-nil, StateAt blocks until it is closed
	stateAtCalls int32
}

func (m *countingSnapshotChainReader) StateAt(root common.Hash) (*state.StateDB, error) {
	atomic.AddInt32(&m.stateAtCalls, 1)
	if m.hold != nil {
		<-m.hold
	}
	return m.snapshotChainReader.StateAt(root)
}

// gatedSnapshotDB signals every database read, which lets a test wait until all
// concurrent getSnapshot callers are past the on-disk snapshot lookup.
type gatedSnapshotDB struct {
	ethdb.Database
	reads chan struct{}
}

func (db *gatedSnapshotDB) Get(key []byte) ([]byte, error) {
	select {
	case db.reads <- struct{}{}:
	default:
	}
	return db.Database.Get(key)
}

func mustBuildStateWithCandidates(t *testing.T, candidates []common.Address, stakes map[common.Address]*big.Int) (common.Hash, *state.StateDB) {
	t.Helper()

	stateDisk := rawdb.NewMemoryDatabase()
	stateDB, err := state.New(types.EmptyRootHash, state.NewDatabase(stateDisk))
	assert.NoError(t, err)

	slotCandidates := common.BigToHash(new(big.Int).SetUint64(8))
	stateDB.SetState(common.MasternodeVotingSMCBinary, slotCandidates, common.BigToHash(new(big.Int).SetUint64(uint64(len(candidates)))))

	for i, addr := range candidates {
		stateDB.SetState(common.MasternodeVotingSMCBinary, state.GetLocDynamicArrAtElement(slotCandidates, uint64(i), 1), common.BytesToHash(addr.Bytes()))

		locValidator := state.GetLocMappingAtKey(addr.Hash(), 1)
		capSlot := common.BigToHash(new(big.Int).Add(locValidator, big.NewInt(1)))
		stateDB.SetState(common.MasternodeVotingSMCBinary, capSlot, common.BigToHash(stakes[addr]))
	}

	root, err := stateDB.Commit(1, false)
	assert.NoError(t, err)
	assert.NoError(t, stateDB.Database().TrieDB().Commit(root, false))

	committedState, err := state.New(root, state.NewDatabase(stateDisk))
	assert.NoError(t, err)
	return root, committedState
}

func TestRebuildSnapshot_ReconstructsAndPersists(t *testing.T) {
	engine := newTestEngineV2(rawdb.NewMemoryDatabase())

	lowStake := common.Address{0x01}
	highStake := common.Address{0x02}
	candidates := []common.Address{lowStake, highStake}
	stakes := map[common.Address]*big.Int{
		lowStake:  big.NewInt(100),
		highStake: big.NewInt(200),
	}
	root, committedState := mustBuildStateWithCandidates(t, candidates, stakes)

	reader := newSnapshotChainReader()
	reader.statesByRoot[root] = committedState

	gapHeader := &types.Header{Number: new(big.Int).SetUint64(testGapNumber), Root: root}
	snap, err := engine.rebuildSnapshot(reader, gapHeader)
	assert.NoError(t, err)
	assert.NotNil(t, snap)
	assert.Equal(t, uint64(testGapNumber), snap.Number)
	assert.Equal(t, gapHeader.Hash(), snap.Hash)
	assert.Equal(t, []common.Address{highStake, lowStake}, snap.NextEpochCandidates)

	persisted, err := loadSnapshot(engine.db, gapHeader.Hash())
	assert.NoError(t, err)
	assert.Equal(t, snap.NextEpochCandidates, persisted.NextEpochCandidates)

	cached, ok := engine.snapshots.Get(gapHeader.Hash())
	assert.True(t, ok)
	assert.Equal(t, snap.NextEpochCandidates, cached.NextEpochCandidates)
}

func TestGetSnapshot_RebuildsWhenSnapshotMissing(t *testing.T) {
	dir := t.TempDir()
	disk, err := leveldb.New(dir, 256, 0, "", false)
	assert.NoError(t, err)

	engine := newTestEngineV2(rawdb.NewDatabase(disk))

	addrA := common.Address{0x0a}
	addrB := common.Address{0x0b}
	candidates := []common.Address{addrA, addrB}
	stakes := map[common.Address]*big.Int{
		addrA: big.NewInt(15),
		addrB: big.NewInt(30),
	}
	root, committedState := mustBuildStateWithCandidates(t, candidates, stakes)

	header := &types.Header{Number: new(big.Int).SetUint64(testGapNumber), Root: root}
	reader := newSnapshotChainReader()
	reader.addHeader(header)
	reader.statesByRoot[root] = committedState

	_, err = loadSnapshot(engine.db, header.Hash())
	assert.Error(t, err)

	snap, err := engine.getSnapshot(reader, testGapNumber, true)
	assert.NoError(t, err)
	assert.NotNil(t, snap)
	assert.Equal(t, header.Hash(), snap.Hash)
	assert.Equal(t, uint64(testGapNumber), snap.Number)
	assert.Equal(t, []common.Address{addrB, addrA}, snap.NextEpochCandidates)

	persisted, err := loadSnapshot(engine.db, header.Hash())
	assert.NoError(t, err)
	assert.Equal(t, snap.NextEpochCandidates, persisted.NextEpochCandidates)
}

func TestGetSnapshot_SingleflightDeduplicatesRebuild(t *testing.T) {
	const workers = 12

	gated := &gatedSnapshotDB{Database: rawdb.NewMemoryDatabase(), reads: make(chan struct{}, workers)}
	engine := newTestEngineV2(gated)

	addrA := common.Address{0x11}
	addrB := common.Address{0x22}
	candidates := []common.Address{addrA, addrB}
	stakes := map[common.Address]*big.Int{
		addrA: big.NewInt(40),
		addrB: big.NewInt(80),
	}
	root, committedState := mustBuildStateWithCandidates(t, candidates, stakes)

	header := &types.Header{Number: new(big.Int).SetUint64(testGapNumber), Root: root}
	baseReader := newSnapshotChainReader()
	baseReader.addHeader(header)
	baseReader.statesByRoot[root] = committedState

	reader := &countingSnapshotChainReader{
		snapshotChainReader: baseReader,
		hold:                make(chan struct{}),
	}

	results := make(chan *SnapshotV2, workers)
	errorsCh := make(chan error, workers)

	var wg sync.WaitGroup
	wg.Add(workers)
	for range workers {
		go func() {
			defer wg.Done()
			snap, err := engine.getSnapshot(reader, testGapNumber, true)
			if err != nil {
				errorsCh <- err
				return
			}
			results <- snap
		}()
	}

	// Wait until every worker has missed the on-disk snapshot, so none of them
	// can short-circuit on the cache once the rebuild completes.
	for range workers {
		<-gated.reads
	}
	close(reader.hold)

	wg.Wait()
	close(results)
	close(errorsCh)

	for err := range errorsCh {
		assert.NoError(t, err)
	}

	for snap := range results {
		assert.NotNil(t, snap)
		assert.Equal(t, header.Hash(), snap.Hash)
		assert.Equal(t, uint64(testGapNumber), snap.Number)
		assert.Equal(t, []common.Address{addrB, addrA}, snap.NextEpochCandidates)
	}

	assert.Equal(t, int32(1), atomic.LoadInt32(&reader.stateAtCalls), "singleflight should deduplicate concurrent rebuilds")
}

func TestGetSnapshot_SkipsRebuildAtOrBeforeSwitchBlock(t *testing.T) {
	engine := newTestEngineV2(rawdb.NewMemoryDatabase())

	root, committedState := mustBuildStateWithCandidates(t, []common.Address{{0x01}}, map[common.Address]*big.Int{{0x01}: big.NewInt(10)})

	// SwitchBlock is 450 in the test config, and 450 is a gap number: its
	// snapshot comes from Initial(), never from the state trie.
	header := &types.Header{Number: new(big.Int).SetUint64(450), Root: root}
	baseReader := newSnapshotChainReader()
	baseReader.addHeader(header)
	baseReader.statesByRoot[root] = committedState
	reader := &countingSnapshotChainReader{snapshotChainReader: baseReader}

	snap, err := engine.getSnapshot(reader, 450, true)
	assert.Error(t, err)
	assert.Nil(t, snap)
	assert.Zero(t, atomic.LoadInt32(&reader.stateAtCalls))
}

// TestRebuildSnapshot_EqualStakeOrdering locks in the order that equal-stake
// candidates get: the comparator is not a strict weak ordering, so a different
// sort implementation would produce a different masternode set and fork.
func TestRebuildSnapshot_EqualStakeOrdering(t *testing.T) {
	engine := newTestEngineV2(rawdb.NewMemoryDatabase())

	addrA := common.Address{0x01}
	addrB := common.Address{0x02}
	addrC := common.Address{0x03}
	candidates := []common.Address{addrA, addrB, addrC}
	stakes := map[common.Address]*big.Int{
		addrA: big.NewInt(100),
		addrB: big.NewInt(100),
		addrC: big.NewInt(100),
	}
	root, committedState := mustBuildStateWithCandidates(t, candidates, stakes)

	reader := newSnapshotChainReader()
	reader.statesByRoot[root] = committedState
	reader.setHead(testGapNumber)

	snap, err := engine.rebuildSnapshot(reader, &types.Header{Number: new(big.Int).SetUint64(testGapNumber), Root: root})
	assert.NoError(t, err)
	assert.Equal(t, []common.Address{addrC, addrB, addrA}, snap.NextEpochCandidates)
}

func TestGetSnapshot_SkipsRebuildFarBehindHead(t *testing.T) {
	engine := newTestEngineV2(rawdb.NewMemoryDatabase())

	root, committedState := mustBuildStateWithCandidates(t, []common.Address{{0x01}}, map[common.Address]*big.Int{{0x01}: big.NewInt(10)})

	header := &types.Header{Number: new(big.Int).SetUint64(testGapNumber), Root: root}
	baseReader := newSnapshotChainReader()
	baseReader.addHeader(header)
	baseReader.statesByRoot[root] = committedState
	// More than snapshotRebuildMaxEpochsBehind epochs past the gap block: an
	// unauthenticated message must not be able to walk old state tries.
	baseReader.setHead(testGapNumber + snapshotRebuildMaxEpochsBehind*engine.config.Epoch + 1)
	reader := &countingSnapshotChainReader{snapshotChainReader: baseReader}

	snap, err := engine.getSnapshot(reader, testGapNumber, true)
	assert.Error(t, err)
	assert.Nil(t, snap)
	assert.Zero(t, atomic.LoadInt32(&reader.stateAtCalls))
}

func TestGetSnapshot_SkipsRebuildForNonGapNumber(t *testing.T) {
	engine := newTestEngineV2(rawdb.NewMemoryDatabase())

	root, committedState := mustBuildStateWithCandidates(t, []common.Address{{0x01}}, map[common.Address]*big.Int{{0x01}: big.NewInt(10)})

	// A vote/timeout message can carry any gap number, so a number that is not a
	// gap block must never reach the state trie or persist a snapshot.
	const nonGapNumber = testGapNumber + 1
	header := &types.Header{Number: new(big.Int).SetUint64(nonGapNumber), Root: root}
	baseReader := newSnapshotChainReader()
	baseReader.addHeader(header)
	baseReader.statesByRoot[root] = committedState
	reader := &countingSnapshotChainReader{snapshotChainReader: baseReader}

	snap, err := engine.getSnapshot(reader, nonGapNumber, true)
	assert.Error(t, err)
	assert.Nil(t, snap)
	assert.Zero(t, atomic.LoadInt32(&reader.stateAtCalls))

	_, err = loadSnapshot(engine.db, header.Hash())
	assert.Error(t, err)
}

func TestGetSnapshot_SkipsRebuildWhenChainCannotReadState(t *testing.T) {
	engine := newTestEngineV2(rawdb.NewMemoryDatabase())

	root, committedState := mustBuildStateWithCandidates(t, []common.Address{{0x01}}, map[common.Address]*big.Int{{0x01}: big.NewInt(10)})

	header := &types.Header{Number: new(big.Int).SetUint64(testGapNumber), Root: root}
	baseReader := newSnapshotChainReader()
	baseReader.addHeader(header)
	baseReader.statesByRoot[root] = committedState

	snap, err := engine.getSnapshot(&headerOnlyChainReader{inner: baseReader}, testGapNumber, true)
	assert.Error(t, err)
	assert.Nil(t, snap)

	_, err = loadSnapshot(engine.db, header.Hash())
	assert.Error(t, err)
}

func TestGetSnapshot_SkipsRebuildWhenBlockNotImported(t *testing.T) {
	engine := newTestEngineV2(rawdb.NewMemoryDatabase())

	root, committedState := mustBuildStateWithCandidates(t, []common.Address{{0x01}}, map[common.Address]*big.Int{{0x01}: big.NewInt(10)})

	// Canonical header only: the block body has not been imported yet, so the
	// missing state is transient and must not be recorded as a failed rebuild.
	header := &types.Header{Number: new(big.Int).SetUint64(testGapNumber), Root: root}
	baseReader := newSnapshotChainReader()
	baseReader.addHeaderOnly(header)
	baseReader.statesByRoot[root] = committedState
	reader := &countingSnapshotChainReader{snapshotChainReader: baseReader}

	snap, err := engine.getSnapshot(reader, testGapNumber, true)
	assert.Error(t, err)
	assert.Nil(t, snap)
	assert.Zero(t, atomic.LoadInt32(&reader.stateAtCalls))

	_, failed := engine.failedRebuilds.Get(header.Hash())
	assert.False(t, failed)

	// Once the block lands, the rebuild runs.
	baseReader.addHeader(header)
	snap, err = engine.getSnapshot(reader, testGapNumber, true)
	assert.NoError(t, err)
	assert.Equal(t, []common.Address{{0x01}}, snap.NextEpochCandidates)
}

func TestGetSnapshot_GivesUpAfterFailedRebuild(t *testing.T) {
	engine := newTestEngineV2(rawdb.NewMemoryDatabase())

	// No state registered for the header root: the gap block is imported but its
	// trie is pruned, so the rebuild can never succeed.
	header := &types.Header{Number: new(big.Int).SetUint64(testGapNumber), Root: common.Hash{0xaa}}
	baseReader := newSnapshotChainReader()
	baseReader.addHeader(header)
	reader := &countingSnapshotChainReader{snapshotChainReader: baseReader}

	_, err := engine.getSnapshot(reader, testGapNumber, true)
	assert.Error(t, err)
	assert.Equal(t, int32(1), atomic.LoadInt32(&reader.stateAtCalls))

	_, err = engine.getSnapshot(reader, testGapNumber, true)
	assert.Error(t, err)
	assert.Equal(t, int32(1), atomic.LoadInt32(&reader.stateAtCalls), "failed rebuild should not be retried")

	_, err = loadSnapshot(engine.db, header.Hash())
	assert.Error(t, err)
}

func TestRebuildSnapshot_NoCandidatesDoesNotPersist(t *testing.T) {
	engine := newTestEngineV2(rawdb.NewMemoryDatabase())

	root, committedState := mustBuildStateWithCandidates(t, nil, nil)

	reader := newSnapshotChainReader()
	reader.statesByRoot[root] = committedState

	gapHeader := &types.Header{Number: new(big.Int).SetUint64(testGapNumber), Root: root}
	snap, err := engine.rebuildSnapshot(reader, gapHeader)
	assert.Error(t, err)
	assert.Nil(t, snap)

	_, err = loadSnapshot(engine.db, gapHeader.Hash())
	assert.Error(t, err)
}

func TestGetSnapshot_SkipsRebuildWhenSnapshotExists(t *testing.T) {
	engine := newTestEngineV2(rawdb.NewMemoryDatabase())

	root, committedState := mustBuildStateWithCandidates(t, []common.Address{{0x01}}, map[common.Address]*big.Int{{0x01}: big.NewInt(10)})

	header := &types.Header{Number: new(big.Int).SetUint64(testGapNumber), Root: root}
	baseReader := newSnapshotChainReader()
	baseReader.addHeader(header)
	baseReader.statesByRoot[root] = committedState
	reader := &countingSnapshotChainReader{snapshotChainReader: baseReader}

	// A snapshot that exists but cannot be decoded must not be replaced by a
	// state-derived rebuild: the stored masternode set may be the correct one.
	stored := []byte("not a snapshot")
	assert.NoError(t, rawdb.WriteXdposV2Snapshot(engine.db, header.Hash(), stored))

	snap, err := engine.getSnapshot(reader, testGapNumber, true)
	assert.Error(t, err)
	assert.Nil(t, snap)
	assert.Zero(t, atomic.LoadInt32(&reader.stateAtCalls))

	blob, err := rawdb.ReadXdposV2Snapshot(engine.db, header.Hash())
	assert.NoError(t, err)
	assert.Equal(t, stored, blob)
}

// raceSnapshotDB persists a snapshot right after the first failed read, which
// reproduces another caller storing it in the window between the getSnapshot
// lookup and the self-heal path.
type raceSnapshotDB struct {
	ethdb.Database
	once sync.Once
	snap *SnapshotV2
}

func (db *raceSnapshotDB) Get(key []byte) ([]byte, error) {
	data, err := db.Database.Get(key)
	if err != nil {
		db.once.Do(func() {
			if storeErr := StoreSnapshot(db.snap, db.Database); storeErr != nil {
				panic(storeErr)
			}
		})
	}
	return data, err
}

func TestGetSnapshot_ReturnsSnapshotStoredWhileHealing(t *testing.T) {
	root, committedState := mustBuildStateWithCandidates(t, []common.Address{{0x01}}, map[common.Address]*big.Int{{0x01}: big.NewInt(10)})

	header := &types.Header{Number: new(big.Int).SetUint64(testGapNumber), Root: root}
	// Deliberately different from what the state would yield, so the assertions
	// tell a reload apart from a rebuild.
	stored := NewSnapshot(testGapNumber, header.Hash(), []common.Address{{0xfe}})

	engine := newTestEngineV2(&raceSnapshotDB{Database: rawdb.NewMemoryDatabase(), snap: stored})

	baseReader := newSnapshotChainReader()
	baseReader.addHeader(header)
	baseReader.statesByRoot[root] = committedState
	reader := &countingSnapshotChainReader{snapshotChainReader: baseReader}

	snap, err := engine.getSnapshot(reader, testGapNumber, true)
	assert.NoError(t, err)
	assert.Equal(t, stored.NextEpochCandidates, snap.NextEpochCandidates)
	assert.Zero(t, atomic.LoadInt32(&reader.stateAtCalls))
}

package engine_v2

import (
	"errors"
	"fmt"
	"math/big"
	"sync/atomic"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/common/lru"
	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS/utils"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/ethdb"
	"github.com/XinFinOrg/XDPoSChain/ethdb/leveldb"
	"github.com/XinFinOrg/XDPoSChain/params"
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

const (
	testRepairEpoch = uint64(900)
	testRepairGap   = uint64(450)
	// testRepairSwitchBlock is aligned to the epoch (SwitchBlock % Epoch == 0),
	// matching the alignment that production chain config validation enforces.
	testRepairSwitchBlock = uint64(900)
)

// newCandidateState returns a state holding the masternode voting contract
// storage that BuildSnapshotFromState reads, with candidates in the given order.
func newCandidateState(t *testing.T, candidates []common.Address, caps []*big.Int) *state.StateDB {
	t.Helper()
	statedb, err := state.New(types.EmptyRootHash, state.NewDatabase(rawdb.NewMemoryDatabase()))
	if err != nil {
		t.Fatalf("create state: %v", err)
	}
	slotHash := common.BigToHash(new(big.Int).SetUint64(8)) // slotValidatorMapping["candidates"]
	statedb.SetState(common.MasternodeVotingSMCBinary, slotHash, common.BigToHash(new(big.Int).SetUint64(uint64(len(candidates)))))
	for i, candidate := range candidates {
		statedb.SetState(common.MasternodeVotingSMCBinary, state.GetLocDynamicArrAtElement(slotHash, uint64(i), 1), candidate.Hash())
		if candidate.IsZero() {
			continue
		}
		locCap := new(big.Int).Add(state.GetLocMappingAtKey(candidate.Hash(), 1), big.NewInt(1))
		statedb.SetState(common.MasternodeVotingSMCBinary, common.BigToHash(locCap), common.BigToHash(caps[i]))
	}
	return statedb
}

// repairTestChain is a minimal GapStateReader over a handful of headers.
type repairTestChain struct {
	headers    map[uint64]*types.Header
	head       *types.Header
	db         ethdb.Database
	stateErr   error
	stateCalls int
	statedb    *state.StateDB
}

func (c *repairTestChain) addHeader(header *types.Header) {
	if c.headers == nil {
		c.headers = make(map[uint64]*types.Header)
	}
	c.headers[header.Number.Uint64()] = header
	if c.head == nil || header.Number.Uint64() > c.head.Number.Uint64() {
		c.head = header
	}
}

func (c *repairTestChain) Config() *params.ChainConfig  { return nil }
func (c *repairTestChain) ChainDb() ethdb.Database      { return c.db }
func (c *repairTestChain) CurrentHeader() *types.Header { return c.head }
func (c *repairTestChain) GetHeaderByNumber(number uint64) *types.Header {
	return c.headers[number]
}
func (c *repairTestChain) GetHeader(common.Hash, uint64) *types.Header { return nil }
func (c *repairTestChain) GetHeaderByHash(common.Hash) *types.Header   { return nil }
func (c *repairTestChain) GetBlock(common.Hash, uint64) *types.Block   { return nil }

func (c *repairTestChain) StateAt(common.Hash) (*state.StateDB, error) {
	c.stateCalls++
	if c.stateErr != nil {
		return nil, c.stateErr
	}
	return c.statedb, nil
}

// failingHasDB wraps a database and fails every Has probe, simulating an I/O
// error while checking whether a snapshot exists.
type failingHasDB struct {
	ethdb.Database
}

func (db *failingHasDB) Has([]byte) (bool, error) {
	return false, errors.New("simulated Has probe failure")
}

func newRepairEngine(db ethdb.Database) *XDPoS_v2 {
	return &XDPoS_v2{
		config: &params.XDPoSConfig{
			Epoch: testRepairEpoch,
			Gap:   testRepairGap,
			V2: &params.V2{
				SwitchBlock: new(big.Int).SetUint64(testRepairSwitchBlock),
			},
		},
		db:        db,
		snapshots: lru.NewCache[common.Hash, *SnapshotV2](utils.InMemorySnapshots),
	}
}

// newRepairFixture wires an engine and a chain whose head is at headNumber, with
// gap block headers present for every gap number at or below it.
func newRepairFixture(t *testing.T, headNumber uint64, candidates []common.Address, caps []*big.Int) (*XDPoS_v2, *repairTestChain, ethdb.Database) {
	t.Helper()
	db := rawdb.NewMemoryDatabase()
	x := newRepairEngine(db)
	chain := &repairTestChain{db: db, statedb: newCandidateState(t, candidates, caps)}
	for num := testRepairEpoch - testRepairGap; num <= headNumber; num += testRepairEpoch {
		chain.addHeader(&types.Header{Number: new(big.Int).SetUint64(num), Extra: []byte{byte(num), byte(num >> 8)}})
	}
	chain.addHeader(&types.Header{Number: new(big.Int).SetUint64(headNumber), Extra: []byte("head")})
	return x, chain, db
}

func gapHash(t *testing.T, chain *repairTestChain, number uint64) common.Hash {
	t.Helper()
	header := chain.GetHeaderByNumber(number)
	if header == nil {
		t.Fatalf("no header at %d", number)
	}
	return header.Hash()
}

func assertSnapshotStored(t *testing.T, db ethdb.Database, hash common.Hash, want []common.Address) {
	t.Helper()
	snap, err := loadSnapshot(db, hash)
	if err != nil {
		t.Fatalf("load snapshot: %v", err)
	}
	if len(snap.NextEpochCandidates) != len(want) {
		t.Fatalf("candidates = %v, want %v", snap.NextEpochCandidates, want)
	}
	for i, addr := range want {
		if snap.NextEpochCandidates[i] != addr {
			t.Fatalf("candidates = %v, want %v", snap.NextEpochCandidates, want)
		}
	}
}

func TestBuildSnapshotFromStateSortsByStakeDescending(t *testing.T) {
	low, mid, high := common.Address{0x1}, common.Address{0x2}, common.Address{0x3}
	statedb := newCandidateState(t,
		[]common.Address{low, mid, high},
		[]*big.Int{big.NewInt(10), big.NewInt(20), big.NewInt(30)},
	)

	snap, err := BuildSnapshotFromState(statedb, 1350, common.Hash{0xaa})
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	want := []common.Address{high, mid, low}
	for i, addr := range want {
		if snap.NextEpochCandidates[i] != addr {
			t.Fatalf("candidates = %v, want %v", snap.NextEpochCandidates, want)
		}
	}
	if snap.Number != 1350 || snap.Hash != (common.Hash{0xaa}) {
		t.Fatalf("snapshot = (%d, %s), want (1350, 0xaa..)", snap.Number, snap.Hash.Hex())
	}
}

// Equal stakes must keep the exact order xdc_sort produces, otherwise nodes
// derive different masternode sets from the same state. A failure here means
// the sort implementation drifted and the derivation no longer matches
// core.BlockChain.UpdateM1.
func TestBuildSnapshotFromStateEqualStakeOrder(t *testing.T) {
	a, b, c := common.Address{0x1}, common.Address{0x2}, common.Address{0x3}
	statedb := newCandidateState(t,
		[]common.Address{a, b, c},
		[]*big.Int{big.NewInt(10), big.NewInt(10), big.NewInt(10)},
	)

	snap, err := BuildSnapshotFromState(statedb, 1350, common.Hash{0xaa})
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	want := []common.Address{c, b, a}
	for i, addr := range want {
		if snap.NextEpochCandidates[i] != addr {
			t.Fatalf("candidates = %v, want %v", snap.NextEpochCandidates, want)
		}
	}
}

// The quicksort path of the vendored xdc_sort (more than 12 elements) yields a
// different equal-stake order than the insertion path pinned above; pin that
// artifact too, so a drift in the sort implementation is caught for large
// candidate sets as well.
func TestBuildSnapshotFromStateEqualStakeOrderLarge(t *testing.T) {
	const n = 15
	candidates := make([]common.Address, n)
	caps := make([]*big.Int, n)
	for i := range n {
		candidates[i] = common.Address{byte(i + 1)}
		caps[i] = big.NewInt(10)
	}
	statedb := newCandidateState(t, candidates, caps)

	snap, err := BuildSnapshotFromState(statedb, 1350, common.Hash{0xaa})
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	want := []common.Address{
		{5}, {4}, {3}, {2}, {12}, {6}, {11}, {10}, {9}, {15}, {13}, {14}, {7}, {1}, {8},
	}
	if len(snap.NextEpochCandidates) != len(want) {
		t.Fatalf("candidates = %v, want %v", snap.NextEpochCandidates, want)
	}
	for i, addr := range want {
		if snap.NextEpochCandidates[i] != addr {
			t.Fatalf("candidates = %v, want %v", snap.NextEpochCandidates, want)
		}
	}
}

func TestBuildSnapshotFromStateSkipsZeroCandidates(t *testing.T) {
	real := common.Address{0x1}
	statedb := newCandidateState(t,
		[]common.Address{{}, real},
		[]*big.Int{big.NewInt(0), big.NewInt(10)},
	)

	snap, err := BuildSnapshotFromState(statedb, 1350, common.Hash{0xaa})
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	if len(snap.NextEpochCandidates) != 1 || snap.NextEpochCandidates[0] != real {
		t.Fatalf("candidates = %v, want [%s]", snap.NextEpochCandidates, real.Hex())
	}
}

func TestBuildSnapshotFromStateRejectsEmptyCandidates(t *testing.T) {
	statedb := newCandidateState(t, nil, nil)

	if _, err := BuildSnapshotFromState(statedb, 1350, common.Hash{0xaa}); !errors.Is(err, ErrNoCandidates) {
		t.Fatalf("err = %v, want ErrNoCandidates", err)
	}
}

// failingReadDB fails every read once armed, simulating a database whose trie
// nodes are unreadable (partially pruned or corrupt voting contract storage).
type failingReadDB struct {
	ethdb.Database
	fail atomic.Bool
}

func (db *failingReadDB) Get(key []byte) ([]byte, error) {
	if db.fail.Load() {
		return nil, errors.New("simulated trie read failure")
	}
	return db.Database.Get(key)
}

func (db *failingReadDB) Has(key []byte) (bool, error) {
	if db.fail.Load() {
		return false, errors.New("simulated trie read failure")
	}
	return db.Database.Has(key)
}

// TestBuildSnapshotFromStateReturnsStateReadError proves that a state whose
// voting contract storage cannot be read yields the recorded StateDB error
// instead of a candidate set that is empty (or worse, non-empty but partial),
// which would be persisted as a valid snapshot and permanently mask the hole.
func TestBuildSnapshotFromStateReturnsStateReadError(t *testing.T) {
	disk := rawdb.NewMemoryDatabase()
	statedb, err := state.New(types.EmptyRootHash, state.NewDatabase(disk))
	if err != nil {
		t.Fatalf("create state: %v", err)
	}
	candidates := []common.Address{{0x4}, {0x3}}
	caps := []*big.Int{big.NewInt(5), big.NewInt(3)}
	slotHash := common.BigToHash(new(big.Int).SetUint64(8)) // slotValidatorMapping["candidates"]
	statedb.SetState(common.MasternodeVotingSMCBinary, slotHash, common.BigToHash(new(big.Int).SetUint64(uint64(len(candidates)))))
	for i, candidate := range candidates {
		statedb.SetState(common.MasternodeVotingSMCBinary, state.GetLocDynamicArrAtElement(slotHash, uint64(i), 1), candidate.Hash())
		locCap := new(big.Int).Add(state.GetLocMappingAtKey(candidate.Hash(), 1), big.NewInt(1))
		statedb.SetState(common.MasternodeVotingSMCBinary, common.BigToHash(locCap), common.BigToHash(caps[i]))
	}
	root, err := statedb.Commit(0, false)
	if err != nil {
		t.Fatalf("commit state: %v", err)
	}
	if err := statedb.Database().TrieDB().Commit(root, false); err != nil {
		t.Fatalf("persist state: %v", err)
	}

	// Reopen the committed state over a database whose reads will fail.
	db := &failingReadDB{Database: disk}
	statedb, err = state.New(root, state.NewDatabase(db))
	if err != nil {
		t.Fatalf("reopen state: %v", err)
	}
	db.fail.Store(true)

	snap, err := BuildSnapshotFromState(statedb, 1350, common.Hash{0xaa})
	if err == nil {
		t.Fatal("err = nil, want the recorded state read error")
	}
	if errors.Is(err, ErrNoCandidates) {
		t.Fatalf("state read error was masked as empty candidates: %v", err)
	}
	if snap != nil {
		t.Fatalf("snapshot = %+v, want nil", snap)
	}
}

func TestRepairGapCandidates(t *testing.T) {
	x := newRepairEngine(rawdb.NewMemoryDatabase())
	// Gap block G=1350 backs heads in [1800, 2700); it must stay a candidate
	// across that whole span plus the margin on either side.
	tests := []struct {
		head uint64
		want []uint64
	}{
		{head: 0, want: nil},
		{head: 449, want: nil},
		{head: 450, want: []uint64{450}},
		{head: 1350, want: []uint64{450, 1350}},
		{head: 1799, want: []uint64{450, 1350}},
		{head: 1800, want: []uint64{450, 1350}},
		{head: 2250, want: []uint64{1350, 2250}},
		{head: 2699, want: []uint64{1350, 2250}},
		{head: 3150, want: []uint64{2250, 3150}},
	}
	for _, tt := range tests {
		got := x.repairGapCandidates(tt.head)
		if len(got) != len(tt.want) {
			t.Fatalf("head %d: got %v, want %v", tt.head, got, tt.want)
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Fatalf("head %d: got %v, want %v", tt.head, got, tt.want)
			}
		}
	}
}

// Invalid schedules must yield no candidates. In particular, with gap == 0 the
// offset math would target epoch-switch blocks, whose snapshots are owned by
// the epoch transition, not by this repair.
func TestRepairGapCandidatesInvalidSchedule(t *testing.T) {
	tests := []struct {
		name  string
		epoch uint64
		gap   uint64
		head  uint64
	}{
		{name: "zero epoch", epoch: 0, gap: 0, head: 1800},
		{name: "zero gap", epoch: 900, gap: 0, head: 1800},
		{name: "gap equals epoch", epoch: 900, gap: 900, head: 1800},
		{name: "gap exceeds epoch", epoch: 900, gap: 1200, head: 1800},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			x := newRepairEngine(rawdb.NewMemoryDatabase())
			x.config.Epoch = tt.epoch
			x.config.Gap = tt.gap
			if got := x.repairGapCandidates(tt.head); got != nil {
				t.Fatalf("repairGapCandidates(%d) = %v, want nil", tt.head, got)
			}
		})
	}
}

func TestRepairGapSnapshotsHeadIsGapBlock(t *testing.T) {
	candidate := common.Address{0x1}
	x, chain, db := newRepairFixture(t, 1350, []common.Address{candidate}, []*big.Int{big.NewInt(10)})

	x.RepairGapSnapshots(chain)

	assertSnapshotStored(t, db, gapHash(t, chain, 1350), []common.Address{candidate})
}

// A node that kept importing past the gap block and only restarted later must
// still have its missing snapshot repaired.
func TestRepairGapSnapshotsHeadPastGapBlock(t *testing.T) {
	candidate := common.Address{0x1}
	x, chain, db := newRepairFixture(t, 1799, []common.Address{candidate}, []*big.Int{big.NewInt(10)})

	x.RepairGapSnapshots(chain)

	assertSnapshotStored(t, db, gapHash(t, chain, 1350), []common.Address{candidate})
}

func TestRepairGapSnapshotsChecksBothCandidates(t *testing.T) {
	candidate := common.Address{0x1}
	x, chain, db := newRepairFixture(t, 2400, []common.Address{candidate}, []*big.Int{big.NewInt(10)})

	x.RepairGapSnapshots(chain)

	for _, gapNum := range []uint64{1350, 2250} {
		assertSnapshotStored(t, db, gapHash(t, chain, gapNum), []common.Address{candidate})
	}
}

// A stored snapshot may come from the reorg path and disagree with the state
// derived one, so it must never be overwritten.
func TestRepairGapSnapshotsKeepsStoredSnapshot(t *testing.T) {
	stored := common.Address{0x9}
	x, chain, db := newRepairFixture(t, 1350, []common.Address{{0x1}}, []*big.Int{big.NewInt(10)})
	if err := StoreSnapshot(NewSnapshot(1350, gapHash(t, chain, 1350), []common.Address{stored}), db); err != nil {
		t.Fatalf("store snapshot: %v", err)
	}

	x.RepairGapSnapshots(chain)

	assertSnapshotStored(t, db, gapHash(t, chain, 1350), []common.Address{stored})
	if chain.stateCalls != 0 {
		t.Fatalf("stateCalls = %d, want 0", chain.stateCalls)
	}
}

func TestRepairGapSnapshotsSkipsMissingState(t *testing.T) {
	x, chain, db := newRepairFixture(t, 1350, []common.Address{{0x1}}, []*big.Int{big.NewInt(10)})
	chain.stateErr = errors.New("missing trie node")

	x.RepairGapSnapshots(chain)

	if _, err := loadSnapshot(db, gapHash(t, chain, 1350)); err == nil {
		t.Fatal("snapshot was stored despite unavailable state")
	}
}

func TestRepairGapSnapshotsSkipsSwitchBlockGap(t *testing.T) {
	x, chain, db := newRepairFixture(t, 450, []common.Address{{0x1}}, []*big.Int{big.NewInt(10)})

	x.RepairGapSnapshots(chain)

	if _, err := loadSnapshot(db, gapHash(t, chain, 450)); err == nil {
		t.Fatal("snapshot at V2 switch block gap should be left to initial()")
	}
	if chain.stateCalls != 0 {
		t.Fatalf("stateCalls = %d, want 0", chain.stateCalls)
	}
}

func TestRepairGapSnapshotsBeforeFirstGap(t *testing.T) {
	x := newRepairEngine(rawdb.NewMemoryDatabase())
	chain := &repairTestChain{}
	chain.addHeader(&types.Header{Number: big.NewInt(100)})

	x.RepairGapSnapshots(chain)

	if chain.stateCalls != 0 {
		t.Fatalf("stateCalls = %d, want 0", chain.stateCalls)
	}
}

// Initial runs the repair through the GapStateReader assertion, without
// requiring a fully initialized engine or a decodable v2 header.
func TestInitialRunsRepair(t *testing.T) {
	candidate := common.Address{0x1}
	x, chain, db := newRepairFixture(t, 1350, []common.Address{candidate}, []*big.Int{big.NewInt(10)})
	// Pretend the engine is already initialized so initial() returns early
	// instead of decoding a real v2 header.
	x.highestQuorumCert = &types.QuorumCert{ProposedBlockInfo: &types.BlockInfo{Hash: common.Hash{0x1}}}

	if err := x.Initial(chain, chain.head); err != nil {
		t.Fatalf("Initial() = %v, want nil", err)
	}
	assertSnapshotStored(t, db, gapHash(t, chain, 1350), []common.Address{candidate})
}

// Initial must skip the repair for chain readers that cannot open historical
// state; only *core.BlockChain implements GapStateReader.
func TestInitialSkipsRepairWithoutStateReader(t *testing.T) {
	x, chain, _ := newRepairFixture(t, 1350, []common.Address{{0x1}}, []*big.Int{big.NewInt(10)})
	x.highestQuorumCert = &types.QuorumCert{ProposedBlockInfo: &types.BlockInfo{Hash: common.Hash{0x1}}}
	plain := struct{ consensus.ChainReader }{chain}

	if err := x.Initial(plain, chain.head); err != nil {
		t.Fatalf("Initial() = %v, want nil", err)
	}
	if chain.stateCalls != 0 {
		t.Fatalf("stateCalls = %d, want 0", chain.stateCalls)
	}
}

// A Has probe that cannot determine whether a snapshot exists must skip the
// repair: an I/O error must never overwrite a masternode set persisted through
// a reorg.
func TestRepairGapSnapshotsSkipsHasProbeError(t *testing.T) {
	x, chain, db := newRepairFixture(t, 1350, []common.Address{{0x1}}, []*big.Int{big.NewInt(10)})
	chain.db = &failingHasDB{Database: db}

	x.RepairGapSnapshots(chain)

	if _, err := loadSnapshot(db, gapHash(t, chain, 1350)); err == nil {
		t.Fatal("snapshot was stored despite a failed Has probe")
	}
	if chain.stateCalls != 0 {
		t.Fatalf("stateCalls = %d, want 0", chain.stateCalls)
	}
}

// An empty derived snapshot must not be stored: it would load back fine and
// permanently mask the missing masternode list.
func TestRepairGapSnapshotsSkipsEmptyCandidates(t *testing.T) {
	x, chain, db := newRepairFixture(t, 1350, nil, nil)

	x.RepairGapSnapshots(chain)

	if _, err := loadSnapshot(db, gapHash(t, chain, 1350)); err == nil {
		t.Fatal("snapshot was stored despite no candidates in state")
	}
	if chain.stateCalls != 1 {
		t.Fatalf("stateCalls = %d, want 1", chain.stateCalls)
	}
}

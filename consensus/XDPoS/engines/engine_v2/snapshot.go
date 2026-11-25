package engine_v2

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS/utils"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/ethdb"
	"github.com/XinFinOrg/XDPoSChain/log"
)

// Snapshot is the state of the smart contract validator list
// The validator list is used on next epoch candidates nodes
// If we don't have the snapshot, then we have to trace back the gap block smart contract state which is very costly
type SnapshotV2 struct {
	Number uint64      `json:"number"` // Block number where the snapshot was created
	Hash   common.Hash `json:"hash"`   // Block hash where the snapshot was created

	// candidates will get assigned on updateM1
	// NOTE: must keep JSON tag "masterNodes", ref: PR #517
	NextEpochCandidates []common.Address `json:"masterNodes"` // Set of authorized candidates nodes at this moment for next epoch

	// NextEpochPenalties is only used by subnets, which compute the penalties
	// of the next epoch at the gap block. See subnet.go.
	NextEpochPenalties []common.Address `json:"penalties,omitempty"`
}

// NewSnapshot creates a new snapshot for next epoch to use
func NewSnapshot(number uint64, hash common.Hash, candidates []common.Address) *SnapshotV2 {
	snap := &SnapshotV2{
		Number:              number,
		Hash:                hash,
		NextEpochCandidates: candidates,
	}
	return snap
}

// errUnusableSnapshot marks a stored snapshot that cannot be served: it either
// does not decode or carries no candidates.
var errUnusableSnapshot = errors.New("unusable gap snapshot")

// loadSnapshot loads an existing snapshot from the database.
func loadSnapshot(db ethdb.Database, hash common.Hash) (*SnapshotV2, error) {
	blob, err := rawdb.ReadXdposV2Snapshot(db, hash)
	if err != nil {
		return nil, err
	}
	snap := new(SnapshotV2)
	if err := json.Unmarshal(blob, snap); err != nil {
		return nil, fmt.Errorf("%w: %w", errUnusableSnapshot, err)
	}
	if len(snap.NextEpochCandidates) == 0 {
		return nil, fmt.Errorf("%w: no candidates for gap block %s", errUnusableSnapshot, hash.Hex())
	}

	return snap, nil
}

// LoadSnapshot loads the stored gap snapshot of a block hash. A record that cannot be served
// is reported as an error for which IsUnusableSnapshot reports true.
func LoadSnapshot(db ethdb.Database, hash common.Hash) (*SnapshotV2, error) {
	return loadSnapshot(db, hash)
}

// IsUnusableSnapshot reports whether err marks a stored snapshot that cannot be served.
func IsUnusableSnapshot(err error) bool { return errors.Is(err, errUnusableSnapshot) }

// snapshotNotStored reports whether the database holds no record under hash. A probe that
// fails answers false, so the caller keeps the error it already has.
func snapshotNotStored(db ethdb.KeyValueReader, hash common.Hash) bool {
	has, err := rawdb.HasXdposV2Snapshot(db, hash)
	return err == nil && !has
}

// EncodeSnapshot marshals a snapshot for storage. Callers that have to write a
// snapshot together with other data (e.g. the chain markers of the gap block it
// belongs to) encode it here and hand the blob to their own writer.
func EncodeSnapshot(s *SnapshotV2) ([]byte, error) {
	if len(s.NextEpochCandidates) == 0 {
		return nil, fmt.Errorf("%w: refusing to encode an empty masternode snapshot", errUnusableSnapshot)
	}
	return json.Marshal(s)
}

// StoreSnapshot inserts the SnapshotV2 into the database. Callers that have to
// write it next to other data encode it with EncodeSnapshot instead and hand the
// blob to their own writer.
func StoreSnapshot(s *SnapshotV2, db ethdb.Database) error {
	blob, err := EncodeSnapshot(s)
	if err != nil {
		return err
	}
	return rawdb.WriteXdposV2Snapshot(db, s.Hash, blob)
}

// retrieves candidates nodes list in map type
func (s *SnapshotV2) GetMappedCandidates() map[common.Address]struct{} {
	ms := make(map[common.Address]struct{})
	for _, n := range s.NextEpochCandidates {
		ms[n] = struct{}{}
	}
	return ms
}

func (s *SnapshotV2) IsCandidates(address common.Address) bool {
	for _, n := range s.NextEpochCandidates {
		if n == address {
			return true
		}
	}
	return false
}

// snapshot retrieves the authorization snapshot at a given point in time.
func (x *XDPoS_v2) getSnapshot(chain consensus.ChainReader, number uint64, isGapNumber bool) (*SnapshotV2, error) {
	var gapBlockNum uint64
	if isGapNumber {
		gapBlockNum = number
	} else {
		if x.config.Epoch == 0 {
			// A config error, not a consensus sentinel: core reads the sentinels as
			// a local condition of the chain data
			return nil, fmt.Errorf("[getSnapshot] XDPoS.Epoch is unset, so no gap block backs number %d", number)
		}
		gapBlockNum, _ = x.config.GapBlockNumber(number)
	}

	gapHeader := chain.GetHeaderByNumber(gapBlockNum)
	if gapHeader == nil {
		log.Error("[getSnapshot] Fail to get header", "number", gapBlockNum)
		// Reported as a sentinel rather than as a bare error: the number this node cannot read
		// by canonical number is the gap block of an epoch switch, and the reason can be its own
		// chain (the gap block sits on a sidechain stored without being imported) rather than
		// the batch under verification. core's classification reads the sentinel as local.
		return nil, fmt.Errorf("%w: gap block %v", consensus.ErrMissingCanonicalGapHeader, gapBlockNum)
	}
	gapBlockHash := gapHeader.Hash()
	log.Debug("get snapshot from gap block", "number", gapBlockNum, "hash", gapBlockHash.Hex())

	// If an in-memory SnapshotV2 was found, use that
	if snap, ok := x.snapshots.Get(gapBlockHash); ok && snap != nil {
		log.Trace("Loaded snapshot from memory", "number", gapBlockNum, "hash", gapBlockHash)
		return snap, nil
	}
	// If an on-disk checkpoint snapshot can be found, use that
	snap, err := loadSnapshot(x.db, gapBlockHash)
	if err != nil {
		// initial() owns the snapshot at the V2 switch gap block, and the bft
		// goroutine can reach this lookup before it has been stored.
		if rebuilt, rerr := x.rebuildBootstrapSnapshot(chain, gapBlockNum, gapBlockHash); rerr == nil {
			return rebuilt, nil
		} else if !errors.Is(rerr, errNotBootstrapSnapshot) {
			log.Warn("[getSnapshot] cannot rebuild bootstrap snapshot", "number", gapBlockNum, "hash", gapBlockHash, "err", rerr)
		}
		// Reported as a sentinel rather than as a bare error: the header above is this node's
		// own canonical gap block, so an entry that is absent, unreadable, undecodable or empty is
		// a condition of its database rather than a fault of the batch under verification. core's
		// classification reads the sentinel as local, and the storage or decoding error stays
		// the cause.
		hint := ""
		if errors.Is(err, errUnusableSnapshot) {
			hint = " (a restart repairs at most the two most recent gap snapshots, from their gap block state, when that state is still readable)"
		}
		return nil, fmt.Errorf("%w: gap block %v (%s): %w%s",
			consensus.ErrGapSnapshotUnavailable, gapBlockNum, gapBlockHash.Hex(), err, hint)
	}

	log.Trace("Loaded snapshot from disk", "number", gapBlockNum, "hash", gapBlockHash)
	x.snapshots.Add(snap.Hash, snap)
	return snap, nil
}

// errNotBootstrapSnapshot marks a getSnapshot miss that rebuildBootstrapSnapshot
// deliberately leaves alone, so callers can stay quiet about it.
var errNotBootstrapSnapshot = errors.New("not the bootstrap gap block")

// rebuildBootstrapSnapshot recreates the V2 switch gap snapshot that initial()
// writes, from the same switch header. A vote verified before initial() stores
// it would otherwise miss, drop every vote for block 1 and stall the chain.
func (x *XDPoS_v2) rebuildBootstrapSnapshot(chain consensus.ChainReader, gapBlockNum uint64, gapBlockHash common.Hash) (*SnapshotV2, error) {
	switchBlock := x.config.V2.SwitchBlock.Uint64()
	lastGapNum, _ := x.config.GapBlockNumber(switchBlock)
	if gapBlockNum != lastGapNum {
		return nil, errNotBootstrapSnapshot
	}

	checkpointHeader := chain.GetHeaderByNumber(switchBlock)
	if checkpointHeader == nil {
		return nil, fmt.Errorf("missing v2 switch header %d", switchBlock)
	}
	_, _, masternodes, err := x.getExtraFields(checkpointHeader)
	if err != nil {
		return nil, fmt.Errorf("reading masternodes from v2 switch header %d: %w", switchBlock, err)
	}
	if len(masternodes) == 0 {
		return nil, fmt.Errorf("no masternodes at v2 switch block %d", switchBlock)
	}

	snap := NewSnapshot(lastGapNum, gapBlockHash, masternodes)
	if err := StoreSnapshot(snap, x.db); err != nil {
		return nil, fmt.Errorf("storing bootstrap snapshot: %w", err)
	}
	x.snapshots.Add(snap.Hash, snap)
	log.Warn("[getSnapshot] rebuilt bootstrap snapshot ahead of initial()", "number", lastGapNum, "hash", gapBlockHash, "masternodes", len(masternodes))
	return snap, nil
}

// GapStateReader is a chain reader that can also open historical state and
// expose its database, which the startup repair needs to rebuild a snapshot
// from its gap block.
type GapStateReader interface {
	consensus.ChainReader
	ChainDb() ethdb.Database
	StateAt(root common.Hash) (*state.StateDB, error)
}

// ErrNoCandidates is returned by BuildSnapshotFromState when the gap block
// state yields no masternode candidates.
var ErrNoCandidates = errors.New("no masternode candidates in state")

// BuildSnapshotFromState derives a gap block snapshot from the state committed
// at that block. The ordering must stay identical to the one
// core.BlockChain.UpdateM1At applies for the v1 era: a different equal-stake
// order yields a different masternode set. Callers such as
// Downloader.generateSnapshot must delegate here instead of reimplementing the
// derivation.
func BuildSnapshotFromState(statedb *state.StateDB, number uint64, hash common.Hash) (*SnapshotV2, error) {
	return buildSnapshotFromCandidates(statedb, statedb.GetCandidates(), number, hash)
}

// BuildSubnetSnapshotFromState derives the snapshot of a subnet gap block from
// the state committed at that block and the penalties that the next block, the
// one after the gap block, published. It serves the paths that cannot compute
// the penalties themselves, which takes the bodies of the epoch before the gap
// block; see XDPoS_v2.BuildGapSnapshot for the one that can.
func BuildSubnetSnapshotFromState(statedb *state.StateDB, number uint64, hash common.Hash, penalties []common.Address) (*SnapshotV2, error) {
	snap, err := buildSnapshotFromCandidates(statedb, statedb.GetSubnetCandidates(), number, hash)
	if err != nil {
		return nil, err
	}
	snap.NextEpochPenalties = penalties
	return snap, nil
}

// buildSnapshotFromCandidates sorts the candidates read from statedb by their
// stake in that state and returns them as the snapshot of the gap block.
func buildSnapshotFromCandidates(statedb *state.StateDB, candidates []common.Address, number uint64, hash common.Hash) (*SnapshotV2, error) {
	var ms []utils.Masternode
	for _, candidate := range candidates {
		if candidate.IsZero() {
			continue
		}
		ms = append(ms, utils.Masternode{Address: candidate, Stake: statedb.GetCandidateCap(candidate)})
	}
	// GetCandidates and GetCandidateCap return zero values when the voting
	// contract storage cannot be read, memoizing the failure in StateDB.Error().
	// Persisting a snapshot derived from such reads would store an empty or
	// partial masternode set that permanently masks the hole, so surface the
	// read error instead.
	if err := statedb.Error(); err != nil {
		return nil, fmt.Errorf("reading masternode candidates from state: %w", err)
	}
	if len(ms) == 0 {
		// An empty set is not a usable snapshot, so it is never written.
		return nil, ErrNoCandidates
	}
	utils.SortMasternodesByStakeDesc(ms)
	// The set is consensus critical and the snapshot keeps only the addresses, so
	// record the members and their stakes here, where the ordered list still
	// exists: this is the only place that can tell which nodes made the set of a
	// gap block and with what stake.
	for i, m := range ms {
		log.Info("next-epoch masternode", "number", number, "hash", hash.Hex(), "i", i, "addr", m.Address, "stake", m.Stake)
	}

	sorted := make([]common.Address, len(ms))
	for i, m := range ms {
		sorted[i] = m.Address
	}
	return NewSnapshot(number, hash, sorted), nil
}

// repairGapCandidates returns the gap block numbers at or below head whose
// snapshot can still matter to the running chain. getSnapshot maps head to the
// gap block between Gap and Gap+Epoch blocks back, which is always one of these.
func (x *XDPoS_v2) repairGapCandidates(head uint64) []uint64 {
	epoch, gap := x.config.Epoch, x.config.Gap
	if epoch == 0 || gap == 0 || gap >= epoch {
		return nil
	}
	offset := epoch - gap
	if head < offset {
		return nil
	}
	latest := head - (head-offset)%epoch
	if latest < epoch {
		return []uint64{latest}
	}
	return []uint64{latest - epoch, latest}
}

// RepairGapSnapshots restores gap block snapshots missing from the database.
// The write path keeps a gap block and its snapshot in one batch, so a snapshot
// is missing here for data written before that, or for a gap block stored by a
// path that derived none. Meant to run once at startup. Failures are only
// logged: a node that is still syncing legitimately has no state to rebuild
// from.
func (x *XDPoS_v2) RepairGapSnapshots(chain GapStateReader) {
	head := chain.CurrentHeader()
	if head == nil {
		return
	}
	// Probe and store through the chain's own database rather than x.db, so a
	// mismatched engine database cannot cause silent wrong-database writes.
	db := chain.ChainDb()
	for _, gapNum := range x.repairGapCandidates(head.Number.Uint64()) {
		// The snapshot at V2 SwitchBlock-Gap is owned by initial(), and gap
		// blocks below the switch belong to the v1 engine. Config validation
		// forces SwitchBlock to align with an epoch switch (SwitchBlock % Epoch
		// == 0), so <= never skips a v2 gap block.
		if gapNum <= x.config.V2.SwitchBlock.Uint64() {
			continue
		}
		gapHeader := chain.GetHeaderByNumber(gapNum)
		if gapHeader == nil {
			// gapNum is at or below the current head, so the canonical header must exist.
			log.Warn("[RepairGapSnapshots] missing canonical gap header", "number", gapNum, "head", head.Number)
			continue
		}
		gapHash := gapHeader.Hash()
		// A stored snapshot is kept unless it cannot be served (it does not decode
		// or carries no candidates): such a record would otherwise reject every
		// signature and epoch switch block it backs, forever. A read that fails
		// tells us nothing about the stored value, so it still skips the repair to
		// avoid overwriting a set that may have been persisted through a reorg.
		has, err := rawdb.HasXdposV2Snapshot(db, gapHash)
		if err != nil {
			log.Debug("[RepairGapSnapshots] cannot probe stored snapshot", "number", gapNum, "hash", gapHash, "err", err)
			continue
		}
		if has {
			_, lerr := loadSnapshot(db, gapHash)
			switch {
			case lerr == nil:
				continue
			case errors.Is(lerr, errUnusableSnapshot):
				log.Warn("[RepairGapSnapshots] stored snapshot is unusable, rebuilding", "number", gapNum, "hash", gapHash, "err", lerr)
			default:
				log.Debug("[RepairGapSnapshots] cannot read stored snapshot", "number", gapNum, "hash", gapHash, "err", lerr)
				continue
			}
		}
		statedb, err := chain.StateAt(gapHeader.Root)
		if err != nil {
			log.Warn("[RepairGapSnapshots] gap block state unavailable", "number", gapNum, "hash", gapHash, "root", gapHeader.Root, "err", err)
			continue
		}
		snap, err := x.BuildGapSnapshot(chain, statedb, gapHeader)
		if err != nil {
			log.Warn("[RepairGapSnapshots] cannot derive snapshot", "number", gapNum, "hash", gapHash, "err", err)
			continue
		}
		if err := StoreSnapshot(snap, db); err != nil {
			log.Warn("[RepairGapSnapshots] cannot store snapshot", "number", gapNum, "hash", gapHash, "err", err)
			continue
		}
		x.snapshots.Add(snap.Hash, snap)
		log.Warn("[RepairGapSnapshots] repaired snapshot", "number", gapNum, "hash", gapHash, "candidates", len(snap.NextEpochCandidates))
	}
}

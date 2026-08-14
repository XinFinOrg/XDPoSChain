package engine_v2

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/XinFinOrg/XDPoSChain/common"
	xdc_sort "github.com/XinFinOrg/XDPoSChain/common/sort"
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

// loadSnapshot loads an existing snapshot from the database.
func loadSnapshot(db ethdb.Database, hash common.Hash) (*SnapshotV2, error) {
	blob, err := rawdb.ReadXdposV2Snapshot(db, hash)
	if err != nil {
		return nil, err
	}
	snap := new(SnapshotV2)
	if err := json.Unmarshal(blob, snap); err != nil {
		return nil, err
	}

	return snap, nil
}

// StoreSnapshot inserts the SnapshotV2 into the database.
func StoreSnapshot(s *SnapshotV2, db ethdb.Database) error {
	blob, err := json.Marshal(s)
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
		gapBlockNum = number - number%x.config.Epoch
		if gapBlockNum > x.config.Gap {
			gapBlockNum -= x.config.Gap
		} else {
			gapBlockNum = 0
		}
	}

	gapHeader := chain.GetHeaderByNumber(gapBlockNum)
	if gapHeader == nil {
		log.Error("[getSnapshot] Fail to get header", "number", gapBlockNum)
		return nil, fmt.Errorf("getSnapshot fail to get header by number: %v", gapBlockNum)
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
		log.Error("Cannot find snapshot from last gap block", "err", err, "number", gapBlockNum, "hash", gapBlockHash)
		return nil, err
	}

	log.Trace("Loaded snapshot from disk", "number", gapBlockNum, "hash", gapBlockHash)
	x.snapshots.Add(snap.Hash, snap)
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
// at that block. The ordering must stay identical to core.BlockChain.UpdateM1
// and Downloader.generateSnapshot: a different equal-stake order yields a
// different masternode set.
func BuildSnapshotFromState(statedb *state.StateDB, number uint64, hash common.Hash) (*SnapshotV2, error) {
	var ms []utils.Masternode
	for _, candidate := range statedb.GetCandidates() {
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
		// An empty snapshot loads back fine and would permanently mask the hole.
		return nil, ErrNoCandidates
	}
	xdc_sort.Slice(ms, func(i, j int) bool {
		return ms[i].Stake.Cmp(ms[j].Stake) >= 0
	})

	candidates := make([]common.Address, len(ms))
	for i, m := range ms {
		candidates[i] = m.Address
	}
	return NewSnapshot(number, hash, candidates), nil
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

// RepairGapSnapshots restores gap block snapshots missing from the database,
// which happens when the process exits between writeHeadBlock and UpdateM1.
// Meant to run once at startup. Failures are only logged: a node that is still
// syncing legitimately has no state to rebuild from.
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
		// Only a genuinely absent key is repaired. If we cannot reliably determine
		// whether a snapshot is present (e.g. I/O error), skip repair to avoid
		// overwriting a snapshot that may have been persisted through a reorg.
		has, err := rawdb.HasXdposV2Snapshot(db, gapHash)
		if err != nil {
			log.Debug("[RepairGapSnapshots] cannot probe stored snapshot", "number", gapNum, "hash", gapHash, "err", err)
			continue
		}
		if has {
			continue
		}
		statedb, err := chain.StateAt(gapHeader.Root)
		if err != nil {
			log.Warn("[RepairGapSnapshots] gap block state unavailable", "number", gapNum, "hash", gapHash, "root", gapHeader.Root, "err", err)
			continue
		}
		snap, err := BuildSnapshotFromState(statedb, gapNum, gapHash)
		if err != nil {
			log.Warn("[RepairGapSnapshots] cannot derive snapshot", "number", gapNum, "hash", gapHash, "err", err)
			continue
		}
		if err := StoreSnapshot(snap, db); err != nil {
			log.Warn("[RepairGapSnapshots] cannot store snapshot", "number", gapNum, "hash", gapHash, "err", err)
			continue
		}
		x.snapshots.Add(snap.Hash, snap)
		log.Warn("[RepairGapSnapshots] repaired missing snapshot", "number", gapNum, "hash", gapHash, "candidates", len(snap.NextEpochCandidates))
	}
}

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
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/ethdb"
	"github.com/XinFinOrg/XDPoSChain/log"
)

// snapshotRebuildMaxEpochsBehind is how far behind the chain head a gap block
// may be for its snapshot to still be rebuilt on demand.
const snapshotRebuildMaxEpochsBehind = 2

// errGapStateUnavailable marks a rebuild that failed because the gap block's
// state trie is gone, which is the normal outcome on a pruning node.
var errGapStateUnavailable = errors.New("gap block state unavailable")

// GapStateReader is an optional extension of consensus.ChainReader that allows
// engine_v2 to open committed state tries by root hash.
// *core.BlockChain satisfies this interface; lightweight mock readers used in
// tests typically do not, in which case self-healing is skipped.
type GapStateReader interface {
	StateAt(root common.Hash) (*state.StateDB, error)
}

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

// BuildSnapshotFromState derives a gap block snapshot from the candidate list
// and stakes held in a committed state trie, so no EVM client is required. It
// is the single source of truth for that derivation: eth/downloader uses it
// after a gap pivot state sync, engine_v2 uses it to rebuild snapshots that
// were never persisted.
//
// NOTE: keep code sync with core.BlockChain.UpdateM1
func BuildSnapshotFromState(statedb *state.StateDB, number uint64, hash common.Hash) (*SnapshotV2, error) {
	candidates := statedb.GetCandidates()
	pairs := make([]utils.Masternode, 0, len(candidates))
	for _, candidate := range candidates {
		// Redundant here (GetCandidates already skips zero addresses), kept to
		// mirror UpdateM1, whose contract fallback can return them.
		if !candidate.IsZero() {
			pairs = append(pairs, utils.Masternode{Address: candidate, Stake: statedb.GetCandidateCap(candidate)})
		}
	}
	// An empty snapshot would load back fine and permanently mask the missing
	// masternode list, so refuse to build one.
	if len(pairs) == 0 {
		return nil, fmt.Errorf("no candidates found in state of block %d (%s)", number, hash.Hex())
	}
	// Must stay xdc_sort.Slice with this exact comparator: the comparator is not
	// a strict weak ordering and the sort is unstable, so any other sort would
	// order equal stakes differently from UpdateM1 and fork the masternode set.
	xdc_sort.Slice(pairs, func(i, j int) bool {
		return pairs[i].Stake.Cmp(pairs[j].Stake) >= 0
	})
	masterNodes := make([]common.Address, len(pairs))
	for i, p := range pairs {
		masterNodes[i] = p.Address
		// Lets an operator cross-check a suspect snapshot against the rest of the network.
		log.Debug("Snapshot candidate", "number", number, "index", i, "address", p.Address, "stake", p.Stake)
	}
	return NewSnapshot(number, hash, masterNodes), nil
}

// rebuildSnapshot reconstructs a missing gap block snapshot from the committed
// state trie at gapHeader.Root, then persists it and adds it to the in-memory
// LRU cache.
//
// core.BlockChain.UpdateM1 takes the candidate list from the head state but
// always reads stakes from the validator contract at "latest". Those are the
// gap block's values on the canonical import path, where the head is the gap
// block itself, but not necessarily on the reorg path, where UpdateM1 runs
// after the head has moved. A rebuilt snapshot therefore reflects the gap block
// state, which may differ from what a peer persisted through the reorg path.
func (x *XDPoS_v2) rebuildSnapshot(sr GapStateReader, gapHeader *types.Header) (*SnapshotV2, error) {
	statedb, err := sr.StateAt(gapHeader.Root)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errGapStateUnavailable, err)
	}
	snap, err := BuildSnapshotFromState(statedb, gapHeader.Number.Uint64(), gapHeader.Hash())
	if err != nil {
		return nil, err
	}
	if err := StoreSnapshot(snap, x.db); err != nil {
		return nil, fmt.Errorf("cannot store rebuilt snapshot: %w", err)
	}
	x.snapshots.Add(snap.Hash, snap)
	return snap, nil
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

// selfHealSnapshot rebuilds a gap block snapshot that was never persisted, e.g.
// because the process exited between writeHeadBlock and StoreSnapshot in
// writeBlockWithState, leaving the head markers on disk without the snapshot.
//
// It returns (nil, nil) when a rebuild is not attempted, in which case the
// caller must report the original load failure.
func (x *XDPoS_v2) selfHealSnapshot(chain consensus.ChainReader, gapHeader *types.Header) (*SnapshotV2, error) {
	gapBlockNum := gapHeader.Number.Uint64()
	gapBlockHash := gapHeader.Hash()

	// The initial V2 gap block snapshot comes from Initial(), not from the state trie.
	if gapBlockNum <= x.config.V2.SwitchBlock.Uint64() {
		return nil, nil
	}
	// The number can come straight from an unauthenticated vote/timeout message
	// (isGapNumber), so reject non-gap numbers before doing any further work.
	// Mirrors the assertion in UpdateMasternodes.
	if gapBlockNum%x.config.Epoch != x.config.Epoch-x.config.Gap {
		return nil, nil
	}
	// Entries are only recorded for an imported gap block whose trie is pruned, so
	// a rebuild that failed once can never start working again. Checked before any
	// database read, as this runs once per vote/timeout message.
	if _, failed := x.failedRebuilds.Get(gapBlockHash); failed {
		return nil, nil
	}
	// Without this an attacker could cycle through every historic gap number and
	// force one trie read plus one database write each.
	currentHeader := chain.CurrentHeader()
	if currentHeader == nil {
		return nil, nil
	}
	if head := currentHeader.Number.Uint64(); head > gapBlockNum+snapshotRebuildMaxEpochsBehind*x.config.Epoch {
		log.Debug("Skip snapshot rebuild, gap block too far behind head", "number", gapBlockNum, "hash", gapBlockHash.Hex(), "head", head)
		return nil, nil
	}
	sr, ok := chain.(GapStateReader)
	if !ok {
		log.Debug("Skip snapshot rebuild, chain reader cannot open state", "number", gapBlockNum, "hash", gapBlockHash.Hex())
		return nil, nil
	}
	// Canonical headers can run ahead of block import while syncing, so the state
	// may simply not exist yet. This case must not be recorded as a permanent
	// failure below, retrying once the block lands works.
	if chain.GetBlock(gapBlockHash, gapBlockNum) == nil {
		log.Debug("Skip snapshot rebuild, gap block not imported yet", "number", gapBlockNum, "hash", gapBlockHash.Hex())
		return nil, nil
	}

	// A missing snapshot is expected while syncing: gap blocks below a fast sync
	// pivot never run UpdateM1. That is not actionable, so keep it quiet.
	syncing := x.HookSyncing != nil && x.HookSyncing()
	logMissing := log.Warn
	if syncing {
		logMissing = log.Debug
	}

	// Collapse concurrent callers (e.g. votes from many peers for the same gap
	// block) into one rebuild. Logging happens inside the closure so that one
	// rebuild logs one line.
	// NOTE: some callers hold x.lock, so the trie read below blocks the consensus
	// loop; it is bounded to one read per gap block.
	result, err, _ := x.snapshotFlight.Do(string(gapBlockHash[:]), func() (interface{}, error) {
		// A concurrent caller may have stored the snapshot while this one queued.
		if snap, err := loadSnapshot(x.db, gapBlockHash); err == nil {
			x.snapshots.Add(snap.Hash, snap)
			return snap, nil
		}
		// Only a genuinely missing snapshot is healed. A decode error means the key
		// is there, and overwriting it with a state-derived rebuild could replace a
		// correct masternode set with a different one.
		has, err := rawdb.HasXdposV2Snapshot(x.db, gapBlockHash)
		if err != nil {
			log.Debug("Skip snapshot rebuild, cannot probe stored snapshot", "err", err, "number", gapBlockNum, "hash", gapBlockHash.Hex())
			return nil, nil
		}
		if has {
			return nil, nil
		}
		logMissing("Cannot find snapshot from last gap block, rebuilding", "number", gapBlockNum, "hash", gapBlockHash.Hex())
		rebuilt, err := x.rebuildSnapshot(sr, gapHeader)
		if err != nil {
			// rawdb.WriteXdposV2Snapshot log.Crit's on a failed Put, so a store error
			// never reaches here and every failure below is final.
			x.failedRebuilds.Add(gapBlockHash, struct{}{})
			logFailed := log.Error
			switch {
			case syncing:
				logFailed = log.Debug
			case errors.Is(err, errGapStateUnavailable):
				logFailed = log.Warn
			}
			logFailed("Failed to rebuild snapshot", "err", err, "number", gapBlockNum, "hash", gapBlockHash.Hex(), "root", gapHeader.Root.Hex())
			return nil, err
		}
		log.Info("Rebuild snapshot OK", "number", gapBlockNum, "hash", gapBlockHash.Hex(), "root", gapHeader.Root.Hex(), "candidates", len(rebuilt.NextEpochCandidates))
		return rebuilt, nil
	})
	if err != nil {
		return nil, err
	}
	snap, ok := result.(*SnapshotV2)
	if !ok || snap == nil {
		return nil, nil
	}
	return snap, nil
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
		rebuilt, rebuildErr := x.selfHealSnapshot(chain, gapHeader)
		if rebuildErr != nil {
			return nil, errors.Join(err, rebuildErr)
		}
		if rebuilt == nil {
			return nil, err
		}
		return rebuilt, nil
	}

	log.Trace("Loaded snapshot from disk", "number", gapBlockNum, "hash", gapBlockHash)
	x.snapshots.Add(snap.Hash, snap)
	return snap, nil
}

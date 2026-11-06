// Copyright 2026 The XDPoSChain Authors
// This file is part of the XDPoSChain library.
//
// The XDPoSChain library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The XDPoSChain library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the XDPoSChain library. If not, see <http://www.gnu.org/licenses/>.

package engine_v2

// Subnet consensus rules, active when XDPoS.IsSubnet is set in the chain config.
//
// A subnet runs this engine from genesis with the HotStuff flow, the vote,
// timeout and sync messages, the quorum certificate rules and the leader
// selection unchanged. What differs, following the subnet clients (Nethermind's
// XDPoSSubnet engine and the Go XDC-Subnet client):
//
//   - Epochs are numbered by block: block n is an epoch switch when
//     n % Epoch == 0, and belongs to epoch n / Epoch. Mainnet numbers them by
//     round.
//   - The gap block (n % Epoch == Epoch - Gap) snapshots the candidates of the
//     subnet validator contract, sorted by stake, together with the penalties
//     of the next epoch, which the subnet computes at the gap block rather
//     than at the epoch switch (see HookPenalty in eth/hooks).
//   - The block after the gap block publishes that snapshot: its header
//     carries the candidates in NextValidators and the penalties in Penalties.
//     Block 1 does the same for the genesis snapshot.
//   - The epoch switch block carries only the masternodes of the new epoch in
//     Validators: the snapshot candidates minus its penalties, in candidate
//     order, capped at MaxMasternodes. They must match the local computation
//     in that exact order, since the order decides the leader rotation.
//   - Headers use the subnet RLP layout (see core/types/block_subnet.go).

import (
	"errors"
	"fmt"
	"math/big"
	"slices"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS/utils"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/log"
)

// isGapPlusOneBlock reports whether the subnet block at number publishes the
// next-epoch candidates and penalties: the block after a gap block, and block 1
// for the genesis snapshot. The subnet config check guarantees 2 <= Gap < Epoch,
// so this is never an epoch switch block.
func (x *XDPoS_v2) isGapPlusOneBlock(number uint64) bool {
	return number == 1 || number%x.config.Epoch == x.config.Epoch-x.config.Gap+1
}

// subnetIsEpochSwitch is IsEpochSwitch for a subnet.
func (x *XDPoS_v2) subnetIsEpochSwitch(number uint64) (bool, uint64) {
	return number%x.config.Epoch == 0, number / x.config.Epoch
}

// EpochNumber returns the epoch of a block from its number and round: subnet
// epochs are numbered by block, mainnet ones by round from V2.SwitchEpoch.
func (x *XDPoS_v2) EpochNumber(number uint64, round types.Round) uint64 {
	if x.config.IsSubnet {
		return number / x.config.Epoch
	}
	return x.config.V2.SwitchEpoch + uint64(round)/x.config.Epoch
}

// calcSubnetMasternodes returns the masternodes of the epoch that starts at
// blockNum and the penalties applied to them: the candidates of the gap block
// snapshot minus its penalties, keeping the candidate order and dropping
// duplicates, capped at MaxMasternodes.
func (x *XDPoS_v2) calcSubnetMasternodes(chain consensus.ChainReader, blockNum *big.Int, round types.Round) ([]common.Address, []common.Address, error) {
	snap, err := x.getSnapshot(chain, blockNum.Uint64(), false)
	if err != nil {
		log.Error("[calcSubnetMasternodes] getSnapshot has error", "number", blockNum, "err", err)
		return nil, nil, err
	}
	maxMasternodes := x.config.V2.Config(uint64(round)).MaxMasternodes
	return subnetMasternodes(snap.NextEpochCandidates, snap.NextEpochPenalties, maxMasternodes), snap.NextEpochPenalties, nil
}

// subnetMasternodes removes penalties and duplicates from candidates, keeping
// their order, and caps the result at max entries.
func subnetMasternodes(candidates, penalties []common.Address, max int) []common.Address {
	excluded := make(map[common.Address]struct{}, len(candidates)+len(penalties))
	for _, p := range penalties {
		excluded[p] = struct{}{}
	}
	masternodes := make([]common.Address, 0, min(len(candidates), max))
	for _, c := range candidates {
		if len(masternodes) == max {
			break
		}
		if _, ok := excluded[c]; ok {
			continue
		}
		excluded[c] = struct{}{}
		masternodes = append(masternodes, c)
	}
	return masternodes
}

// prepareSubnetHeader fills the subnet-only fields of a header being mined:
// the next-epoch candidates and penalties of the block after the gap block.
func (x *XDPoS_v2) prepareSubnetHeader(chain consensus.ChainReader, header *types.Header) error {
	header.Subnet = true
	header.NextValidators = nil
	header.Penalties = nil
	if !x.isGapPlusOneBlock(header.Number.Uint64()) {
		return nil
	}
	snap, err := x.getSnapshotByHash(chain, header.ParentHash)
	if err != nil {
		log.Error("[prepareSubnetHeader] no snapshot for the gap block", "number", header.Number, "parentHash", header.ParentHash, "err", err)
		return err
	}
	header.NextValidators = types.PackAddresses(snap.NextEpochCandidates)
	header.Penalties = types.PackAddresses(snap.NextEpochPenalties)
	return nil
}

// verifySubnetHeader checks the subnet-only fields of a header. The epoch
// switch Validators are checked by verifyHeader with the masternodes.
func (x *XDPoS_v2) verifySubnetHeader(chain consensus.ChainReader, header *types.Header, fullVerify bool) error {
	if !x.isGapPlusOneBlock(header.Number.Uint64()) {
		if len(header.NextValidators) != 0 || len(header.Penalties) != 0 {
			log.Warn("[verifySubnetHeader] next epoch validators or penalties outside the block after the gap block", "number", header.Number, "hash", header.Hash())
			return utils.ErrInvalidFieldInNonGapPlusOneBlock
		}
		return nil
	}
	if len(header.NextValidators)%common.AddressLength != 0 || len(header.Penalties)%common.AddressLength != 0 {
		return utils.ErrInvalidCheckpointSigners
	}
	// Like the epoch switch masternodes, the published snapshot is only
	// recomputed on a full verification.
	if !fullVerify {
		return nil
	}
	snap, err := x.getSnapshotByHash(chain, header.ParentHash)
	if err != nil {
		log.Error("[verifySubnetHeader] no snapshot for the gap block", "number", header.Number, "parentHash", header.ParentHash, "err", err)
		return err
	}
	if !utils.CompareSignersLists(snap.NextEpochCandidates, common.ExtractAddressFromBytes(header.NextValidators)) {
		logAddresses("[verifySubnetHeader] local next epoch candidates", snap.NextEpochCandidates)
		logAddresses("[verifySubnetHeader] header next epoch validators", common.ExtractAddressFromBytes(header.NextValidators))
		return utils.ErrNextEpochValidatorsNotLegit
	}
	if !utils.CompareSignersLists(snap.NextEpochPenalties, common.ExtractAddressFromBytes(header.Penalties)) {
		logAddresses("[verifySubnetHeader] local penalties", snap.NextEpochPenalties)
		logAddresses("[verifySubnetHeader] header penalties", common.ExtractAddressFromBytes(header.Penalties))
		return utils.ErrPenaltiesNotLegit
	}
	return nil
}

// sameSubnetMasternodes reports whether the epoch switch Validators equal the
// computed masternodes in order. The order matters on a subnet: it decides the
// leader of each round, and the other subnet clients reject any other order.
func sameSubnetMasternodes(local, header []common.Address) bool {
	return slices.Equal(local, header)
}

func logAddresses(msg string, addrs []common.Address) {
	for i, addr := range addrs {
		log.Warn(msg, "i", i, "addr", addr.Hex())
	}
}

// BuildGapSnapshot derives the snapshot a gap block stores for the next epoch
// from the state committed at that block. A subnet reads the candidates of its
// own validator contract and adds the next-epoch penalties, computed by
// HookPenalty from the blocks before the gap block, so the header must be the
// gap block itself. Its ancestors have to be stored, its own body not.
func (x *XDPoS_v2) BuildGapSnapshot(chain consensus.ChainReader, statedb *state.StateDB, header *types.Header) (*SnapshotV2, error) {
	number, hash := header.Number.Uint64(), header.Hash()
	if !x.config.IsSubnet {
		return BuildSnapshotFromState(statedb, number, hash)
	}
	snap, err := buildSnapshotFromCandidates(statedb, statedb.GetSubnetCandidates(), number, hash)
	if err != nil {
		return nil, err
	}
	if x.HookPenalty != nil {
		penalties, err := x.HookPenalty(chain, header.Number, header.ParentHash, snap.NextEpochCandidates)
		if err != nil {
			return nil, fmt.Errorf("computing the next-epoch penalties of gap block %d (%s): %w", number, hash.Hex(), err)
		}
		snap.NextEpochPenalties = penalties
	}
	for i, p := range snap.NextEpochPenalties {
		log.Info("next-epoch penalty", "number", number, "hash", hash.Hex(), "i", i, "addr", p)
	}
	return snap, nil
}

// errNotSubnetGapBlock reports a snapshot lookup for a block that holds none.
var errNotSubnetGapBlock = errors.New("not a subnet gap block")

// getSnapshotByHash returns the snapshot of the gap block with the given hash.
// It is keyed by hash rather than by number, so it also serves a gap block on a
// fork that is not canonical yet: such a block has no stored snapshot, which is
// then derived from its own state, as the import of a canonical gap block does.
func (x *XDPoS_v2) getSnapshotByHash(chain consensus.ChainReader, hash common.Hash) (*SnapshotV2, error) {
	if snap, ok := x.snapshots.Get(hash); ok && snap != nil {
		return snap, nil
	}
	if snap, err := loadSnapshot(x.db, hash); err == nil {
		x.snapshots.Add(snap.Hash, snap)
		return snap, nil
	}
	header := chain.GetHeaderByHash(hash)
	if header == nil {
		return nil, fmt.Errorf("%w: unknown gap block %s", consensus.ErrUnknownAncestor, hash.Hex())
	}
	number := header.Number.Uint64()
	// The genesis snapshot is owned by initial(), which may not have stored it
	// yet when a vote or a block arrives first.
	if number == 0 {
		return x.rebuildBootstrapSnapshot(chain, 0, hash)
	}
	if number%x.config.Epoch != x.config.Epoch-x.config.Gap {
		return nil, fmt.Errorf("%w: block %d (%s)", errNotSubnetGapBlock, number, hash.Hex())
	}
	stateChain, ok := chain.(GapStateReader)
	if !ok {
		return nil, fmt.Errorf("%w: gap block %d (%s): chain cannot open state", consensus.ErrGapSnapshotUnavailable, number, hash.Hex())
	}
	statedb, err := stateChain.StateAt(header.Root)
	if err != nil {
		return nil, fmt.Errorf("%w: gap block %d (%s): %w", consensus.ErrGapSnapshotUnavailable, number, hash.Hex(), err)
	}
	snap, err := x.BuildGapSnapshot(chain, statedb, header)
	if err != nil {
		return nil, err
	}
	// Only cached: storing stays with the chain, which writes the snapshot of a
	// gap block with its chain markers once the block becomes canonical.
	x.snapshots.Add(snap.Hash, snap)
	log.Info("[getSnapshotByHash] derived the snapshot of a non-canonical gap block", "number", number, "hash", hash.Hex())
	return snap, nil
}

// subnetGetBlockByEpochNumber returns the epoch switch block of an epoch, which
// on a subnet is the canonical block at epoch * Epoch.
func (x *XDPoS_v2) subnetGetBlockByEpochNumber(chain consensus.ChainReader, targetEpochNum uint64) (*types.BlockInfo, error) {
	current := chain.CurrentHeader()
	if current == nil {
		return nil, errors.New("current header is nil")
	}
	if epochNum := current.Number.Uint64() / x.config.Epoch; targetEpochNum > epochNum {
		return nil, fmt.Errorf("input epoch number > current epoch number, targetEpochNum:%d, epochNum:%d", targetEpochNum, epochNum)
	}
	number := targetEpochNum * x.config.Epoch
	header := chain.GetHeaderByNumber(number)
	if header == nil {
		return nil, fmt.Errorf("fail to get epoch switch header by number: %d", number)
	}
	_, round, _, err := x.getExtraFields(header)
	if err != nil {
		return nil, err
	}
	return &types.BlockInfo{Hash: header.Hash(), Round: round, Number: header.Number}, nil
}

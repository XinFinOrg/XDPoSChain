package engine_v2_subnet

import (
	"fmt"
	"math/big"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/log"
)

// get epoch switch of the previous `limit` epoch
func (x *XDPoS_v2) getPreviousEpochSwitchInfoByHash(chain consensus.ChainReader, hash common.Hash, limit int) (*types.EpochSwitchInfo, error) {
	epochSwitchInfo, err := x.getEpochSwitchInfo(chain, nil, hash)
	if err != nil {
		log.Error("[getPreviousEpochSwitchInfoByHash] Adaptor v2 getEpochSwitchInfo has error, potentially bug", "err", err)
		return nil, err
	}
	for i := 0; i < limit; i++ {
		epochSwitchInfo, err = x.getEpochSwitchInfo(chain, nil, epochSwitchInfo.EpochSwitchParentBlockInfo.Hash)
		if err != nil {
			log.Error("[getPreviousEpochSwitchInfoByHash] Adaptor v2 getEpochSwitchInfo has error, potentially bug", "err", err)
			return nil, err
		}
	}
	return epochSwitchInfo, nil
}

// Given header and its hash, get epoch switch info from the epoch switch block of that epoch,
// header is allow to be nil.
func (x *XDPoS_v2) getEpochSwitchInfo(chain consensus.ChainReader, header *types.Header, hash common.Hash) (*types.EpochSwitchInfo, error) {
	epochSwitchInfo, ok := x.epochSwitches.Get(hash)
	if ok && epochSwitchInfo != nil {
		log.Debug("[getEpochSwitchInfo] cache hit", "number", epochSwitchInfo.EpochSwitchBlockInfo.Number, "hash", hash.Hex())
		return epochSwitchInfo, nil
	}
	h := header
	if h == nil {
		log.Debug("[getEpochSwitchInfo] header doesn't provide, get header by hash", "hash", hash.Hex())
		h = chain.GetHeaderByHash(hash)
		if h == nil {
			return nil, fmt.Errorf("[getEpochSwitchInfo] can not find header from db hash %v", hash.Hex())
		}
	} else {
		if h.Hash() != hash {
			return nil, fmt.Errorf("[getEpochSwitchInfo] header hash not match, header hash %v, input hash %v", h.Hash().Hex(), hash.Hex())
		}
	}
	isEpochSwitch, _, err := x.IsEpochSwitch(h)
	if err != nil {
		return nil, err
	}
	if isEpochSwitch {
		log.Debug("[getEpochSwitchInfo] header is epoch switch", "hash", hash.Hex(), "number", h.Number.Uint64())
		if h.Number.Uint64() == 0 {
			log.Warn("[getEpochSwitchInfo] block 0, init epoch differently")
			// handle genesis block differently as follows
			masternodes := common.ExtractAddressFromBytes(h.Extra[32 : len(h.Extra)-65])
			penalties := []common.Address{}
			standbynodes := []common.Address{}
			epochSwitchInfo := &types.EpochSwitchInfo{
				Penalties:      penalties,
				Standbynodes:   standbynodes,
				Masternodes:    masternodes,
				MasternodesLen: len(masternodes),
				EpochSwitchBlockInfo: &types.BlockInfo{
					Hash:   hash,
					Number: h.Number,
					Round:  0,
				},
			}
			x.epochSwitches.Add(hash, epochSwitchInfo)
			return epochSwitchInfo, nil
		}
		quorumCert, round, masternodes, err := x.getExtraFields(h)
		if err != nil {
			log.Error("[getEpochSwitchInfo] get extra field", "err", err, "number", h.Number.Uint64())
			return nil, err
		}
		snap, err := x.getSnapshot(chain, h.Number.Uint64(), false)
		if err != nil {
			log.Error("[getEpochSwitchInfo] Adaptor v2 getSnapshot has error", "err", err)
			return nil, err
		}
		// penalties := common.ExtractAddressFromBytes(h.Penalties)
		penalties := snap.NextEpochPenalties
		candidates := snap.NextEpochCandidates
		standbynodes := []common.Address{}
		if len(masternodes) != len(candidates) {
			standbynodes = candidates
			standbynodes = common.RemoveItemFromArray(standbynodes, masternodes)
			standbynodes = common.RemoveItemFromArray(standbynodes, penalties)
		}

		epochSwitchInfo := &types.EpochSwitchInfo{
			Penalties:      penalties,
			Standbynodes:   standbynodes,
			Masternodes:    masternodes,
			MasternodesLen: len(masternodes),
			EpochSwitchBlockInfo: &types.BlockInfo{
				Hash:   hash,
				Number: h.Number,
				Round:  round,
			},
		}
		if quorumCert != nil {
			epochSwitchInfo.EpochSwitchParentBlockInfo = quorumCert.ProposedBlockInfo
		}

		x.epochSwitches.Add(hash, epochSwitchInfo)
		return epochSwitchInfo, nil
	}
	epochSwitchInfo, err = x.getEpochSwitchInfo(chain, nil, h.ParentHash)
	if err != nil {
		log.Error("[getEpochSwitchInfo] recursive error", "err", err, "hash", hash.Hex(), "number", h.Number.Uint64())
		return nil, err
	}
	log.Debug("[getEpochSwitchInfo] get epoch switch info recursively", "hash", hash.Hex(), "number", h.Number.Uint64())
	x.epochSwitches.Add(hash, epochSwitchInfo)
	return epochSwitchInfo, nil
}

// IsEpochSwitchAtRound() is used by miner to check whether it mines a block in the same epoch with parent
func (x *XDPoS_v2) isEpochSwitchAtRound(_ types.Round, parentHeader *types.Header) (bool, uint64, error) {
	// in subnet, we don't use round to decide epoch switch
	blockNum := parentHeader.Number.Uint64() + 1
	return blockNum%x.config.Epoch == 0, blockNum / x.config.Epoch, nil
}

func (x *XDPoS_v2) GetCurrentEpochSwitchBlock(chain consensus.ChainReader, blockNum *big.Int) (uint64, uint64, error) {
	// in subnet, epoch switch block is whose block num % Epoch == 0
	num := blockNum.Uint64()
	currentCheckpointNumber := num - num%x.config.Epoch
	epochNum := num / x.config.Epoch
	return currentCheckpointNumber, epochNum, nil
}

func (x *XDPoS_v2) IsEpochSwitch(header *types.Header) (bool, uint64, error) {
	// in subnet, epoch switch block is whose block num % Epoch == 0
	num := header.Number.Uint64()
	epochNum := num / x.config.Epoch
	return num%x.config.Epoch == 0, epochNum, nil
}

// GetEpochSwitchInfoBetween get epoch switch between begin and end headers
// Search backwardly from end number to begin number
func (x *XDPoS_v2) GetEpochSwitchInfoBetween(chain consensus.ChainReader, begin, end *types.Header) ([]*types.EpochSwitchInfo, error) {
	infos := make([]*types.EpochSwitchInfo, 0)
	// after the first iteration, it becomes nil since epoch switch info does not have header info
	iteratorHeader := end
	// after the first iteration, it becomes the parent hash of the epoch switch block
	iteratorHash := end.Hash()
	iteratorNum := end.Number
	// when iterator is strictly > begin number, do the search
	for iteratorNum.Cmp(begin.Number) > 0 {
		epochSwitchInfo, err := x.getEpochSwitchInfo(chain, iteratorHeader, iteratorHash)
		if err != nil {
			log.Error("[GetEpochSwitchInfoBetween] Adaptor v2 getEpochSwitchInfo has error, potentially bug", "err", err)
			return nil, err
		}
		iteratorHeader = nil
		// V2 switch epoch switch info has nil parent
		if epochSwitchInfo.EpochSwitchParentBlockInfo == nil {
			break
		}
		iteratorHash = epochSwitchInfo.EpochSwitchParentBlockInfo.Hash
		iteratorNum = epochSwitchInfo.EpochSwitchBlockInfo.Number
		if iteratorNum.Cmp(begin.Number) >= 0 {
			infos = append(infos, epochSwitchInfo)
		}
	}
	// reverse the array
	for i := 0; i < len(infos)/2; i++ {
		infos[i], infos[len(infos)-1-i] = infos[len(infos)-1-i], infos[i]
	}
	return infos, nil
}

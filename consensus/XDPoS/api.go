// Copyright (c) 2018 XDPoSChain
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.

package XDPoS

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS/utils"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/log"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/XinFinOrg/XDPoSChain/rlp"
	"github.com/XinFinOrg/XDPoSChain/rpc"
)

// API is a user facing RPC API to allow controlling the signer and voting
// mechanisms of the proof-of-authority scheme.
type API struct {
	chain consensus.ChainReader
	XDPoS *XDPoS
}

type V2BlockInfo struct {
	Hash       common.Hash
	Round      types.Round
	Number     *big.Int
	ParentHash common.Hash
	Committed  bool
	Miner      common.Hash
	Timestamp  *big.Int
	EncodedRLP string
	Error      string
}

type NetworkInformation struct {
	NetworkId                  *big.Int
	XDCValidatorAddress        common.Address
	RelayerRegistrationAddress common.Address
	XDCXListingAddress         common.Address
	XDCZAddress                common.Address
	LendingAddress             common.Address
	ConsensusConfigs           params.XDPoSConfig
}

type SignerTypes struct {
	CurrentNumber  int
	CurrentSigners []common.Address
	MissingSigners []common.Address
}

type MasternodesStatus struct {
	Epoch           uint64
	Number          uint64
	Round           types.Round
	MasternodesLen  int
	Masternodes     []common.Address
	PenaltyLen      int
	Penalty         []common.Address
	StandbynodesLen int
	Standbynodes    []common.Address
	Error           error
}

type AccountEpochReward struct {
	EpochBlockNum   uint64
	Address         common.Address
	AccountStatus   AccountRewardStatus
	AccountReward   *big.Int
	DelegatedReward map[string]*big.Int
}

type TotalRewards struct {
	Address              common.Address
	StartBlockNum        uint64
	EndBlockNum          uint64
	TotalAccountReward   *big.Int
	TotalDelegatedReward map[string]*big.Int
}

type AccountRewardResponse struct {
	EpochRewards []AccountEpochReward
	Total        TotalRewards
}

type AccountRewardStatus string

type rewardFileName struct {
	epochBlockNum  int
	epochBlockHash common.Hash
}

const (
	statusMasternode    AccountRewardStatus = "MasterNode"
	statusProtectornode AccountRewardStatus = "ProtectorNode"
	statusObservernode  AccountRewardStatus = "ObserverNode"
)

type MessageStatus map[string]map[string]interface{}

type SyncInfoTypes struct {
	Hash      common.Hash `json:"hash"`
	QCSigners int         `json:"qcSigners"`
	TCSigners int         `json:"tcSigners"`
}

type PoolStatus struct {
	Vote     map[string]SignerTypes   `json:"vote"`
	Timeout  map[string]SignerTypes   `json:"timeout"`
	SyncInfo map[string]SyncInfoTypes `json:"syncInfo"`
}

// GetSnapshot retrieves the state snapshot at a given block.
func (api *API) GetSnapshot(number *rpc.BlockNumber) (*utils.PublicApiSnapshot, error) {
	// Retrieve the requested block number (or current if none requested)
	var header *types.Header
	if number == nil || *number == rpc.LatestBlockNumber {
		header = api.chain.CurrentHeader()
	} else {
		header = api.chain.GetHeaderByNumber(uint64(number.Int64()))
	}
	// Ensure we have an actually valid block and return its snapshot
	if header == nil {
		return nil, utils.ErrUnknownBlock
	}
	return api.XDPoS.GetSnapshot(api.chain, header)
}

// GetSnapshotAtHash retrieves the state snapshot at a given block.
func (api *API) GetSnapshotAtHash(hash common.Hash) (*utils.PublicApiSnapshot, error) {
	header := api.chain.GetHeaderByHash(hash)
	if header == nil {
		return nil, utils.ErrUnknownBlock
	}
	return api.XDPoS.GetSnapshot(api.chain, header)
}

// GetSigners retrieves the list of authorized signers at the specified block.
func (api *API) GetSigners(number *rpc.BlockNumber) ([]common.Address, error) {
	// Retrieve the requested block number (or current if none requested)
	var header *types.Header
	if number == nil || *number == rpc.LatestBlockNumber {
		header = api.chain.CurrentHeader()
	} else {
		header = api.chain.GetHeaderByNumber(uint64(number.Int64()))
	}
	// Ensure we have an actually valid block and return the signers from its snapshot
	if header == nil {
		return nil, utils.ErrUnknownBlock
	}

	return api.XDPoS.GetAuthorisedSignersFromSnapshot(api.chain, header)
}

// GetSignersAtHash retrieves the state snapshot at a given block.
func (api *API) GetSignersAtHash(hash common.Hash) ([]common.Address, error) {
	header := api.chain.GetHeaderByHash(hash)
	if header == nil {
		return nil, utils.ErrUnknownBlock
	}
	return api.XDPoS.GetAuthorisedSignersFromSnapshot(api.chain, header)
}

func (api *API) GetMasternodesByNumber(number *rpc.BlockNumber) MasternodesStatus {
	var header *types.Header
	if number == nil || *number == rpc.LatestBlockNumber {
		header = api.chain.CurrentHeader()
	} else if *number == rpc.CommittedBlockNumber {
		hash := api.XDPoS.EngineV2.GetLatestCommittedBlockInfo().Hash
		header = api.chain.GetHeaderByHash(hash)
	} else {
		header = api.chain.GetHeaderByNumber(uint64(number.Int64()))
	}

	round, err := api.XDPoS.EngineV2.GetRoundNumber(header)
	if err != nil {
		return MasternodesStatus{
			Error: err,
		}
	}

	epochNum := api.XDPoS.config.V2.SwitchEpoch + uint64(round)/api.XDPoS.config.Epoch
	masterNodes := api.XDPoS.EngineV2.GetMasternodes(api.chain, header)
	penalties := api.XDPoS.EngineV2.GetPenalties(api.chain, header)
	standbynodes := api.XDPoS.EngineV2.GetStandbynodes(api.chain, header)

	info := MasternodesStatus{
		Epoch:           epochNum,
		Number:          header.Number.Uint64(),
		Round:           round,
		MasternodesLen:  len(masterNodes),
		Masternodes:     masterNodes,
		PenaltyLen:      len(penalties),
		Penalty:         penalties,
		StandbynodesLen: len(standbynodes),
		Standbynodes:    standbynodes,
	}
	return info
}

// Get current vote pool and timeout pool content and missing messages
func (api *API) GetLatestPoolStatus() PoolStatus {
	header := api.chain.CurrentHeader()
	masternodes := api.XDPoS.EngineV2.GetMasternodes(api.chain, header)

	receivedVotes := api.XDPoS.EngineV2.ReceivedVotes()
	receivedTimeouts := api.XDPoS.EngineV2.ReceivedTimeouts()
	receivedSyncInfo := api.XDPoS.EngineV2.ReceivedSyncInfo()

	info := PoolStatus{}
	info.Vote = make(map[string]SignerTypes)
	info.Timeout = make(map[string]SignerTypes)
	info.SyncInfo = make(map[string]SyncInfoTypes)

	calculateSigners(info.Vote, receivedVotes, masternodes)
	calculateSigners(info.Timeout, receivedTimeouts, masternodes)

	for name, objs := range receivedSyncInfo {
		for _, obj := range objs {
			syncInfo := obj.(*types.SyncInfo)
			hash := syncInfo.Hash()
			key := name + ":" + hash.Hex()

			qcSigners := len(syncInfo.HighestQuorumCert.Signatures)
			tcSigners := 0
			if syncInfo.HighestTimeoutCert != nil {
				tcSigners = len(syncInfo.HighestTimeoutCert.Signatures)
			}
			info.SyncInfo[key] = SyncInfoTypes{
				Hash:      hash,
				QCSigners: qcSigners,
				TCSigners: tcSigners,
			}
		}
	}

	return info
}

func (api *API) GetV2BlockByHeader(header *types.Header, uncle bool) *V2BlockInfo {
	committed := false
	latestCommittedBlock := api.XDPoS.EngineV2.GetLatestCommittedBlockInfo()
	if latestCommittedBlock == nil {
		return &V2BlockInfo{
			Hash:  header.Hash(),
			Error: "can not find latest committed block from consensus",
		}
	}
	if header.Number.Uint64() <= latestCommittedBlock.Number.Uint64() {
		committed = true && !uncle
	}

	round, err := api.XDPoS.EngineV2.GetRoundNumber(header)

	if err != nil {
		return &V2BlockInfo{
			Hash:  header.Hash(),
			Error: err.Error(),
		}
	}

	encodeBytes, err := rlp.EncodeToBytes(header)
	if err != nil {
		return &V2BlockInfo{
			Hash:  header.Hash(),
			Error: err.Error(),
		}
	}

	block := &V2BlockInfo{
		Hash:       header.Hash(),
		ParentHash: header.ParentHash,
		Number:     header.Number,
		Round:      round,
		Committed:  committed,
		Miner:      header.Coinbase.Hash(),
		Timestamp:  new(big.Int).SetUint64(header.Time),
		EncodedRLP: base64.StdEncoding.EncodeToString(encodeBytes),
	}
	return block
}

func (api *API) GetV2BlockByNumber(number *rpc.BlockNumber) *V2BlockInfo {
	header := api.getHeaderFromApiBlockNum(number)
	if header == nil {
		return &V2BlockInfo{
			Number: big.NewInt(number.Int64()),
			Error:  "can not find block from this number",
		}
	}

	uncle := false
	return api.GetV2BlockByHeader(header, uncle)
}

// Confirm V2 Block Committed Status
func (api *API) GetV2BlockByHash(blockHash common.Hash) *V2BlockInfo {
	header := api.chain.GetHeaderByHash(blockHash)
	if header == nil {
		return &V2BlockInfo{
			Hash:  blockHash,
			Error: "can not find block from this hash",
		}
	}

	// confirm this is on the main chain
	chainHeader := api.chain.GetHeaderByNumber(header.Number.Uint64())
	uncle := false
	if header.Hash() != chainHeader.Hash() {
		uncle = true
	}

	return api.GetV2BlockByHeader(header, uncle)
}

func (api *API) NetworkInformation() NetworkInformation {
	info := NetworkInformation{}
	info.NetworkId = api.chain.Config().ChainId
	info.XDCValidatorAddress = common.MasternodeVotingSMCBinary
	info.LendingAddress = common.LendingRegistrationSMC
	info.RelayerRegistrationAddress = common.RelayerRegistrationSMC
	info.XDCXListingAddress = common.XDCXListingSMC
	info.XDCZAddress = common.TRC21IssuerSMC
	info.ConsensusConfigs = *api.XDPoS.config

	return info
}

/*
An API exclusively for V2 consensus, designed to assist in troubleshooting miners by identifying who mined during their allocated term.
*/
func (api *API) GetMissedRoundsInEpochByBlockNum(number *rpc.BlockNumber) (*utils.PublicApiMissedRoundsMetadata, error) {
	return api.XDPoS.CalculateMissingRounds(api.chain, api.getHeaderFromApiBlockNum(number))
}

func (api *API) getHeaderFromApiBlockNum(number *rpc.BlockNumber) *types.Header {
	var header *types.Header
	if number == nil || *number == rpc.LatestBlockNumber {
		header = api.chain.CurrentHeader()
	} else if *number == rpc.CommittedBlockNumber {
		hash := api.XDPoS.EngineV2.GetLatestCommittedBlockInfo().Hash
		header = api.chain.GetHeaderByHash(hash)
	} else {
		header = api.chain.GetHeaderByNumber(uint64(number.Int64()))
	}
	return header
}

func calculateSigners(message map[string]SignerTypes, pool map[string]map[common.Hash]utils.PoolObj, masternodes []common.Address) {
	for name, objs := range pool {
		var currentSigners []common.Address
		missingSigners := make([]common.Address, len(masternodes))
		copy(missingSigners, masternodes)

		num := len(objs)
		for _, obj := range objs {
			signer := obj.GetSigner()
			currentSigners = append(currentSigners, signer)
			for i, mn := range missingSigners {
				if mn == signer {
					missingSigners = append(missingSigners[:i], missingSigners[i+1:]...)
					break
				}
			}
		}
		message[name] = SignerTypes{
			CurrentNumber:  num,
			CurrentSigners: currentSigners,
			MissingSigners: missingSigners,
		}
	}
}

func (api *API) GetRewardByAccount(account common.Address, begin rpc.BlockNumber, end rpc.BlockNumber) (AccountRewardResponse, error) {
	rewardFileNames, err := api.getRewardFileNamesInRange(&begin, &end)
	if err != nil {
		return AccountRewardResponse{}, err
	}

	epochRewards := []AccountEpochReward{}
	for _, fileName := range rewardFileNames {
		header := api.chain.GetHeaderByHash(fileName.epochBlockHash)
		if header == nil {
			// this is the case when there is chain rollback but the reward files of the old chain still remain, skip the reward of unknown blockhash
			continue
		}
		if int(header.Number.Int64()) != fileName.epochBlockNum {
			log.Error("[GetRewardByAccount] block number mismatch in reward filename", "reward file blocknum", fileName.epochBlockNum, "header blocknum", int(header.Number.Int64()), "blockhash", header.Hash())
			return AccountRewardResponse{}, errors.New("reward file block number mismatch")
		}
		epochReward, err := getEpochReward(account, header)
		if err != nil {
			return AccountRewardResponse{}, err
		}
		epochRewards = append(epochRewards, epochReward)
	}

	total := TotalRewards{
		Address:              account,
		StartBlockNum:        uint64(begin.Int64()),
		EndBlockNum:          uint64(end.Int64()),
		TotalAccountReward:   big.NewInt(0),
		TotalDelegatedReward: make(map[string]*big.Int),
	}

	for _, reward := range epochRewards {
		if reward.AccountReward != nil {
			total.TotalAccountReward = new(big.Int).Add(total.TotalAccountReward, reward.AccountReward)
		}
		for k, v := range reward.DelegatedReward {
			_, exist := total.TotalDelegatedReward[k]
			if exist {
				total.TotalDelegatedReward[k] = new(big.Int).Add(total.TotalDelegatedReward[k], v)
			} else {
				total.TotalDelegatedReward[k] = v
			}
		}
	}

	response := AccountRewardResponse{
		EpochRewards: epochRewards,
		Total:        total,
	}
	return response, nil
}

func (api *API) getRewardFileNamesInRange(begin, end *rpc.BlockNumber) ([]rewardFileName, error) {
	beginHeader := api.getHeaderFromApiBlockNum(begin)
	if beginHeader == nil {
		return nil, errors.New("illegal begin block number")
	}
	endHeader := api.getHeaderFromApiBlockNum(end)
	if endHeader == nil {
		return nil, errors.New("illegal end block number")
	}
	if beginHeader.Number.Cmp(endHeader.Number) > 0 {
		return nil, errors.New("illegal begin and end block number, begin > end")
	}
	diff := new(big.Int).Sub(endHeader.Number, beginHeader.Number).Int64()
	if diff < 0 {
		return nil, errors.New("illegal begin and end block number, begin > end")
	}
	if diff > 1_500_000 {
		return nil, errors.New("block range over limit of 1,500,000 blocks")
	}
	files, err := os.ReadDir(common.StoreRewardFolder)
	if err != nil {
		return nil, err
	}

	var rewardFileNames = []rewardFileName{}
	for _, file := range files {
		if !file.IsDir() {
			filePrefix, fileSuffix, found := strings.Cut(file.Name(), ".")
			if found {
				filePrefixInt, err := strconv.Atoi(filePrefix)
				if err != nil {
					log.Warn("[getEpochNumbersFromRewardFiles] found unknown filename format in rewards folder")
					return nil, err
				}
				fileSuffixHash := common.HexToHash(fileSuffix)
				rewardName := rewardFileName{
					epochBlockNum:  filePrefixInt,
					epochBlockHash: fileSuffixHash,
				}
				rewardFileNames = append(rewardFileNames, rewardName)
			}
		}
	}

	sort.Slice(rewardFileNames, func(i, j int) bool {
		return rewardFileNames[i].epochBlockNum < rewardFileNames[j].epochBlockNum
	})

	epochNumbers := make([]int, len(rewardFileNames))
	for i, obj := range rewardFileNames {
		epochNumbers[i] = obj.epochBlockNum
	}

	startIndex := sort.SearchInts(epochNumbers, int(beginHeader.Number.Int64()))
	endIndex := sort.SearchInts(epochNumbers, int(endHeader.Number.Int64()))
	if endIndex == len(epochNumbers) {
		endIndex-- //this is to prevent endIndex out of bounds when endInput is higher than last reward(epoch) block but lower than latest block
	}

	var rewardfileNamesInRange []rewardFileName
	for i := startIndex; i <= endIndex; i++ {
		rewardfileNamesInRange = append(rewardfileNamesInRange, rewardFileNames[i])
	}
	return rewardfileNamesInRange, nil
}

func getEpochReward(account common.Address, header *types.Header) (AccountEpochReward, error) {
	path := filepath.Join(common.StoreRewardFolder, header.Number.String()+"."+header.Hash().Hex())
	file, err := os.Open(path)
	if err != nil {
		alternatePath := filepath.Join(common.StoreRewardFolder, header.Number.String()+"."+header.HashNoValidator().Hex())
		file, err = os.Open(alternatePath)
		if err != nil {
			log.Warn("[getEpochReward] rewards file not found", "path", path, "alternatePath", alternatePath)
			return AccountEpochReward{}, err
		}
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	decoder.UseNumber()

	var data map[string]interface{}
	if err := decoder.Decode(&data); err != nil {
		log.Warn("[getEpochReward] Failed to decode JSON:", "err", err)
		return AccountEpochReward{}, err
	}

	epochReward := AccountEpochReward{
		Address:         account,
		EpochBlockNum:   header.Number.Uint64(),
		DelegatedReward: make(map[string]*big.Int),
	}
	epochReward.getRewardAndStatus(strings.ToLower(account.String0x()), data)

	return epochReward, nil
}

func (rewardObj *AccountEpochReward) getRewardAndStatus(account string, data map[string]interface{}) {
	if signersData, exists := data["signers"]; exists {
		if accountData, ok := signersData.(map[string]interface{})[account]; ok {
			nodeReward := accountData.(map[string]interface{})["reward"]
			delegatedReward := data["rewards"].(map[string]interface{})[account]
			rewardObj.AccountStatus = statusMasternode
			nodeRewardBigInt, ok := new(big.Int).SetString(nodeReward.(json.Number).String(), 10)
			if ok {
				rewardObj.AccountReward = nodeRewardBigInt
			}

			for k, v := range delegatedReward.(map[string]interface{}) {
				delegatedBigInt, ok := new(big.Int).SetString(v.(json.Number).String(), 10)
				if ok {
					rewardObj.DelegatedReward[k] = delegatedBigInt
				}
			}
			return
		}
	}

	if signersData, exists := data["signersProtector"]; exists {
		if accountData, ok := signersData.(map[string]interface{})[account]; ok {
			nodeReward := accountData.(map[string]interface{})["reward"]
			delegatedReward := data["rewardsProtector"].(map[string]interface{})[account]
			rewardObj.AccountStatus = statusProtectornode
			nodeRewardBigInt, successSetNodeReward := new(big.Int).SetString(nodeReward.(json.Number).String(), 10)
			if successSetNodeReward {
				rewardObj.AccountReward = nodeRewardBigInt
			}

			for k, v := range delegatedReward.(map[string]interface{}) {
				delegatedBigInt, successSetDelegatedReward := new(big.Int).SetString(v.(json.Number).String(), 10)
				if successSetDelegatedReward {
					rewardObj.DelegatedReward[k] = delegatedBigInt
				}
			}
			return
		}

	}

	if signersData, exists := data["signersObserver"]; exists {
		if accountData, ok := signersData.(map[string]interface{})[account]; ok {
			nodeReward := accountData.(map[string]interface{})["reward"]
			delegatedReward := data["rewardsObserver"].(map[string]interface{})[account]
			rewardObj.AccountStatus = statusObservernode
			nodeRewardBigInt, successSetNodeReward := new(big.Int).SetString(nodeReward.(json.Number).String(), 10)
			if successSetNodeReward {
				rewardObj.AccountReward = nodeRewardBigInt
			}

			for k, v := range delegatedReward.(map[string]interface{}) {
				delegatedBigInt, successSetDelegatedReward := new(big.Int).SetString(v.(json.Number).String(), 10)
				if successSetDelegatedReward {
					rewardObj.DelegatedReward[k] = delegatedBigInt
				}
			}
			return
		}
	}

}

func (api *API) GetEpochNumbersBetween(begin, end *rpc.BlockNumber) ([]uint64, error) {
	beginHeader := api.getHeaderFromApiBlockNum(begin)
	if beginHeader == nil {
		return nil, errors.New("illegal begin block number")
	}
	endHeader := api.getHeaderFromApiBlockNum(end)
	if endHeader == nil {
		return nil, errors.New("illegal end block number")
	}
	diff := new(big.Int).Sub(endHeader.Number, beginHeader.Number).Int64()
	if diff < 0 {
		return nil, errors.New("illegal begin and end block number, begin > end")
	}
	if diff > 50_000 {
		return nil, errors.New("block range over limit of 50,000 blocks")
	}
	epochSwitchInfos, err := api.XDPoS.GetEpochSwitchInfoBetween(api.chain, beginHeader, endHeader)
	if err != nil {
		return nil, err
	}
	epochSwitchNumbers := make([]uint64, len(epochSwitchInfos))
	for i, info := range epochSwitchInfos {
		epochSwitchNumbers[i] = info.EpochSwitchBlockInfo.Number.Uint64()
	}
	return epochSwitchNumbers, nil
}

/*
An API exclusively for V2 consensus, designed to assist in getting rewards of the epoch number.
Given the epoch number, search the epoch switch block.
*/
func (api *API) GetBlockInfoByV2EpochNum(epochNumber uint64) (*utils.EpochNumInfo, error) {
	thisEpoch, err := api.XDPoS.EngineV2.GetBlockByEpochNumber(api.chain, epochNumber)
	if err != nil {
		return nil, err
	}
	info := &utils.EpochNumInfo{
		EpochBlockHash:        thisEpoch.Hash,
		EpochRound:            &thisEpoch.Round,
		EpochFirstBlockNumber: thisEpoch.Number,
		EpochConsensusVersion: "v2",
	}
	nextEpoch, err := api.XDPoS.EngineV2.GetBlockByEpochNumber(api.chain, epochNumber+1)

	if err == nil {
		info.EpochLastBlockNumber = new(big.Int).Sub(nextEpoch.Number, big.NewInt(1))
	}
	return info, nil
}

func (api *API) CalculateBlockInfoByV1EpochNum(targetEpochNum uint64) (*utils.EpochNumInfo, error) {
	epoch := api.XDPoS.config.Epoch //900
	epochBlockNum := targetEpochNum*epoch + 1
	currentBlock := api.chain.CurrentHeader().Number.Uint64()
	if currentBlock < epochBlockNum {
		return nil, fmt.Errorf("epoch not reached: current block number %d, epoch block number %d", currentBlock, epochBlockNum)
	}

	epochLastBlockNum := epochBlockNum + epoch - 1

	return &utils.EpochNumInfo{
		EpochBlockHash:        api.chain.GetHeaderByNumber(epochBlockNum).Hash(),
		EpochFirstBlockNumber: big.NewInt(int64(epochBlockNum)),
		EpochLastBlockNumber:  big.NewInt(int64(epochLastBlockNum)),
		EpochConsensusVersion: "v1",
	}, nil
}

func (api *API) GetBlockInfoByEpochNum(epochNumber uint64) (*utils.EpochNumInfo, error) {
	if epochNumber < api.XDPoS.config.V2.SwitchEpoch {
		return api.CalculateBlockInfoByV1EpochNum(epochNumber)
	}
	return api.GetBlockInfoByV2EpochNum(epochNumber)
}

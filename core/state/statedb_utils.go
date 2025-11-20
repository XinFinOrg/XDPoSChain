package state

import (
	"math/big"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/crypto"
)

var (
	slotBlockSignerMapping = map[string]uint64{
		"blockSigners": 0,
		"blocks":       1,
	}
)

func (s *StateDB) GetSigners(block *types.Block) []common.Address {
	slot := slotBlockSignerMapping["blockSigners"]
	keys := []common.Hash{}
	keyArrSlot := GetLocMappingAtKey(block.Hash(), slot)
	arrSlot := s.GetState(common.BlockSignersBinary, common.BigToHash(keyArrSlot))
	arrLength := arrSlot.Big().Uint64()
	for i := range arrLength {
		key := GetLocDynamicArrAtElement(common.BigToHash(keyArrSlot), i, 1)
		keys = append(keys, key)
	}
	rets := []common.Address{}
	for _, key := range keys {
		ret := s.GetState(common.BlockSignersBinary, key)
		rets = append(rets, common.HexToAddress(ret.Hex()))
	}

	return rets
}

var (
	slotRandomizeMapping = map[string]uint64{
		"randomSecret":  0,
		"randomOpening": 1,
	}
)

func (s *StateDB) GetSecret(address common.Address) [][32]byte {
	slot := slotRandomizeMapping["randomSecret"]
	locSecret := GetLocMappingAtKey(address.Hash(), slot)
	arrLength := s.GetState(common.RandomizeSMCBinary, common.BigToHash(locSecret))
	keys := []common.Hash{}
	for i := uint64(0); i < arrLength.Big().Uint64(); i++ {
		key := GetLocDynamicArrAtElement(common.BigToHash(locSecret), i, 1)
		keys = append(keys, key)
	}
	rets := [][32]byte{}
	for _, key := range keys {
		ret := s.GetState(common.RandomizeSMCBinary, key)
		rets = append(rets, ret)
	}
	return rets
}

func (s *StateDB) GetOpening(address common.Address) [32]byte {
	slot := slotRandomizeMapping["randomOpening"]
	locOpening := GetLocMappingAtKey(address.Hash(), slot)
	ret := s.GetState(common.RandomizeSMCBinary, common.BigToHash(locOpening))
	return ret
}

// The smart contract and the compiled byte code (in corresponding *.go file) is at commit "KYC Layer added." 7f856ffe672162dfa9c4006c89afb45a24fb7f9f
// Notice that if smart contract and the compiled byte code (in corresponding *.go file) changes, below also changes
var (
	slotValidatorMapping = map[string]uint64{
		"withdrawsState":         0,
		"validatorsState":        1,
		"voters":                 2,
		"KYCString":              3,
		"invalidKYCCount":        4,
		"hasVotedInvalid":        5,
		"ownerToCandidate":       6,
		"owners":                 7,
		"candidates":             8,
		"candidateCount":         9,
		"ownerCount":             10,
		"minCandidateCap":        11,
		"minVoterCap":            12,
		"maxValidatorNumber":     13,
		"candidateWithdrawDelay": 14,
		"voterWithdrawDelay":     15,
	}
)

func (s *StateDB) GetCandidates() []common.Address {
	slot := slotValidatorMapping["candidates"]
	slotHash := common.BigToHash(new(big.Int).SetUint64(slot))
	arrLength := s.GetState(common.MasternodeVotingSMCBinary, slotHash)
	count := arrLength.Big().Uint64()
	rets := make([]common.Address, 0, count)

	for i := range count {
		key := GetLocDynamicArrAtElement(slotHash, i, 1)
		ret := s.GetState(common.MasternodeVotingSMCBinary, key)
		if !ret.IsZero() {
			rets = append(rets, common.HexToAddress(ret.Hex()))
		}
	}

	return rets
}

func (s *StateDB) GetCandidateOwner(candidate common.Address) common.Address {
	slot := slotValidatorMapping["validatorsState"]
	// validatorsState[_candidate].owner;
	locValidatorsState := GetLocMappingAtKey(candidate.Hash(), slot)
	locCandidateOwner := locValidatorsState.Add(locValidatorsState, new(big.Int).SetUint64(uint64(0)))
	ret := s.GetState(common.MasternodeVotingSMCBinary, common.BigToHash(locCandidateOwner))
	return common.HexToAddress(ret.Hex())
}

func (s *StateDB) GetCandidateCap(candidate common.Address) *big.Int {
	slot := slotValidatorMapping["validatorsState"]
	// validatorsState[_candidate].cap;
	locValidatorsState := GetLocMappingAtKey(candidate.Hash(), slot)
	locCandidateCap := locValidatorsState.Add(locValidatorsState, new(big.Int).SetUint64(uint64(1)))
	ret := s.GetState(common.MasternodeVotingSMCBinary, common.BigToHash(locCandidateCap))
	return ret.Big()
}

func (s *StateDB) GetVoters(candidate common.Address) []common.Address {
	//mapping(address => address[]) voters;
	slot := slotValidatorMapping["voters"]
	locVoters := GetLocMappingAtKey(candidate.Hash(), slot)
	arrLength := s.GetState(common.MasternodeVotingSMCBinary, common.BigToHash(locVoters))
	keys := []common.Hash{}
	for i := uint64(0); i < arrLength.Big().Uint64(); i++ {
		key := GetLocDynamicArrAtElement(common.BigToHash(locVoters), i, 1)
		keys = append(keys, key)
	}
	rets := []common.Address{}
	for _, key := range keys {
		ret := s.GetState(common.MasternodeVotingSMCBinary, key)
		rets = append(rets, common.HexToAddress(ret.Hex()))
	}

	return rets
}

func (s *StateDB) GetVoterCap(candidate, voter common.Address) *big.Int {
	slot := slotValidatorMapping["validatorsState"]
	locValidatorsState := GetLocMappingAtKey(candidate.Hash(), slot)
	locCandidateVoters := locValidatorsState.Add(locValidatorsState, new(big.Int).SetUint64(uint64(2)))
	retByte := crypto.Keccak256(voter.Hash().Bytes(), common.BigToHash(locCandidateVoters).Bytes())
	ret := s.GetState(common.MasternodeVotingSMCBinary, common.BytesToHash(retByte))
	return ret.Big()
}

func (s *StateDB) IncrementMintedRecordNonce() {
	nonce := s.GetNonce(common.MintedRecordAddressBinary)
	s.SetNonce(common.MintedRecordAddressBinary, nonce+1)
}

var (
	// Storage slot locations (32-byte keys) within MintedRecord SMC
	slotMintedRecordOnsetEpoch             = common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000001")
	slotMintedRecordOnsetBlock             = common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000002")
	slotMintedRecordPostMintedBase, _      = new(big.Int).SetString("0x0100000000000000000000000000000000000000000000000000000000000000", 0)
	slotMintedRecordPostBurnedBase, _      = new(big.Int).SetString("0x0200000000000000000000000000000000000000000000000000000000000000", 0)
	slotMintedRecordPostRewardBlockBase, _ = new(big.Int).SetString("0x0300000000000000000000000000000000000000000000000000000000000000", 0)
)

func (s *StateDB) GetMintedRecordOnsetEpoch() common.Hash {
	return s.GetState(common.MintedRecordAddressBinary, slotMintedRecordOnsetEpoch)
}

func (s *StateDB) PutMintedRecordOnsetEpoch(value common.Hash) {
	s.SetState(common.MintedRecordAddressBinary, slotMintedRecordOnsetEpoch, value)
}

func (s *StateDB) GetMintedRecordOnsetBlock() common.Hash {
	return s.GetState(common.MintedRecordAddressBinary, slotMintedRecordOnsetBlock)
}

func (s *StateDB) PutMintedRecordOnsetBlock(value common.Hash) {
	s.SetState(common.MintedRecordAddressBinary, slotMintedRecordOnsetBlock, value)
}

func (s *StateDB) GetPostMinted(epoch uint64) common.Hash {
	hash := common.BigToHash(new(big.Int).Add(slotMintedRecordPostMintedBase, new(big.Int).SetUint64(epoch)))
	return s.GetState(common.MintedRecordAddressBinary, hash)
}

func (s *StateDB) PutPostMinted(epoch uint64, value common.Hash) {
	hash := common.BigToHash(new(big.Int).Add(slotMintedRecordPostMintedBase, new(big.Int).SetUint64(epoch)))
	s.SetState(common.MintedRecordAddressBinary, hash, value)
}

func (s *StateDB) GetPostBurned(epoch uint64) common.Hash {
	hash := common.BigToHash(new(big.Int).Add(slotMintedRecordPostBurnedBase, new(big.Int).SetUint64(epoch)))
	return s.GetState(common.MintedRecordAddressBinary, hash)
}

func (s *StateDB) PutPostBurned(epoch uint64, value common.Hash) {
	hash := common.BigToHash(new(big.Int).Add(slotMintedRecordPostBurnedBase, new(big.Int).SetUint64(epoch)))
	s.SetState(common.MintedRecordAddressBinary, hash, value)
}

func (s *StateDB) GetPostRewardBlock(epoch uint64) common.Hash {
	hash := common.BigToHash(new(big.Int).Add(slotMintedRecordPostRewardBlockBase, new(big.Int).SetUint64(epoch)))
	return s.GetState(common.MintedRecordAddressBinary, hash)
}

func (s *StateDB) PutPostRewardBlock(epoch uint64, value common.Hash) {
	hash := common.BigToHash(new(big.Int).Add(slotMintedRecordPostRewardBlockBase, new(big.Int).SetUint64(epoch)))
	s.SetState(common.MintedRecordAddressBinary, hash, value)
}

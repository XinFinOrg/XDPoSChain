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

func GetSigners(statedb *StateDB, block *types.Block) []common.Address {
	slot := slotBlockSignerMapping["blockSigners"]
	keys := []common.Hash{}
	keyArrSlot := GetLocMappingAtKey(block.Hash(), slot)
	arrSlot := statedb.GetState(common.BlockSignersBinary, common.BigToHash(keyArrSlot))
	arrLength := arrSlot.Big().Uint64()
	for i := uint64(0); i < arrLength; i++ {
		key := GetLocDynamicArrAtElement(common.BigToHash(keyArrSlot), i, 1)
		keys = append(keys, key)
	}
	rets := []common.Address{}
	for _, key := range keys {
		ret := statedb.GetState(common.BlockSignersBinary, key)
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

func GetSecret(statedb *StateDB, address common.Address) [][32]byte {
	slot := slotRandomizeMapping["randomSecret"]
	locSecret := GetLocMappingAtKey(address.Hash(), slot)
	arrLength := statedb.GetState(common.RandomizeSMCBinary, common.BigToHash(locSecret))
	keys := []common.Hash{}
	for i := uint64(0); i < arrLength.Big().Uint64(); i++ {
		key := GetLocDynamicArrAtElement(common.BigToHash(locSecret), i, 1)
		keys = append(keys, key)
	}
	rets := [][32]byte{}
	for _, key := range keys {
		ret := statedb.GetState(common.RandomizeSMCBinary, key)
		rets = append(rets, ret)
	}
	return rets
}

func GetOpening(statedb *StateDB, address common.Address) [32]byte {
	slot := slotRandomizeMapping["randomOpening"]
	locOpening := GetLocMappingAtKey(address.Hash(), slot)
	ret := statedb.GetState(common.RandomizeSMCBinary, common.BigToHash(locOpening))
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

func GetCandidates(statedb *StateDB) []common.Address {
	slot := slotValidatorMapping["candidates"]
	slotHash := common.BigToHash(new(big.Int).SetUint64(slot))
	arrLength := statedb.GetState(common.MasternodeVotingSMCBinary, slotHash)
	count := arrLength.Big().Uint64()
	rets := make([]common.Address, 0, count)

	for i := uint64(0); i < count; i++ {
		key := GetLocDynamicArrAtElement(slotHash, i, 1)
		ret := statedb.GetState(common.MasternodeVotingSMCBinary, key)
		if !ret.IsZero() {
			rets = append(rets, common.HexToAddress(ret.Hex()))
		}
	}

	return rets
}

func GetCandidateOwner(statedb *StateDB, candidate common.Address) common.Address {
	slot := slotValidatorMapping["validatorsState"]
	// validatorsState[_candidate].owner;
	locValidatorsState := GetLocMappingAtKey(candidate.Hash(), slot)
	locCandidateOwner := locValidatorsState.Add(locValidatorsState, new(big.Int).SetUint64(uint64(0)))
	ret := statedb.GetState(common.MasternodeVotingSMCBinary, common.BigToHash(locCandidateOwner))
	return common.HexToAddress(ret.Hex())
}

func GetCandidateCap(statedb *StateDB, candidate common.Address) *big.Int {
	slot := slotValidatorMapping["validatorsState"]
	// validatorsState[_candidate].cap;
	locValidatorsState := GetLocMappingAtKey(candidate.Hash(), slot)
	locCandidateCap := locValidatorsState.Add(locValidatorsState, new(big.Int).SetUint64(uint64(1)))
	ret := statedb.GetState(common.MasternodeVotingSMCBinary, common.BigToHash(locCandidateCap))
	return ret.Big()
}

func GetVoters(statedb *StateDB, candidate common.Address) []common.Address {
	//mapping(address => address[]) voters;
	slot := slotValidatorMapping["voters"]
	locVoters := GetLocMappingAtKey(candidate.Hash(), slot)
	arrLength := statedb.GetState(common.MasternodeVotingSMCBinary, common.BigToHash(locVoters))
	keys := []common.Hash{}
	for i := uint64(0); i < arrLength.Big().Uint64(); i++ {
		key := GetLocDynamicArrAtElement(common.BigToHash(locVoters), i, 1)
		keys = append(keys, key)
	}
	rets := []common.Address{}
	for _, key := range keys {
		ret := statedb.GetState(common.MasternodeVotingSMCBinary, key)
		rets = append(rets, common.HexToAddress(ret.Hex()))
	}

	return rets
}

func GetVoterCap(statedb *StateDB, candidate, voter common.Address) *big.Int {
	slot := slotValidatorMapping["validatorsState"]
	locValidatorsState := GetLocMappingAtKey(candidate.Hash(), slot)
	locCandidateVoters := locValidatorsState.Add(locValidatorsState, new(big.Int).SetUint64(uint64(2)))
	retByte := crypto.Keccak256(voter.Hash().Bytes(), common.BigToHash(locCandidateVoters).Bytes())
	ret := statedb.GetState(common.MasternodeVotingSMCBinary, common.BytesToHash(retByte))
	return ret.Big()
}

func IncrementMintedRecordNonce(statedb *StateDB) {
	nonce := statedb.GetNonce(common.MintedRecordAddressBinary)
	statedb.SetNonce(common.MintedRecordAddressBinary, nonce+1)
}

var (
	// Storage slot locations (32-byte keys) within MintedRecord SMC
	slotMintedRecordOnsetEpoch             = common.HexToHash("0000000000000000000000000000000000000000000000000000000000000001")
	slotMintedRecordOnsetBlock             = common.HexToHash("0000000000000000000000000000000000000000000000000000000000000002")
	slotMintedRecordPostTotalMintedBase, _ = new(big.Int).SetString("0100000000000000000000000000000000000000000000000000000000000000", 16)
	slotMintedRecordPostTotalBurnedBase, _ = new(big.Int).SetString("0200000000000000000000000000000000000000000000000000000000000000", 16)
	slotMintedRecordPostRewardBlockBase, _ = new(big.Int).SetString("0300000000000000000000000000000000000000000000000000000000000000", 16)
)

func GetMintedRecordOnsetEpoch(statedb *StateDB) common.Hash {
	return statedb.GetState(common.MintedRecordAddressBinary, slotMintedRecordOnsetEpoch)
}

func PutMintedRecordOnsetEpoch(statedb *StateDB, value common.Hash) {
	statedb.SetState(common.MintedRecordAddressBinary, slotMintedRecordOnsetEpoch, value)
}

func GetMintedRecordOnsetBlock(statedb *StateDB) common.Hash {
	return statedb.GetState(common.MintedRecordAddressBinary, slotMintedRecordOnsetBlock)
}

func PutMintedRecordOnsetBlock(statedb *StateDB, value common.Hash) {
	statedb.SetState(common.MintedRecordAddressBinary, slotMintedRecordOnsetBlock, value)
}

func GetPostTotalMinted(statedb *StateDB, epoch uint64) common.Hash {
	hash := common.BigToHash(new(big.Int).Add(slotMintedRecordPostTotalMintedBase, new(big.Int).SetUint64(epoch)))
	v := statedb.GetState(common.MintedRecordAddressBinary, hash)
	return v
}

func PutPostTotalMinted(statedb *StateDB, epoch uint64, value common.Hash) {
	hash := common.BigToHash(new(big.Int).Add(slotMintedRecordPostTotalMintedBase, new(big.Int).SetUint64(epoch)))
	statedb.SetState(common.MintedRecordAddressBinary, hash, value)
}

func GetPostTotalBurned(statedb *StateDB, epoch uint64) common.Hash {
	hash := common.BigToHash(new(big.Int).Add(slotMintedRecordPostTotalBurnedBase, new(big.Int).SetUint64(epoch)))
	v := statedb.GetState(common.MintedRecordAddressBinary, hash)
	return v
}

func PutPostTotalBurned(statedb *StateDB, epoch uint64, value common.Hash) {
	hash := common.BigToHash(new(big.Int).Add(slotMintedRecordPostTotalBurnedBase, new(big.Int).SetUint64(epoch)))
	statedb.SetState(common.MintedRecordAddressBinary, hash, value)
}

func GetPostRewardBlock(statedb *StateDB, epoch uint64) common.Hash {
	hash := common.BigToHash(new(big.Int).Add(slotMintedRecordPostRewardBlockBase, new(big.Int).SetUint64(epoch)))
	v := statedb.GetState(common.MintedRecordAddressBinary, hash)
	return v
}

func PutPostRewardBlock(statedb *StateDB, epoch uint64, value common.Hash) {
	hash := common.BigToHash(new(big.Int).Add(slotMintedRecordPostRewardBlockBase, new(big.Int).SetUint64(epoch)))
	statedb.SetState(common.MintedRecordAddressBinary, hash, value)
}

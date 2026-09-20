package utils

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strconv"

	"github.com/XinFinOrg/XDPoSChain/common"
	xdc_sort "github.com/XinFinOrg/XDPoSChain/common/sort"
	"github.com/XinFinOrg/XDPoSChain/log"
	"github.com/XinFinOrg/XDPoSChain/rlp"
)

func Position(list []common.Address, x common.Address) int {
	for i, item := range list {
		if item == x {
			return i
		}
	}
	return -1
}

func Hop(length, preIndex, curIndex int) int {
	switch {
	case preIndex < curIndex:
		return curIndex - (preIndex + 1)
	case preIndex > curIndex:
		return (length - preIndex) + (curIndex - 1)
	default:
		return length - 1
	}
}

// Extract validators from byte array.
func ExtractValidatorsFromBytes(byteValidators []byte) ([]int64, error) {
	if len(byteValidators)%M2ByteLength != 0 {
		return []int64{}, fmt.Errorf("invalid byte array length %d for validators", len(byteValidators))
	}
	lenValidator := len(byteValidators) / M2ByteLength
	validators := make([]int64, 0, lenValidator)
	for i := range lenValidator {
		trimByte := bytes.Trim(byteValidators[i*M2ByteLength:(i+1)*M2ByteLength], "\x00")
		intNumber, err := strconv.ParseInt(string(trimByte), 10, 64)
		if err != nil {
			log.Error("Can not convert string to integer", "error", err)
			return []int64{}, fmt.Errorf("can not convert string %s to integer: %v", string(trimByte), err)
		}
		validators = append(validators, intNumber)
	}

	return validators, nil
}

// compare 2 signers lists
// return true if they are same elements, otherwise return false
func CompareSignersLists(list1 []common.Address, list2 []common.Address) bool {
	if len(list1) != len(list2) {
		return false
	}
	if len(list1) == 0 {
		return true
	}

	l1 := slices.Clone(list1)
	l2 := slices.Clone(list2)

	slices.SortFunc(l1, common.Address.Cmp)
	slices.SortFunc(l2, common.Address.Cmp)

	return slices.Equal(l1, l2)
}

// Decode extra fields for consensus version >= 2 (XDPoS 2.0 and future versions)
func DecodeBytesExtraFields(b []byte, val interface{}) error {
	if len(b) == 0 {
		return errors.New("extra field is 0 length")
	}
	// Prevent payload attack, limit the size of extra field to 20k bytes.
	// Normal Extrafield payload is less than 7k bytes.
	if len(b) > 20*1024 {
		return errors.New("extra field is too long")
	}

	switch b[0] {
	case 2:
		return rlp.DecodeBytes(b[1:], val)
	default:
		return fmt.Errorf("consensus version %d is not defined, or this block is v1 block", b[0])
	}
}

// SortMasternodesByStakeDesc sorts masternodes by stake, highest first.
//
// The comparator is deliberately non-strict -- ">=", so Less(i, i) is true for
// equal stakes, which sort.Slice does not allow -- because it is the ordering
// the consensus derivations have always produced, and common/sort is a frozen
// copy of the pre-1.19 sort.Slice. For equal stakes the two together yield one
// specific permutation, and that permutation decides which candidates land
// inside the top maxMasternodes. A strict comparator, or the pdqsort in the
// current standard library, reorders equal stakes and therefore changes the
// masternode set derived from a given state: a consensus break.
//
// Every derivation of the top-N set must go through here, including the
// eth_getCandidates and eth_getCandidateStatus RPCs, whose status fields are
// decided by the same boundary.
func SortMasternodesByStakeDesc(ms []Masternode) {
	xdc_sort.Slice(ms, func(i, j int) bool {
		return ms[i].Stake.Cmp(ms[j].Stake) >= 0
	})
}

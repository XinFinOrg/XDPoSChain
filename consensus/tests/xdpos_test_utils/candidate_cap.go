// Package xdpos_test_utils holds helpers shared by the XDPoS engine test
// packages. It is imported by test files only.
package xdpos_test_utils

import (
	"math/big"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/state"
)

// CandidateCapSlot resolves the storage slot of ValidatorState.cap for a
// candidate: validatorsState is slot 1, its owner and isCandidate share the
// first slot of the entry, and cap follows it.
func CandidateCapSlot(candidate common.Address) common.Hash {
	loc := state.GetLocMappingAtKey(candidate.Hash(), 1)
	loc.Add(loc, new(big.Int).SetUint64(uint64(1)))
	return common.BigToHash(loc)
}

// SetCandidateCap writes ValidatorState.cap, which sits one slot after the slot
// that packs owner and isCandidate, the same location StateDB.GetCandidateCap
// reads (core/state/statedb_utils.go).
func SetCandidateCap(statedb *state.StateDB, candidate common.Address, cap *big.Int) {
	statedb.SetState(common.MasternodeVotingSMCBinary, CandidateCapSlot(candidate), common.BigToHash(cap))
}

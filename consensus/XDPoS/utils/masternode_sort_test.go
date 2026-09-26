package utils

import (
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
)

// The tests below pin the order SortMasternodesByStakeDesc produces, not just
// the stake ordering: for equal stakes the permutation itself decides which
// candidates land inside the top maxMasternodes, and every derivation of that
// set -- the consensus ones and the eth_getCandidates / eth_getCandidateStatus
// RPCs -- reads it from this one helper.
//
// They cannot assert the RPC outcome end to end: internal/ethapi has no backend
// stub for the candidate RPCs, so nothing here exercises GetCandidates or
// GetCandidateStatus. What is covered is that those two RPCs and the consensus
// derivations can no longer drift apart, because they call this helper.

func TestSortMasternodesByStakeDesc(t *testing.T) {
	low, mid, high := common.Address{0x1}, common.Address{0x2}, common.Address{0x3}
	ms := []Masternode{
		{Address: low, Stake: big.NewInt(10)},
		{Address: mid, Stake: big.NewInt(20)},
		{Address: high, Stake: big.NewInt(30)},
	}

	SortMasternodesByStakeDesc(ms)

	want := []common.Address{high, mid, low}
	assertOrder(t, ms, want)
}

// Equal stakes must keep the exact order the non-strict comparator produces.
// A failure here means the comparator was made strict or common/sort drifted,
// either of which reorders equal stakes.
func TestSortMasternodesByStakeDescEqualStake(t *testing.T) {
	a, b, c := common.Address{0x1}, common.Address{0x2}, common.Address{0x3}
	ms := []Masternode{
		{Address: a, Stake: big.NewInt(10)},
		{Address: b, Stake: big.NewInt(10)},
		{Address: c, Stake: big.NewInt(10)},
	}

	SortMasternodesByStakeDesc(ms)

	want := []common.Address{c, b, a}
	assertOrder(t, ms, want)
}

// The quicksort path of the vendored common/sort (more than 12 elements) yields
// a different equal-stake order than the insertion path pinned above; pin that
// artifact too, so a drift is caught for large candidate sets as well. The
// expectation is the one the engine_v2 snapshot derivation already relies on.
func TestSortMasternodesByStakeDescEqualStakeLarge(t *testing.T) {
	const n = 15
	ms := make([]Masternode, n)
	for i := range n {
		ms[i] = Masternode{Address: common.Address{byte(i + 1)}, Stake: big.NewInt(10)}
	}

	SortMasternodesByStakeDesc(ms)

	// pinned artifact of the frozen quicksort, not a sorted order
	want := []common.Address{
		{5}, {4}, {3}, {2}, {12}, {6}, {11}, {10}, {9}, {15}, {13}, {14}, {7}, {1}, {8},
	}
	assertOrder(t, ms, want)
}

// A tie must not reorder the stakes around it: the tie group stays where its
// stake ranks, only its internal order follows the pinned artifact.
func TestSortMasternodesByStakeDescTieKeepsStakeRank(t *testing.T) {
	ms := []Masternode{
		{Address: common.Address{0x1}, Stake: big.NewInt(10)},
		{Address: common.Address{0x2}, Stake: big.NewInt(30)},
		{Address: common.Address{0x3}, Stake: big.NewInt(10)},
		{Address: common.Address{0x4}, Stake: big.NewInt(20)},
	}

	SortMasternodesByStakeDesc(ms)

	wantStakes := []int64{30, 20, 10, 10}
	if len(ms) != len(wantStakes) {
		t.Fatalf("masternodes = %v, want %d entries", ms, len(wantStakes))
	}
	for i, want := range wantStakes {
		if ms[i].Stake.Int64() != want {
			t.Fatalf("masternodes = %v, want stakes %v", ms, wantStakes)
		}
	}
}

func assertOrder(t *testing.T, ms []Masternode, want []common.Address) {
	t.Helper()
	if len(ms) != len(want) {
		t.Fatalf("masternodes = %v, want %v", ms, want)
	}
	for i, addr := range want {
		if ms[i].Address != addr {
			t.Fatalf("masternodes = %v, want %v", ms, want)
		}
	}
}

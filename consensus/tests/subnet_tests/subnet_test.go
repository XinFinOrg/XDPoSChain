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

package subnet_tests

import (
	"bytes"
	"errors"
	"math/big"
	"slices"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/accounts"
	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS/utils"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/rlp"
)

func assertAddresses(t *testing.T, what string, got []byte, want []common.Address) {
	t.Helper()
	if gotAddrs := common.ExtractAddressFromBytes(got); !slices.Equal(gotAddrs, want) {
		t.Fatalf("%s: got %v, want %v", what, gotAddrs, want)
	}
}

// A subnet with all masternodes online: the subnet fields appear exactly on
// the blocks the specification names, with the expected contents, and the
// masternode cap applies at the epoch switch.
func TestSubnetHappyPath(t *testing.T) {
	// Five candidates with decreasing stakes, four of them masternodes at
	// genesis, a cap of four.
	h := newSubnetHarness(t, 4, []int64{50_000, 40_000, 30_000, 20_000, 10_000}, 4)
	candidates := h.addrs(h.nodes)
	h.extend(3*testEpoch+testEpoch/2, nil)

	for n := uint64(1); n <= h.head().NumberU64(); n++ {
		header := h.bc.GetHeaderByNumber(n)
		if !header.Subnet {
			t.Fatalf("block %d does not use the subnet layout", n)
		}
		switch {
		case n == 1:
			// Block 1 publishes the genesis snapshot.
			assertAddresses(t, "block 1 next validators", header.NextValidators, h.genesisMNs)
			assertAddresses(t, "block 1 penalties", header.Penalties, nil)
		case n%testEpoch == testEpoch-testGap+1:
			assertAddresses(t, "gap+1 next validators", header.NextValidators, candidates)
			assertAddresses(t, "gap+1 penalties", header.Penalties, nil)
		default:
			if len(header.NextValidators) != 0 || len(header.Penalties) != 0 {
				t.Fatalf("block %d carries next validators or penalties", n)
			}
		}
		if n%testEpoch == 0 {
			assertAddresses(t, "epoch switch validators", header.Validators, candidates[:4])
		} else if len(header.Validators) != 0 {
			t.Fatalf("block %d carries validators", n)
		}
	}

	// The gap blocks stored the stake-sorted candidates and no penalties.
	for gap := uint64(testEpoch - testGap); gap < h.head().NumberU64(); gap += testEpoch {
		snap := h.storedSnapshot(h.bc.GetHeaderByNumber(gap).Hash())
		if !slices.Equal(snap.NextEpochCandidates, candidates) || len(snap.NextEpochPenalties) != 0 {
			t.Fatalf("gap block %d snapshot: candidates %v penalties %v", gap, snap.NextEpochCandidates, snap.NextEpochPenalties)
		}
	}

	// Epoch numbering and lookups follow block numbers.
	v2 := h.engine.EngineV2
	for _, n := range []uint64{0, 1, testEpoch - 1, testEpoch, 2*testEpoch + 3} {
		header := h.bc.GetHeaderByNumber(n)
		isSwitch, epoch, err := v2.IsEpochSwitch(header)
		if err != nil || isSwitch != (n%testEpoch == 0) || epoch != n/testEpoch {
			t.Fatalf("IsEpochSwitch(%d) = %v, %d, %v", n, isSwitch, epoch, err)
		}
		switchNum, epochNum, err := v2.GetCurrentEpochSwitchBlock(h.bc, header.Number)
		if err != nil || switchNum != n-n%testEpoch || epochNum != n/testEpoch {
			t.Fatalf("GetCurrentEpochSwitchBlock(%d) = %d, %d, %v", n, switchNum, epochNum, err)
		}
	}
	for epoch := uint64(0); epoch <= 3; epoch++ {
		info, err := v2.GetBlockByEpochNumber(h.bc, epoch)
		if err != nil || info.Number.Uint64() != epoch*testEpoch {
			t.Fatalf("GetBlockByEpochNumber(%d) = %v, %v", epoch, info, err)
		}
	}
	if mns := v2.GetMasternodes(h.bc, h.head().Header()); !slices.Equal(mns, candidates[:4]) {
		t.Fatalf("GetMasternodes = %v", mns)
	}
	if standby := v2.GetStandbynodes(h.bc, h.head().Header()); !slices.Equal(standby, candidates[4:]) {
		t.Fatalf("GetStandbynodes = %v", standby)
	}

	// Stored headers keep the subnet layout and hash.
	head := h.head()
	enc, err := rlp.EncodeToBytes(head.Header())
	if err != nil {
		t.Fatal(err)
	}
	var dec types.Header
	if err := rlp.DecodeBytes(enc, &dec); err != nil || !dec.Subnet || dec.Hash() != head.Hash() {
		t.Fatalf("head header round trip: subnet %v, hash %v, err %v", dec.Subnet, dec.Hash() == head.Hash(), err)
	}
}

// Headers that break the subnet rules are rejected with the matching error.
func TestSubnetHeaderVerification(t *testing.T) {
	h := newSubnetHarness(t, 4, []int64{50_000, 40_000, 30_000, 20_000, 10_000}, 4)
	candidates := h.addrs(h.nodes)

	verify := func(block *types.Block) error {
		return h.engine.VerifyHeader(h.bc, block.Header(), true)
	}
	expect := func(name string, block *types.Block, want error) {
		t.Helper()
		if err := verify(block); !errors.Is(err, want) {
			t.Fatalf("%s: got %v, want %v", name, err, want)
		}
	}

	// Block 1 must publish the genesis snapshot.
	expect("block 1 without next validators", h.buildBlock(h.head(), blockOpts{mutate: func(hd *types.Header) {
		hd.NextValidators = nil
	}}), utils.ErrNextEpochValidatorsNotLegit)
	expect("block 1 with penalties", h.buildBlock(h.head(), blockOpts{mutate: func(hd *types.Header) {
		hd.Penalties = types.PackAddresses(candidates[:1])
	}}), utils.ErrPenaltiesNotLegit)
	h.extend(1, nil)

	expect("next validators on an ordinary block", h.buildBlock(h.head(), blockOpts{mutate: func(hd *types.Header) {
		hd.NextValidators = types.PackAddresses(candidates)
	}}), utils.ErrInvalidFieldInNonGapPlusOneBlock)
	expect("penalties on an ordinary block", h.buildBlock(h.head(), blockOpts{mutate: func(hd *types.Header) {
		hd.Penalties = types.PackAddresses(candidates[:1])
	}}), utils.ErrInvalidFieldInNonGapPlusOneBlock)
	expect("validators on an ordinary block", h.buildBlock(h.head(), blockOpts{mutate: func(hd *types.Header) {
		hd.Validators = types.PackAddresses(candidates)
	}}), utils.ErrInvalidFieldInNonEpochSwitch)

	// A legacy-layout header is refused even when it is otherwise valid.
	legacy := h.buildBlock(h.head(), blockOpts{})
	legacyHeader := legacy.Header()
	legacyHeader.Subnet = false
	expect("legacy layout", types.NewBlockWithHeader(legacyHeader), utils.ErrInvalidHeaderLayout)

	// The block after the gap block must publish the stored snapshot.
	h.extend(testEpoch-testGap, nil)
	expect("gap+1 without next validators", h.buildBlock(h.head(), blockOpts{mutate: func(hd *types.Header) {
		hd.NextValidators = nil
	}}), utils.ErrNextEpochValidatorsNotLegit)
	expect("gap+1 with an extra candidate", h.buildBlock(h.head(), blockOpts{mutate: func(hd *types.Header) {
		hd.NextValidators = append(hd.NextValidators, common.HexToAddress("0x1234").Bytes()...)
	}}), utils.ErrNextEpochValidatorsNotLegit)
	expect("gap+1 with a made-up penalty", h.buildBlock(h.head(), blockOpts{mutate: func(hd *types.Header) {
		hd.Penalties = types.PackAddresses(candidates[1:2])
	}}), utils.ErrPenaltiesNotLegit)
	// The published candidates are compared as a set.
	reordered := h.buildBlock(h.head(), blockOpts{mutate: func(hd *types.Header) {
		addrs := common.ExtractAddressFromBytes(hd.NextValidators)
		slices.Reverse(addrs)
		hd.NextValidators = types.PackAddresses(addrs)
	}})
	if err := verify(reordered); err != nil {
		t.Fatalf("gap+1 with reordered candidates: %v", err)
	}

	// The epoch switch block must list the masternodes in candidate order.
	h.extend(testEpoch-1, nil)
	expect("epoch switch with reordered validators", h.buildBlock(h.head(), blockOpts{mutate: func(hd *types.Header) {
		addrs := common.ExtractAddressFromBytes(hd.Validators)
		addrs[0], addrs[1] = addrs[1], addrs[0]
		hd.Validators = types.PackAddresses(addrs)
	}}), utils.ErrValidatorsNotLegit)
	expect("epoch switch over the cap", h.buildBlock(h.head(), blockOpts{mutate: func(hd *types.Header) {
		hd.Validators = types.PackAddresses(candidates)
	}}), utils.ErrValidatorsNotLegit)
	expect("epoch switch with penalties", h.buildBlock(h.head(), blockOpts{mutate: func(hd *types.Header) {
		hd.Penalties = types.PackAddresses(candidates[4:])
	}}), utils.ErrInvalidFieldInNonGapPlusOneBlock)
	good := h.buildBlock(h.head(), blockOpts{})
	if err := verify(good); err != nil {
		t.Fatalf("valid epoch switch block: %v", err)
	}
	h.insert(good)
	if !bytes.Equal(h.head().Header().Validators, types.PackAddresses(candidates[:4])) {
		t.Fatal("epoch switch block did not keep its validators")
	}
}

// The engine's own Prepare, the miner path, fills the subnet fields exactly as
// the specification-built blocks of the harness carry them.
func TestSubnetPrepareMatchesSpecification(t *testing.T) {
	h := newSubnetHarness(t, 4, []int64{50_000, 40_000, 30_000, 20_000, 10_000}, 4)
	v2 := h.engine.EngineV2
	for _, target := range []uint64{1, 2, testEpoch - testGap, testEpoch - testGap + 1, testEpoch, testEpoch + 1, 2*testEpoch - testGap + 1, 2 * testEpoch} {
		h.extend(target-1, nil)
		parent := h.head()
		qc := h.quorumCert(parent)
		if err := v2.SyncInfoHandler(h.bc, &types.SyncInfo{HighestQuorumCert: qc, HighestTimeoutCert: &types.TimeoutCert{}}); err != nil {
			t.Fatalf("block %d: sync info: %v", target, err)
		}
		want := h.buildBlock(parent, blockOpts{})
		leader := h.byAddr[want.Coinbase()]
		h.engine.Authorize(leader.addr, func(_ accounts.Account, hash []byte) ([]byte, error) {
			return crypto.Sign(hash, leader.key)
		})

		header := &types.Header{
			ParentHash: parent.Hash(),
			Number:     new(big.Int).SetUint64(target),
			GasLimit:   testGasLimit,
			Coinbase:   leader.addr,
		}
		if err := h.engine.Prepare(h.bc, header); err != nil {
			t.Fatalf("block %d: prepare: %v", target, err)
		}
		if !header.Subnet {
			t.Fatalf("block %d: prepared header does not use the subnet layout", target)
		}
		wantHeader := want.Header()
		for _, field := range []struct {
			name      string
			got, want []byte
		}{
			{"validators", header.Validators, wantHeader.Validators},
			{"nextValidators", header.NextValidators, wantHeader.NextValidators},
			{"penalties", header.Penalties, wantHeader.Penalties},
		} {
			if !bytes.Equal(field.got, field.want) {
				t.Fatalf("block %d: prepared %s %x, want %x", target, field.name, field.got, field.want)
			}
		}
		h.insert(want)
	}
}

// A masternode that stops mining is penalized at the next gap block, the
// block after it publishes the penalty, the next epoch switch drops it and the
// penalty carries over while the node stays away.
func TestSubnetPenaltyLifecycle(t *testing.T) {
	h := newSubnetHarness(t, 4, []int64{50_000, 40_000, 30_000, 20_000, 10_000}, 4)
	candidates := h.addrs(h.nodes)
	offline := candidates[1]

	// Everyone mines through the first epoch, then the second masternode goes
	// offline from the epoch switch block on: its rounds are skipped and it
	// signs nothing.
	h.extend(testEpoch-1, nil)
	h.offline[offline] = true
	h.extend(4*testEpoch+testEpoch/2, nil)

	header := func(n uint64) *types.Header { return h.bc.GetHeaderByNumber(n) }
	// Gap block 30: the walk covers blocks 29 down to 10, the second segment
	// (10..19) has everyone mining but the epoch starting at 20 does not.
	snap := h.storedSnapshot(header(testEpoch + testEpoch - testGap).Hash())
	if !slices.Equal(snap.NextEpochPenalties, []common.Address{offline}) {
		t.Fatalf("gap block %d penalties %v, want [%v]", 2*testEpoch-testGap, snap.NextEpochPenalties, offline)
	}
	assertAddresses(t, "gap+1 penalties", header(2*testEpoch-testGap+1).Penalties, []common.Address{offline})
	assertAddresses(t, "gap+1 candidates", header(2*testEpoch-testGap+1).NextValidators, candidates)

	// The epoch switch drops the offline node and promotes the standby one.
	without := slices.DeleteFunc(slices.Clone(candidates), func(a common.Address) bool { return a == offline })
	assertAddresses(t, "epoch 2 validators", header(2*testEpoch).Validators, without[:4])
	if !slices.Equal(h.engine.EngineV2.GetPenalties(h.bc, header(2*testEpoch+1)), []common.Address{offline}) {
		t.Fatal("epoch 2 does not report the penalty")
	}

	// It is no longer a masternode, so only the carry-over keeps it penalized.
	for _, epoch := range []uint64{3, 4} {
		assertAddresses(t, "carried penalties", header(epoch*testEpoch-testGap+1).Penalties, []common.Address{offline})
		assertAddresses(t, "validators while penalized", header(epoch*testEpoch).Validators, without[:4])
	}
}

// A penalized node comes back once it sends a signing transaction for one of
// the MergeSignRange blocks of the range the gap block looks at.
func TestSubnetPenaltyComeback(t *testing.T) {
	h := newSubnetHarness(t, 4, []int64{50_000, 40_000, 30_000, 20_000, 10_000}, 4)
	candidates := h.addrs(h.nodes)
	offline := h.byAddr[candidates[1]]

	h.extend(testEpoch-1, nil)
	h.offline[offline.addr] = true
	h.extend(2*testEpoch+1, nil)
	header := func(n uint64) *types.Header { return h.bc.GetHeaderByNumber(n) }
	assertAddresses(t, "first penalty", header(2*testEpoch-testGap+1).Penalties, []common.Address{offline.addr})

	// Block 45 is a MergeSignRange block before gap block 50; a signing
	// transaction for it in block 46 brings the node back.
	const signed = 3 * common.MergeSignRange
	h.extend(signed, nil)
	signedHash := h.head().Hash()
	h.extend(signed+1, func(n uint64) blockOpts {
		return blockOpts{txs: func(*types.Header) []*types.Transaction {
			return []*types.Transaction{h.signingTx(offline, h.stateAtHead().GetNonce(offline.addr), signed, signedHash)}
		}}
	})
	h.extend(3*testEpoch-testGap+1, nil)
	if p := header(3*testEpoch - testGap + 1).Penalties; len(p) != 0 {
		t.Fatalf("penalties after comeback: %v", common.ExtractAddressFromBytes(p))
	}

	// A signing transaction for a block that is not a MergeSignRange block
	// does not count.
	h.extend(4*testEpoch+1, nil)
	h.extend(5*testEpoch-testGap-3, func(n uint64) blockOpts {
		if n != 5*testEpoch-testGap-3 {
			return blockOpts{}
		}
		target := h.head()
		return blockOpts{txs: func(*types.Header) []*types.Transaction {
			return []*types.Transaction{h.signingTx(offline, h.stateAtHead().GetNonce(offline.addr), target.NumberU64(), target.Hash())}
		}}
	})
	h.extend(5*testEpoch-testGap+1, nil)
	assertAddresses(t, "penalty without a valid comeback", header(5*testEpoch-testGap+1).Penalties, []common.Address{offline.addr})
}

// The cap bounds the masternodes and duplicates in the contract never count
// twice.
func TestSubnetMasternodeCap(t *testing.T) {
	h := newSubnetHarness(t, 2, []int64{50_000, 40_000, 30_000, 20_000}, 3)
	candidates := h.addrs(h.nodes)
	h.extend(2*testEpoch, nil)
	assertAddresses(t, "capped validators", h.bc.GetHeaderByNumber(testEpoch).Validators, candidates[:2])
	assertAddresses(t, "capped validators", h.bc.GetHeaderByNumber(2*testEpoch).Validators, candidates[:2])
	// Genesis listed three masternodes; the cap only applies from epoch 1.
	if mns := h.engine.EngineV2.GetMasternodes(h.bc, h.bc.GetHeaderByNumber(1)); !slices.Equal(mns, candidates[:3]) {
		t.Fatalf("epoch 0 masternodes %v", mns)
	}
}

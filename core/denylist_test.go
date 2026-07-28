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

package core

import (
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/params"
)

func TestIsDeniedGatesEachVersionOnItsOwnActivation(t *testing.T) {
	t.Parallel()

	version1 := common.HexToAddress("0x5248bfb72fd4f234e062d3e9bb76f08643004fcd")
	version2 := common.HexToAddress("0xdb6552adc538e39b4f2a58aea3cd365def1be89b")
	unlisted := common.HexToAddress("0x0000000000000000000000000000000000000001")

	activations := func(pairs map[uint8]int64) map[uint8]*big.Int {
		scheduled := make(map[uint8]*big.Int, len(pairs))
		for version, block := range pairs {
			scheduled[version] = big.NewInt(block)
		}
		return scheduled
	}

	tests := []struct {
		name    string
		config  *params.ChainConfig
		num     *big.Int
		address common.Address
		want    bool
	}{
		{"version 1 before its activation", &params.ChainConfig{DenylistBlock: big.NewInt(10)}, big.NewInt(9), version1, false},
		{"version 1 at its activation", &params.ChainConfig{DenylistBlock: big.NewInt(10)}, big.NewInt(10), version1, true},
		{"version 1 unaffected by version 2 schedule", &params.ChainConfig{DenylistActivations: activations(map[uint8]int64{2: 0})}, big.NewInt(10), version1, false},

		{"version 2 before its activation", &params.ChainConfig{DenylistActivations: activations(map[uint8]int64{2: 10})}, big.NewInt(9), version2, false},
		{"version 2 at its activation", &params.ChainConfig{DenylistActivations: activations(map[uint8]int64{2: 10})}, big.NewInt(10), version2, true},
		{"version 2 unaffected by version 1 fork", &params.ChainConfig{DenylistBlock: big.NewInt(0)}, big.NewInt(10), version2, false},

		// An unscheduled version is never active, which is why shipping the
		// addresses ahead of the fork decision is inert.
		{"unscheduled versions deny nothing", &params.ChainConfig{}, big.NewInt(1_000_000), version2, false},
		{"version absent from a populated schedule", &params.ChainConfig{DenylistActivations: activations(map[uint8]int64{3: 0})}, big.NewInt(10), version2, false},
		{"version scheduled at nil is unscheduled", &params.ChainConfig{DenylistActivations: map[uint8]*big.Int{2: nil}}, big.NewInt(10), version2, false},

		{"unlisted address is never denied", &params.ChainConfig{DenylistBlock: big.NewInt(0), DenylistActivations: activations(map[uint8]int64{2: 0})}, big.NewInt(10), unlisted, false},

		// A nil height means the height is unknown, so every version applies.
		{"nil height applies version 1", &params.ChainConfig{}, nil, version1, true},
		{"nil height applies version 2", &params.ChainConfig{}, nil, version2, true},
		{"nil height still ignores unlisted", &params.ChainConfig{}, nil, unlisted, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsDeniedSender(tt.config, tt.num, &tt.address); got != tt.want {
				t.Errorf("IsDeniedSender = %v, want %v", got, tt.want)
			}
			if got := IsDeniedReceiver(tt.config, tt.num, &tt.address); got != tt.want {
				t.Errorf("IsDeniedReceiver = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestIsDeniedNilAddress covers contract creation (nil recipient) and senders
// whose signature could not be recovered.
func TestIsDeniedNilAddress(t *testing.T) {
	t.Parallel()

	config := &params.ChainConfig{
		DenylistBlock:       big.NewInt(0),
		DenylistActivations: map[uint8]*big.Int{2: big.NewInt(0)},
	}
	if IsDeniedSender(config, big.NewInt(10), nil) {
		t.Error("expected nil sender to not be denied")
	}
	if IsDeniedReceiver(config, big.NewInt(10), nil) {
		t.Error("expected nil receiver to not be denied")
	}
	if IsDeniedReceiver(config, nil, nil) {
		t.Error("expected nil receiver at unknown height to not be denied")
	}
}

// TestDenylistActivationsSurviveCloneAndCompare covers the config plumbing the
// schedule depends on: a clone must not alias the source heights, and an equal
// schedule must compare equal so genesis setup does not report a spurious
// mismatch.
func TestDenylistActivationsSurviveCloneAndCompare(t *testing.T) {
	t.Parallel()

	original := &params.ChainConfig{
		ChainID:             big.NewInt(1),
		DenylistActivations: map[uint8]*big.Int{2: big.NewInt(100)},
	}
	clone := original.Clone()
	if clone.DenylistActivations[2] == original.DenylistActivations[2] {
		t.Fatal("expected clone to deep-copy the activation height")
	}
	if !original.Equal(clone) {
		t.Fatal("expected clone to compare equal")
	}

	clone.DenylistActivations[2].SetInt64(200)
	if original.DenylistActivations[2].Int64() != 100 {
		t.Fatalf("original activation mutated: have %v want 100", original.DenylistActivations[2])
	}
	if original.Equal(clone) {
		t.Fatal("expected a rescheduled version to compare unequal")
	}

	// An absent version and one scheduled at nil are both unscheduled.
	if !(&params.ChainConfig{ChainID: big.NewInt(1)}).Equal(&params.ChainConfig{
		ChainID:             big.NewInt(1),
		DenylistActivations: map[uint8]*big.Int{2: nil},
	}) {
		t.Fatal("expected absent and nil-scheduled versions to compare equal")
	}
}

// TestCheckConfigForkOrderValidatesDenylistSchedule covers the two rules the
// activation schedule has: version 1 belongs to DenylistBlock, and versions must
// activate in order.
//
// Ordering is a sanity rule rather than a safety one — each version gates only its
// own addresses, so an out-of-order schedule is internally consistent — but versions
// are created in sequence as addresses are discovered, so a later version activating
// before an earlier one is a mistyped height.
func TestCheckConfigForkOrderValidatesDenylistSchedule(t *testing.T) {
	t.Parallel()

	// DenylistBlock is 38383838 on mainnet and heads the ordering chain.
	tests := []struct {
		name       string
		schedule   map[uint8]*big.Int
		wantReject bool
	}{
		{"version 1 may not be scheduled in the map", map[uint8]*big.Int{1: big.NewInt(100000000)}, true},
		{"version 2 after version 1", map[uint8]*big.Int{2: big.NewInt(120000000)}, false},
		{"version 2 before version 1", map[uint8]*big.Int{2: big.NewInt(100)}, true},
		{"versions in order", map[uint8]*big.Int{2: big.NewInt(120000000), 3: big.NewInt(130000000)}, false},
		{"versions at the same height", map[uint8]*big.Int{2: big.NewInt(120000000), 3: big.NewInt(120000000)}, false},
		{"version 3 before version 2", map[uint8]*big.Int{2: big.NewInt(130000000), 3: big.NewInt(120000000)}, true},
		{"unscheduled version is skipped", map[uint8]*big.Int{2: nil, 3: big.NewInt(120000000)}, false},
		{"gap in versions is allowed", map[uint8]*big.Int{4: big.NewInt(120000000)}, false},
		{"empty schedule", map[uint8]*big.Int{}, false},
		{"nil schedule", nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := params.XDCMainnetChainConfig.Clone()
			cfg.DenylistActivations = tt.schedule
			err := cfg.CheckConfigForkOrder()
			if tt.wantReject && err == nil {
				t.Fatalf("expected schedule %v to be rejected", tt.schedule)
			}
			if !tt.wantReject && err != nil {
				t.Fatalf("expected schedule %v to be accepted, have %v", tt.schedule, err)
			}
		})
	}
}

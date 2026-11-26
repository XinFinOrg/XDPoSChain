// Copyright 2017 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package params

import (
	"math"
	"math/big"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCheckCompatible(t *testing.T) {
	type test struct {
		stored, new   *ChainConfig
		headBlock     uint64
		headTimestamp uint64
		wantErr       *ConfigCompatError
	}
	tests := []test{
		{stored: AllEthashProtocolChanges, new: AllEthashProtocolChanges, headBlock: 0, headTimestamp: 0, wantErr: nil},
		{stored: AllEthashProtocolChanges, new: AllEthashProtocolChanges, headBlock: 0, headTimestamp: uint64(time.Now().Unix()), wantErr: nil},
		{stored: AllEthashProtocolChanges, new: AllEthashProtocolChanges, headBlock: 100, wantErr: nil},
		{
			stored:    &ChainConfig{EIP150Block: big.NewInt(10)},
			new:       &ChainConfig{EIP150Block: big.NewInt(20)},
			headBlock: 9,
			wantErr:   nil,
		},
		{
			stored:    AllEthashProtocolChanges,
			new:       &ChainConfig{HomesteadBlock: nil},
			headBlock: 3,
			wantErr: &ConfigCompatError{
				What:          "Homestead fork block",
				StoredBlock:   big.NewInt(0),
				NewBlock:      nil,
				RewindToBlock: 0,
			},
		},
		{
			stored:    AllEthashProtocolChanges,
			new:       &ChainConfig{HomesteadBlock: big.NewInt(1)},
			headBlock: 3,
			wantErr: &ConfigCompatError{
				What:          "Homestead fork block",
				StoredBlock:   big.NewInt(0),
				NewBlock:      big.NewInt(1),
				RewindToBlock: 0,
			},
		},
		{
			stored:    &ChainConfig{HomesteadBlock: big.NewInt(30), EIP150Block: big.NewInt(10)},
			new:       &ChainConfig{HomesteadBlock: big.NewInt(25), EIP150Block: big.NewInt(20)},
			headBlock: 25,
			wantErr: &ConfigCompatError{
				What:          "EIP150 fork block",
				StoredBlock:   big.NewInt(10),
				NewBlock:      big.NewInt(20),
				RewindToBlock: 9,
			},
		},
		{
			stored:    &ChainConfig{ConstantinopleBlock: big.NewInt(30)},
			new:       &ChainConfig{ConstantinopleBlock: big.NewInt(30), PetersburgBlock: big.NewInt(30)},
			headBlock: 40,
			wantErr:   nil,
		},
		{
			stored:    &ChainConfig{ConstantinopleBlock: big.NewInt(30)},
			new:       &ChainConfig{ConstantinopleBlock: big.NewInt(30), PetersburgBlock: big.NewInt(31)},
			headBlock: 40,
			wantErr: &ConfigCompatError{
				What:          "Petersburg fork block",
				StoredBlock:   nil,
				NewBlock:      big.NewInt(31),
				RewindToBlock: 30,
			},
		},
		{
			stored:        &ChainConfig{ShanghaiTime: newUint64(10)},
			new:           &ChainConfig{ShanghaiTime: newUint64(20)},
			headTimestamp: 9,
			wantErr:       nil,
		},
		{
			stored:        &ChainConfig{ShanghaiTime: newUint64(10)},
			new:           &ChainConfig{ShanghaiTime: newUint64(20)},
			headTimestamp: 25,
			wantErr: &ConfigCompatError{
				What:         "Shanghai fork timestamp",
				StoredTime:   newUint64(10),
				NewTime:      newUint64(20),
				RewindToTime: 9,
			},
		},
	}

	for _, test := range tests {
		err := test.stored.CheckCompatible(test.new, test.headBlock, test.headTimestamp)
		if !reflect.DeepEqual(err, test.wantErr) {
			t.Errorf("error mismatch:\nstored: %v\nnew: %v\nheadBlock: %v\nheadTimestamp: %v\nerr: %v\nwant: %v", test.stored, test.new, test.headBlock, test.headTimestamp, err, test.wantErr)
		}
	}
}

func TestConfigRules(t *testing.T) {
	c := &ChainConfig{
		LondonBlock:  new(big.Int),
		ShanghaiTime: newUint64(500),
	}
	var stamp uint64
	if r := c.Rules(big.NewInt(0), true, stamp); r.IsShanghai {
		t.Errorf("expected %v to not be shanghai", stamp)
	}
	stamp = 500
	if r := c.Rules(big.NewInt(0), true, stamp); !r.IsShanghai {
		t.Errorf("expected %v to be shanghai", stamp)
	}
	stamp = math.MaxInt64
	if r := c.Rules(big.NewInt(0), true, stamp); !r.IsShanghai {
		t.Errorf("expected %v to be shanghai", stamp)
	}
}

func TestTimestampCompatError(t *testing.T) {
	require.Equal(t, new(ConfigCompatError).Error(), "")

	errWhat := "Shanghai fork timestamp"
	require.Equal(t, newTimestampCompatError(errWhat, nil, newUint64(1681338455)).Error(),
		"mismatching Shanghai fork timestamp in database (have timestamp nil, want timestamp 1681338455, rewindto timestamp 1681338454)")

	require.Equal(t, newTimestampCompatError(errWhat, newUint64(1681338455), nil).Error(),
		"mismatching Shanghai fork timestamp in database (have timestamp 1681338455, want timestamp nil, rewindto timestamp 1681338454)")

	require.Equal(t, newTimestampCompatError(errWhat, newUint64(1681338455), newUint64(600624000)).Error(),
		"mismatching Shanghai fork timestamp in database (have timestamp 1681338455, want timestamp 600624000, rewindto timestamp 600623999)")

	require.Equal(t, newTimestampCompatError(errWhat, newUint64(0), newUint64(1681338455)).Error(),
		"mismatching Shanghai fork timestamp in database (have timestamp 0, want timestamp 1681338455, rewindto timestamp 0)")
}

// TestIsFrameTx verifies that the EIP-8141 frame-transaction fork is inactive
// by default and only activates at-or-after the configured timestamp.
func TestIsFrameTx(t *testing.T) {
	num := big.NewInt(1)
	// nil fork time (every preset network default): never active.
	cfg := &ChainConfig{ChainID: big.NewInt(1), LondonBlock: big.NewInt(0)}
	if cfg.IsFrameTx(num, 0) || cfg.IsFrameTx(num, math.MaxUint64) {
		t.Fatal("FrameTx fork active with nil FrameTxTime")
	}
	if rules := cfg.Rules(num, true, math.MaxUint64); rules.IsFrameTx {
		t.Fatal("Rules.IsFrameTx set with nil FrameTxTime")
	}
	// Scheduled in the future: inactive before, active at, active after.
	future := uint64(1_000_000)
	cfg.FrameTxTime = &future
	if cfg.IsFrameTx(num, future-1) {
		t.Fatal("FrameTx fork active before its timestamp")
	}
	if !cfg.IsFrameTx(num, future) || !cfg.IsFrameTx(num, future+1) {
		t.Fatal("FrameTx fork inactive at/after its timestamp")
	}
	// Pre-London chain: the fork must not activate regardless of time.
	preLondon := &ChainConfig{ChainID: big.NewInt(1), LondonBlock: big.NewInt(100), FrameTxTime: &future}
	if preLondon.IsFrameTx(num, future+1) {
		t.Fatal("FrameTx fork active on pre-London chain")
	}
}

// TestIsBogota verifies that the EIP-5920 (PAY opcode) Bogotá fork is
// inactive by default, activates at-or-after its timestamp, and — unlike the
// merge-gated timestamp forks — is NOT gated on the post-merge
// zero-difficulty signal: XDPoS headers always carry difficulty 1/2, so an
// isMerge-gated Rules field would be permanently false on every XDC chain
// (the documented IsFrameTx trap; see the comment at config.go Rules()).
func TestIsBogota(t *testing.T) {
	num := big.NewInt(1)
	// nil fork time (every preset network default): never active.
	cfg := &ChainConfig{ChainID: big.NewInt(1), LondonBlock: big.NewInt(0)}
	if cfg.IsBogota(num, 0) || cfg.IsBogota(num, math.MaxUint64) {
		t.Fatal("Bogota fork active with nil BogotaTime")
	}
	if rules := cfg.Rules(num, true, math.MaxUint64); rules.IsBogota {
		t.Fatal("Rules.IsBogota set with nil BogotaTime")
	}
	if rules := cfg.Rules(num, false, math.MaxUint64); rules.IsBogota {
		t.Fatal("Rules.IsBogota set with nil BogotaTime (isMerge=false)")
	}
	// Scheduled in the future: inactive before, active at, active after.
	future := uint64(1_000_000)
	cfg.BogotaTime = &future
	if cfg.IsBogota(num, future-1) {
		t.Fatal("Bogota fork active before its timestamp")
	}
	if !cfg.IsBogota(num, future) || !cfg.IsBogota(num, future+1) {
		t.Fatal("Bogota fork inactive at/after its timestamp")
	}
	// NOT merge-gated: the XDPoS-shaped header (isMerge=false) must still see
	// the fork once scheduled. This is the regression pin for the
	// `isMerge && c.IsBogota(...)` defect.
	if rules := cfg.Rules(num, false, future+1); !rules.IsBogota {
		t.Fatal("Rules.IsBogota not set with isMerge=false (merge-gated defect)")
	}
	if rules := cfg.Rules(num, true, future+1); !rules.IsBogota {
		t.Fatal("Rules.IsBogota not set with isMerge=true")
	}
	// Pre-London chain: the fork must not activate regardless of time.
	preLondon := &ChainConfig{ChainID: big.NewInt(1), LondonBlock: big.NewInt(100), BogotaTime: &future}
	if preLondon.IsBogota(num, future+1) {
		t.Fatal("Bogota fork active on pre-London chain")
	}
	if rules := preLondon.Rules(num, false, future+1); rules.IsBogota {
		t.Fatal("Rules.IsBogota set on pre-London chain")
	}
}

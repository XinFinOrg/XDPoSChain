// Copyright 2016 The go-ethereum Authors
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
	"errors"
	"math"
	"math/big"
	"strings"
	"testing"
)

func TestCheckSchedule(t *testing.T) {
	for _, test := range []struct {
		name     string
		schedule *XDPoSConfig
		wantErr  bool
		wantMsg  string
	}{
		{name: "nil schedule", schedule: nil},
		{name: "default schedule", schedule: &XDPoSConfig{Epoch: 900, Gap: 450}},
		{name: "smallest usable schedule", schedule: &XDPoSConfig{Epoch: 2, Gap: 1}},
		{name: "epoch above the int64 range", schedule: &XDPoSConfig{Epoch: math.MaxUint64, Gap: 450}},
		{
			name:     "zero gap",
			schedule: &XDPoSConfig{Epoch: 900, Gap: 0},
			wantErr:  true,
			wantMsg:  "invalid XDPoS schedule: XDPoS.Gap 0 designates no gap block inside XDPoS.Epoch 900 (want 1 <= Gap < Epoch)",
		},
		{
			name:     "gap equal to the epoch",
			schedule: &XDPoSConfig{Epoch: 900, Gap: 900},
			wantErr:  true,
			wantMsg:  "invalid XDPoS schedule: XDPoS.Gap 900 puts the gap trigger on the epoch switch block, which would have to consume the candidate set it samples (want 1 <= Gap < Epoch)",
		},
		{
			name:     "gap above the epoch",
			schedule: &XDPoSConfig{Epoch: 900, Gap: 901},
			wantErr:  true,
			wantMsg:  "invalid XDPoS schedule: XDPoS.Gap 901 designates no gap block inside XDPoS.Epoch 900 (want 1 <= Gap < Epoch)",
		},
		{
			name:     "zero epoch",
			schedule: &XDPoSConfig{Epoch: 0, Gap: 450},
			wantErr:  true,
			wantMsg:  "invalid XDPoS schedule: XDPoS.Epoch is unset, so no gap block fits (want 1 <= Gap < Epoch)",
		},
		{
			name:     "zero epoch and zero gap",
			schedule: &XDPoSConfig{Epoch: 0, Gap: 0},
			wantErr:  true,
			wantMsg:  "invalid XDPoS schedule: XDPoS.Epoch is unset, so no gap block fits (want 1 <= Gap < Epoch)",
		},
		{
			name:     "epoch of one",
			schedule: &XDPoSConfig{Epoch: 1, Gap: 1},
			wantErr:  true,
			wantMsg:  "invalid XDPoS schedule: XDPoS.Epoch 1 leaves no gap block (want Epoch >= 2 so that 1 <= Gap < Epoch is satisfiable)",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := test.schedule.CheckSchedule()
			if !test.wantErr {
				if err != nil {
					t.Fatalf("CheckSchedule = %v, want no error", err)
				}
				return
			}
			if !errors.Is(err, ErrInvalidEpochGap) {
				t.Fatalf("CheckSchedule = %v, want ErrInvalidEpochGap", err)
			}
			if test.wantMsg != "" && err.Error() != test.wantMsg {
				t.Errorf("error = %q, want %q", err, test.wantMsg)
			}
		})
	}
}

// TestCheckConfigForkOrderRejectsInvalidSchedule pins the gate on the config
// level: every built-in XDPoS config still passes, and the same configs fail
// once their schedule leaves the bound.
func TestCheckConfigForkOrderRejectsInvalidSchedule(t *testing.T) {
	for _, test := range []struct {
		name string
		cfg  *ChainConfig
	}{
		{name: "XDCMainnetChainConfig", cfg: XDCMainnetChainConfig},
		{name: "AllDevChainProtocolChanges", cfg: AllDevChainProtocolChanges},
		{name: "TestnetChainConfig", cfg: TestnetChainConfig},
		{name: "DevnetChainConfig", cfg: DevnetChainConfig},
		{name: "LocalnetChainConfig", cfg: LocalnetChainConfig},
		{name: "TestXDPoSMockChainConfig", cfg: TestXDPoSMockChainConfig},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := test.cfg.CheckConfigForkOrder(); err != nil {
				t.Fatalf("built-in config rejected: %v", err)
			}
			for _, mutate := range []struct {
				name  string
				apply func(*XDPoSConfig)
			}{
				{name: "zero gap", apply: func(c *XDPoSConfig) { c.Gap = 0 }},
				{name: "zero epoch", apply: func(c *XDPoSConfig) { c.Epoch = 0 }},
				{name: "gap equal to the epoch", apply: func(c *XDPoSConfig) { c.Gap = c.Epoch }},
				{name: "gap above the epoch", apply: func(c *XDPoSConfig) { c.Gap = c.Epoch + 1 }},
			} {
				t.Run(mutate.name, func(t *testing.T) {
					clone := test.cfg.Clone()
					mutate.apply(clone.XDPoS)
					if err := clone.CheckConfigForkOrder(); !errors.Is(err, ErrInvalidEpochGap) {
						t.Fatalf("CheckConfigForkOrder = %v, want ErrInvalidEpochGap", err)
					}
				})
			}
		})
	}
}

// TestSwitchEpochFor pins the pairing arithmetic the puppeth wizard derives
// XDPoS.V2.SwitchEpoch with: the quotient of the big.Int block by the epoch, and
// whether that quotient is a uint64 at all.
func TestSwitchEpochFor(t *testing.T) {
	for _, test := range []struct {
		name  string
		block *big.Int
		epoch uint64
		want  *big.Int // nil when the quotient does not fit in a uint64
	}{
		{name: "nil block", block: nil, epoch: 900},
		{name: "zero epoch", block: big.NewInt(900), epoch: 0},
		{name: "genesis block", block: big.NewInt(0), epoch: 900, want: big.NewInt(0)},
		{name: "inside the first epoch", block: big.NewInt(899), epoch: 900, want: big.NewInt(0)},
		{name: "epoch switch block", block: big.NewInt(900), epoch: 900, want: big.NewInt(1)},
		{name: "last block of the second epoch", block: big.NewInt(1799), epoch: 900, want: big.NewInt(1)},
		{name: "quotient one above the uint64 range", block: new(big.Int).Lsh(big.NewInt(1), 64), epoch: 1},
		{name: "negative block", block: big.NewInt(-1), epoch: 900},
		{name: "epoch above the int64 range", block: new(big.Int).Lsh(big.NewInt(1), 64), epoch: math.MaxUint64, want: big.NewInt(1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, fits := SwitchEpochFor(test.block, test.epoch)
			if test.want == nil {
				if fits {
					t.Fatalf("SwitchEpochFor(%v, %d) = %v, true, want no uint64 quotient", test.block, test.epoch, got)
				}
				return
			}
			if !fits {
				t.Fatalf("SwitchEpochFor(%v, %d) = %v, false, want %v", test.block, test.epoch, got, test.want)
			}
			if got.Cmp(test.want) != 0 {
				t.Errorf("SwitchEpochFor(%v, %d) = %v, want %v", test.block, test.epoch, got, test.want)
			}
		})
	}
}

// TestCheckSwitchBlockAlignment pins the rule the puppeth prompt and
// CheckConfigForkOrder now share: the switch block starts an epoch. The sign is
// not part of it - the remainder runs on the big.Int, where Euclidean Mod keeps
// a block and its absolute value equally divisible - so the wizard refuses a
// negative block separately and this rule judges divisibility only.
func TestCheckSwitchBlockAlignment(t *testing.T) {
	for _, test := range []struct {
		name     string
		block    *big.Int
		epoch    uint64
		want     string // substring the refusal must carry, empty when accepted
		sentinel error  // the sentinel the refusal must wrap
	}{
		{name: "nil block", block: nil, epoch: 900, want: "XDPoS.V2.SwitchBlock is unset", sentinel: ErrMissingForkSwitch},
		{name: "zero epoch", block: big.NewInt(900), epoch: 0, want: "XDPoS.Epoch is unset", sentinel: ErrMissingForkSwitch},
		{name: "genesis block", block: big.NewInt(0), epoch: 900},
		{name: "epoch switch block", block: big.NewInt(900), epoch: 900},
		{name: "inside the epoch", block: big.NewInt(899), epoch: 900, want: "not aligned to XDPoS.Epoch 900", sentinel: ErrWrongForkSwitchOrder},
		// A negative block is how a config below the genesis block spells "v2
		// from block 0": BlockConsensusVersion compares block > SwitchBlock, so
		// 0 still starts v1 at the genesis block. Euclidean Mod keeps a negative
		// multiple of the epoch divisible, so it passes here and the sign is
		// left to the wizard.
		{name: "negative block below the genesis switch", block: big.NewInt(-2), epoch: 2},
		{name: "negative multiple of the epoch", block: big.NewInt(-900), epoch: 900},
		{name: "negative block", block: big.NewInt(-1), epoch: 900, want: "not aligned to XDPoS.Epoch 900", sentinel: ErrWrongForkSwitchOrder},
		// A positive block past 2^64 is judged by the epoch it names: the low
		// 64 bits are aligned here, but the quotient does not fit a uint64.
		{name: "positive block beyond the uint64 range", block: new(big.Int).Lsh(big.NewInt(1), 64), epoch: 1, want: "no uint64 can hold", sentinel: ErrWrongForkSwitchOrder},
		// The same block with an epoch large enough that its quotient fits is
		// judged by its real remainder: 2^64 mod (2^64-1) is 1, so the low 64
		// bits reading zero does not make it aligned.
		{name: "positive block beyond the uint64 range with a representable epoch", block: new(big.Int).Lsh(big.NewInt(1), 64), epoch: math.MaxUint64, want: "not aligned to XDPoS.Epoch", sentinel: ErrWrongForkSwitchOrder},
		// The converse: 2^64+884 is a multiple of 900 even though its low 64
		// bits, 884, are not.
		{name: "aligned block beyond the uint64 range", block: new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 64), big.NewInt(884)), epoch: 900},
		// A positive block that fails both checks reports the quotient first,
		// which is the order the rule documents: the block is judged by the
		// epoch it names before the remainder runs.
		{name: "positive block beyond the uint64 range and misaligned", block: new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 65), big.NewInt(1)), epoch: 2, want: "no uint64 can hold", sentinel: ErrWrongForkSwitchOrder},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := CheckSwitchBlockAlignment(test.block, test.epoch)
			if test.want == "" {
				if err != nil {
					t.Fatalf("CheckSwitchBlockAlignment(%v, %d) = %v, want no error", test.block, test.epoch, err)
				}
				return
			}
			if !errors.Is(err, test.sentinel) {
				t.Fatalf("CheckSwitchBlockAlignment(%v, %d) = %v, want %v", test.block, test.epoch, err, test.sentinel)
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Errorf("error = %q, want it to carry %q", err, test.want)
			}
		})
	}
}

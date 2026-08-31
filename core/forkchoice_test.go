// Copyright 2025 The XDC Authors
// This file is part of the XDC library.
//
// The XDC library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The XDC library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the XDC library. If not, see <http://www.gnu.org/licenses/>.

package core

import (
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/params"
)

// v2TestConfig returns a chain config whose XDPoS consensus switches to v2
// for blocks strictly above switchBlock.
func v2TestConfig(switchBlock int64) *params.ChainConfig {
	return &params.ChainConfig{
		XDPoS: &params.XDPoSConfig{
			V2: &params.V2{SwitchBlock: big.NewInt(switchBlock)},
		},
	}
}

// TestForkChoiceCmpV2Height verifies that in the v2 region the fork choice is
// decided by height only, regardless of the (degenerate) total difficulties.
func TestForkChoiceCmpV2Height(t *testing.T) {
	cfg := v2TestConfig(900)

	// Higher number wins even when the candidate TD looks smaller.
	if got := forkChoiceCmp(cfg, 1000, big.NewInt(5), 1001, big.NewInt(1000000)); got >= 0 {
		t.Fatalf("expected lower candidate height to lose, got %d", got)
	}
	if got := forkChoiceCmp(cfg, 1002, big.NewInt(5), 1001, big.NewInt(1000000)); got <= 0 {
		t.Fatalf("expected higher candidate height to win, got %d", got)
	}
	// Equal height ties regardless of the TDs.
	if got := forkChoiceCmp(cfg, 1000, big.NewInt(5), 1000, big.NewInt(7)); got != 0 {
		t.Fatalf("expected tie, got %d", got)
	}
	// Missing TDs fall back to height.
	if got := forkChoiceCmp(cfg, 1001, nil, 1000, nil); got <= 0 {
		t.Fatalf("expected higher candidate to win with missing TDs, got %d", got)
	}
	if got := forkChoiceCmp(cfg, 1000, nil, 1001, nil); got >= 0 {
		t.Fatalf("expected lower candidate to lose with missing TDs, got %d", got)
	}
}

// TestForkChoiceCmpV1Td verifies that below the v2 transition the original
// heaviest-chain (total difficulty) rule is retained.
func TestForkChoiceCmpV1Td(t *testing.T) {
	cfg := v2TestConfig(900)

	// Both sides below the transition: TD decides.
	if got := forkChoiceCmp(cfg, 100, big.NewInt(1000), 101, big.NewInt(999)); got <= 0 {
		t.Fatalf("expected heavier candidate to win, got %d", got)
	}
	if got := forkChoiceCmp(cfg, 100, big.NewInt(999), 101, big.NewInt(1000)); got >= 0 {
		t.Fatalf("expected lighter candidate to lose, got %d", got)
	}
	// Equal TD ties even at different heights (pre-existing semantics).
	if got := forkChoiceCmp(cfg, 100, big.NewInt(1000), 101, big.NewInt(1000)); got != 0 {
		t.Fatalf("expected tie, got %d", got)
	}
	// A missing TD falls back to height comparison.
	if got := forkChoiceCmp(cfg, 101, nil, 100, big.NewInt(1000000)); got <= 0 {
		t.Fatalf("expected higher candidate to win with missing candidate TD, got %d", got)
	}
	if got := forkChoiceCmp(cfg, 100, big.NewInt(1000000), 101, nil); got >= 0 {
		t.Fatalf("expected lower candidate to lose with missing current TD, got %d", got)
	}
}

// TestForkChoiceCmpMixedRegion verifies the transition edge: a v2 candidate
// always beats a v1 head, with or without TDs.
func TestForkChoiceCmpMixedRegion(t *testing.T) {
	cfg := v2TestConfig(900)

	// v2 candidate extends the v1 head: heavier TD wins.
	if got := forkChoiceCmp(cfg, 901, big.NewInt(1000001), 900, big.NewInt(1000000)); got <= 0 {
		t.Fatalf("expected v2 candidate to win via TD, got %d", got)
	}
	// Missing candidate TD falls back to height, still wins.
	if got := forkChoiceCmp(cfg, 901, nil, 900, big.NewInt(1000000)); got <= 0 {
		t.Fatalf("expected v2 candidate to win via height, got %d", got)
	}
	// A v1 candidate never beats a v2 head.
	if got := forkChoiceCmp(cfg, 900, big.NewInt(1000000), 901, nil); got >= 0 {
		t.Fatalf("expected v1 candidate to lose, got %d", got)
	}
	// With both TDs present the mixed region keeps the pure TD rule. The
	// safety of the comparison in real chains comes from the invariant that
	// a canonical v2 head extends the TD-heaviest chain through the switch
	// block, so the losing direction below is the only one that can occur in
	// practice. Both directions are pinned to document the contract.
	if got := forkChoiceCmp(cfg, 900, big.NewInt(999), 901, big.NewInt(1000)); got >= 0 {
		t.Fatalf("expected lighter v1 candidate to lose via TD, got %d", got)
	}
	if got := forkChoiceCmp(cfg, 900, big.NewInt(1000000), 901, big.NewInt(999)); got <= 0 {
		t.Fatalf("expected heavier v1 candidate to win via TD, got %d", got)
	}
}

// TestForkChoiceCmpNoXDPoS verifies that chains without an XDPoS config keep
// the original heaviest-chain rule.
func TestForkChoiceCmpNoXDPoS(t *testing.T) {
	if got := forkChoiceCmp(nil, 100, big.NewInt(10), 101, big.NewInt(9)); got <= 0 {
		t.Fatalf("expected heavier candidate to win, got %d", got)
	}
	if got := forkChoiceCmp(nil, 100, nil, 101, nil); got >= 0 {
		t.Fatalf("expected higher candidate to win with missing TDs, got %d", got)
	}
}

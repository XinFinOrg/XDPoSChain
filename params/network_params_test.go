// Copyright 2025 The XDPoSChain Authors
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

package params

import "testing"

// TestImmutabilityThresholdClearsConsensusLookback guards the invariant behind
// MinFullImmutabilityThreshold.
//
// XDPoS reward and penalty calculation walks 2*RewardCheckpoint blocks back
// reading block bodies and raw receipts (contracts.GetRewardForCheckpoint, and
// the engine v1/v2 hooks). The chain freezer cutoff -- and, once minimal history
// mode lands, the pruning tail -- must never move inside that window.
//
// If a network is ever configured with a larger RewardCheckpoint, this test
// fails and MinFullImmutabilityThreshold must be raised to match.
func TestImmutabilityThresholdClearsConsensusLookback(t *testing.T) {
	configs := map[string]*ChainConfig{
		"mainnet": MainnetChainConfig,
		"testnet": TestnetChainConfig,
		"devnet":  DevnetChainConfig,
	}
	for name, cfg := range configs {
		if cfg == nil || cfg.XDPoS == nil {
			continue
		}
		lookback := 2 * cfg.XDPoS.RewardCheckpoint
		if lookback == 0 {
			t.Errorf("%s: RewardCheckpoint is 0, consensus lookback cannot be computed", name)
			continue
		}
		if MinFullImmutabilityThreshold <= lookback {
			t.Errorf("%s: MinFullImmutabilityThreshold (%d) must exceed the consensus body/receipt lookback of 2*RewardCheckpoint (%d)",
				name, MinFullImmutabilityThreshold, lookback)
		}
	}
	if DefaultFullImmutabilityThreshold < MinFullImmutabilityThreshold {
		t.Errorf("default threshold (%d) is below the minimum (%d)",
			DefaultFullImmutabilityThreshold, MinFullImmutabilityThreshold)
	}
}

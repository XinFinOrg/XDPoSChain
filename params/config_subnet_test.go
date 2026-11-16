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

package params

import (
	"encoding/json"
	"errors"
	"math/big"
	"testing"
)

// validSubnetConfig is the Localnet config turned into a subnet: EIP-1559 and
// the forks built on it off, the flat reward, a masternode cap.
func validSubnetConfig() *ChainConfig {
	cfg := LocalnetChainConfig.Clone()
	cfg.EIP1559Block = nil
	cfg.Gas2500xBlock = nil
	cfg.CancunBlock = nil
	cfg.PragueBlock = nil
	cfg.OsakaBlock = nil
	cfg.AmsterdamBlock = nil
	cfg.TIPFixedRewardBlock = nil
	cfg.TIPProportionalRewardBlock = nil
	cfg.TIPEpochHalvingBlock = nil
	cfg.TIPNoHalvingMNRewardBlock = big.NewInt(0)
	cfg.XDPoS.IsSubnet = true
	return cfg
}

func TestSubnetConfigValidation(t *testing.T) {
	if err := validSubnetConfig().CheckConfigForkOrder(); err != nil {
		t.Fatalf("valid subnet config rejected: %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*ChainConfig)
	}{
		{"v2 after genesis", func(c *ChainConfig) { c.XDPoS.V2.SwitchBlock = big.NewInt(900) }},
		{"switch epoch", func(c *ChainConfig) { c.XDPoS.V2.SwitchEpoch = 1 }},
		{"gap of one", func(c *ChainConfig) { c.XDPoS.Gap = 1 }},
		{"eip1559", func(c *ChainConfig) { c.EIP1559Block = big.NewInt(0) }},
		{"halving reward", func(c *ChainConfig) { c.TIPNoHalvingMNRewardBlock = nil }},
		{"late no-halving", func(c *ChainConfig) { c.TIPNoHalvingMNRewardBlock = big.NewInt(10) }},
		{"fixed reward", func(c *ChainConfig) { c.TIPFixedRewardBlock = big.NewInt(0) }},
		{"proportional reward", func(c *ChainConfig) { c.TIPProportionalRewardBlock = big.NewInt(0) }},
		{"epoch halving", func(c *ChainConfig) { c.TIPEpochHalvingBlock = big.NewInt(0) }},
		{"no masternode cap", func(c *ChainConfig) {
			v2cfg := c.XDPoS.V2.AllConfigs[0].Clone()
			v2cfg.MaxMasternodes = 0
			c.XDPoS.V2 = &V2{SwitchBlock: big.NewInt(0), CurrentConfig: v2cfg, AllConfigs: map[uint64]*V2Config{0: v2cfg}}
			c.XDPoS.V2.BuildConfigIndex()
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validSubnetConfig()
			tt.mutate(cfg)
			err := cfg.CheckConfigForkOrder()
			// Moving a fork block can trip the fork order check before the
			// subnet rules; every other case is a subnet rule.
			forkOrder := tt.name == "eip1559" || tt.name == "late no-halving"
			if err == nil || (!forkOrder && !errors.Is(err, ErrInvalidSubnetConfig)) {
				t.Fatalf("got %v, want a subnet config error", err)
			}
		})
	}
	// The rules do not apply to other chains.
	cfg := validSubnetConfig()
	cfg.XDPoS.IsSubnet = false
	cfg.XDPoS.Gap = 1
	if err := cfg.CheckConfigForkOrder(); errors.Is(err, ErrInvalidSubnetConfig) {
		t.Fatalf("subnet rule applied to a non-subnet chain: %v", err)
	}
}

// The subnet keys survive the JSON round trip of the stored chain config, and
// a non-subnet config does not gain them.
func TestSubnetConfigJSON(t *testing.T) {
	cfg := validSubnetConfig()
	cfg.XDPoS.NetworkName = "mysubnet"
	cfg.XDPoS.Denom = "sdc"
	blob, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var dec ChainConfig
	if err := json.Unmarshal(blob, &dec); err != nil {
		t.Fatal(err)
	}
	if !dec.IsSubnet() || dec.XDPoS.NetworkName != "mysubnet" || dec.XDPoS.Denom != "sdc" {
		t.Fatalf("round trip lost the subnet keys: %+v", dec.XDPoS)
	}
	if dec.XDPoS.BlockConsensusVersion(big.NewInt(0)) != ConsensusEngineVersion2 {
		t.Fatal("a subnet genesis must be a v2 block")
	}

	blob, err = json.Marshal(LocalnetChainConfig)
	if err != nil {
		t.Fatal(err)
	}
	var raw struct {
		XDPoS map[string]json.RawMessage `json:"XDPoS"`
	}
	if err := json.Unmarshal(blob, &raw); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"isSubnet", "networkName", "denom"} {
		if _, ok := raw.XDPoS[key]; ok {
			t.Fatalf("non-subnet config marshals %q", key)
		}
	}
	if (*ChainConfig)(nil).IsSubnet() || LocalnetChainConfig.IsSubnet() {
		t.Fatal("IsSubnet true outside a subnet")
	}
}

// Changing the subnet flag of a stored chain is incompatible.
func TestSubnetConfigCompatibility(t *testing.T) {
	stored := validSubnetConfig()
	updated := validSubnetConfig()
	updated.XDPoS.IsSubnet = false
	if err := stored.CheckCompatible(updated, 0); err == nil {
		t.Fatal("dropping the subnet flag is accepted")
	}
	if stored.Equal(updated) {
		t.Fatal("configs differing in the subnet flag compare equal")
	}
}

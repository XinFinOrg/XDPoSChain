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
	"encoding/json"
	"sync"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/stretchr/testify/assert"
)

func TestUpdateV2Config(t *testing.T) {
	TestXDPoSMockChainConfig.XDPoS.V2.BuildConfigIndex()
	c := TestXDPoSMockChainConfig.XDPoS.V2.CurrentConfig
	assert.Equal(t, 0.667, c.CertThreshold)

	TestXDPoSMockChainConfig.XDPoS.V2.UpdateConfig(10)
	c = TestXDPoSMockChainConfig.XDPoS.V2.CurrentConfig
	assert.Equal(t, float64(0.667), c.CertThreshold)

	TestXDPoSMockChainConfig.XDPoS.V2.UpdateConfig(900)
	c = TestXDPoSMockChainConfig.XDPoS.V2.CurrentConfig
	assert.Equal(t, 4, c.TimeoutSyncThreshold)
}

func TestV2Config(t *testing.T) {
	TestXDPoSMockChainConfig.XDPoS.V2.BuildConfigIndex()
	c := TestXDPoSMockChainConfig.XDPoS.V2.Config(1)
	assert.Equal(t, 0.667, c.CertThreshold)

	c = TestXDPoSMockChainConfig.XDPoS.V2.Config(5)
	assert.Equal(t, 0.667, c.CertThreshold)

	c = TestXDPoSMockChainConfig.XDPoS.V2.Config(10)
	assert.Equal(t, 0.667, c.CertThreshold)

	c = TestXDPoSMockChainConfig.XDPoS.V2.Config(11)
	assert.Equal(t, float64(0.667), c.CertThreshold)
}

func TestV2ConfigAccessorsReturnIndependentCopies(t *testing.T) {
	v2 := &V2{
		CurrentConfig: &V2Config{
			SwitchRound: 1,
			json:        jsonFieldPresence{tracked: true, keys: map[string]struct{}{"switchRound": {}}},
			ExpTimeoutConfig: ExpTimeoutConfig{
				Base: 1,
				json: jsonFieldPresence{tracked: true, keys: map[string]struct{}{"base": {}}},
			},
		},
		AllConfigs: map[uint64]*V2Config{
			0: {
				SwitchRound: 0,
				json:        jsonFieldPresence{tracked: true, keys: map[string]struct{}{"switchRound": {}}},
				ExpTimeoutConfig: ExpTimeoutConfig{
					Base: 2,
					json: jsonFieldPresence{tracked: true, keys: map[string]struct{}{"base": {}}},
				},
			},
		},
		configIndex: []uint64{0},
	}

	current := v2.GetCurrentConfig()
	delete(current.json.keys, "switchRound")
	delete(current.ExpTimeoutConfig.json.keys, "base")

	if _, ok := v2.CurrentConfig.json.keys["switchRound"]; !ok {
		t.Fatal("expected GetCurrentConfig to return an independent copy of jsonPresence")
	}
	if _, ok := v2.CurrentConfig.ExpTimeoutConfig.json.keys["base"]; !ok {
		t.Fatal("expected GetCurrentConfig to deep copy ExpTimeoutConfig jsonPresence")
	}

	cfg := v2.Config(0)
	delete(cfg.json.keys, "switchRound")
	delete(cfg.ExpTimeoutConfig.json.keys, "base")

	if _, ok := v2.AllConfigs[0].json.keys["switchRound"]; !ok {
		t.Fatal("expected Config to return an independent copy of jsonPresence")
	}
	if _, ok := v2.AllConfigs[0].ExpTimeoutConfig.json.keys["base"]; !ok {
		t.Fatal("expected Config to deep copy ExpTimeoutConfig jsonPresence")
	}
}

func TestChainConfigEqualConcurrentWithV2Update(t *testing.T) {
	left := TestXDPoSMockChainConfig.Clone()
	right := TestXDPoSMockChainConfig.Clone()
	left.XDPoS.V2.BuildConfigIndex()
	right.XDPoS.V2.BuildConfigIndex()

	rounds := []uint64{0, 10, 900}
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < 2000; i++ {
			left.XDPoS.V2.UpdateConfig(rounds[i%len(rounds)])
		}
	}()

	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < 2000; i++ {
			_ = left.Equal(right)
		}
	}()

	close(start)
	wg.Wait()
}

func TestV2EqualConcurrentWithUpdateConfig(t *testing.T) {
	left := TestXDPoSMockChainConfig.XDPoS.V2.Clone()
	right := TestXDPoSMockChainConfig.XDPoS.V2.Clone()
	left.BuildConfigIndex()
	right.BuildConfigIndex()

	rounds := []uint64{0, 10, 900}
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < 2000; i++ {
			left.UpdateConfig(rounds[i%len(rounds)])
		}
	}()

	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < 2000; i++ {
			_ = V2Equal(left, right)
		}
	}()

	close(start)
	wg.Wait()
}

func TestV2StringConcurrentWithUpdateConfig(t *testing.T) {
	v2 := TestXDPoSMockChainConfig.XDPoS.V2.Clone()
	v2.BuildConfigIndex()

	rounds := []uint64{0, 10, 900}
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < 2000; i++ {
			v2.UpdateConfig(rounds[i%len(rounds)])
		}
	}()

	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < 2000; i++ {
			_ = v2.String()
		}
	}()

	close(start)
	wg.Wait()
}

func TestBuildConfigIndex(t *testing.T) {
	TestXDPoSMockChainConfig.XDPoS.V2.BuildConfigIndex()
	index := TestXDPoSMockChainConfig.XDPoS.V2.ConfigIndex()
	expected := []uint64{900, 10, 0}
	assert.Equal(t, expected, index)
}

func TestBuildConfigIndexDescendingOrder(t *testing.T) {
	v2 := &V2{
		AllConfigs: map[uint64]*V2Config{
			5:  {SwitchRound: 5},
			2:  {SwitchRound: 2},
			10: {SwitchRound: 10},
			0:  {SwitchRound: 0},
			15: {SwitchRound: 15},
		},
	}
	v2.BuildConfigIndex()
	assert.Equal(t, []uint64{15, 10, 5, 2, 0}, v2.ConfigIndex())
}

func TestV2ConfigIndexReturnsCopy(t *testing.T) {
	v2 := &V2{
		configIndex: []uint64{3, 2, 1},
	}

	index := v2.ConfigIndex()
	index[0] = 99

	assert.Equal(t, []uint64{3, 2, 1}, v2.ConfigIndex())
}

func TestSwitchEpoch(t *testing.T) {
	config := XDCMainnetChainConfig.XDPoS
	epoch := config.Epoch
	assert.Equal(t, config.V2.SwitchEpoch, config.V2.SwitchBlock.Uint64()/epoch)

	config = TestnetChainConfig.XDPoS
	epoch = config.Epoch
	assert.Equal(t, config.V2.SwitchEpoch, config.V2.SwitchBlock.Uint64()/epoch)

	config = DevnetChainConfig.XDPoS
	epoch = config.Epoch
	assert.Equal(t, config.V2.SwitchEpoch, config.V2.SwitchBlock.Uint64()/epoch)

	config = TestXDPoSMockChainConfig.XDPoS
	epoch = config.Epoch
	assert.Equal(t, config.V2.SwitchEpoch, config.V2.SwitchBlock.Uint64()/epoch)
}

func TestXDPoSConfigUnmarshalLegacyFoundationWalletAddr(t *testing.T) {
	const raw = `{"period":2,"epoch":900,"reward":5000,"rewardCheckpoint":900,"gap":450,"foudationWalletAddr":"xdc746249c61f5832c5eed53172776b460491bdcd5c"}`

	var cfg XDPoSConfig
	err := json.Unmarshal([]byte(raw), &cfg)
	assert.NoError(t, err)
	assert.Equal(t, common.HexToAddress("xdc746249c61f5832c5eed53172776b460491bdcd5c"), cfg.FoundationWalletAddr)
}

func TestXDPoSConfigUnmarshalFoundationWalletAddrPrecedence(t *testing.T) {
	const raw = `{"period":2,"epoch":900,"reward":5000,"rewardCheckpoint":900,"gap":450,"foudationWalletAddr":"xdc746249c61f5832c5eed53172776b460491bdcd5c","foundationWalletAddr":"xdc92a289fe95a85c53b8d0d113cbaef0c1ec98ac65"}`

	var cfg XDPoSConfig
	err := json.Unmarshal([]byte(raw), &cfg)
	assert.NoError(t, err)
	assert.Equal(t, common.HexToAddress("xdc92a289fe95a85c53b8d0d113cbaef0c1ec98ac65"), cfg.FoundationWalletAddr)
}

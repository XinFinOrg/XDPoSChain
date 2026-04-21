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
	"errors"
	"math"
	"math/big"
	"reflect"
	"strings"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/stretchr/testify/assert"
)

func TestCheckCompatible(t *testing.T) {
	type test struct {
		stored, new *ChainConfig
		head        uint64
		wantErr     *ConfigCompatError
	}
	tests := []test{
		{
			stored:  AllEthashProtocolChanges,
			new:     AllEthashProtocolChanges,
			head:    0,
			wantErr: nil,
		},
		{
			stored:  AllEthashProtocolChanges,
			new:     AllEthashProtocolChanges,
			head:    100,
			wantErr: nil,
		},
		{
			stored:  &ChainConfig{EIP150Block: big.NewInt(10)},
			new:     &ChainConfig{EIP150Block: big.NewInt(20)},
			head:    9,
			wantErr: nil,
		},
		{
			stored: AllEthashProtocolChanges,
			new:    &ChainConfig{HomesteadBlock: nil},
			head:   3,
			wantErr: &ConfigCompatError{
				What:         "Homestead fork block",
				StoredConfig: big.NewInt(0),
				NewConfig:    nil,
				RewindTo:     0,
			},
		},
		{
			stored: AllEthashProtocolChanges,
			new:    &ChainConfig{HomesteadBlock: big.NewInt(1)},
			head:   3,
			wantErr: &ConfigCompatError{
				What:         "Homestead fork block",
				StoredConfig: big.NewInt(0),
				NewConfig:    big.NewInt(1),
				RewindTo:     0,
			},
		},
		{
			stored: &ChainConfig{TIP2019Block: big.NewInt(10)},
			new:    &ChainConfig{TIP2019Block: big.NewInt(20)},
			head:   15,
			wantErr: &ConfigCompatError{
				What:         "TIP2019 fork block",
				StoredConfig: big.NewInt(10),
				NewConfig:    big.NewInt(20),
				RewindTo:     9,
			},
		},
		{
			stored: &ChainConfig{HomesteadBlock: big.NewInt(30), EIP150Block: big.NewInt(10)},
			new:    &ChainConfig{HomesteadBlock: big.NewInt(25), EIP150Block: big.NewInt(20)},
			head:   25,
			wantErr: &ConfigCompatError{
				What:         "EIP150 fork block",
				StoredConfig: big.NewInt(10),
				NewConfig:    big.NewInt(20),
				RewindTo:     9,
			},
		},
		{
			stored: &ChainConfig{TIPSigningBlock: big.NewInt(10)},
			new:    &ChainConfig{TIPSigningBlock: big.NewInt(20)},
			head:   15,
			wantErr: &ConfigCompatError{
				What:         "TIPSigning fork block",
				StoredConfig: big.NewInt(10),
				NewConfig:    big.NewInt(20),
				RewindTo:     9,
			},
		},
		{
			stored: &ChainConfig{TIPRandomizeBlock: big.NewInt(10)},
			new:    &ChainConfig{TIPRandomizeBlock: big.NewInt(20)},
			head:   15,
			wantErr: &ConfigCompatError{
				What:         "TIPRandomize fork block",
				StoredConfig: big.NewInt(10),
				NewConfig:    big.NewInt(20),
				RewindTo:     9,
			},
		},
		{
			stored: &ChainConfig{DenylistBlock: big.NewInt(10)},
			new:    &ChainConfig{DenylistBlock: big.NewInt(20)},
			head:   15,
			wantErr: &ConfigCompatError{
				What:         "Denylist fork block",
				StoredConfig: big.NewInt(10),
				NewConfig:    big.NewInt(20),
				RewindTo:     9,
			},
		},
		{
			stored: &ChainConfig{TIPNoHalvingMNRewardBlock: big.NewInt(10)},
			new:    &ChainConfig{TIPNoHalvingMNRewardBlock: big.NewInt(20)},
			head:   15,
			wantErr: &ConfigCompatError{
				What:         "TIPNoHalvingMNReward fork block",
				StoredConfig: big.NewInt(10),
				NewConfig:    big.NewInt(20),
				RewindTo:     9,
			},
		},
		{
			stored: &ChainConfig{TIPXDCXBlock: big.NewInt(10)},
			new:    &ChainConfig{TIPXDCXBlock: big.NewInt(20)},
			head:   15,
			wantErr: &ConfigCompatError{
				What:         "TIPXDCX fork block",
				StoredConfig: big.NewInt(10),
				NewConfig:    big.NewInt(20),
				RewindTo:     9,
			},
		},
		{
			stored: &ChainConfig{TIPXDCXLendingBlock: big.NewInt(10)},
			new:    &ChainConfig{TIPXDCXLendingBlock: big.NewInt(20)},
			head:   15,
			wantErr: &ConfigCompatError{
				What:         "TIPXDCXLending fork block",
				StoredConfig: big.NewInt(10),
				NewConfig:    big.NewInt(20),
				RewindTo:     9,
			},
		},
		{
			stored: &ChainConfig{TIPXDCXCancellationFeeBlock: big.NewInt(10)},
			new:    &ChainConfig{TIPXDCXCancellationFeeBlock: big.NewInt(20)},
			head:   15,
			wantErr: &ConfigCompatError{
				What:         "TIPXDCXCancellationFee fork block",
				StoredConfig: big.NewInt(10),
				NewConfig:    big.NewInt(20),
				RewindTo:     9,
			},
		},
		{
			stored: &ChainConfig{TIPTRC21FeeBlock: big.NewInt(10)},
			new:    &ChainConfig{TIPTRC21FeeBlock: big.NewInt(20)},
			head:   15,
			wantErr: &ConfigCompatError{
				What:         "TIPTRC21Fee fork block",
				StoredConfig: big.NewInt(10),
				NewConfig:    big.NewInt(20),
				RewindTo:     9,
			},
		},
		{
			stored: &ChainConfig{BerlinBlock: big.NewInt(10)},
			new:    &ChainConfig{BerlinBlock: big.NewInt(20)},
			head:   15,
			wantErr: &ConfigCompatError{
				What:         "Berlin fork block",
				StoredConfig: big.NewInt(10),
				NewConfig:    big.NewInt(20),
				RewindTo:     9,
			},
		},
		{
			stored: &ChainConfig{LondonBlock: big.NewInt(10)},
			new:    &ChainConfig{LondonBlock: big.NewInt(20)},
			head:   15,
			wantErr: &ConfigCompatError{
				What:         "London fork block",
				StoredConfig: big.NewInt(10),
				NewConfig:    big.NewInt(20),
				RewindTo:     9,
			},
		},
		{
			stored: &ChainConfig{MergeBlock: big.NewInt(10)},
			new:    &ChainConfig{MergeBlock: big.NewInt(20)},
			head:   15,
			wantErr: &ConfigCompatError{
				What:         "Merge fork block",
				StoredConfig: big.NewInt(10),
				NewConfig:    big.NewInt(20),
				RewindTo:     9,
			},
		},
		{
			stored: &ChainConfig{ShanghaiBlock: big.NewInt(10)},
			new:    &ChainConfig{ShanghaiBlock: big.NewInt(20)},
			head:   15,
			wantErr: &ConfigCompatError{
				What:         "Shanghai fork block",
				StoredConfig: big.NewInt(10),
				NewConfig:    big.NewInt(20),
				RewindTo:     9,
			},
		},
		{
			stored: &ChainConfig{TIPXDCXMinerDisableBlock: big.NewInt(10)},
			new:    &ChainConfig{TIPXDCXMinerDisableBlock: big.NewInt(20)},
			head:   15,
			wantErr: &ConfigCompatError{
				What:         "TIPXDCXMinerDisable fork block",
				StoredConfig: big.NewInt(10),
				NewConfig:    big.NewInt(20),
				RewindTo:     9,
			},
		},
		{
			stored: &ChainConfig{TIPXDCXReceiverDisableBlock: big.NewInt(10)},
			new:    &ChainConfig{TIPXDCXReceiverDisableBlock: big.NewInt(20)},
			head:   15,
			wantErr: &ConfigCompatError{
				What:         "TIPXDCXReceiverDisable fork block",
				StoredConfig: big.NewInt(10),
				NewConfig:    big.NewInt(20),
				RewindTo:     9,
			},
		},
		{
			stored: &ChainConfig{Eip1559Block: big.NewInt(10)},
			new:    &ChainConfig{Eip1559Block: big.NewInt(20)},
			head:   15,
			wantErr: &ConfigCompatError{
				What:         "Eip1559 fork block",
				StoredConfig: big.NewInt(10),
				NewConfig:    big.NewInt(20),
				RewindTo:     9,
			},
		},
		{
			stored: &ChainConfig{CancunBlock: big.NewInt(10)},
			new:    &ChainConfig{CancunBlock: big.NewInt(20)},
			head:   15,
			wantErr: &ConfigCompatError{
				What:         "Cancun fork block",
				StoredConfig: big.NewInt(10),
				NewConfig:    big.NewInt(20),
				RewindTo:     9,
			},
		},
		{
			stored: &ChainConfig{PragueBlock: big.NewInt(10)},
			new:    &ChainConfig{PragueBlock: big.NewInt(20)},
			head:   15,
			wantErr: &ConfigCompatError{
				What:         "Prague fork block",
				StoredConfig: big.NewInt(10),
				NewConfig:    big.NewInt(20),
				RewindTo:     9,
			},
		},
		{
			stored: &ChainConfig{OsakaBlock: big.NewInt(10)},
			new:    &ChainConfig{OsakaBlock: big.NewInt(20)},
			head:   15,
			wantErr: &ConfigCompatError{
				What:         "Osaka fork block",
				StoredConfig: big.NewInt(10),
				NewConfig:    big.NewInt(20),
				RewindTo:     9,
			},
		},
		{
			stored: &ChainConfig{DynamicGasLimitBlock: big.NewInt(10)},
			new:    &ChainConfig{DynamicGasLimitBlock: big.NewInt(20)},
			head:   15,
			wantErr: &ConfigCompatError{
				What:         "DynamicGasLimit fork block",
				StoredConfig: big.NewInt(10),
				NewConfig:    big.NewInt(20),
				RewindTo:     9,
			},
		},
		{
			stored: &ChainConfig{TIPUpgradeRewardBlock: big.NewInt(10)},
			new:    &ChainConfig{TIPUpgradeRewardBlock: big.NewInt(20)},
			head:   15,
			wantErr: &ConfigCompatError{
				What:         "TIPUpgradeReward fork block",
				StoredConfig: big.NewInt(10),
				NewConfig:    big.NewInt(20),
				RewindTo:     9,
			},
		},
		{
			stored: &ChainConfig{TIPUpgradePenaltyBlock: big.NewInt(10)},
			new:    &ChainConfig{TIPUpgradePenaltyBlock: big.NewInt(20)},
			head:   15,
			wantErr: &ConfigCompatError{
				What:         "TIPUpgradePenalty fork block",
				StoredConfig: big.NewInt(10),
				NewConfig:    big.NewInt(20),
				RewindTo:     9,
			},
		},
		{
			stored: &ChainConfig{TIPEpochHalvingBlock: big.NewInt(10)},
			new:    &ChainConfig{TIPEpochHalvingBlock: big.NewInt(20)},
			head:   15,
			wantErr: &ConfigCompatError{
				What:         "TIPEpochHalving fork block",
				StoredConfig: big.NewInt(10),
				NewConfig:    big.NewInt(20),
				RewindTo:     9,
			},
		},
	}

	for _, test := range tests {
		err := test.stored.CheckCompatible(test.new, test.head)
		if !reflect.DeepEqual(err, test.wantErr) {
			t.Errorf("error mismatch:\nstored: %v\nnew: %v\nhead: %v\nerr: %v\nwant: %v", test.stored, test.new, test.head, err, test.wantErr)
		}
	}
}

func TestChainConfigValidateForStartup(t *testing.T) {
	t.Run("missing field", func(t *testing.T) {
		cfg := &ChainConfig{}
		err := cfg.CheckConfigForkOrder()
		if !errors.Is(err, ErrMissingForkSwitch) {
			t.Fatalf("unexpected error: have %v want %v", err, ErrMissingForkSwitch)
		}
		if err == nil || err.Error() != "invalid chain config: missing fork switch ChainID" {
			t.Fatalf("unexpected error string: %v", err)
		}
	})

	t.Run("valid config", func(t *testing.T) {
		cfg := &ChainConfig{
			ChainID:          big.NewInt(1),
			TIPTRC21FeeBlock: big.NewInt(0),
		}
		if err := cfg.CheckConfigForkOrder(); err != nil {
			t.Fatalf("ValidateForStartup failed: %v", err)
		}
	})
}

func TestXDPoSMockChainConfigDeclaresModernForks(t *testing.T) {
	config := TestXDPoSMockChainConfig
	if !assert.NotNil(t, config) {
		return
	}
	assertBlock := func(name string, got *big.Int) {
		t.Helper()
		if assert.NotNil(t, got, "%s must be explicitly declared on TestXDPoSMockChainConfig", name) {
			assert.Zero(t, got.Cmp(common.Big0), "%s must be active from genesis on TestXDPoSMockChainConfig", name)
		}
	}

	assertBlock("TIP2019Block", config.TIP2019Block)
	assertBlock("TIPSigningBlock", config.TIPSigningBlock)
	assertBlock("TIPRandomizeBlock", config.TIPRandomizeBlock)
	assertBlock("TIPIncreaseMasternodesBlock", config.TIPIncreaseMasternodesBlock)
	assertBlock("TIPNoHalvingMNRewardBlock", config.TIPNoHalvingMNRewardBlock)
	assertBlock("TIPXDCXBlock", config.TIPXDCXBlock)
	assertBlock("TIPXDCXLendingBlock", config.TIPXDCXLendingBlock)
	assertBlock("TIPXDCXCancellationFeeBlock", config.TIPXDCXCancellationFeeBlock)
	assertBlock("TIPTRC21Fee", config.TIPTRC21FeeBlock)
	assertBlock("BerlinBlock", config.BerlinBlock)
	assertBlock("LondonBlock", config.LondonBlock)
	assertBlock("MergeBlock", config.MergeBlock)
	assertBlock("ShanghaiBlock", config.ShanghaiBlock)
	assertBlock("Eip1559Block", config.Eip1559Block)
	assertBlock("CancunBlock", config.CancunBlock)
	assertBlock("PragueBlock", config.PragueBlock)
	assertBlock("OsakaBlock", config.OsakaBlock)
}

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

func TestChainConfigCloneDeepCopiesNestedConfig(t *testing.T) {
	original := &ChainConfig{
		ChainID:                     big.NewInt(50),
		TIP2019Block:                big.NewInt(10),
		Gas50xBlock:                 big.NewInt(15),
		TIPXDCXMinerDisableBlock:    big.NewInt(20),
		TIPXDCXReceiverDisableBlock: big.NewInt(25),
		OsakaBlock:                  big.NewInt(30),
		Ethash:                      new(EthashConfig),
		XDPoS: &XDPoSConfig{
			V2: &V2{
				SwitchEpoch: 12,
				SwitchBlock: big.NewInt(99),
				CurrentConfig: &V2Config{
					SwitchRound: 1,
				},
				AllConfigs: map[uint64]*V2Config{
					1: {SwitchRound: 1},
				},
			},
		},
	}
	original.XDPoS.V2.BuildConfigIndex()

	clone := original.Clone()
	if assert.NotNil(t, clone) {
		assert.NotSame(t, original, clone)
		assert.NotSame(t, original.ChainID, clone.ChainID)
		assert.NotSame(t, original.TIP2019Block, clone.TIP2019Block)
		assert.NotSame(t, original.Gas50xBlock, clone.Gas50xBlock)
		assert.NotSame(t, original.TIPXDCXMinerDisableBlock, clone.TIPXDCXMinerDisableBlock)
		assert.NotSame(t, original.TIPXDCXReceiverDisableBlock, clone.TIPXDCXReceiverDisableBlock)
		assert.NotSame(t, original.OsakaBlock, clone.OsakaBlock)
		assert.NotSame(t, original.XDPoS, clone.XDPoS)
		assert.NotSame(t, original.XDPoS.V2, clone.XDPoS.V2)
		assert.NotSame(t, original.XDPoS.V2.SwitchBlock, clone.XDPoS.V2.SwitchBlock)
		assert.NotSame(t, original.XDPoS.V2.CurrentConfig, clone.XDPoS.V2.CurrentConfig)
		assert.NotSame(t, original.XDPoS.V2.AllConfigs[1], clone.XDPoS.V2.AllConfigs[1])

		clone.ChainID.SetInt64(999)
		clone.Gas50xBlock.SetInt64(1)
		clone.XDPoS.V2.SwitchBlock.SetInt64(123)
		clone.XDPoS.V2.CurrentConfig.SwitchRound = 7
		cloneIndex := clone.XDPoS.V2.ConfigIndex()
		cloneIndex[0] = 77

		assert.Equal(t, int64(50), original.ChainID.Int64())
		assert.Equal(t, int64(15), original.Gas50xBlock.Int64())
		assert.Equal(t, int64(99), original.XDPoS.V2.SwitchBlock.Int64())
		assert.Equal(t, uint64(1), original.XDPoS.V2.CurrentConfig.SwitchRound)
		assert.Equal(t, []uint64{1}, original.XDPoS.V2.ConfigIndex())
	}
}

func TestChainConfigGas50xBlockDefaults(t *testing.T) {
	tests := []struct {
		name string
		cfg  *ChainConfig
		want int64
	}{
		{name: "mainnet", cfg: XDCMainnetChainConfig, want: 80370000},
		{name: "testnet", cfg: TestnetChainConfig, want: 56828700},
		{name: "devnet", cfg: DevnetChainConfig, want: 0},
		{name: "localnet", cfg: LocalnetChainConfig, want: 0},
		{name: "custom default", cfg: &ChainConfig{}, want: 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.cfg.Gas50xBlock
			if got == nil {
				got = big.NewInt(0)
			}
			assert.Equal(t, tc.want, got.Int64())
		})
	}
}

// Test switch epoch is switchblock divide into epoch per block
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

func TestBuiltInV2SwitchBlockConstants(t *testing.T) {
	assert.Equal(t, MainnetV2SwitchBlock, XDCMainnetChainConfig.XDPoS.V2.SwitchBlock.Uint64())
	assert.Equal(t, XDCMainnetChainConfig.XDPoS.V2.SwitchBlock.Uint64()/XDCMainnetChainConfig.XDPoS.Epoch, XDCMainnetChainConfig.XDPoS.V2.SwitchEpoch)

	assert.Equal(t, TestnetV2SwitchBlock, TestnetChainConfig.XDPoS.V2.SwitchBlock.Uint64())
	assert.Equal(t, TestnetChainConfig.XDPoS.V2.SwitchBlock.Uint64()/TestnetChainConfig.XDPoS.Epoch, TestnetChainConfig.XDPoS.V2.SwitchEpoch)

	assert.Equal(t, DevnetV2SwitchBlock, DevnetChainConfig.XDPoS.V2.SwitchBlock.Uint64())
	assert.Equal(t, DevnetChainConfig.XDPoS.V2.SwitchBlock.Uint64()/DevnetChainConfig.XDPoS.Epoch, DevnetChainConfig.XDPoS.V2.SwitchEpoch)
}

func TestXDCChainConfigsDeclareForkBlocks(t *testing.T) {
	tests := []struct {
		name                        string
		config                      *ChainConfig
		tip2019Block                *big.Int
		tipSigningBlock             *big.Int
		tipRandomizeBlock           *big.Int
		tipIncreaseMasternodesBlock *big.Int
		denylistBlock               *big.Int
		tipNoHalvingMNRewardBlock   *big.Int
		tipXDCXBlock                *big.Int
		tipXDCXLendingBlock         *big.Int
		tipXDCXCancellationFeeBlock *big.Int
		tipTRC21Fee                 *big.Int
		berlinBlock                 *big.Int
		londonBlock                 *big.Int
		mergeBlock                  *big.Int
		shanghaiBlock               *big.Int
		tipXDCXMinerDisable         *big.Int
		tipXDCXReceiverDisable      *big.Int
		eip1559Block                *big.Int
		cancunBlock                 *big.Int
		pragueBlock                 *big.Int
		osakaBlock                  *big.Int
		dynamicGasLimitBlock        *big.Int
		tipUpgradeRewardBlock       *big.Int
		tipUpgradePenaltyBlock      *big.Int
		tipEpochHalvingBlock        *big.Int
	}{
		{
			name:                        "mainnet",
			config:                      XDCMainnetChainConfig,
			tip2019Block:                big.NewInt(1),
			tipSigningBlock:             big.NewInt(3000000),
			tipRandomizeBlock:           big.NewInt(3464000),
			tipIncreaseMasternodesBlock: big.NewInt(5000000),
			denylistBlock:               big.NewInt(38383838),
			tipNoHalvingMNRewardBlock:   big.NewInt(38383838),
			tipXDCXBlock:                big.NewInt(38383838),
			tipXDCXLendingBlock:         big.NewInt(38383838),
			tipXDCXCancellationFeeBlock: big.NewInt(38383838),
			tipTRC21Fee:                 big.NewInt(38383838),
			berlinBlock:                 big.NewInt(76321000),
			londonBlock:                 big.NewInt(76321000),
			mergeBlock:                  big.NewInt(76321000),
			shanghaiBlock:               big.NewInt(76321000),
			tipXDCXMinerDisable:         big.NewInt(80370000),
			tipXDCXReceiverDisable:      big.NewInt(80370900),
			eip1559Block:                big.NewInt(98800200),
			cancunBlock:                 big.NewInt(98802000),
			pragueBlock:                 nil,
			osakaBlock:                  nil,
			dynamicGasLimitBlock:        nil,
			tipUpgradeRewardBlock:       nil,
			tipUpgradePenaltyBlock:      nil,
			tipEpochHalvingBlock:        nil,
		},
		{
			name:                        "testnet",
			config:                      TestnetChainConfig,
			tip2019Block:                big.NewInt(1),
			tipSigningBlock:             big.NewInt(3000000),
			tipRandomizeBlock:           big.NewInt(3464000),
			tipIncreaseMasternodesBlock: big.NewInt(5000000),
			denylistBlock:               big.NewInt(23779191),
			tipNoHalvingMNRewardBlock:   big.NewInt(23779191),
			tipXDCXBlock:                big.NewInt(23779191),
			tipXDCXLendingBlock:         big.NewInt(23779191),
			tipXDCXCancellationFeeBlock: big.NewInt(23779191),
			tipTRC21Fee:                 big.NewInt(23779191),
			berlinBlock:                 big.NewInt(61290000),
			londonBlock:                 big.NewInt(61290000),
			mergeBlock:                  big.NewInt(61290000),
			shanghaiBlock:               big.NewInt(61290000),
			tipXDCXMinerDisable:         big.NewInt(61290000),
			tipXDCXReceiverDisable:      big.NewInt(66825000),
			eip1559Block:                big.NewInt(71550000),
			cancunBlock:                 big.NewInt(71551800),
			pragueBlock:                 nil,
			osakaBlock:                  nil,
			dynamicGasLimitBlock:        nil,
			tipUpgradeRewardBlock:       nil,
			tipUpgradePenaltyBlock:      nil,
			tipEpochHalvingBlock:        nil,
		},
		{
			name:                        "devnet",
			config:                      DevnetChainConfig,
			tip2019Block:                big.NewInt(0),
			tipSigningBlock:             big.NewInt(0),
			tipRandomizeBlock:           big.NewInt(0),
			tipIncreaseMasternodesBlock: big.NewInt(0),
			denylistBlock:               big.NewInt(0),
			tipNoHalvingMNRewardBlock:   big.NewInt(0),
			tipXDCXBlock:                big.NewInt(0),
			tipXDCXLendingBlock:         big.NewInt(0),
			tipXDCXCancellationFeeBlock: big.NewInt(0),
			tipTRC21Fee:                 big.NewInt(0),
			berlinBlock:                 big.NewInt(0),
			londonBlock:                 big.NewInt(0),
			mergeBlock:                  big.NewInt(0),
			shanghaiBlock:               big.NewInt(0),
			tipXDCXMinerDisable:         big.NewInt(0),
			tipXDCXReceiverDisable:      big.NewInt(0),
			eip1559Block:                big.NewInt(250000),
			cancunBlock:                 big.NewInt(250000),
			pragueBlock:                 big.NewInt(5000000),
			osakaBlock:                  nil,
			dynamicGasLimitBlock:        big.NewInt(5000000),
			tipUpgradeRewardBlock:       big.NewInt(5000000),
			tipUpgradePenaltyBlock:      big.NewInt(5000000),
			tipEpochHalvingBlock:        nil,
		},
		{
			name:                        "localnet",
			config:                      LocalnetChainConfig,
			tip2019Block:                big.NewInt(0),
			tipSigningBlock:             big.NewInt(0),
			tipRandomizeBlock:           big.NewInt(0),
			tipIncreaseMasternodesBlock: big.NewInt(0),
			denylistBlock:               big.NewInt(0),
			tipNoHalvingMNRewardBlock:   big.NewInt(0),
			tipXDCXBlock:                big.NewInt(0),
			tipXDCXLendingBlock:         big.NewInt(0),
			tipXDCXCancellationFeeBlock: big.NewInt(0),
			tipTRC21Fee:                 big.NewInt(0),
			berlinBlock:                 big.NewInt(0),
			londonBlock:                 big.NewInt(0),
			mergeBlock:                  big.NewInt(0),
			shanghaiBlock:               big.NewInt(0),
			tipXDCXMinerDisable:         big.NewInt(0),
			tipXDCXReceiverDisable:      big.NewInt(0),
			eip1559Block:                big.NewInt(0),
			cancunBlock:                 big.NewInt(0),
			pragueBlock:                 nil,
			osakaBlock:                  nil,
			dynamicGasLimitBlock:        nil,
			tipUpgradeRewardBlock:       nil,
			tipUpgradePenaltyBlock:      nil,
			tipEpochHalvingBlock:        nil,
		},
	}

	assertBlock := func(t *testing.T, fork string, got, want *big.Int) {
		t.Helper()
		if want == nil {
			assert.Nil(t, got, "%s block must be nil when unscheduled", fork)
			return
		}
		if assert.NotNil(t, got, "%s block must be declared", fork) {
			assert.Equal(t, 0, got.Cmp(want), "%s block mismatch", fork)
		}
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if !assert.NotNil(t, test.config, "chain config must not be nil") {
				return
			}
			assertBlock(t, "TIP2019", test.config.TIP2019Block, test.tip2019Block)
			assertBlock(t, "TIPSigning", test.config.TIPSigningBlock, test.tipSigningBlock)
			assertBlock(t, "TIPRandomize", test.config.TIPRandomizeBlock, test.tipRandomizeBlock)
			assertBlock(t, "TIPIncreaseMasternodes", test.config.TIPIncreaseMasternodesBlock, test.tipIncreaseMasternodesBlock)
			assertBlock(t, "DenylistHardFork", test.config.DenylistBlock, test.denylistBlock)
			assertBlock(t, "TIPNoHalvingMNReward", test.config.TIPNoHalvingMNRewardBlock, test.tipNoHalvingMNRewardBlock)
			assertBlock(t, "TIPXDCX", test.config.TIPXDCXBlock, test.tipXDCXBlock)
			assertBlock(t, "TIPXDCXLending", test.config.TIPXDCXLendingBlock, test.tipXDCXLendingBlock)
			assertBlock(t, "TIPXDCXCancellationFee", test.config.TIPXDCXCancellationFeeBlock, test.tipXDCXCancellationFeeBlock)
			assertBlock(t, "TIPTRC21Fee", test.config.TIPTRC21FeeBlock, test.tipTRC21Fee)
			assertBlock(t, "Berlin", test.config.BerlinBlock, test.berlinBlock)
			assertBlock(t, "London", test.config.LondonBlock, test.londonBlock)
			assertBlock(t, "Merge", test.config.MergeBlock, test.mergeBlock)
			assertBlock(t, "Shanghai", test.config.ShanghaiBlock, test.shanghaiBlock)
			assertBlock(t, "TIPXDCXMinerDisable", test.config.TIPXDCXMinerDisableBlock, test.tipXDCXMinerDisable)
			assertBlock(t, "TIPXDCXReceiverDisable", test.config.TIPXDCXReceiverDisableBlock, test.tipXDCXReceiverDisable)
			assertBlock(t, "Eip1559", test.config.Eip1559Block, test.eip1559Block)
			assertBlock(t, "Cancun", test.config.CancunBlock, test.cancunBlock)
			assertBlock(t, "Prague", test.config.PragueBlock, test.pragueBlock)
			assertBlock(t, "Osaka", test.config.OsakaBlock, test.osakaBlock)
			assertBlock(t, "DynamicGasLimit", test.config.DynamicGasLimitBlock, test.dynamicGasLimitBlock)
			assertBlock(t, "TIPUpgradeReward", test.config.TIPUpgradeRewardBlock, test.tipUpgradeRewardBlock)
			assertBlock(t, "TIPUpgradePenalty", test.config.TIPUpgradePenaltyBlock, test.tipUpgradePenaltyBlock)
			assertBlock(t, "TIPEpochHalving", test.config.TIPEpochHalvingBlock, test.tipEpochHalvingBlock)
		})
	}
}

func TestForkActivationIgnoresCommonFallbacks(t *testing.T) {
	const zeroAddress0x = "0x0000000000000000000000000000000000000000"
	config := &ChainConfig{}
	block := big.NewInt(1)

	assert.False(t, config.IsTIP2019(big.NewInt(math.MaxInt64)))
	assert.False(t, config.IsTIPSigning(big.NewInt(math.MaxInt64)))
	assert.False(t, config.IsTIPRandomize(big.NewInt(math.MaxInt64)))
	assert.False(t, config.IsTIPIncreaseMasternodes(big.NewInt(math.MaxInt64)))
	assert.False(t, config.IsDenylist(big.NewInt(math.MaxInt64)))
	assert.False(t, config.IsTIPNoHalvingMNReward(big.NewInt(math.MaxInt64)))
	assert.False(t, config.IsTIPXDCX(big.NewInt(math.MaxInt64)))
	assert.False(t, config.IsTIPXDCXLending(big.NewInt(math.MaxInt64)))
	assert.False(t, config.IsTIPXDCXCancellationFee(big.NewInt(math.MaxInt64)))
	assert.False(t, config.IsBerlin(block))
	assert.False(t, config.IsLondon(block))
	assert.False(t, config.IsMerge(block))
	assert.False(t, config.IsShanghai(block))
	assert.False(t, config.IsTIPXDCXMiner(big.NewInt(math.MaxInt64)))
	assert.False(t, config.IsTIPXDCXReceiver(big.NewInt(math.MaxInt64)))
	assert.False(t, config.IsXDCxDisable(big.NewInt(math.MaxInt64)))
	assert.False(t, config.IsCancun(big.NewInt(math.MaxInt64)))
	assert.False(t, config.IsPrague(big.NewInt(math.MaxInt64)))
	assert.False(t, config.IsOsaka(big.NewInt(math.MaxInt64)))
	assert.False(t, config.IsDynamicGasLimit(big.NewInt(math.MaxInt64)))
	assert.False(t, config.IsTIPUpgradeReward(big.NewInt(math.MaxInt64)))
	assert.False(t, config.IsTIPUpgradePenalty(big.NewInt(math.MaxInt64)))
	assert.False(t, config.IsTIPEpochHalving(big.NewInt(math.MaxInt64)))

	description := config.Description()
	assertDescriptionLineValue := func(t *testing.T, label, value string) {
		t.Helper()
		for _, line := range strings.Split(description, "\n") {
			if strings.Contains(line, label) {
				assert.Contains(t, line, value, "description line for %s should contain %s", label, value)
				return
			}
		}
		assert.Failf(t, "missing description line", "description must contain a line for %s", label)
	}

	assertDescriptionLineValue(t, "TIP2019:", "<nil>")
	assertDescriptionLineValue(t, "TIPSigning:", "<nil>")
	assertDescriptionLineValue(t, "TIPRandomize:", "<nil>")
	assertDescriptionLineValue(t, "TIPIncreaseMasternodes:", "<nil>")
	assertDescriptionLineValue(t, "Denylist:", "<nil>")
	assertDescriptionLineValue(t, "TIPNoHalvingMNReward:", "<nil>")
	assertDescriptionLineValue(t, "TIPXDCX:", "<nil>")
	assertDescriptionLineValue(t, "TIPXDCXLending:", "<nil>")
	assertDescriptionLineValue(t, "TIPXDCXCancellationFee:", "<nil>")
	assertDescriptionLineValue(t, "TIPTRC21Fee:", "<nil>")
	assertDescriptionLineValue(t, "Berlin:", "<nil>")
	assertDescriptionLineValue(t, "London:", "<nil>")
	assertDescriptionLineValue(t, "Merge:", "<nil>")
	assertDescriptionLineValue(t, "Shanghai:", "<nil>")
	assertDescriptionLineValue(t, "TIPXDCXMinerDisable:", "<nil>")
	assertDescriptionLineValue(t, "TIPXDCXReceiverDisable:", "<nil>")
	assertDescriptionLineValue(t, "Cancun:", "<nil>")
	assertDescriptionLineValue(t, "Prague:", "<nil>")
	assertDescriptionLineValue(t, "Osaka:", "<nil>")
	assertDescriptionLineValue(t, "DynamicGasLimit:", "<nil>")
	assertDescriptionLineValue(t, "TIPUpgradeReward:", "<nil>")
	assertDescriptionLineValue(t, "TIPUpgradePenalty:", "<nil>")
	assertDescriptionLineValue(t, "TIPEpochHalving:", "<nil>")
	assertDescriptionLineValue(t, "TRC21IssuerSMC:", zeroAddress0x)
	assertDescriptionLineValue(t, "XDCXListingSMC:", zeroAddress0x)
	assertDescriptionLineValue(t, "RelayerRegistrationSMC:", zeroAddress0x)
	assertDescriptionLineValue(t, "LendingRegistrationSMC:", zeroAddress0x)
}

func TestGatherForksIncludesXDPoSV2SwitchBlock(t *testing.T) {
	config := &ChainConfig{
		HomesteadBlock: big.NewInt(0),
		BerlinBlock:    big.NewInt(1000),
		Eip1559Block:   big.NewInt(1000),
		XDPoS: &XDPoSConfig{V2: &V2{
			SwitchBlock: big.NewInt(1500),
		}},
	}
	assert.Equal(t, []uint64{1000, 1500}, config.GatherForks())
}

func TestChainConfigStringIncludesAllFields(t *testing.T) {
	config := &ChainConfig{
		ChainID:                     big.NewInt(1),
		HomesteadBlock:              big.NewInt(2),
		DAOForkBlock:                big.NewInt(3),
		DAOForkSupport:              true,
		EIP150Block:                 big.NewInt(4),
		EIP155Block:                 big.NewInt(5),
		EIP158Block:                 big.NewInt(6),
		ByzantiumBlock:              big.NewInt(7),
		ConstantinopleBlock:         big.NewInt(8),
		PetersburgBlock:             big.NewInt(9),
		IstanbulBlock:               big.NewInt(10),
		BerlinBlock:                 big.NewInt(11),
		LondonBlock:                 big.NewInt(12),
		MergeBlock:                  big.NewInt(13),
		ShanghaiBlock:               big.NewInt(14),
		Eip1559Block:                big.NewInt(15),
		CancunBlock:                 big.NewInt(16),
		PragueBlock:                 big.NewInt(17),
		OsakaBlock:                  big.NewInt(18),
		TIP2019Block:                big.NewInt(19),
		TIPSigningBlock:             big.NewInt(20),
		TIPRandomizeBlock:           big.NewInt(21),
		TIPIncreaseMasternodesBlock: big.NewInt(22),
		DenylistBlock:               big.NewInt(23),
		TIPNoHalvingMNRewardBlock:   big.NewInt(24),
		TIPXDCXBlock:                big.NewInt(25),
		TIPXDCXLendingBlock:         big.NewInt(26),
		TIPXDCXCancellationFeeBlock: big.NewInt(27),
		TIPTRC21FeeBlock:            big.NewInt(28),
		TIPXDCXMinerDisableBlock:    big.NewInt(29),
		TIPXDCXReceiverDisableBlock: big.NewInt(30),
		DynamicGasLimitBlock:        big.NewInt(31),
		TIPUpgradeRewardBlock:       big.NewInt(32),
		TIPUpgradePenaltyBlock:      big.NewInt(33),
		TIPEpochHalvingBlock:        big.NewInt(34),
		TRC21IssuerSMC:              common.HexToAddress("0x8c0faeb5C6bEd2129b8674F262Fd45c4e9468bee"),
		XDCXListingSMC:              common.HexToAddress("0xDE34dD0f536170993E8CFF639DdFfCF1A85D3E53"),
		RelayerRegistrationSMC:      common.HexToAddress("0x16c63b79f9C8784168103C0b74E6A59EC2de4a02"),
		LendingRegistrationSMC:      common.HexToAddress("0x7d761afd7ff65a79e4173897594a194e3c506e57"),
		Ethash:                      new(EthashConfig),
		Clique:                      &CliqueConfig{Period: 1, Epoch: 2},
		XDPoS: &XDPoSConfig{
			Period:               2,
			Epoch:                900,
			Reward:               5000,
			RewardCheckpoint:     900,
			Gap:                  450,
			FoundationWalletAddr: common.HexToAddress("0x0000000000000000000000000000000000000068"),
			V2: &V2{
				SwitchEpoch: 1,
				SwitchBlock: big.NewInt(900),
				CurrentConfig: &V2Config{
					MaxMasternodes: 18,
				},
			},
		},
	}

	got := config.String()
	assert.NotContains(t, got, "SchemaVersion:")

	encoded, err := json.Marshal(config)
	assert.NoError(t, err)
	assert.NotContains(t, string(encoded), "schemaVersion")

	for _, label := range []string{
		"ChainID:",
		"Homestead:",
		"DAOFork:",
		"DAOForkSupport:",
		"TIP2019:",
		"EIP150:",
		"EIP155:",
		"EIP158:",
		"Byzantium:",
		"Constantinople:",
		"Petersburg:",
		"Istanbul:",
		"TIPSigning:",
		"TIPRandomize:",
		"TIPIncreaseMasternodes:",
		"Denylist:",
		"TIPNoHalvingMNReward:",
		"TIPXDCX:",
		"TIPXDCXLending:",
		"TIPXDCXCancellationFee:",
		"TIPTRC21Fee:",
		"Berlin:",
		"London:",
		"Merge:",
		"Shanghai:",
		"TIPXDCXMinerDisable:",
		"TIPXDCXReceiverDisable:",
		"Eip1559:",
		"Cancun:",
		"Prague:",
		"Osaka:",
		"DynamicGasLimit:",
		"TIPUpgradeReward:",
		"TIPUpgradePenalty:",
		"TIPEpochHalving:",
		"TRC21IssuerSMC:",
		"XDCXListingSMC:",
		"RelayerRegistrationSMC:",
		"LendingRegistrationSMC:",
		"Ethash:",
		"Clique:",
		"XDPoS:",
	} {
		assert.Contains(t, got, label)
	}
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

func TestGetBuiltInChainConfigByHashHashOnly(t *testing.T) {
	tests := []struct {
		name string
		hash common.Hash
		want bool
	}{
		{name: "mainnet hash", hash: MainnetGenesisHash, want: true},
		{name: "testnet hash", hash: TestnetGenesisHash, want: true},
		{name: "devnet hash", hash: DevnetGenesisHash, want: true},
		{name: "empty hash", hash: common.Hash{}, want: false},
		{name: "random hash", hash: common.HexToHash("0x1"), want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, GetBuiltInChainConfigByHash(tt.hash) != nil)
		})
	}
}

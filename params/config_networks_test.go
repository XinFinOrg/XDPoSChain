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
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/stretchr/testify/assert"
)

func TestBuiltInChainConfigsPassCheckConfigForkOrder(t *testing.T) {
	tests := []struct {
		name string
		cfg  *ChainConfig
	}{
		{name: "XDCMainnetChainConfig", cfg: XDCMainnetChainConfig},
		{name: "MainnetChainConfig", cfg: MainnetChainConfig},
		{name: "TestnetChainConfig", cfg: TestnetChainConfig},
		{name: "DevnetChainConfig", cfg: DevnetChainConfig},
		{name: "LocalnetChainConfig", cfg: LocalnetChainConfig},
		{name: "AllEthashProtocolChanges", cfg: AllEthashProtocolChanges},
		{name: "AllDevChainProtocolChanges", cfg: AllDevChainProtocolChanges},
		{name: "AllCliqueProtocolChanges", cfg: AllCliqueProtocolChanges},
		{name: "TestXDPoSMockChainConfig", cfg: TestXDPoSMockChainConfig},
		{name: "TestChainConfig", cfg: TestChainConfig},
		{name: "MergedTestChainConfig", cfg: MergedTestChainConfig},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.cfg.CheckConfigForkOrder(); err != nil {
				t.Fatalf("CheckConfigForkOrder returned unexpected error: %v", err)
			}
		})
	}
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
	assertBlock("EIP1559Block", config.EIP1559Block)
	assertBlock("CancunBlock", config.CancunBlock)
	assertBlock("PragueBlock", config.PragueBlock)
	assertBlock("OsakaBlock", config.OsakaBlock)
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
			assertBlock(t, "EIP1559", test.config.EIP1559Block, test.eip1559Block)
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

func TestSharedTestConfigsDefaultGas50xBlockToZero(t *testing.T) {
	tests := []struct {
		name string
		cfg  *ChainConfig
	}{
		{name: "all ethash", cfg: AllEthashProtocolChanges},
		{name: "all clique", cfg: AllCliqueProtocolChanges},
		{name: "test", cfg: TestChainConfig},
		{name: "merged test", cfg: MergedTestChainConfig},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.cfg.Gas50xBlock == nil || tc.cfg.Gas50xBlock.Cmp(big.NewInt(0)) != 0 {
				t.Fatalf("expected Gas50xBlock to default to 0, have %v", tc.cfg.Gas50xBlock)
			}
		})
	}
}

func TestMainnetChainConfigDoesNotDeclareXDCSpecificFields(t *testing.T) {
	if MainnetChainConfig.TIPTRC21FeeBlock != nil {
		t.Fatalf("expected MainnetChainConfig TIPTRC21FeeBlock to be nil, have %v", MainnetChainConfig.TIPTRC21FeeBlock)
	}
	if MainnetChainConfig.Gas50xBlock != nil {
		t.Fatalf("expected MainnetChainConfig Gas50xBlock to be nil, have %v", MainnetChainConfig.Gas50xBlock)
	}
	if MainnetChainConfig.TRC21IssuerSMC != (common.Address{}) {
		t.Fatalf("expected MainnetChainConfig TRC21IssuerSMC to be zero, have %s", MainnetChainConfig.TRC21IssuerSMC.Hex())
	}
	if MainnetChainConfig.XDCXListingSMC != (common.Address{}) {
		t.Fatalf("expected MainnetChainConfig XDCXListingSMC to be zero, have %s", MainnetChainConfig.XDCXListingSMC.Hex())
	}
	if MainnetChainConfig.RelayerRegistrationSMC != (common.Address{}) {
		t.Fatalf("expected MainnetChainConfig RelayerRegistrationSMC to be zero, have %s", MainnetChainConfig.RelayerRegistrationSMC.Hex())
	}
	if MainnetChainConfig.LendingRegistrationSMC != (common.Address{}) {
		t.Fatalf("expected MainnetChainConfig LendingRegistrationSMC to be zero, have %s", MainnetChainConfig.LendingRegistrationSMC.Hex())
	}

	if XDCMainnetChainConfig.TIPTRC21FeeBlock == nil {
		t.Fatal("expected XDCMainnetChainConfig TIPTRC21FeeBlock to remain configured")
	}
	if XDCMainnetChainConfig.Gas50xBlock == nil {
		t.Fatal("expected XDCMainnetChainConfig Gas50xBlock to remain configured")
	}
	if XDCMainnetChainConfig.TRC21IssuerSMC == (common.Address{}) {
		t.Fatal("expected XDCMainnetChainConfig TRC21IssuerSMC to remain configured")
	}
}

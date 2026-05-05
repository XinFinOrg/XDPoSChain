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
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math/big"
	"slices"
	"strings"
	"sync"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/log"
)

const (
	ConsensusEngineVersion1 = "v1"
	ConsensusEngineVersion2 = "v2"
	Default                 = 0

	MainnetV2SwitchBlock uint64 = 80370000 // Target 2nd Oct 2024
	TestnetV2SwitchBlock uint64 = 56828700 // Target 13th Nov 2023
	DevnetV2SwitchBlock  uint64 = 2700
)

var migratedForkFieldJSONKeys = []string{
	"tip2019Block",
	"tipSigningBlock",
	"tipRandomizeBlock",
	"tipIncreaseMasternodesBlock",
	"denylistBlock",
	"tipNoHalvingMNRewardBlock",
	"tipXDCXBlock",
	"tipXDCXLendingBlock",
	"tipXDCXCancellationFeeBlock",
	"tipTRC21FeeBlock",
	"berlinBlock",
	"londonBlock",
	"mergeBlock",
	"shanghaiBlock",
	"tipXDCXMinerDisableBlock",
	"tipXDCXReceiverDisableBlock",
	"eip1559Block",
	"cancunBlock",
	"pragueBlock",
	"osakaBlock",
	"dynamicGasLimitBlock",
	"tipUpgradeRewardBlock",
	"tipUpgradePenaltyBlock",
	"tipEpochHalvingBlock",
}

var (
	ErrMissingForkSwitch    = errors.New("missing fork switch")
	ErrWrongForkSwitchOrder = errors.New("wrong fork switch order")
)

// MigratedForkFieldJSONKeys returns migrated fork JSON keys as a defensive copy.
func MigratedForkFieldJSONKeys() []string {
	return append([]string(nil), migratedForkFieldJSONKeys...)
}

var (
	MainnetGenesisHash = common.HexToHash("0x4a9d748bd78a8d0385b67788c2435dcdb914f98a96250b68863a1f8b7642d6b1") // XDC Mainnet genesis hash to enforce below configs on
	TestnetGenesisHash = common.HexToHash("0xbdea512b4f12ff1135ec92c00dc047ffb93890c2ea1aa0eefe9b013d80640075") // XDC Testnet genesis hash to enforce below configs on
	DevnetGenesisHash  = common.HexToHash("0x7dad95b83c6c1d413de03bd5fcf2d446217db55b2b18e3eaacacbfa4e7629cc9") // XDC Devnet genesis hash to enforce below configs on
)

var (
	MainnetV2Configs = map[uint64]*V2Config{
		Default: {
			MaxMasternodes:       108,
			SwitchRound:          0,
			CertThreshold:        0.667,
			TimeoutSyncThreshold: 3,
			TimeoutPeriod:        30,
			MinePeriod:           2,
			ExpTimeoutConfig:     ExpTimeoutConfig{Base: 1.0, MaxExponent: 0},
		},
		2000: {
			MaxMasternodes:       108,
			SwitchRound:          2000,
			CertThreshold:        0.667,
			TimeoutSyncThreshold: 2,
			TimeoutPeriod:        600,
			MinePeriod:           2,
			ExpTimeoutConfig:     ExpTimeoutConfig{Base: 1.0, MaxExponent: 0},
		},
		8000: {
			MaxMasternodes:       108,
			SwitchRound:          8000,
			CertThreshold:        0.667,
			TimeoutSyncThreshold: 2,
			TimeoutPeriod:        60,
			MinePeriod:           2,
			ExpTimeoutConfig:     ExpTimeoutConfig{Base: 1.0, MaxExponent: 0},
		},
		220000: {
			MaxMasternodes:       108,
			SwitchRound:          220000,
			CertThreshold:        0.667,
			TimeoutSyncThreshold: 2,
			TimeoutPeriod:        30,
			MinePeriod:           2,
			ExpTimeoutConfig:     ExpTimeoutConfig{Base: 1.0, MaxExponent: 0},
		},
		460000: {
			MaxMasternodes:       108,
			SwitchRound:          460000,
			CertThreshold:        0.667,
			TimeoutSyncThreshold: 2,
			TimeoutPeriod:        20,
			MinePeriod:           2,
			ExpTimeoutConfig:     ExpTimeoutConfig{Base: 1.0, MaxExponent: 0},
		},
		3200000: {
			MaxMasternodes:       108,
			SwitchRound:          3200000,
			CertThreshold:        0.667,
			TimeoutSyncThreshold: 3,
			TimeoutPeriod:        10,
			MinePeriod:           2,
			ExpTimeoutConfig:     ExpTimeoutConfig{Base: 1.0, MaxExponent: 0},
		},
	}

	TestnetV2Configs = map[uint64]*V2Config{
		Default: {
			MaxMasternodes:       15,
			SwitchRound:          0,
			CertThreshold:        0.45,
			TimeoutSyncThreshold: 3,
			TimeoutPeriod:        60,
			MinePeriod:           2,
			ExpTimeoutConfig:     ExpTimeoutConfig{Base: 1.0, MaxExponent: 0},
		},
		900000: {
			MaxMasternodes:       108,
			SwitchRound:          900000,
			CertThreshold:        0.667,
			TimeoutSyncThreshold: 3,
			TimeoutPeriod:        60,
			MinePeriod:           2,
			ExpTimeoutConfig:     ExpTimeoutConfig{Base: 1.0, MaxExponent: 0},
		},
		15000000: {
			MaxMasternodes:       108,
			SwitchRound:          15000000,
			CertThreshold:        0.667,
			TimeoutSyncThreshold: 3,
			TimeoutPeriod:        10,
			MinePeriod:           2,
			ExpTimeoutConfig:     ExpTimeoutConfig{Base: 1.0, MaxExponent: 0},
		},
	}

	DevnetV2Configs = map[uint64]*V2Config{
		Default: {
			SwitchRound:               0,
			MaxMasternodes:            108,
			MaxProtectorNodes:         0,
			MaxObverserNodes:          0,
			CertThreshold:             0.667,
			TimeoutSyncThreshold:      3,
			TimeoutPeriod:             10,
			MinePeriod:                2,
			ExpTimeoutConfig:          ExpTimeoutConfig{Base: 1.0, MaxExponent: 0},
			MasternodeReward:          0,
			ProtectorReward:           0,
			ObserverReward:            0,
			MinimumMinerBlockPerEpoch: 0,
			LimitPenaltyEpoch:         0,
			MinimumSigningTx:          0,
		},
		5000000: {
			SwitchRound:               5000000,
			MaxMasternodes:            108,
			MaxProtectorNodes:         10,
			MaxObverserNodes:          1000,
			CertThreshold:             0.667,
			TimeoutSyncThreshold:      3,
			TimeoutPeriod:             10,
			MinePeriod:                2,
			ExpTimeoutConfig:          ExpTimeoutConfig{Base: 1.0, MaxExponent: 0},
			MasternodeReward:          63.42,
			ProtectorReward:           50.27,
			ObserverReward:            25.13,
			MinimumMinerBlockPerEpoch: 0,
			LimitPenaltyEpoch:         0,
			MinimumSigningTx:          0,
		},
	}

	LocalnetV2Configs = map[uint64]*V2Config{
		Default: {
			MaxMasternodes:       108,
			SwitchRound:          0,
			CertThreshold:        0.666,
			TimeoutSyncThreshold: 3,
			TimeoutPeriod:        10,
			MinePeriod:           2,
			ExpTimeoutConfig:     ExpTimeoutConfig{Base: 1.0, MaxExponent: 0},
		},
	}

	UnitTestV2Configs = map[uint64]*V2Config{
		Default: {
			MaxMasternodes:       18,
			SwitchRound:          0,
			CertThreshold:        0.667,
			TimeoutSyncThreshold: 2,
			TimeoutPeriod:        4,
			MinePeriod:           2,
			ExpTimeoutConfig:     ExpTimeoutConfig{Base: 1.0, MaxExponent: 0},
		},
		10: {
			MaxMasternodes:       18,
			SwitchRound:          10,
			CertThreshold:        0.667,
			TimeoutSyncThreshold: 2,
			TimeoutPeriod:        4,
			MinePeriod:           3,
			ExpTimeoutConfig:     ExpTimeoutConfig{Base: 1.0, MaxExponent: 0},
		},
		900: {
			MaxMasternodes:       20,
			MaxProtectorNodes:    17,
			MaxObverserNodes:     1,
			SwitchRound:          900,
			CertThreshold:        0.667,
			TimeoutSyncThreshold: 4,
			TimeoutPeriod:        5,
			MinePeriod:           2,
			ExpTimeoutConfig:     ExpTimeoutConfig{Base: 1.0, MaxExponent: 0},
			MasternodeReward:     500, // double as Reward
			ProtectorReward:      400,
			ObserverReward:       300.125,
			LimitPenaltyEpoch:    2,
			MinimumSigningTx:     2,
		},
	}

	// XDPoSChain mainnet config
	XDCMainnetChainConfig = &ChainConfig{
		Name:                        "XDCMainnetChainConfig",
		ChainID:                     big.NewInt(50),
		HomesteadBlock:              big.NewInt(1),
		DAOForkBlock:                nil,
		DAOForkSupport:              false,
		TIP2019Block:                big.NewInt(1),
		EIP150Block:                 big.NewInt(2),
		EIP155Block:                 big.NewInt(3),
		EIP158Block:                 big.NewInt(3),
		ByzantiumBlock:              big.NewInt(4),
		ConstantinopleBlock:         nil,
		PetersburgBlock:             nil,
		IstanbulBlock:               nil,
		TIPSigningBlock:             big.NewInt(3000000),
		TIPRandomizeBlock:           big.NewInt(3464000),
		TIPIncreaseMasternodesBlock: big.NewInt(5000000),
		DenylistBlock:               big.NewInt(38383838),
		TIPNoHalvingMNRewardBlock:   big.NewInt(38383838),
		TIPXDCXBlock:                big.NewInt(38383838),
		TIPXDCXLendingBlock:         big.NewInt(38383838),
		TIPXDCXCancellationFeeBlock: big.NewInt(38383838),
		TIPTRC21FeeBlock:            big.NewInt(38383838),
		BerlinBlock:                 big.NewInt(76321000),
		LondonBlock:                 big.NewInt(76321000),
		MergeBlock:                  big.NewInt(76321000),
		ShanghaiBlock:               big.NewInt(76321000),
		Gas50xBlock:                 big.NewInt(80370000),
		TIPXDCXMinerDisableBlock:    big.NewInt(80370000),
		TIPXDCXReceiverDisableBlock: big.NewInt(80370900),
		Eip1559Block:                big.NewInt(98800200),
		CancunBlock:                 big.NewInt(98802000),
		PragueBlock:                 nil,
		OsakaBlock:                  nil,
		DynamicGasLimitBlock:        nil,
		TIPUpgradeRewardBlock:       nil,
		TIPUpgradePenaltyBlock:      nil,
		TIPEpochHalvingBlock:        nil,
		TRC21IssuerSMC:              common.HexToAddress("0x8c0faeb5C6bEd2129b8674F262Fd45c4e9468bee"),
		XDCXListingSMC:              common.HexToAddress("0xDE34dD0f536170993E8CFF639DdFfCF1A85D3E53"),
		RelayerRegistrationSMC:      common.HexToAddress("0x16c63b79f9C8784168103C0b74E6A59EC2de4a02"),
		LendingRegistrationSMC:      common.HexToAddress("0x7d761afd7ff65a79e4173897594a194e3c506e57"),
		Clique:                      nil,
		Ethash:                      nil,
		XDPoS: &XDPoSConfig{
			Period:               2,
			Epoch:                900,
			Reward:               5000,
			RewardCheckpoint:     900,
			Gap:                  450,
			FoundationWalletAddr: common.HexToAddress("xdc92a289fe95a85c53b8d0d113cbaef0c1ec98ac65"),
			MaxMasternodesV2:     108,
			V2: &V2{
				SwitchEpoch:   MainnetV2SwitchBlock / 900,
				SwitchBlock:   big.NewInt(int64(MainnetV2SwitchBlock)),
				CurrentConfig: MainnetV2Configs[0],
				AllConfigs:    MainnetV2Configs,
			},
		},
	}

	// MainnetChainConfig is the chain parameters to run a node on the ethereum main network.
	MainnetChainConfig = &ChainConfig{
		Name:                        "MainnetChainConfig",
		ChainID:                     big.NewInt(1),
		HomesteadBlock:              big.NewInt(1150000),
		DAOForkBlock:                big.NewInt(1920000),
		DAOForkSupport:              true,
		TIP2019Block:                nil,
		EIP150Block:                 big.NewInt(2463000),
		EIP155Block:                 big.NewInt(2675000),
		EIP158Block:                 big.NewInt(2675000),
		ByzantiumBlock:              big.NewInt(4370000),
		ConstantinopleBlock:         nil,
		PetersburgBlock:             nil,
		IstanbulBlock:               nil,
		TIPSigningBlock:             nil,
		TIPRandomizeBlock:           nil,
		TIPIncreaseMasternodesBlock: nil,
		DenylistBlock:               nil,
		TIPNoHalvingMNRewardBlock:   nil,
		TIPXDCXBlock:                nil,
		TIPXDCXLendingBlock:         nil,
		TIPXDCXCancellationFeeBlock: nil,
		TIPTRC21FeeBlock:            big.NewInt(0),
		BerlinBlock:                 nil,
		LondonBlock:                 nil,
		MergeBlock:                  nil,
		ShanghaiBlock:               nil,
		Gas50xBlock:                 big.NewInt(80370000),
		TIPXDCXMinerDisableBlock:    nil,
		TIPXDCXReceiverDisableBlock: nil,
		Eip1559Block:                nil,
		CancunBlock:                 nil,
		PragueBlock:                 nil,
		OsakaBlock:                  nil,
		DynamicGasLimitBlock:        nil,
		TIPUpgradeRewardBlock:       nil,
		TIPUpgradePenaltyBlock:      nil,
		TIPEpochHalvingBlock:        nil,
		TRC21IssuerSMC:              common.HexToAddress("0x8c0faeb5C6bEd2129b8674F262Fd45c4e9468bee"),
		XDCXListingSMC:              common.HexToAddress("0xDE34dD0f536170993E8CFF639DdFfCF1A85D3E53"),
		RelayerRegistrationSMC:      common.HexToAddress("0x16c63b79f9C8784168103C0b74E6A59EC2de4a02"),
		LendingRegistrationSMC:      common.HexToAddress("0x7d761afd7ff65a79e4173897594a194e3c506e57"),
		Clique:                      nil,
		Ethash:                      new(EthashConfig),
		XDPoS:                       nil,
	}

	// TestnetChainConfig contains the chain parameters to run a node on the Apothem testnet.
	TestnetChainConfig = &ChainConfig{
		Name:                        "TestnetChainConfig",
		ChainID:                     big.NewInt(51),
		HomesteadBlock:              big.NewInt(1),
		DAOForkBlock:                nil,
		DAOForkSupport:              false,
		TIP2019Block:                big.NewInt(1),
		EIP150Block:                 big.NewInt(2),
		EIP155Block:                 big.NewInt(3),
		EIP158Block:                 big.NewInt(3),
		ByzantiumBlock:              big.NewInt(4),
		ConstantinopleBlock:         nil,
		PetersburgBlock:             nil,
		IstanbulBlock:               nil,
		TIPSigningBlock:             big.NewInt(3000000),
		TIPRandomizeBlock:           big.NewInt(3464000),
		TIPIncreaseMasternodesBlock: big.NewInt(5000000),
		DenylistBlock:               big.NewInt(23779191),
		TIPNoHalvingMNRewardBlock:   big.NewInt(23779191),
		TIPXDCXBlock:                big.NewInt(23779191),
		TIPXDCXLendingBlock:         big.NewInt(23779191),
		TIPXDCXCancellationFeeBlock: big.NewInt(23779191),
		TIPTRC21FeeBlock:            big.NewInt(23779191),
		Gas50xBlock:                 big.NewInt(56828700),
		BerlinBlock:                 big.NewInt(61290000),
		LondonBlock:                 big.NewInt(61290000),
		MergeBlock:                  big.NewInt(61290000),
		ShanghaiBlock:               big.NewInt(61290000),
		TIPXDCXMinerDisableBlock:    big.NewInt(61290000),
		TIPXDCXReceiverDisableBlock: big.NewInt(66825000),
		Eip1559Block:                big.NewInt(71550000),
		CancunBlock:                 big.NewInt(71551800),
		PragueBlock:                 nil,
		OsakaBlock:                  nil,
		DynamicGasLimitBlock:        nil,
		TIPUpgradeRewardBlock:       nil,
		TIPUpgradePenaltyBlock:      nil,
		TIPEpochHalvingBlock:        nil,
		TRC21IssuerSMC:              common.HexToAddress("0x0E2C88753131CE01c7551B726b28BFD04e44003F"),
		XDCXListingSMC:              common.HexToAddress("0x14B2Bf043b9c31827A472CE4F94294fE9a6277e0"),
		RelayerRegistrationSMC:      common.HexToAddress("0xA1996F69f47ba14Cb7f661010A7C31974277958c"),
		LendingRegistrationSMC:      common.HexToAddress("0x28d7fC2Cf5c18203aaCD7459EFC6Af0643C97bE8"),
		Clique:                      nil,
		Ethash:                      nil,
		XDPoS: &XDPoSConfig{
			Period:               2,
			Epoch:                900,
			Reward:               5000,
			RewardCheckpoint:     900,
			Gap:                  450,
			FoundationWalletAddr: common.HexToAddress("xdc746249c61f5832c5eed53172776b460491bdcd5c"),
			MaxMasternodesV2:     15,
			V2: &V2{
				SwitchEpoch:   TestnetV2SwitchBlock / 900,
				SwitchBlock:   big.NewInt(int64(TestnetV2SwitchBlock)),
				CurrentConfig: TestnetV2Configs[0],
				AllConfigs:    TestnetV2Configs,
			},
		},
	}

	// DevnetChainConfig contains the chain parameters to run a node on the devnet.
	DevnetChainConfig = &ChainConfig{
		Name:                        "DevnetChainConfig",
		ChainID:                     big.NewInt(5551),
		HomesteadBlock:              big.NewInt(0),
		DAOForkBlock:                nil,
		DAOForkSupport:              false,
		TIP2019Block:                big.NewInt(0),
		EIP150Block:                 big.NewInt(0),
		EIP155Block:                 big.NewInt(0),
		EIP158Block:                 big.NewInt(0),
		ByzantiumBlock:              big.NewInt(0),
		ConstantinopleBlock:         nil,
		PetersburgBlock:             nil,
		IstanbulBlock:               nil,
		TIPSigningBlock:             big.NewInt(0),
		TIPRandomizeBlock:           big.NewInt(0),
		TIPIncreaseMasternodesBlock: big.NewInt(0),
		DenylistBlock:               big.NewInt(0),
		TIPNoHalvingMNRewardBlock:   big.NewInt(0),
		TIPXDCXBlock:                big.NewInt(0),
		TIPXDCXLendingBlock:         big.NewInt(0),
		TIPXDCXCancellationFeeBlock: big.NewInt(0),
		TIPTRC21FeeBlock:            big.NewInt(0),
		BerlinBlock:                 big.NewInt(0),
		LondonBlock:                 big.NewInt(0),
		MergeBlock:                  big.NewInt(0),
		ShanghaiBlock:               big.NewInt(0),
		Gas50xBlock:                 big.NewInt(0),
		TIPXDCXMinerDisableBlock:    big.NewInt(0),
		TIPXDCXReceiverDisableBlock: big.NewInt(0),
		Eip1559Block:                big.NewInt(250000),
		CancunBlock:                 big.NewInt(250000),
		PragueBlock:                 big.NewInt(5000000),
		OsakaBlock:                  nil,
		DynamicGasLimitBlock:        big.NewInt(5000000),
		TIPUpgradeRewardBlock:       big.NewInt(5000000),
		TIPUpgradePenaltyBlock:      big.NewInt(5000000),
		TIPEpochHalvingBlock:        nil,
		TRC21IssuerSMC:              common.HexToAddress("0x8c0faeb5C6bEd2129b8674F262Fd45c4e9468bee"),
		XDCXListingSMC:              common.HexToAddress("0xDE34dD0f536170993E8CFF639DdFfCF1A85D3E53"),
		RelayerRegistrationSMC:      common.HexToAddress("0x16c63b79f9C8784168103C0b74E6A59EC2de4a02"),
		LendingRegistrationSMC:      common.HexToAddress("0x7d761afd7ff65a79e4173897594a194e3c506e57"),
		Clique:                      nil,
		Ethash:                      nil,
		XDPoS: &XDPoSConfig{
			Period:               2,
			Epoch:                900,
			Reward:               7125,
			RewardCheckpoint:     900,
			Gap:                  450,
			FoundationWalletAddr: common.HexToAddress("0x4f288181b1d1aa599c6d7629f1168d46d5f96338"),
			MaxMasternodesV2:     108,
			V2: &V2{
				SwitchEpoch:   DevnetV2SwitchBlock / 900,
				SwitchBlock:   big.NewInt(int64(DevnetV2SwitchBlock)),
				CurrentConfig: DevnetV2Configs[0],
				AllConfigs:    DevnetV2Configs,
			},
		},
	}

	// LocalnetChainConfig contains the chain parameters to run a node on the local network.
	LocalnetChainConfig = &ChainConfig{
		Name:                        "LocalnetChainConfig",
		ChainID:                     big.NewInt(5151),
		HomesteadBlock:              big.NewInt(0),
		DAOForkBlock:                nil,
		DAOForkSupport:              false,
		TIP2019Block:                big.NewInt(0),
		EIP150Block:                 big.NewInt(0),
		EIP155Block:                 big.NewInt(0),
		EIP158Block:                 big.NewInt(0),
		ByzantiumBlock:              big.NewInt(0),
		ConstantinopleBlock:         nil,
		PetersburgBlock:             nil,
		IstanbulBlock:               nil,
		TIPSigningBlock:             big.NewInt(0),
		TIPRandomizeBlock:           big.NewInt(0),
		TIPIncreaseMasternodesBlock: big.NewInt(0),
		DenylistBlock:               big.NewInt(0),
		TIPNoHalvingMNRewardBlock:   big.NewInt(0),
		TIPXDCXBlock:                big.NewInt(0),
		TIPXDCXLendingBlock:         big.NewInt(0),
		TIPXDCXCancellationFeeBlock: big.NewInt(0),
		TIPTRC21FeeBlock:            big.NewInt(0),
		BerlinBlock:                 big.NewInt(0),
		LondonBlock:                 big.NewInt(0),
		MergeBlock:                  big.NewInt(0),
		ShanghaiBlock:               big.NewInt(0),
		Gas50xBlock:                 big.NewInt(0),
		TIPXDCXMinerDisableBlock:    big.NewInt(0),
		TIPXDCXReceiverDisableBlock: big.NewInt(0),
		Eip1559Block:                big.NewInt(0),
		CancunBlock:                 big.NewInt(0),
		PragueBlock:                 nil,
		OsakaBlock:                  nil,
		DynamicGasLimitBlock:        nil,
		TIPUpgradeRewardBlock:       nil,
		TIPUpgradePenaltyBlock:      nil,
		TIPEpochHalvingBlock:        nil,
		TRC21IssuerSMC:              common.HexToAddress("0x8c0faeb5C6bEd2129b8674F262Fd45c4e9468bee"),
		XDCXListingSMC:              common.HexToAddress("0xDE34dD0f536170993E8CFF639DdFfCF1A85D3E53"),
		RelayerRegistrationSMC:      common.HexToAddress("0x16c63b79f9C8784168103C0b74E6A59EC2de4a02"),
		LendingRegistrationSMC:      common.HexToAddress("0x7d761afd7ff65a79e4173897594a194e3c506e57"),
		Clique:                      nil,
		Ethash:                      nil,
		XDPoS: &XDPoSConfig{
			MaxMasternodesV2: 108,
		},
	}

	// AllEthashProtocolChanges contains every protocol change (EIPs) introduced
	// and accepted by the Ethereum core developers into the Ethash consensus.
	AllEthashProtocolChanges = &ChainConfig{
		Name:                        "AllEthashProtocolChanges",
		ChainID:                     big.NewInt(1337),
		HomesteadBlock:              big.NewInt(0),
		DAOForkBlock:                nil,
		DAOForkSupport:              false,
		TIP2019Block:                big.NewInt(0),
		EIP150Block:                 big.NewInt(0),
		EIP155Block:                 big.NewInt(0),
		EIP158Block:                 big.NewInt(0),
		ByzantiumBlock:              big.NewInt(0),
		ConstantinopleBlock:         big.NewInt(0),
		PetersburgBlock:             big.NewInt(0),
		IstanbulBlock:               big.NewInt(0),
		TIPSigningBlock:             big.NewInt(0),
		TIPRandomizeBlock:           big.NewInt(0),
		TIPIncreaseMasternodesBlock: big.NewInt(0),
		DenylistBlock:               big.NewInt(0),
		TIPNoHalvingMNRewardBlock:   big.NewInt(0),
		TIPXDCXBlock:                big.NewInt(0),
		TIPXDCXLendingBlock:         big.NewInt(0),
		TIPXDCXCancellationFeeBlock: big.NewInt(0),
		TIPTRC21FeeBlock:            big.NewInt(0),
		BerlinBlock:                 big.NewInt(0),
		LondonBlock:                 big.NewInt(0),
		MergeBlock:                  big.NewInt(0),
		ShanghaiBlock:               big.NewInt(0),
		Gas50xBlock:                 big.NewInt(80370000),
		TIPXDCXMinerDisableBlock:    nil,
		TIPXDCXReceiverDisableBlock: nil,
		Eip1559Block:                big.NewInt(0),
		CancunBlock:                 big.NewInt(0),
		PragueBlock:                 big.NewInt(0),
		OsakaBlock:                  big.NewInt(0),
		DynamicGasLimitBlock:        nil,
		TIPUpgradeRewardBlock:       nil,
		TIPUpgradePenaltyBlock:      nil,
		TIPEpochHalvingBlock:        nil,
		TRC21IssuerSMC:              common.HexToAddress("0x8c0faeb5C6bEd2129b8674F262Fd45c4e9468bee"),
		XDCXListingSMC:              common.HexToAddress("0xDE34dD0f536170993E8CFF639DdFfCF1A85D3E53"),
		RelayerRegistrationSMC:      common.HexToAddress("0x16c63b79f9C8784168103C0b74E6A59EC2de4a02"),
		LendingRegistrationSMC:      common.HexToAddress("0x7d761afd7ff65a79e4173897594a194e3c506e57"),
		Clique:                      nil,
		Ethash:                      new(EthashConfig),
		XDPoS:                       nil,
	}

	// AllDevChainProtocolChanges contains every protocol change (EIPs) introduced
	// and accepted by the Ethereum core developers into the XDPoS consensus.
	//
	// This configuration is intentionally not using keyed fields to force anyone
	// adding flags to the config to also have to set these fields.
	AllDevChainProtocolChanges = &ChainConfig{
		Name:                        "AllDevChainProtocolChanges",
		ChainID:                     big.NewInt(1337),
		HomesteadBlock:              big.NewInt(0),
		DAOForkBlock:                nil,
		DAOForkSupport:              false,
		TIP2019Block:                big.NewInt(0),
		EIP150Block:                 big.NewInt(0),
		EIP155Block:                 big.NewInt(0),
		EIP158Block:                 big.NewInt(0),
		ByzantiumBlock:              big.NewInt(0),
		ConstantinopleBlock:         big.NewInt(0),
		PetersburgBlock:             big.NewInt(0),
		IstanbulBlock:               big.NewInt(0),
		TIPSigningBlock:             big.NewInt(0),
		TIPRandomizeBlock:           big.NewInt(0),
		TIPIncreaseMasternodesBlock: big.NewInt(0),
		DenylistBlock:               big.NewInt(0),
		TIPNoHalvingMNRewardBlock:   big.NewInt(0),
		TIPXDCXBlock:                big.NewInt(0),
		TIPXDCXLendingBlock:         big.NewInt(0),
		TIPXDCXCancellationFeeBlock: big.NewInt(0),
		TIPTRC21FeeBlock:            big.NewInt(0),
		BerlinBlock:                 big.NewInt(0),
		LondonBlock:                 big.NewInt(0),
		MergeBlock:                  big.NewInt(0),
		ShanghaiBlock:               big.NewInt(0),
		Gas50xBlock:                 big.NewInt(80370000),
		TIPXDCXMinerDisableBlock:    nil,
		TIPXDCXReceiverDisableBlock: nil,
		Eip1559Block:                big.NewInt(0),
		CancunBlock:                 big.NewInt(0),
		PragueBlock:                 big.NewInt(0),
		OsakaBlock:                  big.NewInt(0),
		DynamicGasLimitBlock:        nil,
		TIPUpgradeRewardBlock:       nil,
		TIPUpgradePenaltyBlock:      nil,
		TIPEpochHalvingBlock:        nil,
		TRC21IssuerSMC:              common.HexToAddress("0x8c0faeb5C6bEd2129b8674F262Fd45c4e9468bee"),
		XDCXListingSMC:              common.HexToAddress("0xDE34dD0f536170993E8CFF639DdFfCF1A85D3E53"),
		RelayerRegistrationSMC:      common.HexToAddress("0x16c63b79f9C8784168103C0b74E6A59EC2de4a02"),
		LendingRegistrationSMC:      common.HexToAddress("0x7d761afd7ff65a79e4173897594a194e3c506e57"),
		Clique:                      nil,
		Ethash:                      nil,
		XDPoS: &XDPoSConfig{
			Epoch:                900,
			Gap:                  450,
			SkipV1Validation:     true,
			FoundationWalletAddr: common.HexToAddress("0x0000000000000000000000000000000000000068"),
			Reward:               250,
			MaxMasternodesV2:     108,
			V2: &V2{
				SwitchEpoch:   1,
				SwitchBlock:   big.NewInt(900),
				CurrentConfig: UnitTestV2Configs[0],
				AllConfigs:    UnitTestV2Configs,
			},
		},
	}

	// AllCliqueProtocolChanges contains every protocol change (EIPs) introduced
	// and accepted by the Ethereum core developers into the Clique consensus.
	AllCliqueProtocolChanges = &ChainConfig{
		Name:                        "AllCliqueProtocolChanges",
		ChainID:                     big.NewInt(1337),
		HomesteadBlock:              big.NewInt(0),
		DAOForkBlock:                nil,
		DAOForkSupport:              false,
		TIP2019Block:                big.NewInt(0),
		EIP150Block:                 big.NewInt(0),
		EIP155Block:                 big.NewInt(0),
		EIP158Block:                 big.NewInt(0),
		ByzantiumBlock:              big.NewInt(0),
		ConstantinopleBlock:         big.NewInt(0),
		PetersburgBlock:             big.NewInt(0),
		IstanbulBlock:               big.NewInt(0),
		TIPSigningBlock:             big.NewInt(0),
		TIPRandomizeBlock:           big.NewInt(0),
		TIPIncreaseMasternodesBlock: big.NewInt(0),
		DenylistBlock:               big.NewInt(0),
		TIPNoHalvingMNRewardBlock:   big.NewInt(0),
		TIPXDCXBlock:                big.NewInt(0),
		TIPXDCXLendingBlock:         big.NewInt(0),
		TIPXDCXCancellationFeeBlock: big.NewInt(0),
		TIPTRC21FeeBlock:            big.NewInt(0),
		BerlinBlock:                 big.NewInt(0),
		LondonBlock:                 big.NewInt(0),
		MergeBlock:                  big.NewInt(0),
		ShanghaiBlock:               big.NewInt(0),
		Gas50xBlock:                 big.NewInt(80370000),
		TIPXDCXMinerDisableBlock:    nil,
		TIPXDCXReceiverDisableBlock: nil,
		Eip1559Block:                big.NewInt(0),
		CancunBlock:                 big.NewInt(0),
		PragueBlock:                 big.NewInt(0),
		OsakaBlock:                  big.NewInt(0),
		DynamicGasLimitBlock:        nil,
		TIPUpgradeRewardBlock:       nil,
		TIPUpgradePenaltyBlock:      nil,
		TIPEpochHalvingBlock:        nil,
		TRC21IssuerSMC:              common.HexToAddress("0x8c0faeb5C6bEd2129b8674F262Fd45c4e9468bee"),
		XDCXListingSMC:              common.HexToAddress("0xDE34dD0f536170993E8CFF639DdFfCF1A85D3E53"),
		RelayerRegistrationSMC:      common.HexToAddress("0x16c63b79f9C8784168103C0b74E6A59EC2de4a02"),
		LendingRegistrationSMC:      common.HexToAddress("0x7d761afd7ff65a79e4173897594a194e3c506e57"),
		Clique:                      &CliqueConfig{Period: 0, Epoch: 900},
		Ethash:                      nil,
		XDPoS:                       nil,
	}

	// XDPoS config with v2 engine after block 901
	TestXDPoSMockChainConfig = &ChainConfig{
		Name:                        "TestXDPoSMockChainConfig",
		ChainID:                     big.NewInt(1337),
		HomesteadBlock:              big.NewInt(0),
		DAOForkBlock:                nil,
		DAOForkSupport:              false,
		TIP2019Block:                big.NewInt(0),
		EIP150Block:                 big.NewInt(0),
		EIP155Block:                 big.NewInt(0),
		EIP158Block:                 big.NewInt(0),
		ByzantiumBlock:              big.NewInt(0),
		ConstantinopleBlock:         big.NewInt(0),
		PetersburgBlock:             big.NewInt(0),
		IstanbulBlock:               big.NewInt(0),
		TIPSigningBlock:             big.NewInt(0),
		TIPRandomizeBlock:           big.NewInt(0),
		TIPIncreaseMasternodesBlock: big.NewInt(0),
		DenylistBlock:               big.NewInt(0),
		TIPNoHalvingMNRewardBlock:   big.NewInt(0),
		TIPXDCXBlock:                big.NewInt(0),
		TIPXDCXLendingBlock:         big.NewInt(0),
		TIPXDCXCancellationFeeBlock: big.NewInt(0),
		TIPTRC21FeeBlock:            big.NewInt(0),
		BerlinBlock:                 big.NewInt(0),
		LondonBlock:                 big.NewInt(0),
		MergeBlock:                  big.NewInt(0),
		ShanghaiBlock:               big.NewInt(0),
		Gas50xBlock:                 big.NewInt(80370000),
		TIPXDCXMinerDisableBlock:    nil,
		TIPXDCXReceiverDisableBlock: nil,
		Eip1559Block:                big.NewInt(0),
		CancunBlock:                 big.NewInt(0),
		PragueBlock:                 big.NewInt(0),
		OsakaBlock:                  big.NewInt(0),
		DynamicGasLimitBlock:        nil,
		TIPUpgradeRewardBlock:       nil,
		TIPUpgradePenaltyBlock:      nil,
		TIPEpochHalvingBlock:        nil,
		TRC21IssuerSMC:              common.HexToAddress("0x8c0faeb5C6bEd2129b8674F262Fd45c4e9468bee"),
		XDCXListingSMC:              common.HexToAddress("0xDE34dD0f536170993E8CFF639DdFfCF1A85D3E53"),
		RelayerRegistrationSMC:      common.HexToAddress("0x16c63b79f9C8784168103C0b74E6A59EC2de4a02"),
		LendingRegistrationSMC:      common.HexToAddress("0x7d761afd7ff65a79e4173897594a194e3c506e57"),
		Clique:                      nil,
		Ethash:                      new(EthashConfig),
		XDPoS: &XDPoSConfig{
			Epoch:                900,
			Gap:                  450,
			SkipV1Validation:     true,
			FoundationWalletAddr: common.HexToAddress("0x0000000000000000000000000000000000000068"),
			Reward:               250,
			MaxMasternodesV2:     108,
			V2: &V2{
				SwitchEpoch:   1,
				SwitchBlock:   big.NewInt(900),
				CurrentConfig: UnitTestV2Configs[0],
				AllConfigs:    UnitTestV2Configs,
			},
		},
	}

	// TestChainConfig contains every protocol change (EIPs) introduced
	// and accepted by the Ethereum core developers for testing purposes.
	TestChainConfig = &ChainConfig{
		Name:                        "TestChainConfig",
		ChainID:                     big.NewInt(1),
		HomesteadBlock:              big.NewInt(0),
		DAOForkBlock:                nil,
		DAOForkSupport:              false,
		TIP2019Block:                big.NewInt(0),
		EIP150Block:                 big.NewInt(0),
		EIP155Block:                 big.NewInt(0),
		EIP158Block:                 big.NewInt(0),
		ByzantiumBlock:              big.NewInt(0),
		ConstantinopleBlock:         big.NewInt(0),
		PetersburgBlock:             big.NewInt(0),
		IstanbulBlock:               big.NewInt(0),
		TIPSigningBlock:             big.NewInt(0),
		TIPRandomizeBlock:           big.NewInt(0),
		TIPIncreaseMasternodesBlock: big.NewInt(0),
		DenylistBlock:               big.NewInt(0),
		TIPNoHalvingMNRewardBlock:   big.NewInt(0),
		TIPXDCXBlock:                big.NewInt(0),
		TIPXDCXLendingBlock:         big.NewInt(0),
		TIPXDCXCancellationFeeBlock: big.NewInt(0),
		TIPTRC21FeeBlock:            big.NewInt(0),
		BerlinBlock:                 big.NewInt(0),
		LondonBlock:                 big.NewInt(0),
		MergeBlock:                  big.NewInt(0),
		ShanghaiBlock:               big.NewInt(0),
		Gas50xBlock:                 big.NewInt(80370000),
		TIPXDCXMinerDisableBlock:    nil,
		TIPXDCXReceiverDisableBlock: nil,
		Eip1559Block:                big.NewInt(0),
		CancunBlock:                 big.NewInt(0),
		PragueBlock:                 big.NewInt(0),
		OsakaBlock:                  big.NewInt(0),
		DynamicGasLimitBlock:        nil,
		TIPUpgradeRewardBlock:       nil,
		TIPUpgradePenaltyBlock:      nil,
		TIPEpochHalvingBlock:        nil,
		TRC21IssuerSMC:              common.HexToAddress("0x8c0faeb5C6bEd2129b8674F262Fd45c4e9468bee"),
		XDCXListingSMC:              common.HexToAddress("0xDE34dD0f536170993E8CFF639DdFfCF1A85D3E53"),
		RelayerRegistrationSMC:      common.HexToAddress("0x16c63b79f9C8784168103C0b74E6A59EC2de4a02"),
		LendingRegistrationSMC:      common.HexToAddress("0x7d761afd7ff65a79e4173897594a194e3c506e57"),
		Clique:                      nil,
		Ethash:                      new(EthashConfig),
		XDPoS:                       nil,
	}

	// MergedTestChainConfig contains every protocol change (EIPs) introduced
	// and accepted by the Ethereum core developers for testing purposes.
	MergedTestChainConfig = &ChainConfig{
		Name:                        "MergedTestChainConfig",
		ChainID:                     big.NewInt(1),
		HomesteadBlock:              big.NewInt(0),
		DAOForkBlock:                nil,
		DAOForkSupport:              false,
		TIP2019Block:                big.NewInt(0),
		EIP150Block:                 big.NewInt(0),
		EIP155Block:                 big.NewInt(0),
		EIP158Block:                 big.NewInt(0),
		ByzantiumBlock:              big.NewInt(0),
		ConstantinopleBlock:         big.NewInt(0),
		PetersburgBlock:             big.NewInt(0),
		IstanbulBlock:               big.NewInt(0),
		TIPSigningBlock:             big.NewInt(0),
		TIPRandomizeBlock:           big.NewInt(0),
		TIPIncreaseMasternodesBlock: big.NewInt(0),
		DenylistBlock:               big.NewInt(0),
		TIPNoHalvingMNRewardBlock:   big.NewInt(0),
		TIPXDCXBlock:                big.NewInt(0),
		TIPXDCXLendingBlock:         big.NewInt(0),
		TIPXDCXCancellationFeeBlock: big.NewInt(0),
		TIPTRC21FeeBlock:            big.NewInt(0),
		BerlinBlock:                 big.NewInt(0),
		LondonBlock:                 big.NewInt(0),
		MergeBlock:                  big.NewInt(0),
		ShanghaiBlock:               big.NewInt(0),
		Gas50xBlock:                 big.NewInt(80370000),
		TIPXDCXMinerDisableBlock:    nil,
		TIPXDCXReceiverDisableBlock: nil,
		Eip1559Block:                big.NewInt(0),
		CancunBlock:                 big.NewInt(0),
		PragueBlock:                 big.NewInt(0),
		OsakaBlock:                  big.NewInt(0),
		DynamicGasLimitBlock:        nil,
		TIPUpgradeRewardBlock:       nil,
		TIPUpgradePenaltyBlock:      nil,
		TIPEpochHalvingBlock:        nil,
		TRC21IssuerSMC:              common.HexToAddress("0x8c0faeb5C6bEd2129b8674F262Fd45c4e9468bee"),
		XDCXListingSMC:              common.HexToAddress("0xDE34dD0f536170993E8CFF639DdFfCF1A85D3E53"),
		RelayerRegistrationSMC:      common.HexToAddress("0x16c63b79f9C8784168103C0b74E6A59EC2de4a02"),
		LendingRegistrationSMC:      common.HexToAddress("0x7d761afd7ff65a79e4173897594a194e3c506e57"),
		Clique:                      nil,
		Ethash:                      new(EthashConfig),
		XDPoS:                       nil,
	}

	TestRules = TestChainConfig.Rules(new(big.Int))
)

// ChainConfig is the core config which determines the blockchain settings.
//
// ChainConfig is stored in the database on a per block basis. This means
// that any network, identified by its genesis block, can have its own
// set of configuration options.
type ChainConfig struct {
	ChainID *big.Int `json:"chainId"` // Chain id identifies the current chain and is used for replay protection

	HomesteadBlock *big.Int `json:"homesteadBlock,omitempty"` // Homestead switch block (nil = no fork, 0 = already homestead)

	DAOForkBlock   *big.Int `json:"daoForkBlock,omitempty"`   // TheDAO hard-fork switch block (nil = no fork)
	DAOForkSupport bool     `json:"daoForkSupport,omitempty"` // Whether the nodes supports or opposes the DAO hard-fork

	// EIP150 implements the Gas price changes (https://github.com/ethereum/EIPs/issues/150)
	EIP150Block *big.Int `json:"eip150Block,omitempty"` // EIP150 HF block (nil = no fork)
	EIP155Block *big.Int `json:"eip155Block,omitempty"` // EIP155 HF block
	EIP158Block *big.Int `json:"eip158Block,omitempty"` // EIP158 HF block

	ByzantiumBlock      *big.Int `json:"byzantiumBlock,omitempty"`      // Byzantium switch block (nil = no fork, 0 = already on byzantium)
	ConstantinopleBlock *big.Int `json:"constantinopleBlock,omitempty"` // Constantinople switch block (nil = no fork, 0 = already activated)

	PetersburgBlock *big.Int `json:"petersburgBlock,omitempty"`
	IstanbulBlock   *big.Int `json:"istanbulBlock,omitempty"`
	BerlinBlock     *big.Int `json:"berlinBlock,omitempty"`
	LondonBlock     *big.Int `json:"londonBlock,omitempty"`
	MergeBlock      *big.Int `json:"mergeBlock,omitempty"`
	ShanghaiBlock   *big.Int `json:"shanghaiBlock,omitempty"`
	Eip1559Block    *big.Int `json:"eip1559Block,omitempty"`
	CancunBlock     *big.Int `json:"cancunBlock,omitempty"`
	PragueBlock     *big.Int `json:"pragueBlock,omitempty"`
	OsakaBlock      *big.Int `json:"osakaBlock,omitempty"`

	TIP2019Block                *big.Int       `json:"tip2019Block,omitempty"`
	TIPSigningBlock             *big.Int       `json:"tipSigningBlock,omitempty"`
	TIPRandomizeBlock           *big.Int       `json:"tipRandomizeBlock,omitempty"`
	TIPIncreaseMasternodesBlock *big.Int       `json:"tipIncreaseMasternodesBlock,omitempty"`
	DenylistBlock               *big.Int       `json:"denylistBlock,omitempty"`
	TIPNoHalvingMNRewardBlock   *big.Int       `json:"tipNoHalvingMNRewardBlock,omitempty"`
	TIPXDCXBlock                *big.Int       `json:"tipXDCXBlock,omitempty"`
	TIPXDCXLendingBlock         *big.Int       `json:"tipXDCXLendingBlock,omitempty"`
	TIPXDCXCancellationFeeBlock *big.Int       `json:"tipXDCXCancellationFeeBlock,omitempty"`
	TIPTRC21FeeBlock            *big.Int       `json:"tipTRC21FeeBlock,omitempty"`
	Gas50xBlock                 *big.Int       `json:"gas50xBlock,omitempty"`
	TIPXDCXMinerDisableBlock    *big.Int       `json:"tipXDCXMinerDisableBlock,omitempty"`
	TIPXDCXReceiverDisableBlock *big.Int       `json:"tipXDCXReceiverDisableBlock,omitempty"`
	DynamicGasLimitBlock        *big.Int       `json:"dynamicGasLimitBlock,omitempty"`
	TIPUpgradeRewardBlock       *big.Int       `json:"tipUpgradeRewardBlock,omitempty"`
	TIPUpgradePenaltyBlock      *big.Int       `json:"tipUpgradePenaltyBlock,omitempty"`
	TIPEpochHalvingBlock        *big.Int       `json:"tipEpochHalvingBlock,omitempty"`
	TRC21IssuerSMC              common.Address `json:"trc21IssuerSMC,omitempty"`
	XDCXListingSMC              common.Address `json:"xdcxListingSMC,omitempty"`
	RelayerRegistrationSMC      common.Address `json:"relayerRegistrationSMC,omitempty"`
	LendingRegistrationSMC      common.Address `json:"lendingRegistrationSMC,omitempty"`

	// Various consensus engines
	Ethash *EthashConfig `json:"ethash,omitempty"`
	Clique *CliqueConfig `json:"clique,omitempty"`
	XDPoS  *XDPoSConfig  `json:"XDPoS,omitempty"`

	Name                string              `json:"-"`
	jsonPresence        map[string]struct{} `json:"-"`
	jsonPresenceTracked bool                `json:"-"`
}

// EthashConfig is the consensus engine configs for proof-of-work based sealing.
type EthashConfig struct{}

// String implements the stringer interface, returning the consensus engine details.
func (c *EthashConfig) String() string {
	return "ethash"
}

// CliqueConfig is the consensus engine configs for proof-of-authority based sealing.
type CliqueConfig struct {
	Period uint64 `json:"period"` // Number of seconds between blocks to enforce
	Epoch  uint64 `json:"epoch"`  // Epoch length to reset votes and checkpoint
}

// String implements the stringer interface, returning the consensus engine details.
func (c *CliqueConfig) String() string {
	return "clique"
}

// XDPoSConfig is the consensus engine configs for delegated-proof-of-stake based sealing.
type XDPoSConfig struct {
	Period               uint64         `json:"period"`               // Number of seconds between blocks to enforce
	Epoch                uint64         `json:"epoch"`                // Epoch length to reset votes and checkpoint
	Reward               uint64         `json:"reward"`               // Block reward - unit Ether
	RewardCheckpoint     uint64         `json:"rewardCheckpoint"`     // Checkpoint block for calculate rewards.
	Gap                  uint64         `json:"gap"`                  // Gap time preparing for the next epoch
	FoundationWalletAddr common.Address `json:"foundationWalletAddr"` // Foundation Address Wallet
	MaxMasternodesV2     int            `json:"maxMasternodesV2"`     // Last v1 masternodes after TIPIncrease
	SkipV1Validation     bool           //Skip Block Validation for testing purpose, V1 consensus only
	V2                   *V2            `json:"v2"`

	jsonPresence        map[string]struct{} `json:"-"`
	jsonPresenceTracked bool                `json:"-"`
}

// UnmarshalJSON captures field presence so strict missing-field backfill can
// distinguish omitted keys from explicit zero-values.
func (c *ChainConfig) UnmarshalJSON(data []byte) error {
	type chainConfigAlias ChainConfig
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	var decoded chainConfigAlias
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*c = ChainConfig(decoded)
	c.jsonPresenceTracked = true
	c.jsonPresence = make(map[string]struct{}, len(raw))
	for key := range raw {
		c.jsonPresence[key] = struct{}{}
	}
	return nil
}

// UnmarshalJSON supports both the current and legacy typo-ed JSON key for
// foundation wallet address to keep old on-disk chain configs compatible.
func (c *XDPoSConfig) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	type xdpJSON struct {
		Period                    uint64         `json:"period"`
		Epoch                     uint64         `json:"epoch"`
		Reward                    uint64         `json:"reward"`
		RewardCheckpoint          uint64         `json:"rewardCheckpoint"`
		Gap                       uint64         `json:"gap"`
		MaxMasternodesV2          int            `json:"maxMasternodesV2"`
		FoundationWalletAddr      common.Address `json:"foundationWalletAddr"`
		LegacyFoudationWalletAddr common.Address `json:"foudationWalletAddr"`
		SkipV1Validation          bool           `json:"SkipV1Validation"`
		V2                        *V2            `json:"v2"`
	}
	var decoded xdpJSON
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}

	c.Period = decoded.Period
	c.Epoch = decoded.Epoch
	c.Reward = decoded.Reward
	c.RewardCheckpoint = decoded.RewardCheckpoint
	c.Gap = decoded.Gap
	c.MaxMasternodesV2 = decoded.MaxMasternodesV2
	c.FoundationWalletAddr = decoded.FoundationWalletAddr
	if c.FoundationWalletAddr == (common.Address{}) && decoded.LegacyFoudationWalletAddr != (common.Address{}) {
		c.FoundationWalletAddr = decoded.LegacyFoudationWalletAddr
	}
	c.SkipV1Validation = decoded.SkipV1Validation
	c.V2 = decoded.V2
	c.jsonPresenceTracked = true
	c.jsonPresence = make(map[string]struct{}, len(raw))
	for key := range raw {
		c.jsonPresence[key] = struct{}{}
	}

	return nil
}

type V2 struct {
	lock sync.RWMutex // Protects the signer fields

	SwitchEpoch   uint64
	SwitchBlock   *big.Int             `json:"switchBlock"`
	CurrentConfig *V2Config            `json:"config"`
	AllConfigs    map[uint64]*V2Config `json:"allConfigs"`
	configIndex   []uint64             // list of switch block of configs
}

type V2Config struct {
	MaxMasternodes       int     `json:"maxMasternodes"`       // v2 max masternodes
	MaxProtectorNodes    int     `json:"maxProtectorNodes"`    // v2 max ProtectorNodes
	MaxObverserNodes     int     `json:"maxObserverNodes"`     // v2 max ObserverNodes
	SwitchRound          uint64  `json:"switchRound"`          // v1 to v2 switch block number
	MinePeriod           int     `json:"minePeriod"`           // Miner mine period to mine a block
	TimeoutSyncThreshold int     `json:"timeoutSyncThreshold"` // send syncInfo after number of timeout
	TimeoutPeriod        int     `json:"timeoutPeriod"`        // Duration in ms
	CertThreshold        float64 `json:"certificateThreshold"` // Necessary number of messages from master nodes to form a certificate

	MasternodeReward float64 `json:"masternodeReward"` // Block reward per master node (core validator) - unit Ether
	ProtectorReward  float64 `json:"protectorReward"`  // Block reward per protector - unit Ether
	ObserverReward   float64 `json:"observerReward"`   // Block reward per observer - unit Ether

	MinimumMinerBlockPerEpoch int `json:"minimumMinerBlockPerEpoch"` // Minimum block per epoch for a miner to not be penalized
	LimitPenaltyEpoch         int `json:"limitPenaltyEpoch"`         // Epochs in a row that a penalty node needs to be penalized
	MinimumSigningTx          int `json:"minimumSigningTx"`          // Signing txs that a node needs to produce to get out of penalty, after `LimitPenaltyEpoch`

	ExpTimeoutConfig ExpTimeoutConfig `json:"expTimeoutConfig"`
}

type ExpTimeoutConfig struct {
	Base        float64 `json:"base"`        // base in base^exponent
	MaxExponent uint8   `json:"maxExponent"` // max exponent in base^exponent
}

// Clone returns an independent copy of the v2 config.
func (c *V2Config) Clone() *V2Config {
	if c == nil {
		return nil
	}
	clone := *c
	return &clone
}

// Clone returns a read-locked deep copy of the V2 state.
func (v2 *V2) Clone() *V2 {
	if v2 == nil {
		return nil
	}
	v2.lock.RLock()
	defer v2.lock.RUnlock()

	clone := &V2{
		SwitchEpoch: v2.SwitchEpoch,
		SwitchBlock: common.CloneBigInt(v2.SwitchBlock),
	}
	if v2.CurrentConfig != nil {
		clone.CurrentConfig = v2.CurrentConfig.Clone()
	}
	if v2.AllConfigs != nil {
		clone.AllConfigs = make(map[uint64]*V2Config, len(v2.AllConfigs))
		for key, cfg := range v2.AllConfigs {
			clone.AllConfigs[key] = cfg.Clone()
		}
	}
	if v2.configIndex != nil {
		clone.configIndex = append([]uint64(nil), v2.configIndex...)
	}
	return clone
}

// Clone returns an independent copy of the XDPoS config.
func (c *XDPoSConfig) Clone() *XDPoSConfig {
	if c == nil {
		return nil
	}
	clone := *c
	clone.V2 = c.V2.Clone()
	if c.jsonPresence != nil {
		clone.jsonPresence = make(map[string]struct{}, len(c.jsonPresence))
		for key := range c.jsonPresence {
			clone.jsonPresence[key] = struct{}{}
		}
	}
	return &clone
}

// Clone returns a deep copy of the chain config and nested consensus configs.
func (c *ChainConfig) Clone() *ChainConfig {
	if c == nil {
		return nil
	}
	clone := *c
	clone.ChainID = common.CloneBigInt(c.ChainID)
	clone.HomesteadBlock = common.CloneBigInt(c.HomesteadBlock)
	clone.TIP2019Block = common.CloneBigInt(c.TIP2019Block)
	clone.DAOForkBlock = common.CloneBigInt(c.DAOForkBlock)
	clone.EIP150Block = common.CloneBigInt(c.EIP150Block)
	clone.EIP155Block = common.CloneBigInt(c.EIP155Block)
	clone.EIP158Block = common.CloneBigInt(c.EIP158Block)
	clone.ByzantiumBlock = common.CloneBigInt(c.ByzantiumBlock)
	clone.ConstantinopleBlock = common.CloneBigInt(c.ConstantinopleBlock)
	clone.PetersburgBlock = common.CloneBigInt(c.PetersburgBlock)
	clone.IstanbulBlock = common.CloneBigInt(c.IstanbulBlock)
	clone.TIPSigningBlock = common.CloneBigInt(c.TIPSigningBlock)
	clone.TIPRandomizeBlock = common.CloneBigInt(c.TIPRandomizeBlock)
	clone.TIPIncreaseMasternodesBlock = common.CloneBigInt(c.TIPIncreaseMasternodesBlock)
	clone.DenylistBlock = common.CloneBigInt(c.DenylistBlock)
	clone.TIPNoHalvingMNRewardBlock = common.CloneBigInt(c.TIPNoHalvingMNRewardBlock)
	clone.TIPXDCXBlock = common.CloneBigInt(c.TIPXDCXBlock)
	clone.TIPXDCXLendingBlock = common.CloneBigInt(c.TIPXDCXLendingBlock)
	clone.TIPXDCXCancellationFeeBlock = common.CloneBigInt(c.TIPXDCXCancellationFeeBlock)
	clone.TIPTRC21FeeBlock = common.CloneBigInt(c.TIPTRC21FeeBlock)
	clone.BerlinBlock = common.CloneBigInt(c.BerlinBlock)
	clone.LondonBlock = common.CloneBigInt(c.LondonBlock)
	clone.MergeBlock = common.CloneBigInt(c.MergeBlock)
	clone.ShanghaiBlock = common.CloneBigInt(c.ShanghaiBlock)
	clone.Gas50xBlock = common.CloneBigInt(c.Gas50xBlock)
	clone.TIPXDCXMinerDisableBlock = common.CloneBigInt(c.TIPXDCXMinerDisableBlock)
	clone.TIPXDCXReceiverDisableBlock = common.CloneBigInt(c.TIPXDCXReceiverDisableBlock)
	clone.Eip1559Block = common.CloneBigInt(c.Eip1559Block)
	clone.CancunBlock = common.CloneBigInt(c.CancunBlock)
	clone.PragueBlock = common.CloneBigInt(c.PragueBlock)
	clone.OsakaBlock = common.CloneBigInt(c.OsakaBlock)
	clone.DynamicGasLimitBlock = common.CloneBigInt(c.DynamicGasLimitBlock)
	clone.TIPUpgradeRewardBlock = common.CloneBigInt(c.TIPUpgradeRewardBlock)
	clone.TIPUpgradePenaltyBlock = common.CloneBigInt(c.TIPUpgradePenaltyBlock)
	clone.TIPEpochHalvingBlock = common.CloneBigInt(c.TIPEpochHalvingBlock)
	clone.TRC21IssuerSMC = c.TRC21IssuerSMC
	clone.XDCXListingSMC = c.XDCXListingSMC
	clone.RelayerRegistrationSMC = c.RelayerRegistrationSMC
	clone.LendingRegistrationSMC = c.LendingRegistrationSMC
	if c.Clique != nil {
		clique := *c.Clique
		clone.Clique = &clique
	}
	if c.Ethash != nil {
		clone.Ethash = new(EthashConfig)
	}
	clone.XDPoS = c.XDPoS.Clone()
	if c.jsonPresence != nil {
		clone.jsonPresence = make(map[string]struct{}, len(c.jsonPresence))
		for key := range c.jsonPresence {
			clone.jsonPresence[key] = struct{}{}
		}
	}
	return &clone
}

func GetBuiltInChainConfigByHash(ghash common.Hash) *ChainConfig {
	switch ghash {
	case MainnetGenesisHash:
		return XDCMainnetChainConfig
	case TestnetGenesisHash:
		return TestnetChainConfig
	case DevnetGenesisHash:
		return DevnetChainConfig
	default:
		return nil
	}
}

func isBuiltInTestNetwork(chainID *big.Int) bool {
	switch chainID.Uint64() {
	case TestnetChainConfig.ChainID.Uint64():
		return true
	case 1: // MainnetChainConfig, TestChainConfig, MergedTestChainConfig
		return true
	case 1337: // AllEthashProtocolChanges, AllDevChainProtocolChanges, AllCliqueProtocolChanges, TestXDPoSMockChainConfig
		return true
	default:
		return false
	}
}

// CheckConfigForkOrder checks that we don't "skip" any forks, geth isn't pluggable enough
// to guarantee that forks can be implemented in a different order than on official networks
func (c *ChainConfig) CheckConfigForkOrder() error {
	if c.ChainID == nil {
		return fmt.Errorf("invalid chain config: %w %s", ErrMissingForkSwitch, "ChainID")
	}
	if c.TIPTRC21FeeBlock == nil {
		return fmt.Errorf("invalid chain config: %w %s", ErrMissingForkSwitch, "TIPTRC21FeeBlock")
	}
	if c.Gas50xBlock != nil && c.Gas50xBlock.Cmp(c.TIPTRC21FeeBlock) < 0 {
		return fmt.Errorf("invalid chain config: %w TIPTRC21FeeBlock %v > Gas50xBlock %v", ErrWrongForkSwitchOrder, c.TIPTRC21FeeBlock, c.Gas50xBlock)
	}
	if c.XDPoS == nil && c.Ethash == nil && c.Clique == nil && !isBuiltInTestNetwork(c.ChainID) {
		return fmt.Errorf("invalid chain config: %w %s", ErrMissingForkSwitch, "XDPoS")
	}
	if c.XDPoS != nil {
		if c.XDPoS.MaxMasternodesV2 == 0 {
			return fmt.Errorf("invalid chain config: %w %s", ErrMissingForkSwitch, "XDPoS.MaxMasternodesV2")
		}
	}
	return nil
}

func (c *ChainConfig) isJSONFieldMissing(key string, fallback bool) bool {
	if c == nil {
		return false
	}
	if !c.jsonPresenceTracked {
		return fallback
	}
	_, ok := c.jsonPresence[key]
	return !ok
}

// BackfillMissingFields copies missing fields from LocalnetChainConfig into c
// using strict JSON-key presence when available. If presence metadata is
// unavailable, pointer-nil/zero-value fallbacks are used for compatibility.
func (c *ChainConfig) BackfillMissingFields() *ChainConfig {
	if c == nil {
		return c
	}

	dest := c.Clone()
	src := LocalnetChainConfig

	bigIntFields := []struct {
		key string
		dst **big.Int
		src *big.Int
	}{
		{"chainId", &dest.ChainID, src.ChainID},
		{"homesteadBlock", &dest.HomesteadBlock, src.HomesteadBlock},
		{"daoForkBlock", &dest.DAOForkBlock, src.DAOForkBlock},
		{"eip150Block", &dest.EIP150Block, src.EIP150Block},
		{"eip155Block", &dest.EIP155Block, src.EIP155Block},
		{"eip158Block", &dest.EIP158Block, src.EIP158Block},
		{"byzantiumBlock", &dest.ByzantiumBlock, src.ByzantiumBlock},
		{"constantinopleBlock", &dest.ConstantinopleBlock, src.ConstantinopleBlock},
		{"petersburgBlock", &dest.PetersburgBlock, src.PetersburgBlock},
		{"istanbulBlock", &dest.IstanbulBlock, src.IstanbulBlock},
		{"tip2019Block", &dest.TIP2019Block, src.TIP2019Block},
		{"tipSigningBlock", &dest.TIPSigningBlock, src.TIPSigningBlock},
		{"tipRandomizeBlock", &dest.TIPRandomizeBlock, src.TIPRandomizeBlock},
		{"tipIncreaseMasternodesBlock", &dest.TIPIncreaseMasternodesBlock, src.TIPIncreaseMasternodesBlock},
		{"denylistBlock", &dest.DenylistBlock, src.DenylistBlock},
		{"tipNoHalvingMNRewardBlock", &dest.TIPNoHalvingMNRewardBlock, src.TIPNoHalvingMNRewardBlock},
		{"tipXDCXBlock", &dest.TIPXDCXBlock, src.TIPXDCXBlock},
		{"tipXDCXLendingBlock", &dest.TIPXDCXLendingBlock, src.TIPXDCXLendingBlock},
		{"tipXDCXCancellationFeeBlock", &dest.TIPXDCXCancellationFeeBlock, src.TIPXDCXCancellationFeeBlock},
		{"tipTRC21FeeBlock", &dest.TIPTRC21FeeBlock, src.TIPTRC21FeeBlock},
		{"gas50xBlock", &dest.Gas50xBlock, src.Gas50xBlock},
		{"berlinBlock", &dest.BerlinBlock, src.BerlinBlock},
		{"londonBlock", &dest.LondonBlock, src.LondonBlock},
		{"mergeBlock", &dest.MergeBlock, src.MergeBlock},
		{"shanghaiBlock", &dest.ShanghaiBlock, src.ShanghaiBlock},
		{"tipXDCXMinerDisableBlock", &dest.TIPXDCXMinerDisableBlock, src.TIPXDCXMinerDisableBlock},
		{"tipXDCXReceiverDisableBlock", &dest.TIPXDCXReceiverDisableBlock, src.TIPXDCXReceiverDisableBlock},
		{"eip1559Block", &dest.Eip1559Block, src.Eip1559Block},
		{"cancunBlock", &dest.CancunBlock, src.CancunBlock},
		{"pragueBlock", &dest.PragueBlock, src.PragueBlock},
		{"osakaBlock", &dest.OsakaBlock, src.OsakaBlock},
		{"dynamicGasLimitBlock", &dest.DynamicGasLimitBlock, src.DynamicGasLimitBlock},
		{"tipUpgradeRewardBlock", &dest.TIPUpgradeRewardBlock, src.TIPUpgradeRewardBlock},
		{"tipUpgradePenaltyBlock", &dest.TIPUpgradePenaltyBlock, src.TIPUpgradePenaltyBlock},
		{"tipEpochHalvingBlock", &dest.TIPEpochHalvingBlock, src.TIPEpochHalvingBlock},
	}

	addressFields := []struct {
		key string
		dst *common.Address
		src common.Address
	}{
		{"trc21IssuerSMC", &dest.TRC21IssuerSMC, src.TRC21IssuerSMC},
		{"xdcxListingSMC", &dest.XDCXListingSMC, src.XDCXListingSMC},
		{"relayerRegistrationSMC", &dest.RelayerRegistrationSMC, src.RelayerRegistrationSMC},
		{"lendingRegistrationSMC", &dest.LendingRegistrationSMC, src.LendingRegistrationSMC},
	}

	for _, field := range bigIntFields {
		if dest.isJSONFieldMissing(field.key, *field.dst == nil) {
			log.Info("Backfilled missing field", "field", field.key, "old", *field.dst, "new", field.src)
			*field.dst = common.CloneBigInt(field.src)
		}
	}

	for _, field := range addressFields {
		if dest.isJSONFieldMissing(field.key, *field.dst == (common.Address{})) {
			log.Info("Backfilled missing field", "field", field.key, "old", field.dst.Hex(), "new", field.src.Hex())
			*field.dst = field.src
		}
	}

	if dest.XDPoS == nil {
		log.Warn("XDPoS in source chain config is nil")
	} else if dest.XDPoS.MaxMasternodesV2 == 0 {
		log.Info("Backfilled missing field", "field", "XDPoS.MaxMasternodesV2", "old", 0, "new", src.XDPoS.MaxMasternodesV2)
		dest.XDPoS.MaxMasternodesV2 = src.XDPoS.MaxMasternodesV2
	}

	return dest
}

func XDPoSConfigEqual(a, b *XDPoSConfig) bool {
	if a == nil || b == nil {
		if a != b {
			log.Warn("[XDPoSConfigEqual] One of the configs is nil", "a", a, "b", b)
			return false
		}
		return true
	}
	if a.Period != b.Period {
		log.Warn("[XDPoSConfigEqual] Period mismatch", "a.Period", a.Period, "b.Period", b.Period)
		return false
	}
	if a.Epoch != b.Epoch {
		log.Warn("[XDPoSConfigEqual] Epoch mismatch", "a.Epoch", a.Epoch, "b.Epoch", b.Epoch)
		return false
	}
	if a.Reward != b.Reward {
		log.Warn("[XDPoSConfigEqual] Reward mismatch", "a.Reward", a.Reward, "b.Reward", b.Reward)
		return false
	}
	if a.RewardCheckpoint != b.RewardCheckpoint {
		log.Warn("[XDPoSConfigEqual] RewardCheckpoint mismatch", "a.RewardCheckpoint", a.RewardCheckpoint, "b.RewardCheckpoint", b.RewardCheckpoint)
		return false
	}
	if a.Gap != b.Gap {
		log.Warn("[XDPoSConfigEqual] Gap mismatch", "a.Gap", a.Gap, "b.Gap", b.Gap)
		return false
	}
	if a.FoundationWalletAddr != b.FoundationWalletAddr {
		log.Warn("[XDPoSConfigEqual] FoundationWalletAddr mismatch", "a.FoundationWalletAddr", a.FoundationWalletAddr.Hex(), "b.FoundationWalletAddr", b.FoundationWalletAddr.Hex())
		return false
	}
	if a.MaxMasternodesV2 != b.MaxMasternodesV2 {
		log.Warn("[XDPoSConfigEqual] MaxMasternodesV2 mismatch", "a.MaxMasternodesV2", a.MaxMasternodesV2, "b.MaxMasternodesV2", b.MaxMasternodesV2)
		return false
	}
	if a.SkipV1Validation != b.SkipV1Validation {
		log.Warn("[XDPoSConfigEqual] SkipV1Validation mismatch", "a.SkipV1Validation", a.SkipV1Validation, "b.SkipV1Validation", b.SkipV1Validation)
		return false
	}
	return V2Equal(a.V2, b.V2)
}

func V2Equal(a, b *V2) bool {
	if a == nil || b == nil {
		if a != b {
			log.Warn("[V2Equal] One of the configs is nil", "a", a, "b", b)
			return false
		}
		return true
	}
	if !configNumEqual(a.SwitchBlock, b.SwitchBlock) {
		log.Warn("[V2Equal] SwitchBlock mismatch", "a.SwitchBlock", a.SwitchBlock, "b.SwitchBlock", b.SwitchBlock)
		return false
	}
	// Only check configs in both of AllConfigs
	for k1, cfg1 := range a.AllConfigs {
		if cfg2, ok := b.AllConfigs[k1]; ok {
			if !V2ConfigEqual(cfg1, cfg2) {
				return false
			}
		}
	}
	return true
}

func V2ConfigEqual(a, b *V2Config) bool {
	if a == nil || b == nil {
		if a != b {
			log.Warn("[V2ConfigEqual] One of the configs is nil", "a", a, "b", b)
			return false
		}
		return true
	}
	if a.MaxMasternodes != b.MaxMasternodes {
		log.Warn("[V2ConfigEqual] MaxMasternodes mismatch", "a.MaxMasternodes", a.MaxMasternodes, "b.MaxMasternodes", b.MaxMasternodes)
		return false
	}
	if a.SwitchRound != b.SwitchRound {
		log.Warn("[V2ConfigEqual] SwitchRound mismatch", "a.SwitchRound", a.SwitchRound, "b.SwitchRound", b.SwitchRound)
		return false
	}
	if a.CertThreshold != b.CertThreshold {
		log.Warn("[V2ConfigEqual] CertThreshold mismatch", "a.CertThreshold", a.CertThreshold, "b.CertThreshold", b.CertThreshold)
		return false
	}
	return true
}

func (c *XDPoSConfig) String() string {
	if c == nil {
		return "XDPoSConfig: <nil>"
	}

	return fmt.Sprintf("XDPoSConfig{Period: %v, Epoch: %v, Reward: %v, RewardCheckpoint: %v, Gap: %v, MaxMasternodesV2: %v, FoundationWalletAddr: %v, SkipV1Validation: %v, V2: %s}", c.Period, c.Epoch, c.Reward, c.RewardCheckpoint, c.Gap, c.MaxMasternodesV2, c.FoundationWalletAddr.String0x(), c.SkipV1Validation, c.V2.String())
}

// Description returns a human-readable description of XDPoSConfig
// NOTE: don't append "\n" to end
func (c *XDPoSConfig) Description(indent int) string {
	if c == nil {
		return "XDPoS: <nil>"
	}

	banner := "XDPoS\n"
	prefix := strings.Repeat(" ", indent)
	banner += fmt.Sprintf("%s- Period: %v\n", prefix, c.Period)
	banner += fmt.Sprintf("%s- Epoch: %v\n", prefix, c.Epoch)
	banner += fmt.Sprintf("%s- Reward: %v\n", prefix, c.Reward)
	banner += fmt.Sprintf("%s- RewardCheckpoint: %v\n", prefix, c.RewardCheckpoint)
	banner += fmt.Sprintf("%s- Gap: %v\n", prefix, c.Gap)
	banner += fmt.Sprintf("%s- MaxMasternodesV2: %v\n", prefix, c.MaxMasternodesV2)
	banner += fmt.Sprintf("%s- FoundationWalletAddr: %v\n", prefix, c.FoundationWalletAddr.Hex())
	banner += fmt.Sprintf("%s- SkipV1Validation: %v\n", prefix, c.SkipV1Validation)
	banner += fmt.Sprintf("%s- %s", prefix, c.V2.Description(indent+2))
	return banner
}

func (v2 *V2) String() string {
	if v2 == nil {
		return "V2: <nil>"
	}

	return fmt.Sprintf("V2{SwitchEpoch: %v, SwitchBlock: %v, %s}", v2.SwitchEpoch, v2.SwitchBlock, v2.CurrentConfig.String())
}

// Description returns a human-readable description of V2
// NOTE: don't append "\n" to end
func (v2 *V2) Description(indent int) string {
	if v2 == nil {
		return "V2: <nil>"
	}

	banner := "V2:\n"
	prefix := strings.Repeat(" ", indent)
	banner += fmt.Sprintf("%s- SwitchEpoch: %v\n", prefix, v2.SwitchEpoch)
	banner += fmt.Sprintf("%s- SwitchBlock: %v\n", prefix, v2.SwitchBlock)
	banner += fmt.Sprintf("%s- %s", prefix, v2.GetCurrentConfig().Description("CurrentConfig", indent+2))
	return banner
}

func (c *V2Config) String() string {
	if c == nil {
		return "V2Config: <nil>"
	}

	return fmt.Sprintf("V2{MaxMasternodes: %v, MaxProtectorNodes: %v, MaxObverserNodes: %v, SwitchRound: %v, MinePeriod: %v, TimeoutSyncThreshold: %v, TimeoutPeriod: %v, CertThreshold: %v, MasternodeReward: %v, ProtectorReward: %v, ObserverReward: %v, MinimumMinerBlockPerEpoch: %v, LimitPenaltyEpoch: %v, MinimumSigningTx: %v, %s}", c.MaxMasternodes, c.MaxProtectorNodes, c.MaxObverserNodes, c.SwitchRound, c.MinePeriod, c.TimeoutSyncThreshold, c.TimeoutPeriod, c.CertThreshold, c.MasternodeReward, c.ProtectorReward, c.ObserverReward, c.MinimumMinerBlockPerEpoch, c.LimitPenaltyEpoch, c.MinimumSigningTx, c.ExpTimeoutConfig.String())
}

// Description returns a human-readable description of V2Config
// NOTE: don't append "\n" to end
func (c *V2Config) Description(name string, indent int) string {
	if c == nil {
		return name + ": <nil>"
	}

	banner := name + ":\n"
	prefix := strings.Repeat(" ", indent)
	banner += fmt.Sprintf("%s- MaxMasternodes: %v\n", prefix, c.MaxMasternodes)
	banner += fmt.Sprintf("%s- SwitchRound: %v\n", prefix, c.SwitchRound)
	banner += fmt.Sprintf("%s- MinePeriod: %v\n", prefix, c.MinePeriod)
	banner += fmt.Sprintf("%s- TimeoutSyncThreshold: %v\n", prefix, c.TimeoutSyncThreshold)
	banner += fmt.Sprintf("%s- TimeoutPeriod: %v\n", prefix, c.TimeoutPeriod)
	banner += fmt.Sprintf("%s- CertThreshold: %v\n", prefix, c.CertThreshold)
	banner += fmt.Sprintf("%s- MasternodeReward: %v\n", prefix, c.MasternodeReward)
	banner += fmt.Sprintf("%s- ProtectorReward: %v\n", prefix, c.ProtectorReward)
	banner += fmt.Sprintf("%s- ObserverReward: %v\n", prefix, c.ObserverReward)
	banner += fmt.Sprintf("%s- MinimumMinerBlockPerEpoch: %v\n", prefix, c.MinimumMinerBlockPerEpoch)
	banner += fmt.Sprintf("%s- LimitPenaltyEpoch: %v\n", prefix, c.LimitPenaltyEpoch)
	banner += fmt.Sprintf("%s- MinimumSigningTx: %v\n", prefix, c.MinimumSigningTx)
	banner += fmt.Sprintf("%s- ExpTimeoutBase: %v\n", prefix, c.ExpTimeoutConfig.Base)
	banner += fmt.Sprintf("%s- ExpTimeoutMaxExponent: %v", prefix, c.ExpTimeoutConfig.MaxExponent)
	return banner
}

func (c ExpTimeoutConfig) String() string {
	return fmt.Sprintf("ExpTimeoutConfig{Base: %v, MaxExponent: %v}", c.Base, c.MaxExponent)
}

func (c *XDPoSConfig) BlockConsensusVersion(num *big.Int) string {
	if c.V2 != nil && c.V2.SwitchBlock != nil && num.Cmp(c.V2.SwitchBlock) > 0 {
		return ConsensusEngineVersion2
	}
	return ConsensusEngineVersion1
}

func (v2 *V2) UpdateConfig(round uint64) {
	v2.lock.Lock()
	defer v2.lock.Unlock()

	var index uint64

	//find the right config
	for i := range v2.configIndex {
		if v2.configIndex[i] <= round {
			index = v2.configIndex[i]
			break
		}
	}
	// update to current config
	log.Info("[updateV2Config] Update config", "index", index, "round", round, "SwitchRound", v2.AllConfigs[index].SwitchRound)
	v2.CurrentConfig = v2.AllConfigs[index]
}

// GetCurrentConfig returns a opy of the current config, it assumes v2 is not nil
func (v2 *V2) GetCurrentConfig() *V2Config {
	v2.lock.RLock()
	defer v2.lock.RUnlock()

	if v2.CurrentConfig == nil {
		return nil
	}

	// avoid CurrentConfig is changed by other goroutines
	cfg := *v2.CurrentConfig
	return &cfg
}

func (v2 *V2) Config(round uint64) *V2Config {
	v2.lock.RLock()
	defer v2.lock.RUnlock()

	configRound := round
	var index uint64

	//find the right config
	for i := range v2.configIndex {
		if v2.configIndex[i] <= configRound {
			index = v2.configIndex[i]
			break
		}
	}

	// avoid config is changed by other goroutines
	cfg := *v2.AllConfigs[index]
	return &cfg
}

func (v2 *V2) BuildConfigIndex() {
	v2.lock.Lock()
	defer v2.lock.Unlock()

	list := slices.Collect(maps.Keys(v2.AllConfigs))
	// Make it descending order
	slices.SortFunc(list, func(a, b uint64) int {
		return cmp.Compare(b, a)
	})
	log.Info("[BuildConfigIndex] config list", "list", list)
	v2.configIndex = list
}

func (v2 *V2) ConfigIndex() []uint64 {
	v2.lock.RLock()
	defer v2.lock.RUnlock()

	if v2.configIndex == nil {
		return nil
	}
	return append([]uint64(nil), v2.configIndex...)
}

// String implements the fmt.Stringer interface, returning a string representation
// of ChainConfig.
func (c *ChainConfig) String() string {
	result := fmt.Sprintf("ChainConfig{ChainID: %v", c.ChainID)

	// Add block-based forks
	if c.HomesteadBlock != nil {
		result += fmt.Sprintf(", Homestead: %v", c.HomesteadBlock)
	}
	if c.TIP2019Block != nil {
		result += fmt.Sprintf(", TIP2019: %v", c.TIP2019Block)
	}
	if c.DAOForkBlock != nil {
		result += fmt.Sprintf(", DAOFork: %v", c.DAOForkBlock)
	}
	result += fmt.Sprintf(", DAOForkSupport: %v", c.DAOForkSupport)
	if c.EIP150Block != nil {
		result += fmt.Sprintf(", EIP150: %v", c.EIP150Block)
	}
	if c.EIP155Block != nil {
		result += fmt.Sprintf(", EIP155: %v", c.EIP155Block)
	}
	if c.EIP158Block != nil {
		result += fmt.Sprintf(", EIP158: %v", c.EIP158Block)
	}
	if c.ByzantiumBlock != nil {
		result += fmt.Sprintf(", Byzantium: %v", c.ByzantiumBlock)
	}
	if c.ConstantinopleBlock != nil {
		result += fmt.Sprintf(", Constantinople: %v", c.ConstantinopleBlock)
	}
	if c.PetersburgBlock != nil {
		result += fmt.Sprintf(", Petersburg: %v", c.PetersburgBlock)
	}
	if c.IstanbulBlock != nil {
		result += fmt.Sprintf(", Istanbul: %v", c.IstanbulBlock)
	}
	if c.TIPSigningBlock != nil {
		result += fmt.Sprintf(", TIPSigning: %v", c.TIPSigningBlock)
	}
	if c.TIPRandomizeBlock != nil {
		result += fmt.Sprintf(", TIPRandomize: %v", c.TIPRandomizeBlock)
	}
	if c.TIPIncreaseMasternodesBlock != nil {
		result += fmt.Sprintf(", TIPIncreaseMasternodes: %v", c.TIPIncreaseMasternodesBlock)
	}
	if c.DenylistBlock != nil {
		result += fmt.Sprintf(", Denylist: %v", c.DenylistBlock)
	}
	if c.TIPNoHalvingMNRewardBlock != nil {
		result += fmt.Sprintf(", TIPNoHalvingMNReward: %v", c.TIPNoHalvingMNRewardBlock)
	}
	if c.TIPXDCXBlock != nil {
		result += fmt.Sprintf(", TIPXDCX: %v", c.TIPXDCXBlock)
	}
	if c.TIPXDCXLendingBlock != nil {
		result += fmt.Sprintf(", TIPXDCXLending: %v", c.TIPXDCXLendingBlock)
	}
	if c.TIPXDCXCancellationFeeBlock != nil {
		result += fmt.Sprintf(", TIPXDCXCancellationFee: %v", c.TIPXDCXCancellationFeeBlock)
	}
	if c.TIPTRC21FeeBlock != nil {
		result += fmt.Sprintf(", TIPTRC21Fee: %v", c.TIPTRC21FeeBlock)
	}
	if c.BerlinBlock != nil {
		result += fmt.Sprintf(", Berlin: %v", c.BerlinBlock)
	}
	if c.LondonBlock != nil {
		result += fmt.Sprintf(", London: %v", c.LondonBlock)
	}
	if c.MergeBlock != nil {
		result += fmt.Sprintf(", Merge: %v", c.MergeBlock)
	}
	if c.ShanghaiBlock != nil {
		result += fmt.Sprintf(", Shanghai: %v", c.ShanghaiBlock)
	}
	if c.Gas50xBlock != nil {
		result += fmt.Sprintf(", Gas50x: %v", c.Gas50xBlock)
	}
	if c.TIPXDCXMinerDisableBlock != nil {
		result += fmt.Sprintf(", TIPXDCXMinerDisable: %v", c.TIPXDCXMinerDisableBlock)
	}
	if c.TIPXDCXReceiverDisableBlock != nil {
		result += fmt.Sprintf(", TIPXDCXReceiverDisable: %v", c.TIPXDCXReceiverDisableBlock)
	}
	if c.Eip1559Block != nil {
		result += fmt.Sprintf(", Eip1559: %v", c.Eip1559Block)
	}
	if c.CancunBlock != nil {
		result += fmt.Sprintf(", Cancun: %v", c.CancunBlock)
	}
	if c.PragueBlock != nil {
		result += fmt.Sprintf(", Prague: %v", c.PragueBlock)
	}
	if c.OsakaBlock != nil {
		result += fmt.Sprintf(", Osaka: %v", c.OsakaBlock)
	}
	if c.DynamicGasLimitBlock != nil {
		result += fmt.Sprintf(", DynamicGasLimit: %v", c.DynamicGasLimitBlock)
	}
	if c.TIPUpgradeRewardBlock != nil {
		result += fmt.Sprintf(", TIPUpgradeReward: %v", c.TIPUpgradeRewardBlock)
	}
	if c.TIPUpgradePenaltyBlock != nil {
		result += fmt.Sprintf(", TIPUpgradePenalty: %v", c.TIPUpgradePenaltyBlock)
	}
	if c.TIPEpochHalvingBlock != nil {
		result += fmt.Sprintf(", TIPEpochHalving: %v", c.TIPEpochHalvingBlock)
	}
	if c.TRC21IssuerSMC != (common.Address{}) {
		result += fmt.Sprintf(", TRC21IssuerSMC: %s", c.TRC21IssuerSMC.Hex())
	}
	if c.XDCXListingSMC != (common.Address{}) {
		result += fmt.Sprintf(", XDCXListingSMC: %s", c.XDCXListingSMC.Hex())
	}
	if c.RelayerRegistrationSMC != (common.Address{}) {
		result += fmt.Sprintf(", RelayerRegistrationSMC: %s", c.RelayerRegistrationSMC.Hex())
	}
	if c.LendingRegistrationSMC != (common.Address{}) {
		result += fmt.Sprintf(", LendingRegistrationSMC: %s", c.LendingRegistrationSMC.Hex())
	}
	if c.Ethash != nil {
		result += fmt.Sprintf(", Ethash: %s", c.Ethash.String())
	}
	if c.Clique != nil {
		result += fmt.Sprintf(", Clique: %s", c.Clique.String())
	}
	if c.XDPoS != nil {
		result += fmt.Sprintf(", XDPoS: %s", c.XDPoS.String())
	}
	result += "}"
	return result
}

// Description returns a human-readable description of ChainConfig.
// NOTE: don't append "\n" to end
func (c *ChainConfig) Description() string {
	var engine string
	switch {
	case c.Ethash != nil:
		engine = c.Ethash.String()
	case c.XDPoS != nil:
		engine = c.XDPoS.Description(4)
	default:
		engine = "unknown"
	}
	var banner = "Chain configuration:\n"
	banner += fmt.Sprintf("  - ChainID:                     %-8v\n", c.ChainID)
	banner += fmt.Sprintf("  - Homestead:                   %-8v\n", c.HomesteadBlock)
	banner += fmt.Sprintf("  - DAO Fork:                    %-8v\n", c.DAOForkBlock)
	banner += fmt.Sprintf("  - DAO Support:                 %-8v\n", c.DAOForkSupport)
	banner += fmt.Sprintf("  - TIP2019:                     %-8v\n", c.TIP2019Block)
	banner += fmt.Sprintf("  - Tangerine Whistle (EIP 150): %-8v\n", c.EIP150Block)
	banner += fmt.Sprintf("  - Spurious Dragon (EIP 155):   %-8v\n", c.EIP155Block)
	banner += fmt.Sprintf("  - Byzantium:                   %-8v\n", c.ByzantiumBlock)
	banner += fmt.Sprintf("  - Constantinople:              %-8v\n", c.ConstantinopleBlock)
	banner += fmt.Sprintf("  - Petersburg:                  %-8v\n", c.PetersburgBlock)
	banner += fmt.Sprintf("  - Istanbul:                    %-8v\n", c.IstanbulBlock)
	banner += fmt.Sprintf("  - TIPSigning:                  %-8v\n", c.TIPSigningBlock)
	banner += fmt.Sprintf("  - TIPRandomize:                %-8v\n", c.TIPRandomizeBlock)
	banner += fmt.Sprintf("  - TIPIncreaseMasternodes:      %-8v\n", c.TIPIncreaseMasternodesBlock)
	banner += fmt.Sprintf("  - Denylist:                    %-8v\n", c.DenylistBlock)
	banner += fmt.Sprintf("  - TIPNoHalvingMNReward:        %-8v\n", c.TIPNoHalvingMNRewardBlock)
	banner += fmt.Sprintf("  - TIPXDCX:                     %-8v\n", c.TIPXDCXBlock)
	banner += fmt.Sprintf("  - TIPXDCXLending:              %-8v\n", c.TIPXDCXLendingBlock)
	banner += fmt.Sprintf("  - TIPXDCXCancellationFee:      %-8v\n", c.TIPXDCXCancellationFeeBlock)
	banner += fmt.Sprintf("  - TIPTRC21Fee:                 %-8v\n", c.TIPTRC21FeeBlock)
	banner += fmt.Sprintf("  - Berlin:                      %-8v\n", c.BerlinBlock)
	banner += fmt.Sprintf("  - London:                      %-8v\n", c.LondonBlock)
	banner += fmt.Sprintf("  - Merge:                       %-8v\n", c.MergeBlock)
	banner += fmt.Sprintf("  - Shanghai:                    %-8v\n", c.ShanghaiBlock)
	banner += fmt.Sprintf("  - Gas50x:                      %-8v\n", c.Gas50xBlock)
	banner += fmt.Sprintf("  - TIPXDCXMinerDisable:         %-8v\n", c.TIPXDCXMinerDisableBlock)
	banner += fmt.Sprintf("  - TIPXDCXReceiverDisable:      %-8v\n", c.TIPXDCXReceiverDisableBlock)
	banner += fmt.Sprintf("  - Eip1559:                     %-8v\n", c.Eip1559Block)
	banner += fmt.Sprintf("  - Cancun:                      %-8v\n", c.CancunBlock)
	banner += fmt.Sprintf("  - Prague:                      %-8v\n", c.PragueBlock)
	banner += fmt.Sprintf("  - Osaka:                       %-8v\n", c.OsakaBlock)
	banner += fmt.Sprintf("  - DynamicGasLimit:             %-8v\n", c.DynamicGasLimitBlock)
	banner += fmt.Sprintf("  - TIPUpgradeReward:            %-8v\n", c.TIPUpgradeRewardBlock)
	banner += fmt.Sprintf("  - TIPUpgradePenalty:           %-8v\n", c.TIPUpgradePenaltyBlock)
	banner += fmt.Sprintf("  - TIPEpochHalving:             %-8v\n", c.TIPEpochHalvingBlock)
	banner += fmt.Sprintf("  - TRC21IssuerSMC:              %-8s\n", c.TRC21IssuerSMC)
	banner += fmt.Sprintf("  - XDCXListingSMC:              %-8s\n", c.XDCXListingSMC)
	banner += fmt.Sprintf("  - RelayerRegistrationSMC:      %-8s\n", c.RelayerRegistrationSMC)
	banner += fmt.Sprintf("  - LendingRegistrationSMC:      %-8s\n", c.LendingRegistrationSMC)
	banner += fmt.Sprintf("  - Engine:                      %v", engine)
	return banner
}

// IsHomestead returns whether num is either equal to the homestead block or greater.
func (c *ChainConfig) IsHomestead(num *big.Int) bool {
	return isForked(c.HomesteadBlock, num)
}

func (c *ChainConfig) IsTIP2019(num *big.Int) bool {
	return isForked(c.TIP2019Block, num)
}

// IsDAO returns whether num is either equal to the DAO fork block or greater.
func (c *ChainConfig) IsDAOFork(num *big.Int) bool {
	return isForked(c.DAOForkBlock, num)
}

func (c *ChainConfig) IsEIP150(num *big.Int) bool {
	return isForked(c.EIP150Block, num)
}

func (c *ChainConfig) IsEIP155(num *big.Int) bool {
	return isForked(c.EIP155Block, num)
}

func (c *ChainConfig) IsEIP158(num *big.Int) bool {
	return isForked(c.EIP158Block, num)
}

func (c *ChainConfig) IsByzantium(num *big.Int) bool {
	return isForked(c.ByzantiumBlock, num)
}

func (c *ChainConfig) IsConstantinople(num *big.Int) bool {
	return isForked(c.ConstantinopleBlock, num)
}

// IsPetersburg returns whether num is either equal to the Petersburg fork block or greater.
func (c *ChainConfig) IsPetersburg(num *big.Int) bool {
	return isForked(c.TIPXDCXCancellationFeeBlock, num) || isForked(c.PetersburgBlock, num)
}

// IsIstanbul returns whether num is either equal to the TIPXDCXCancellationFeeBlock fork block or greater.
func (c *ChainConfig) IsIstanbul(num *big.Int) bool {
	return isForked(c.TIPXDCXCancellationFeeBlock, num) || isForked(c.IstanbulBlock, num)
}

// IsTIPTRC21Fee returns whether num is either equal to the TIPTRC21Fee fork block or greater.
func (c *ChainConfig) IsTIPTRC21Fee(num *big.Int) bool {
	return isForked(c.TIPTRC21FeeBlock, num)
}

func (c *ChainConfig) IsDenylist(num *big.Int) bool {
	return isForked(c.DenylistBlock, num)
}

// IsBerlin returns whether num is either equal to the Berlin fork block or greater.
func (c *ChainConfig) IsBerlin(num *big.Int) bool {
	return isForked(c.BerlinBlock, num)
}

// IsLondon returns whether num is either equal to the London fork block or greater.
func (c *ChainConfig) IsLondon(num *big.Int) bool {
	return isForked(c.LondonBlock, num)
}

// IsMerge returns whether num is either equal to the Merge fork block or greater.
// Different from Geth which uses `block.difficulty != nil`
func (c *ChainConfig) IsMerge(num *big.Int) bool {
	return isForked(c.MergeBlock, num)
}

// IsShanghai returns whether num is either equal to the Shanghai fork block or greater.
func (c *ChainConfig) IsShanghai(num *big.Int) bool {
	return isForked(c.ShanghaiBlock, num)
}

// IsGas50x returns whether num is either equal to the Gas50x fork block or greater.
func (c *ChainConfig) IsGas50x(num *big.Int) bool {
	return isForked(c.Gas50xBlock, num)
}

// IsEIP1559 returns whether num is either equal to the EIP1559 fork block or greater.
func (c *ChainConfig) IsEIP1559(num *big.Int) bool {
	return isForked(c.Eip1559Block, num)
}

// IsCancun returns whether num is either equal to the Cancun fork block or greater.
func (c *ChainConfig) IsCancun(num *big.Int) bool {
	return isForked(c.CancunBlock, num)
}

// IsPrague returns whether num is either equal to the Prague fork block or greater.
func (c *ChainConfig) IsPrague(num *big.Int) bool {
	return isForked(c.PragueBlock, num)
}

// IsOsaka returns whether num is either equal to the Osaka fork block or greater.
func (c *ChainConfig) IsOsaka(num *big.Int) bool {
	return isForked(c.OsakaBlock, num)
}

// IsDynamicGasLimitBlock returns whether num is either equal to the DynamicGasLimitBlock fork block or greater.
func (c *ChainConfig) IsDynamicGasLimitBlock(num *big.Int) bool {
	return isForked(c.DynamicGasLimitBlock, num)
}

func (c *ChainConfig) IsTIPSigning(num *big.Int) bool {
	return isForked(c.TIPSigningBlock, num)
}

func (c *ChainConfig) IsTIPRandomize(num *big.Int) bool {
	return isForked(c.TIPRandomizeBlock, num)
}

// IsTIPIncreaseMasternodes using for increase masternodes from 18 to 40
func (c *ChainConfig) IsTIPIncreaseMasternodes(num *big.Int) bool {
	return isForked(c.TIPIncreaseMasternodesBlock, num)
}

func (c *ChainConfig) IsTIPNoHalvingMNReward(num *big.Int) bool {
	return isForked(c.TIPNoHalvingMNRewardBlock, num)
}

func (c *ChainConfig) IsTIPXDCX(num *big.Int) bool {
	return isForked(c.TIPXDCXBlock, num)
}

func (c *ChainConfig) IsTIPXDCXMiner(num *big.Int) bool {
	return isForked(c.TIPXDCXBlock, num) && !isForked(c.TIPXDCXMinerDisableBlock, num)
}

func (c *ChainConfig) IsTIPXDCXReceiver(num *big.Int) bool {
	return isForked(c.TIPXDCXBlock, num) && !isForked(c.TIPXDCXReceiverDisableBlock, num)
}

func (c *ChainConfig) IsXDCxDisable(num *big.Int) bool {
	return isForked(c.TIPXDCXMinerDisableBlock, num)
}

func (c *ChainConfig) IsTIPXDCXLending(num *big.Int) bool {
	return isForked(c.TIPXDCXLendingBlock, num)
}

func (c *ChainConfig) IsTIPXDCXCancellationFee(num *big.Int) bool {
	return isForked(c.TIPXDCXCancellationFeeBlock, num)
}

func (c *ChainConfig) IsTIPUpgradeReward(num *big.Int) bool {
	return isForked(c.TIPUpgradeRewardBlock, num)
}

func (c *ChainConfig) IsTIPUpgradePenalty(num *big.Int) bool {
	return isForked(c.TIPUpgradePenaltyBlock, num)
}

func (c *ChainConfig) IsTIPEpochHalving(num *big.Int) bool {
	return isForked(c.TIPEpochHalvingBlock, num)
}

// GasTable returns the gas table corresponding to the current phase (homestead or homestead reprice).
//
// The returned GasTable's fields shouldn't, under any circumstances, be changed.
func (c *ChainConfig) GasTable(num *big.Int) GasTable {
	if num == nil {
		return GasTableHomestead
	}
	switch {
	case c.IsEIP158(num):
		return GasTableEIP158
	case c.IsEIP150(num):
		return GasTableEIP150
	default:
		return GasTableHomestead
	}
}

// CheckCompatible checks whether scheduled fork transitions have been imported
// with a mismatching chain configuration.
func (c *ChainConfig) CheckCompatible(newcfg *ChainConfig, height uint64) *ConfigCompatError {
	bhead := new(big.Int).SetUint64(height)

	// Iterate checkCompatible to find the lowest conflict.
	var lasterr *ConfigCompatError
	for {
		err := c.checkCompatible(newcfg, bhead)
		if err == nil || (lasterr != nil && err.RewindTo == lasterr.RewindTo) {
			break
		}
		lasterr = err
		bhead.SetUint64(err.RewindTo)
	}
	return lasterr
}

func (c *ChainConfig) checkCompatible(newcfg *ChainConfig, head *big.Int) *ConfigCompatError {
	if isForkIncompatible(c.HomesteadBlock, newcfg.HomesteadBlock, head) {
		return newCompatError("Homestead fork block", c.HomesteadBlock, newcfg.HomesteadBlock)
	}
	if isForkIncompatible(c.TIP2019Block, newcfg.TIP2019Block, head) {
		return newCompatError("TIP2019 fork block", c.TIP2019Block, newcfg.TIP2019Block)
	}
	if isForkIncompatible(c.DAOForkBlock, newcfg.DAOForkBlock, head) {
		return newCompatError("DAO fork block", c.DAOForkBlock, newcfg.DAOForkBlock)
	}
	if c.IsDAOFork(head) && c.DAOForkSupport != newcfg.DAOForkSupport {
		return newCompatError("DAO fork support flag", c.DAOForkBlock, newcfg.DAOForkBlock)
	}
	if isForkIncompatible(c.EIP150Block, newcfg.EIP150Block, head) {
		return newCompatError("EIP150 fork block", c.EIP150Block, newcfg.EIP150Block)
	}
	if isForkIncompatible(c.EIP155Block, newcfg.EIP155Block, head) {
		return newCompatError("EIP155 fork block", c.EIP155Block, newcfg.EIP155Block)
	}
	if isForkIncompatible(c.EIP158Block, newcfg.EIP158Block, head) {
		return newCompatError("EIP158 fork block", c.EIP158Block, newcfg.EIP158Block)
	}
	if c.IsEIP158(head) && !configNumEqual(c.ChainID, newcfg.ChainID) {
		return newCompatError("EIP158 chain ID", c.EIP158Block, newcfg.EIP158Block)
	}
	if isForkIncompatible(c.ByzantiumBlock, newcfg.ByzantiumBlock, head) {
		return newCompatError("Byzantium fork block", c.ByzantiumBlock, newcfg.ByzantiumBlock)
	}
	if isForkIncompatible(c.ConstantinopleBlock, newcfg.ConstantinopleBlock, head) {
		return newCompatError("Constantinople fork block", c.ConstantinopleBlock, newcfg.ConstantinopleBlock)
	}
	if isForkIncompatible(c.PetersburgBlock, newcfg.PetersburgBlock, head) {
		// the only case where we allow Petersburg to be set in the past is if it is equal to Constantinople
		// mainly to satisfy fork ordering requirements which state that Petersburg fork be set if Constantinople fork is set
		if isForkIncompatible(c.ConstantinopleBlock, newcfg.PetersburgBlock, head) {
			return newCompatError("Petersburg fork block", c.PetersburgBlock, newcfg.PetersburgBlock)
		}
	}
	if isForkIncompatible(c.IstanbulBlock, newcfg.IstanbulBlock, head) {
		return newCompatError("Istanbul fork block", c.IstanbulBlock, newcfg.IstanbulBlock)
	}
	if isForkIncompatible(c.TIPSigningBlock, newcfg.TIPSigningBlock, head) {
		return newCompatError("TIPSigning fork block", c.TIPSigningBlock, newcfg.TIPSigningBlock)
	}
	if isForkIncompatible(c.TIPRandomizeBlock, newcfg.TIPRandomizeBlock, head) {
		return newCompatError("TIPRandomize fork block", c.TIPRandomizeBlock, newcfg.TIPRandomizeBlock)
	}
	if isForkIncompatible(c.TIPIncreaseMasternodesBlock, newcfg.TIPIncreaseMasternodesBlock, head) {
		return newCompatError("TIPIncreaseMasternodes fork block", c.TIPIncreaseMasternodesBlock, newcfg.TIPIncreaseMasternodesBlock)
	}
	if isForkIncompatible(c.DenylistBlock, newcfg.DenylistBlock, head) {
		return newCompatError("Denylist fork block", c.DenylistBlock, newcfg.DenylistBlock)
	}
	if isForkIncompatible(c.TIPNoHalvingMNRewardBlock, newcfg.TIPNoHalvingMNRewardBlock, head) {
		return newCompatError("TIPNoHalvingMNReward fork block", c.TIPNoHalvingMNRewardBlock, newcfg.TIPNoHalvingMNRewardBlock)
	}
	if isForkIncompatible(c.TIPXDCXBlock, newcfg.TIPXDCXBlock, head) {
		return newCompatError("TIPXDCX fork block", c.TIPXDCXBlock, newcfg.TIPXDCXBlock)
	}
	if isForkIncompatible(c.TIPXDCXLendingBlock, newcfg.TIPXDCXLendingBlock, head) {
		return newCompatError("TIPXDCXLending fork block", c.TIPXDCXLendingBlock, newcfg.TIPXDCXLendingBlock)
	}
	if isForkIncompatible(c.TIPXDCXCancellationFeeBlock, newcfg.TIPXDCXCancellationFeeBlock, head) {
		return newCompatError("TIPXDCXCancellationFee fork block", c.TIPXDCXCancellationFeeBlock, newcfg.TIPXDCXCancellationFeeBlock)
	}
	if isForkIncompatible(c.TIPTRC21FeeBlock, newcfg.TIPTRC21FeeBlock, head) {
		return newCompatError("TIPTRC21Fee fork block", c.TIPTRC21FeeBlock, newcfg.TIPTRC21FeeBlock)
	}
	if isForkIncompatible(c.BerlinBlock, newcfg.BerlinBlock, head) {
		return newCompatError("Berlin fork block", c.BerlinBlock, newcfg.BerlinBlock)
	}
	if isForkIncompatible(c.LondonBlock, newcfg.LondonBlock, head) {
		return newCompatError("London fork block", c.LondonBlock, newcfg.LondonBlock)
	}
	if isForkIncompatible(c.MergeBlock, newcfg.MergeBlock, head) {
		return newCompatError("Merge fork block", c.MergeBlock, newcfg.MergeBlock)
	}
	if isForkIncompatible(c.ShanghaiBlock, newcfg.ShanghaiBlock, head) {
		return newCompatError("Shanghai fork block", c.ShanghaiBlock, newcfg.ShanghaiBlock)
	}
	if isForkIncompatible(c.Gas50xBlock, newcfg.Gas50xBlock, head) {
		return newCompatError("Gas50x fork block", c.Gas50xBlock, newcfg.Gas50xBlock)
	}
	if isForkIncompatible(c.TIPXDCXMinerDisableBlock, newcfg.TIPXDCXMinerDisableBlock, head) {
		return newCompatError("TIPXDCXMinerDisable fork block", c.TIPXDCXMinerDisableBlock, newcfg.TIPXDCXMinerDisableBlock)
	}
	if isForkIncompatible(c.TIPXDCXReceiverDisableBlock, newcfg.TIPXDCXReceiverDisableBlock, head) {
		return newCompatError("TIPXDCXReceiverDisable fork block", c.TIPXDCXReceiverDisableBlock, newcfg.TIPXDCXReceiverDisableBlock)
	}
	if isForkIncompatible(c.Eip1559Block, newcfg.Eip1559Block, head) {
		return newCompatError("Eip1559 fork block", c.Eip1559Block, newcfg.Eip1559Block)
	}
	if isForkIncompatible(c.CancunBlock, newcfg.CancunBlock, head) {
		return newCompatError("Cancun fork block", c.CancunBlock, newcfg.CancunBlock)
	}
	if isForkIncompatible(c.PragueBlock, newcfg.PragueBlock, head) {
		return newCompatError("Prague fork block", c.PragueBlock, newcfg.PragueBlock)
	}
	if isForkIncompatible(c.OsakaBlock, newcfg.OsakaBlock, head) {
		return newCompatError("Osaka fork block", c.OsakaBlock, newcfg.OsakaBlock)
	}
	if isForkIncompatible(c.DynamicGasLimitBlock, newcfg.DynamicGasLimitBlock, head) {
		return newCompatError("DynamicGasLimit fork block", c.DynamicGasLimitBlock, newcfg.DynamicGasLimitBlock)
	}
	if isForkIncompatible(c.TIPUpgradeRewardBlock, newcfg.TIPUpgradeRewardBlock, head) {
		return newCompatError("TIPUpgradeReward fork block", c.TIPUpgradeRewardBlock, newcfg.TIPUpgradeRewardBlock)
	}
	if isForkIncompatible(c.TIPUpgradePenaltyBlock, newcfg.TIPUpgradePenaltyBlock, head) {
		return newCompatError("TIPUpgradePenalty fork block", c.TIPUpgradePenaltyBlock, newcfg.TIPUpgradePenaltyBlock)
	}
	if isForkIncompatible(c.TIPEpochHalvingBlock, newcfg.TIPEpochHalvingBlock, head) {
		return newCompatError("TIPEpochHalving fork block", c.TIPEpochHalvingBlock, newcfg.TIPEpochHalvingBlock)
	}
	if !XDPoSConfigEqual(c.XDPoS, newcfg.XDPoS) {
		storedblock := big.NewInt(1)
		if c.XDPoS != nil && c.XDPoS.V2 != nil && c.XDPoS.V2.SwitchBlock != nil {
			storedblock = c.XDPoS.V2.SwitchBlock
		}
		newblock := big.NewInt(1)
		if newcfg.XDPoS != nil && newcfg.XDPoS.V2 != nil && newcfg.XDPoS.V2.SwitchBlock != nil {
			newblock = newcfg.XDPoS.V2.SwitchBlock
		}
		return newCompatError("XDPoS not equal", storedblock, newblock)
	}
	if c.XDPoS != nil && newcfg.XDPoS != nil && c.XDPoS.V2 != nil && newcfg.XDPoS.V2 != nil && isForkIncompatible(c.XDPoS.V2.SwitchBlock, newcfg.XDPoS.V2.SwitchBlock, head) {
		return newCompatError("XDPoS.V2.SwitchBlock", c.XDPoS.V2.SwitchBlock, newcfg.XDPoS.V2.SwitchBlock)
	}
	return nil
}

// isForkIncompatible returns true if a fork scheduled at s1 cannot be rescheduled to
// block s2 because head is already past the fork.
func isForkIncompatible(s1, s2, head *big.Int) bool {
	return (isForked(s1, head) || isForked(s2, head)) && !configNumEqual(s1, s2)
}

// isForked returns whether a fork scheduled at block s is active at the given head block.
func isForked(s, head *big.Int) bool {
	if s == nil || head == nil {
		return false
	}
	return s.Cmp(head) <= 0
}

func configNumEqual(x, y *big.Int) bool {
	if x == nil || y == nil {
		return x == y
	}
	return x.Cmp(y) == 0
}

// ConfigCompatError is raised if the locally-stored blockchain is initialised with a
// ChainConfig that would alter the past.
type ConfigCompatError struct {
	What string
	// block numbers of the stored and new configurations
	StoredConfig, NewConfig *big.Int
	// the block number to which the local chain must be rewound to correct the error
	RewindTo uint64
}

func newCompatError(what string, storedblock, newblock *big.Int) *ConfigCompatError {
	var rew *big.Int
	switch {
	case storedblock == nil:
		rew = newblock
	case newblock == nil || storedblock.Cmp(newblock) < 0:
		rew = storedblock
	default:
		rew = newblock
	}
	err := &ConfigCompatError{what, storedblock, newblock, 0}
	if rew != nil && rew.Sign() > 0 {
		err.RewindTo = rew.Uint64() - 1
	}
	return err
}

func (err *ConfigCompatError) Error() string {
	return fmt.Sprintf("mismatching %s in database (have %d, want %d, rewindto %d)", err.What, err.StoredConfig, err.NewConfig, err.RewindTo)
}

// Rules wraps ChainConfig and is merely syntatic sugar or can be used for functions
// that do not have or require information about the block.
//
// Rules is a one time interface meaning that it shouldn't be used in between transition
// phases.
type Rules struct {
	ChainId          *big.Int
	IsHomestead      bool
	IsEIP150         bool
	IsEIP155         bool
	IsEIP158         bool
	IsByzantium      bool
	IsConstantinople bool
	IsPetersburg     bool
	IsIstanbul       bool
	IsBerlin         bool
	IsLondon         bool
	IsMerge          bool
	IsShanghai       bool
	IsXDCxDisable    bool
	IsEIP1559        bool
	IsCancun         bool
	IsPrague         bool
	IsOsaka          bool
}

func (c *ChainConfig) Rules(num *big.Int) Rules {
	chainId := c.ChainID
	if chainId == nil {
		chainId = new(big.Int)
	}
	return Rules{
		ChainId:          new(big.Int).Set(chainId),
		IsHomestead:      c.IsHomestead(num),
		IsEIP150:         c.IsEIP150(num),
		IsEIP155:         c.IsEIP155(num),
		IsEIP158:         c.IsEIP158(num),
		IsByzantium:      c.IsByzantium(num),
		IsConstantinople: c.IsConstantinople(num),
		IsPetersburg:     c.IsPetersburg(num),
		IsIstanbul:       c.IsIstanbul(num),
		IsBerlin:         c.IsBerlin(num),
		IsLondon:         c.IsLondon(num),
		IsMerge:          c.IsMerge(num),
		IsShanghai:       c.IsShanghai(num),
		IsXDCxDisable:    c.IsXDCxDisable(num),
		IsEIP1559:        c.IsEIP1559(num),
		IsCancun:         c.IsCancun(num),
		IsPrague:         c.IsPrague(num),
		IsOsaka:          c.IsOsaka(num),
	}
}

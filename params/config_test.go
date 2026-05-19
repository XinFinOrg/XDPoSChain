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
	"math/big"
	"strings"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/stretchr/testify/assert"
)

func TestChainConfigValidateForStartup(t *testing.T) {
	t.Run("missing field", func(t *testing.T) {
		cfg := &ChainConfig{}
		err := cfg.CheckConfigForkOrder()
		if !errors.Is(err, ErrMissingForkSwitch) {
			t.Fatalf("unexpected error: have %v want %v", err, ErrMissingForkSwitch)
		}
		if err == nil || err.Error() != "invalid chain config: missing fork switch: ChainID" {
			t.Fatalf("unexpected error string: %v", err)
		}
	})

	t.Run("engine-less mainnet chain id fails", func(t *testing.T) {
		cfg := &ChainConfig{
			ChainID:                big.NewInt(1),
			TIPTRC21FeeBlock:       big.NewInt(0),
			Gas50xBlock:            big.NewInt(0),
			TRC21IssuerSMC:         TestnetChainConfig.TRC21IssuerSMC,
			XDCXListingSMC:         TestnetChainConfig.XDCXListingSMC,
			RelayerRegistrationSMC: TestnetChainConfig.RelayerRegistrationSMC,
			LendingRegistrationSMC: TestnetChainConfig.LendingRegistrationSMC,
		}
		err := cfg.CheckConfigForkOrder()
		if !errors.Is(err, ErrMissingForkSwitch) {
			t.Fatalf("unexpected error: have %v want %v", err, ErrMissingForkSwitch)
		}
		if err == nil || err.Error() != "invalid chain config: missing fork switch: XDPoS" {
			t.Fatalf("unexpected error string: %v", err)
		}
	})
	t.Run("engine-less testnet chain id fails", func(t *testing.T) {
		cfg := &ChainConfig{
			ChainID:                new(big.Int).Set(TestnetChainConfig.ChainID),
			TIPTRC21FeeBlock:       big.NewInt(0),
			Gas50xBlock:            big.NewInt(0),
			TRC21IssuerSMC:         TestnetChainConfig.TRC21IssuerSMC,
			XDCXListingSMC:         TestnetChainConfig.XDCXListingSMC,
			RelayerRegistrationSMC: TestnetChainConfig.RelayerRegistrationSMC,
			LendingRegistrationSMC: TestnetChainConfig.LendingRegistrationSMC,
		}
		err := cfg.CheckConfigForkOrder()
		if !errors.Is(err, ErrMissingForkSwitch) {
			t.Fatalf("unexpected error: have %v want %v", err, ErrMissingForkSwitch)
		}
		if err == nil || err.Error() != "invalid chain config: missing fork switch: XDPoS" {
			t.Fatalf("unexpected error string: %v", err)
		}
	})
	t.Run("engine-less 1337 remains valid", func(t *testing.T) {
		cfg := &ChainConfig{
			ChainID:                big.NewInt(1337),
			TIPTRC21FeeBlock:       big.NewInt(0),
			Gas50xBlock:            big.NewInt(0),
			TRC21IssuerSMC:         TestnetChainConfig.TRC21IssuerSMC,
			XDCXListingSMC:         TestnetChainConfig.XDCXListingSMC,
			RelayerRegistrationSMC: TestnetChainConfig.RelayerRegistrationSMC,
			LendingRegistrationSMC: TestnetChainConfig.LendingRegistrationSMC,
		}
		if err := cfg.CheckConfigForkOrder(); err != nil {
			t.Fatalf("ValidateForStartup failed: %v", err)
		}
	})
	t.Run("custom ethash chain without XDC forks remains valid", func(t *testing.T) {
		cfg := &ChainConfig{
			ChainID:        big.NewInt(1234),
			HomesteadBlock: big.NewInt(0),
			Ethash:         new(EthashConfig),
		}
		if err := cfg.CheckConfigForkOrder(); err != nil {
			t.Fatalf("ValidateForStartup failed for plain custom ethash config: %v", err)
		}
	})
	t.Run("gas50x block requires tiptrc21 fee block", func(t *testing.T) {
		cfg := &ChainConfig{
			ChainID:     big.NewInt(1234),
			Gas50xBlock: big.NewInt(100),
			Ethash:      new(EthashConfig),
		}
		err := cfg.CheckConfigForkOrder()
		if !errors.Is(err, ErrMissingForkSwitch) {
			t.Fatalf("unexpected error: have %v want %v", err, ErrMissingForkSwitch)
		}
		if err == nil || err.Error() != "invalid chain config: missing fork switch: TIPTRC21FeeBlock" {
			t.Fatalf("unexpected error string: %v", err)
		}
	})
	t.Run("gas50x block must not precede tiptrc21 fee block", func(t *testing.T) {
		cfg := &ChainConfig{
			ChainID:                big.NewInt(1234),
			TIPTRC21FeeBlock:       big.NewInt(20),
			Gas50xBlock:            big.NewInt(10),
			TRC21IssuerSMC:         TestnetChainConfig.TRC21IssuerSMC,
			XDCXListingSMC:         TestnetChainConfig.XDCXListingSMC,
			RelayerRegistrationSMC: TestnetChainConfig.RelayerRegistrationSMC,
			LendingRegistrationSMC: TestnetChainConfig.LendingRegistrationSMC,
			Ethash:                 new(EthashConfig),
		}

		err := cfg.CheckConfigForkOrder()
		if !errors.Is(err, ErrWrongForkSwitchOrder) {
			t.Fatalf("unexpected error: have %v want %v", err, ErrWrongForkSwitchOrder)
		}
		if err == nil || err.Error() != "invalid chain config: wrong fork switch order: TIPTRC21FeeBlock 20 > Gas50xBlock 10" {
			t.Fatalf("unexpected error string: %v", err)
		}
	})
	t.Run("gas50x block must not follow miner disable block", func(t *testing.T) {
		cfg := &ChainConfig{
			ChainID:                  big.NewInt(1234),
			TIPTRC21FeeBlock:         big.NewInt(0),
			Gas50xBlock:              big.NewInt(20),
			TIPXDCXMinerDisableBlock: big.NewInt(10),
			TRC21IssuerSMC:           TestnetChainConfig.TRC21IssuerSMC,
			XDCXListingSMC:           TestnetChainConfig.XDCXListingSMC,
			RelayerRegistrationSMC:   TestnetChainConfig.RelayerRegistrationSMC,
			LendingRegistrationSMC:   TestnetChainConfig.LendingRegistrationSMC,
			Ethash:                   new(EthashConfig),
		}

		err := cfg.CheckConfigForkOrder()
		if !errors.Is(err, ErrWrongForkSwitchOrder) {
			t.Fatalf("unexpected error: have %v want %v", err, ErrWrongForkSwitchOrder)
		}
		if err == nil || err.Error() != "invalid chain config: wrong fork switch order: Gas50xBlock 20 > TIPXDCXMinerDisableBlock 10" {
			t.Fatalf("unexpected error string: %v", err)
		}
	})
	t.Run("tiptrc21 fee block requires system contract addresses", func(t *testing.T) {
		cfg := &ChainConfig{
			ChainID:          big.NewInt(1234),
			TIPTRC21FeeBlock: big.NewInt(0),
			Gas50xBlock:      big.NewInt(0),
			Ethash:           new(EthashConfig),
		}
		err := cfg.CheckConfigForkOrder()
		if !errors.Is(err, ErrMissingForkSwitch) {
			t.Fatalf("unexpected error: have %v want %v", err, ErrMissingForkSwitch)
		}
		if err == nil || !strings.Contains(err.Error(), "TRC21IssuerSMC") {
			t.Fatalf("unexpected error string: %v", err)
		}
	})
	t.Run("built-in config", func(t *testing.T) {
		cfg := TestnetChainConfig.Clone()
		if err := cfg.CheckConfigForkOrder(); err != nil {
			t.Fatalf("ValidateForStartup failed for built-in config: %v", err)
		}
	})
	t.Run("xdpos v2 missing fails", func(t *testing.T) {
		cfg := &ChainConfig{
			ChainID:                big.NewInt(1234),
			TIPTRC21FeeBlock:       big.NewInt(0),
			Gas50xBlock:            big.NewInt(0),
			TRC21IssuerSMC:         TestnetChainConfig.TRC21IssuerSMC,
			XDCXListingSMC:         TestnetChainConfig.XDCXListingSMC,
			RelayerRegistrationSMC: TestnetChainConfig.RelayerRegistrationSMC,
			LendingRegistrationSMC: TestnetChainConfig.LendingRegistrationSMC,
			XDPoS: &XDPoSConfig{
				Epoch:                900,
				FoundationWalletAddr: TestnetChainConfig.XDPoS.FoundationWalletAddr,
				MaxMasternodesV2:     108,
			},
		}
		err := cfg.CheckConfigForkOrder()
		if !errors.Is(err, ErrMissingForkSwitch) {
			t.Fatalf("unexpected error: have %v want %v", err, ErrMissingForkSwitch)
		}
		if err == nil || !strings.Contains(err.Error(), "XDPoS.V2") {
			t.Fatalf("unexpected error string: %v", err)
		}
	})
	t.Run("xdpos v2 current config missing fails", func(t *testing.T) {
		cfg := &ChainConfig{
			ChainID:                big.NewInt(1234),
			TIPTRC21FeeBlock:       big.NewInt(0),
			Gas50xBlock:            big.NewInt(0),
			TRC21IssuerSMC:         TestnetChainConfig.TRC21IssuerSMC,
			XDCXListingSMC:         TestnetChainConfig.XDCXListingSMC,
			RelayerRegistrationSMC: TestnetChainConfig.RelayerRegistrationSMC,
			LendingRegistrationSMC: TestnetChainConfig.LendingRegistrationSMC,
			XDPoS: &XDPoSConfig{
				Epoch:                900,
				FoundationWalletAddr: TestnetChainConfig.XDPoS.FoundationWalletAddr,
				MaxMasternodesV2:     108,
				V2: &V2{
					SwitchEpoch: 1,
					SwitchBlock: big.NewInt(900),
					AllConfigs: map[uint64]*V2Config{
						0: {SwitchRound: 0, MinePeriod: 2, TimeoutPeriod: 10},
					},
				},
			},
		}
		err := cfg.CheckConfigForkOrder()
		if !errors.Is(err, ErrMissingForkSwitch) {
			t.Fatalf("unexpected error: have %v want %v", err, ErrMissingForkSwitch)
		}
		if err == nil || !strings.Contains(err.Error(), "XDPoS.V2.CurrentConfig") {
			t.Fatalf("unexpected error string: %v", err)
		}
	})
	t.Run("xdpos v2 all configs requires round zero entry", func(t *testing.T) {
		cfg := &ChainConfig{
			ChainID:                big.NewInt(1234),
			TIPTRC21FeeBlock:       big.NewInt(0),
			Gas50xBlock:            big.NewInt(0),
			TRC21IssuerSMC:         TestnetChainConfig.TRC21IssuerSMC,
			XDCXListingSMC:         TestnetChainConfig.XDCXListingSMC,
			RelayerRegistrationSMC: TestnetChainConfig.RelayerRegistrationSMC,
			LendingRegistrationSMC: TestnetChainConfig.LendingRegistrationSMC,
			XDPoS: &XDPoSConfig{
				Epoch:                900,
				FoundationWalletAddr: TestnetChainConfig.XDPoS.FoundationWalletAddr,
				MaxMasternodesV2:     108,
				V2: &V2{
					SwitchEpoch:   1,
					SwitchBlock:   big.NewInt(900),
					CurrentConfig: &V2Config{SwitchRound: 9, MinePeriod: 2, TimeoutPeriod: 10},
					AllConfigs: map[uint64]*V2Config{
						9: {SwitchRound: 9, MinePeriod: 2, TimeoutPeriod: 10},
					},
				},
			},
		}
		err := cfg.CheckConfigForkOrder()
		if !errors.Is(err, ErrMissingForkSwitch) {
			t.Fatalf("unexpected error: have %v want %v", err, ErrMissingForkSwitch)
		}
		if err == nil || !strings.Contains(err.Error(), "XDPoS.V2.AllConfigs[0]") {
			t.Fatalf("unexpected error string: %v", err)
		}
	})
	t.Run("xdpos v2 all configs requires matching switch round", func(t *testing.T) {
		cfg := &ChainConfig{
			ChainID:                big.NewInt(1234),
			TIPTRC21FeeBlock:       big.NewInt(0),
			Gas50xBlock:            big.NewInt(0),
			TRC21IssuerSMC:         TestnetChainConfig.TRC21IssuerSMC,
			XDCXListingSMC:         TestnetChainConfig.XDCXListingSMC,
			RelayerRegistrationSMC: TestnetChainConfig.RelayerRegistrationSMC,
			LendingRegistrationSMC: TestnetChainConfig.LendingRegistrationSMC,
			XDPoS: &XDPoSConfig{
				Epoch:                900,
				FoundationWalletAddr: TestnetChainConfig.XDPoS.FoundationWalletAddr,
				MaxMasternodesV2:     108,
				V2: &V2{
					SwitchEpoch:   1,
					SwitchBlock:   big.NewInt(900),
					CurrentConfig: &V2Config{SwitchRound: 0, MinePeriod: 2, TimeoutPeriod: 10},
					AllConfigs: map[uint64]*V2Config{
						0:  {SwitchRound: 0, MinePeriod: 2, TimeoutPeriod: 10},
						10: {SwitchRound: 9, MinePeriod: 2, TimeoutPeriod: 10},
					},
				},
			},
		}
		err := cfg.CheckConfigForkOrder()
		if !errors.Is(err, ErrWrongForkSwitchOrder) {
			t.Fatalf("unexpected error: have %v want %v", err, ErrWrongForkSwitchOrder)
		}
		if err == nil || !strings.Contains(err.Error(), "XDPoS.V2.AllConfigs[10].SwitchRound") {
			t.Fatalf("unexpected error string: %v", err)
		}
	})
	t.Run("xdpos v2 current config must match scheduled entry", func(t *testing.T) {
		cfg := &ChainConfig{
			ChainID:                big.NewInt(1234),
			TIPTRC21FeeBlock:       big.NewInt(0),
			Gas50xBlock:            big.NewInt(0),
			TRC21IssuerSMC:         TestnetChainConfig.TRC21IssuerSMC,
			XDCXListingSMC:         TestnetChainConfig.XDCXListingSMC,
			RelayerRegistrationSMC: TestnetChainConfig.RelayerRegistrationSMC,
			LendingRegistrationSMC: TestnetChainConfig.LendingRegistrationSMC,
			XDPoS: &XDPoSConfig{
				Epoch:                900,
				FoundationWalletAddr: TestnetChainConfig.XDPoS.FoundationWalletAddr,
				MaxMasternodesV2:     108,
				V2: &V2{
					SwitchEpoch:   1,
					SwitchBlock:   big.NewInt(900),
					CurrentConfig: &V2Config{SwitchRound: 0, MinePeriod: 3, TimeoutPeriod: 10},
					AllConfigs: map[uint64]*V2Config{
						0: {SwitchRound: 0, MinePeriod: 2, TimeoutPeriod: 10},
					},
				},
			},
		}
		err := cfg.CheckConfigForkOrder()
		if !errors.Is(err, ErrWrongForkSwitchOrder) {
			t.Fatalf("unexpected error: have %v want %v", err, ErrWrongForkSwitchOrder)
		}
		if err == nil || !strings.Contains(err.Error(), "XDPoS.V2.CurrentConfig") {
			t.Fatalf("unexpected error string: %v", err)
		}
	})
	t.Run("xdpos v2 switch block must align with epoch", func(t *testing.T) {
		cfg := &ChainConfig{
			ChainID:                big.NewInt(1234),
			TIPTRC21FeeBlock:       big.NewInt(0),
			Gas50xBlock:            big.NewInt(0),
			TRC21IssuerSMC:         TestnetChainConfig.TRC21IssuerSMC,
			XDCXListingSMC:         TestnetChainConfig.XDCXListingSMC,
			RelayerRegistrationSMC: TestnetChainConfig.RelayerRegistrationSMC,
			LendingRegistrationSMC: TestnetChainConfig.LendingRegistrationSMC,
			XDPoS: &XDPoSConfig{
				Epoch:                900,
				FoundationWalletAddr: TestnetChainConfig.XDPoS.FoundationWalletAddr,
				MaxMasternodesV2:     108,
				V2: &V2{
					SwitchEpoch:   1,
					SwitchBlock:   big.NewInt(901),
					CurrentConfig: &V2Config{SwitchRound: 0, MinePeriod: 2, TimeoutPeriod: 10},
					AllConfigs: map[uint64]*V2Config{
						0: {SwitchRound: 0, MinePeriod: 2, TimeoutPeriod: 10},
					},
				},
			},
		}
		err := cfg.CheckConfigForkOrder()
		if !errors.Is(err, ErrWrongForkSwitchOrder) {
			t.Fatalf("unexpected error: have %v want %v", err, ErrWrongForkSwitchOrder)
		}
		if err == nil || !strings.Contains(err.Error(), "XDPoS.V2.SwitchBlock") {
			t.Fatalf("unexpected error string: %v", err)
		}
	})
	t.Run("xdpos v2 exp timeout config must be sane", func(t *testing.T) {
		cfg := &ChainConfig{
			ChainID:                big.NewInt(1234),
			TIPTRC21FeeBlock:       big.NewInt(0),
			Gas50xBlock:            big.NewInt(0),
			TRC21IssuerSMC:         TestnetChainConfig.TRC21IssuerSMC,
			XDCXListingSMC:         TestnetChainConfig.XDCXListingSMC,
			RelayerRegistrationSMC: TestnetChainConfig.RelayerRegistrationSMC,
			LendingRegistrationSMC: TestnetChainConfig.LendingRegistrationSMC,
			XDPoS: &XDPoSConfig{
				Epoch:                900,
				FoundationWalletAddr: TestnetChainConfig.XDPoS.FoundationWalletAddr,
				MaxMasternodesV2:     108,
				V2: &V2{
					SwitchEpoch: 1,
					SwitchBlock: big.NewInt(900),
					CurrentConfig: &V2Config{
						SwitchRound:   0,
						MinePeriod:    2,
						TimeoutPeriod: 10,
						ExpTimeoutConfig: ExpTimeoutConfig{
							Base:        2,
							MaxExponent: 32,
						},
					},
					AllConfigs: map[uint64]*V2Config{
						0: {
							SwitchRound:   0,
							MinePeriod:    2,
							TimeoutPeriod: 10,
							ExpTimeoutConfig: ExpTimeoutConfig{
								Base:        2,
								MaxExponent: 32,
							},
						},
					},
				},
			},
		}
		err := cfg.CheckConfigForkOrder()
		if !errors.Is(err, ErrWrongForkSwitchOrder) {
			t.Fatalf("unexpected error: have %v want %v", err, ErrWrongForkSwitchOrder)
		}
		if err == nil || !strings.Contains(err.Error(), "XDPoS.V2.CurrentConfig.ExpTimeoutConfig") {
			t.Fatalf("unexpected error string: %v", err)
		}
	})
	t.Run("missing system contract addresses fail", func(t *testing.T) {
		tests := []struct {
			name      string
			mutate    func(*ChainConfig)
			wantField string
		}{
			{
				name: "missing trc21 issuer",
				mutate: func(cfg *ChainConfig) {
					cfg.TRC21IssuerSMC = common.Address{}
				},
				wantField: "TRC21IssuerSMC",
			},
			{
				name: "missing xdcx listing",
				mutate: func(cfg *ChainConfig) {
					cfg.XDCXListingSMC = common.Address{}
				},
				wantField: "XDCXListingSMC",
			},
			{
				name: "missing relayer registration",
				mutate: func(cfg *ChainConfig) {
					cfg.RelayerRegistrationSMC = common.Address{}
				},
				wantField: "RelayerRegistrationSMC",
			},
			{
				name: "missing lending registration",
				mutate: func(cfg *ChainConfig) {
					cfg.LendingRegistrationSMC = common.Address{}
				},
				wantField: "LendingRegistrationSMC",
			},
		}

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				cfg := TestnetChainConfig.Clone()
				test.mutate(cfg)

				err := cfg.CheckConfigForkOrder()
				if !errors.Is(err, ErrMissingForkSwitch) {
					t.Fatalf("unexpected error: have %v want %v", err, ErrMissingForkSwitch)
				}
				if err == nil || !strings.Contains(err.Error(), test.wantField) {
					t.Fatalf("unexpected error string: %v", err)
				}
			})
		}
	})
	t.Run("missing foundation wallet fails", func(t *testing.T) {
		cfg := TestnetChainConfig.Clone()
		cfg.XDPoS.FoundationWalletAddr = common.Address{}

		err := cfg.CheckConfigForkOrder()
		if !errors.Is(err, ErrMissingForkSwitch) {
			t.Fatalf("unexpected error: have %v want %v", err, ErrMissingForkSwitch)
		}
		if err == nil || !strings.Contains(err.Error(), "XDPoS.FoundationWalletAddr") {
			t.Fatalf("unexpected error string: %v", err)
		}
	})

	tests := []struct {
		name      string
		mutate    func(*ChainConfig)
		wantField string
	}{
		{
			name: "eip150 before tip2019",
			mutate: func(cfg *ChainConfig) {
				cfg.EIP150Block = big.NewInt(cfg.TIP2019Block.Int64() - 1)
			},
			wantField: "TIP2019Block",
		},
		{
			name: "eip155 before eip150",
			mutate: func(cfg *ChainConfig) {
				cfg.EIP155Block = big.NewInt(cfg.EIP150Block.Int64() - 1)
			},
			wantField: "EIP150Block",
		},
		{
			name: "byzantium before eip158",
			mutate: func(cfg *ChainConfig) {
				cfg.ByzantiumBlock = big.NewInt(cfg.EIP158Block.Int64() - 1)
			},
			wantField: "EIP158Block",
		},
		{
			name: "tip signing before byzantium",
			mutate: func(cfg *ChainConfig) {
				cfg.TIPSigningBlock = big.NewInt(cfg.ByzantiumBlock.Int64() - 1)
			},
			wantField: "ByzantiumBlock",
		},
		{
			name: "tip randomize before tip signing",
			mutate: func(cfg *ChainConfig) {
				cfg.TIPRandomizeBlock = big.NewInt(cfg.TIPSigningBlock.Int64() - 1)
			},
			wantField: "TIPSigningBlock",
		},
		{
			name: "tip increase masternodes before tip randomize",
			mutate: func(cfg *ChainConfig) {
				cfg.TIPIncreaseMasternodesBlock = big.NewInt(cfg.TIPRandomizeBlock.Int64() - 1)
			},
			wantField: "TIPRandomizeBlock",
		},
		{
			name: "miner disable before gas50x",
			mutate: func(cfg *ChainConfig) {
				cfg.BerlinBlock = nil
				cfg.LondonBlock = nil
				cfg.MergeBlock = nil
				cfg.ShanghaiBlock = nil
				cfg.TIPXDCXMinerDisableBlock = big.NewInt(cfg.Gas50xBlock.Int64() - 1)
			},
			wantField: "Gas50xBlock",
		},
		{
			name: "receiver disable before miner disable",
			mutate: func(cfg *ChainConfig) {
				cfg.TIPXDCXReceiverDisableBlock = big.NewInt(cfg.TIPXDCXMinerDisableBlock.Int64() - 1)
			},
			wantField: "TIPXDCXMinerDisableBlock",
		},
		{
			name: "berlin before trc21",
			mutate: func(cfg *ChainConfig) {
				cfg.BerlinBlock = big.NewInt(cfg.TIPTRC21FeeBlock.Int64() - 1)
			},
			wantField: "TIPTRC21FeeBlock",
		},
		{
			name: "london before berlin",
			mutate: func(cfg *ChainConfig) {
				cfg.LondonBlock = big.NewInt(cfg.BerlinBlock.Int64() - 1)
			},
			wantField: "BerlinBlock",
		},
		{
			name: "merge before london",
			mutate: func(cfg *ChainConfig) {
				cfg.MergeBlock = big.NewInt(cfg.LondonBlock.Int64() - 1)
			},
			wantField: "LondonBlock",
		},
		{
			name: "shanghai before merge",
			mutate: func(cfg *ChainConfig) {
				cfg.ShanghaiBlock = big.NewInt(cfg.MergeBlock.Int64() - 1)
			},
			wantField: "MergeBlock",
		},
		{
			name: "eip1559 before shanghai",
			mutate: func(cfg *ChainConfig) {
				cfg.TIPXDCXMinerDisableBlock = nil
				cfg.TIPXDCXReceiverDisableBlock = nil
				cfg.EIP1559Block = big.NewInt(cfg.ShanghaiBlock.Int64() - 1)
			},
			wantField: "ShanghaiBlock",
		},
		{
			name: "cancun before eip1559",
			mutate: func(cfg *ChainConfig) {
				cfg.CancunBlock = big.NewInt(cfg.EIP1559Block.Int64() - 1)
			},
			wantField: "EIP1559Block",
		},
		{
			name: "prague before cancun",
			mutate: func(cfg *ChainConfig) {
				cfg.PragueBlock = big.NewInt(cfg.CancunBlock.Int64() - 1)
			},
			wantField: "CancunBlock",
		},
		{
			name: "osaka before prague",
			mutate: func(cfg *ChainConfig) {
				cfg.PragueBlock = big.NewInt(cfg.CancunBlock.Int64())
				cfg.OsakaBlock = big.NewInt(cfg.PragueBlock.Int64() - 1)
			},
			wantField: "PragueBlock",
		},
		{
			name: "dynamic gas limit before osaka",
			mutate: func(cfg *ChainConfig) {
				cfg.PragueBlock = big.NewInt(cfg.CancunBlock.Int64())
				cfg.OsakaBlock = big.NewInt(cfg.PragueBlock.Int64())
				cfg.DynamicGasLimitBlock = big.NewInt(cfg.OsakaBlock.Int64() - 1)
			},
			wantField: "OsakaBlock",
		},
		{
			name: "upgrade reward before dynamic gas limit",
			mutate: func(cfg *ChainConfig) {
				cfg.PragueBlock = big.NewInt(cfg.CancunBlock.Int64())
				cfg.OsakaBlock = big.NewInt(cfg.PragueBlock.Int64())
				cfg.DynamicGasLimitBlock = big.NewInt(cfg.OsakaBlock.Int64())
				cfg.TIPUpgradeRewardBlock = big.NewInt(cfg.DynamicGasLimitBlock.Int64() - 1)
			},
			wantField: "DynamicGasLimitBlock",
		},
		{
			name: "upgrade penalty before upgrade reward",
			mutate: func(cfg *ChainConfig) {
				cfg.PragueBlock = big.NewInt(cfg.CancunBlock.Int64())
				cfg.OsakaBlock = big.NewInt(cfg.PragueBlock.Int64())
				cfg.DynamicGasLimitBlock = big.NewInt(cfg.OsakaBlock.Int64())
				cfg.TIPUpgradeRewardBlock = big.NewInt(cfg.DynamicGasLimitBlock.Int64())
				cfg.TIPUpgradePenaltyBlock = big.NewInt(cfg.TIPUpgradeRewardBlock.Int64() - 1)
			},
			wantField: "TIPUpgradeRewardBlock",
		},
		{
			name: "epoch halving before upgrade penalty",
			mutate: func(cfg *ChainConfig) {
				cfg.PragueBlock = big.NewInt(cfg.CancunBlock.Int64())
				cfg.OsakaBlock = big.NewInt(cfg.PragueBlock.Int64())
				cfg.DynamicGasLimitBlock = big.NewInt(cfg.OsakaBlock.Int64())
				cfg.TIPUpgradeRewardBlock = big.NewInt(cfg.DynamicGasLimitBlock.Int64())
				cfg.TIPUpgradePenaltyBlock = big.NewInt(cfg.TIPUpgradeRewardBlock.Int64())
				cfg.TIPEpochHalvingBlock = big.NewInt(cfg.TIPUpgradePenaltyBlock.Int64() - 1)
			},
			wantField: "TIPUpgradePenaltyBlock",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := TestnetChainConfig.Clone()
			test.mutate(cfg)

			err := cfg.CheckConfigForkOrder()
			if !errors.Is(err, ErrWrongForkSwitchOrder) {
				t.Fatalf("unexpected error: have %v want %v", err, ErrWrongForkSwitchOrder)
			}
			if err == nil || !strings.Contains(err.Error(), test.wantField) {
				t.Fatalf("unexpected error string: %v", err)
			}
		})
	}
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

func TestChainConfigClonePreservesNilBigIntFields(t *testing.T) {
	original := &ChainConfig{}

	clone := original.Clone()
	if clone == nil {
		t.Fatal("expected clone for non-nil config")
	}
	if clone == original {
		t.Fatal("expected distinct config clone")
	}
	if clone.ChainID != nil {
		t.Fatalf("expected nil ChainID, got %v", clone.ChainID)
	}
	if clone.OsakaBlock != nil {
		t.Fatalf("expected nil OsakaBlock, got %v", clone.OsakaBlock)
	}
	if clone.TIP2019Block != nil {
		t.Fatalf("expected nil TIP2019Block, got %v", clone.TIP2019Block)
	}
}

func TestChainConfigSemanticEqualIgnoresJSONPresence(t *testing.T) {
	left := XDCMainnetChainConfig.CloneForBackfill()
	right := XDCMainnetChainConfig.Clone()

	if !left.Equal(right) {
		t.Fatalf("expected semantic equality to ignore JSON presence: left=%v right=%v", left, right)
	}
}

func TestChainConfigMarshalJSONOmitsInferredZeroValueFields(t *testing.T) {
	cfg := (&ChainConfig{
		ChainID:        big.NewInt(51),
		DAOForkBlock:   big.NewInt(0),
		DAOForkSupport: false,
		Ethash:         new(EthashConfig),
	}).CloneForBackfill()

	encoded, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("failed to marshal inferred config: %v", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &raw); err != nil {
		t.Fatalf("failed to inspect marshaled config: %v", err)
	}
	if _, ok := raw["daoForkSupport"]; ok {
		t.Fatalf("expected inferred false daoForkSupport to remain omitted, have %s", encoded)
	}
	if _, ok := raw["daoForkBlock"]; !ok {
		t.Fatalf("expected declared daoForkBlock to remain present, have %s", encoded)
	}
}

func TestChainConfigCloneForJSONOmitsRuntimeOnlyJSONPresence(t *testing.T) {
	cfg := (&ChainConfig{
		ChainID:        big.NewInt(51),
		DAOForkBlock:   big.NewInt(0),
		DAOForkSupport: false,
		Ethash:         new(EthashConfig),
	}).CloneForBackfill().CloneForJSON()

	encoded, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("failed to marshal plain config: %v", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &raw); err != nil {
		t.Fatalf("failed to inspect marshaled config: %v", err)
	}
	if _, ok := raw["daoForkSupport"]; ok {
		t.Fatalf("expected runtime-only JSON presence to be stripped, have %s", encoded)
	}
	if _, ok := raw["daoForkBlock"]; !ok {
		t.Fatalf("expected declared daoForkBlock to remain present, have %s", encoded)
	}
}

func TestChainConfigUnmarshalJSONResetsRuntimeOnlyMetadata(t *testing.T) {
	cfg := &ChainConfig{}
	cfg.SetBuiltInGenesisOverride(true)
	cfg.runtime.json.startInferredTracking()
	cfg.runtime.json.mark("homesteadBlock")

	raw := []byte(`{"chainId":51,"daoForkSupport":false,"ethash":{}}`)
	if err := json.Unmarshal(raw, cfg); err != nil {
		t.Fatalf("failed to unmarshal chain config: %v", err)
	}
	if cfg.hasBuiltInGenesisOverride() {
		t.Fatal("expected unmarshal to clear built-in genesis override marker")
	}
	if !cfg.runtime.json.tracked || !cfg.runtime.json.preserve {
		t.Fatalf("expected unmarshal to recapture JSON field presence, have %+v", cfg.runtime.json)
	}
	if cfg.runtime.json.isMissing("chainId", true) {
		t.Fatal("expected chainId presence to be captured from JSON")
	}
	if !cfg.runtime.json.isMissing("homesteadBlock", false) {
		t.Fatal("expected stale pre-unmarshal presence state to be discarded")
	}
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
		EIP1559Block:                big.NewInt(15),
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
		"EIP1559:",
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

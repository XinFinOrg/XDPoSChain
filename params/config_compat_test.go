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
	"reflect"
	"slices"
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
			stored: &ChainConfig{EIP1559Block: big.NewInt(10)},
			new:    &ChainConfig{EIP1559Block: big.NewInt(20)},
			head:   15,
			wantErr: &ConfigCompatError{
				What:         "EIP1559 fork block",
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
func TestCheckCompatibleRejectsXDCSystemContractAddressDrift(t *testing.T) {
	activationByField := map[string]chainConfigBigIntField{
		"TRC21IssuerSMC":         mustChainConfigForkBlockField(t, "TIPTRC21FeeBlock"),
		"XDCXListingSMC":         mustChainConfigForkBlockField(t, "TIPXDCXBlock"),
		"RelayerRegistrationSMC": mustChainConfigForkBlockField(t, "TIPXDCXBlock"),
		"LendingRegistrationSMC": mustChainConfigForkBlockField(t, "TIPXDCXLendingBlock"),
	}

	coveredFields := make([]string, 0, len(chainConfigXDCSystemContractFields))
	for index, field := range chainConfigXDCSystemContractFields {
		activation, ok := activationByField[field.name]
		if !ok {
			t.Fatalf("missing compatibility activation mapping for %s", field.name)
		}
		coveredFields = append(coveredFields, field.name)

		t.Run(field.name, func(t *testing.T) {
			stored := &ChainConfig{}
			activation.set(stored, big.NewInt(10))
			newcfg := stored.Clone()
			newAddress := common.BigToAddress(big.NewInt(int64(index + 1)))
			field.set(newcfg, newAddress)
			storedAddress := field.get(stored)

			assert.Nil(t, stored.CheckCompatible(newcfg, 9))
			err := stored.CheckCompatible(newcfg, 10)
			assert.Equal(t, &ConfigCompatError{
				What:         field.name,
				StoredConfig: big.NewInt(10),
				NewConfig:    big.NewInt(10),
				StoredValue:  storedAddress.Hex(),
				NewValue:     newAddress.Hex(),
				RewindTo:     9,
			}, err)
			assert.Contains(t, err.Error(), storedAddress.Hex())
			assert.Contains(t, err.Error(), newAddress.Hex())
		})
	}

	slices.Sort(coveredFields)
	assert.Equal(t, []string{
		"LendingRegistrationSMC",
		"RelayerRegistrationSMC",
		"TRC21IssuerSMC",
		"XDCXListingSMC",
	}, coveredFields)
}

func TestChainConfigXDCSystemContractFieldsCoverTopLevelAddresses(t *testing.T) {
	typ := reflect.TypeOf(ChainConfig{})
	expected := make([]string, 0, typ.NumField())
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if !field.IsExported() || field.Type != reflect.TypeOf(common.Address{}) {
			continue
		}
		expected = append(expected, field.Name)
	}
	slices.Sort(expected)

	got := make([]string, 0, len(chainConfigXDCSystemContractFields))
	for _, field := range chainConfigXDCSystemContractFields {
		if field.compat == nil {
			t.Fatalf("missing compatibility activation getter for %s", field.name)
		}
		got = append(got, field.name)
	}
	slices.Sort(got)

	assert.Equal(t, expected, got)
}

func mustChainConfigForkBlockField(t *testing.T, name string) chainConfigBigIntField {
	t.Helper()
	field, ok := chainConfigForkBlockFieldByName(name)
	if !ok {
		t.Fatalf("missing fork block field descriptor %s", name)
	}
	return field
}

func TestCheckCompatibleRejectsXDPoSV2SwitchEpochDrift(t *testing.T) {
	stored := &ChainConfig{
		XDPoS: &XDPoSConfig{
			V2: &V2{
				SwitchEpoch: 1,
				SwitchBlock: big.NewInt(900),
			},
		},
	}
	newcfg := stored.Clone()
	newcfg.XDPoS.V2.SwitchEpoch = 2

	assert.Nil(t, stored.CheckCompatible(newcfg, 899))
	assert.Equal(t, &ConfigCompatError{
		What:         "XDPoS.V2.SwitchEpoch",
		StoredConfig: big.NewInt(900),
		NewConfig:    big.NewInt(900),
		RewindTo:     899,
	}, stored.CheckCompatible(newcfg, 900))
	assert.False(t, V2Equal(stored.XDPoS.V2, newcfg.XDPoS.V2))
}
func TestCheckCompatibleXDPoSV2Schedule(t *testing.T) {
	t.Run("historical schedule drift uses supplied current round", func(t *testing.T) {
		stored := AllDevChainProtocolChanges.Clone()
		stored.XDPoS.V2.CurrentConfig = stored.XDPoS.V2.AllConfigs[0].Clone()

		newcfg := stored.Clone()
		newcfg.XDPoS.V2.AllConfigs[10].MaxMasternodes++
		newcfg.XDPoS.V2.CurrentConfig = newcfg.XDPoS.V2.AllConfigs[0].Clone()

		currentRound := uint64(10)
		assert.NotNil(t, stored.CheckCompatibleWithXDPoSRound(newcfg, 1000, &currentRound))
	})

	t.Run("future schedule drift after supplied current round is allowed", func(t *testing.T) {
		stored := AllDevChainProtocolChanges.Clone()
		stored.XDPoS.V2.CurrentConfig = stored.XDPoS.V2.AllConfigs[0].Clone()

		newcfg := stored.Clone()
		newcfg.XDPoS.V2.AllConfigs[900].MaxMasternodes++
		newcfg.XDPoS.V2.CurrentConfig = newcfg.XDPoS.V2.AllConfigs[0].Clone()

		currentRound := uint64(10)
		assert.Nil(t, stored.CheckCompatibleWithXDPoSRound(newcfg, 1000, &currentRound))
	})

	t.Run("historical timeout drift is allowed", func(t *testing.T) {
		stored := AllDevChainProtocolChanges.Clone()
		stored.XDPoS.V2.CurrentConfig = stored.XDPoS.V2.AllConfigs[10].Clone()

		newcfg := stored.Clone()
		newcfg.XDPoS.V2.AllConfigs[10].TimeoutPeriod++
		newcfg.XDPoS.V2.AllConfigs[10].TimeoutSyncThreshold++
		newcfg.XDPoS.V2.CurrentConfig = newcfg.XDPoS.V2.AllConfigs[10].Clone()

		assert.Nil(t, stored.CheckCompatible(newcfg, 1000))
	})

	t.Run("future schedule entry can be added", func(t *testing.T) {
		stored := AllDevChainProtocolChanges.Clone()
		stored.XDPoS.V2.CurrentConfig = stored.XDPoS.V2.AllConfigs[10].Clone()

		newcfg := stored.Clone()
		newcfg.XDPoS.V2.AllConfigs[1000] = &V2Config{
			MaxMasternodes:       99,
			SwitchRound:          1000,
			CertThreshold:        0.75,
			TimeoutSyncThreshold: 9,
			TimeoutPeriod:        99,
			MinePeriod:           7,
		}

		assert.Nil(t, stored.CheckCompatible(newcfg, 1000))
	})

	t.Run("historical operational drift fails", func(t *testing.T) {
		tests := []struct {
			name   string
			mutate func(*V2Config)
		}{
			{
				name: "mine period",
				mutate: func(cfg *V2Config) {
					cfg.MinePeriod++
				},
			},
			{
				name: "minimum signing tx",
				mutate: func(cfg *V2Config) {
					cfg.MinimumSigningTx++
				},
			},
			{
				name: "masternode reward",
				mutate: func(cfg *V2Config) {
					cfg.MasternodeReward += 0.01
				},
			},
		}

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				stored := AllDevChainProtocolChanges.Clone()
				stored.XDPoS.V2.CurrentConfig = stored.XDPoS.V2.AllConfigs[10].Clone()

				newcfg := stored.Clone()
				test.mutate(newcfg.XDPoS.V2.AllConfigs[10])
				newcfg.XDPoS.V2.CurrentConfig = newcfg.XDPoS.V2.AllConfigs[10].Clone()

				assert.NotNil(t, stored.CheckCompatible(newcfg, 1000))
			})
		}
	})

	t.Run("future schedule drift on existing entry is allowed", func(t *testing.T) {
		stored := AllDevChainProtocolChanges.Clone()
		stored.XDPoS.V2.CurrentConfig = stored.XDPoS.V2.AllConfigs[10].Clone()

		newcfg := stored.Clone()
		newcfg.XDPoS.V2.AllConfigs[900].MaxMasternodes++

		assert.Nil(t, stored.CheckCompatible(newcfg, 1000))
	})

	t.Run("historical consensus drift still fails", func(t *testing.T) {
		stored := AllDevChainProtocolChanges.Clone()
		stored.XDPoS.V2.CurrentConfig = stored.XDPoS.V2.AllConfigs[10].Clone()

		newcfg := stored.Clone()
		newcfg.XDPoS.V2.AllConfigs[10].MaxMasternodes++
		newcfg.XDPoS.V2.CurrentConfig = newcfg.XDPoS.V2.AllConfigs[10].Clone()

		assert.NotNil(t, stored.CheckCompatible(newcfg, 1000))
	})

	t.Run("historical schedule entry removal fails", func(t *testing.T) {
		stored := AllDevChainProtocolChanges.Clone()
		stored.XDPoS.V2.CurrentConfig = stored.XDPoS.V2.AllConfigs[10].Clone()

		newcfg := stored.Clone()
		delete(newcfg.XDPoS.V2.AllConfigs, 10)
		newcfg.XDPoS.V2.CurrentConfig = newcfg.XDPoS.V2.AllConfigs[0].Clone()

		assert.NotNil(t, stored.CheckCompatible(newcfg, 1000))
	})
}
func TestV2ConsensusConfigEqualCoversConsensusFields(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*V2Config)
	}{
		{
			name: "max protector nodes",
			mutate: func(cfg *V2Config) {
				cfg.MaxProtectorNodes++
			},
		},
		{
			name: "max observer nodes",
			mutate: func(cfg *V2Config) {
				cfg.MaxObverserNodes++
			},
		},
		{
			name: "mine period",
			mutate: func(cfg *V2Config) {
				cfg.MinePeriod++
			},
		},
		{
			name: "masternode reward",
			mutate: func(cfg *V2Config) {
				cfg.MasternodeReward += 0.01
			},
		},
		{
			name: "protector reward",
			mutate: func(cfg *V2Config) {
				cfg.ProtectorReward += 0.01
			},
		},
		{
			name: "observer reward",
			mutate: func(cfg *V2Config) {
				cfg.ObserverReward += 0.01
			},
		},
		{
			name: "minimum miner block per epoch",
			mutate: func(cfg *V2Config) {
				cfg.MinimumMinerBlockPerEpoch++
			},
		},
		{
			name: "limit penalty epoch",
			mutate: func(cfg *V2Config) {
				cfg.LimitPenaltyEpoch++
			},
		},
		{
			name: "minimum signing tx",
			mutate: func(cfg *V2Config) {
				cfg.MinimumSigningTx++
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			base := AllDevChainProtocolChanges.XDPoS.V2.AllConfigs[10].Clone()
			mutated := base.Clone()
			test.mutate(mutated)

			assert.False(t, v2ConsensusConfigEqual(base, mutated))
		})
	}
}

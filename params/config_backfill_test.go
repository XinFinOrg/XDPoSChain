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
	"bytes"
	"encoding/json"
	"math/big"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	xdclog "github.com/XinFinOrg/XDPoSChain/log"
)

var builtInBackfillForkFieldJSONKeysForTests = BuiltInBackfillForkFieldJSONKeys()

func TestForEachChainConfigForkBlockCoversStandardAndXDCForks(t *testing.T) {
	got := make([]string, 0)
	ForEachChainConfigForkBlock(TestnetChainConfig, func(name string, _ *big.Int) {
		got = append(got, name)
	})

	want := []string{
		"HomesteadBlock",
		"DAOForkBlock",
		"EIP150Block",
		"EIP155Block",
		"EIP158Block",
		"ByzantiumBlock",
		"ConstantinopleBlock",
		"PetersburgBlock",
		"IstanbulBlock",
		"BerlinBlock",
		"LondonBlock",
		"MergeBlock",
		"ShanghaiBlock",
		"EIP1559Block",
		"CancunBlock",
		"PragueBlock",
		"OsakaBlock",
		"TIP2019Block",
		"TIPSigningBlock",
		"TIPRandomizeBlock",
		"TIPIncreaseMasternodesBlock",
		"DenylistBlock",
		"TIPNoHalvingMNRewardBlock",
		"TIPXDCXBlock",
		"TIPXDCXLendingBlock",
		"TIPXDCXCancellationFeeBlock",
		"TIPTRC21FeeBlock",
		"Gas50xBlock",
		"TIPXDCXMinerDisableBlock",
		"TIPXDCXReceiverDisableBlock",
		"DynamicGasLimitBlock",
		"TIPUpgradeRewardBlock",
		"TIPUpgradePenaltyBlock",
		"TIPEpochHalvingBlock",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected unified fork field order:\nhave=%v\nwant=%v", got, want)
	}
}

func TestForEachChainConfigForkOrderBlockCoversValidationOrder(t *testing.T) {
	got := make([]string, 0)
	ForEachChainConfigForkOrderBlock(TestnetChainConfig, func(name string, _ *big.Int, _ bool) {
		got = append(got, name)
	})

	want := []string{
		"HomesteadBlock",
		"TIP2019Block",
		"DAOForkBlock",
		"EIP150Block",
		"EIP155Block",
		"EIP158Block",
		"ByzantiumBlock",
		"ConstantinopleBlock",
		"PetersburgBlock",
		"IstanbulBlock",
		"TIPSigningBlock",
		"TIPRandomizeBlock",
		"TIPIncreaseMasternodesBlock",
		"DenylistBlock",
		"TIPNoHalvingMNRewardBlock",
		"TIPXDCXBlock",
		"TIPXDCXLendingBlock",
		"TIPXDCXCancellationFeeBlock",
		"TIPTRC21FeeBlock",
		"BerlinBlock",
		"LondonBlock",
		"MergeBlock",
		"ShanghaiBlock",
		"TIPXDCXMinerDisableBlock",
		"TIPXDCXReceiverDisableBlock",
		"EIP1559Block",
		"CancunBlock",
		"PragueBlock",
		"OsakaBlock",
		"DynamicGasLimitBlock",
		"TIPUpgradeRewardBlock",
		"TIPUpgradePenaltyBlock",
		"TIPEpochHalvingBlock",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected fork validation order:\nhave=%v\nwant=%v", got, want)
	}
}

func TestForEachChainConfigForkOrderBlockMarksTIPTRC21FeeBlockOptional(t *testing.T) {
	tests := []struct {
		name string
		cfg  *ChainConfig
	}{
		{
			name: "nil block",
			cfg:  &ChainConfig{},
		},
		{
			name: "configured block",
			cfg: &ChainConfig{
				TIPTRC21FeeBlock: big.NewInt(1),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			found := false
			ForEachChainConfigForkOrderBlock(test.cfg, func(name string, _ *big.Int, optional bool) {
				if name != "TIPTRC21FeeBlock" {
					return
				}
				found = true
				if !optional {
					t.Fatalf("expected TIPTRC21FeeBlock to be marked optional")
				}
			})
			if !found {
				t.Fatal("TIPTRC21FeeBlock not found in fork order iteration")
			}
		})
	}
}

func TestForEachChainConfigForkOrderSpecialCaseRuleCoversGas50xConstraints(t *testing.T) {
	type rule struct {
		before string
		after  string
	}
	got := make([]rule, 0)
	ForEachChainConfigForkOrderSpecialCaseRule(func(before, after string) {
		got = append(got, rule{before: before, after: after})
	})

	want := []rule{
		{before: "TIPTRC21FeeBlock", after: "Gas50xBlock"},
		{before: "Gas50xBlock", after: "TIPXDCXMinerDisableBlock"},
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected fork validation special-case rules:\nhave=%v\nwant=%v", got, want)
	}
}

func TestChainConfigTopLevelFieldDescriptorsCoverStructJSONTags(t *testing.T) {
	typ := reflect.TypeOf(ChainConfig{})
	expected := make([]string, 0, typ.NumField())
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if !field.IsExported() {
			continue
		}
		jsonTag := field.Tag.Get("json")
		if jsonTag == "" || jsonTag == "-" {
			continue
		}
		expected = append(expected, strings.Split(jsonTag, ",")[0])
	}
	slices.Sort(expected)
	expected = slices.Compact(expected)

	got := chainConfigTopLevelFieldJSONKeys()
	slices.Sort(got)

	if !reflect.DeepEqual(got, expected) {
		t.Fatalf("expected top-level ChainConfig field descriptors %v, got %v", expected, got)
	}
}

// TestRequiresXDCForkConfigUsesAuthoritativeFieldList tests requires xd c fork config uses authoritative field list.
func TestRequiresXDCForkConfigUsesAuthoritativeFieldList(t *testing.T) {
	for _, field := range chainConfigXDCForkBlockFields {
		cfg := &ChainConfig{}
		field.set(cfg, big.NewInt(1))
		if !cfg.requiresXDCForkConfig() {
			t.Fatalf("expected requiresXDCForkConfig to detect %s (%s)", field.name, field.jsonKey)
		}
	}

	for _, field := range chainConfigXDCSystemContractFields {
		cfg := &ChainConfig{}
		field.set(cfg, common.HexToAddress("0x1"))
		if !cfg.requiresXDCForkConfig() {
			t.Fatalf("expected requiresXDCForkConfig to detect %s (%s)", field.name, field.jsonKey)
		}
	}
}

// TestBackfillFieldJSONKeySetsSeparateBuiltInAndCustomScopes tests backfill field json key sets separate built in and custom scopes.
func TestBackfillFieldJSONKeySetsSeparateBuiltInAndCustomScopes(t *testing.T) {
	builtInKeys := append([]string(nil), builtInBackfillForkFieldJSONKeysForTests...)
	customKeys := append([]string(nil), customBackfillForkFieldJSONKeys...)
	if len(builtInKeys) == 0 {
		t.Fatal("expected built-in backfill key set")
	}
	if len(customKeys) == 0 {
		t.Fatal("expected custom backfill key set")
	}
	if !slices.Contains(builtInKeys, "eip1559Block") {
		t.Fatalf("expected built-in backfill keys to include later fork field eip1559Block, have %v", builtInKeys)
	}
	if slices.Contains(customKeys, "eip1559Block") {
		t.Fatalf("expected custom backfill keys to exclude later fork field eip1559Block, have %v", customKeys)
	}
	if !slices.Contains(customKeys, "gas50xBlock") {
		t.Fatalf("expected custom backfill keys to include migrated field gas50xBlock, have %v", customKeys)
	}
	for _, key := range customKeys {
		if !slices.Contains(builtInKeys, key) {
			t.Fatalf("expected custom backfill key %q to also exist in built-in key set", key)
		}
	}
}

// TestV2SwitchEpochHasExplicitJSONTag tests v 2 switch epoch has explicit json tag.
func TestV2SwitchEpochHasExplicitJSONTag(t *testing.T) {
	field, ok := reflect.TypeOf(V2{}).FieldByName("SwitchEpoch")
	if !ok {
		t.Fatal("expected V2.SwitchEpoch field")
	}
	if got := field.Tag.Get("json"); got != "switchEpoch" {
		t.Fatalf("unexpected json tag: have %q want %q", got, "switchEpoch")
	}
}

// TestBackfillMissingFieldsFromPreservesLowercaseSwitchEpoch tests backfill missing fields from preserves lowercase switch epoch.
func TestBackfillMissingFieldsFromPreservesLowercaseSwitchEpoch(t *testing.T) {
	var cfg ChainConfig
	raw := []byte(`{"chainId":9999,"tipTRC21FeeBlock":0,"XDPoS":{"maxMasternodesV2":108,"v2":{"switchEpoch":7,"switchBlock":900,"config":{"maxMasternodes":7}}}}`)
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("failed to unmarshal chain config: %v", err)
	}

	source := &ChainConfig{
		XDPoS: &XDPoSConfig{
			MaxMasternodesV2: 108,
			V2: &V2{
				SwitchEpoch: 9,
				SwitchBlock: big.NewInt(900),
				CurrentConfig: &V2Config{
					MaxMasternodes: 25,
					SwitchRound:    9,
				},
			},
		},
	}

	hydrated := cfg.BackfillMissingFieldsFrom(source)
	if hydrated == nil || hydrated.XDPoS == nil || hydrated.XDPoS.V2 == nil {
		t.Fatalf("expected hydrated V2 config, have %v", hydrated)
	}
	if hydrated.XDPoS.V2.SwitchEpoch != 7 {
		t.Fatalf("expected explicit lowercase switchEpoch to be preserved, have %d want %d", hydrated.XDPoS.V2.SwitchEpoch, 7)
	}
}

// TestBackfillMissingFieldsFromPreservesExplicitNull tests backfill missing fields from preserves explicit null.
func TestBackfillMissingFieldsFromPreservesExplicitNull(t *testing.T) {
	var cfg ChainConfig
	raw := []byte(`{"chainId":51,"tipTRC21FeeBlock":1,"eip1559Block":null,"ethash":{}}`)
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("failed to unmarshal chain config: %v", err)
	}

	hydrated := cfg.BackfillMissingFieldsFrom(TestnetChainConfig)
	if hydrated == nil {
		t.Fatal("expected hydrated config")
	}
	if hydrated.EIP1559Block != nil {
		t.Fatalf("expected explicit null eip1559Block to remain nil, have %v", hydrated.EIP1559Block)
	}
	if hydrated.BerlinBlock == nil || hydrated.BerlinBlock.Cmp(TestnetChainConfig.BerlinBlock) != 0 {
		t.Fatalf("expected omitted berlinBlock to be backfilled from source, have %v want %v", hydrated.BerlinBlock, TestnetChainConfig.BerlinBlock)
	}
	if cfg.EIP1559Block != nil {
		t.Fatalf("expected original config to remain unchanged, have %v", cfg.EIP1559Block)
	}
}

// TestBackfillMissingFieldsFromBackfillsMissingPragueBlockFromBuiltInSource tests backfill missing fields from backfills missing prague block from built-in source.
func TestBackfillMissingFieldsFromBackfillsMissingPragueBlockFromBuiltInSource(t *testing.T) {
	var cfg ChainConfig
	raw := []byte(`{"chainId":5551,"tipTRC21FeeBlock":0,"ethash":{}}`)
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("failed to unmarshal chain config: %v", err)
	}

	hydrated := cfg.BackfillMissingFieldsFrom(DevnetChainConfig)
	if hydrated == nil {
		t.Fatal("expected hydrated config")
	}
	if hydrated.PragueBlock == nil || hydrated.PragueBlock.Cmp(DevnetChainConfig.PragueBlock) != 0 {
		t.Fatalf("expected omitted pragueBlock to be backfilled from source, have %v want %v", hydrated.PragueBlock, DevnetChainConfig.PragueBlock)
	}
	if hydrated.DynamicGasLimitBlock == nil || hydrated.DynamicGasLimitBlock.Cmp(DevnetChainConfig.DynamicGasLimitBlock) != 0 {
		t.Fatalf("expected omitted dynamicGasLimitBlock to be backfilled from source, have %v want %v", hydrated.DynamicGasLimitBlock, DevnetChainConfig.DynamicGasLimitBlock)
	}
	if cfg.PragueBlock != nil {
		t.Fatalf("expected original config to remain unchanged, have %v", cfg.PragueBlock)
	}
}

// TestBackfillMissingFieldsFromPreservesExplicitNullPragueBlock tests backfill missing fields from preserves explicit null prague block.
func TestBackfillMissingFieldsFromPreservesExplicitNullPragueBlock(t *testing.T) {
	var cfg ChainConfig
	raw := []byte(`{"chainId":5551,"tipTRC21FeeBlock":0,"pragueBlock":null,"ethash":{}}`)
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("failed to unmarshal chain config: %v", err)
	}

	hydrated := cfg.BackfillMissingFieldsFrom(DevnetChainConfig)
	if hydrated == nil {
		t.Fatal("expected hydrated config")
	}
	if hydrated.PragueBlock != nil {
		t.Fatalf("expected explicit null pragueBlock to remain nil, have %v", hydrated.PragueBlock)
	}
	if hydrated.DynamicGasLimitBlock == nil || hydrated.DynamicGasLimitBlock.Cmp(DevnetChainConfig.DynamicGasLimitBlock) != 0 {
		t.Fatalf("expected omitted dynamicGasLimitBlock to be backfilled from source, have %v want %v", hydrated.DynamicGasLimitBlock, DevnetChainConfig.DynamicGasLimitBlock)
	}
}

// TestChainConfigMarshalJSONPreservesExplicitZeroValueFields tests chain config marshal json preserves explicit zero value fields.
func TestChainConfigMarshalJSONPreservesExplicitZeroValueFields(t *testing.T) {
	var cfg ChainConfig
	raw := []byte(`{"chainId":51,"tipTRC21FeeBlock":1,"eip1559Block":null,"daoForkSupport":false,"trc21IssuerSMC":"0x0000000000000000000000000000000000000000","ethash":{}}`)
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("failed to unmarshal chain config: %v", err)
	}

	marshaled, err := json.Marshal(&cfg)
	if err != nil {
		t.Fatalf("failed to marshal chain config: %v", err)
	}
	var persistedRaw map[string]json.RawMessage
	if err := json.Unmarshal(marshaled, &persistedRaw); err != nil {
		t.Fatalf("failed to inspect marshaled chain config: %v", err)
	}
	for _, key := range []string{"eip1559Block", "daoForkSupport", "trc21IssuerSMC"} {
		if _, ok := persistedRaw[key]; !ok {
			t.Fatalf("expected marshaled chain config to preserve %s, have %s", key, marshaled)
		}
	}

	var persisted ChainConfig
	if err := json.Unmarshal(marshaled, &persisted); err != nil {
		t.Fatalf("failed to unmarshal persisted chain config: %v", err)
	}
	source := TestnetChainConfig.Clone()
	source.DAOForkSupport = true
	source.TRC21IssuerSMC = common.HexToAddress("0x1111111111111111111111111111111111111111")
	hydrated := persisted.BackfillMissingFieldsFrom(source)
	if hydrated == nil {
		t.Fatal("expected hydrated config")
	}
	if hydrated.EIP1559Block != nil {
		t.Fatalf("expected explicit null eip1559Block to survive round-trip, have %v", hydrated.EIP1559Block)
	}
	if hydrated.DAOForkSupport {
		t.Fatal("expected explicit false daoForkSupport to survive round-trip")
	}
	if hydrated.TRC21IssuerSMC != (common.Address{}) {
		t.Fatalf("expected explicit zero trc21IssuerSMC to survive round-trip, have %s", hydrated.TRC21IssuerSMC.Hex())
	}
	if hydrated.BerlinBlock == nil || hydrated.BerlinBlock.Cmp(source.BerlinBlock) != 0 {
		t.Fatalf("expected omitted berlinBlock to be backfilled from source, have %v want %v", hydrated.BerlinBlock, source.BerlinBlock)
	}
}

// TestChainConfigMarshalJSONRoundTripPreservesPresenceKeyNames tests chain config marshal json round trip preserves tracked key names.
func TestChainConfigMarshalJSONRoundTripPreservesPresenceKeyNames(t *testing.T) {
	raw := []byte(`{"chainId":51,"tipTRC21FeeBlock":1,"XDPoS":{"period":2,"epoch":900,"maxMasternodesV2":108,"SkipV1Validation":false,"v2":{"switchEpoch":8,"switchBlock":900,"config":{"maxMasternodes":108}}}}`)

	var cfg ChainConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("failed to unmarshal chain config: %v", err)
	}
	encoded, err := json.Marshal(&cfg)
	if err != nil {
		t.Fatalf("failed to marshal chain config: %v", err)
	}

	var persistedRaw map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &persistedRaw); err != nil {
		t.Fatalf("failed to inspect marshaled chain config: %v", err)
	}
	for _, key := range []string{"chainId", "tipTRC21FeeBlock", "XDPoS"} {
		if _, ok := persistedRaw[key]; !ok {
			t.Fatalf("expected marshaled chain config to preserve %s, have %s", key, encoded)
		}
	}
	for _, key := range []string{"jsonPresence", "jsonPresenceTracked", "customBuiltInOverride"} {
		if _, ok := persistedRaw[key]; ok {
			t.Fatalf("unexpected internal key %s in marshaled chain config: %s", key, encoded)
		}
	}

	var xdpRaw map[string]json.RawMessage
	if err := json.Unmarshal(persistedRaw["XDPoS"], &xdpRaw); err != nil {
		t.Fatalf("failed to inspect marshaled XDPoS config: %v", err)
	}
	for _, key := range []string{"period", "epoch", "maxMasternodesV2", "v2"} {
		if _, ok := xdpRaw[key]; !ok {
			t.Fatalf("expected marshaled XDPoS config to preserve %s, have %s", key, persistedRaw["XDPoS"])
		}
	}
	if _, ok := xdpRaw["jsonPresence"]; ok {
		t.Fatalf("unexpected internal jsonPresence key in marshaled XDPoS config: %s", persistedRaw["XDPoS"])
	}
	if _, ok := xdpRaw["jsonPresenceTracked"]; ok {
		t.Fatalf("unexpected internal jsonPresenceTracked key in marshaled XDPoS config: %s", persistedRaw["XDPoS"])
	}
}

// TestChainConfigMarshalJSONPreserveModeIsIdempotent tests chain config marshal json preserve mode is idempotent.
func TestChainConfigMarshalJSONPreserveModeIsIdempotent(t *testing.T) {
	raw := []byte(`{"chainId":51,"tipTRC21FeeBlock":1,"eip1559Block":null,"daoForkSupport":false,"trc21IssuerSMC":"0x0000000000000000000000000000000000000000","ethash":{}}`)

	var cfg ChainConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("failed to unmarshal initial chain config: %v", err)
	}
	if !cfg.runtime.json.preserve {
		t.Fatal("expected captured JSON field presence to enable preserve mode")
	}

	first, err := json.Marshal(&cfg)
	if err != nil {
		t.Fatalf("failed first marshal: %v", err)
	}

	var roundTripped ChainConfig
	if err := json.Unmarshal(first, &roundTripped); err != nil {
		t.Fatalf("failed to unmarshal first marshaled output: %v", err)
	}
	if !roundTripped.runtime.json.preserve {
		t.Fatal("expected round-tripped config to keep preserve mode enabled")
	}

	second, err := json.Marshal(&roundTripped)
	if err != nil {
		t.Fatalf("failed second marshal: %v", err)
	}

	if !bytes.Equal(first, second) {
		t.Fatalf("expected preserve-mode marshal to be idempotent, first=%s second=%s", first, second)
	}
}

// TestBackfillMissingFieldsFromUsesFallbackWhenPresenceUnavailable tests backfill missing fields from uses fallback when presence unavailable.
func TestBackfillMissingFieldsFromUsesFallbackWhenPresenceUnavailable(t *testing.T) {
	cfg := &ChainConfig{
		ChainID:          big.NewInt(51),
		TIPTRC21FeeBlock: big.NewInt(1),
		Ethash:           new(EthashConfig),
	}

	hydrated := cfg.BackfillMissingFieldsFrom(TestnetChainConfig)
	if hydrated == nil {
		t.Fatal("expected hydrated config")
	}
	if hydrated == cfg {
		t.Fatal("expected BackfillMissingFieldsFrom to return a clone")
	}
	if hydrated.EIP1559Block == nil || hydrated.EIP1559Block.Cmp(TestnetChainConfig.EIP1559Block) != 0 {
		t.Fatalf("expected eip1559Block to be backfilled from source, have %v want %v", hydrated.EIP1559Block, TestnetChainConfig.EIP1559Block)
	}
	if cfg.EIP1559Block != nil {
		t.Fatalf("expected original config to remain unchanged, have %v", cfg.EIP1559Block)
	}
	if hydrated.ChainID == nil || hydrated.ChainID.Cmp(cfg.ChainID) != 0 {
		t.Fatalf("expected declared chainId to be preserved, have %v want %v", hydrated.ChainID, cfg.ChainID)
	}
}

// TestBackfillMissingFieldsFromUsesLocalnetSource tests backfill missing fields from uses localnet source.
func TestBackfillMissingFieldsFromUsesLocalnetSource(t *testing.T) {
	cfg := &ChainConfig{
		ChainID:          big.NewInt(7777),
		TIPTRC21FeeBlock: big.NewInt(1),
		Ethash:           new(EthashConfig),
	}

	hydrated := cfg.BackfillMissingFieldsFrom(LocalnetChainConfig)
	if hydrated == nil {
		t.Fatal("expected hydrated config")
	}
	if hydrated.BerlinBlock == nil || hydrated.BerlinBlock.Cmp(LocalnetChainConfig.BerlinBlock) != 0 {
		t.Fatalf("expected berlinBlock to be backfilled from LocalnetChainConfig, have %v want %v", hydrated.BerlinBlock, LocalnetChainConfig.BerlinBlock)
	}
	if hydrated.ChainID == nil || hydrated.ChainID.Cmp(cfg.ChainID) != 0 {
		t.Fatalf("expected declared chainId to be preserved, have %v want %v", hydrated.ChainID, cfg.ChainID)
	}
}

// TestBackfillMissingFieldsFromWarnsOnCustomLocalnetFallback tests backfill missing fields from warns on custom localnet fallback.
func TestBackfillMissingFieldsFromWarnsOnCustomLocalnetFallback(t *testing.T) {
	prevLog := xdclog.Root()
	defer xdclog.SetDefault(prevLog)

	out := new(bytes.Buffer)
	glog := xdclog.NewGlogHandler(xdclog.NewTerminalHandlerWithLevel(out, xdclog.LevelWarn, false))
	glog.Verbosity(xdclog.LevelWarn)
	xdclog.SetDefault(xdclog.NewLogger(glog))

	cfg := &ChainConfig{
		ChainID:          big.NewInt(7777),
		TIPTRC21FeeBlock: big.NewInt(1),
		Ethash:           new(EthashConfig),
	}

	hydrated := cfg.BackfillMissingFieldsFrom(LocalnetChainConfig)
	if hydrated == nil {
		t.Fatal("expected hydrated config")
	}

	have := out.String()
	if !strings.Contains(have, "Custom chain config used Localnet fallback defaults") {
		t.Fatalf("expected custom localnet fallback warning, have %q", have)
	}
	for _, field := range []string{"berlinBlock", "eip1559Block"} {
		if !strings.Contains(have, field) {
			t.Fatalf("expected warning to mention %s, have %q", field, have)
		}
	}
}

// TestBackfillMissingFieldsFromDoesNotInjectXDPoSIntoEthashConfig tests backfill missing fields from does not inject xd po s into ethash config.
func TestBackfillMissingFieldsFromDoesNotInjectXDPoSIntoEthashConfig(t *testing.T) {
	cfg := &ChainConfig{
		ChainID:          big.NewInt(7778),
		TIPTRC21FeeBlock: big.NewInt(0),
		Ethash:           new(EthashConfig),
	}

	hydrated := cfg.BackfillMissingFieldsFrom(LocalnetChainConfig)
	if hydrated == nil {
		t.Fatal("expected hydrated config")
	}
	if hydrated.XDPoS != nil {
		t.Fatalf("expected ethash config to keep XDPoS nil, have %v", hydrated.XDPoS)
	}
	if hydrated.Ethash == nil {
		t.Fatal("expected ethash config to be preserved")
	}
	if cfg.XDPoS != nil {
		t.Fatalf("expected original config to remain unchanged, have %v", cfg.XDPoS)
	}
}

// TestBackfillMissingConsensusConfigsFromMaintainsMutualExclusion tests backfill missing consensus configs from maintains mutual exclusion.
func TestBackfillMissingConsensusConfigsFromMaintainsMutualExclusion(t *testing.T) {
	tests := []struct {
		name string
		dest *ChainConfig
		src  *ChainConfig
		want func(*testing.T, *ChainConfig)
	}{
		{
			name: "backfills ethash when others absent",
			dest: &ChainConfig{},
			src:  &ChainConfig{Ethash: new(EthashConfig)},
			want: func(t *testing.T, got *ChainConfig) {
				if got.Ethash == nil {
					t.Fatal("expected ethash to be backfilled")
				}
				if got.Clique != nil || got.XDPoS != nil {
					t.Fatalf("expected only ethash to be populated, have clique=%v xdpos=%v", got.Clique, got.XDPoS)
				}
			},
		},
		{
			name: "backfills clique when others absent",
			dest: &ChainConfig{},
			src:  &ChainConfig{Clique: &CliqueConfig{Period: 5, Epoch: 10}},
			want: func(t *testing.T, got *ChainConfig) {
				if got.Clique == nil || got.Clique.Period != 5 || got.Clique.Epoch != 10 {
					t.Fatalf("expected clique to be backfilled, have %#v", got.Clique)
				}
				if got.Ethash != nil || got.XDPoS != nil {
					t.Fatalf("expected only clique to be populated, have ethash=%v xdpos=%v", got.Ethash, got.XDPoS)
				}
			},
		},
		{
			name: "does not backfill xdpos when ethash already set",
			dest: &ChainConfig{Ethash: new(EthashConfig)},
			src: &ChainConfig{XDPoS: &XDPoSConfig{
				Period: 2,
			}},
			want: func(t *testing.T, got *ChainConfig) {
				if got.XDPoS != nil {
					t.Fatalf("expected xdpos to remain nil when ethash is present, have %#v", got.XDPoS)
				}
				if got.Ethash == nil {
					t.Fatal("expected ethash to remain set")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dest := tt.dest.Clone()
			dest.backfillMissingConsensusConfigsFrom(tt.src)
			tt.want(t, dest)
		})
	}
}

// TestIsBuiltInTestNetworkRejectsLargeChainIDOverflow tests the built-in test
// network shortcut does not accept chain IDs that only equal 1337 after Uint64
// truncation.
func TestIsBuiltInTestNetworkRejectsLargeChainIDOverflow(t *testing.T) {
	largeChainID := new(big.Int).Lsh(big.NewInt(1), 64)
	largeChainID.Add(largeChainID, big.NewInt(1337))
	if isBuiltInTestNetwork(largeChainID) {
		t.Fatalf("expected large chain ID %v to not be treated as a built-in test network", largeChainID)
	}
}

func TestBuiltInTestConfigsUseConsensusOptionalTestChainID(t *testing.T) {
	want := new(big.Int).SetUint64(ConsensusOptionalTestChainID)
	configs := []struct {
		name string
		cfg  *ChainConfig
	}{
		{name: "AllEthashProtocolChanges", cfg: AllEthashProtocolChanges},
		{name: "AllDevChainProtocolChanges", cfg: AllDevChainProtocolChanges},
		{name: "AllCliqueProtocolChanges", cfg: AllCliqueProtocolChanges},
		{name: "TestXDPoSMockChainConfig", cfg: TestXDPoSMockChainConfig},
	}

	for _, tt := range configs {
		t.Run(tt.name, func(t *testing.T) {
			if tt.cfg == nil || tt.cfg.ChainID == nil {
				t.Fatalf("expected chain config with chain ID, have %v", tt.cfg)
			}
			if tt.cfg.ChainID.Cmp(want) != 0 {
				t.Fatalf("unexpected chain ID: have %v want %v", tt.cfg.ChainID, want)
			}
		})
	}

	if !isBuiltInTestNetwork(new(big.Int).SetUint64(ConsensusOptionalTestChainID)) {
		t.Fatalf("expected chain ID %d to be treated as a built-in test network", ConsensusOptionalTestChainID)
	}
}

// TestBackfillMissingFieldsFromNilSourceReturnsClone tests backfill missing fields from nil source returns clone.
func TestBackfillMissingFieldsFromNilSourceReturnsClone(t *testing.T) {
	cfg := &ChainConfig{
		ChainID:          big.NewInt(5151),
		TIPTRC21FeeBlock: big.NewInt(0),
		Ethash:           new(EthashConfig),
		BerlinBlock:      big.NewInt(123),
	}

	hydrated := cfg.BackfillMissingFieldsFrom(nil)
	if hydrated == nil {
		t.Fatal("expected hydrated config")
	}
	if hydrated == cfg {
		t.Fatal("expected clone when source is nil")
	}
	if hydrated.BerlinBlock == nil || hydrated.BerlinBlock.Cmp(cfg.BerlinBlock) != 0 {
		t.Fatalf("expected berlinBlock to be preserved, have %v want %v", hydrated.BerlinBlock, cfg.BerlinBlock)
	}
	hydrated.BerlinBlock = big.NewInt(456)
	if cfg.BerlinBlock.Cmp(big.NewInt(123)) != 0 {
		t.Fatalf("expected original config to remain unchanged, have %v want %v", cfg.BerlinBlock, big.NewInt(123))
	}
}

// TestBackfillMissingFieldsFromBackfillsXDPoSMaxMasternodesV2 tests backfill missing fields from backfills xd po s max masternodes v 2.
func TestBackfillMissingFieldsFromBackfillsXDPoSMaxMasternodesV2(t *testing.T) {
	cfg := &ChainConfig{
		ChainID:          big.NewInt(8888),
		TIPTRC21FeeBlock: big.NewInt(0),
		XDPoS: &XDPoSConfig{
			Period:           2,
			Epoch:            900,
			Reward:           5000,
			RewardCheckpoint: 900,
			Gap:              450,
			MaxMasternodesV2: 0,
		},
	}
	source := &ChainConfig{
		XDPoS: &XDPoSConfig{MaxMasternodesV2: 123},
	}

	hydrated := cfg.BackfillMissingFieldsFrom(source)
	if hydrated == nil || hydrated.XDPoS == nil {
		t.Fatalf("expected hydrated XDPoS config, have %v", hydrated)
	}
	if hydrated.XDPoS.MaxMasternodesV2 != 123 {
		t.Fatalf("expected MaxMasternodesV2 to be backfilled from source, have %d want %d", hydrated.XDPoS.MaxMasternodesV2, 123)
	}
	if cfg.XDPoS.MaxMasternodesV2 != 0 {
		t.Fatalf("expected original config to remain unchanged, have %d want %d", cfg.XDPoS.MaxMasternodesV2, 0)
	}
}

// TestBackfillMissingFieldsFromBackfillsMissingXDPoSFields tests backfill missing fields from backfills missing xd po s fields.
func TestBackfillMissingFieldsFromBackfillsMissingXDPoSFields(t *testing.T) {
	cfg := &ChainConfig{
		ChainID:          big.NewInt(9999),
		TIPTRC21FeeBlock: big.NewInt(0),
		XDPoS: &XDPoSConfig{
			Period:               0,
			Epoch:                0,
			Reward:               0,
			RewardCheckpoint:     0,
			Gap:                  0,
			FoundationWalletAddr: common.Address{},
			MaxMasternodesV2:     0,
			SkipV1Validation:     false,
			V2:                   nil,
		},
	}
	source := &ChainConfig{
		XDPoS: &XDPoSConfig{
			Period:               2,
			Epoch:                900,
			Reward:               5000,
			RewardCheckpoint:     900,
			Gap:                  450,
			FoundationWalletAddr: common.HexToAddress("0x00000000000000000000000000000000000000aa"),
			MaxMasternodesV2:     123,
			SkipV1Validation:     true,
			V2: &V2{
				SwitchEpoch: 7,
				SwitchBlock: big.NewInt(900),
				CurrentConfig: &V2Config{
					MaxMasternodes: 25,
					SwitchRound:    7,
				},
			},
		},
	}

	hydrated := cfg.BackfillMissingFieldsFrom(source)
	if hydrated == nil || hydrated.XDPoS == nil {
		t.Fatalf("expected hydrated XDPoS config, have %v", hydrated)
	}
	if hydrated.XDPoS.Period != source.XDPoS.Period {
		t.Fatalf("expected Period to be backfilled, have %d want %d", hydrated.XDPoS.Period, source.XDPoS.Period)
	}
	if hydrated.XDPoS.Epoch != source.XDPoS.Epoch {
		t.Fatalf("expected Epoch to be backfilled, have %d want %d", hydrated.XDPoS.Epoch, source.XDPoS.Epoch)
	}
	if hydrated.XDPoS.Reward != source.XDPoS.Reward {
		t.Fatalf("expected Reward to be backfilled, have %d want %d", hydrated.XDPoS.Reward, source.XDPoS.Reward)
	}
	if hydrated.XDPoS.RewardCheckpoint != source.XDPoS.RewardCheckpoint {
		t.Fatalf("expected RewardCheckpoint to be backfilled, have %d want %d", hydrated.XDPoS.RewardCheckpoint, source.XDPoS.RewardCheckpoint)
	}
	if hydrated.XDPoS.Gap != source.XDPoS.Gap {
		t.Fatalf("expected Gap to be backfilled, have %d want %d", hydrated.XDPoS.Gap, source.XDPoS.Gap)
	}
	if hydrated.XDPoS.FoundationWalletAddr != source.XDPoS.FoundationWalletAddr {
		t.Fatalf("expected FoundationWalletAddr to be backfilled, have %s want %s", hydrated.XDPoS.FoundationWalletAddr.Hex(), source.XDPoS.FoundationWalletAddr.Hex())
	}
	if hydrated.XDPoS.MaxMasternodesV2 != source.XDPoS.MaxMasternodesV2 {
		t.Fatalf("expected MaxMasternodesV2 to be backfilled, have %d want %d", hydrated.XDPoS.MaxMasternodesV2, source.XDPoS.MaxMasternodesV2)
	}
	if hydrated.XDPoS.SkipV1Validation != source.XDPoS.SkipV1Validation {
		t.Fatalf("expected SkipV1Validation to be backfilled, have %v want %v", hydrated.XDPoS.SkipV1Validation, source.XDPoS.SkipV1Validation)
	}
	if hydrated.XDPoS.V2 == nil {
		t.Fatal("expected V2 to be backfilled")
	}
	if hydrated.XDPoS.V2 == source.XDPoS.V2 {
		t.Fatal("expected V2 to be cloned, not aliased")
	}
	if cfg.XDPoS.V2 != nil {
		t.Fatalf("expected original config to remain unchanged, have %v", cfg.XDPoS.V2)
	}
}

// TestBackfillCustomMigratedFieldsFromUsesNarrowWhitelist tests backfill custom migrated fields from uses narrow whitelist.
func TestBackfillCustomMigratedFieldsFromUsesNarrowWhitelist(t *testing.T) {
	cfg := &ChainConfig{
		ChainID:          big.NewInt(9999),
		TIPTRC21FeeBlock: big.NewInt(0),
		XDPoS: &XDPoSConfig{
			Period:           2,
			Epoch:            900,
			Reward:           0,
			RewardCheckpoint: 900,
			Gap:              450,
			MaxMasternodesV2: 0,
		},
	}
	source := &ChainConfig{
		Gas50xBlock:    big.NewInt(123),
		BerlinBlock:    big.NewInt(456),
		EIP1559Block:   big.NewInt(789),
		TRC21IssuerSMC: common.HexToAddress("0x00000000000000000000000000000000000000aa"),
		XDPoS: &XDPoSConfig{
			Reward:           5000,
			MaxMasternodesV2: 77,
		},
	}

	hydrated := cfg.BackfillCustomMigratedFieldsFrom(source)
	if hydrated == nil || hydrated.XDPoS == nil {
		t.Fatalf("expected hydrated XDPoS config, have %v", hydrated)
	}
	if hydrated.Gas50xBlock == nil || hydrated.Gas50xBlock.Cmp(source.Gas50xBlock) != 0 {
		t.Fatalf("expected Gas50xBlock to be backfilled, have %v want %v", hydrated.Gas50xBlock, source.Gas50xBlock)
	}
	if hydrated.TRC21IssuerSMC != source.TRC21IssuerSMC {
		t.Fatalf("expected TRC21IssuerSMC to be backfilled, have %s want %s", hydrated.TRC21IssuerSMC.Hex(), source.TRC21IssuerSMC.Hex())
	}
	if hydrated.XDPoS.MaxMasternodesV2 != source.XDPoS.MaxMasternodesV2 {
		t.Fatalf("expected MaxMasternodesV2 to be backfilled, have %d want %d", hydrated.XDPoS.MaxMasternodesV2, source.XDPoS.MaxMasternodesV2)
	}
	if hydrated.BerlinBlock != nil {
		t.Fatalf("expected BerlinBlock to remain nil, have %v", hydrated.BerlinBlock)
	}
	if hydrated.EIP1559Block != nil {
		t.Fatalf("expected EIP1559Block to remain nil, have %v", hydrated.EIP1559Block)
	}
	if hydrated.XDPoS.Reward != 0 {
		t.Fatalf("expected Reward to remain unchanged, have %d want 0", hydrated.XDPoS.Reward)
	}
	if cfg.Gas50xBlock != nil {
		t.Fatalf("expected original config to remain unchanged, have %v", cfg.Gas50xBlock)
	}
}

// TestBackfillMissingFieldsFromBackfillsMissingXDPoSV2Fields tests backfill missing fields from backfills missing xd po sv 2 fields.
func TestBackfillMissingFieldsFromBackfillsMissingXDPoSV2Fields(t *testing.T) {
	var cfg ChainConfig
	raw := []byte(`{"chainId":9999,"tipTRC21FeeBlock":0,"XDPoS":{"maxMasternodesV2":108,"v2":{"config":{"maxMasternodes":7},"allConfigs":{"0":{"maxMasternodes":7}}}}}`)
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("failed to unmarshal chain config: %v", err)
	}

	source := &ChainConfig{
		XDPoS: &XDPoSConfig{
			MaxMasternodesV2: 108,
			V2: &V2{
				SwitchEpoch: 9,
				SwitchBlock: big.NewInt(900),
				CurrentConfig: &V2Config{
					MaxMasternodes:       25,
					SwitchRound:          9,
					TimeoutSyncThreshold: 3,
					TimeoutPeriod:        10,
					CertThreshold:        0.667,
				},
				AllConfigs: map[uint64]*V2Config{
					0: {
						MaxMasternodes:       25,
						SwitchRound:          0,
						TimeoutSyncThreshold: 3,
						TimeoutPeriod:        10,
						CertThreshold:        0.667,
					},
					9: {
						MaxMasternodes:       108,
						SwitchRound:          9,
						TimeoutSyncThreshold: 2,
						TimeoutPeriod:        30,
						CertThreshold:        0.45,
					},
				},
			},
		},
	}

	hydrated := cfg.BackfillMissingFieldsFrom(source)
	if hydrated == nil || hydrated.XDPoS == nil || hydrated.XDPoS.V2 == nil {
		t.Fatalf("expected hydrated V2 config, have %v", hydrated)
	}
	if hydrated.XDPoS.V2.SwitchEpoch != source.XDPoS.V2.SwitchEpoch {
		t.Fatalf("expected SwitchEpoch to be backfilled, have %d want %d", hydrated.XDPoS.V2.SwitchEpoch, source.XDPoS.V2.SwitchEpoch)
	}
	if hydrated.XDPoS.V2.SwitchBlock == nil || hydrated.XDPoS.V2.SwitchBlock.Cmp(source.XDPoS.V2.SwitchBlock) != 0 {
		t.Fatalf("expected SwitchBlock to be backfilled, have %v want %v", hydrated.XDPoS.V2.SwitchBlock, source.XDPoS.V2.SwitchBlock)
	}
	if hydrated.XDPoS.V2.CurrentConfig == nil {
		t.Fatal("expected CurrentConfig to be backfilled")
	}
	if hydrated.XDPoS.V2.CurrentConfig.MaxMasternodes != 7 {
		t.Fatalf("expected declared CurrentConfig.MaxMasternodes to be preserved, have %d want %d", hydrated.XDPoS.V2.CurrentConfig.MaxMasternodes, 7)
	}
	if hydrated.XDPoS.V2.CurrentConfig.TimeoutPeriod != source.XDPoS.V2.CurrentConfig.TimeoutPeriod {
		t.Fatalf("expected CurrentConfig.TimeoutPeriod to be backfilled, have %d want %d", hydrated.XDPoS.V2.CurrentConfig.TimeoutPeriod, source.XDPoS.V2.CurrentConfig.TimeoutPeriod)
	}
	if hydrated.XDPoS.V2.AllConfigs[0] == nil {
		t.Fatal("expected existing AllConfigs[0]")
	}
	if hydrated.XDPoS.V2.AllConfigs[0].MaxMasternodes != 7 {
		t.Fatalf("expected declared AllConfigs[0].MaxMasternodes to be preserved, have %d want %d", hydrated.XDPoS.V2.AllConfigs[0].MaxMasternodes, 7)
	}
	if hydrated.XDPoS.V2.AllConfigs[0].TimeoutPeriod != source.XDPoS.V2.AllConfigs[0].TimeoutPeriod {
		t.Fatalf("expected AllConfigs[0].TimeoutPeriod to be backfilled, have %d want %d", hydrated.XDPoS.V2.AllConfigs[0].TimeoutPeriod, source.XDPoS.V2.AllConfigs[0].TimeoutPeriod)
	}
	if hydrated.XDPoS.V2.AllConfigs[9] == nil {
		t.Fatal("expected missing AllConfigs[9] entry to be backfilled")
	}
	if hydrated.XDPoS.V2.AllConfigs[9] == source.XDPoS.V2.AllConfigs[9] {
		t.Fatal("expected AllConfigs[9] to be cloned, not aliased")
	}
}

// TestBackfillMissingFieldsFromPreservesExplicitZeroInXDPoSV2Config tests backfill missing fields from preserves explicit zero in xd po sv 2 config.
func TestBackfillMissingFieldsFromPreservesExplicitZeroInXDPoSV2Config(t *testing.T) {
	var cfg ChainConfig
	raw := []byte(`{"chainId":9999,"tipTRC21FeeBlock":0,"XDPoS":{"maxMasternodesV2":108,"v2":{"config":{"maxMasternodes":7,"switchRound":0}}}}`)
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("failed to unmarshal chain config: %v", err)
	}

	source := &ChainConfig{
		XDPoS: &XDPoSConfig{
			MaxMasternodesV2: 108,
			V2: &V2{
				CurrentConfig: &V2Config{
					MaxMasternodes:       25,
					SwitchRound:          9,
					TimeoutSyncThreshold: 3,
					TimeoutPeriod:        10,
				},
			},
		},
	}

	hydrated := cfg.BackfillMissingFieldsFrom(source)
	if hydrated == nil || hydrated.XDPoS == nil || hydrated.XDPoS.V2 == nil || hydrated.XDPoS.V2.CurrentConfig == nil {
		t.Fatalf("expected hydrated current config, have %v", hydrated)
	}
	if hydrated.XDPoS.V2.CurrentConfig.SwitchRound != 0 {
		t.Fatalf("expected explicit zero SwitchRound to be preserved, have %d want 0", hydrated.XDPoS.V2.CurrentConfig.SwitchRound)
	}
	if hydrated.XDPoS.V2.CurrentConfig.TimeoutPeriod != source.XDPoS.V2.CurrentConfig.TimeoutPeriod {
		t.Fatalf("expected missing TimeoutPeriod to be backfilled, have %d want %d", hydrated.XDPoS.V2.CurrentConfig.TimeoutPeriod, source.XDPoS.V2.CurrentConfig.TimeoutPeriod)
	}
}

// TestCloneWithInferredFieldPresencePreservesProgrammaticFalseXDPoSBool tests clone with inferred field presence preserves programmatic false xd po s bool.
func TestCloneForBackfillPreservesProgrammaticFalseXDPoSBool(t *testing.T) {
	cfg := (&ChainConfig{
		ChainID:          big.NewInt(5151),
		TIPTRC21FeeBlock: big.NewInt(0),
		XDPoS: &XDPoSConfig{
			Period:           2,
			SkipV1Validation: false,
		},
	}).CloneForBackfill()
	if cfg.XDPoS == nil || !cfg.XDPoS.json.tracked {
		t.Fatalf("expected CloneForBackfill to track XDPoS field presence, have %+v", cfg.XDPoS)
	}
	if _, ok := cfg.XDPoS.json.keys["SkipV1Validation"]; !ok {
		t.Fatalf("expected CloneForBackfill to preserve explicit false SkipV1Validation, have %+v", cfg.XDPoS.json.keys)
	}

	source := &ChainConfig{
		XDPoS: &XDPoSConfig{
			Period:           3,
			Gap:              450,
			MaxMasternodesV2: 108,
			SkipV1Validation: true,
		},
	}

	hydrated := cfg.BackfillMissingFieldsFrom(source)
	if hydrated == nil || hydrated.XDPoS == nil {
		t.Fatalf("expected hydrated XDPoS config, have %v", hydrated)
	}
	if hydrated.XDPoS.SkipV1Validation {
		t.Fatalf("expected explicit false SkipV1Validation to be preserved, tracked=%v keys=%v", hydrated.XDPoS.json.tracked, hydrated.XDPoS.json.keys)
	}
	if hydrated.XDPoS.Gap != source.XDPoS.Gap {
		t.Fatalf("expected missing Gap to be backfilled, have %d want %d", hydrated.XDPoS.Gap, source.XDPoS.Gap)
	}
	if hydrated.XDPoS.MaxMasternodesV2 != source.XDPoS.MaxMasternodesV2 {
		t.Fatalf("expected missing MaxMasternodesV2 to be backfilled, have %d want %d", hydrated.XDPoS.MaxMasternodesV2, source.XDPoS.MaxMasternodesV2)
	}
	if hydrated.XDPoS.Period != cfg.XDPoS.Period {
		t.Fatalf("expected explicit Period to be preserved, have %d want %d", hydrated.XDPoS.Period, cfg.XDPoS.Period)
	}
}

// TestXDPoSBackfillMissingScalarFieldsFromPreservesExplicitBool tests xd po s backfill missing scalar fields from preserves explicit bool.
func TestXDPoSBackfillMissingScalarFieldsFromPreservesExplicitBool(t *testing.T) {
	dest := &XDPoSConfig{
		Period:           2,
		SkipV1Validation: false,
		json: jsonFieldPresence{tracked: true, keys: map[string]struct{}{
			"period":           {},
			"SkipV1Validation": {},
		}},
	}
	src := &XDPoSConfig{
		Period:               3,
		Gap:                  450,
		FoundationWalletAddr: common.HexToAddress("0x00000000000000000000000000000000000000aa"),
		MaxMasternodesV2:     108,
		SkipV1Validation:     true,
	}

	dest.backfillMissingScalarFieldsFrom(src)

	if dest.SkipV1Validation {
		t.Fatal("expected explicit false SkipV1Validation to be preserved")
	}
	if dest.Period != 2 {
		t.Fatalf("expected explicit Period to be preserved, have %d want %d", dest.Period, 2)
	}
	if dest.Gap != src.Gap {
		t.Fatalf("expected missing Gap to be backfilled, have %d want %d", dest.Gap, src.Gap)
	}
	if dest.FoundationWalletAddr != src.FoundationWalletAddr {
		t.Fatalf("expected missing FoundationWalletAddr to be backfilled, have %s want %s", dest.FoundationWalletAddr.Hex(), src.FoundationWalletAddr.Hex())
	}
	if dest.MaxMasternodesV2 != src.MaxMasternodesV2 {
		t.Fatalf("expected missing MaxMasternodesV2 to be backfilled, have %d want %d", dest.MaxMasternodesV2, src.MaxMasternodesV2)
	}
}

// TestV2ConfigBackfillMissingScalarFieldsFromPreservesExplicitZero tests v 2 config backfill missing scalar fields from preserves explicit zero.
func TestV2ConfigBackfillMissingScalarFieldsFromPreservesExplicitZero(t *testing.T) {
	dest := &V2Config{
		SwitchRound:   0,
		CertThreshold: 0,
		json: jsonFieldPresence{tracked: true, keys: map[string]struct{}{
			"switchRound":          {},
			"certificateThreshold": {},
		}},
	}
	src := &V2Config{
		SwitchRound:          9,
		TimeoutPeriod:        10,
		TimeoutSyncThreshold: 3,
		CertThreshold:        0.67,
		MasternodeReward:     0.7,
	}

	dest.backfillMissingScalarFieldsFrom(src)

	if dest.SwitchRound != 0 {
		t.Fatalf("expected explicit zero SwitchRound to be preserved, have %d want 0", dest.SwitchRound)
	}
	if dest.CertThreshold != 0 {
		t.Fatalf("expected explicit zero CertThreshold to be preserved, have %v want 0", dest.CertThreshold)
	}
	if dest.TimeoutPeriod != src.TimeoutPeriod {
		t.Fatalf("expected missing TimeoutPeriod to be backfilled, have %d want %d", dest.TimeoutPeriod, src.TimeoutPeriod)
	}
	if dest.TimeoutSyncThreshold != src.TimeoutSyncThreshold {
		t.Fatalf("expected missing TimeoutSyncThreshold to be backfilled, have %d want %d", dest.TimeoutSyncThreshold, src.TimeoutSyncThreshold)
	}
	if dest.MasternodeReward != src.MasternodeReward {
		t.Fatalf("expected missing MasternodeReward to be backfilled, have %v want %v", dest.MasternodeReward, src.MasternodeReward)
	}
}

// TestExpTimeoutConfigBackfillMissingScalarFieldsFromPreservesExplicitZero tests exp timeout config backfill missing scalar fields from preserves explicit zero.
func TestExpTimeoutConfigBackfillMissingScalarFieldsFromPreservesExplicitZero(t *testing.T) {
	dest := &ExpTimeoutConfig{
		Base: 0,
		json: jsonFieldPresence{tracked: true, keys: map[string]struct{}{
			"base": {},
		}},
	}
	src := &ExpTimeoutConfig{
		Base:        2,
		MaxExponent: 5,
	}

	dest.backfillMissingScalarFieldsFrom(src)

	if dest.Base != 0 {
		t.Fatalf("expected explicit zero Base to be preserved, have %v want 0", dest.Base)
	}
	if dest.MaxExponent != src.MaxExponent {
		t.Fatalf("expected missing MaxExponent to be backfilled, have %d want %d", dest.MaxExponent, src.MaxExponent)
	}
}

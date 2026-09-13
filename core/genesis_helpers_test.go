package core

import (
	"bytes"
	"encoding/json"
	"math/big"
	"reflect"
	"strings"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/ethdb"
	"github.com/XinFinOrg/XDPoSChain/params"
)

var builtInBackfillForkFieldJSONKeysForTests = params.BuiltInBackfillForkFieldJSONKeys()

// customXDPoSGenesisSwitchEpoch is the V2 switch epoch newCustomXDPoSGenesis
// installs. Tests that drift it compare against the next value.
const customXDPoSGenesisSwitchEpoch = 1

// newCustomXDPoSGenesis builds a custom chain with the smallest XDPoS schedule
// the config validation accepts, so compat tests do not need long block ranges.
// Epoch 2 with gap 1 also keeps the V2 switch block aligned to the epoch. The
// genesis timestamp is parameterized because some compat tests need a non-zero
// one.
func newCustomXDPoSGenesis(chainID int64, timestamp uint64) *Genesis {
	xdposCfg := params.TestnetChainConfig.XDPoS.Clone()
	xdposCfg.Epoch = 2
	xdposCfg.Gap = 1
	xdposCfg.V2 = xdposCfg.V2.Clone()
	xdposCfg.V2.SwitchBlock = big.NewInt(2)
	xdposCfg.V2.SwitchEpoch = customXDPoSGenesisSwitchEpoch
	return &Genesis{
		Config: &params.ChainConfig{
			ChainID:                big.NewInt(chainID),
			TIPTRC21FeeBlock:       big.NewInt(1),
			Gas50xBlock:            big.NewInt(1),
			TRC21IssuerSMC:         params.TestnetChainConfig.TRC21IssuerSMC,
			XDCXListingSMC:         params.TestnetChainConfig.XDCXListingSMC,
			RelayerRegistrationSMC: params.TestnetChainConfig.RelayerRegistrationSMC,
			LendingRegistrationSMC: params.TestnetChainConfig.LendingRegistrationSMC,
			XDPoS:                  xdposCfg,
		},
		Timestamp: timestamp,
		ExtraData: make([]byte, 32+crypto.SignatureLength),
		Alloc: types.GenesisAlloc{
			{1}: {Balance: big.NewInt(1)},
		},
		GasLimit:   4700000,
		Difficulty: big.NewInt(1),
	}
}

// jsonKeyToForkFieldName maps a migrated fork JSON key to the matching
// ChainConfig struct field name used by reflection-based test and logging helpers.
func jsonKeyToForkFieldName(jsonKey string) string {
	if strings.HasPrefix(jsonKey, "tip") {
		return "TIP" + jsonKey[len("tip"):]
	}
	if strings.HasPrefix(jsonKey, "eip") {
		return "EIP" + jsonKey[len("eip"):]
	}
	if jsonKey == "" {
		return ""
	}
	return strings.ToUpper(jsonKey[:1]) + jsonKey[1:]
}

func TestJSONKeyToForkFieldName(t *testing.T) {
	tests := []struct {
		jsonKey string
		want    string
	}{
		{jsonKey: "berlinBlock", want: "BerlinBlock"},
		{jsonKey: "tipTRC21FeeBlock", want: "TIPTRC21FeeBlock"},
		{jsonKey: "eip1559Block", want: "EIP1559Block"},
	}
	for _, test := range tests {
		if got := jsonKeyToForkFieldName(test.jsonKey); got != test.want {
			t.Fatalf("unexpected field name for %s: have %s want %s", test.jsonKey, got, test.want)
		}
	}
}

// assertBuiltInBackfillForkFieldsEqual verifies that all built-in backfill fork
// fields match between two chain configs.
func assertBuiltInBackfillForkFieldsEqual(t *testing.T, got, want *params.ChainConfig) {
	t.Helper()
	vgot := reflect.ValueOf(got).Elem()
	vwant := reflect.ValueOf(want).Elem()
	for _, key := range builtInBackfillForkFieldJSONKeysForTests {
		name := jsonKeyToForkFieldName(key)
		gotField := vgot.FieldByName(name)
		wantField := vwant.FieldByName(name)
		if !gotField.IsValid() || !wantField.IsValid() {
			t.Fatalf("missing field %s on ChainConfig", name)
		}
		if wantField.IsNil() {
			if !gotField.IsNil() {
				t.Fatalf("unexpected %s: have %v want nil", name, gotField.Interface())
			}
			continue
		}
		if gotField.IsNil() {
			t.Fatalf("unexpected %s: have nil want %v", name, wantField.Interface())
		}
		gotBig := gotField.Interface().(*big.Int)
		wantBig := wantField.Interface().(*big.Int)
		if gotBig.Cmp(wantBig) != 0 {
			t.Fatalf("unexpected %s: have %v want %v", name, gotBig, wantBig)
		}
	}
}

// removeXDPoSMaxMasternodesV2FromRawConfig removes the legacy
// maxMasternodesV2 field from raw chain-config JSON.
func removeXDPoSMaxMasternodesV2FromRawConfig(raw []byte) ([]byte, error) {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(raw, &root); err != nil {
		return nil, err
	}
	xdposRaw, ok := root["XDPoS"]
	if !ok || len(xdposRaw) == 0 || string(bytes.TrimSpace(xdposRaw)) == "null" {
		return raw, nil
	}
	var xdposFields map[string]json.RawMessage
	if err := json.Unmarshal(xdposRaw, &xdposFields); err != nil {
		return nil, err
	}
	delete(xdposFields, "maxMasternodesV2")
	updatedXDPoS, err := json.Marshal(xdposFields)
	if err != nil {
		return nil, err
	}
	root["XDPoS"] = updatedXDPoS
	return json.Marshal(root)
}

// removeTopLevelFieldFromRawConfig removes a top-level field from raw
// chain-config JSON.
func removeTopLevelFieldFromRawConfig(raw []byte, field string) ([]byte, error) {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(raw, &root); err != nil {
		return nil, err
	}
	delete(root, field)
	return json.Marshal(root)
}

// setTopLevelFieldRawConfig overwrites a top-level field in raw chain-config
// JSON.
func setTopLevelFieldRawConfig(raw []byte, field string, value json.RawMessage) ([]byte, error) {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(raw, &root); err != nil {
		return nil, err
	}
	root[field] = value
	return json.Marshal(root)
}

type failingConfigReadDB struct {
	ethdb.Database
	targetKey []byte
	getErr    error
	hasResult bool
	hasErr    error
}

// Has injects a synthetic Has result for chain-config read failure tests.
func (db *failingConfigReadDB) Has(key []byte) (bool, error) {
	if bytes.Equal(key, db.targetKey) {
		return db.hasResult, db.hasErr
	}
	return db.Database.Has(key)
}

// Get injects a synthetic Get failure for chain-config read failure tests.
func (db *failingConfigReadDB) Get(key []byte) ([]byte, error) {
	if bytes.Equal(key, db.targetKey) {
		return nil, db.getErr
	}
	return db.Database.Get(key)
}

// testConfigKey returns the rawdb key used to store a chain config blob.
func testConfigKey(hash common.Hash) []byte {
	return append([]byte("ethereum-config-"), hash.Bytes()...)
}

// overwriteStoredChainConfig replaces the stored chain-config blob for tests.
func overwriteStoredChainConfig(t *testing.T, db ethdb.KeyValueStore, hash common.Hash, cfg *params.ChainConfig) {
	t.Helper()
	rawCfg, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("failed to marshal stored chain config: %v", err)
	}
	if err := db.Put(testConfigKey(hash), rawCfg); err != nil {
		t.Fatalf("failed to overwrite stored chain config: %v", err)
	}
}

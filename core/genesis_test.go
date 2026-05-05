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

package core

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/ethdb"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/davecgh/go-spew/spew"
)

func chainConfigSemanticallyEqual(a, b *params.ChainConfig) bool {
	if a == nil || b == nil {
		return a == b
	}
	va := reflect.ValueOf(a).Elem()
	vb := reflect.ValueOf(b).Elem()
	fields := []string{"ChainID", "TIPTRC21FeeBlock", "XDPoS"}
	// Add non-nil fields from b (only call IsNil on types that support it)
	nilKinds := map[reflect.Kind]bool{
		reflect.Pointer: true, reflect.Slice: true, reflect.Map: true, reflect.Chan: true, reflect.Func: true, reflect.Interface: true,
	}
	typeOfCfg := va.Type()
	for i := 0; i < vb.NumField(); i++ {
		fname := typeOfCfg.Field(i).Name
		if slices.Contains(fields, fname) {
			continue
		}
		fieldVal := vb.Field(i)
		if nilKinds[fieldVal.Kind()] && !fieldVal.IsNil() {
			fields = append(fields, fname)
		}
	}
	for _, fname := range fields {
		fa := va.FieldByName(fname)
		fb := vb.FieldByName(fname)
		if !fa.IsValid() || !fb.IsValid() {
			return false
		}
		// For *big.Int pointers
		if fa.Type().String() == "*big.Int" {
			if fa.Kind() == reflect.Ptr && fb.Kind() == reflect.Ptr {
				if (fa.IsNil() && !fb.IsNil()) || (!fa.IsNil() && fb.IsNil()) {
					return false
				}
				if !fa.IsNil() && fa.Interface().(*big.Int).Cmp(fb.Interface().(*big.Int)) != 0 {
					return false
				}
				continue
			}
		}
		// For XDPoS field
		if fname == "XDPoS" {
			if !params.XDPoSConfigEqual(fa.Interface().(*params.XDPoSConfig), fb.Interface().(*params.XDPoSConfig)) {
				return false
			}
			continue
		}
		// Only call IsNil on types that support it
		nilKinds := map[reflect.Kind]bool{
			reflect.Ptr: true, reflect.Slice: true, reflect.Map: true, reflect.Chan: true, reflect.Func: true, reflect.Interface: true,
		}
		if !nilKinds[fa.Kind()] {
			if !reflect.DeepEqual(fa.Interface(), fb.Interface()) {
				return false
			}
			continue
		}
		// Only proceed if both sides support IsNil
		if fa.IsNil() != fb.IsNil() {
			return false
		}
		if fa.IsNil() && fb.IsNil() {
			continue
		}
		if !reflect.DeepEqual(fa.Interface(), fb.Interface()) {
			return false
		}
	}
	return true
}

// jsonKeyToForkFieldName maps a migrated fork JSON key to the matching
// ChainConfig struct field name used by reflection-based test and logging helpers.
func jsonKeyToForkFieldName(jsonKey string) string {
	if strings.HasPrefix(jsonKey, "tip") {
		return "TIP" + jsonKey[len("tip"):]
	}
	if jsonKey == "" {
		return ""
	}
	return strings.ToUpper(jsonKey[:1]) + jsonKey[1:]
}

func assertMigratedForkFieldsEqual(t *testing.T, got, want *params.ChainConfig) {
	t.Helper()
	vgot := reflect.ValueOf(got).Elem()
	vwant := reflect.ValueOf(want).Elem()
	for _, key := range params.MigratedForkFieldJSONKeys() {
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

func assertMigratedForkFieldsNil(t *testing.T, got *params.ChainConfig) {
	t.Helper()
	vgot := reflect.ValueOf(got).Elem()
	for _, key := range params.MigratedForkFieldJSONKeys() {
		name := jsonKeyToForkFieldName(key)
		gotField := vgot.FieldByName(name)
		if !gotField.IsValid() {
			t.Fatalf("missing field %s on ChainConfig", name)
		}
		if !gotField.IsNil() {
			t.Fatalf("unexpected %s for custom chain: have %v want nil", name, gotField.Interface())
		}
	}
}

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

func removeTopLevelFieldFromRawConfig(raw []byte, field string) ([]byte, error) {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(raw, &root); err != nil {
		return nil, err
	}
	delete(root, field)
	return json.Marshal(root)
}

type failingConfigReadDB struct {
	ethdb.Database
	targetKey []byte
	getErr    error
	hasResult bool
	hasErr    error
}

func (db *failingConfigReadDB) Has(key []byte) (bool, error) {
	if bytes.Equal(key, db.targetKey) {
		return db.hasResult, db.hasErr
	}
	return db.Database.Has(key)
}

func (db *failingConfigReadDB) Get(key []byte) ([]byte, error) {
	if bytes.Equal(key, db.targetKey) {
		return nil, db.getErr
	}
	return db.Database.Get(key)
}

func testConfigKey(hash common.Hash) []byte {
	return append([]byte("ethereum-config-"), hash.Bytes()...)
}

func TestDefaultGenesisBlock(t *testing.T) {
	block := DefaultGenesisBlock().ToBlock()
	if block.Hash() != params.MainnetGenesisHash {
		t.Errorf("wrong mainnet genesis hash, got %v, want %v", block.Hash().String(), params.MainnetGenesisHash.String())
	}
	block = DefaultTestnetGenesisBlock().ToBlock()
	if block.Hash() != params.TestnetGenesisHash {
		t.Errorf("wrong testnet genesis hash, got %v, want %v", block.Hash().String(), params.TestnetGenesisHash.String())
	}
}

func TestSetupGenesisNormalizesLocalnetChainConfig(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	genesis := &Genesis{
		Config: &params.ChainConfig{
			ChainID:             params.LocalnetChainConfig.ChainID,
			TIPTRC21FeeBlock:    big.NewInt(0),
			ConstantinopleBlock: big.NewInt(9),
			BerlinBlock:         big.NewInt(12),
			CancunBlock:         big.NewInt(34),
			Ethash:              new(params.EthashConfig),
		},
		Alloc: types.GenesisAlloc{
			{1}: {Balance: big.NewInt(1)},
		},
		GasLimit:   4700000,
		Difficulty: big.NewInt(1),
	}
	inputCfg := genesis.Config

	cfg, _, _, err := SetupGenesisBlock(db, genesis)
	if err != nil {
		t.Fatalf("SetupGenesisBlock failed: %v", err)
	}
	if cfg == params.LocalnetChainConfig {
		t.Fatal("unexpected localnet singleton reuse")
	}
	if cfg == inputCfg {
		t.Fatal("expected canonicalized config to be a copy")
	}
	if cfg.ChainID == params.LocalnetChainConfig.ChainID {
		t.Fatal("expected canonicalized chain id to be deep-copied")
	}
	if cfg.ConstantinopleBlock == nil || cfg.ConstantinopleBlock.Cmp(big.NewInt(9)) != 0 {
		t.Fatalf("unexpected preserved Constantinople block: have %v want 9", cfg.ConstantinopleBlock)
	}
	if cfg.BerlinBlock == nil || cfg.BerlinBlock.Cmp(big.NewInt(12)) != 0 {
		t.Fatalf("unexpected preserved Berlin block: have %v want 12", cfg.BerlinBlock)
	}
	if cfg.CancunBlock == nil || cfg.CancunBlock.Cmp(big.NewInt(34)) != 0 {
		t.Fatalf("unexpected preserved Cancun block: have %v want 34", cfg.CancunBlock)
	}
	if cfg.Ethash == nil {
		t.Fatal("expected non-whitelisted fields to be preserved")
	}
	if cfg.PragueBlock != nil || cfg.DynamicGasLimitBlock != nil || cfg.TIPUpgradeRewardBlock != nil {
		t.Fatalf("unexpected localnet whitelist fields: Prague=%v DynamicGasLimit=%v TIPUpgradeReward=%v", cfg.PragueBlock, cfg.DynamicGasLimitBlock, cfg.TIPUpgradeRewardBlock)
	}
	if cfg.LondonBlock == nil || cfg.LondonBlock.Cmp(big.NewInt(0)) != 0 {
		t.Fatalf("unexpected localnet London block: have %v want 0", cfg.LondonBlock)
	}

	storedCfg, _, err := LoadChainConfig(db, genesis)
	if err != nil {
		t.Fatalf("LoadChainConfig failed: %v", err)
	}
	if storedCfg == nil {
		t.Fatal("expected stored config")
	}
	if storedCfg.ChainID == nil || storedCfg.ChainID.Cmp(big.NewInt(5151)) != 0 {
		t.Fatalf("unexpected stored chain id: have %v want 5151", storedCfg.ChainID)
	}
	if storedCfg.ConstantinopleBlock == nil || storedCfg.ConstantinopleBlock.Cmp(big.NewInt(9)) != 0 {
		t.Fatalf("unexpected stored Constantinople block: have %v want 9", storedCfg.ConstantinopleBlock)
	}
	if storedCfg.BerlinBlock == nil || storedCfg.BerlinBlock.Cmp(big.NewInt(12)) != 0 {
		t.Fatalf("unexpected stored Berlin block: have %v want 12", storedCfg.BerlinBlock)
	}
	if storedCfg.CancunBlock == nil || storedCfg.CancunBlock.Cmp(big.NewInt(34)) != 0 {
		t.Fatalf("unexpected stored Cancun block: have %v want 34", storedCfg.CancunBlock)
	}
	if storedCfg.LondonBlock == nil || storedCfg.LondonBlock.Cmp(big.NewInt(0)) != 0 {
		t.Fatalf("unexpected stored London block: have %v want 0", storedCfg.LondonBlock)
	}
}

func TestCloneChainConfigDeepCopiesMigratedForkBlocks(t *testing.T) {
	original := &params.ChainConfig{
		ChainID:                     big.NewInt(5151),
		TIP2019Block:                big.NewInt(10),
		TIPSigningBlock:             big.NewInt(20),
		TIPRandomizeBlock:           big.NewInt(30),
		TIPIncreaseMasternodesBlock: big.NewInt(35),
		DenylistBlock:               big.NewInt(40),
		TIPNoHalvingMNRewardBlock:   big.NewInt(45),
		TIPXDCXBlock:                big.NewInt(50),
		TIPXDCXLendingBlock:         big.NewInt(60),
		TIPXDCXCancellationFeeBlock: big.NewInt(70),
		TIPTRC21FeeBlock:            big.NewInt(75),
		BerlinBlock:                 big.NewInt(80),
		LondonBlock:                 big.NewInt(90),
		MergeBlock:                  big.NewInt(100),
		ShanghaiBlock:               big.NewInt(110),
		TIPXDCXMinerDisableBlock:    big.NewInt(120),
		TIPXDCXReceiverDisableBlock: big.NewInt(130),
		Eip1559Block:                big.NewInt(140),
		CancunBlock:                 big.NewInt(150),
		PragueBlock:                 big.NewInt(160),
		OsakaBlock:                  big.NewInt(170),
		DynamicGasLimitBlock:        big.NewInt(180),
		TIPUpgradeRewardBlock:       big.NewInt(190),
		TIPUpgradePenaltyBlock:      big.NewInt(200),
		TIPEpochHalvingBlock:        big.NewInt(210),
	}
	clone := original.Clone()
	if clone == nil {
		t.Fatal("expected clone")
	}
	orig := reflect.ValueOf(original).Elem()
	cloned := reflect.ValueOf(clone).Elem()
	for _, key := range params.MigratedForkFieldJSONKeys() {
		name := jsonKeyToForkFieldName(key)
		origField := orig.FieldByName(name)
		cloneField := cloned.FieldByName(name)
		if origField.IsNil() || cloneField.IsNil() {
			t.Fatalf("field %s must be non-nil in clone test", name)
		}
		origBig := origField.Interface().(*big.Int)
		cloneBig := cloneField.Interface().(*big.Int)
		if origBig == cloneBig {
			t.Fatalf("expected %s to be deep-copied", name)
		}
		want := new(big.Int).Set(origBig)
		cloneBig.Add(cloneBig, big.NewInt(999))
		if origBig.Cmp(want) != 0 {
			t.Fatalf("original %s mutated: have %v want %v", name, origBig, want)
		}
	}
}

func TestSetupGenesisBackfillsMissingXDPoSMaxMasternodesV2ForBuiltInNetworks(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	DefaultGenesisBlock().MustCommit(db)

	stored := params.MainnetGenesisHash
	rawCfg, err := rawdb.ReadChainConfigJSON(db, stored)
	if err != nil {
		t.Fatalf("failed to read raw chain config: %v", err)
	}
	updatedRawCfg, err := removeXDPoSMaxMasternodesV2FromRawConfig(rawCfg)
	if err != nil {
		t.Fatalf("failed to remove XDPoS.maxMasternodesV2 from raw config: %v", err)
	}
	if err := db.Put(testConfigKey(stored), updatedRawCfg); err != nil {
		t.Fatalf("failed to write modified raw chain config: %v", err)
	}

	cfg, _, _, err := SetupGenesisBlock(db, nil)
	if err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
	if cfg != nil && cfg.XDPoS != nil && cfg.XDPoS.MaxMasternodesV2 != params.XDCMainnetChainConfig.XDPoS.MaxMasternodesV2 {
		t.Fatalf("expected MaxMasternodesV2 to be %d when missing, got %d", params.XDCMainnetChainConfig.XDPoS.MaxMasternodesV2, cfg.XDPoS.MaxMasternodesV2)
	}

	persistedCfg, err := rawdb.ReadChainConfig(db, stored)
	if err != nil {
		t.Fatalf("failed to read persisted config: %v", err)
	}
	if persistedCfg == nil || persistedCfg.XDPoS == nil {
		t.Fatalf("expected persisted XDPoS config, have %v", persistedCfg)
	}
	if persistedCfg.XDPoS.MaxMasternodesV2 != params.XDCMainnetChainConfig.XDPoS.MaxMasternodesV2 {
		t.Fatalf("unexpected persisted MaxMasternodesV2: have %d want %d", persistedCfg.XDPoS.MaxMasternodesV2, params.XDCMainnetChainConfig.XDPoS.MaxMasternodesV2)
	}
}

func TestSetupGenesisBackfillsMissingXDPoSMaxMasternodesV2ForDevnet(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	DefaultDevnetGenesisBlock().MustCommit(db)

	stored := params.DevnetGenesisHash
	rawCfg, err := rawdb.ReadChainConfigJSON(db, stored)
	if err != nil {
		t.Fatalf("failed to read raw chain config: %v", err)
	}
	updatedRawCfg, err := removeXDPoSMaxMasternodesV2FromRawConfig(rawCfg)
	if err != nil {
		t.Fatalf("failed to remove XDPoS.maxMasternodesV2 from raw config: %v", err)
	}
	if err := db.Put(testConfigKey(stored), updatedRawCfg); err != nil {
		t.Fatalf("failed to write modified raw chain config: %v", err)
	}

	cfg, _, _, err := SetupGenesisBlock(db, nil)
	if err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
	if cfg != nil && cfg.XDPoS != nil && cfg.XDPoS.MaxMasternodesV2 != params.DevnetChainConfig.XDPoS.MaxMasternodesV2 {
		t.Fatalf("expected MaxMasternodesV2 to be %d when missing, got %d", params.DevnetChainConfig.XDPoS.MaxMasternodesV2, cfg.XDPoS.MaxMasternodesV2)
	}
}

func TestSetupGenesisFillsLegacyCustomChainMissingXDPoSMaxMasternodesV2InMemory(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	genesisCfg := params.XDCMainnetChainConfig.Clone()
	genesisCfg.ChainID = big.NewInt(9798)
	genesisCfg.XDPoS = genesisCfg.XDPoS.Clone()
	genesisCfg.XDPoS.MaxMasternodesV2 = 0
	genesis := &Genesis{
		Config:    genesisCfg,
		ExtraData: make([]byte, 32+crypto.SignatureLength),
		Alloc: types.GenesisAlloc{
			{1}: {Balance: big.NewInt(1)},
		},
		GasLimit:   4700000,
		Difficulty: big.NewInt(1),
	}
	_, err := genesis.Commit(db)
	if !errors.Is(err, params.ErrMissingForkSwitch) {
		t.Fatalf("expected ErrMissingForkSwitch from Commit, got %v", err)
	}
}

func TestSetupGenesisBackfillsMissingChainIDForNonBuiltInChain(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	genesis := &Genesis{
		Config: &params.ChainConfig{
			ChainID:          big.NewInt(4444),
			TIPTRC21FeeBlock: big.NewInt(0),
			Ethash:           new(params.EthashConfig),
		},
		Alloc: types.GenesisAlloc{
			{1}: {Balance: big.NewInt(1)},
		},
		GasLimit:   4700000,
		Difficulty: big.NewInt(1),
	}
	block := genesis.MustCommit(db)

	rawCfg, err := rawdb.ReadChainConfigJSON(db, block.Hash())
	if err != nil {
		t.Fatalf("failed to read raw chain config: %v", err)
	}
	updatedRawCfg, err := removeTopLevelFieldFromRawConfig(rawCfg, "chainId")
	if err != nil {
		t.Fatalf("failed to remove chainId from raw config: %v", err)
	}
	if err := db.Put(testConfigKey(block.Hash()), updatedRawCfg); err != nil {
		t.Fatalf("failed to write modified raw chain config: %v", err)
	}

	resolvedCfg, hash, _, err := SetupGenesisBlock(db, nil)
	if err != nil {
		t.Fatalf("SetupGenesisBlock failed: %v", err)
	}
	if hash != block.Hash() {
		t.Fatalf("unexpected genesis hash: have %s want %s", hash.Hex(), block.Hash().Hex())
	}
	if resolvedCfg == nil || resolvedCfg.ChainID == nil {
		t.Fatalf("expected resolved ChainID, have %v", resolvedCfg)
	}
	if resolvedCfg.ChainID.Cmp(params.LocalnetChainConfig.ChainID) != 0 {
		t.Fatalf("unexpected ChainID: have %v want %v", resolvedCfg.ChainID, params.LocalnetChainConfig.ChainID)
	}
}

func TestSetupGenesisBackfillsNilXDPoSForNonBuiltInChain(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	genesis := &Genesis{
		Config: &params.ChainConfig{
			ChainID:          big.NewInt(5555),
			TIPTRC21FeeBlock: big.NewInt(0),
			Ethash:           new(params.EthashConfig),
		},
		Alloc: types.GenesisAlloc{
			{1}: {Balance: big.NewInt(1)},
		},
		GasLimit:   4700000,
		Difficulty: big.NewInt(1),
	}
	block := genesis.MustCommit(db)

	resolvedCfg, hash, _, err := SetupGenesisBlock(db, nil)
	if err != nil {
		t.Fatalf("SetupGenesisBlock failed: %v", err)
	}
	if hash != block.Hash() {
		t.Fatalf("unexpected genesis hash: have %s want %s", hash.Hex(), block.Hash().Hex())
	}
	if resolvedCfg != nil && resolvedCfg.XDPoS != nil {
		t.Fatalf("expected resolvedCfg: nil, have %v", resolvedCfg)
	}
}

func TestSetupGenesisBackfillsCustomGenesisFromLocalnetOnWrite(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	genesis := &Genesis{
		Config: &params.ChainConfig{
			ChainID:          big.NewInt(999001),
			TIPTRC21FeeBlock: big.NewInt(0),
			Ethash:           new(params.EthashConfig),
		},
		Alloc: types.GenesisAlloc{
			{1}: {Balance: big.NewInt(1)},
		},
		GasLimit:   4700000,
		Difficulty: big.NewInt(1),
	}

	cfg, _, _, err := SetupGenesisBlock(db, genesis)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected resolved config")
	}
	if cfg == params.XDCMainnetChainConfig || cfg == params.TestnetChainConfig || cfg == params.DevnetChainConfig {
		t.Fatalf("expected custom config classification, got built-in pointer: %v", cfg)
	}
	if cfg.ChainID == nil || cfg.ChainID.Cmp(big.NewInt(999001)) != 0 {
		t.Fatalf("unexpected ChainID: have %v want 999001", cfg.ChainID)
	}
	if cfg.TIP2019Block == nil || cfg.TIP2019Block.Cmp(big.NewInt(0)) != 0 {
		t.Fatalf("expected TIP2019Block to be backfilled to 0, have %v", cfg.TIP2019Block)
	}
	if cfg.XDPoS != nil {
		t.Fatalf("expected no XDPoS backfill for explicit genesis, have %v", cfg.XDPoS)
	}
}

func TestSetupGenesisTreatsStoredCustomGenesisWithBuiltInChainIDAsLocalnet(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	genesis := &Genesis{
		Config: &params.ChainConfig{
			ChainID:          new(big.Int).Set(params.XDCMainnetChainConfig.ChainID),
			TIPTRC21FeeBlock: big.NewInt(0),
			Ethash:           new(params.EthashConfig),
		},
		Alloc: types.GenesisAlloc{
			{1}: {Balance: big.NewInt(1)},
		},
		GasLimit:   4700000,
		Difficulty: big.NewInt(1),
	}
	genesis.MustCommit(db)

	cfg, hash, _, err := SetupGenesisBlock(db, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hash != genesis.ToBlock().Hash() {
		t.Fatalf("unexpected hash: have %s want %s", hash.Hex(), genesis.ToBlock().Hash().Hex())
	}
	// Only check ChainID and XDPoS.MaxMasternodesV2, do not require all migrated fork fields to be backfilled.
	if cfg.ChainID.Cmp(params.XDCMainnetChainConfig.ChainID) != 0 {
		t.Fatalf("unexpected ChainID: have %v want %v", cfg.ChainID, params.XDCMainnetChainConfig.ChainID)
	}
	if cfg.XDPoS != nil && cfg.XDPoS.MaxMasternodesV2 != params.LocalnetChainConfig.XDPoS.MaxMasternodesV2 {
		t.Fatalf("unexpected MaxMasternodesV2: have %v want %v", cfg.XDPoS, params.LocalnetChainConfig.XDPoS.MaxMasternodesV2)
	}
}

func TestSetupGenesisAllowsCustomChainWithIntentionallyNilOsakaBlock(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	cfg := params.XDCMainnetChainConfig.Clone()
	cfg.ChainID = big.NewInt(7778)
	cfg.XDPoS = nil
	cfg.Ethash = new(params.EthashConfig)
	cfg.OsakaBlock = nil

	genesis := &Genesis{
		Config: cfg,
		Alloc: types.GenesisAlloc{
			{1}: {Balance: big.NewInt(1)},
		},
		GasLimit:   4700000,
		Difficulty: big.NewInt(1),
	}
	block := genesis.MustCommit(db)

	resolvedCfg, hash, _, err := SetupGenesisBlock(db, nil)
	if err != nil {
		t.Fatalf("SetupGenesisBlock failed: %v", err)
	}
	if hash != block.Hash() {
		t.Fatalf("unexpected genesis hash: have %s want %s", hash.Hex(), block.Hash().Hex())
	}
	if resolvedCfg == nil {
		t.Fatal("expected resolved config")
	}
	if resolvedCfg.OsakaBlock != nil {
		t.Fatalf("expected OsakaBlock to remain nil, have %v", resolvedCfg.OsakaBlock)
	}
}

func TestSetupGenesisCustomChainProvidedGenesisThenRestartWithoutGenesis(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	cfg := params.XDCMainnetChainConfig.Clone()
	cfg.ChainID = big.NewInt(8888)
	cfg.XDPoS = nil
	cfg.Ethash = new(params.EthashConfig)
	cfg.OsakaBlock = nil

	genesis := &Genesis{
		Config: cfg,
		Alloc: types.GenesisAlloc{
			{1}: {Balance: big.NewInt(1)},
		},
		GasLimit:   4700000,
		Difficulty: big.NewInt(1),
	}

	initialCfg, hash, _, err := SetupGenesisBlock(db, genesis)
	if err != nil {
		t.Fatalf("initial SetupGenesisBlock failed: %v", err)
	}
	if initialCfg == nil {
		t.Fatal("expected initial config")
	}
	if initialCfg.OsakaBlock != nil {
		t.Fatalf("expected OsakaBlock to remain nil after initial setup, have %v", initialCfg.OsakaBlock)
	}

	restartedCfg, restartedHash, _, err := SetupGenesisBlock(db, nil)
	if err != nil {
		t.Fatalf("restart SetupGenesisBlock failed: %v", err)
	}
	if restartedCfg == nil {
		t.Fatal("expected restart config")
	}
	if restartedHash != hash {
		t.Fatalf("unexpected restart genesis hash: have %s want %s", restartedHash.Hex(), hash.Hex())
	}
	if restartedCfg.OsakaBlock != nil {
		t.Fatalf("expected OsakaBlock to remain nil after restart, have %v", restartedCfg.OsakaBlock)
	}
}

func TestLoadChainConfigAllowsLegacyCustomChainWithCompleteMigratedForkFields(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	cfg := params.XDCMainnetChainConfig.Clone()
	cfg.ChainID = big.NewInt(9898)
	cfg.XDPoS = nil
	cfg.Ethash = new(params.EthashConfig)

	genesis := &Genesis{
		Config: cfg,
		Alloc: types.GenesisAlloc{
			{1}: {Balance: big.NewInt(1)},
		},
		GasLimit:   4700000,
		Difficulty: big.NewInt(1),
	}
	block := genesis.MustCommit(db)

	loadedCfg, loadedHash, err := LoadChainConfig(db, nil)
	if err != nil {
		t.Fatalf("LoadChainConfig failed: %v", err)
	}
	if loadedCfg == nil {
		t.Fatal("expected loaded config")
	}
	if loadedHash != block.Hash() {
		t.Fatalf("unexpected genesis hash: have %s want %s", loadedHash.Hex(), block.Hash().Hex())
	}
}

func TestLoadChainConfigUsesStoredBuiltInHashWhenChainConfigMissing(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	block := DefaultTestnetGenesisBlock().ToBlock()
	rawdb.WriteBlock(db, block)
	rawdb.WriteHeadHeaderHash(db, block.Hash())
	rawdb.WriteCanonicalHash(db, block.Hash(), 0)
	rawdb.WriteChainConfig(db, block.Hash(), params.TestnetChainConfig)

	cfg, hash, err := LoadChainConfig(db, nil)
	if err != nil {
		t.Fatalf("LoadChainConfig failed: %v", err)
	}
	if hash != params.TestnetGenesisHash {
		t.Fatalf("unexpected hash: have %s want %s", hash.Hex(), params.TestnetGenesisHash.Hex())
	}
	if !chainConfigSemanticallyEqual(cfg, params.TestnetChainConfig) {
		t.Fatalf("unexpected config: have %v want %v", cfg, params.TestnetChainConfig)
	}
}

func TestLoadChainConfigReturnsBuiltInConfigInstanceWhenStoredBuiltInConfigMissingFields(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	DefaultTestnetGenesisBlock().MustCommit(db)

	stored := params.TestnetGenesisHash
	rawCfg, err := rawdb.ReadChainConfigJSON(db, stored)
	if err != nil {
		t.Fatalf("failed to read raw chain config: %v", err)
	}
	updatedRawCfg, err := removeTopLevelFieldFromRawConfig(rawCfg, "eip1559Block")
	if err != nil {
		t.Fatalf("failed to remove eip1559Block from raw config: %v", err)
	}
	if err := db.Put(testConfigKey(stored), updatedRawCfg); err != nil {
		t.Fatalf("failed to write modified raw chain config: %v", err)
	}

	cfg, hash, err := LoadChainConfig(db, nil)
	if err != nil {
		t.Fatalf("LoadChainConfig failed: %v", err)
	}
	if hash != stored {
		t.Fatalf("unexpected hash: have %s want %s", hash.Hex(), stored.Hex())
	}
	if cfg != params.TestnetChainConfig {
		t.Fatalf("expected in-memory built-in config instance, have %p want %p", cfg, params.TestnetChainConfig)
	}
	if cfg.Eip1559Block == nil {
		t.Fatalf("expected eip1559Block from built-in config, got nil")
	}
}

func TestSetupGenesisBlockReturnsMarshalStoredConfigError(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	DefaultGenesisBlock().MustCommit(db)

	originalMarshal := jsonMarshal
	defer func() { jsonMarshal = originalMarshal }()

	injectedErr := errors.New("injected marshal failure")
	callCount := 0
	jsonMarshal = func(v any) ([]byte, error) {
		callCount++
		if callCount == 1 {
			return nil, injectedErr
		}
		return json.Marshal(v)
	}

	_, _, _, err := SetupGenesisBlock(db, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "failed to marshal stored chain config") {
		t.Fatalf("unexpected error: %v", err)
	}
	if !errors.Is(err, injectedErr) {
		t.Fatalf("expected injected error, got %v", err)
	}
}

func TestSetupGenesisBlockReturnsMarshalNewConfigError(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	DefaultGenesisBlock().MustCommit(db)

	originalMarshal := jsonMarshal
	defer func() { jsonMarshal = originalMarshal }()

	injectedErr := errors.New("injected marshal failure")
	callCount := 0
	jsonMarshal = func(v any) ([]byte, error) {
		callCount++
		if callCount == 2 {
			return nil, injectedErr
		}
		return json.Marshal(v)
	}

	_, _, _, err := SetupGenesisBlock(db, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "failed to marshal new chain config") {
		t.Fatalf("unexpected error: %v", err)
	}
	if !errors.Is(err, injectedErr) {
		t.Fatalf("expected injected error, got %v", err)
	}
}

func TestSetupGenesisTreatsCustomChainAsLocalnetWhenChainConfigMissing(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	cfg, hash, _, err := SetupGenesisBlock(db, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hash != params.MainnetGenesisHash {
		t.Fatalf("unexpected hash: have %s want %s", hash.Hex(), params.MainnetGenesisHash.Hex())
	}
	if cfg == nil {
		t.Fatal("expected resolved config")
	}
	assertMigratedForkFieldsEqual(t, cfg, params.XDCMainnetChainConfig)
}

func TestLoadChainConfigTreatsCustomChainAsLocalnetWhenChainConfigMissing(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	cfg, hash, err := LoadChainConfig(db, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hash != params.MainnetGenesisHash {
		t.Fatalf("unexpected hash: have %s want %s", hash.Hex(), params.MainnetGenesisHash.Hex())
	}
	if cfg == nil {
		t.Fatal("expected resolved config")
	}
	assertMigratedForkFieldsEqual(t, cfg, params.XDCMainnetChainConfig)
}

func TestGenesisCommitRejectsMissingTIPTRC21FeeBlock(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	genesis := &Genesis{
		Config: &params.ChainConfig{
			ChainID: big.NewInt(31337),
			Ethash:  new(params.EthashConfig),
		},
		Alloc: types.GenesisAlloc{
			{1}: {Balance: big.NewInt(1)},
		},
		GasLimit:   4700000,
		Difficulty: big.NewInt(1),
	}

	_, err := genesis.Commit(db)
	if !errors.Is(err, params.ErrMissingForkSwitch) {
		t.Fatalf("unexpected error: have %v want %v", err, params.ErrMissingForkSwitch)
	}
}

func TestSetupGenesisBackfillsMissingTIPTRC21FeeBlock(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	genesis := &Genesis{
		Config: &params.ChainConfig{
			ChainID: big.NewInt(41414),
			Ethash:  new(params.EthashConfig),
		},
		Alloc: types.GenesisAlloc{
			{1}: {Balance: big.NewInt(1)},
		},
		GasLimit:   4700000,
		Difficulty: big.NewInt(1),
	}

	cfg, hash, _, err := SetupGenesisBlock(db, genesis)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hash == (common.Hash{}) {
		t.Fatalf("unexpected empty hash")
	}
	if cfg == nil || cfg.TIPTRC21FeeBlock == nil || cfg.TIPTRC21FeeBlock.Cmp(big.NewInt(0)) != 0 {
		t.Fatalf("expected TIPTRC21FeeBlock to be backfilled to 0, have %v", cfg)
	}
}

func TestLoadChainConfigBackfillsMissingTIPTRC21FeeBlock(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	genesis := &Genesis{
		Config: &params.ChainConfig{
			ChainID: big.NewInt(51515),
			Ethash:  new(params.EthashConfig),
		},
		Alloc: types.GenesisAlloc{
			{1}: {Balance: big.NewInt(1)},
		},
		GasLimit:   4700000,
		Difficulty: big.NewInt(1),
	}

	cfg, hash, err := LoadChainConfig(db, genesis)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected resolved config")
	}
	if hash == (common.Hash{}) {
		t.Fatalf("unexpected empty hash")
	}
	if cfg.TIPTRC21FeeBlock == nil || cfg.TIPTRC21FeeBlock.Cmp(big.NewInt(0)) != 0 {
		t.Fatalf("expected TIPTRC21FeeBlock to be backfilled to 0, have %v", cfg.TIPTRC21FeeBlock)
	}
}

func TestLoadChainConfigBackfillsMissingStoredFieldForCustomNetworkReadPath(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	genesis := &Genesis{
		Config: &params.ChainConfig{
			ChainID:          big.NewInt(61616),
			TIPTRC21FeeBlock: big.NewInt(0),
			Gas50xBlock:      big.NewInt(12345),
			Ethash:           new(params.EthashConfig),
		},
		Alloc: types.GenesisAlloc{
			{1}: {Balance: big.NewInt(1)},
		},
		GasLimit:   4700000,
		Difficulty: big.NewInt(1),
	}
	block := genesis.MustCommit(db)

	rawCfg, err := rawdb.ReadChainConfigJSON(db, block.Hash())
	if err != nil {
		t.Fatalf("failed to read raw chain config: %v", err)
	}
	updatedRawCfg, err := removeTopLevelFieldFromRawConfig(rawCfg, "gas50xBlock")
	if err != nil {
		t.Fatalf("failed to remove gas50xBlock from raw config: %v", err)
	}
	if err := db.Put(testConfigKey(block.Hash()), updatedRawCfg); err != nil {
		t.Fatalf("failed to write modified raw chain config: %v", err)
	}

	cfg, hash, err := LoadChainConfig(db, nil)
	if err != nil {
		t.Fatalf("LoadChainConfig failed: %v", err)
	}
	if hash != block.Hash() {
		t.Fatalf("unexpected hash: have %s want %s", hash.Hex(), block.Hash().Hex())
	}
	if cfg == nil || cfg.Gas50xBlock == nil {
		t.Fatalf("expected Gas50xBlock to be backfilled, have %v", cfg)
	}
	if cfg.Gas50xBlock.Cmp(big.NewInt(0)) != 0 {
		t.Fatalf("unexpected Gas50xBlock: have %v want 0 (Localnet default)", cfg.Gas50xBlock)
	}
}

func TestSetupGenesisBackfillsMissingStoredFieldForCustomNetworkReadPath(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	genesis := &Genesis{
		Config: &params.ChainConfig{
			ChainID:          big.NewInt(62626),
			TIPTRC21FeeBlock: big.NewInt(0),
			Gas50xBlock:      big.NewInt(12345),
			Ethash:           new(params.EthashConfig),
		},
		Alloc: types.GenesisAlloc{
			{1}: {Balance: big.NewInt(1)},
		},
		GasLimit:   4700000,
		Difficulty: big.NewInt(1),
	}
	block := genesis.MustCommit(db)

	rawCfg, err := rawdb.ReadChainConfigJSON(db, block.Hash())
	if err != nil {
		t.Fatalf("failed to read raw chain config: %v", err)
	}
	updatedRawCfg, err := removeTopLevelFieldFromRawConfig(rawCfg, "gas50xBlock")
	if err != nil {
		t.Fatalf("failed to remove gas50xBlock from raw config: %v", err)
	}
	if err := db.Put(testConfigKey(block.Hash()), updatedRawCfg); err != nil {
		t.Fatalf("failed to write modified raw chain config: %v", err)
	}

	cfg, hash, _, err := SetupGenesisBlock(db, nil)
	if err != nil {
		t.Fatalf("SetupGenesisBlock failed: %v", err)
	}
	if hash != block.Hash() {
		t.Fatalf("unexpected hash: have %s want %s", hash.Hex(), block.Hash().Hex())
	}
	if cfg == nil || cfg.Gas50xBlock == nil {
		t.Fatalf("expected Gas50xBlock to be backfilled, have %v", cfg)
	}
	if cfg.Gas50xBlock.Cmp(big.NewInt(0)) != 0 {
		t.Fatalf("unexpected Gas50xBlock: have %v want 0 (Localnet default)", cfg.Gas50xBlock)
	}
}

func TestSetupGenesisBackfillsTIPTRC21FeeBlockForLocalnetChainID(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	genesis := &Genesis{
		Config: &params.ChainConfig{
			ChainID: big.NewInt(5151),
			Ethash:  new(params.EthashConfig),
		},
		Alloc: types.GenesisAlloc{
			{1}: {Balance: big.NewInt(1)},
		},
		GasLimit:   4700000,
		Difficulty: big.NewInt(1),
	}

	cfg, _, _, err := SetupGenesisBlock(db, genesis)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg == nil || cfg.TIPTRC21FeeBlock == nil || cfg.TIPTRC21FeeBlock.Cmp(big.NewInt(0)) != 0 {
		t.Fatalf("expected TIPTRC21FeeBlock to be backfilled to 0, have %v", cfg)
	}
}

func TestSetupGenesis(t *testing.T) {
	var (
		customg = Genesis{
			Config: &params.ChainConfig{
				ChainID:          big.NewInt(4444),
				HomesteadBlock:   big.NewInt(3),
				TIPTRC21FeeBlock: big.NewInt(0),
				Ethash:           new(params.EthashConfig),
			},
			Alloc: types.GenesisAlloc{
				{1}: {Balance: big.NewInt(1), Storage: map[common.Hash]common.Hash{{1}: {1}}},
			},
		}
		oldcustomg    = customg
		configReadErr = errors.New("chain config read failed")
	)
	canonicalCustomCfg := canonicalizeChainConfig(common.Hash{}, customg.Config)
	customg.Config = canonicalCustomCfg.Clone()
	customghash := customg.ToBlock().Hash()
	oldcustomg.Config = &params.ChainConfig{ChainID: big.NewInt(4444), HomesteadBlock: big.NewInt(2), TIPTRC21FeeBlock: big.NewInt(0), Ethash: new(params.EthashConfig)}
	oldcustomg.Config = canonicalizeChainConfig(common.Hash{}, oldcustomg.Config)
	tests := []struct {
		name           string
		fn             func(ethdb.Database) (*params.ChainConfig, common.Hash, error, error)
		wantConfig     *params.ChainConfig
		wantHash       common.Hash
		wantErr        error
		wantCompactErr *params.ConfigCompatError
	}{
		{
			name: "genesis without ChainConfig",
			fn: func(db ethdb.Database) (*params.ChainConfig, common.Hash, error, error) {
				return SetupGenesisBlock(db, new(Genesis))
			},
			wantErr:    errGenesisNoConfig,
			wantConfig: nil,
		},
		{
			name: "no block in DB, genesis == nil",
			fn: func(db ethdb.Database) (*params.ChainConfig, common.Hash, error, error) {
				return SetupGenesisBlock(db, nil)
			},
			wantHash:   params.MainnetGenesisHash,
			wantConfig: params.XDCMainnetChainConfig,
		},
		{
			name: "mainnet block in DB, genesis == nil",
			fn: func(db ethdb.Database) (*params.ChainConfig, common.Hash, error, error) {
				DefaultGenesisBlock().MustCommit(db)
				return SetupGenesisBlock(db, nil)
			},
			wantHash:   params.MainnetGenesisHash,
			wantConfig: params.XDCMainnetChainConfig,
		},
		{
			name: "custom block in DB, genesis == nil",
			fn: func(db ethdb.Database) (*params.ChainConfig, common.Hash, error, error) {
				customg.MustCommit(db)
				return SetupGenesisBlock(db, nil)
			},
			wantHash:   customghash,
			wantConfig: canonicalCustomCfg,
		},
		{
			name: "custom block in DB, genesis == testnet",
			fn: func(db ethdb.Database) (*params.ChainConfig, common.Hash, error, error) {
				customg.MustCommit(db)
				return SetupGenesisBlock(db, DefaultTestnetGenesisBlock())
			},
			wantErr:    &GenesisMismatchError{Stored: customghash, New: params.TestnetGenesisHash},
			wantHash:   common.Hash{},
			wantConfig: nil,
		},
		{
			name: "stored canonical hash without header",
			fn: func(db ethdb.Database) (*params.ChainConfig, common.Hash, error, error) {
				missingHash := common.HexToHash("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
				rawdb.WriteCanonicalHash(db, missingHash, 0)
				return SetupGenesisBlock(db, nil)
			},
			wantErr:    fmt.Errorf("missing genesis header for hash: %s", common.HexToHash("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").Hex()),
			wantHash:   common.HexToHash("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
			wantConfig: nil,
		},
		{
			name: "genesis header present but state missing",
			fn: func(db ethdb.Database) (*params.ChainConfig, common.Hash, error, error) {
				block := DefaultGenesisBlock().ToBlock()
				rawdb.WriteCanonicalHash(db, block.Hash(), 0)
				rawdb.WriteHeader(db, block.Header())
				return SetupGenesisBlock(db, nil)
			},
			wantHash:   params.MainnetGenesisHash,
			wantConfig: params.XDCMainnetChainConfig,
		},
		{
			name: "genesis block without chain config",
			fn: func(db ethdb.Database) (*params.ChainConfig, common.Hash, error, error) {
				block := DefaultGenesisBlock().ToBlock()
				rawdb.WriteBlock(db, block)
				rawdb.WriteCanonicalHash(db, block.Hash(), 0)
				return SetupGenesisBlock(db, nil)
			},
			wantHash:   params.MainnetGenesisHash,
			wantConfig: params.XDCMainnetChainConfig,
		},
		{
			name: "chain config read error does not trigger recovery",
			fn: func(db ethdb.Database) (*params.ChainConfig, common.Hash, error, error) {
				block := DefaultGenesisBlock().MustCommit(db)
				brokenDB := &failingConfigReadDB{
					Database:  db,
					targetKey: testConfigKey(block.Hash()),
					getErr:    configReadErr,
					hasResult: true,
				}
				return SetupGenesisBlock(brokenDB, nil)
			},
			wantErr:    fmt.Errorf("failed to read chain config for hash %s: %w", params.MainnetGenesisHash.Hex(), configReadErr),
			wantHash:   common.Hash{},
			wantConfig: nil,
		},
		{
			name: "missing block number for head header hash",
			fn: func(db ethdb.Database) (*params.ChainConfig, common.Hash, error, error) {
				DefaultGenesisBlock().MustCommit(db)
				rawdb.WriteHeadHeaderHash(db, common.HexToHash("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"))
				return SetupGenesisBlock(db, nil)
			},
			wantErr:    errors.New("missing block number for head header hash"),
			wantHash:   params.MainnetGenesisHash,
			wantConfig: params.XDCMainnetChainConfig,
		},
		{
			name: "compatible config in DB",
			fn: func(db ethdb.Database) (*params.ChainConfig, common.Hash, error, error) {
				oldcustomg.MustCommit(db)
				genesis := customg
				genesis.Config = customg.Config.Clone()
				return SetupGenesisBlock(db, &genesis)
			},
			wantHash:   customghash,
			wantConfig: canonicalCustomCfg,
		},
		{
			name: "incompatible config in DB",
			fn: func(db ethdb.Database) (*params.ChainConfig, common.Hash, error, error) {
				// Commit the 'old' genesis block with Homestead transition at #2.
				// Advance to block #4, past the homestead transition block of customg.
				genesis := oldcustomg.MustCommit(db)

				bc, err := NewBlockChain(db, nil, &oldcustomg, ethash.NewFullFaker(), vm.Config{})
				if err != nil {
					return nil, common.Hash{}, err, nil
				}
				defer bc.Stop()

				blocks, _ := GenerateChain(oldcustomg.Config, genesis, ethash.NewFaker(), db, 4, nil)
				if _, err := bc.InsertChain(blocks); err != nil {
					return nil, common.Hash{}, err, nil
				}
				bc.CurrentBlock()
				// This should return a compatibility error.
				genesisCfg := customg
				genesisCfg.Config = customg.Config.Clone()
				return SetupGenesisBlock(db, &genesisCfg)
			},
			wantHash:   customghash,
			wantConfig: canonicalCustomCfg,
			wantCompactErr: &params.ConfigCompatError{
				What:         "Homestead fork block",
				StoredConfig: big.NewInt(2),
				NewConfig:    big.NewInt(3),
				RewindTo:     1,
			},
		},
	}

	// Only compare fields explicitly set in the user's original config and required backfilled fields
	chainConfigSemanticallyEqual := func(a, b *params.ChainConfig) bool {
		if a == nil || b == nil {
			return a == b
		}
		va := reflect.ValueOf(a).Elem()
		vb := reflect.ValueOf(b).Elem()
		fields := []string{"ChainID", "TIPTRC21FeeBlock", "XDPoS"}
		// Add non-nil fields from b (only call IsNil on types that support it)
		nilKinds := map[reflect.Kind]bool{
			reflect.Pointer: true, reflect.Slice: true, reflect.Map: true, reflect.Chan: true, reflect.Func: true, reflect.Interface: true,
		}
		typeOfCfg := va.Type()
		for i := 0; i < vb.NumField(); i++ {
			fname := typeOfCfg.Field(i).Name
			if slices.Contains(fields, fname) {
				continue
			}
			fieldVal := vb.Field(i)
			if nilKinds[fieldVal.Kind()] && !fieldVal.IsNil() {
				fields = append(fields, fname)
			}
		}
		for _, fname := range fields {
			fa := va.FieldByName(fname)
			fb := vb.FieldByName(fname)
			if !fa.IsValid() || !fb.IsValid() {
				return false
			}
			// For *big.Int pointers
			if fa.Type().String() == "*big.Int" {
				if fa.Kind() == reflect.Ptr && fb.Kind() == reflect.Ptr {
					if (fa.IsNil() && !fb.IsNil()) || (!fa.IsNil() && fb.IsNil()) {
						return false
					}
					if !fa.IsNil() && fa.Interface().(*big.Int).Cmp(fb.Interface().(*big.Int)) != 0 {
						return false
					}
					continue
				}
			}
			// For XDPoS field
			if fname == "XDPoS" {
				if !params.XDPoSConfigEqual(fa.Interface().(*params.XDPoSConfig), fb.Interface().(*params.XDPoSConfig)) {
					return false
				}
				continue
			}
			// Only call IsNil on types that support it
			nilKinds := map[reflect.Kind]bool{
				reflect.Ptr: true, reflect.Slice: true, reflect.Map: true, reflect.Chan: true, reflect.Func: true, reflect.Interface: true,
			}
			if !nilKinds[fa.Kind()] {
				if !reflect.DeepEqual(fa.Interface(), fb.Interface()) {
					return false
				}
				continue
			}
			// Only proceed if both sides support IsNil
			if fa.IsNil() != fb.IsNil() {
				return false
			}
			if fa.IsNil() && fb.IsNil() {
				continue
			}
			if !reflect.DeepEqual(fa.Interface(), fb.Interface()) {
				return false
			}
		}
		return true
	}

	for _, test := range tests {
		db := rawdb.NewMemoryDatabase()
		config, hash, compatErr, err := test.fn(db)
		// Check the return values.
		if !chainConfigSemanticallyEqual(config, test.wantConfig) {
			t.Errorf("%s:\nreturned %v\nwant     %v", test.name, config, test.wantConfig)
		}
		if !reflect.DeepEqual(err, test.wantErr) {
			spew := spew.ConfigState{DisablePointerAddresses: true, DisableCapacities: true}
			t.Errorf("%s: returned error %#v, want %#v", test.name, spew.NewFormatter(err), spew.NewFormatter(test.wantErr))
		}
		if !reflect.DeepEqual(compatErr, test.wantCompactErr) {
			spew := spew.ConfigState{DisablePointerAddresses: true, DisableCapacities: true}
			t.Errorf("%s: returned error %#v, want %#v", test.name, spew.NewFormatter(compatErr), spew.NewFormatter(test.wantCompactErr))
		}
		if hash != test.wantHash {
			t.Errorf("%s: returned hash %s, want %s", test.name, hash.Hex(), test.wantHash.Hex())
		} else if err == nil {
			// Check database content.
			stored := rawdb.ReadBlock(db, test.wantHash, 0)
			if stored.Hash() != test.wantHash {
				t.Errorf("%s: block in DB has hash %s, want %s", test.name, stored.Hash(), test.wantHash)
			}
		}
	}
}

func TestSetupGenesisConfigCompatibilityPathReturnsConfig(t *testing.T) {
	customg := Genesis{
		Config: &params.ChainConfig{ChainID: big.NewInt(4444), HomesteadBlock: big.NewInt(3), TIPTRC21FeeBlock: big.NewInt(0), Ethash: new(params.EthashConfig)},
		Alloc: types.GenesisAlloc{
			{1}: {Balance: big.NewInt(1), Storage: map[common.Hash]common.Hash{{1}: {1}}},
		},
	}
	oldcustomg := customg
	oldcustomg.Config = &params.ChainConfig{ChainID: big.NewInt(4444), HomesteadBlock: big.NewInt(2), TIPTRC21FeeBlock: big.NewInt(0), Ethash: new(params.EthashConfig)}
	customg.Config = canonicalizeChainConfig(common.Hash{}, customg.Config)
	oldcustomg.Config = canonicalizeChainConfig(common.Hash{}, oldcustomg.Config)

	db := rawdb.NewMemoryDatabase()
	genesis := oldcustomg.MustCommit(db)

	bc, err := NewBlockChain(db, nil, &oldcustomg, ethash.NewFullFaker(), vm.Config{})
	if err != nil {
		t.Fatalf("failed to create blockchain: %v", err)
	}
	defer bc.Stop()

	blocks, _ := GenerateChain(oldcustomg.Config, genesis, ethash.NewFaker(), db, 4, nil)
	if _, err := bc.InsertChain(blocks); err != nil {
		t.Fatalf("failed to insert chain: %v", err)
	}

	config, hash, compatErr, gotErr := SetupGenesisBlock(db, &customg)
	if compatErr == nil {
		t.Fatal("expected compatibility error")
	}
	if compatErr.What != "Homestead fork block" || compatErr.RewindTo != 1 {
		t.Fatalf("unexpected compatibility error: %v", compatErr)
	}
	if gotErr != nil {
		t.Fatalf("unexpected setup error: have %v want ConfigCompatError", gotErr)
	}
	if config == nil {
		t.Fatal("unexpected nil config")
	}
	wantHash := genesis.Hash()
	if hash != wantHash {
		t.Fatalf("unexpected hash: have %s want %s", hash.Hex(), wantHash.Hex())
	}
}

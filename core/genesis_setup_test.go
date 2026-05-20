package core

import (
	"bytes"
	"encoding/json"
	"errors"
	"math/big"
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
)

// TestSetupGenesisNormalizesLocalnetChainConfig tests setup genesis normalizes localnet chain config.
func TestSetupGenesisNormalizesLocalnetChainConfig(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	genesis := &Genesis{
		Config: &params.ChainConfig{
			ChainID:                     params.LocalnetChainConfig.ChainID,
			TIPTRC21FeeBlock:            big.NewInt(0),
			ConstantinopleBlock:         big.NewInt(0),
			BerlinBlock:                 big.NewInt(12),
			LondonBlock:                 big.NewInt(12),
			MergeBlock:                  big.NewInt(12),
			ShanghaiBlock:               big.NewInt(12),
			TIPXDCXMinerDisableBlock:    big.NewInt(12),
			TIPXDCXReceiverDisableBlock: big.NewInt(12),
			EIP1559Block:                big.NewInt(12),
			CancunBlock:                 big.NewInt(34),
			TRC21IssuerSMC:              params.LocalnetChainConfig.TRC21IssuerSMC,
			XDCXListingSMC:              params.LocalnetChainConfig.XDCXListingSMC,
			RelayerRegistrationSMC:      params.LocalnetChainConfig.RelayerRegistrationSMC,
			LendingRegistrationSMC:      params.LocalnetChainConfig.LendingRegistrationSMC,
			Ethash:                      new(params.EthashConfig),
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
	if cfg.ConstantinopleBlock == nil || cfg.ConstantinopleBlock.Cmp(big.NewInt(0)) != 0 {
		t.Fatalf("unexpected preserved Constantinople block: have %v want 0", cfg.ConstantinopleBlock)
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
	if cfg.LondonBlock == nil || cfg.LondonBlock.Cmp(big.NewInt(12)) != 0 {
		t.Fatalf("unexpected localnet London block: have %v want 12", cfg.LondonBlock)
	}
	if cfg.Gas50xBlock == nil || cfg.Gas50xBlock.Cmp(big.NewInt(0)) != 0 {
		t.Fatalf("unexpected localnet Gas50x block: have %v want 0", cfg.Gas50xBlock)
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
	if storedCfg.ConstantinopleBlock == nil || storedCfg.ConstantinopleBlock.Cmp(big.NewInt(0)) != 0 {
		t.Fatalf("unexpected stored Constantinople block: have %v want 0", storedCfg.ConstantinopleBlock)
	}
	if storedCfg.BerlinBlock == nil || storedCfg.BerlinBlock.Cmp(big.NewInt(12)) != 0 {
		t.Fatalf("unexpected stored Berlin block: have %v want 12", storedCfg.BerlinBlock)
	}
	if storedCfg.CancunBlock == nil || storedCfg.CancunBlock.Cmp(big.NewInt(34)) != 0 {
		t.Fatalf("unexpected stored Cancun block: have %v want 34", storedCfg.CancunBlock)
	}
	if storedCfg.LondonBlock == nil || storedCfg.LondonBlock.Cmp(big.NewInt(12)) != 0 {
		t.Fatalf("unexpected stored London block: have %v want 12", storedCfg.LondonBlock)
	}
	if storedCfg.Gas50xBlock == nil || storedCfg.Gas50xBlock.Cmp(big.NewInt(0)) != 0 {
		t.Fatalf("unexpected stored Gas50x block: have %v want 0", storedCfg.Gas50xBlock)
	}
}

func TestSetupGenesisBlockReturnsGenesisHashError(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	genesis := &Genesis{
		Config: &params.ChainConfig{
			ChainID:        big.NewInt(1234),
			HomesteadBlock: big.NewInt(0),
			Ethash:         new(params.EthashConfig),
		},
		Alloc: types.GenesisAlloc{
			{1}: {Balance: big.NewInt(1)},
		},
		GasLimit:   4700000,
		Difficulty: big.NewInt(1),
	}
	deps := defaultGenesisDeps
	wantErr := errors.New("genesis hash failed")
	deps.genesisHash = func(*Genesis) (common.Hash, error) {
		return common.Hash{}, wantErr
	}

	cfg, hash, compatErr, err := setupGenesisBlockWithDeps(db, genesis, deps, GenesisStartupOptions{})
	if !errors.Is(err, wantErr) {
		t.Fatalf("unexpected error: have %v want %v", err, wantErr)
	}
	if compatErr != nil {
		t.Fatalf("unexpected compatibility error: %v", compatErr)
	}
	if cfg != nil {
		t.Fatalf("expected nil config, have %v", cfg)
	}
	if hash != (common.Hash{}) {
		t.Fatalf("expected zero genesis hash, have %s", hash.Hex())
	}
}

// TestSetupGenesisBlockReturnsIndependentCopyForBuiltInConfig tests setup genesis block returns independent copy for built in config.
func TestSetupGenesisBlockReturnsIndependentCopyForBuiltInConfig(t *testing.T) {
	db := rawdb.NewMemoryDatabase()

	cfg, hash, _, err := SetupGenesisBlock(db, nil)
	if err != nil {
		t.Fatalf("SetupGenesisBlock failed: %v", err)
	}
	if hash != params.MainnetGenesisHash {
		t.Fatalf("unexpected genesis hash: have %s want %s", hash.Hex(), params.MainnetGenesisHash.Hex())
	}
	if cfg == nil {
		t.Fatal("expected config")
	}
	if cfg == params.XDCMainnetChainConfig {
		t.Fatal("unexpected builtin singleton reuse on initial setup")
	}
	if cfg.ChainID == params.XDCMainnetChainConfig.ChainID {
		t.Fatal("expected builtin chain id to be deep-copied on initial setup")
	}
	if cfg.XDPoS == nil || cfg.XDPoS.V2 == nil || cfg.XDPoS.V2.CurrentConfig == nil {
		t.Fatalf("expected XDPoS V2 config to be present: have %+v", cfg.XDPoS)
	}
	if cfg.XDPoS == params.XDCMainnetChainConfig.XDPoS {
		t.Fatal("expected XDPoS config to be deep-copied on initial setup")
	}
	if cfg.XDPoS.V2 == params.XDCMainnetChainConfig.XDPoS.V2 {
		t.Fatal("expected V2 config to be deep-copied on initial setup")
	}
	if cfg.XDPoS.V2.CurrentConfig == params.XDCMainnetChainConfig.XDPoS.V2.CurrentConfig {
		t.Fatal("expected CurrentConfig to be deep-copied on initial setup")
	}

	originalBuiltinTimeout := params.XDCMainnetChainConfig.XDPoS.V2.CurrentConfig.TimeoutPeriod
	cfg.XDPoS.V2.CurrentConfig.TimeoutPeriod++
	if params.XDCMainnetChainConfig.XDPoS.V2.CurrentConfig.TimeoutPeriod != originalBuiltinTimeout {
		t.Fatal("mutating returned config must not affect builtin singleton")
	}

	restartedCfg, restartedHash, _, err := SetupGenesisBlock(db, nil)
	if err != nil {
		t.Fatalf("SetupGenesisBlock restart failed: %v", err)
	}
	if restartedHash != params.MainnetGenesisHash {
		t.Fatalf("unexpected restarted genesis hash: have %s want %s", restartedHash.Hex(), params.MainnetGenesisHash.Hex())
	}
	if restartedCfg == params.XDCMainnetChainConfig {
		t.Fatal("unexpected builtin singleton reuse on restart")
	}
	if restartedCfg.XDPoS == params.XDCMainnetChainConfig.XDPoS {
		t.Fatal("expected restarted XDPoS config to be deep-copied")
	}
	if restartedCfg.XDPoS.V2.CurrentConfig.TimeoutPeriod != originalBuiltinTimeout {
		t.Fatalf("unexpected restarted timeout period: have %d want %d", restartedCfg.XDPoS.V2.CurrentConfig.TimeoutPeriod, originalBuiltinTimeout)
	}
}

// TestSetupGenesisBackfillsMissingXDPoSMaxMasternodesV2ForBuiltInNetworks tests setup genesis backfills missing xd po s max masternodes v 2 for built in networks.
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
	rawBefore := append([]byte(nil), updatedRawCfg...)
	deps := defaultGenesisDeps
	deps.writeChainConfig = func(db ethdb.KeyValueWriter, hash common.Hash, cfg *params.ChainConfig) {
		t.Fatalf("unexpected chain-config write during hydration-only startup for %s", hash.Hex())
	}

	cfg, _, _, err := setupGenesisBlockWithDeps(db, nil, deps, GenesisStartupOptions{})
	if err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
	if cfg != nil && cfg.XDPoS != nil && cfg.XDPoS.MaxMasternodesV2 != params.XDCMainnetChainConfig.XDPoS.MaxMasternodesV2 {
		t.Fatalf("expected MaxMasternodesV2 to be %d when missing, got %d", params.XDCMainnetChainConfig.XDPoS.MaxMasternodesV2, cfg.XDPoS.MaxMasternodesV2)
	}

	rawAfter, err := rawdb.ReadChainConfigJSON(db, stored)
	if err != nil {
		t.Fatalf("failed to read persisted raw config: %v", err)
	}
	if !bytes.Equal(rawAfter, rawBefore) {
		t.Fatalf("expected stored raw config to remain unchanged when startup only hydrates missing fields")
	}
}

// TestSetupGenesisBackfillsMissingXDPoSMaxMasternodesV2ForDevnet tests setup genesis backfills missing xd po s max masternodes v 2 for devnet.
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
	rawBefore := append([]byte(nil), updatedRawCfg...)

	cfg, _, _, err := SetupGenesisBlock(db, nil)
	if err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
	if cfg != nil && cfg.XDPoS != nil && cfg.XDPoS.MaxMasternodesV2 != params.DevnetChainConfig.XDPoS.MaxMasternodesV2 {
		t.Fatalf("expected MaxMasternodesV2 to be %d when missing, got %d", params.DevnetChainConfig.XDPoS.MaxMasternodesV2, cfg.XDPoS.MaxMasternodesV2)
	}
	rawAfter, err := rawdb.ReadChainConfigJSON(db, stored)
	if err != nil {
		t.Fatalf("failed to read persisted raw config: %v", err)
	}
	if !bytes.Equal(rawAfter, rawBefore) {
		t.Fatalf("expected stored raw config to remain unchanged when startup only hydrates missing fields")
	}
}

// TestSetupGenesisBackfillsStoredLegacyCustomChainMissingXDPoSMaxMasternodesV2 tests setup genesis backfills stored legacy custom chain missing xd po s max masternodes v 2.
func TestSetupGenesisBackfillsStoredLegacyCustomChainMissingXDPoSMaxMasternodesV2(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	genesisCfg := params.LocalnetChainConfig.Clone()
	genesisCfg.ChainID = big.NewInt(9798)
	genesis := &Genesis{
		Config:    genesisCfg,
		ExtraData: make([]byte, 32+crypto.SignatureLength),
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
	updatedRawCfg, err := removeXDPoSMaxMasternodesV2FromRawConfig(rawCfg)
	if err != nil {
		t.Fatalf("failed to remove XDPoS.maxMasternodesV2 from raw config: %v", err)
	}
	if err := db.Put(testConfigKey(block.Hash()), updatedRawCfg); err != nil {
		t.Fatalf("failed to write modified raw chain config: %v", err)
	}
	rawBefore := append([]byte(nil), updatedRawCfg...)

	resolvedCfg, resolvedHash, _, err := SetupGenesisBlock(db, nil)
	if err != nil {
		t.Fatalf("SetupGenesisBlock failed: %v", err)
	}
	if resolvedHash != block.Hash() {
		t.Fatalf("unexpected genesis hash: have %s want %s", resolvedHash.Hex(), block.Hash().Hex())
	}
	if resolvedCfg == nil || resolvedCfg.XDPoS == nil {
		t.Fatalf("expected resolved XDPoS config, have %v", resolvedCfg)
	}
	if resolvedCfg.XDPoS.MaxMasternodesV2 != params.LocalnetChainConfig.XDPoS.MaxMasternodesV2 {
		t.Fatalf("expected MaxMasternodesV2 to be backfilled to %d, got %d", params.LocalnetChainConfig.XDPoS.MaxMasternodesV2, resolvedCfg.XDPoS.MaxMasternodesV2)
	}
	rawAfter, err := rawdb.ReadChainConfigJSON(db, block.Hash())
	if err != nil {
		t.Fatalf("failed to read persisted raw config: %v", err)
	}
	if !bytes.Equal(rawAfter, rawBefore) {
		t.Fatalf("expected stored raw config to remain unchanged when startup only hydrates missing fields")
	}
}

// TestSetupGenesisRejectsMissingChainIDForNonBuiltInChain tests setup genesis rejects missing chain id for non built in chain.
func TestSetupGenesisRejectsMissingChainIDForNonBuiltInChain(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	genesis := &Genesis{
		Config: &params.ChainConfig{
			ChainID:                big.NewInt(4444),
			TIPTRC21FeeBlock:       big.NewInt(0),
			Gas50xBlock:            big.NewInt(1),
			TRC21IssuerSMC:         params.TestnetChainConfig.TRC21IssuerSMC,
			XDCXListingSMC:         params.TestnetChainConfig.XDCXListingSMC,
			RelayerRegistrationSMC: params.TestnetChainConfig.RelayerRegistrationSMC,
			LendingRegistrationSMC: params.TestnetChainConfig.LendingRegistrationSMC,
			Ethash:                 new(params.EthashConfig),
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
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if hash != block.Hash() {
		t.Fatalf("unexpected genesis hash: have %s want %s", hash.Hex(), block.Hash().Hex())
	}
	if resolvedCfg != nil {
		t.Fatalf("expected nil config on missing custom chainId, have %v", resolvedCfg)
	}
}

// TestSetupGenesisBackfillsNilXDPoSForNonBuiltInChain tests setup genesis backfills nil xd po s for non built in chain.
func TestSetupGenesisBackfillsNilXDPoSForNonBuiltInChain(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	genesis := &Genesis{
		Config: &params.ChainConfig{
			ChainID:                big.NewInt(5555),
			TIPTRC21FeeBlock:       big.NewInt(0),
			Gas50xBlock:            big.NewInt(1),
			TRC21IssuerSMC:         params.TestnetChainConfig.TRC21IssuerSMC,
			XDCXListingSMC:         params.TestnetChainConfig.XDCXListingSMC,
			RelayerRegistrationSMC: params.TestnetChainConfig.RelayerRegistrationSMC,
			LendingRegistrationSMC: params.TestnetChainConfig.LendingRegistrationSMC,
			Ethash:                 new(params.EthashConfig),
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

// TestSetupGenesisPreservesExplicitCustomGenesisWithoutLocalnetBackfill tests setup genesis preserves explicit custom genesis without localnet backfill.
func TestSetupGenesisPreservesExplicitCustomGenesisWithoutLocalnetBackfill(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	genesis := &Genesis{
		Config: &params.ChainConfig{
			ChainID:                big.NewInt(999001),
			TIPTRC21FeeBlock:       big.NewInt(0),
			Gas50xBlock:            big.NewInt(1),
			TRC21IssuerSMC:         params.TestnetChainConfig.TRC21IssuerSMC,
			XDCXListingSMC:         params.TestnetChainConfig.XDCXListingSMC,
			RelayerRegistrationSMC: params.TestnetChainConfig.RelayerRegistrationSMC,
			LendingRegistrationSMC: params.TestnetChainConfig.LendingRegistrationSMC,
			Ethash:                 new(params.EthashConfig),
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
	if cfg.TIP2019Block != nil {
		t.Fatalf("expected TIP2019Block to remain unset for custom genesis, have %v", cfg.TIP2019Block)
	}
	if cfg.XDPoS != nil {
		t.Fatalf("expected no XDPoS backfill for explicit genesis, have %v", cfg.XDPoS)
	}
}

// TestSetupGenesisRejectsCustomGenesisMissingGas50xBlock tests setup genesis rejects custom genesis missing gas 50 x block.
func TestSetupGenesisRejectsCustomGenesisMissingGas50xBlock(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	genesis := &Genesis{
		Config: &params.ChainConfig{
			ChainID:                big.NewInt(999002),
			TIPTRC21FeeBlock:       big.NewInt(0),
			TRC21IssuerSMC:         params.TestnetChainConfig.TRC21IssuerSMC,
			XDCXListingSMC:         params.TestnetChainConfig.XDCXListingSMC,
			RelayerRegistrationSMC: params.TestnetChainConfig.RelayerRegistrationSMC,
			LendingRegistrationSMC: params.TestnetChainConfig.LendingRegistrationSMC,
			Ethash:                 new(params.EthashConfig),
		},
		Alloc: types.GenesisAlloc{
			{1}: {Balance: big.NewInt(1)},
		},
		GasLimit:   4700000,
		Difficulty: big.NewInt(1),
	}

	_, _, _, err := SetupGenesisBlock(db, genesis)
	if err == nil {
		t.Fatal("expected missing Gas50xBlock error")
	}
	if !strings.Contains(err.Error(), "Gas50xBlock") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestSetupGenesisRejectsCustomXDPoSConfigMissingNonMigratedFieldsOnEmptyDB tests setup genesis rejects custom xd po s configs that rely on non-migrated field backfill.
func TestSetupGenesisRejectsCustomXDPoSConfigMissingNonMigratedFieldsOnEmptyDB(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	genesis := &Genesis{
		Config: &params.ChainConfig{
			ChainID: big.NewInt(999003),
			XDPoS: &params.XDPoSConfig{
				Period: 5,
			},
		},
		Alloc: types.GenesisAlloc{
			{1}: {Balance: big.NewInt(1)},
		},
		ExtraData:  DefaultGenesisBlock().ExtraData,
		GasLimit:   4700000,
		Difficulty: big.NewInt(1),
	}

	if cfg, _, _, err := SetupGenesisBlock(db, genesis); !errors.Is(err, params.ErrMissingForkSwitch) {
		t.Fatalf("expected missing fork switch error, have %v want %v", err, params.ErrMissingForkSwitch)
	} else if cfg != nil {
		t.Fatalf("expected no resolved config for incomplete custom XDPoS config, have %v", cfg)
	}
}

// TestSetupGenesisBackfillsProgrammaticBuiltInPartialConfig tests setup genesis backfills programmatic built in partial config.
func TestSetupGenesisBackfillsProgrammaticBuiltInPartialConfig(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	genesis := DefaultGenesisBlock()
	genesis.Config = &params.ChainConfig{
		ChainID: new(big.Int).Set(params.XDCMainnetChainConfig.ChainID),
	}

	cfg, hash, _, err := SetupGenesisBlock(db, genesis)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hash != params.MainnetGenesisHash {
		t.Fatalf("unexpected hash: have %s want %s", hash.Hex(), params.MainnetGenesisHash.Hex())
	}
	if cfg == nil {
		t.Fatal("expected resolved config")
	}
	assertBuiltInBackfillForkFieldsEqual(t, cfg, params.XDCMainnetChainConfig)
	if cfg.TRC21IssuerSMC != params.XDCMainnetChainConfig.TRC21IssuerSMC {
		t.Fatalf("unexpected TRC21 issuer: have %s want %s", cfg.TRC21IssuerSMC.Hex(), params.XDCMainnetChainConfig.TRC21IssuerSMC.Hex())
	}
	if cfg.XDCXListingSMC != params.XDCMainnetChainConfig.XDCXListingSMC {
		t.Fatalf("unexpected XDCX listing SMC: have %s want %s", cfg.XDCXListingSMC.Hex(), params.XDCMainnetChainConfig.XDCXListingSMC.Hex())
	}
	if cfg.RelayerRegistrationSMC != params.XDCMainnetChainConfig.RelayerRegistrationSMC {
		t.Fatalf("unexpected relayer registration SMC: have %s want %s", cfg.RelayerRegistrationSMC.Hex(), params.XDCMainnetChainConfig.RelayerRegistrationSMC.Hex())
	}
	if cfg.LendingRegistrationSMC != params.XDCMainnetChainConfig.LendingRegistrationSMC {
		t.Fatalf("unexpected lending registration SMC: have %s want %s", cfg.LendingRegistrationSMC.Hex(), params.XDCMainnetChainConfig.LendingRegistrationSMC.Hex())
	}
	if !params.XDPoSConfigEqual(cfg.XDPoS, params.XDCMainnetChainConfig.XDPoS) {
		t.Fatalf("unexpected XDPoS config: have %v want %v", cfg.XDPoS, params.XDCMainnetChainConfig.XDPoS)
	}
}

// TestSetupGenesisBackfillsProgrammaticBuiltInPartialConfigWithForkField tests setup genesis backfills programmatic built in partial config with an xd c fork field.
func TestSetupGenesisBackfillsProgrammaticBuiltInPartialConfigWithForkField(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	genesis := DefaultGenesisBlock()
	genesis.Config = &params.ChainConfig{
		ChainID:      new(big.Int).Set(params.XDCMainnetChainConfig.ChainID),
		TIP2019Block: new(big.Int).Set(params.XDCMainnetChainConfig.TIP2019Block),
	}

	cfg, hash, _, err := SetupGenesisBlock(db, genesis)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hash != params.MainnetGenesisHash {
		t.Fatalf("unexpected hash: have %s want %s", hash.Hex(), params.MainnetGenesisHash.Hex())
	}
	if cfg == nil {
		t.Fatal("expected resolved config")
	}
	if cfg.TIP2019Block == nil || cfg.TIP2019Block.Cmp(params.XDCMainnetChainConfig.TIP2019Block) != 0 {
		t.Fatalf("unexpected TIP2019 block: have %v want %v", cfg.TIP2019Block, params.XDCMainnetChainConfig.TIP2019Block)
	}
	if cfg.TRC21IssuerSMC != params.XDCMainnetChainConfig.TRC21IssuerSMC {
		t.Fatalf("unexpected TRC21 issuer: have %s want %s", cfg.TRC21IssuerSMC.Hex(), params.XDCMainnetChainConfig.TRC21IssuerSMC.Hex())
	}
	if cfg.XDCXListingSMC != params.XDCMainnetChainConfig.XDCXListingSMC {
		t.Fatalf("unexpected XDCX listing SMC: have %s want %s", cfg.XDCXListingSMC.Hex(), params.XDCMainnetChainConfig.XDCXListingSMC.Hex())
	}
	if cfg.RelayerRegistrationSMC != params.XDCMainnetChainConfig.RelayerRegistrationSMC {
		t.Fatalf("unexpected relayer registration SMC: have %s want %s", cfg.RelayerRegistrationSMC.Hex(), params.XDCMainnetChainConfig.RelayerRegistrationSMC.Hex())
	}
	if cfg.LendingRegistrationSMC != params.XDCMainnetChainConfig.LendingRegistrationSMC {
		t.Fatalf("unexpected lending registration SMC: have %s want %s", cfg.LendingRegistrationSMC.Hex(), params.XDCMainnetChainConfig.LendingRegistrationSMC.Hex())
	}
}

// TestSetupGenesisBackfillsProgrammaticBuiltInPartialV2Config tests setup genesis backfills programmatic built in partial v 2 config.
func TestSetupGenesisBackfillsProgrammaticBuiltInPartialV2Config(t *testing.T) {
	tests := []struct {
		name   string
		config *params.ChainConfig
	}{
		{
			name: "empty v2",
			config: &params.ChainConfig{
				ChainID: new(big.Int).Set(params.XDCMainnetChainConfig.ChainID),
				XDPoS:   &params.XDPoSConfig{V2: &params.V2{}},
			},
		},
		{
			name: "switch epoch only",
			config: &params.ChainConfig{
				ChainID: new(big.Int).Set(params.XDCMainnetChainConfig.ChainID),
				XDPoS: &params.XDPoSConfig{V2: &params.V2{
					SwitchEpoch: params.XDCMainnetChainConfig.XDPoS.V2.SwitchEpoch,
				}},
			},
		},
		{
			name: "current config only",
			config: &params.ChainConfig{
				ChainID: new(big.Int).Set(params.XDCMainnetChainConfig.ChainID),
				XDPoS: &params.XDPoSConfig{V2: &params.V2{
					CurrentConfig: &params.V2Config{
						TimeoutPeriod: params.XDCMainnetChainConfig.XDPoS.V2.CurrentConfig.TimeoutPeriod,
					},
				}},
			},
		},
		{
			name: "nested timeout config only",
			config: &params.ChainConfig{
				ChainID: new(big.Int).Set(params.XDCMainnetChainConfig.ChainID),
				XDPoS: &params.XDPoSConfig{V2: &params.V2{
					CurrentConfig: &params.V2Config{
						ExpTimeoutConfig: params.ExpTimeoutConfig{
							Base: params.XDCMainnetChainConfig.XDPoS.V2.CurrentConfig.ExpTimeoutConfig.Base,
						},
					},
				}},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			db := rawdb.NewMemoryDatabase()
			genesis := DefaultGenesisBlock()
			genesis.Config = test.config

			cfg, hash, _, err := SetupGenesisBlock(db, genesis)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if hash != params.MainnetGenesisHash {
				t.Fatalf("unexpected hash: have %s want %s", hash.Hex(), params.MainnetGenesisHash.Hex())
			}
			if cfg == nil {
				t.Fatal("expected resolved config")
			}
			assertBuiltInBackfillForkFieldsEqual(t, cfg, params.XDCMainnetChainConfig)
			if !params.XDPoSConfigEqual(cfg.XDPoS, params.XDCMainnetChainConfig.XDPoS) {
				t.Fatalf("unexpected XDPoS config: have %v want %v", cfg.XDPoS, params.XDCMainnetChainConfig.XDPoS)
			}
		})
	}
}

// TestSetupGenesisPreservesStoredCustomGenesisWithBuiltInChainID tests setup genesis preserves stored custom genesis with built in chain id.
func TestSetupGenesisPreservesStoredCustomGenesisWithBuiltInChainID(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	genesis := &Genesis{
		Config: &params.ChainConfig{
			ChainID:                new(big.Int).Set(params.XDCMainnetChainConfig.ChainID),
			TIPTRC21FeeBlock:       big.NewInt(0),
			Gas50xBlock:            big.NewInt(1),
			TRC21IssuerSMC:         params.TestnetChainConfig.TRC21IssuerSMC,
			XDCXListingSMC:         params.TestnetChainConfig.XDCXListingSMC,
			RelayerRegistrationSMC: params.TestnetChainConfig.RelayerRegistrationSMC,
			LendingRegistrationSMC: params.TestnetChainConfig.LendingRegistrationSMC,
			Ethash:                 new(params.EthashConfig),
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
	if cfg.XDPoS != nil {
		t.Fatalf("expected stored custom genesis to remain non-XDPoS, have %v", cfg.XDPoS)
	}
}

// TestSetupGenesisAllowsCustomChainWithIntentionallyNilOsakaBlock tests setup genesis allows custom chain with intentionally nil osaka block.
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

// TestSetupGenesisCustomChainProvidedGenesisThenRestartWithoutGenesis tests setup genesis custom chain provided genesis then restart without genesis.
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

// TestSetupGenesisCustomChainRestartDoesNotPersistInferredZeroValueFields tests setup genesis custom chain restart does not persist inferred zero value fields.
func TestSetupGenesisCustomChainRestartDoesNotPersistInferredZeroValueFields(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	genesis := &Genesis{
		Config: &params.ChainConfig{
			ChainID:        big.NewInt(8889),
			DAOForkBlock:   big.NewInt(0),
			DAOForkSupport: false,
			Ethash:         new(params.EthashConfig),
		},
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

	rawBefore, err := rawdb.ReadChainConfigJSON(db, hash)
	if err != nil {
		t.Fatalf("failed to read stored chain config JSON: %v", err)
	}
	var storedKeys map[string]json.RawMessage
	if err := json.Unmarshal(rawBefore, &storedKeys); err != nil {
		t.Fatalf("failed to inspect stored chain config JSON: %v", err)
	}
	if _, ok := storedKeys["daoForkBlock"]; !ok {
		t.Fatalf("expected daoForkBlock to be persisted, have %s", rawBefore)
	}
	if _, ok := storedKeys["daoForkSupport"]; ok {
		t.Fatalf("expected inferred false daoForkSupport to remain omitted, have %s", rawBefore)
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
	if restartedCfg.DAOForkBlock == nil || restartedCfg.DAOForkBlock.Cmp(big.NewInt(0)) != 0 {
		t.Fatalf("expected daoForkBlock to remain 0 after restart, have %v", restartedCfg.DAOForkBlock)
	}
	if restartedCfg.DAOForkSupport {
		t.Fatal("expected daoForkSupport to remain false after restart")
	}

	rawAfter, err := rawdb.ReadChainConfigJSON(db, hash)
	if err != nil {
		t.Fatalf("failed to read persisted chain config JSON after restart: %v", err)
	}
	if !bytes.Equal(rawAfter, rawBefore) {
		t.Fatalf("expected stored raw config to remain unchanged on restart: before=%s after=%s", rawBefore, rawAfter)
	}
}

func TestSetupGenesisRestartWithoutRewriteDoesNotNeedJSONMarshal(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	cfg := params.XDCMainnetChainConfig.Clone()
	cfg.ChainID = big.NewInt(8890)
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

	_, hash, _, err := SetupGenesisBlock(db, genesis)
	if err != nil {
		t.Fatalf("initial SetupGenesisBlock failed: %v", err)
	}

	deps := defaultGenesisDeps
	deps.jsonMarshal = func(v any) ([]byte, error) {
		return nil, errors.New("unexpected json marshal")
	}
	deps.writeChainConfig = func(db ethdb.KeyValueWriter, gotHash common.Hash, cfg *params.ChainConfig) {
		t.Fatalf("unexpected chain-config rewrite for %s", gotHash.Hex())
	}

	restartedCfg, restartedHash, _, err := setupGenesisBlockWithDeps(db, nil, deps, GenesisStartupOptions{})
	if err != nil {
		t.Fatalf("restart SetupGenesisBlock failed: %v", err)
	}
	if restartedCfg == nil {
		t.Fatal("expected restart config")
	}
	if restartedHash != hash {
		t.Fatalf("unexpected restart genesis hash: have %s want %s", restartedHash.Hex(), hash.Hex())
	}
	if restartedCfg.ChainID == nil || restartedCfg.ChainID.Cmp(cfg.ChainID) != 0 {
		t.Fatalf("expected restart to preserve stored chain ID, have %v want %v", restartedCfg.ChainID, cfg.ChainID)
	}
}

// TestSetupGenesisRejectsPartialLegacyCustomXDPoSConfig tests setup genesis rejects partial legacy custom xd po s configs that rely on non-migrated field backfill.
func TestSetupGenesisRejectsPartialLegacyCustomXDPoSConfig(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	genesis := &Genesis{
		Config: &params.ChainConfig{
			ChainID:      big.NewInt(4545),
			TIP2019Block: big.NewInt(0),
			XDPoS:        &params.XDPoSConfig{MaxMasternodesV2: 108},
		},
		ExtraData:  make([]byte, 32+crypto.SignatureLength),
		Alloc:      types.GenesisAlloc{{1}: {Balance: big.NewInt(1)}},
		GasLimit:   4700000,
		Difficulty: big.NewInt(1),
	}

	if cfg, hash, compatErr, err := SetupGenesisBlock(db, genesis); !errors.Is(err, params.ErrMissingForkSwitch) {
		t.Fatalf("expected missing fork switch error, have %v want %v", err, params.ErrMissingForkSwitch)
	} else if compatErr != nil {
		t.Fatalf("expected no compatibility error alongside validation failure, have %v", compatErr)
	} else if hash != (common.Hash{}) {
		t.Fatalf("expected no resolved custom genesis hash, have %s", hash.Hex())
	} else if cfg != nil {
		t.Fatalf("expected no resolved chain config for incomplete custom config, have %v", cfg)
	}
}

// TestSetupGenesisBlockAllowsPlainCustomEthashChainWithoutXDCForkFields tests setup genesis block allows plain custom ethash chain without xdc fork fields.
func TestSetupGenesisBlockAllowsPlainCustomEthashChainWithoutXDCForkFields(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	genesis := &Genesis{
		Config: &params.ChainConfig{
			ChainID:        big.NewInt(1234),
			HomesteadBlock: big.NewInt(0),
			Ethash:         new(params.EthashConfig),
		},
		Alloc: types.GenesisAlloc{
			{1}: {Balance: big.NewInt(1)},
		},
		GasLimit:   4700000,
		Difficulty: big.NewInt(1),
	}

	cfg, hash, _, err := SetupGenesisBlock(db, genesis)
	if err != nil {
		t.Fatalf("SetupGenesisBlock failed: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected resolved config")
	}
	if hash != genesis.ToBlock().Hash() {
		t.Fatalf("unexpected genesis hash: have %s want %s", hash.Hex(), genesis.ToBlock().Hash().Hex())
	}
	if cfg.TIPTRC21FeeBlock != nil {
		t.Fatalf("expected TIPTRC21FeeBlock to remain nil for plain custom ethash chain, have %v", cfg.TIPTRC21FeeBlock)
	}
	if cfg.TRC21IssuerSMC != (common.Address{}) {
		t.Fatalf("expected no XDC system contract backfill for plain custom ethash chain, have %s", cfg.TRC21IssuerSMC.Hex())
	}
}

// TestSetupGenesisBlockRejectsInvalidXDPoSV2Config tests setup genesis block rejects incomplete xdpos v2 config.
func TestSetupGenesisBlockRejectsInvalidXDPoSV2Config(t *testing.T) {
	genesis := &Genesis{
		Config: &params.ChainConfig{
			ChainID:                big.NewInt(4545),
			TIPTRC21FeeBlock:       big.NewInt(1),
			Gas50xBlock:            big.NewInt(1),
			TRC21IssuerSMC:         params.TestnetChainConfig.TRC21IssuerSMC,
			XDCXListingSMC:         params.TestnetChainConfig.XDCXListingSMC,
			RelayerRegistrationSMC: params.TestnetChainConfig.RelayerRegistrationSMC,
			LendingRegistrationSMC: params.TestnetChainConfig.LendingRegistrationSMC,
			XDPoS: &params.XDPoSConfig{
				Epoch:                900,
				FoundationWalletAddr: params.TestnetChainConfig.XDPoS.FoundationWalletAddr,
				MaxMasternodesV2:     108,
			},
		},
		ExtraData: make([]byte, 32+crypto.SignatureLength),
		Alloc: types.GenesisAlloc{
			{1}: {Balance: big.NewInt(1)},
		},
		GasLimit:   4700000,
		Difficulty: big.NewInt(1),
	}

	cfg, hash, compatErr, err := SetupGenesisBlock(rawdb.NewMemoryDatabase(), genesis)
	if !errors.Is(err, params.ErrMissingForkSwitch) {
		t.Fatalf("unexpected error: have %v want %v", err, params.ErrMissingForkSwitch)
	}
	if err == nil || !strings.Contains(err.Error(), "XDPoS.V2") {
		t.Fatalf("unexpected error string: %v", err)
	}
	if compatErr != nil {
		t.Fatalf("unexpected compatibility error: %v", compatErr)
	}
	if cfg != nil {
		t.Fatalf("expected nil config, have %v", cfg)
	}
	if hash != (common.Hash{}) {
		t.Fatalf("expected zero hash on rejected startup, have %s", hash.Hex())
	}
}

// TestSetupGenesisBlockRejectsXDPoSV2MissingDefaultConfig tests setup genesis block rejects xdpos v2 schedules without a round zero default.
func TestSetupGenesisBlockRejectsXDPoSV2MissingDefaultConfig(t *testing.T) {
	genesis := &Genesis{
		Config: &params.ChainConfig{
			ChainID:                big.NewInt(4545),
			TIPTRC21FeeBlock:       big.NewInt(1),
			Gas50xBlock:            big.NewInt(1),
			TRC21IssuerSMC:         params.TestnetChainConfig.TRC21IssuerSMC,
			XDCXListingSMC:         params.TestnetChainConfig.XDCXListingSMC,
			RelayerRegistrationSMC: params.TestnetChainConfig.RelayerRegistrationSMC,
			LendingRegistrationSMC: params.TestnetChainConfig.LendingRegistrationSMC,
			XDPoS: &params.XDPoSConfig{
				Epoch:                900,
				FoundationWalletAddr: params.TestnetChainConfig.XDPoS.FoundationWalletAddr,
				MaxMasternodesV2:     108,
				V2: &params.V2{
					SwitchEpoch:   1,
					SwitchBlock:   big.NewInt(900),
					CurrentConfig: &params.V2Config{SwitchRound: 9, MinePeriod: 2, TimeoutPeriod: 10},
					AllConfigs: map[uint64]*params.V2Config{
						9: {SwitchRound: 9, MinePeriod: 2, TimeoutPeriod: 10},
					},
				},
			},
		},
		ExtraData: make([]byte, 32+crypto.SignatureLength),
		Alloc: types.GenesisAlloc{
			{1}: {Balance: big.NewInt(1)},
		},
		GasLimit:   4700000,
		Difficulty: big.NewInt(1),
	}

	cfg, hash, compatErr, err := SetupGenesisBlock(rawdb.NewMemoryDatabase(), genesis)
	if !errors.Is(err, params.ErrMissingForkSwitch) {
		t.Fatalf("unexpected error: have %v want %v", err, params.ErrMissingForkSwitch)
	}
	if err == nil || !strings.Contains(err.Error(), "XDPoS.V2.AllConfigs[0]") {
		t.Fatalf("unexpected error string: %v", err)
	}
	if compatErr != nil {
		t.Fatalf("unexpected compatibility error: %v", compatErr)
	}
	if cfg != nil {
		t.Fatalf("expected nil config, have %v", cfg)
	}
	if hash != (common.Hash{}) {
		t.Fatalf("expected zero hash on rejected startup, have %s", hash.Hex())
	}
}

// TestSetupGenesisBlockRejectsXDPoSV2NilDefaultConfig tests setup genesis block rejects xdpos v2 schedules with a nil round zero default.
func TestSetupGenesisBlockRejectsXDPoSV2NilDefaultConfig(t *testing.T) {
	genesis := &Genesis{
		Config: &params.ChainConfig{
			ChainID:                big.NewInt(4545),
			TIPTRC21FeeBlock:       big.NewInt(1),
			Gas50xBlock:            big.NewInt(1),
			TRC21IssuerSMC:         params.TestnetChainConfig.TRC21IssuerSMC,
			XDCXListingSMC:         params.TestnetChainConfig.XDCXListingSMC,
			RelayerRegistrationSMC: params.TestnetChainConfig.RelayerRegistrationSMC,
			LendingRegistrationSMC: params.TestnetChainConfig.LendingRegistrationSMC,
			XDPoS: &params.XDPoSConfig{
				Epoch:                900,
				FoundationWalletAddr: params.TestnetChainConfig.XDPoS.FoundationWalletAddr,
				MaxMasternodesV2:     108,
				V2: &params.V2{
					SwitchEpoch:   1,
					SwitchBlock:   big.NewInt(900),
					CurrentConfig: &params.V2Config{SwitchRound: 0, MinePeriod: 2, TimeoutPeriod: 10},
					AllConfigs: map[uint64]*params.V2Config{
						0: nil,
					},
				},
			},
		},
		ExtraData: make([]byte, 32+crypto.SignatureLength),
		Alloc: types.GenesisAlloc{
			{1}: {Balance: big.NewInt(1)},
		},
		GasLimit:   4700000,
		Difficulty: big.NewInt(1),
	}

	cfg, hash, compatErr, err := SetupGenesisBlock(rawdb.NewMemoryDatabase(), genesis)
	if !errors.Is(err, params.ErrMissingForkSwitch) {
		t.Fatalf("unexpected error: have %v want %v", err, params.ErrMissingForkSwitch)
	}
	if err == nil || !strings.Contains(err.Error(), "XDPoS.V2.AllConfigs[0]") {
		t.Fatalf("unexpected error string: %v", err)
	}
	if compatErr != nil {
		t.Fatalf("unexpected compatibility error: %v", compatErr)
	}
	if cfg != nil {
		t.Fatalf("expected nil config, have %v", cfg)
	}
	if hash != (common.Hash{}) {
		t.Fatalf("expected zero hash on rejected startup, have %s", hash.Hex())
	}
}

// TestGenesisCommitAllowsPlainCustomEthashChainWithoutXDCForkFields tests genesis commit allows plain custom ethash chain without xdc fork fields.
func TestGenesisCommitAllowsPlainCustomEthashChainWithoutXDCForkFields(t *testing.T) {
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
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestSetupGenesisAllowsPlainCustomEthashChainWithoutXDCForkFields tests setup genesis allows plain custom ethash chain without xdc fork fields.
func TestSetupGenesisAllowsPlainCustomEthashChainWithoutXDCForkFields(t *testing.T) {
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

	cfg, _, _, err := SetupGenesisBlock(db, genesis)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected resolved config")
	}
	if cfg.TIPTRC21FeeBlock != nil {
		t.Fatalf("expected TIPTRC21FeeBlock to remain nil for plain custom ethash chain, have %v", cfg.TIPTRC21FeeBlock)
	}
	if cfg.TRC21IssuerSMC != (common.Address{}) {
		t.Fatalf("expected no XDC system contract backfill for plain custom ethash chain, have %s", cfg.TRC21IssuerSMC.Hex())
	}
}

// TestSetupGenesisRejectsCustomGenesisMissingFoundationWalletAddr tests setup genesis rejects custom genesis missing foundation wallet addr.
func TestSetupGenesisRejectsCustomGenesisMissingFoundationWalletAddr(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	cfg := params.TestnetChainConfig.Clone()
	cfg.ChainID = big.NewInt(62627)
	cfg.XDPoS = cfg.XDPoS.Clone()
	cfg.XDPoS.FoundationWalletAddr = common.Address{}

	genesis := &Genesis{
		Config: cfg,
		Alloc: types.GenesisAlloc{
			{1}: {Balance: big.NewInt(1)},
		},
		GasLimit:   4700000,
		Difficulty: big.NewInt(1),
	}

	cfg, hash, _, err := SetupGenesisBlock(db, genesis)
	if !errors.Is(err, params.ErrMissingForkSwitch) {
		t.Fatalf("unexpected error: have %v want %v", err, params.ErrMissingForkSwitch)
	}
	if hash != (common.Hash{}) {
		t.Fatalf("unexpected hash: have %s want %s", hash.Hex(), common.Hash{}.Hex())
	}
	if cfg != nil {
		t.Fatalf("expected nil config on invalid custom genesis, have %v", cfg)
	}
	if err == nil || !strings.Contains(err.Error(), "XDPoS.FoundationWalletAddr") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestSetupGenesisBackfillsTIPTRC21FeeBlockForLocalnetJSONConfig tests setup genesis backfills tiptrc 21 fee block for localnet json config.
func TestSetupGenesisBackfillsTIPTRC21FeeBlockForLocalnetJSONConfig(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	var cfg params.ChainConfig
	raw := []byte(`{"chainId":5151,"ethash":{}}`)
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("failed to unmarshal chain config: %v", err)
	}

	genesis := &Genesis{
		Config: &cfg,
		Alloc: types.GenesisAlloc{
			{1}: {Balance: big.NewInt(1)},
		},
		GasLimit:   4700000,
		Difficulty: big.NewInt(1),
	}

	resolvedCfg, _, _, err := SetupGenesisBlock(db, genesis)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resolvedCfg == nil || resolvedCfg.TIPTRC21FeeBlock == nil || resolvedCfg.TIPTRC21FeeBlock.Cmp(big.NewInt(0)) != 0 {
		t.Fatalf("expected TIPTRC21FeeBlock to be backfilled to 0, have %v", resolvedCfg)
	}
}

// TestSetupGenesisBackfillsProgrammaticZeroRequiredAddressesWhileBackfillingNilPointers tests setup genesis backfills required addresses for programmatic configs while backfilling nil pointers.
func TestSetupGenesisBackfillsProgrammaticZeroRequiredAddressesWhileBackfillingNilPointers(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	genesis := &Genesis{
		Config: &params.ChainConfig{
			ChainID:          big.NewInt(5151),
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
	legacyDefaults := params.LocalnetChainConfig
	if cfg.TRC21IssuerSMC != legacyDefaults.TRC21IssuerSMC {
		t.Fatalf("expected TRC21IssuerSMC to be backfilled, have %s want %s", cfg.TRC21IssuerSMC.Hex(), legacyDefaults.TRC21IssuerSMC.Hex())
	}
	if cfg.XDCXListingSMC != legacyDefaults.XDCXListingSMC {
		t.Fatalf("expected XDCXListingSMC to be backfilled, have %s want %s", cfg.XDCXListingSMC.Hex(), legacyDefaults.XDCXListingSMC.Hex())
	}
	if cfg.RelayerRegistrationSMC != legacyDefaults.RelayerRegistrationSMC {
		t.Fatalf("expected RelayerRegistrationSMC to be backfilled, have %s want %s", cfg.RelayerRegistrationSMC.Hex(), legacyDefaults.RelayerRegistrationSMC.Hex())
	}
	if cfg.LendingRegistrationSMC != legacyDefaults.LendingRegistrationSMC {
		t.Fatalf("expected LendingRegistrationSMC to be backfilled, have %s want %s", cfg.LendingRegistrationSMC.Hex(), legacyDefaults.LendingRegistrationSMC.Hex())
	}
}

// TestNewBlockChainPreservesSetupGenesisBlockError tests new block chain preserves setup genesis block error.
func TestNewBlockChainPreservesSetupGenesisBlockError(t *testing.T) {
	db := rawdb.NewMemoryDatabase()

	bc, err := NewBlockChain(db, nil, new(Genesis), ethash.NewFaker(), vm.Config{})
	if bc != nil {
		bc.Stop()
		t.Fatal("expected nil blockchain")
	}
	if !errors.Is(err, errGenesisNoConfig) {
		t.Fatalf("unexpected error: have %v want %v", err, errGenesisNoConfig)
	}
}

// TestSetupGenesisBlockBackfillsStoredLegacyCustomConfigMissingMaxMasternodesV2WithCustomMigratedFields tests setup genesis block backfills stored legacy custom config missing max masternodes v 2 with custom migrated fields.
func TestSetupGenesisBlockBackfillsStoredLegacyCustomConfigMissingMaxMasternodesV2WithCustomMigratedFields(t *testing.T) {
	newLegacyStyleCustomXDPoSGenesis := func() *Genesis {
		xdposCfg := params.LocalnetChainConfig.XDPoS.Clone()
		cfg := params.LocalnetChainConfig.Clone()
		cfg.ChainID = big.NewInt(9798)
		cfg.TRC21IssuerSMC = common.HexToAddress("0x0000000000000000000000000000000000000001")
		cfg.XDPoS = xdposCfg
		return &Genesis{
			Config:    cfg,
			ExtraData: make([]byte, 32+crypto.SignatureLength),
			Alloc: types.GenesisAlloc{
				{1}: {Balance: big.NewInt(1)},
			},
			GasLimit:   4700000,
			Difficulty: big.NewInt(1),
		}
	}

	db := rawdb.NewMemoryDatabase()
	storedGenesis := newLegacyStyleCustomXDPoSGenesis()
	block := storedGenesis.MustCommit(db)

	rawCfg, err := rawdb.ReadChainConfigJSON(db, block.Hash())
	if err != nil {
		t.Fatalf("failed to read raw chain config: %v", err)
	}
	updatedRawCfg, err := removeXDPoSMaxMasternodesV2FromRawConfig(rawCfg)
	if err != nil {
		t.Fatalf("failed to remove XDPoS.maxMasternodesV2 from raw config: %v", err)
	}
	if err := db.Put(testConfigKey(block.Hash()), updatedRawCfg); err != nil {
		t.Fatalf("failed to write modified raw chain config: %v", err)
	}

	resolvedCfg, resolvedHash, _, err := SetupGenesisBlock(db, nil)
	if err != nil {
		t.Fatalf("SetupGenesisBlock failed: %v", err)
	}
	if resolvedHash != block.Hash() {
		t.Fatalf("unexpected genesis hash: have %s want %s", resolvedHash.Hex(), block.Hash().Hex())
	}
	if resolvedCfg == nil || resolvedCfg.XDPoS == nil {
		t.Fatalf("expected resolved XDPoS config, have %v", resolvedCfg)
	}
	if resolvedCfg.XDPoS.MaxMasternodesV2 != params.LocalnetChainConfig.XDPoS.MaxMasternodesV2 {
		t.Fatalf("expected MaxMasternodesV2 to be backfilled to %d, got %d", params.LocalnetChainConfig.XDPoS.MaxMasternodesV2, resolvedCfg.XDPoS.MaxMasternodesV2)
	}
	if resolvedCfg.TRC21IssuerSMC != storedGenesis.Config.TRC21IssuerSMC {
		t.Fatalf("expected custom TRC21 issuer to be preserved: have %s want %s", resolvedCfg.TRC21IssuerSMC.Hex(), storedGenesis.Config.TRC21IssuerSMC.Hex())
	}
}

// TestSetupGenesisBlockBackfillsProvidedCustomConfigMissingMaxMasternodesV2WithCustomMigratedFields tests setup genesis block backfills provided custom config missing max masternodes v 2 with custom migrated fields.
func TestSetupGenesisBlockBackfillsProvidedCustomConfigMissingMaxMasternodesV2WithCustomMigratedFields(t *testing.T) {
	xdposCfg := params.LocalnetChainConfig.XDPoS.Clone()
	xdposCfg.MaxMasternodesV2 = 0
	xdposCfg.Reward = 251
	genesisCfg := params.LocalnetChainConfig.Clone()
	genesisCfg.ChainID = big.NewInt(9798)
	genesisCfg.TRC21IssuerSMC = common.HexToAddress("0x0000000000000000000000000000000000000001")
	genesisCfg.XDPoS = xdposCfg

	genesis := &Genesis{
		Config:    genesisCfg,
		ExtraData: make([]byte, 32+crypto.SignatureLength),
		Alloc: types.GenesisAlloc{
			{1}: {Balance: big.NewInt(1)},
		},
		GasLimit:   4700000,
		Difficulty: big.NewInt(1),
	}

	resolvedCfg, _, _, err := SetupGenesisBlock(rawdb.NewMemoryDatabase(), genesis)
	if err != nil {
		t.Fatalf("SetupGenesisBlock failed: %v", err)
	}
	if resolvedCfg == nil || resolvedCfg.XDPoS == nil {
		t.Fatalf("expected resolved XDPoS config, have %v", resolvedCfg)
	}
	if resolvedCfg.XDPoS.MaxMasternodesV2 != params.LocalnetChainConfig.XDPoS.MaxMasternodesV2 {
		t.Fatalf("expected MaxMasternodesV2 to be backfilled to %d, got %d", params.LocalnetChainConfig.XDPoS.MaxMasternodesV2, resolvedCfg.XDPoS.MaxMasternodesV2)
	}
	if resolvedCfg.XDPoS.Reward != xdposCfg.Reward {
		t.Fatalf("expected explicit Reward to be preserved: have %d want %d", resolvedCfg.XDPoS.Reward, xdposCfg.Reward)
	}
	if resolvedCfg.TRC21IssuerSMC != genesisCfg.TRC21IssuerSMC {
		t.Fatalf("expected custom TRC21 issuer to be preserved: have %s want %s", resolvedCfg.TRC21IssuerSMC.Hex(), genesisCfg.TRC21IssuerSMC.Hex())
	}
}

// TestSetupGenesisBlockPreservesExplicitProvidedCustomMaxMasternodesV2WithoutLegacyBackfill tests setup genesis block preserves explicit provided custom max masternodes v 2 without legacy backfill.
func TestSetupGenesisBlockPreservesExplicitProvidedCustomMaxMasternodesV2WithoutLegacyBackfill(t *testing.T) {
	const explicitMaxMasternodesV2 = 77

	xdposCfg := params.LocalnetChainConfig.XDPoS.Clone()
	xdposCfg.MaxMasternodesV2 = explicitMaxMasternodesV2
	genesisCfg := params.LocalnetChainConfig.Clone()
	genesisCfg.ChainID = big.NewInt(9798)
	genesisCfg.TRC21IssuerSMC = common.HexToAddress("0x0000000000000000000000000000000000000001")
	genesisCfg.XDPoS = xdposCfg

	genesis := &Genesis{
		Config:    genesisCfg,
		ExtraData: make([]byte, 32+crypto.SignatureLength),
		Alloc: types.GenesisAlloc{
			{1}: {Balance: big.NewInt(1)},
		},
		GasLimit:   4700000,
		Difficulty: big.NewInt(1),
	}

	resolvedCfg, _, _, err := SetupGenesisBlock(rawdb.NewMemoryDatabase(), genesis)
	if err != nil {
		t.Fatalf("SetupGenesisBlock failed: %v", err)
	}
	if resolvedCfg == nil || resolvedCfg.XDPoS == nil {
		t.Fatalf("expected resolved XDPoS config, have %v", resolvedCfg)
	}
	if resolvedCfg.XDPoS.MaxMasternodesV2 != explicitMaxMasternodesV2 {
		t.Fatalf("expected explicit MaxMasternodesV2 to be preserved: have %d want %d", resolvedCfg.XDPoS.MaxMasternodesV2, explicitMaxMasternodesV2)
	}
	if resolvedCfg.TRC21IssuerSMC != genesisCfg.TRC21IssuerSMC {
		t.Fatalf("expected custom TRC21 issuer to be preserved: have %s want %s", resolvedCfg.TRC21IssuerSMC.Hex(), genesisCfg.TRC21IssuerSMC.Hex())
	}
}

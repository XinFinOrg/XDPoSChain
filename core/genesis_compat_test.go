package core

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/startup"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/ethdb"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/davecgh/go-spew/spew"
)

// TestSetupGenesisAcceptsProvidedBuiltInHashCustomConfigOnEmptyDBWithExplicitRecovery
// tests setup genesis accepts a built-in hash custom config on empty db when
// the operator explicitly opts into built-in override recovery.
func TestSetupGenesisAcceptsProvidedBuiltInHashCustomConfigOnEmptyDBWithExplicitRecovery(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	genesis := DefaultTestnetGenesisBlock()
	genesis.Config = genesis.Config.Clone()
	genesis.Config.ChainID = big.NewInt(99999)

	cfg, hash, compatErr, err := SetupGenesisBlockWithOverride(db, genesis, true)
	if err != nil {
		t.Fatalf("SetupGenesisBlock failed: %v", err)
	}
	if compatErr != nil {
		t.Fatalf("unexpected compatibility error: %v", compatErr)
	}
	if cfg == nil {
		t.Fatal("expected returned config")
	}
	if hash != params.TestnetGenesisHash {
		t.Fatalf("unexpected hash: have %s want %s", hash.Hex(), params.TestnetGenesisHash.Hex())
	}
	if cfg.ChainID == nil || cfg.ChainID.Cmp(big.NewInt(99999)) != 0 {
		t.Fatalf("expected custom chain id to be preserved, have %v", cfg.ChainID)
	}
	persistedCfg, err := rawdb.ReadChainConfig(db, hash)
	if err != nil {
		t.Fatalf("failed to read persisted chain config: %v", err)
	}
	if persistedCfg == nil {
		t.Fatal("expected persisted custom config")
	}
	if persistedCfg.ChainID == nil || persistedCfg.ChainID.Cmp(big.NewInt(99999)) != 0 {
		t.Fatalf("expected persisted custom chain id, have %v", persistedCfg.ChainID)
	}
}

// TestSetupGenesisReloadsPersistedBuiltInHashCustomConfigWithExplicitRecovery
// tests setup genesis reloads a persisted built-in hash custom config when the
// operator explicitly opts into built-in override recovery.
func TestSetupGenesisReloadsPersistedBuiltInHashCustomConfigWithExplicitRecovery(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	genesis := DefaultTestnetGenesisBlock()
	genesis.Config = genesis.Config.Clone()
	genesis.Config.ChainID = big.NewInt(99999)

	if _, _, _, err := SetupGenesisBlockWithOverride(db, genesis, true); err != nil {
		t.Fatalf("initial SetupGenesisBlock failed: %v", err)
	}

	cfg, hash, compatErr, err := SetupGenesisBlockWithOverride(db, nil, true)
	if err != nil {
		t.Fatalf("restart SetupGenesisBlock failed: %v", err)
	}
	if compatErr != nil {
		t.Fatalf("unexpected compatibility error: %v", compatErr)
	}
	if hash != params.TestnetGenesisHash {
		t.Fatalf("unexpected hash: have %s want %s", hash.Hex(), params.TestnetGenesisHash.Hex())
	}
	if cfg == nil {
		t.Fatal("expected returned config")
	}
	if cfg.ChainID == nil || cfg.ChainID.Cmp(big.NewInt(99999)) != 0 {
		t.Fatalf("expected persisted custom chain id on restart, have %v", cfg.ChainID)
	}
}

// TestSetupGenesisPreservesStoredBuiltInHashCustomConfigWhenProvidedBuiltInGenesisOnBlockZeroWithExplicitRecovery
// tests setup genesis preserves stored built-in hash custom config when the
// operator explicitly opts into built-in override recovery.
func TestSetupGenesisPreservesStoredBuiltInHashCustomConfigWhenProvidedBuiltInGenesisOnBlockZeroWithExplicitRecovery(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	genesis := DefaultTestnetGenesisBlock()
	genesis.Config = genesis.Config.Clone()
	genesis.Config.ChainID = big.NewInt(99999)

	if _, _, _, err := SetupGenesisBlockWithOverride(db, genesis, true); err != nil {
		t.Fatalf("initial SetupGenesisBlock failed: %v", err)
	}
	storedRawBefore, err := rawdb.ReadChainConfigJSON(db, params.TestnetGenesisHash)
	if err != nil {
		t.Fatalf("failed to read stored chain config before restart: %v", err)
	}

	provided := DefaultTestnetGenesisBlock()

	cfg, hash, compatErr, err := SetupGenesisBlockWithOverride(db, provided, true)
	if err != nil {
		t.Fatalf("restart SetupGenesisBlock failed: %v", err)
	}
	if compatErr != nil {
		t.Fatalf("unexpected compatibility error: %v", compatErr)
	}
	if hash != params.TestnetGenesisHash {
		t.Fatalf("unexpected hash: have %s want %s", hash.Hex(), params.TestnetGenesisHash.Hex())
	}
	if cfg == nil {
		t.Fatal("expected returned config")
	}
	if cfg.ChainID == nil || cfg.ChainID.Cmp(big.NewInt(99999)) != 0 {
		t.Fatalf("expected restart with bundled genesis to preserve stored custom chain id, have %v", cfg.ChainID)
	}

	storedRawAfter, err := rawdb.ReadChainConfigJSON(db, params.TestnetGenesisHash)
	if err != nil {
		t.Fatalf("failed to read stored chain config after restart: %v", err)
	}
	if !bytes.Equal(storedRawBefore, storedRawAfter) {
		t.Fatalf("expected bundled startup path to keep stored override config unchanged")
	}
}

// TestSetupGenesisRecognizesLegacyOverrideSchemaAndPromotesMarker tests writable
// startup recognizes v1 same-hash override storage before promoting it to the
// explicit override marker schema.
func TestSetupGenesisRecognizesLegacyOverrideSchemaAndPromotesMarker(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	DefaultTestnetGenesisBlock().MustCommit(db)

	legacyGenesis := DefaultTestnetGenesisBlock()
	legacyGenesis.Config = legacyGenesis.Config.Clone()
	legacyGenesis.Config.ChainID = big.NewInt(92929)
	rawdb.WriteChainConfig(db, params.TestnetGenesisHash, legacyGenesis.Config)

	marker, err := rawdb.ReadChainConfigOverride(db, params.TestnetGenesisHash)
	if err != nil {
		t.Fatalf("failed to read override marker: %v", err)
	}
	if marker {
		t.Fatal("did not expect override marker in v1 schema state")
	}

	resolvedGenesis, state, err := prepareSetupStoredConfigOverridesWithDeps(
		defaultGenesisDeps,
		db,
		params.TestnetGenesisHash,
		legacyGenesis.Config,
		legacyGenesis,
		legacyGenesis.ToBlock().Hash(),
		true,
	)
	if err != nil {
		t.Fatalf("prepareSetupStoredConfigOverridesWithDeps failed: %v", err)
	}
	if resolvedGenesis == nil {
		t.Fatal("expected legacy override reconciliation to keep provided genesis")
	}
	if state.markerPresent {
		t.Fatal("did not expect marker before writable migration")
	}
	if !state.legacyStoredOverride {
		t.Fatal("expected v1 same-hash override to be recognized as legacy override")
	}
	if !state.trustedOverride {
		t.Fatal("expected legacy override to be treated as trusted during writable startup")
	}

	cfg, hash, compatErr, err := SetupGenesisBlockWithOverride(db, legacyGenesis, true)
	if err != nil {
		t.Fatalf("SetupGenesisBlock failed: %v", err)
	}
	if compatErr != nil {
		t.Fatalf("unexpected compatibility error: %v", compatErr)
	}
	if hash != params.TestnetGenesisHash {
		t.Fatalf("unexpected hash: have %s want %s", hash.Hex(), params.TestnetGenesisHash.Hex())
	}
	if cfg == nil {
		t.Fatal("expected resolved config")
	}
	if cfg.ChainID == nil || cfg.ChainID.Cmp(legacyGenesis.Config.ChainID) != 0 {
		t.Fatalf("expected writable startup to preserve legacy override chain id, have %v want %v", cfg.ChainID, legacyGenesis.Config.ChainID)
	}

	marker, err = rawdb.ReadChainConfigOverride(db, params.TestnetGenesisHash)
	if err != nil {
		t.Fatalf("failed to read override marker after migration: %v", err)
	}
	if !marker {
		t.Fatal("expected writable startup to promote legacy override to explicit marker")
	}
}

// TestSetupGenesisAcceptsProvidedBuiltInHashConfigWithMissingFields tests setup genesis accepts provided built in hash config with missing fields.
func TestSetupGenesisAcceptsProvidedBuiltInHashConfigWithMissingFields(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	genesis := DefaultTestnetGenesisBlock()
	genesis.Config = genesis.Config.Clone()
	genesis.Config.EIP1559Block = nil

	cfg, hash, _, err := SetupGenesisBlock(db, genesis)
	if err != nil {
		t.Fatalf("SetupGenesisBlock failed: %v", err)
	}
	if hash != params.TestnetGenesisHash {
		t.Fatalf("unexpected hash: have %s want %s", hash.Hex(), params.TestnetGenesisHash.Hex())
	}
	if !chainConfigSemanticallyEqual(cfg, params.TestnetChainConfig) {
		t.Fatalf("unexpected config: have %v want %v", cfg, params.TestnetChainConfig)
	}
	if cfg.EIP1559Block == nil {
		t.Fatal("expected eip1559Block to be backfilled from built-in config")
	}

	persistedCfg, err := rawdb.ReadChainConfig(db, hash)
	if err != nil {
		t.Fatalf("failed to read persisted chain config: %v", err)
	}
	if persistedCfg == nil || persistedCfg.EIP1559Block == nil {
		t.Fatalf("expected persisted config with eip1559Block, have %v", persistedCfg)
	}
}

// TestSetupGenesisAcceptsStoredBuiltInHashDriftAtBlockZero tests setup genesis accepts stored built in hash drift at block zero.
func TestSetupGenesisAcceptsStoredBuiltInHashDriftAtBlockZero(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	DefaultTestnetGenesisBlock().MustCommit(db)

	stored := params.TestnetGenesisHash
	storedCfg := params.TestnetChainConfig.Clone()
	storedCfg.BerlinBlock = big.NewInt(100)
	rawCfg, err := json.Marshal(storedCfg)
	if err != nil {
		t.Fatalf("failed to marshal stored chain config: %v", err)
	}
	if err := db.Put(testConfigKey(stored), rawCfg); err != nil {
		t.Fatalf("failed to overwrite stored chain config: %v", err)
	}

	provided := DefaultTestnetGenesisBlock()
	cfg, hash, compatErr, err := SetupGenesisBlock(db, provided)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if compatErr != nil {
		t.Fatalf("unexpected compatibility error: %v", compatErr)
	}
	if hash != stored {
		t.Fatalf("unexpected hash: have %s want %s", hash.Hex(), stored.Hex())
	}
	if !chainConfigSemanticallyEqual(cfg, params.TestnetChainConfig) {
		t.Fatalf("expected corrected config to be accepted: have %v want %v", cfg, params.TestnetChainConfig)
	}
	persistedCfg, err := rawdb.ReadChainConfig(db, stored)
	if err != nil {
		t.Fatalf("failed to read persisted chain config: %v", err)
	}
	if !chainConfigSemanticallyEqual(persistedCfg, params.TestnetChainConfig) {
		t.Fatalf("expected stored config to be corrected at block zero, have %v want %v", persistedCfg, params.TestnetChainConfig)
	}
}

// TestSetupGenesisReturnsCompatErrorForStoredBuiltInHashDriftAfterFork tests setup genesis returns compat error for stored built in hash drift after fork.
func TestSetupGenesisReturnsCompatErrorForStoredBuiltInHashDriftAfterFork(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	genesisBlock := DefaultTestnetGenesisBlock().MustCommit(db)

	stored := params.TestnetGenesisHash
	storedCfg := params.TestnetChainConfig.Clone()
	storedCfg.BerlinBlock = big.NewInt(100)
	rawCfg, err := json.Marshal(storedCfg)
	if err != nil {
		t.Fatalf("failed to marshal stored chain config: %v", err)
	}
	if err := db.Put(testConfigKey(stored), rawCfg); err != nil {
		t.Fatalf("failed to overwrite stored chain config: %v", err)
	}

	head := types.NewBlockWithHeader(&types.Header{
		Number:     big.NewInt(101),
		ParentHash: genesisBlock.Hash(),
	})
	rawdb.WriteBlock(db, head)
	rawdb.WriteCanonicalHash(db, head.Hash(), head.NumberU64())
	rawdb.WriteHeadHeaderHash(db, head.Hash())
	rawdb.WriteHeadBlockHash(db, head.Hash())
	rawdb.WriteHeadFastBlockHash(db, head.Hash())

	provided := DefaultTestnetGenesisBlock()
	cfg, hash, compatErr, err := SetupGenesisBlock(db, provided)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	wantCompatErr := &params.ConfigCompatError{
		What:         "Berlin fork block",
		StoredConfig: big.NewInt(100),
		NewConfig:    new(big.Int).Set(params.TestnetChainConfig.BerlinBlock),
		RewindTo:     99,
	}
	if !reflect.DeepEqual(compatErr, wantCompatErr) {
		t.Fatalf("unexpected compatibility error: have %#v want %#v", compatErr, wantCompatErr)
	}
	if hash != stored {
		t.Fatalf("unexpected hash: have %s want %s", hash.Hex(), stored.Hex())
	}
	if !chainConfigSemanticallyEqual(cfg, params.TestnetChainConfig) {
		t.Fatalf("unexpected config: have %v want %v", cfg, params.TestnetChainConfig)
	}

	persistedCfg, err := rawdb.ReadChainConfig(db, stored)
	if err != nil {
		t.Fatalf("failed to read persisted chain config: %v", err)
	}
	if persistedCfg == nil || persistedCfg.BerlinBlock == nil || persistedCfg.BerlinBlock.Cmp(big.NewInt(100)) != 0 {
		t.Fatalf("expected stored config to remain unchanged, have %v", persistedCfg)
	}
}

// TestSetupGenesisRejectsStoredBuiltInHashDeclaredFields tests setup genesis rejects stored built in hash declared fields.
func TestSetupGenesisRejectsStoredBuiltInHashDeclaredFields(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	DefaultTestnetGenesisBlock().MustCommit(db)

	stored := params.TestnetGenesisHash
	storedCfg := params.TestnetChainConfig.Clone()
	storedCfg.ChainID = big.NewInt(99999)
	storedCfg.Ethash = new(params.EthashConfig)
	storedCfg.XDPoS = nil
	rawCfg, err := json.Marshal(storedCfg)
	if err != nil {
		t.Fatalf("failed to marshal stored chain config: %v", err)
	}
	rawCfg, err = setTopLevelFieldRawConfig(rawCfg, "XDPoS", json.RawMessage("null"))
	if err != nil {
		t.Fatalf("failed to set XDPoS to null in raw config: %v", err)
	}
	if err := db.Put(testConfigKey(stored), rawCfg); err != nil {
		t.Fatalf("failed to overwrite stored chain config: %v", err)
	}

	cfg, hash, compatErr, err := SetupGenesisBlock(db, nil)
	if !errors.Is(err, errGenesisConfigConflict) {
		t.Fatalf("unexpected error: have %v want %v", err, errGenesisConfigConflict)
	}
	if compatErr != nil {
		t.Fatalf("unexpected compatibility error: %v", compatErr)
	}
	if hash != stored {
		t.Fatalf("unexpected hash: have %s want %s", hash.Hex(), stored.Hex())
	}
	if cfg != nil {
		t.Fatalf("expected nil config on built-in drift, have %v", cfg)
	}
}

// TestSetupGenesisRejectsStoredBuiltInHashDriftWithXDPoS tests setup genesis rejects stored built in hash drift with xd po s.
func TestSetupGenesisRejectsStoredBuiltInHashDriftWithXDPoS(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*params.ChainConfig)
	}{
		{
			name: "chain id drift",
			mutate: func(cfg *params.ChainConfig) {
				cfg.ChainID = big.NewInt(99999)
			},
		},
		{
			name: "fork drift",
			mutate: func(cfg *params.ChainConfig) {
				cfg.BerlinBlock = big.NewInt(61289999)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			db := rawdb.NewMemoryDatabase()
			DefaultTestnetGenesisBlock().MustCommit(db)

			stored := params.TestnetGenesisHash
			storedCfg := params.TestnetChainConfig.Clone()
			test.mutate(storedCfg)
			overwriteStoredChainConfig(t, db, stored, storedCfg)

			cfg, hash, compatErr, err := SetupGenesisBlock(db, nil)
			if !errors.Is(err, errGenesisConfigConflict) {
				t.Fatalf("unexpected error: have %v want %v", err, errGenesisConfigConflict)
			}
			if compatErr != nil {
				t.Fatalf("unexpected compatibility error: %v", compatErr)
			}
			if hash != stored {
				t.Fatalf("unexpected hash: have %s want %s", hash.Hex(), stored.Hex())
			}
			if cfg != nil {
				t.Fatalf("expected nil config on built-in drift, have %v", cfg)
			}
		})
	}
}

// TestSetupGenesisRejectsStoredBuiltInHashFutureDriftWithExistingHead tests setup genesis rejects stored built in hash future drift with existing head.
func TestSetupGenesisRejectsStoredBuiltInHashFutureDriftWithExistingHead(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	genesisBlock := DefaultTestnetGenesisBlock().MustCommit(db)

	head := types.NewBlockWithHeader(&types.Header{
		Number:     big.NewInt(1),
		ParentHash: genesisBlock.Hash(),
	})
	rawdb.WriteBlock(db, head)
	rawdb.WriteCanonicalHash(db, genesisBlock.Hash(), 0)
	rawdb.WriteCanonicalHash(db, head.Hash(), 1)
	rawdb.WriteHeadHeaderHash(db, head.Hash())
	rawdb.WriteHeadBlockHash(db, head.Hash())
	rawdb.WriteHeadFastBlockHash(db, head.Hash())

	storedCfg := params.TestnetChainConfig.Clone()
	storedCfg.PragueBlock = big.NewInt(99999999)
	overwriteStoredChainConfig(t, db, params.TestnetGenesisHash, storedCfg)

	cfg, hash, compatErr, err := SetupGenesisBlock(db, nil)
	if !errors.Is(err, errGenesisConfigConflict) {
		t.Fatalf("unexpected error: have %v want %v", err, errGenesisConfigConflict)
	}
	if compatErr != nil {
		t.Fatalf("unexpected compatibility error: %v", compatErr)
	}
	if hash != params.TestnetGenesisHash {
		t.Fatalf("unexpected hash: have %s want %s", hash.Hex(), params.TestnetGenesisHash.Hex())
	}
	if cfg != nil {
		t.Fatalf("expected nil config on built-in future drift, have %v", cfg)
	}
}

// TestSetupGenesis tests setup genesis.
func TestSetupGenesis(t *testing.T) {
	var (
		futureFork = big.NewInt(1_000_000_000)
		customg    = Genesis{
			Config: &params.ChainConfig{
				ChainID:                big.NewInt(4444),
				HomesteadBlock:         big.NewInt(3),
				TIP2019Block:           new(big.Int).Set(futureFork),
				EIP150Block:            new(big.Int).Set(futureFork),
				EIP155Block:            new(big.Int).Set(futureFork),
				EIP158Block:            new(big.Int).Set(futureFork),
				ByzantiumBlock:         new(big.Int).Set(futureFork),
				ConstantinopleBlock:    new(big.Int).Set(futureFork),
				PetersburgBlock:        new(big.Int).Set(futureFork),
				IstanbulBlock:          new(big.Int).Set(futureFork),
				TIPTRC21FeeBlock:       big.NewInt(0),
				Gas50xBlock:            new(big.Int).Set(futureFork),
				TRC21IssuerSMC:         params.TestnetChainConfig.TRC21IssuerSMC,
				XDCXListingSMC:         params.TestnetChainConfig.XDCXListingSMC,
				RelayerRegistrationSMC: params.TestnetChainConfig.RelayerRegistrationSMC,
				LendingRegistrationSMC: params.TestnetChainConfig.LendingRegistrationSMC,
				Ethash:                 new(params.EthashConfig),
			},
			Alloc: types.GenesisAlloc{
				{1}: {Balance: big.NewInt(1), Storage: map[common.Hash]common.Hash{{1}: {1}}},
			},
		}
		oldcustomg    = customg
		configReadErr = errors.New("chain config read failed")
	)
	setXinFinForksToFuture(customg.Config, futureFork)
	canonicalCustomCfg, err := resolveProvidedChainConfig(common.Hash{}, customg.Config, builtInChainConfigMustMatch)
	if err != nil {
		t.Fatalf("failed to hydrate custom config: %v", err)
	}
	customg.Config = canonicalCustomCfg.Clone()
	customghash := customg.ToBlock().Hash()
	oldcustomg.Config = &params.ChainConfig{ChainID: big.NewInt(4444), HomesteadBlock: big.NewInt(2), TIP2019Block: new(big.Int).Set(futureFork), EIP150Block: new(big.Int).Set(futureFork), EIP155Block: new(big.Int).Set(futureFork), EIP158Block: new(big.Int).Set(futureFork), ByzantiumBlock: new(big.Int).Set(futureFork), ConstantinopleBlock: new(big.Int).Set(futureFork), PetersburgBlock: new(big.Int).Set(futureFork), IstanbulBlock: new(big.Int).Set(futureFork), TIPTRC21FeeBlock: big.NewInt(0), Gas50xBlock: new(big.Int).Set(futureFork), TRC21IssuerSMC: params.TestnetChainConfig.TRC21IssuerSMC, XDCXListingSMC: params.TestnetChainConfig.XDCXListingSMC, RelayerRegistrationSMC: params.TestnetChainConfig.RelayerRegistrationSMC, LendingRegistrationSMC: params.TestnetChainConfig.LendingRegistrationSMC, Ethash: new(params.EthashConfig)}
	setXinFinForksToFuture(oldcustomg.Config, futureFork)
	oldcustomg.Config, err = resolveProvidedChainConfig(common.Hash{}, oldcustomg.Config, builtInChainConfigMustMatch)
	if err != nil {
		t.Fatalf("failed to hydrate old custom config: %v", err)
	}
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
			wantErr:    startup.ErrGenesisHeaderNotFound,
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

	for _, test := range tests {
		db := rawdb.NewMemoryDatabase()
		config, hash, compatErr, err := test.fn(db)
		// Check the return values.
		if !chainConfigSemanticallyEqual(config, test.wantConfig) {
			t.Errorf("%s:\nreturned %v\nwant     %v", test.name, config, test.wantConfig)
		}
		if (err == nil) != (test.wantErr == nil) || (err != nil && err.Error() != test.wantErr.Error()) {
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

// TestSetupGenesisConfigCompatibilityPathReturnsConfig tests setup genesis config compatibility path returns config.
func TestSetupGenesisConfigCompatibilityPathReturnsConfig(t *testing.T) {
	futureFork := big.NewInt(1_000_000_000)
	customg := Genesis{
		Config: &params.ChainConfig{ChainID: big.NewInt(4444), HomesteadBlock: big.NewInt(3), TIP2019Block: new(big.Int).Set(futureFork), EIP150Block: new(big.Int).Set(futureFork), EIP155Block: new(big.Int).Set(futureFork), EIP158Block: new(big.Int).Set(futureFork), ByzantiumBlock: new(big.Int).Set(futureFork), ConstantinopleBlock: new(big.Int).Set(futureFork), PetersburgBlock: new(big.Int).Set(futureFork), IstanbulBlock: new(big.Int).Set(futureFork), TIPTRC21FeeBlock: big.NewInt(0), Gas50xBlock: new(big.Int).Set(futureFork), TRC21IssuerSMC: params.TestnetChainConfig.TRC21IssuerSMC, XDCXListingSMC: params.TestnetChainConfig.XDCXListingSMC, RelayerRegistrationSMC: params.TestnetChainConfig.RelayerRegistrationSMC, LendingRegistrationSMC: params.TestnetChainConfig.LendingRegistrationSMC, Ethash: new(params.EthashConfig)},
		Alloc: types.GenesisAlloc{
			{1}: {Balance: big.NewInt(1), Storage: map[common.Hash]common.Hash{{1}: {1}}},
		},
	}
	oldcustomg := customg
	setXinFinForksToFuture(customg.Config, futureFork)
	oldcustomg.Config = &params.ChainConfig{ChainID: big.NewInt(4444), HomesteadBlock: big.NewInt(2), TIP2019Block: new(big.Int).Set(futureFork), EIP150Block: new(big.Int).Set(futureFork), EIP155Block: new(big.Int).Set(futureFork), EIP158Block: new(big.Int).Set(futureFork), ByzantiumBlock: new(big.Int).Set(futureFork), ConstantinopleBlock: new(big.Int).Set(futureFork), PetersburgBlock: new(big.Int).Set(futureFork), IstanbulBlock: new(big.Int).Set(futureFork), TIPTRC21FeeBlock: big.NewInt(0), Gas50xBlock: new(big.Int).Set(futureFork), TRC21IssuerSMC: params.TestnetChainConfig.TRC21IssuerSMC, XDCXListingSMC: params.TestnetChainConfig.XDCXListingSMC, RelayerRegistrationSMC: params.TestnetChainConfig.RelayerRegistrationSMC, LendingRegistrationSMC: params.TestnetChainConfig.LendingRegistrationSMC, Ethash: new(params.EthashConfig)}
	setXinFinForksToFuture(oldcustomg.Config, futureFork)
	var err error
	customg.Config, err = resolveProvidedChainConfig(common.Hash{}, customg.Config, builtInChainConfigMustMatch)
	if err != nil {
		t.Fatalf("failed to hydrate custom config: %v", err)
	}
	oldcustomg.Config, err = resolveProvidedChainConfig(common.Hash{}, oldcustomg.Config, builtInChainConfigMustMatch)
	if err != nil {
		t.Fatalf("failed to hydrate old custom config: %v", err)
	}

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

// TestSetupGenesisBlockDoesNotRewriteStoredCustomConfigOnCompatDrift tests setup genesis block does not rewrite stored custom config on compat drift.
func TestSetupGenesisBlockDoesNotRewriteStoredCustomConfigOnCompatDrift(t *testing.T) {
	newCustomXDPoSGenesis := func() *Genesis {
		xdposCfg := params.TestnetChainConfig.XDPoS.Clone()
		xdposCfg.Epoch = 1
		xdposCfg.V2 = xdposCfg.V2.Clone()
		xdposCfg.V2.SwitchBlock = big.NewInt(2)
		xdposCfg.V2.SwitchEpoch = 2
		cfg := &params.ChainConfig{
			ChainID:                big.NewInt(4444),
			TIPTRC21FeeBlock:       big.NewInt(1),
			Gas50xBlock:            big.NewInt(1),
			TRC21IssuerSMC:         params.TestnetChainConfig.TRC21IssuerSMC,
			XDCXListingSMC:         params.TestnetChainConfig.XDCXListingSMC,
			RelayerRegistrationSMC: params.TestnetChainConfig.RelayerRegistrationSMC,
			LendingRegistrationSMC: params.TestnetChainConfig.LendingRegistrationSMC,
			XDPoS:                  xdposCfg,
		}
		return &Genesis{
			Config:    cfg,
			Timestamp: 1,
			ExtraData: make([]byte, 32+crypto.SignatureLength),
			Alloc: types.GenesisAlloc{
				{1}: {Balance: big.NewInt(1)},
			},
			GasLimit:   4700000,
			Difficulty: big.NewInt(1),
		}
	}

	writeHead := func(db ethdb.Database, number uint64) {
		t.Helper()
		header := &types.Header{Number: new(big.Int).SetUint64(number)}
		rawdb.WriteHeader(db, header)
		rawdb.WriteHeadHeaderHash(db, header.Hash())
	}

	tests := []struct {
		name           string
		head           uint64
		mutate         func(*params.ChainConfig)
		wantCompatErr  *params.ConfigCompatError
		assertReturned func(*testing.T, *params.ChainConfig)
	}{
		{
			name: "v2 switch epoch drift",
			head: 2,
			mutate: func(cfg *params.ChainConfig) {
				cfg.XDPoS = cfg.XDPoS.Clone()
				cfg.XDPoS.V2 = cfg.XDPoS.V2.Clone()
				cfg.XDPoS.V2.SwitchEpoch++
			},
			wantCompatErr: &params.ConfigCompatError{
				What:         "XDPoS.V2.SwitchEpoch",
				StoredConfig: big.NewInt(2),
				NewConfig:    big.NewInt(2),
				RewindTo:     1,
			},
			assertReturned: func(t *testing.T, cfg *params.ChainConfig) {
				t.Helper()
				if cfg == nil || cfg.XDPoS == nil || cfg.XDPoS.V2 == nil {
					t.Fatalf("expected returned V2 config, have %v", cfg)
				}
				if cfg.XDPoS.V2.SwitchEpoch == 2 {
					t.Fatalf("expected returned config to keep provided switchEpoch drift, have %d", cfg.XDPoS.V2.SwitchEpoch)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			db := rawdb.NewMemoryDatabase()
			storedGenesis := newCustomXDPoSGenesis()
			block := storedGenesis.MustCommit(db)
			writeHead(db, test.head)

			storedRawBefore, err := rawdb.ReadChainConfigJSON(db, block.Hash())
			if err != nil {
				t.Fatalf("failed to read stored chain config before restart: %v", err)
			}

			provided := newCustomXDPoSGenesis()
			test.mutate(provided.Config)

			cfg, hash, compatErr, err := SetupGenesisBlock(db, provided)
			if err != nil {
				t.Fatalf("unexpected setup error: %v", err)
			}
			if !reflect.DeepEqual(compatErr, test.wantCompatErr) {
				t.Fatalf("unexpected compatibility error: have %#v want %#v", compatErr, test.wantCompatErr)
			}
			if hash != block.Hash() {
				t.Fatalf("unexpected hash: have %s want %s", hash.Hex(), block.Hash().Hex())
			}
			test.assertReturned(t, cfg)

			storedRawAfter, err := rawdb.ReadChainConfigJSON(db, block.Hash())
			if err != nil {
				t.Fatalf("failed to read stored chain config after restart: %v", err)
			}
			if !bytes.Equal(storedRawBefore, storedRawAfter) {
				t.Fatalf("expected stored chain config to remain unchanged after compat error")
			}
		})
	}
}

// TestSetupGenesisBlockReturnsCompatErrorWhenCompatDriftRewindsToZero tests
// setup genesis preserves rewind-to-zero compatibility errors instead of
// rewriting the stored config.
func TestSetupGenesisBlockReturnsCompatErrorWhenCompatDriftRewindsToZero(t *testing.T) {
	newCustomXDPoSGenesis := func() *Genesis {
		xdposCfg := params.TestnetChainConfig.XDPoS.Clone()
		xdposCfg.Epoch = 1
		xdposCfg.V2 = xdposCfg.V2.Clone()
		xdposCfg.V2.SwitchBlock = big.NewInt(2)
		xdposCfg.V2.SwitchEpoch = 2
		cfg := &params.ChainConfig{
			ChainID:                big.NewInt(4444),
			TIPTRC21FeeBlock:       big.NewInt(1),
			Gas50xBlock:            big.NewInt(1),
			TRC21IssuerSMC:         params.TestnetChainConfig.TRC21IssuerSMC,
			XDCXListingSMC:         params.TestnetChainConfig.XDCXListingSMC,
			RelayerRegistrationSMC: params.TestnetChainConfig.RelayerRegistrationSMC,
			LendingRegistrationSMC: params.TestnetChainConfig.LendingRegistrationSMC,
			XDPoS:                  xdposCfg,
		}
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

	writeHead := func(db ethdb.Database, number uint64) {
		t.Helper()
		header := &types.Header{Number: new(big.Int).SetUint64(number)}
		rawdb.WriteHeader(db, header)
		rawdb.WriteHeadHeaderHash(db, header.Hash())
	}

	db := rawdb.NewMemoryDatabase()
	storedGenesis := newCustomXDPoSGenesis()
	block := storedGenesis.MustCommit(db)
	writeHead(db, 1)

	storedRawBefore, err := rawdb.ReadChainConfigJSON(db, block.Hash())
	if err != nil {
		t.Fatalf("failed to read stored chain config before restart: %v", err)
	}

	provided := newCustomXDPoSGenesis()
	provided.Config.TRC21IssuerSMC = common.HexToAddress("0x0000000000000000000000000000000000000001")

	cfg, hash, compatErr, err := SetupGenesisBlock(db, provided)
	if err != nil {
		t.Fatalf("unexpected setup error: %v", err)
	}
	wantCompatErr := &params.ConfigCompatError{
		What:         "TRC21IssuerSMC",
		StoredConfig: big.NewInt(1),
		NewConfig:    big.NewInt(1),
		StoredValue:  storedGenesis.Config.TRC21IssuerSMC.Hex(),
		NewValue:     provided.Config.TRC21IssuerSMC.Hex(),
		RewindTo:     0,
	}
	if !reflect.DeepEqual(compatErr, wantCompatErr) {
		t.Fatalf("unexpected compatibility error: have %#v want %#v", compatErr, wantCompatErr)
	}
	if hash != block.Hash() {
		t.Fatalf("unexpected hash: have %s want %s", hash.Hex(), block.Hash().Hex())
	}
	if cfg == nil {
		t.Fatal("expected returned config")
	}
	if cfg.TRC21IssuerSMC != provided.Config.TRC21IssuerSMC {
		t.Fatalf("expected returned config to keep provided TRC21 issuer drift: have %s want %s", cfg.TRC21IssuerSMC.Hex(), provided.Config.TRC21IssuerSMC.Hex())
	}

	storedRawAfter, err := rawdb.ReadChainConfigJSON(db, block.Hash())
	if err != nil {
		t.Fatalf("failed to read stored chain config after restart: %v", err)
	}
	if !bytes.Equal(storedRawBefore, storedRawAfter) {
		t.Fatal("expected stored chain config to remain unchanged when compat rewind targets zero")
	}

	storedCfg, err := rawdb.ReadChainConfig(db, block.Hash())
	if err != nil {
		t.Fatalf("failed to read stored chain config: %v", err)
	}
	if storedCfg == nil {
		t.Fatal("expected stored chain config")
	}
	if storedCfg.TRC21IssuerSMC != storedGenesis.Config.TRC21IssuerSMC {
		t.Fatalf("expected stored chain config to remain unchanged: have %s want %s", storedCfg.TRC21IssuerSMC.Hex(), storedGenesis.Config.TRC21IssuerSMC.Hex())
	}

}

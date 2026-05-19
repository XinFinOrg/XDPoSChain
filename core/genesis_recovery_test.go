package core

import (
	"bytes"
	"errors"
	"math/big"
	"reflect"
	"strings"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/startup"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/ethdb"
	"github.com/XinFinOrg/XDPoSChain/log"
	"github.com/XinFinOrg/XDPoSChain/params"
)

func TestGetGenesisStateBuiltInStillFallsBackWithoutCustomRecovery(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	alloc, err := getGenesisState(db, params.MainnetGenesisHash, nil, recoveryDisabled)
	if err != nil {
		t.Fatalf("failed to load built-in genesis alloc: %v", err)
	}
	if !reflect.DeepEqual(alloc, DefaultGenesisBlock().Alloc) {
		t.Fatalf("unexpected built-in alloc: have %#v want %#v", alloc, DefaultGenesisBlock().Alloc)
	}
}

func TestGetGenesisStateCustomFallbackRequiresWritableRecovery(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	genesis := &Genesis{
		Config: &params.ChainConfig{
			ChainID:        big.NewInt(4446),
			HomesteadBlock: new(big.Int),
			Ethash:         new(params.EthashConfig),
		},
		Nonce:      69,
		ExtraData:  make([]byte, 32+crypto.SignatureLength),
		GasLimit:   4700000,
		Difficulty: big.NewInt(1),
		Timestamp:  12348,
		Alloc: types.GenesisAlloc{
			common.Address{4}: {Balance: big.NewInt(1)},
		},
	}
	hash := genesis.ToBlock().Hash()

	alloc, err := getGenesisState(db, hash, genesis, recoveryDisabled)
	if err != nil {
		t.Fatalf("failed to load readonly custom genesis alloc: %v", err)
	}
	if alloc != nil {
		t.Fatalf("expected readonly custom recovery to be disabled, have %#v", alloc)
	}

	alloc, err = getGenesisState(db, hash, genesis, recoveryWritable)
	if err != nil {
		t.Fatalf("failed to load writable custom genesis alloc: %v", err)
	}
	if !reflect.DeepEqual(alloc, genesis.Alloc) {
		t.Fatalf("unexpected writable custom alloc: have %#v want %#v", alloc, genesis.Alloc)
	}
}

// TestSetupGenesisMissingChainConfigDoesNotResetHead tests setup genesis missing chain config does not reset head.
func TestSetupGenesisMissingChainConfigDoesNotResetHead(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	genesis := DefaultGenesisBlock()
	genesisBlock := genesis.MustCommit(db)

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

	if err := db.Delete(testConfigKey(genesisBlock.Hash())); err != nil {
		t.Fatalf("failed to delete chain config: %v", err)
	}

	if _, _, _, err := SetupGenesisBlock(db, genesis); err != nil {
		t.Fatalf("SetupGenesisBlock failed: %v", err)
	}

	if got := rawdb.ReadHeadHeaderHash(db); got != head.Hash() {
		t.Fatalf("head header hash changed: have %s want %s", got.Hex(), head.Hash().Hex())
	}
	if got := rawdb.ReadHeadBlockHash(db); got != head.Hash() {
		t.Fatalf("head block hash changed: have %s want %s", got.Hex(), head.Hash().Hex())
	}
	if got := rawdb.ReadHeadFastBlockHash(db); got != head.Hash() {
		t.Fatalf("head fast block hash changed: have %s want %s", got.Hex(), head.Hash().Hex())
	}
}

// TestSetupGenesisMissingChainConfigDoesNotResetPartialHeadMetadata tests setup genesis missing chain config does not reset partial head metadata.
func TestSetupGenesisMissingChainConfigDoesNotResetPartialHeadMetadata(t *testing.T) {
	tests := []struct {
		name      string
		writeHead func(ethdb.KeyValueWriter, common.Hash)
		readHead  func(ethdb.KeyValueReader) common.Hash
	}{
		{
			name:      "head block only",
			writeHead: rawdb.WriteHeadBlockHash,
			readHead:  rawdb.ReadHeadBlockHash,
		},
		{
			name:      "head fast block only",
			writeHead: rawdb.WriteHeadFastBlockHash,
			readHead:  rawdb.ReadHeadFastBlockHash,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := rawdb.NewMemoryDatabase()
			genesis := DefaultGenesisBlock()
			genesisBlock := genesis.MustCommit(db)

			head := types.NewBlockWithHeader(&types.Header{
				Number:     big.NewInt(1),
				ParentHash: genesisBlock.Hash(),
			})
			rawdb.WriteBlock(db, head)
			rawdb.WriteCanonicalHash(db, genesisBlock.Hash(), 0)
			rawdb.WriteCanonicalHash(db, head.Hash(), 1)
			rawdb.WriteHeadHeaderHash(db, common.Hash{})
			rawdb.WriteHeadBlockHash(db, common.Hash{})
			rawdb.WriteHeadFastBlockHash(db, common.Hash{})
			tt.writeHead(db, head.Hash())

			if err := db.Delete(testConfigKey(genesisBlock.Hash())); err != nil {
				t.Fatalf("failed to delete chain config: %v", err)
			}

			if _, _, _, err := SetupGenesisBlock(db, genesis); err != nil {
				t.Fatalf("SetupGenesisBlock failed: %v", err)
			}

			if got := tt.readHead(db); got != head.Hash() {
				t.Fatalf("head marker changed: have %s want %s", got.Hex(), head.Hash().Hex())
			}
		})
	}
}

// TestSetupGenesisMissingChainConfigRejectsInvalidConfigWithExistingHead tests setup genesis missing chain config rejects invalid config with existing head.
func TestSetupGenesisMissingChainConfigRejectsInvalidConfigWithExistingHead(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	genesis := &Genesis{
		Config: &params.ChainConfig{
			ChainID:                big.NewInt(5151),
			Ethash:                 new(params.EthashConfig),
			TIPTRC21FeeBlock:       big.NewInt(0),
			TRC21IssuerSMC:         common.HexToAddress("0x0000000000000000000000000000000000000001"),
			XDCXListingSMC:         common.HexToAddress("0x0000000000000000000000000000000000000002"),
			RelayerRegistrationSMC: common.HexToAddress("0x0000000000000000000000000000000000000003"),
			LendingRegistrationSMC: common.HexToAddress("0x0000000000000000000000000000000000000004"),
		},
		Nonce:      66,
		GasLimit:   params.GenesisGasLimit,
		Difficulty: params.GenesisDifficulty,
	}
	var err error
	genesis.Config, err = resolveProvidedChainConfig(genesis.ToBlock().Hash(), genesis.Config, builtInChainConfigMustMatch)
	if err != nil {
		t.Fatalf("failed to hydrate genesis config: %v", err)
	}
	genesisBlock := genesis.MustCommit(db)

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

	if err := db.Delete(testConfigKey(genesisBlock.Hash())); err != nil {
		t.Fatalf("failed to delete chain config: %v", err)
	}

	badGenesis := genesis.copy()
	badGenesis.Config.ChainID = nil

	_, _, _, err = SetupGenesisBlock(db, badGenesis)
	if err == nil {
		t.Fatal("expected invalid chain config error")
	}
	if !strings.Contains(err.Error(), "missing fork switch: ChainID") {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := rawdb.ReadHeadHeaderHash(db); got != head.Hash() {
		t.Fatalf("head header hash changed: have %s want %s", got.Hex(), head.Hash().Hex())
	}
	if cfg, readErr := rawdb.ReadChainConfig(db, genesisBlock.Hash()); readErr != nil && !errors.Is(readErr, rawdb.ErrChainConfigNotFound) {
		t.Fatalf("failed to read chain config: %v", readErr)
	} else if cfg != nil {
		t.Fatalf("expected no chain config to be restored on validation failure, got %#v", cfg)
	}
}

// TestSetupGenesisUsesStoredBuiltInGenesisWhenChainConfigMissing tests setup genesis uses stored built in genesis when chain config missing.
func TestSetupGenesisUsesStoredBuiltInGenesisWhenChainConfigMissing(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	block := DefaultTestnetGenesisBlock().MustCommit(db)

	if err := db.Delete(testConfigKey(block.Hash())); err != nil {
		t.Fatalf("failed to delete chain config: %v", err)
	}

	cfg, hash, _, err := SetupGenesisBlock(db, nil)
	if err != nil {
		t.Fatalf("SetupGenesisBlock failed: %v", err)
	}
	if hash != params.TestnetGenesisHash {
		t.Fatalf("unexpected hash: have %s want %s", hash.Hex(), params.TestnetGenesisHash.Hex())
	}
	if !chainConfigSemanticallyEqual(cfg, params.TestnetChainConfig) {
		t.Fatalf("unexpected config: have %v want %v", cfg, params.TestnetChainConfig)
	}
}

// TestSetupGenesisTreatsCustomChainAsLocalnetWhenChainConfigMissing tests setup genesis treats custom chain as localnet when chain config missing.
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
	assertBuiltInBackfillForkFieldsEqual(t, cfg, params.XDCMainnetChainConfig)
}

// TestLoadChainConfigFailsForStoredCustomChainWhenChainConfigMissing tests load chain config fails for stored custom chain when chain config missing.
func TestLoadChainConfigFailsForStoredCustomChainWhenChainConfigMissing(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	genesis := &Genesis{
		Config: &params.ChainConfig{
			ChainID:                big.NewInt(91919),
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

	if err := db.Delete(testConfigKey(block.Hash())); err != nil {
		t.Fatalf("failed to delete chain config: %v", err)
	}

	cfg, hash, err := LoadChainConfig(db, nil)
	if !errors.Is(err, rawdb.ErrChainConfigNotFound) {
		t.Fatalf("unexpected error: have %v want %v", err, rawdb.ErrChainConfigNotFound)
	}
	if hash != block.Hash() {
		t.Fatalf("unexpected hash: have %s want %s", hash.Hex(), block.Hash().Hex())
	}
	if cfg != nil {
		t.Fatalf("expected nil config on missing custom chain config, have %v", cfg)
	}
}

// TestLoadChainConfigUsesProvidedGenesisForStoredCustomChainWhenChainConfigMissing tests load chain config uses provided genesis for stored custom chain when chain config missing.
func TestLoadChainConfigUsesProvidedGenesisForStoredCustomChainWhenChainConfigMissing(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	genesis := &Genesis{
		Config: &params.ChainConfig{
			ChainID:                big.NewInt(92929),
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

	if err := db.Delete(testConfigKey(block.Hash())); err != nil {
		t.Fatalf("failed to delete chain config: %v", err)
	}

	cfg, hash, err := LoadChainConfig(db, genesis)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hash != block.Hash() {
		t.Fatalf("unexpected hash: have %s want %s", hash.Hex(), block.Hash().Hex())
	}
	if cfg == nil {
		t.Fatal("expected config from provided genesis")
	}
	if cfg.ChainID == nil || cfg.ChainID.Cmp(genesis.Config.ChainID) != 0 {
		t.Fatalf("unexpected chain id: have %v want %v", cfg.ChainID, genesis.Config.ChainID)
	}
	if cfg.TIPTRC21FeeBlock == nil || cfg.TIPTRC21FeeBlock.Cmp(genesis.Config.TIPTRC21FeeBlock) != 0 {
		t.Fatalf("unexpected TIPTRC21FeeBlock: have %v want %v", cfg.TIPTRC21FeeBlock, genesis.Config.TIPTRC21FeeBlock)
	}
}

// TestLoadChainConfigRejectsStoredConfigWithoutGenesisHeader tests load chain config rejects internally inconsistent stored startup facts.
func TestLoadChainConfigRejectsStoredConfigWithoutGenesisHeader(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	rawdb.WriteCanonicalHash(db, params.MainnetGenesisHash, 0)
	rawdb.WriteChainConfig(db, params.MainnetGenesisHash, params.XDCMainnetChainConfig)

	cfg, hash, err := LoadChainConfig(db, nil)
	if !errors.Is(err, startup.ErrInvalidFacts) {
		t.Fatalf("unexpected error: have %v want %v", err, startup.ErrInvalidFacts)
	}
	if hash != params.MainnetGenesisHash {
		t.Fatalf("unexpected hash: have %s want %s", hash.Hex(), params.MainnetGenesisHash.Hex())
	}
	if cfg != nil {
		t.Fatalf("expected nil config, have %v", cfg)
	}
}

func TestSetupGenesisBlockRejectsStoredConfigWithoutGenesisHeader(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	rawdb.WriteCanonicalHash(db, params.MainnetGenesisHash, 0)
	rawdb.WriteChainConfig(db, params.MainnetGenesisHash, params.XDCMainnetChainConfig)

	cfg, hash, compatErr, err := SetupGenesisBlock(db, nil)
	if !errors.Is(err, startup.ErrInvalidFacts) {
		t.Fatalf("unexpected error: have %v want %v", err, startup.ErrInvalidFacts)
	}
	if compatErr != nil {
		t.Fatalf("unexpected compatibility error: %v", compatErr)
	}
	if hash != params.MainnetGenesisHash {
		t.Fatalf("unexpected hash: have %s want %s", hash.Hex(), params.MainnetGenesisHash.Hex())
	}
	if cfg != nil {
		t.Fatalf("expected nil config, have %v", cfg)
	}
}

func TestSetupGenesisBlockPropagatesChainConfigOverrideReadError(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	DefaultGenesisBlock().MustCommit(db)

	wantErr := errors.New("boom")
	deps := defaultGenesisDeps
	deps.readChainConfigOverride = func(db ethdb.KeyValueReader, hash common.Hash) (bool, error) {
		return false, wantErr
	}

	_, _, _, err := setupGenesisBlockWithDeps(db, nil, deps, GenesisStartupOptions{})
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected override marker read error, got %v", err)
	}
}

func TestLoadChainConfigPropagatesChainConfigOverrideReadError(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	DefaultGenesisBlock().MustCommit(db)

	wantErr := errors.New("boom")
	deps := defaultGenesisDeps
	deps.readChainConfigOverride = func(db ethdb.KeyValueReader, hash common.Hash) (bool, error) {
		return false, wantErr
	}

	_, _, err := loadChainConfigWithDeps(db, nil, deps)
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected override marker read error, got %v", err)
	}
}

// TestLoadChainConfigRejectsMissingChainConfigForStoredSameHashCustomChainWithOverride tests load chain config rejects missing chain config for stored same hash custom chain with override.
func TestLoadChainConfigRejectsMissingChainConfigForStoredSameHashCustomChainWithOverride(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	genesis := DefaultTestnetGenesisBlock()
	genesis.Config = genesis.Config.Clone()
	genesis.Config.ChainID = big.NewInt(92929)

	_, hash, _, err := SetupGenesisBlockWithOverride(db, genesis, true)
	if err != nil {
		t.Fatalf("SetupGenesisBlock failed: %v", err)
	}
	if hash != params.TestnetGenesisHash {
		t.Fatalf("unexpected hash: have %s want %s", hash.Hex(), params.TestnetGenesisHash.Hex())
	}
	marker, err := rawdb.ReadChainConfigOverride(db, hash)
	if err != nil {
		t.Fatalf("failed to read override marker: %v", err)
	}
	if !marker {
		t.Fatal("expected same-hash custom config override marker")
	}
	if err := db.Delete(testConfigKey(hash)); err != nil {
		t.Fatalf("failed to delete chain config: %v", err)
	}

	cfg, loadedHash, err := LoadChainConfig(db, nil)
	if !errors.Is(err, errGenesisConfigConflict) {
		t.Fatalf("unexpected error: have %v want %v", err, errGenesisConfigConflict)
	}
	if loadedHash != hash {
		t.Fatalf("unexpected hash: have %s want %s", loadedHash.Hex(), hash.Hex())
	}
	if cfg != nil {
		t.Fatalf("expected nil config when override-backed custom config is missing, have %v", cfg)
	}
}

// TestLoadChainConfigClassifiesStoredBuiltInAndOverrideBackedConfigsWithoutAllEthashFallback
// tests same-hash database classification stays on the built-in or override-backed
// path and never falls back to the broad AllEthash protocol config.
func TestLoadChainConfigClassifiesStoredBuiltInAndOverrideBackedConfigsWithoutAllEthashFallback(t *testing.T) {
	tests := []struct {
		name         string
		writeMarker  bool
		storedConfig *params.ChainConfig
		wantConfig   *params.ChainConfig
		wantChainID  *big.Int
		wantOverride bool
		wantDesc     string
		allowRead    bool
	}{
		{
			name:         "missing marker keeps built-in classification",
			writeMarker:  false,
			storedConfig: params.TestnetChainConfig,
			wantConfig:   params.TestnetChainConfig,
			wantChainID:  params.TestnetChainConfig.ChainID,
			wantOverride: false,
		},
		{
			name:        "marker keeps custom override classification",
			writeMarker: true,
			storedConfig: func() *params.ChainConfig {
				cfg := params.TestnetChainConfig.Clone()
				cfg.ChainID = big.NewInt(92929)
				return cfg
			}(),
			wantConfig: func() *params.ChainConfig {
				cfg := params.TestnetChainConfig.Clone()
				cfg.ChainID = big.NewInt(92929)
				return cfg
			}(),
			wantChainID:  big.NewInt(92929),
			wantOverride: true,
			wantDesc:     "(custom override of built-in genesis)",
			allowRead:    true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			db := rawdb.NewMemoryDatabase()
			DefaultTestnetGenesisBlock().MustCommit(db)

			rawdb.WriteChainConfig(db, params.TestnetGenesisHash, test.storedConfig)
			if test.writeMarker {
				rawdb.WriteChainConfigOverride(db, params.TestnetGenesisHash)
			}

			marker, err := rawdb.ReadChainConfigOverride(db, params.TestnetGenesisHash)
			if err != nil {
				t.Fatalf("failed to read override marker: %v", err)
			}
			if marker != test.wantOverride {
				t.Fatalf("unexpected override marker state: have %t want %t", marker, test.wantOverride)
			}

			var (
				cfg       *params.ChainConfig
				hash      common.Hash
				compatErr *params.ConfigCompatError
			)
			if test.allowRead {
				cfg, hash, compatErr, err = LoadChainConfigWithCompatWithOverride(db, nil, true)
			} else {
				cfg, hash, err = LoadChainConfig(db, nil)
			}
			if err != nil {
				t.Fatalf("LoadChainConfig failed: %v", err)
			}
			if compatErr != nil {
				t.Fatalf("unexpected compatibility error: %v", compatErr)
			}
			if hash != params.TestnetGenesisHash {
				t.Fatalf("unexpected hash: have %s want %s", hash.Hex(), params.TestnetGenesisHash.Hex())
			}
			if cfg == nil {
				t.Fatal("expected loaded config")
			}
			if !chainConfigSemanticallyEqual(cfg, test.wantConfig) {
				t.Fatalf("unexpected config: have %v want %v", cfg, test.wantConfig)
			}
			if cfg.ChainID == nil || cfg.ChainID.Cmp(test.wantChainID) != 0 {
				t.Fatalf("unexpected chain ID: have %v want %v", cfg.ChainID, test.wantChainID)
			}
			if chainConfigSemanticallyEqual(cfg, params.AllEthashProtocolChanges) {
				t.Fatalf("unexpected AllEthash fallback: have %v", cfg)
			}
			if test.wantDesc != "" && !strings.Contains(cfg.Description(), test.wantDesc) {
				t.Fatalf("expected description to contain %q, have %q", test.wantDesc, cfg.Description())
			}
			if test.wantDesc == "" && strings.Contains(cfg.Description(), "(custom override of built-in genesis)") {
				t.Fatalf("did not expect custom override description, have %q", cfg.Description())
			}
		})
	}
}

// TestSetupGenesisBlockRejectsMissingChainConfigForBuiltInHashWithoutOverride tests setup genesis block rejects same-hash custom config recovery when the config blob is missing and no override marker exists.
func TestSetupGenesisBlockRejectsMissingChainConfigForBuiltInHashWithoutOverride(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	builtinGenesis := DefaultTestnetGenesisBlock()
	genesisBlock := builtinGenesis.MustCommit(db)

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

	if err := db.Delete(testConfigKey(genesisBlock.Hash())); err != nil {
		t.Fatalf("failed to delete chain config: %v", err)
	}

	customGenesis := DefaultTestnetGenesisBlock()
	customGenesis.Config = customGenesis.Config.Clone()
	customGenesis.Config.ChainID = big.NewInt(92929)

	cfg, hash, compatErr, err := SetupGenesisBlock(db, customGenesis)
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
		t.Fatalf("expected nil config, have %v", cfg)
	}
	marker, err := rawdb.ReadChainConfigOverride(db, hash)
	if err != nil {
		t.Fatalf("failed to read override marker: %v", err)
	}
	if marker {
		t.Fatal("did not expect same-hash custom config override marker to be created")
	}
}

// TestSetupGenesisBlockRejectsMissingChainConfigForStoredSameHashCustomChainWithOverride tests setup genesis block rejects missing chain config for stored same hash custom chain with override.
func TestSetupGenesisBlockRejectsMissingChainConfigForStoredSameHashCustomChainWithOverride(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	genesis := DefaultTestnetGenesisBlock()
	genesis.Config = genesis.Config.Clone()
	genesis.Config.ChainID = big.NewInt(92929)

	_, hash, _, err := SetupGenesisBlockWithOverride(db, genesis, true)
	if err != nil {
		t.Fatalf("SetupGenesisBlock failed: %v", err)
	}
	if hash != params.TestnetGenesisHash {
		t.Fatalf("unexpected hash: have %s want %s", hash.Hex(), params.TestnetGenesisHash.Hex())
	}
	marker, err := rawdb.ReadChainConfigOverride(db, hash)
	if err != nil {
		t.Fatalf("failed to read override marker: %v", err)
	}
	if !marker {
		t.Fatal("expected same-hash custom config override marker")
	}
	if err := db.Delete(testConfigKey(hash)); err != nil {
		t.Fatalf("failed to delete chain config: %v", err)
	}

	cfg, resolvedHash, compatErr, err := SetupGenesisBlockWithOverride(db, nil, true)
	if !errors.Is(err, startup.ErrGenesisConfigConflict) {
		t.Fatalf("unexpected error: have %v want %v", err, startup.ErrGenesisConfigConflict)
	}
	if compatErr != nil {
		t.Fatalf("unexpected compatibility error: %v", compatErr)
	}
	if resolvedHash != hash {
		t.Fatalf("unexpected hash: have %s want %s", resolvedHash.Hex(), hash.Hex())
	}
	if cfg != nil {
		t.Fatalf("expected nil config when override-backed custom config is missing, have %v", cfg)
	}
}

func TestSetupGenesisBlockRejectsSameHashCustomOverrideWithoutExplicitRecovery(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	genesis := DefaultTestnetGenesisBlock()
	genesis.Config = genesis.Config.Clone()
	genesis.Config.ChainID = big.NewInt(92929)

	cfg, hash, compatErr, err := SetupGenesisBlock(db, genesis)
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
		t.Fatalf("expected nil config, have %v", cfg)
	}
	marker, err := rawdb.ReadChainConfigOverride(db, hash)
	if err != nil {
		t.Fatalf("failed to read override marker: %v", err)
	}
	if marker {
		t.Fatal("did not expect same-hash custom config override marker without explicit recovery")
	}
}

// TestSetupGenesisBlockRestoresMissingChainConfigForStoredSameHashCustomChainWithProvidedGenesis tests setup genesis block restores an override-backed same-hash custom config when a matching genesis is provided.
func TestSetupGenesisBlockRestoresMissingChainConfigForStoredSameHashCustomChainWithProvidedGenesis(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	genesis := DefaultTestnetGenesisBlock()
	genesis.Config = genesis.Config.Clone()
	genesis.Config.ChainID = big.NewInt(92929)

	_, hash, _, err := SetupGenesisBlockWithOverride(db, genesis, true)
	if err != nil {
		t.Fatalf("SetupGenesisBlock failed: %v", err)
	}
	if hash != params.TestnetGenesisHash {
		t.Fatalf("unexpected hash: have %s want %s", hash.Hex(), params.TestnetGenesisHash.Hex())
	}
	marker, err := rawdb.ReadChainConfigOverride(db, hash)
	if err != nil {
		t.Fatalf("failed to read override marker: %v", err)
	}
	if !marker {
		t.Fatal("expected same-hash custom config override marker")
	}
	if err := db.Delete(testConfigKey(hash)); err != nil {
		t.Fatalf("failed to delete chain config: %v", err)
	}

	cfg, resolvedHash, compatErr, err := SetupGenesisBlockWithOverride(db, genesis, true)
	if err != nil {
		t.Fatalf("SetupGenesisBlock failed: %v", err)
	}
	if compatErr != nil {
		t.Fatalf("unexpected compatibility error: %v", compatErr)
	}
	if resolvedHash != hash {
		t.Fatalf("unexpected hash: have %s want %s", resolvedHash.Hex(), hash.Hex())
	}
	if cfg == nil {
		t.Fatal("expected resolved config")
	}
	if cfg.ChainID == nil || cfg.ChainID.Cmp(genesis.Config.ChainID) != 0 {
		t.Fatalf("unexpected restored chain ID: have %v want %v", cfg.ChainID, genesis.Config.ChainID)
	}
	marker, err = rawdb.ReadChainConfigOverride(db, hash)
	if err != nil {
		t.Fatalf("failed to read override marker: %v", err)
	}
	if !marker {
		t.Fatal("expected same-hash custom config override marker to remain set")
	}

	loadedCfg, loadedHash, _, err := loadChainConfigInternal(db, nil, defaultGenesisDeps, GenesisStartupOptions{AllowBuiltInCustomRecovery: true}, false)
	if err != nil {
		t.Fatalf("LoadChainConfig failed: %v", err)
	}
	if loadedHash != hash {
		t.Fatalf("unexpected loaded hash: have %s want %s", loadedHash.Hex(), hash.Hex())
	}
	if loadedCfg == nil {
		t.Fatal("expected loaded config")
	}
	if !strings.Contains(loadedCfg.Description(), "(custom override of built-in genesis)") {
		t.Fatalf("expected loaded description to mark custom built-in override, have %q", loadedCfg.Description())
	}
	if loadedCfg.ChainID == nil || loadedCfg.ChainID.Cmp(genesis.Config.ChainID) != 0 {
		t.Fatalf("unexpected loaded chain ID: have %v want %v", loadedCfg.ChainID, genesis.Config.ChainID)
	}
}

// TestSetupGenesisBlockMigratesLegacyStoredSameHashCustomConfigWithoutOverrideMarker
// tests writable startup recognizes and migrates a pre-marker same-hash custom
// config instead of rejecting it as built-in drift.
func TestSetupGenesisBlockMigratesLegacyStoredSameHashCustomConfigWithoutOverrideMarker(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	DefaultTestnetGenesisBlock().MustCommit(db)

	genesis := DefaultTestnetGenesisBlock()
	genesis.Config = genesis.Config.Clone()
	genesis.Config.ChainID = big.NewInt(92929)

	rawdb.WriteChainConfig(db, params.TestnetGenesisHash, genesis.Config)
	marker, err := rawdb.ReadChainConfigOverride(db, params.TestnetGenesisHash)
	if err != nil {
		t.Fatalf("failed to read override marker: %v", err)
	}
	if marker {
		t.Fatal("did not expect override marker before migration")
	}
	var logBuf bytes.Buffer
	prevLog := log.Root()
	glog := log.NewGlogHandler(log.NewTerminalHandlerWithLevel(&logBuf, log.LevelTrace, false))
	glog.Verbosity(log.LevelTrace)
	log.SetDefault(log.NewLogger(glog))
	defer log.SetDefault(prevLog)

	cfg, hash, compatErr, err := SetupGenesisBlockWithOverride(db, genesis, true)
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
	if cfg.ChainID == nil || cfg.ChainID.Cmp(genesis.Config.ChainID) != 0 {
		t.Fatalf("unexpected resolved chain ID: have %v want %v", cfg.ChainID, genesis.Config.ChainID)
	}
	if !strings.Contains(cfg.Description(), "(custom override of built-in genesis)") {
		t.Fatalf("expected description to mark custom built-in override, have %q", cfg.Description())
	}
	if !strings.Contains(logBuf.String(), "YOU ARE OVERRIDING BUILTIN CHAIN CONFIG") {
		t.Fatalf("expected warning log for custom built-in override, have %q", logBuf.String())
	}
	marker, err = rawdb.ReadChainConfigOverride(db, hash)
	if err != nil {
		t.Fatalf("failed to read override marker: %v", err)
	}
	if !marker {
		t.Fatal("expected migration to persist same-hash custom config override marker")
	}

	storedCfg, err := rawdb.ReadChainConfig(db, hash)
	if err != nil {
		t.Fatalf("failed to read stored chain config: %v", err)
	}
	if storedCfg == nil {
		t.Fatal("expected stored chain config")
	}
	if storedCfg.ChainID == nil || storedCfg.ChainID.Cmp(genesis.Config.ChainID) != 0 {
		t.Fatalf("unexpected stored chain ID: have %v want %v", storedCfg.ChainID, genesis.Config.ChainID)
	}
}

// TestSetupGenesisBlockMigrationPersistsHydratedLegacyOverrideConfig ensures
// legacy same-hash override migration writes the hydrated config alongside the
// new override marker instead of leaving sparse raw JSON in place.
func TestSetupGenesisBlockMigrationPersistsHydratedLegacyOverrideConfig(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	DefaultTestnetGenesisBlock().MustCommit(db)

	genesis := DefaultTestnetGenesisBlock()
	genesis.Config = genesis.Config.Clone()
	genesis.Config.ChainID = big.NewInt(92929)

	rawdb.WriteChainConfig(db, params.TestnetGenesisHash, genesis.Config)
	rawCfg, err := rawdb.ReadChainConfigJSON(db, params.TestnetGenesisHash)
	if err != nil {
		t.Fatalf("failed to read raw chain config: %v", err)
	}
	updatedRawCfg, err := removeXDPoSMaxMasternodesV2FromRawConfig(rawCfg)
	if err != nil {
		t.Fatalf("failed to remove XDPoS.maxMasternodesV2 from raw config: %v", err)
	}
	if err := db.Put(testConfigKey(params.TestnetGenesisHash), updatedRawCfg); err != nil {
		t.Fatalf("failed to write sparse raw chain config: %v", err)
	}

	migratedCfg, hash, compatErr, err := SetupGenesisBlockWithOverride(db, genesis, true)
	if err != nil {
		t.Fatalf("SetupGenesisBlock failed: %v", err)
	}
	if compatErr != nil {
		t.Fatalf("unexpected compatibility error: %v", compatErr)
	}
	if hash != params.TestnetGenesisHash {
		t.Fatalf("unexpected hash: have %s want %s", hash.Hex(), params.TestnetGenesisHash.Hex())
	}
	if migratedCfg == nil || migratedCfg.XDPoS == nil {
		t.Fatalf("expected migrated XDPoS config, have %v", migratedCfg)
	}

	marker, err := rawdb.ReadChainConfigOverride(db, hash)
	if err != nil {
		t.Fatalf("failed to read override marker: %v", err)
	}
	if !marker {
		t.Fatal("expected migration to persist same-hash custom config override marker")
	}

	storedCfg, err := rawdb.ReadChainConfig(db, hash)
	if err != nil {
		t.Fatalf("failed to read stored chain config: %v", err)
	}
	if storedCfg == nil || storedCfg.XDPoS == nil {
		t.Fatalf("expected stored XDPoS config, have %v", storedCfg)
	}
	if storedCfg.XDPoS.MaxMasternodesV2 != params.TestnetChainConfig.XDPoS.MaxMasternodesV2 {
		t.Fatalf("expected stored MaxMasternodesV2 to be %d after migration, got %d", params.TestnetChainConfig.XDPoS.MaxMasternodesV2, storedCfg.XDPoS.MaxMasternodesV2)
	}

	persistedRawCfg, err := rawdb.ReadChainConfigJSON(db, hash)
	if err != nil {
		t.Fatalf("failed to read persisted raw chain config: %v", err)
	}
	if bytes.Equal(persistedRawCfg, updatedRawCfg) {
		t.Fatal("expected migration to rewrite sparse raw chain config")
	}
}

func TestResolveSetupStoredConfigResultWritesConfigAndMarkerAtomically(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	storedCfg := params.TestnetChainConfig.Clone()
	newCfg := storedCfg.Clone()

	deps := defaultGenesisDeps
	deps.writeChainConfigOverride = func(ethdb.KeyValueWriter, common.Hash) {
		panic("simulated crash before override marker write")
	}

	defer func() {
		if recover() == nil {
			t.Fatal("expected override marker write to panic")
		}
		storedAfterPanic, err := rawdb.ReadChainConfig(db, params.TestnetGenesisHash)
		if !errors.Is(err, rawdb.ErrChainConfigNotFound) {
			t.Fatalf("expected no stored chain config after interrupted persistence, have cfg=%v err=%v", storedAfterPanic, err)
		}
		marker, err := rawdb.ReadChainConfigOverride(db, params.TestnetGenesisHash)
		if err != nil {
			t.Fatalf("failed to read override marker: %v", err)
		}
		if marker {
			t.Fatal("did not expect override marker after interrupted persistence")
		}
	}()

	_, _, _ = resolveSetupStoredConfigResultWithDeps(deps, db, params.TestnetGenesisHash, storedCfg, newCfg, nil, &types.Header{Number: new(big.Int)}, setupStoredOverrideState{
		legacyStoredOverride: true,
		trustedOverride:      true,
	})
}

func TestResolveSetupStoredConfigResultUsesChainConfigJSONEqualForPersistDecision(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	storedCfg := params.TestnetChainConfig.Clone()
	newCfg := storedCfg.Clone()
	newCfg.XDPoS = newCfg.XDPoS.Clone()
	newCfg.XDPoS.MaxMasternodesV2++

	writeCalls := 0
	deps := defaultGenesisDeps
	deps.hashChainConfigSemanticVersioned = func(*params.ChainConfig) (byte, [32]byte) {
		return chainConfigDigestVersion, [32]byte{}
	}
	deps.writeChainConfig = func(db ethdb.KeyValueWriter, hash common.Hash, cfg *params.ChainConfig) {
		writeCalls++
		rawdb.WriteChainConfig(db, hash, cfg)
	}

	resolvedCfg, compatErr, err := resolveSetupStoredConfigResultWithDeps(deps, db, common.HexToHash("0x1234"), storedCfg, newCfg, nil, &types.Header{Number: new(big.Int)}, setupStoredOverrideState{
		trustedOverride: true,
	})
	if err != nil {
		t.Fatalf("resolveSetupStoredConfigResultWithDeps failed: %v", err)
	}
	if compatErr != nil {
		t.Fatalf("unexpected compatibility error: %v", compatErr)
	}
	if resolvedCfg != newCfg {
		t.Fatalf("unexpected resolved config: have %p want %p", resolvedCfg, newCfg)
	}
	if writeCalls != 0 {
		t.Fatalf("expected chain-config write to be skipped when chainConfigJSONEqual reports equality, got %d writes", writeCalls)
	}
	storedAfter, err := rawdb.ReadChainConfig(db, common.HexToHash("0x1234"))
	if !errors.Is(err, rawdb.ErrChainConfigNotFound) {
		t.Fatalf("expected no stored chain config write, have cfg=%v err=%v", storedAfter, err)
	}
}

// TestSetupGenesisBlockRejectsLegacyStoredSameHashCustomConfigWithoutExplicitGenesis
// tests ordinary writable restart does not implicitly migrate a pre-marker
// same-hash custom config without the authoritative genesis file.
func TestSetupGenesisBlockRejectsLegacyStoredSameHashCustomConfigWithoutExplicitGenesis(t *testing.T) {
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
		t.Fatal("did not expect override marker before explicit migration")
	}

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
		t.Fatalf("expected nil config on implicit migration attempt, have %v", cfg)
	}

	marker, err = rawdb.ReadChainConfigOverride(db, params.TestnetGenesisHash)
	if err != nil {
		t.Fatalf("failed to read override marker after restart attempt: %v", err)
	}
	if marker {
		t.Fatal("did not expect restart without explicit genesis to write override marker")
	}
	storedCfg, err := rawdb.ReadChainConfig(db, params.TestnetGenesisHash)
	if err != nil {
		t.Fatalf("failed to read stored chain config: %v", err)
	}
	if storedCfg == nil {
		t.Fatal("expected stored chain config")
	}
	if storedCfg.ChainID == nil || storedCfg.ChainID.Cmp(legacyGenesis.Config.ChainID) != 0 {
		t.Fatalf("unexpected stored chain ID after failed restart: have %v want %v", storedCfg.ChainID, legacyGenesis.Config.ChainID)
	}
}

// TestLoadChainConfigWithCompatRejectsLegacyStoredSameHashCustomConfigWithoutOverrideMarker
// tests readonly startup diagnostics do not implicitly migrate a pre-marker
// same-hash custom config even when a matching explicit genesis is provided.
func TestLoadChainConfigWithCompatRejectsLegacyStoredSameHashCustomConfigWithoutOverrideMarker(t *testing.T) {
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
		t.Fatal("did not expect override marker before explicit writable migration")
	}

	cfg, hash, compatErr, err := LoadChainConfigWithCompat(db, legacyGenesis)
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
		t.Fatalf("expected nil config for readonly legacy migration attempt, have %v", cfg)
	}

	marker, err = rawdb.ReadChainConfigOverride(db, params.TestnetGenesisHash)
	if err != nil {
		t.Fatalf("failed to read override marker after readonly check: %v", err)
	}
	if marker {
		t.Fatal("did not expect readonly check to write override marker")
	}
}

// TestLoadChainConfigWithCompatRejectsMalformedOverrideMarker tests readonly startup fails fast on malformed versioned override metadata.
func TestLoadChainConfigWithCompatRejectsMalformedOverrideMarker(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	DefaultTestnetGenesisBlock().MustCommit(db)

	key := append([]byte("xdc-cfg-override-"), params.TestnetGenesisHash.Bytes()...)
	if err := db.Put(key, []byte{1}); err != nil {
		t.Fatalf("failed to write malformed override marker: %v", err)
	}

	cfg, hash, compatErr, err := LoadChainConfigWithCompat(db, nil)
	if err == nil || !strings.Contains(err.Error(), "invalid chain config override marker payload") {
		t.Fatalf("expected malformed marker error, got %v", err)
	}
	if compatErr != nil {
		t.Fatalf("unexpected compatibility error: %v", compatErr)
	}
	if hash != params.TestnetGenesisHash {
		t.Fatalf("unexpected hash: have %s want %s", hash.Hex(), params.TestnetGenesisHash.Hex())
	}
	if cfg != nil {
		t.Fatalf("expected nil config on malformed marker, have %v", cfg)
	}
}

// TestLoadChainConfigRejectsProvidedSameHashCustomConfigForStoredBuiltInChainWhenChainConfigMissing tests load chain config rejects same-hash custom config when built-in chain metadata is missing and no override marker exists.
func TestLoadChainConfigRejectsProvidedSameHashCustomConfigForStoredBuiltInChainWhenChainConfigMissing(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	block := DefaultTestnetGenesisBlock().MustCommit(db)

	if err := db.Delete(testConfigKey(block.Hash())); err != nil {
		t.Fatalf("failed to delete chain config: %v", err)
	}

	provided := DefaultTestnetGenesisBlock()
	provided.Config = provided.Config.Clone()
	provided.Config.ChainID = big.NewInt(99999)
	provided.Config.XDPoS = nil
	provided.Config.Ethash = new(params.EthashConfig)

	cfg, hash, err := LoadChainConfig(db, provided)
	if !errors.Is(err, errGenesisConfigConflict) {
		t.Fatalf("unexpected error: have %v want %v", err, errGenesisConfigConflict)
	}
	if hash != params.TestnetGenesisHash {
		t.Fatalf("unexpected hash: have %s want %s", hash.Hex(), params.TestnetGenesisHash.Hex())
	}
	if cfg != nil {
		t.Fatalf("expected nil config, have %v", cfg)
	}
}

// TestLoadChainConfigRejectsMissingStoredGas50xBlockForCustomNetworkReadPath tests load chain config rejects missing stored gas 50 x block for custom network read path.
func TestLoadChainConfigRejectsMissingStoredGas50xBlockForCustomNetworkReadPath(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	genesis := &Genesis{
		Config: &params.ChainConfig{
			ChainID:                big.NewInt(61616),
			TIPTRC21FeeBlock:       big.NewInt(0),
			Gas50xBlock:            big.NewInt(12345),
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
	updatedRawCfg, err := removeTopLevelFieldFromRawConfig(rawCfg, "gas50xBlock")
	if err != nil {
		t.Fatalf("failed to remove gas50xBlock from raw config: %v", err)
	}
	if err := db.Put(testConfigKey(block.Hash()), updatedRawCfg); err != nil {
		t.Fatalf("failed to write modified raw chain config: %v", err)
	}

	cfg, hash, err := LoadChainConfig(db, nil)
	if err == nil {
		t.Fatal("expected missing Gas50xBlock error")
	}
	if hash != block.Hash() {
		t.Fatalf("unexpected hash: have %s want %s", hash.Hex(), block.Hash().Hex())
	}
	if cfg != nil {
		t.Fatalf("expected nil config on invalid stored custom network, have %v", cfg)
	}
	if !strings.Contains(err.Error(), "Gas50xBlock") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestSetupGenesisRejectsMissingStoredGas50xBlockForCustomNetworkReadPath tests setup genesis rejects missing stored gas 50 x block for custom network read path.
func TestSetupGenesisRejectsMissingStoredGas50xBlockForCustomNetworkReadPath(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	genesis := &Genesis{
		Config: &params.ChainConfig{
			ChainID:                big.NewInt(62626),
			TIPTRC21FeeBlock:       big.NewInt(0),
			Gas50xBlock:            big.NewInt(12345),
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
	updatedRawCfg, err := removeTopLevelFieldFromRawConfig(rawCfg, "gas50xBlock")
	if err != nil {
		t.Fatalf("failed to remove gas50xBlock from raw config: %v", err)
	}
	if err := db.Put(testConfigKey(block.Hash()), updatedRawCfg); err != nil {
		t.Fatalf("failed to write modified raw chain config: %v", err)
	}

	cfg, hash, _, err := SetupGenesisBlock(db, nil)
	if err == nil {
		t.Fatal("expected missing Gas50xBlock error")
	}
	if hash != (common.Hash{}) {
		t.Fatalf("unexpected hash: have %s want %s", hash.Hex(), common.Hash{}.Hex())
	}
	if cfg != nil {
		t.Fatalf("expected nil config on invalid stored custom network, have %v", cfg)
	}
	if !strings.Contains(err.Error(), "Gas50xBlock") {
		t.Fatalf("unexpected error: %v", err)
	}
}

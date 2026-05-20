package core

import (
	"encoding/json"
	"errors"
	"math/big"
	"reflect"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/startup"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/params"
)

func TestResolveLoadDefaultMainnetWithActionUsesExplicitReadonlySource(t *testing.T) {
	action := decideInitialStartupAction(common.Hash{}, false, false)
	if action.GenesisSource != startup.GenesisSourceDefaultMainnetReadonly {
		t.Fatalf("unexpected readonly genesis source: have %v want %v", action.GenesisSource, startup.GenesisSourceDefaultMainnetReadonly)
	}
	if action.AllowCommitGenesis {
		t.Fatal("readonly fallback must not allow genesis commit")
	}

	cfg, hash := resolveLoadDefaultMainnetWithAction()
	if cfg == nil {
		t.Fatal("expected config")
	}
	if hash != params.MainnetGenesisHash {
		t.Fatalf("unexpected genesis hash: have %s want %s", hash.Hex(), params.MainnetGenesisHash.Hex())
	}
	if !chainConfigSemanticallyEqual(cfg, params.XDCMainnetChainConfig) {
		t.Fatalf("unexpected config: have %v want %v", cfg, params.XDCMainnetChainConfig)
	}
}

func TestSelectInitialGenesisPanicsOnUnexpectedSource(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic for unexpected startup genesis source")
		}
	}()

	selectInitialGenesis(startup.Action{GenesisSource: startup.GenesisSourceStored}, &Genesis{})
}

func TestExpectReadonlyDefaultMainnetAction(t *testing.T) {
	t.Run("accepts explicit readonly default-mainnet action", func(t *testing.T) {
		expectReadonlyDefaultMainnetAction(startup.Action{GenesisSource: startup.GenesisSourceDefaultMainnetReadonly})
	})

	t.Run("panics on unexpected action", func(t *testing.T) {
		defer func() {
			if recover() == nil {
				t.Fatal("expected panic for unexpected readonly fallback action")
			}
		}()

		expectReadonlyDefaultMainnetAction(startup.Action{GenesisSource: startup.GenesisSourceProvided})
	})
}

func TestExpectStoredConfigHeaderAction(t *testing.T) {
	t.Run("returns terminal error", func(t *testing.T) {
		err := expectStoredConfigHeaderAction(startup.Action{TerminalError: startup.DecisionErrorGenesisHeaderNotFound})
		if !errors.Is(err, startup.ErrGenesisHeaderNotFound) {
			t.Fatalf("unexpected error: have %v want %v", err, startup.ErrGenesisHeaderNotFound)
		}
	})

	t.Run("accepts explicit stored source", func(t *testing.T) {
		if err := expectStoredConfigHeaderAction(startup.Action{GenesisSource: startup.GenesisSourceStored}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("panics on unexpected non-terminal action", func(t *testing.T) {
		defer func() {
			if recover() == nil {
				t.Fatal("expected panic for unexpected stored-config header action")
			}
		}()

		_ = expectStoredConfigHeaderAction(startup.Action{GenesisSource: startup.GenesisSourceDefaultMainnet})
	})
}

func TestLoadChainConfigReturnsGenesisHashError(t *testing.T) {
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

	cfg, hash, err := loadChainConfigWithDeps(db, genesis, deps)
	if !errors.Is(err, wantErr) {
		t.Fatalf("unexpected error: have %v want %v", err, wantErr)
	}
	if cfg != nil {
		t.Fatalf("expected nil config, have %v", cfg)
	}
	if hash != (common.Hash{}) {
		t.Fatalf("expected zero genesis hash, have %s", hash.Hex())
	}
}

func TestDecideStoredConfigHeaderActionUsesExplicitStoredSource(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	DefaultGenesisBlock().MustCommit(db)

	action := decideStoredConfigHeaderAction(db, params.MainnetGenesisHash)
	if action.GenesisSource != startup.GenesisSourceStored {
		t.Fatalf("unexpected startup source: have %v want %v", action.GenesisSource, startup.GenesisSourceStored)
	}
	if action.TerminalError != startup.DecisionErrorNone {
		t.Fatalf("unexpected terminal error: have %v want %v", action.TerminalError, startup.DecisionErrorNone)
	}
}

func TestIsExpectedStoredConfigHeaderAction(t *testing.T) {
	tests := []struct {
		name   string
		action startup.Action
		want   bool
	}{
		{
			name: "stored source without terminal error is expected",
			action: startup.Action{
				GenesisSource: startup.GenesisSourceStored,
			},
			want: true,
		},
		{
			name: "terminal error keeps action unexpected",
			action: startup.Action{
				GenesisSource: startup.GenesisSourceStored,
				TerminalError: startup.DecisionErrorGenesisHeaderNotFound,
			},
			want: false,
		},
		{
			name: "non stored source is unexpected",
			action: startup.Action{
				GenesisSource: startup.GenesisSourceDefaultMainnet,
			},
			want: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := isExpectedStoredConfigHeaderAction(test.action); got != test.want {
				t.Fatalf("unexpected expectation result: have %t want %t", got, test.want)
			}
		})
	}
}

// TestLoadChainConfigReturnsIndependentCopyForBuiltInConfig tests load chain config returns independent copy for built in config.
func TestLoadChainConfigReturnsIndependentCopyForBuiltInConfig(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	DefaultGenesisBlock().MustCommit(db)

	cfg, hash, err := LoadChainConfig(db, nil)
	if err != nil {
		t.Fatalf("LoadChainConfig failed: %v", err)
	}
	if hash != params.MainnetGenesisHash {
		t.Fatalf("unexpected genesis hash: have %s want %s", hash.Hex(), params.MainnetGenesisHash.Hex())
	}
	if cfg == nil {
		t.Fatal("expected config")
	}
	if cfg == params.XDCMainnetChainConfig {
		t.Fatal("unexpected builtin singleton reuse")
	}
	if cfg.ChainID == params.XDCMainnetChainConfig.ChainID {
		t.Fatal("expected builtin chain id to be deep-copied")
	}
	if cfg.XDPoS == nil || params.XDCMainnetChainConfig.XDPoS == nil {
		t.Fatalf("expected XDPoS configs to be present: have %v builtin %v", cfg.XDPoS, params.XDCMainnetChainConfig.XDPoS)
	}
	if cfg.XDPoS == params.XDCMainnetChainConfig.XDPoS {
		t.Fatal("expected XDPoS config to be deep-copied")
	}
	if cfg.XDPoS.V2 == nil || params.XDCMainnetChainConfig.XDPoS.V2 == nil {
		t.Fatalf("expected V2 configs to be present: have %v builtin %v", cfg.XDPoS.V2, params.XDCMainnetChainConfig.XDPoS.V2)
	}
	if cfg.XDPoS.V2 == params.XDCMainnetChainConfig.XDPoS.V2 {
		t.Fatal("expected V2 config to be deep-copied")
	}
	if cfg.XDPoS.V2.CurrentConfig == params.XDCMainnetChainConfig.XDPoS.V2.CurrentConfig {
		t.Fatal("expected CurrentConfig to be deep-copied")
	}
}

// TestLoadChainConfigRejectsMissingChainIDForNonBuiltInChain tests load chain config rejects missing chain id for non built in chain.
func TestLoadChainConfigRejectsMissingChainIDForNonBuiltInChain(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	genesis := &Genesis{
		Config: &params.ChainConfig{
			ChainID:                big.NewInt(4545),
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

	resolvedCfg, hash, err := LoadChainConfig(db, nil)
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

// TestChainConfigOrDefaultUsesBundledConfigOnBuiltInHash tests chain config or default uses bundled config on built in hash.
func TestChainConfigOrDefaultUsesBundledConfigOnBuiltInHash(t *testing.T) {
	stored := &params.ChainConfig{ChainID: big.NewInt(7777)}
	got := (*Genesis)(nil).chainConfigOrDefault(params.MainnetGenesisHash, stored, false)
	got = got.CloneForBackfill()
	if got == nil {
		t.Fatal("expected config")
	}
	if got == params.XDCMainnetChainConfig {
		t.Fatal("expected built-in config to be cloned")
	}
	if !chainConfigSemanticallyEqual(got, params.XDCMainnetChainConfig) {
		t.Fatalf("expected bundled config values to win on built-in hash, have %+v want %+v", got, params.XDCMainnetChainConfig)
	}
}

func TestResolveStoredChainConfigBackfillsBuiltInConfig(t *testing.T) {
	stored := params.TestnetChainConfig.Clone()
	stored.EIP1559Block = nil

	resolved, err := resolveStoredChainConfig(params.TestnetGenesisHash, stored)
	if err != nil {
		t.Fatalf("resolveStoredChainConfig failed: %v", err)
	}
	if resolved == nil {
		t.Fatal("expected resolved config")
	}
	if resolved.EIP1559Block == nil {
		t.Fatal("expected eip1559Block to be backfilled from built-in config")
	}
}

// TestLoadChainConfigReturnsCompatErrorForStoredBuiltInHashDriftAfterFork tests load chain config returns compat error for stored built in hash drift after fork.
func TestLoadChainConfigReturnsCompatErrorForStoredBuiltInHashDriftAfterFork(t *testing.T) {
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
	cfg, hash, compatErr, err := LoadChainConfigWithCompat(db, provided)
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

// TestLoadChainConfigAllowsLegacyCustomChainWithCompleteMigratedForkFields tests load chain config allows legacy custom chain with complete migrated fork fields.
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

// TestLoadChainConfigBackfillsMissingMigratedForkFieldForLegacyCustomXDPoSChain tests load chain config backfills missing migrated fork field for legacy custom xd po s chain.
func TestLoadChainConfigBackfillsMissingMigratedForkFieldForLegacyCustomXDPoSChain(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	cfg := params.LocalnetChainConfig.Clone()
	cfg.ChainID = big.NewInt(9899)
	genesis := &Genesis{
		Config:    cfg,
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
	updatedRawCfg, err := removeTopLevelFieldFromRawConfig(rawCfg, "gas50xBlock")
	if err != nil {
		t.Fatalf("failed to remove gas50xBlock from raw config: %v", err)
	}
	if err := db.Put(testConfigKey(block.Hash()), updatedRawCfg); err != nil {
		t.Fatalf("failed to write modified raw chain config: %v", err)
	}

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
	wantGas50x := big.NewInt(0)
	if loadedCfg.Gas50xBlock == nil || loadedCfg.Gas50xBlock.Cmp(wantGas50x) != 0 {
		t.Fatalf("expected Gas50xBlock to be backfilled from compatibility defaults, have %v want %v", loadedCfg.Gas50xBlock, wantGas50x)
	}
}

// TestLoadChainConfigUsesStoredBuiltInConfigWhenChainConfigMissing tests load chain config uses stored built in config when chain config missing.
func TestLoadChainConfigUsesStoredBuiltInConfigWhenChainConfigMissing(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	block := DefaultTestnetGenesisBlock().MustCommit(db)

	if err := db.Delete(testConfigKey(block.Hash())); err != nil {
		t.Fatalf("failed to delete chain config: %v", err)
	}

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

// TestLoadChainConfigUsesStoredBuiltInHashWhenChainConfigMissing tests load chain config uses stored built in hash when chain config missing.
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

// TestLoadChainConfigReturnsIndependentBuiltInConfigWhenStoredBuiltInConfigMissingFields tests load chain config returns independent built in config when stored built in config missing fields.
func TestLoadChainConfigReturnsIndependentBuiltInConfigWhenStoredBuiltInConfigMissingFields(t *testing.T) {
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
	if cfg == params.TestnetChainConfig {
		t.Fatal("unexpected builtin singleton reuse")
	}
	if !chainConfigSemanticallyEqual(cfg, params.TestnetChainConfig) {
		t.Fatalf("unexpected config: have %v want %v", cfg, params.TestnetChainConfig)
	}
	if cfg.EIP1559Block == nil {
		t.Fatalf("expected eip1559Block from built-in config, got nil")
	}
}

// TestLoadChainConfigReturnsIndependentBuiltInConfigWhenStoredBuiltInConfigMissingXDPoS tests load chain config returns independent built in config when stored built in config missing xd po s.
func TestLoadChainConfigReturnsIndependentBuiltInConfigWhenStoredBuiltInConfigMissingXDPoS(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	DefaultTestnetGenesisBlock().MustCommit(db)

	stored := params.TestnetGenesisHash
	rawCfg, err := rawdb.ReadChainConfigJSON(db, stored)
	if err != nil {
		t.Fatalf("failed to read raw chain config: %v", err)
	}
	updatedRawCfg, err := removeTopLevelFieldFromRawConfig(rawCfg, "XDPoS")
	if err != nil {
		t.Fatalf("failed to remove XDPoS from raw config: %v", err)
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
	if cfg == params.TestnetChainConfig {
		t.Fatal("unexpected builtin singleton reuse")
	}
	if !chainConfigSemanticallyEqual(cfg, params.TestnetChainConfig) {
		t.Fatalf("unexpected config: have %v want %v", cfg, params.TestnetChainConfig)
	}
	if cfg.XDPoS == nil {
		t.Fatal("expected XDPoS from built-in config, got nil")
	}
}

// TestLoadChainConfigReturnsStoredBuiltInHashDeclaredFields tests load chain config returns stored built in hash declared fields.
func TestLoadChainConfigReturnsStoredBuiltInHashDeclaredFields(t *testing.T) {
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

	cfg, hash, err := LoadChainConfig(db, nil)
	if !errors.Is(err, errGenesisConfigConflict) {
		t.Fatalf("unexpected error: have %v want %v", err, errGenesisConfigConflict)
	}
	if hash != stored {
		t.Fatalf("unexpected hash: have %s want %s", hash.Hex(), stored.Hex())
	}
	if cfg != nil {
		t.Fatalf("expected nil config on built-in drift, have %v", cfg)
	}
}

// TestLoadChainConfigReturnsStoredBuiltInHashDriftWithXDPoS tests load chain config returns stored built in hash drift with xd po s.
func TestLoadChainConfigReturnsStoredBuiltInHashDriftWithXDPoS(t *testing.T) {
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
		{
			name: "address drift",
			mutate: func(cfg *params.ChainConfig) {
				cfg.TRC21IssuerSMC = common.HexToAddress("0x0000000000000000000000000000000000000001")
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

			cfg, hash, err := LoadChainConfig(db, nil)
			if !errors.Is(err, errGenesisConfigConflict) {
				t.Fatalf("unexpected error: have %v want %v", err, errGenesisConfigConflict)
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

// TestLoadChainConfigAcceptsProvidedBuiltInHashConfigWithMissingFields tests load chain config accepts provided built in hash config with missing fields.
func TestLoadChainConfigAcceptsProvidedBuiltInHashConfigWithMissingFields(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	genesis := DefaultTestnetGenesisBlock()
	genesis.Config = genesis.Config.Clone()
	genesis.Config.EIP1559Block = nil

	cfg, hash, err := LoadChainConfig(db, genesis)
	if err != nil {
		t.Fatalf("LoadChainConfig failed: %v", err)
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
}

// TestLoadChainConfigDoesNotMutateProvidedBuiltInHashConfigWithoutStoredConfig tests load chain config does not mutate provided built in hash config without stored config.
func TestLoadChainConfigDoesNotMutateProvidedBuiltInHashConfigWithoutStoredConfig(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	genesis := DefaultTestnetGenesisBlock()
	genesis.Config = genesis.Config.Clone()
	genesis.Config.EIP1559Block = nil
	originalHash := genesis.ToBlock().Hash()

	cfg, hash, err := LoadChainConfig(db, genesis)
	if err != nil {
		t.Fatalf("LoadChainConfig failed: %v", err)
	}
	if hash != params.TestnetGenesisHash {
		t.Fatalf("unexpected hash: have %s want %s", hash.Hex(), params.TestnetGenesisHash.Hex())
	}
	if cfg == nil || cfg.EIP1559Block == nil {
		t.Fatalf("expected hydrated config with eip1559Block, have %v", cfg)
	}
	if genesis.Config.EIP1559Block != nil {
		t.Fatalf("expected provided genesis config to remain unchanged, have %v", genesis.Config.EIP1559Block)
	}
	if got := genesis.ToBlock().Hash(); got != originalHash {
		t.Fatalf("expected provided genesis hash to remain unchanged, have %s want %s", got.Hex(), originalHash.Hex())
	}
}

// TestLoadChainConfigDoesNotMutateProvidedBuiltInHashConfigWithStoredConfig tests load chain config does not mutate provided built in hash config with stored config.
func TestLoadChainConfigDoesNotMutateProvidedBuiltInHashConfigWithStoredConfig(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	DefaultTestnetGenesisBlock().MustCommit(db)

	genesis := DefaultTestnetGenesisBlock()
	genesis.Config = genesis.Config.Clone()
	genesis.Config.EIP1559Block = nil
	originalHash := genesis.ToBlock().Hash()

	cfg, hash, err := LoadChainConfig(db, genesis)
	if err != nil {
		t.Fatalf("LoadChainConfig failed: %v", err)
	}
	if hash != params.TestnetGenesisHash {
		t.Fatalf("unexpected hash: have %s want %s", hash.Hex(), params.TestnetGenesisHash.Hex())
	}
	if cfg == nil || cfg.EIP1559Block == nil {
		t.Fatalf("expected hydrated config with eip1559Block, have %v", cfg)
	}
	if genesis.Config.EIP1559Block != nil {
		t.Fatalf("expected provided genesis config to remain unchanged, have %v", genesis.Config.EIP1559Block)
	}
	if got := genesis.ToBlock().Hash(); got != originalHash {
		t.Fatalf("expected provided genesis hash to remain unchanged, have %s want %s", got.Hex(), originalHash.Hex())
	}
}

// TestLoadChainConfigAcceptsProvidedBuiltInHashConfigWithMissingXDPoS tests load chain config accepts provided built in hash config with missing xd po s.
func TestLoadChainConfigAcceptsProvidedBuiltInHashConfigWithMissingXDPoS(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	genesis := DefaultTestnetGenesisBlock()
	genesis.Config = genesis.Config.Clone()
	genesis.Config.XDPoS = nil

	cfg, hash, err := LoadChainConfig(db, genesis)
	if err != nil {
		t.Fatalf("LoadChainConfig failed: %v", err)
	}
	if hash != params.TestnetGenesisHash {
		t.Fatalf("unexpected hash: have %s want %s", hash.Hex(), params.TestnetGenesisHash.Hex())
	}
	if !chainConfigSemanticallyEqual(cfg, params.TestnetChainConfig) {
		t.Fatalf("unexpected config: have %v want %v", cfg, params.TestnetChainConfig)
	}
	if cfg.XDPoS == nil {
		t.Fatal("expected XDPoS to be backfilled from built-in config")
	}
}

// TestLoadChainConfigAcceptsProvidedBuiltInHashCustomConfigOnEmptyDBWithExplicitRecovery
// tests load chain config accepts a built-in hash custom config on empty db
// when the operator explicitly opts into built-in override recovery.
func TestLoadChainConfigAcceptsProvidedBuiltInHashCustomConfigOnEmptyDBWithExplicitRecovery(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	genesis := DefaultTestnetGenesisBlock()
	genesis.Config = genesis.Config.Clone()
	genesis.Config.ChainID = big.NewInt(99999)

	cfg, hash, compatErr, err := LoadChainConfigWithCompatWithOverride(db, genesis, true)
	if err != nil {
		t.Fatalf("LoadChainConfig failed: %v", err)
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
}

// TestLoadChainConfigReloadsPersistedBuiltInHashCustomConfigWithExplicitRecovery
// tests load chain config reloads a persisted built-in hash custom config when
// the operator explicitly opts into built-in override recovery.
func TestLoadChainConfigReloadsPersistedBuiltInHashCustomConfigWithExplicitRecovery(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	genesis := DefaultTestnetGenesisBlock()
	genesis.Config = genesis.Config.Clone()
	genesis.Config.ChainID = big.NewInt(99999)

	if _, _, _, err := SetupGenesisBlockWithOverride(db, genesis, true); err != nil {
		t.Fatalf("initial SetupGenesisBlock failed: %v", err)
	}

	cfg, hash, compatErr, err := LoadChainConfigWithCompatWithOverride(db, nil, true)
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
		t.Fatal("expected returned config")
	}
	if cfg.ChainID == nil || cfg.ChainID.Cmp(big.NewInt(99999)) != 0 {
		t.Fatalf("expected persisted custom chain id on restart, have %v", cfg.ChainID)
	}
}

// TestLoadChainConfigRejectsStoredBuiltInHashDeclaredFieldsWhenProvidedGenesisPresent tests load chain config rejects stored built in hash declared fields when provided genesis present.
func TestLoadChainConfigRejectsStoredBuiltInHashDeclaredFieldsWhenProvidedGenesisPresent(t *testing.T) {
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

	provided := DefaultTestnetGenesisBlock()
	cfg, hash, err := LoadChainConfig(db, provided)
	if !errors.Is(err, errGenesisConfigConflict) {
		t.Fatalf("unexpected error: have %v want %v", err, errGenesisConfigConflict)
	}
	if hash != stored {
		t.Fatalf("unexpected hash: have %s want %s", hash.Hex(), stored.Hex())
	}
	if cfg != nil {
		t.Fatalf("expected nil config on built-in drift, have %v", cfg)
	}
}

// TestLoadChainConfigRejectsStoredBuiltInHashDriftWhenProvidedGenesisPresent tests load chain config rejects stored built in hash drift when provided genesis present.
func TestLoadChainConfigRejectsStoredBuiltInHashDriftWhenProvidedGenesisPresent(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	DefaultTestnetGenesisBlock().MustCommit(db)

	stored := params.TestnetGenesisHash
	storedCfg := params.TestnetChainConfig.Clone()
	storedCfg.TRC21IssuerSMC = common.HexToAddress("0x0000000000000000000000000000000000000001")
	overwriteStoredChainConfig(t, db, stored, storedCfg)

	provided := DefaultTestnetGenesisBlock()
	cfg, hash, err := LoadChainConfig(db, provided)
	if !errors.Is(err, errGenesisConfigConflict) {
		t.Fatalf("unexpected error: have %v want %v", err, errGenesisConfigConflict)
	}
	if hash != stored {
		t.Fatalf("unexpected hash: have %s want %s", hash.Hex(), stored.Hex())
	}
	if cfg != nil {
		t.Fatalf("expected nil config on built-in drift, have %v", cfg)
	}
}

func TestLoadChainConfigInternalMatchesCompatWrapperWhenNoCompatError(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	provided := DefaultTestnetGenesisBlock()
	_, _, _, err := SetupGenesisBlock(db, provided)
	if err != nil {
		t.Fatalf("SetupGenesisBlock failed: %v", err)
	}

	plainCfg, plainHash, plainCompatErr, err := loadChainConfigInternal(db, provided, defaultGenesisDeps, GenesisStartupOptions{}, false)
	if err != nil {
		t.Fatalf("loadChainConfigInternal without compat failed: %v", err)
	}
	if plainCompatErr != nil {
		t.Fatalf("expected nil compatErr from plain path, got %v", plainCompatErr)
	}

	compatCfg, compatHash, compatErr, err := loadChainConfigInternal(db, provided, defaultGenesisDeps, GenesisStartupOptions{}, true)
	if err != nil {
		t.Fatalf("loadChainConfigInternal with compat failed: %v", err)
	}
	if compatErr != nil {
		t.Fatalf("expected nil compatErr from compat path, got %v", compatErr)
	}
	if plainHash != compatHash {
		t.Fatalf("unexpected hash mismatch: have %s want %s", plainHash.Hex(), compatHash.Hex())
	}
	if !chainConfigSemanticallyEqual(plainCfg, compatCfg) {
		t.Fatalf("unexpected config mismatch: have %v want %v", plainCfg, compatCfg)
	}
}

// TestLoadChainConfigRejectsProvidedGenesisDriftForStoredCustomChain tests load chain config rejects provided genesis drift for stored custom chain.
func TestLoadChainConfigRejectsProvidedGenesisDriftForStoredCustomChain(t *testing.T) {
	newCustomXDPoSGenesis := func() *Genesis {
		xdposCfg := params.TestnetChainConfig.XDPoS.Clone()
		xdposCfg.Epoch = 1
		xdposCfg.V2 = xdposCfg.V2.Clone()
		xdposCfg.V2.SwitchBlock = big.NewInt(2)
		xdposCfg.V2.SwitchEpoch = 2
		return &Genesis{
			Config: &params.ChainConfig{
				ChainID:                big.NewInt(4545),
				TIPTRC21FeeBlock:       big.NewInt(1),
				Gas50xBlock:            big.NewInt(1),
				TRC21IssuerSMC:         params.TestnetChainConfig.TRC21IssuerSMC,
				XDCXListingSMC:         params.TestnetChainConfig.XDCXListingSMC,
				RelayerRegistrationSMC: params.TestnetChainConfig.RelayerRegistrationSMC,
				LendingRegistrationSMC: params.TestnetChainConfig.LendingRegistrationSMC,
				XDPoS:                  xdposCfg,
			},
			ExtraData: make([]byte, 32+crypto.SignatureLength),
			Alloc: types.GenesisAlloc{
				{1}: {Balance: big.NewInt(1)},
			},
			GasLimit:   4700000,
			Difficulty: big.NewInt(1),
		}
	}

	tests := []struct {
		name   string
		mutate func(*params.ChainConfig)
	}{
		{
			name: "system contract address drift",
			mutate: func(cfg *params.ChainConfig) {
				cfg.TRC21IssuerSMC = common.HexToAddress("0x0000000000000000000000000000000000000001")
			},
		},
		{
			name: "v2 switch epoch drift",
			mutate: func(cfg *params.ChainConfig) {
				cfg.XDPoS = cfg.XDPoS.Clone()
				cfg.XDPoS.V2 = cfg.XDPoS.V2.Clone()
				cfg.XDPoS.V2.SwitchEpoch++
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			db := rawdb.NewMemoryDatabase()
			storedGenesis := newCustomXDPoSGenesis()
			block := storedGenesis.MustCommit(db)

			provided := newCustomXDPoSGenesis()
			test.mutate(provided.Config)

			cfg, hash, err := LoadChainConfig(db, provided)
			if !errors.Is(err, errGenesisConfigConflict) {
				t.Fatalf("unexpected error: have %v want %v", err, errGenesisConfigConflict)
			}
			if hash != block.Hash() {
				t.Fatalf("unexpected hash: have %s want %s", hash.Hex(), block.Hash().Hex())
			}
			if cfg != nil {
				t.Fatalf("expected nil config on custom drift, have %v", cfg)
			}
		})
	}
}

// TestLoadChainConfigAllowsPlainCustomEthashChainWithoutXDCForkFields tests load chain config allows plain custom ethash chain without xdc fork fields.
func TestLoadChainConfigAllowsPlainCustomEthashChainWithoutXDCForkFields(t *testing.T) {
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

	cfg, _, err := LoadChainConfig(db, genesis)
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

// TestLoadChainConfigReturnsCompatErrorWhenCompatDriftRewindsToZero tests
// readonly config loading preserves rewind-to-zero compatibility errors.
func TestLoadChainConfigReturnsCompatErrorWhenCompatDriftRewindsToZero(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	genesisBlock := DefaultTestnetGenesisBlock().MustCommit(db)

	stored := params.TestnetGenesisHash
	storedCfg := params.TestnetChainConfig.Clone()
	storedCfg.EIP150Block = big.NewInt(1)
	rawCfg, err := json.Marshal(storedCfg)
	if err != nil {
		t.Fatalf("failed to marshal stored chain config: %v", err)
	}
	if err := db.Put(testConfigKey(stored), rawCfg); err != nil {
		t.Fatalf("failed to overwrite stored chain config: %v", err)
	}

	if genesisBlock == nil {
		t.Fatal("expected stored genesis block")
	}

	head := types.NewBlockWithHeader(&types.Header{
		Number:     big.NewInt(1),
		ParentHash: genesisBlock.Hash(),
	})
	rawdb.WriteBlock(db, head)
	rawdb.WriteCanonicalHash(db, head.Hash(), head.NumberU64())
	rawdb.WriteHeadHeaderHash(db, head.Hash())
	rawdb.WriteHeadBlockHash(db, head.Hash())
	rawdb.WriteHeadFastBlockHash(db, head.Hash())

	provided := DefaultTestnetGenesisBlock()
	cfg, hash, compatErr, err := LoadChainConfigWithCompat(db, provided)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	wantCompatErr := &params.ConfigCompatError{
		What:         "EIP150 fork block",
		StoredConfig: big.NewInt(1),
		NewConfig:    big.NewInt(2),
		RewindTo:     0,
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
	if persistedCfg == nil || persistedCfg.EIP150Block == nil || persistedCfg.EIP150Block.Cmp(storedCfg.EIP150Block) != 0 {
		t.Fatalf("expected stored config to remain unchanged, have %v", persistedCfg)
	}
}

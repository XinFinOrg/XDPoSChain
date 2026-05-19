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
	"github.com/XinFinOrg/XDPoSChain/ethdb"
	"github.com/XinFinOrg/XDPoSChain/params"
)

func TestCurrentXDPoSRoundFromHead(t *testing.T) {
	cfg := &params.ChainConfig{
		XDPoS: &params.XDPoSConfig{
			V2: &params.V2{SwitchBlock: big.NewInt(100)},
		},
	}

	switchHead := &types.Header{Number: big.NewInt(100)}
	round, err := currentXDPoSRoundFromHead(switchHead, cfg)
	if err != nil {
		t.Fatalf("unexpected error at switch block: %v", err)
	}
	if round == nil || *round != 0 {
		t.Fatalf("unexpected switch block round: have %v want 0", round)
	}

	extra, err := (&types.ExtraFields_v2{
		Round: types.Round(12),
		QuorumCert: &types.QuorumCert{
			ProposedBlockInfo: &types.BlockInfo{Hash: common.BigToHash(big.NewInt(1)), Round: types.Round(11), Number: big.NewInt(100)},
			Signatures:        []types.Signature{{1, 2, 3}},
		},
	}).EncodeToBytes()
	if err != nil {
		t.Fatalf("failed to encode V2 extra fields: %v", err)
	}
	postSwitchHead := &types.Header{Number: big.NewInt(101), Extra: extra}
	round, err = currentXDPoSRoundFromHead(postSwitchHead, cfg)
	if err != nil {
		t.Fatalf("unexpected error after switch block: %v", err)
	}
	if round == nil || *round != 12 {
		t.Fatalf("unexpected post-switch round: have %v want 12", round)
	}

	_, err = currentXDPoSRoundFromHead(&types.Header{Number: big.NewInt(101), Extra: []byte{1}}, cfg)
	if err == nil {
		t.Fatal("expected invalid post-switch extra fields to fail")
	}
}

// TestDefaultGenesisBlock tests default genesis block.
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

// TestBuiltInChainConfigByHashHashOnly tests built in chain config by hash hash only.
func TestBuiltInChainConfigByHashHashOnly(t *testing.T) {
	tests := []struct {
		name string
		hash common.Hash
		want bool
	}{
		{name: "mainnet hash", hash: params.MainnetGenesisHash, want: true},
		{name: "testnet hash", hash: params.TestnetGenesisHash, want: true},
		{name: "devnet hash", hash: params.DevnetGenesisHash, want: true},
		{name: "empty hash", hash: common.Hash{}, want: false},
		{name: "random hash", hash: common.HexToHash("0x1"), want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := builtInChainConfigByHash(tt.hash) != nil; got != tt.want {
				t.Fatalf("unexpected built-in match for %s: have %v want %v", tt.hash.Hex(), got, tt.want)
			}
		})
	}
}

func TestIsConsensusOptionalTestChain(t *testing.T) {
	tests := []struct {
		name    string
		chainID *big.Int
		want    bool
	}{
		{name: "nil chain id", chainID: nil, want: false},
		{name: "consensus-optional test chain", chainID: new(big.Int).SetUint64(params.ConsensusOptionalTestChainID), want: true},
		{name: "other chain", chainID: big.NewInt(1), want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isConsensusOptionalTestChain(tt.chainID); got != tt.want {
				t.Fatalf("unexpected consensus optional result: have %v want %v", got, tt.want)
			}
		})
	}
}

// TestCloneChainConfigDeepCopiesMigratedForkBlocks tests clone chain config deep copies migrated fork blocks.
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
		Gas50xBlock:                 big.NewInt(77),
		BerlinBlock:                 big.NewInt(80),
		LondonBlock:                 big.NewInt(90),
		MergeBlock:                  big.NewInt(100),
		ShanghaiBlock:               big.NewInt(110),
		TIPXDCXMinerDisableBlock:    big.NewInt(120),
		TIPXDCXReceiverDisableBlock: big.NewInt(130),
		EIP1559Block:                big.NewInt(140),
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
	for _, key := range builtInBackfillForkFieldJSONKeysForTests {
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

func TestGenesisCopyDeepCopiesChainConfig(t *testing.T) {
	original := &Genesis{
		Config: &params.ChainConfig{
			ChainID: big.NewInt(5151),
			XDPoS: &params.XDPoSConfig{
				V2: &params.V2{
					CurrentConfig: &params.V2Config{TimeoutPeriod: 15},
				},
			},
		},
	}

	copy := original.copy()
	if copy == nil || copy.Config == nil {
		t.Fatalf("expected copied genesis config, have %#v", copy)
	}
	if copy.Config == original.Config {
		t.Fatal("expected Genesis.copy to clone ChainConfig")
	}
	if copy.Config.ChainID == original.Config.ChainID {
		t.Fatal("expected Genesis.copy to deep-copy ChainID")
	}
	if copy.Config.XDPoS == nil || copy.Config.XDPoS.V2 == nil || copy.Config.XDPoS.V2.CurrentConfig == nil {
		t.Fatalf("expected copied XDPoS V2 config, have %+v", copy.Config.XDPoS)
	}
	if copy.Config.XDPoS == original.Config.XDPoS {
		t.Fatal("expected Genesis.copy to deep-copy XDPoS config")
	}
	if copy.Config.XDPoS.V2 == original.Config.XDPoS.V2 {
		t.Fatal("expected Genesis.copy to deep-copy XDPoS V2 config")
	}
	if copy.Config.XDPoS.V2.CurrentConfig == original.Config.XDPoS.V2.CurrentConfig {
		t.Fatal("expected Genesis.copy to deep-copy current V2 config")
	}

	copy.Config.ChainID.SetUint64(9999)
	copy.Config.XDPoS.V2.CurrentConfig.TimeoutPeriod = 30
	if original.Config.ChainID.Uint64() != 5151 {
		t.Fatalf("expected original chain ID to remain unchanged, have %d", original.Config.ChainID.Uint64())
	}
	if original.Config.XDPoS.V2.CurrentConfig.TimeoutPeriod != 15 {
		t.Fatalf("expected original timeout period to remain unchanged, have %d", original.Config.XDPoS.V2.CurrentConfig.TimeoutPeriod)
	}
}

// TestHydrateProvidedChainConfigPreservesEngineLessBuiltInTestNetwork tests hydrate provided chain config preserves engine less built in test network.
func TestHydrateProvidedChainConfigPreservesEngineLessBuiltInTestNetwork(t *testing.T) {
	futureFork := big.NewInt(1_000_000_000)
	cfg := &params.ChainConfig{
		ChainID:             big.NewInt(1337),
		EIP150Block:         big.NewInt(0),
		EIP155Block:         big.NewInt(2),
		EIP158Block:         big.NewInt(2),
		ByzantiumBlock:      new(big.Int).Set(futureFork),
		ConstantinopleBlock: new(big.Int).Set(futureFork),
		PetersburgBlock:     new(big.Int).Set(futureFork),
		IstanbulBlock:       new(big.Int).Set(futureFork),
		HomesteadBlock:      new(big.Int),
		TIPTRC21FeeBlock:    new(big.Int),
		BerlinBlock:         new(big.Int).Set(futureFork),
		LondonBlock:         new(big.Int).Set(futureFork),
		MergeBlock:          new(big.Int).Set(futureFork),
		ShanghaiBlock:       new(big.Int).Set(futureFork),
		EIP1559Block:        new(big.Int).Set(futureFork),
		CancunBlock:         new(big.Int).Set(futureFork),
		PragueBlock:         new(big.Int).Set(futureFork),
		OsakaBlock:          new(big.Int).Set(futureFork),
	}
	setXinFinForksToFuture(cfg, futureFork)

	hydrated, err := resolveProvidedChainConfig(common.Hash{}, cfg, builtInChainConfigMustMatch)
	if err != nil {
		t.Fatalf("hydrateProvidedChainConfig failed: %v", err)
	}
	if hydrated == nil {
		t.Fatal("expected hydrated config")
	}
	if hydrated.XDPoS != nil {
		t.Fatalf("expected XDPoS to remain nil for engine-less test config, have %v", hydrated.XDPoS)
	}
	if hydrated.Ethash != nil {
		t.Fatalf("expected Ethash to remain nil, have %v", hydrated.Ethash)
	}
	if hydrated.TIP2019Block != nil {
		t.Fatalf("expected no Localnet backfill for engine-less custom config, have %v", hydrated.TIP2019Block)
	}

	loadedCfg, _, err := LoadChainConfig(rawdb.NewMemoryDatabase(), &Genesis{Config: cfg, Alloc: types.GenesisAlloc{{1}: {Balance: big.NewInt(1)}}, GasLimit: 4700000, Difficulty: big.NewInt(1)})
	if err != nil {
		t.Fatalf("LoadChainConfig failed: %v", err)
	}
	if loadedCfg == nil {
		t.Fatal("expected LoadChainConfig to return resolved config")
	}
	if loadedCfg.XDPoS != nil {
		t.Fatalf("expected LoadChainConfig to preserve engine-less config for chain ID 1337, have %v", loadedCfg)
	}
}

// TestHydrateProvidedChainConfigRejectsEngineLessCustomMainnetChainIDWithoutBackfill tests hydrate provided chain config rejects engine less custom mainnet chain id without backfill.
func TestHydrateProvidedChainConfigRejectsEngineLessCustomMainnetChainIDWithoutBackfill(t *testing.T) {
	futureFork := big.NewInt(1_000_000_000)
	cfg := &params.ChainConfig{
		ChainID:             big.NewInt(1),
		EIP150Block:         big.NewInt(0),
		EIP155Block:         big.NewInt(2),
		EIP158Block:         big.NewInt(2),
		ByzantiumBlock:      new(big.Int).Set(futureFork),
		ConstantinopleBlock: new(big.Int).Set(futureFork),
		PetersburgBlock:     new(big.Int).Set(futureFork),
		IstanbulBlock:       new(big.Int).Set(futureFork),
		HomesteadBlock:      new(big.Int),
		TIPTRC21FeeBlock:    new(big.Int),
		BerlinBlock:         new(big.Int).Set(futureFork),
		LondonBlock:         new(big.Int).Set(futureFork),
		MergeBlock:          new(big.Int).Set(futureFork),
		ShanghaiBlock:       new(big.Int).Set(futureFork),
		EIP1559Block:        new(big.Int).Set(futureFork),
		CancunBlock:         new(big.Int).Set(futureFork),
		PragueBlock:         new(big.Int).Set(futureFork),
		OsakaBlock:          new(big.Int).Set(futureFork),
	}
	setXinFinForksToFuture(cfg, futureFork)

	hydrated, err := resolveProvidedChainConfig(common.Hash{}, cfg, builtInChainConfigMustMatch)
	if err != nil {
		t.Fatalf("hydrateProvidedChainConfig failed: %v", err)
	}
	if hydrated == nil {
		t.Fatal("expected hydrated config")
	}
	if hydrated.XDPoS != nil {
		t.Fatalf("expected custom chain ID 1 to remain engine-less, have %v", hydrated)
	}
	if hydrated.TIP2019Block != nil {
		t.Fatalf("expected no Localnet compatibility backfill for custom chain ID 1, have %v", hydrated.TIP2019Block)
	}

	loadedCfg, _, err := LoadChainConfig(rawdb.NewMemoryDatabase(), &Genesis{Config: cfg, Alloc: types.GenesisAlloc{{1}: {Balance: big.NewInt(1)}}, GasLimit: 4700000, Difficulty: big.NewInt(1)})
	if !errors.Is(err, params.ErrMissingForkSwitch) {
		t.Fatalf("expected missing consensus engine error, have %v want %v", err, params.ErrMissingForkSwitch)
	}
	if loadedCfg != nil {
		t.Fatalf("expected no resolved config for invalid custom chain ID 1, have %v", loadedCfg)
	}
}

// TestHydrateProvidedChainConfigRejectsCustomMainnetGenesisConfigDrift tests hydrate provided chain config rejects custom mainnet genesis config drift.
func TestHydrateProvidedChainConfigRejectsCustomMainnetGenesisConfigDrift(t *testing.T) {
	cfg := &params.ChainConfig{
		ChainID:        big.NewInt(7777),
		HomesteadBlock: big.NewInt(1),
		EIP150Block:    big.NewInt(2),
		EIP155Block:    big.NewInt(3),
		EIP158Block:    big.NewInt(3),
		ByzantiumBlock: big.NewInt(4),
	}

	hydrated, err := resolveProvidedChainConfig(params.MainnetGenesisHash, cfg, builtInChainConfigMustMatch)
	if !errors.Is(err, errGenesisConfigConflict) {
		t.Fatalf("unexpected error: have %v want %v", err, errGenesisConfigConflict)
	}
	if hydrated != nil {
		t.Fatalf("expected nil hydrated config on built-in drift, have %v", hydrated)
	}
}

func TestResolveProvidedChainConfigRejectsBuiltInConfigDrift(t *testing.T) {
	cfg := &params.ChainConfig{
		ChainID:        big.NewInt(7777),
		HomesteadBlock: big.NewInt(1),
		EIP150Block:    big.NewInt(2),
		EIP155Block:    big.NewInt(3),
		EIP158Block:    big.NewInt(3),
		ByzantiumBlock: big.NewInt(4),
	}

	resolved, err := resolveProvidedChainConfig(params.MainnetGenesisHash, cfg, builtInChainConfigMustMatch)
	if !errors.Is(err, errGenesisConfigConflict) {
		t.Fatalf("unexpected error: have %v want %v", err, errGenesisConfigConflict)
	}
	if resolved != nil {
		t.Fatalf("expected nil config on built-in drift, have %v", resolved)
	}
}

func TestGenesisConfigConflictMatchesCoreSentinel(t *testing.T) {
	err := builtInGenesisConfigConflictError(params.TestnetGenesisHash)
	if !errors.Is(err, errGenesisConfigConflict) {
		t.Fatalf("unexpected conflict classification: have %v want %v", err, errGenesisConfigConflict)
	}
	if errors.Is(err, startup.ErrGenesisConfigConflict) {
		t.Fatalf("unexpected startup decision classification: have %v should not match %v", err, startup.ErrGenesisConfigConflict)
	}

	_, resolveErr := resolveProvidedChainConfig(params.MainnetGenesisHash, &params.ChainConfig{
		ChainID:        big.NewInt(7777),
		HomesteadBlock: big.NewInt(1),
		EIP150Block:    big.NewInt(2),
		EIP155Block:    big.NewInt(3),
		EIP158Block:    big.NewInt(3),
		ByzantiumBlock: big.NewInt(4),
	}, builtInChainConfigMustMatch)
	if !errors.Is(resolveErr, errGenesisConfigConflict) {
		t.Fatalf("unexpected direct conflict classification: have %v want %v", resolveErr, errGenesisConfigConflict)
	}
	if errors.Is(resolveErr, startup.ErrGenesisConfigConflict) {
		t.Fatalf("unexpected startup decision classification: have %v should not match %v", resolveErr, startup.ErrGenesisConfigConflict)
	}
}

func TestNormalizeProvidedGenesisConfig(t *testing.T) {
	_, _, err := normalizeProvidedGenesisConfig(defaultGenesisDeps, &Genesis{}, builtInChainConfigMustMatch)
	if !errors.Is(err, errGenesisNoConfig) {
		t.Fatalf("unexpected error: have %v want %v", err, errGenesisNoConfig)
	}

	genesis := DefaultTestnetGenesisBlock()
	genesis.Config = genesis.Config.Clone()
	genesis.Config.EIP1559Block = nil
	originalHash := genesis.ToBlock().Hash()

	resolvedGenesis, resolvedHash, err := normalizeProvidedGenesisConfig(defaultGenesisDeps, genesis, builtInChainConfigMustMatch)
	if err != nil {
		t.Fatalf("normalizeProvidedGenesisConfig failed: %v", err)
	}
	if resolvedHash != originalHash {
		t.Fatalf("unexpected original hash: have %s want %s", resolvedHash.Hex(), originalHash.Hex())
	}
	if resolvedGenesis == nil || resolvedGenesis.Config == nil {
		t.Fatal("expected resolved genesis config")
	}
	if resolvedGenesis.Config.EIP1559Block == nil {
		t.Fatal("expected eip1559Block to be backfilled")
	}
	if genesis.Config.EIP1559Block != nil {
		t.Fatalf("expected caller genesis config to remain unchanged, have %v", genesis.Config.EIP1559Block)
	}
}

func TestDecideBuiltInChainConfigAction(t *testing.T) {
	tests := []struct {
		name  string
		facts builtInChainConfigFacts
		want  builtInChainConfigAction
	}{
		{
			name: "stored drift can be repaired at block zero with provided genesis",
			facts: builtInChainConfigFacts{
				hasBuiltInConfig:        true,
				storedMatchesBuiltIn:    false,
				candidateMatchesBuiltIn: true,
				allowStoredDriftRepair:  true,
			},
			want: builtInChainConfigAction{canonicalizeToBuiltIn: true},
		},
		{
			name: "stored drift after fork is conflict",
			facts: builtInChainConfigFacts{
				hasBuiltInConfig:        true,
				storedMatchesBuiltIn:    false,
				candidateMatchesBuiltIn: true,
			},
			want: builtInChainConfigAction{terminalError: startup.DecisionErrorGenesisConfigConflict},
		},
		{
			name: "candidate drift is conflict",
			facts: builtInChainConfigFacts{
				hasBuiltInConfig:        true,
				storedMatchesBuiltIn:    true,
				candidateMatchesBuiltIn: false,
			},
			want: builtInChainConfigAction{terminalError: startup.DecisionErrorGenesisConfigConflict},
		},
		{
			name: "trusted override bypasses built-in canonicalization",
			facts: builtInChainConfigFacts{
				hasBuiltInConfig:        true,
				trustedOverride:         true,
				storedMatchesBuiltIn:    false,
				candidateMatchesBuiltIn: false,
			},
			want: builtInChainConfigAction{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := decideBuiltInChainConfigAction(test.facts)
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("unexpected built-in chain-config action:\n%#v\nwant:\n%#v", got, test.want)
			}
		})
	}
}

// TestHydrateProvidedChainConfigRejectsEngineLessCustomTestnetChainIDWithoutBackfill tests hydrate provided chain config rejects engine less custom testnet chain id without backfill.
func TestHydrateProvidedChainConfigRejectsEngineLessCustomTestnetChainIDWithoutBackfill(t *testing.T) {
	futureFork := big.NewInt(1_000_000_000)
	cfg := &params.ChainConfig{
		ChainID:             new(big.Int).Set(params.TestnetChainConfig.ChainID),
		EIP150Block:         big.NewInt(0),
		EIP155Block:         big.NewInt(2),
		EIP158Block:         big.NewInt(2),
		ByzantiumBlock:      new(big.Int).Set(futureFork),
		ConstantinopleBlock: new(big.Int).Set(futureFork),
		PetersburgBlock:     new(big.Int).Set(futureFork),
		IstanbulBlock:       new(big.Int).Set(futureFork),
		HomesteadBlock:      new(big.Int),
		TIPTRC21FeeBlock:    new(big.Int),
		BerlinBlock:         new(big.Int).Set(futureFork),
		LondonBlock:         new(big.Int).Set(futureFork),
		MergeBlock:          new(big.Int).Set(futureFork),
		ShanghaiBlock:       new(big.Int).Set(futureFork),
		EIP1559Block:        new(big.Int).Set(futureFork),
		CancunBlock:         new(big.Int).Set(futureFork),
		PragueBlock:         new(big.Int).Set(futureFork),
		OsakaBlock:          new(big.Int).Set(futureFork),
	}
	setXinFinForksToFuture(cfg, futureFork)

	hydrated, err := resolveProvidedChainConfig(common.Hash{}, cfg, builtInChainConfigMustMatch)
	if err != nil {
		t.Fatalf("hydrateProvidedChainConfig failed: %v", err)
	}
	if hydrated == nil {
		t.Fatal("expected hydrated config")
	}
	if hydrated.XDPoS != nil {
		t.Fatalf("expected custom chain ID %v to remain engine-less, have %v", params.TestnetChainConfig.ChainID, hydrated)
	}
	if hydrated.TIP2019Block != nil {
		t.Fatalf("expected no Localnet compatibility backfill for custom chain ID %v, have %v", params.TestnetChainConfig.ChainID, hydrated.TIP2019Block)
	}

	loadedCfg, _, err := LoadChainConfig(rawdb.NewMemoryDatabase(), &Genesis{Config: cfg, Alloc: types.GenesisAlloc{{1}: {Balance: big.NewInt(1)}}, GasLimit: 4700000, Difficulty: big.NewInt(1)})
	if !errors.Is(err, params.ErrMissingForkSwitch) {
		t.Fatalf("expected missing consensus engine error, have %v want %v", err, params.ErrMissingForkSwitch)
	}
	if loadedCfg != nil {
		t.Fatalf("expected no resolved config for invalid custom chain ID %v, have %v", params.TestnetChainConfig.ChainID, loadedCfg)
	}
}

// TestStoredChainConfigRoundTripPreservesExplicitZeroValueOverrides tests stored chain config round trip preserves explicit zero value overrides.
func TestStoredChainConfigRoundTripPreservesExplicitZeroValueOverrides(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	var cfg params.ChainConfig
	raw := []byte(`{"chainId":51,"tipTRC21FeeBlock":1,"eip1559Block":null,"daoForkSupport":false,"trc21IssuerSMC":"0x0000000000000000000000000000000000000000","ethash":{}}`)
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("failed to unmarshal chain config: %v", err)
	}

	rawdb.WriteChainConfig(db, params.TestnetGenesisHash, &cfg)
	storedJSON, err := rawdb.ReadChainConfigJSON(db, params.TestnetGenesisHash)
	if err != nil {
		t.Fatalf("failed to read stored chain config JSON: %v", err)
	}
	var storedKeys map[string]json.RawMessage
	if err := json.Unmarshal(storedJSON, &storedKeys); err != nil {
		t.Fatalf("failed to inspect stored chain config JSON: %v", err)
	}
	for _, key := range []string{"eip1559Block", "daoForkSupport", "trc21IssuerSMC"} {
		if _, ok := storedKeys[key]; !ok {
			t.Fatalf("expected stored chain config JSON to preserve %s, have %s", key, storedJSON)
		}
	}

	persistedCfg, err := rawdb.ReadChainConfig(db, params.TestnetGenesisHash)
	if err != nil {
		t.Fatalf("failed to read persisted chain config: %v", err)
	}
	source := params.TestnetChainConfig.Clone()
	source.DAOForkSupport = true
	source.TRC21IssuerSMC = common.HexToAddress("0x1111111111111111111111111111111111111111")
	hydrated := persistedCfg.BackfillMissingFieldsFrom(source)
	if hydrated == nil {
		t.Fatal("expected hydrated config")
	}
	if hydrated.EIP1559Block != nil {
		t.Fatalf("expected explicit null eip1559Block to survive database round-trip, have %v", hydrated.EIP1559Block)
	}
	if hydrated.DAOForkSupport {
		t.Fatal("expected explicit false daoForkSupport to survive database round-trip")
	}
	if hydrated.TRC21IssuerSMC != (common.Address{}) {
		t.Fatalf("expected explicit zero trc21IssuerSMC to survive database round-trip, have %s", hydrated.TRC21IssuerSMC.Hex())
	}
	if hydrated.BerlinBlock == nil || hydrated.BerlinBlock.Cmp(source.BerlinBlock) != 0 {
		t.Fatalf("expected omitted berlinBlock to be backfilled from source, have %v want %v", hydrated.BerlinBlock, source.BerlinBlock)
	}
}

// TestStoredBuiltInHashExplicitZeroValueOverridesStillConflict tests stored built in hash explicit zero value overrides still conflict.
func TestStoredBuiltInHashExplicitZeroValueOverridesStillConflict(t *testing.T) {
	raw := []byte(`{"chainId":51,"tipTRC21FeeBlock":1,"eip1559Block":null,"trc21IssuerSMC":"0x0000000000000000000000000000000000000000","ethash":{}}`)
	buildDB := func(t *testing.T) ethdb.Database {
		t.Helper()
		db := rawdb.NewMemoryDatabase()
		DefaultTestnetGenesisBlock().MustCommit(db)
		var cfg params.ChainConfig
		if err := json.Unmarshal(raw, &cfg); err != nil {
			t.Fatalf("failed to unmarshal chain config: %v", err)
		}
		rawdb.WriteChainConfig(db, params.TestnetGenesisHash, &cfg)
		storedJSON, err := rawdb.ReadChainConfigJSON(db, params.TestnetGenesisHash)
		if err != nil {
			t.Fatalf("failed to read stored chain config JSON: %v", err)
		}
		var storedKeys map[string]json.RawMessage
		if err := json.Unmarshal(storedJSON, &storedKeys); err != nil {
			t.Fatalf("failed to inspect stored chain config JSON: %v", err)
		}
		for _, key := range []string{"eip1559Block", "trc21IssuerSMC"} {
			if _, ok := storedKeys[key]; !ok {
				t.Fatalf("expected stored chain config JSON to preserve %s, have %s", key, storedJSON)
			}
		}
		return db
	}

	t.Run("LoadChainConfig", func(t *testing.T) {
		db := buildDB(t)
		cfg, hash, err := LoadChainConfig(db, nil)
		if !errors.Is(err, errGenesisConfigConflict) {
			t.Fatalf("unexpected error: have %v want %v", err, errGenesisConfigConflict)
		}
		if hash != params.TestnetGenesisHash {
			t.Fatalf("unexpected hash: have %s want %s", hash.Hex(), params.TestnetGenesisHash.Hex())
		}
		if cfg != nil {
			t.Fatalf("expected nil config on invalid built-in drift, have %v", cfg)
		}
	})

	t.Run("SetupGenesisBlock", func(t *testing.T) {
		db := buildDB(t)
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
			t.Fatalf("expected nil config on built-in drift, have %v", cfg)
		}
	})
}

// TestIsConsensusOptionalTestChainRejectsLargeChainIDOverflow tests the
// test-chain exemption does not accept chain IDs that only match 1337 after
// Uint64 truncation.
func TestIsConsensusOptionalTestChainRejectsLargeChainIDOverflow(t *testing.T) {
	largeChainID := new(big.Int).Lsh(big.NewInt(1), 64)
	largeChainID.Add(largeChainID, big.NewInt(1337))
	if isConsensusOptionalTestChain(largeChainID) {
		t.Fatalf("expected large chain ID %v to not be treated as a consensus-optional test chain", largeChainID)
	}
}

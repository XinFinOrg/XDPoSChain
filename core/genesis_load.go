package core

import (
	"errors"
	"fmt"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/startup"
	"github.com/XinFinOrg/XDPoSChain/ethdb"
	"github.com/XinFinOrg/XDPoSChain/params"
)

type loadStoredConfigState struct {
	trustedOverride bool
	builtin         *params.ChainConfig
}

// Load-path execution helpers consume precomputed decisions and state.

// normalizeProvidedGenesisForStoredConfig normalizes and validates provided genesis against stored state.
func normalizeProvidedGenesisForStoredConfig(stored common.Hash, storedCfg *params.ChainConfig, genesis *Genesis, trustedOverride, allowBuiltInCustomRecovery bool) (*Genesis, common.Hash, error) {
	if genesis == nil {
		return nil, common.Hash{}, nil
	}
	originalHash := common.Hash{}
	var err error
	genesis, originalHash, err = normalizeProvidedGenesisConfig(genesis, builtInChainConfigPolicyForOverride(trustedOverride))
	if err != nil {
		return nil, originalHash, err
	}
	if err := genesis.Config.CheckConfigForkOrder(); err != nil {
		return nil, common.Hash{}, err
	}
	providedHash, err := genesis.Hash()
	if err != nil {
		return nil, common.Hash{}, err
	}
	if providedHash != stored && originalHash != stored {
		return nil, providedHash, &GenesisMismatchError{stored, providedHash}
	}
	if trustedOverride {
		genesis, err = reconcileTrustedStoredOverrideGenesis(stored, storedCfg, genesis, startup.StoredOverrideOpts{
			OriginalGenesisHash:        originalHash,
			TrustedOverride:            trustedOverride,
			LegacyStoredOverride:       false,
			Writable:                   false,
			AllowBuiltInCustomRecovery: true,
		})
		if err != nil {
			return nil, common.Hash{}, err
		}
	}
	return genesis, common.Hash{}, nil
}

// resolveLoadStoredConfigResult finalizes readonly stored-config resolution.
func resolveLoadStoredConfigResult(db ethdb.Database, stored common.Hash, storedCfg, newCfg *params.ChainConfig, state loadStoredConfigState, genesis *Genesis, returnCompat bool) (cfg *params.ChainConfig, compatErr *params.ConfigCompatError, err error) {
	if returnCompat {
		resolvedCfg, compatErr, err := resolveHeadCompatibleChainConfig(db, storedCfg, newCfg, state.trustedOverride, state.builtin)
		if err != nil {
			return nil, nil, err
		}
		return resolvedCfg, compatErr, nil
	}
	if state.trustedOverride || state.builtin == nil {
		if genesis != nil {
			equal, err := chainConfigJSONEqual(storedCfg, genesis.Config)
			if err != nil {
				return nil, nil, err
			}
			if !equal {
				return nil, nil, errGenesisConfigConflict
			}
		}
		if err := newCfg.CheckConfigForkOrder(); err != nil {
			return nil, nil, err
		}
		return newCfg, nil, nil
	}
	if err := newCfg.CheckConfigForkOrder(); err != nil {
		return nil, nil, err
	}
	storedEqual, err := chainConfigJSONEqual(storedCfg, state.builtin)
	if err != nil {
		return nil, nil, err
	}
	if !storedEqual {
		return nil, nil, builtInGenesisConfigConflictError(stored)
	}
	newEqual, err := chainConfigJSONEqual(newCfg, state.builtin)
	if err != nil {
		return nil, nil, err
	}
	if !newEqual {
		return nil, nil, builtInGenesisConfigConflictError(stored)
	}
	return state.builtin.Clone(), nil, nil
}

// resolveLoadStoredMissingConfigNoProvidedGenesis handles readonly missing-config recovery.
func resolveLoadStoredMissingConfigNoProvidedGenesis(db ethdb.Database, stored common.Hash, allowBuiltInCustomRecovery bool) (cfg *params.ChainConfig, err error) {
	// Missing config metadata is recoverable from bundled defaults only for
	// plain bundled networks. Override-backed same-hash custom chains need
	// their persisted custom config or a matching explicit genesis.
	state, err := prepareLoadStoredConfigState(db, stored, allowBuiltInCustomRecovery)
	if err != nil {
		return nil, err
	}
	action := decideMissingConfigAction(stored, rawdb.ReadHeader(db, stored, 0) != nil, state.trustedOverride, false, false)
	if action.TerminalError != nil {
		if errors.Is(action.TerminalError, startup.ErrGenesisConfigConflict) {
			return nil, builtInGenesisConfigConflictError(stored)
		}
		return nil, action.TerminalError
	}
	if state.builtin != nil {
		if err := state.builtin.CheckConfigForkOrder(); err != nil {
			return nil, err
		}
		return state.builtin.Clone(), nil
	}
	return nil, rawdb.ErrChainConfigNotFound
}

// resolveLoadProvidedGenesis resolves readonly config directly from provided genesis.
func resolveLoadProvidedGenesis(db ethdb.Database, stored common.Hash, genesis *Genesis, allowBuiltInCustomRecovery bool) (cfg *params.ChainConfig, ghash common.Hash, err error) {
	// Load the config from the provided genesis specification.
	originalHash, err := genesis.Hash()
	if err != nil {
		return nil, common.Hash{}, err
	}
	allowCustomBuiltIn, allowErr := shouldAllowCustomBuiltInConfig(db, stored, originalHash, genesis.Config, allowBuiltInCustomRecovery)
	if allowErr != nil {
		return nil, originalHash, allowErr
	}
	genesis, originalHash, err = normalizeProvidedGenesisConfig(genesis, builtInChainConfigPolicyForOverride(allowCustomBuiltIn))
	if err != nil {
		return nil, originalHash, err
	}
	err = genesis.Config.CheckConfigForkOrder()
	if err != nil {
		return nil, common.Hash{}, err
	}
	// If the canonical genesis header is present, but the chain
	// config is missing(initialize the empty leveldb with an
	// external ancient chain segment), ensure the provided genesis
	// is matched.
	ghash, err = genesis.Hash()
	if err != nil {
		return nil, common.Hash{}, err
	}
	if stored != (common.Hash{}) && ghash != stored && originalHash != stored {
		return nil, ghash, &GenesisMismatchError{stored, ghash}
	}
	if stored != (common.Hash{}) {
		ghash = stored
	}
	return genesis.Config, ghash, nil
}

// resolveLoadDefaultMainnetWithAction returns readonly default-mainnet fallback.
func resolveLoadDefaultMainnetWithAction() (cfg *params.ChainConfig, ghash common.Hash) {
	// There is no stored chain config and no new config provided,
	// In this case the default chain config(mainnet) will be used.
	action := decideInitialStartupAction(common.Hash{}, false, false)
	expectReadonlyDefaultMainnetAction(action)
	return params.XDCMainnetChainConfig, params.MainnetGenesisHash
}

func expectReadonlyDefaultMainnetAction(action startup.Action) {
	if action.TerminalError != nil || action.GenesisSource != startup.GenesisSourceDefaultMainnetReadonly || action.AllowCommitGenesis || action.PreferStoredConfig || action.PromoteOverrideMarker {
		panic(fmt.Sprintf("BUG: readonly fallback returned unexpected action: %+v", action))
	}
}

// prepareLoadStoredConfigState loads override marker and built-in baseline.
func prepareLoadStoredConfigState(db ethdb.Database, stored common.Hash, allowBuiltInCustomRecovery bool) (loadStoredConfigState, error) {
	trustedOverride, err := rawdb.ReadChainConfigOverride(db, stored)
	if err != nil {
		return loadStoredConfigState{}, err
	}
	return loadStoredConfigState{
		trustedOverride: trustedOverride,
		builtin:         builtInChainConfigByHash(stored),
	}, nil
}

// LoadChainConfig loads the stored chain config from the database, or falls
// back to the provided genesis config.
//   - Known built-in genesis hashes backfill missing values from the matching
//     bundled config and require the resolved config to match it.
//   - Other hashes keep the Localnet-based compatibility backfill.
//   - Conflicting explicit fields on a built-in genesis hash are rejected.
//
// This helper preserves the historical three-value return signature and
// intentionally discards compatibility rewind metadata. Callers that need to
// distinguish readonly rewind requirements from hard conflicts should use
// LoadChainConfigWithCompat.
//
// Returns:
// - cfg: the resolved config (never nil on success)
// - ghash: the canonical genesis block hash
// - err: error if config is missing or invalid
func LoadChainConfig(db ethdb.Database, genesis *Genesis) (cfg *params.ChainConfig, ghash common.Hash, err error) {
	return loadChainConfig(db, genesis)
}

func loadChainConfig(db ethdb.Database, genesis *Genesis) (cfg *params.ChainConfig, ghash common.Hash, err error) {
	cfg, ghash, _, err = loadChainConfigInternal(db, genesis, false, false)
	return cfg, ghash, err
}

func loadChainConfigInternal(db ethdb.Database, genesis *Genesis, returnCompat, allowBuiltInCustomRecovery bool) (cfg *params.ChainConfig, ghash common.Hash, compatErr *params.ConfigCompatError, err error) {
	defer func() {
		annotateResolvedCustomBuiltInConfig(ghash, cfg)
	}()

	genesis = genesis.copy()
	stored := rawdb.ReadCanonicalHash(db, 0)
	var storedcfg *params.ChainConfig
	if stored != (common.Hash{}) {
		storedcfg, err = rawdb.ReadChainConfig(db, stored)
		if err != nil && !errors.Is(err, rawdb.ErrChainConfigNotFound) {
			return nil, common.Hash{}, nil, err
		}
	}

	switch decideLoadChainConfigPath(stored, storedcfg != nil, genesis != nil) {
	case loadChainConfigPathStoredConfig:
		if err := expectStoredConfigHeaderAction(decideStoredConfigHeaderAction(db, stored)); err != nil {
			return nil, stored, nil, err
		}
		state, err := prepareLoadStoredConfigState(db, stored, allowBuiltInCustomRecovery)
		if err != nil {
			return nil, stored, nil, err
		}
		cfg, err := resolveStoredChainConfig(stored, storedcfg)
		if err != nil {
			return nil, stored, nil, err
		}
		genesis, mismatchHash, err := normalizeProvidedGenesisForStoredConfig(stored, cfg, genesis, state.trustedOverride, allowBuiltInCustomRecovery)
		if err != nil {
			if mismatchHash != (common.Hash{}) {
				return nil, mismatchHash, nil, err
			}
			return nil, stored, nil, err
		}

		newCfg := genesis.chainConfigOrDefault(stored, cfg, state.trustedOverride)
		resolvedCfg, resolvedCompatErr, err := resolveLoadStoredConfigResult(db, stored, cfg, newCfg, state, genesis, returnCompat)
		if err != nil {
			return nil, stored, nil, err
		}
		return resolvedCfg, stored, resolvedCompatErr, nil

	case loadChainConfigPathStoredMissingConfigNoProvidedGenesis:
		resolvedCfg, err := resolveLoadStoredMissingConfigNoProvidedGenesis(db, stored, allowBuiltInCustomRecovery)
		if err != nil {
			return nil, stored, nil, err
		}
		return resolvedCfg, stored, nil, nil

	case loadChainConfigPathProvidedGenesis:
		resolvedCfg, resolvedHash, err := resolveLoadProvidedGenesis(db, stored, genesis, allowBuiltInCustomRecovery)
		if err != nil {
			if resolvedHash != (common.Hash{}) {
				return nil, resolvedHash, nil, err
			}
			return nil, common.Hash{}, nil, err
		}
		return resolvedCfg, resolvedHash, nil, nil

	case loadChainConfigPathDefaultMainnet:
		resolvedCfg, resolvedHash := resolveLoadDefaultMainnetWithAction()
		return resolvedCfg, resolvedHash, nil, nil
	}

	return nil, common.Hash{}, nil, errors.New("unreachable loadChainConfig path")
}

// LoadChainConfigWithCompat resolves the canonical chain config for readonly
// startup without mutating the database. It mirrors SetupGenesisBlock's
// normalization rules, including same-hash custom override handling, and
// surfaces any compatibility rewind that writable startup would need to apply.
func LoadChainConfigWithCompat(db ethdb.Database, genesis *Genesis) (cfg *params.ChainConfig, ghash common.Hash, compatErr *params.ConfigCompatError, err error) {
	return LoadChainConfigWithCompatWithOverride(db, genesis, false)
}

func LoadChainConfigWithCompatWithOverride(db ethdb.Database, genesis *Genesis, allowBuiltInCustomRecovery bool) (cfg *params.ChainConfig, ghash common.Hash, compatErr *params.ConfigCompatError, err error) {
	return loadChainConfigInternal(db, genesis, true, allowBuiltInCustomRecovery)
}

// resolveHeadCompatibleChainConfig checks whether candidateCfg can be used at the current head.
func resolveHeadCompatibleChainConfig(db ethdb.Database, storedCfg, candidateCfg *params.ChainConfig, trustedOverride bool, builtin *params.ChainConfig) (*params.ChainConfig, *params.ConfigCompatError, error) {
	head, err := loadStartupHead(db)
	if err != nil {
		return nil, nil, err
	}
	if err := candidateCfg.CheckConfigForkOrder(); err != nil {
		return nil, nil, err
	}
	xdposRound, err := currentXDPoSRoundFromHead(head, storedCfg)
	if err != nil {
		return nil, nil, err
	}
	compatErr := storedCfg.CheckCompatibleWithXDPoSRound(candidateCfg, head.Number.Uint64(), xdposRound)
	if compatErr != nil && head.Number.Uint64() != 0 {
		return candidateCfg, compatErr, nil
	}
	if builtin != nil && !trustedOverride {
		storedEqual, err := chainConfigJSONEqual(storedCfg, builtin)
		if err != nil {
			return nil, nil, err
		}
		newEqual, err := chainConfigJSONEqual(candidateCfg, builtin)
		if err != nil {
			return nil, nil, err
		}
		action := decideBuiltInChainConfigAction(builtInChainConfigFacts{
			hasBuiltInConfig:        true,
			trustedOverride:         trustedOverride,
			storedMatchesBuiltIn:    storedEqual,
			candidateMatchesBuiltIn: newEqual,
		})
		if errors.Is(action.terminalError, startup.ErrGenesisConfigConflict) {
			return nil, nil, builtInGenesisConfigConflictError(rawdb.ReadCanonicalHash(db, 0))
		}
		if action.canonicalizeToBuiltIn {
			candidateCfg = builtin.Clone()
		}
	}
	return candidateCfg, nil, nil
}

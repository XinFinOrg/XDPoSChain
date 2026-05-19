package core

import (
	"errors"

	"github.com/XinFinOrg/XDPoSChain/common"
	xdposutils "github.com/XinFinOrg/XDPoSChain/consensus/XDPoS/utils"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/startup"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/ethdb"
	"github.com/XinFinOrg/XDPoSChain/log"
	"github.com/XinFinOrg/XDPoSChain/params"
)

var (
	errMissingHeadHeader       = errors.New("missing head header")
	errMissingHeadHeaderNumber = errors.New("missing block number for head header hash")
)

type setupStoredOverrideState struct {
	markerPresent        bool
	legacyStoredOverride bool
	trustedOverride      bool
}

// prepareSetupStoredConfigOverrides derives setup override state and preferred genesis.
// Here "legacy stored override" means the historical v1 same-hash built-in
// override path where the custom config was already persisted but the explicit
// override marker had not been written yet.
func prepareSetupStoredConfigOverrides(db ethdb.Database, ghash common.Hash, storedCfg *params.ChainConfig, genesis *Genesis, originalGenesisHash common.Hash, allowBuiltInCustomRecovery bool) (resolvedGenesis *Genesis, state setupStoredOverrideState, err error) {
	state.markerPresent, err = rawdb.ReadChainConfigOverride(db, ghash)
	if err != nil {
		return nil, setupStoredOverrideState{}, err
	}
	state.legacyStoredOverride = false
	if genesis != nil && originalGenesisHash == ghash {
		state.legacyStoredOverride, err = isLegacyStoredCustomBuiltInConfig(ghash, storedCfg)
		if err != nil {
			return nil, setupStoredOverrideState{}, err
		}
		if state.legacyStoredOverride {
			equal, err := chainConfigJSONEqual(genesis.Config, storedCfg)
			if err != nil {
				return nil, setupStoredOverrideState{}, err
			}
			state.legacyStoredOverride = equal
		}
	}
	state.trustedOverride = state.markerPresent || state.legacyStoredOverride
	if state.trustedOverride {
		if err := requireBuiltInCustomRecovery(ghash, allowBuiltInCustomRecovery); err != nil {
			return nil, setupStoredOverrideState{}, err
		}
		genesis, err = reconcileTrustedStoredOverrideGenesis(ghash, storedCfg, genesis, startup.StoredOverrideOpts{
			OriginalGenesisHash:        originalGenesisHash,
			TrustedOverride:            state.markerPresent,
			LegacyStoredOverride:       state.legacyStoredOverride,
			Writable:                   true,
			AllowBuiltInCustomRecovery: allowBuiltInCustomRecovery,
		})
		if err != nil {
			return nil, setupStoredOverrideState{}, err
		}
	}
	return genesis, state, nil
}

// Setup-path execution helpers consume precomputed decisions and state.

// resolveSetupStoredConfigResult finalizes writable stored-config reconciliation and persistence.
func resolveSetupStoredConfigResult(db ethdb.Database, ghash common.Hash, storedCfg, newCfg *params.ChainConfig, genesis *Genesis, head *types.Header, state setupStoredOverrideState) (cfg *params.ChainConfig, compatErr *params.ConfigCompatError, err error) {
	if err := newCfg.CheckConfigForkOrder(); err != nil {
		return nil, nil, err
	}
	xdposRound, err := currentXDPoSRoundFromHead(head, storedCfg)
	if err != nil {
		return nil, nil, err
	}
	compatErr = storedCfg.CheckCompatibleWithXDPoSRound(newCfg, head.Number.Uint64(), xdposRound)
	if compatErr != nil && head.Number.Uint64() != 0 {
		if state.legacyStoredOverride && !state.markerPresent {
			rawdb.WriteChainConfigOverride(db, ghash)
			logPersistedChainConfig("promote_legacy_override_marker", ghash, newCfg, true)
		}
		return newCfg, compatErr, nil
	}
	if builtin := builtInChainConfigByHash(ghash); builtin != nil && !state.trustedOverride {
		storedEqual, err := chainConfigJSONEqual(storedCfg, builtin)
		if err != nil {
			return nil, nil, err
		}
		newEqual, err := chainConfigJSONEqual(newCfg, builtin)
		if err != nil {
			return nil, nil, err
		}
		action := decideBuiltInChainConfigAction(builtInChainConfigFacts{
			hasBuiltInConfig:        true,
			trustedOverride:         state.trustedOverride,
			storedMatchesBuiltIn:    storedEqual,
			candidateMatchesBuiltIn: newEqual,
			allowStoredDriftRepair:  head.Number.Uint64() == 0 && genesis != nil,
		})
		if errors.Is(action.terminalError, startup.ErrGenesisConfigConflict) {
			return nil, nil, builtInGenesisConfigConflictError(ghash)
		}
		if action.canonicalizeToBuiltIn {
			newCfg = builtin.Clone()
		}
	}
	persistResolvedConfig := state.legacyStoredOverride && !state.markerPresent
	resolvedEqual, err := chainConfigJSONEqual(storedCfg, newCfg)
	if err != nil {
		return nil, nil, err
	}
	writeResolvedConfig := !resolvedEqual || persistResolvedConfig
	writeOverrideMarker := state.legacyStoredOverride && !state.markerPresent
	if writeResolvedConfig || writeOverrideMarker {
		batch := db.NewBatch()
		if writeResolvedConfig {
			rawdb.WriteChainConfig(batch, ghash, newCfg)
		}
		if writeOverrideMarker {
			rawdb.WriteChainConfigOverride(batch, ghash)
		}
		if err := batch.Write(); err != nil {
			return nil, nil, err
		}
		logPersistedChainConfig("reconcile_stored_chain_config", ghash, newCfg, writeOverrideMarker)
	}
	return newCfg, nil, nil
}

// loadStartupHead loads and validates startup head-header metadata from the database.
func loadStartupHead(db ethdb.Database) (*types.Header, error) {
	headHeaderHash := rawdb.ReadHeadHeaderHash(db)
	if headHeaderHash != (common.Hash{}) && rawdb.ReadHeaderNumber(db, headHeaderHash) == nil {
		return nil, errMissingHeadHeaderNumber
	}
	head := rawdb.ReadHeadHeader(db)
	if head == nil {
		return nil, errMissingHeadHeader
	}
	return head, nil
}

// SetupGenesisBlock writes or updates the genesis block in db,
// returning the resolved chain config and genesis hash.
// The block that will be used is:
//
//	                     genesis == nil       genesis != nil
//	                  +------------------------------------------
//	db has no genesis |  main-net default  |  genesis
//	db has genesis    |  from DB           |  genesis (if compatible)
//
// Rules:
//   - For known built-in genesis hashes, missing fields are completed from the
//     matching bundled config and the final result must match that bundled
//     config.
//   - For other networks, LocalnetChainConfig is still used to backfill
//     missing fields for compatibility with older custom chain configs.
//   - Conflicting explicit fields on a built-in genesis hash are rejected.
//   - Empty databases may persist an explicit same-hash custom override during
//     first initialization, and later restarts then keep trusting that stored
//     config instead of silently reverting to the bundled one.
//   - If the canonical genesis exists but the chain-config blob is missing,
//     bundled networks may rebuild it from the bundled genesis while
//     override-backed same-hash custom chains must provide a matching explicit
//     genesis.
//
// SetupGenesisBlock resolves and persists the canonical genesis metadata for
// writable startup. It may repair missing config blobs, honor a stored
// same-hash custom override, and surface a required compatibility rewind via
// compatErr, but it does not perform the rewind itself.
//
// Returns:
// - chainConfig: the resolved config (never nil on success)
// - genesisHash: the canonical genesis block hash
// - compatErr: compatibility rewind metadata for the caller to apply if needed
// - err: other errors (e.g. missing config, DB errors)
func SetupGenesisBlock(db ethdb.Database, genesis *Genesis) (chainConfig *params.ChainConfig, genesisHash common.Hash, compatErr *params.ConfigCompatError, err error) {
	return SetupGenesisBlockWithOverride(db, genesis, false)
}

func SetupGenesisBlockWithOverride(db ethdb.Database, genesis *Genesis, allowBuiltInCustomRecovery bool) (chainConfig *params.ChainConfig, genesisHash common.Hash, compatErr *params.ConfigCompatError, err error) {
	return setupGenesisBlock(db, genesis, allowBuiltInCustomRecovery)
}

func setupGenesisBlock(db ethdb.Database, genesis *Genesis, allowBuiltInCustomRecovery bool) (chainConfig *params.ChainConfig, genesisHash common.Hash, compatErr *params.ConfigCompatError, err error) {
	defer func() {
		annotateResolvedCustomBuiltInConfig(genesisHash, chainConfig)
		logResolvedChainConfig(err, chainConfig, genesisHash, compatErr)
	}()

	genesis = genesis.copy()
	ghash := rawdb.ReadCanonicalHash(db, 0)

	var originalGenesisHash common.Hash
	if genesis != nil {
		originalGenesisHash, err = genesis.Hash()
		if err != nil {
			return nil, common.Hash{}, nil, err
		}
		allowCustomBuiltIn, allowErr := shouldAllowCustomBuiltInConfig(db, ghash, originalGenesisHash, genesis.Config, allowBuiltInCustomRecovery)
		if allowErr != nil {
			return nil, originalGenesisHash, nil, allowErr
		}
		genesis, originalGenesisHash, err = normalizeProvidedGenesisConfig(genesis, builtInChainConfigPolicyForOverride(allowCustomBuiltIn))
		if err != nil {
			return nil, originalGenesisHash, nil, err
		}
	}

	storedCfg, readErr := rawdb.ReadChainConfig(db, ghash)
	if readErr != nil && !errors.Is(readErr, rawdb.ErrChainConfigNotFound) {
		return nil, common.Hash{}, nil, readErr
	}
	switch decideSetupGenesisPath(ghash, storedCfg != nil) {
	case setupGenesisPathEmptyDB:
		action := decideInitialStartupAction(ghash, genesis != nil, true)
		if err := expectInitialGenesisAction(action); err != nil {
			return nil, common.Hash{}, nil, err
		}
		genesis = selectInitialGenesis(action, genesis)
		block, err := genesis.commit(db, true, true)
		if err != nil {
			return nil, common.Hash{}, nil, err
		}
		logPersistedGenesisMetadata("initialize_empty_database", block.Hash(), genesis.Config)
		return genesis.Config.Clone(), block.Hash(), nil, nil

	case setupGenesisPathMissingConfig:
		hasGenesisHeader := rawdb.ReadHeader(db, ghash, 0) != nil
		if !hasGenesisHeader {
			return nil, ghash, nil, startup.ErrGenesisHeaderNotFound
		}
		trustedOverride, err := rawdb.ReadChainConfigOverride(db, ghash)
		if err != nil {
			return nil, ghash, nil, err
		}
		if trustedOverride {
			if err := requireBuiltInCustomRecovery(ghash, allowBuiltInCustomRecovery); err != nil {
				return nil, ghash, nil, err
			}
		}
		missingConfigAction := decideSetupMissingConfigAction(ghash, hasGenesisHeader, trustedOverride, genesis != nil, allowBuiltInCustomRecovery)
		if err := expectSetupMissingConfigAction(missingConfigAction); err != nil {
			return nil, ghash, nil, err
		}
		genesis = selectMissingConfigGenesis(ghash, genesis)
		hash, err := genesis.Hash()
		if err != nil {
			return nil, common.Hash{}, nil, err
		}
		if hash != ghash && originalGenesisHash != ghash {
			return nil, common.Hash{}, nil, &GenesisMismatchError{ghash, hash}
		}
		if rawdb.ReadHeadHeaderHash(db) != (common.Hash{}) || rawdb.ReadHeadBlockHash(db) != (common.Hash{}) || rawdb.ReadHeadFastBlockHash(db) != (common.Hash{}) {
			newCfg := genesis.chainConfigOrDefault(ghash, nil, false)
			if err := newCfg.CheckConfigForkOrder(); err != nil {
				return nil, common.Hash{}, nil, err
			}
			rawdb.WriteChainConfig(db, ghash, newCfg)
			wroteOverrideMarker := false
			if builtin := builtInChainConfigByHash(ghash); builtin != nil {
				equal, err := chainConfigJSONEqual(newCfg, builtin)
				if err != nil {
					return nil, common.Hash{}, nil, err
				}
				if !equal {
					rawdb.WriteChainConfigOverride(db, ghash)
					wroteOverrideMarker = true
				}
			}
			logPersistedChainConfig("repair_missing_chain_config", ghash, newCfg, wroteOverrideMarker)
			return newCfg, ghash, nil, nil
		}
		block, err := genesis.commit(db, true, true)
		if err != nil {
			return nil, common.Hash{}, nil, err
		}
		logPersistedGenesisMetadata("repair_missing_chain_config", block.Hash(), genesis.Config)
		return genesis.Config.Clone(), block.Hash(), nil, nil

	case setupGenesisPathStoredConfig:
	}

	storedCfg, err = resolveStoredChainConfig(ghash, storedCfg)
	if err != nil {
		return nil, ghash, nil, err
	}
	if err := expectStoredConfigHeaderAction(decideStoredConfigHeaderAction(db, ghash)); err != nil {
		return nil, ghash, nil, err
	}
	if genesis != nil {
		hash, err := genesis.Hash()
		if err != nil {
			return nil, common.Hash{}, nil, err
		}
		if hash != ghash && originalGenesisHash != ghash {
			return nil, common.Hash{}, nil, &GenesisMismatchError{ghash, hash}
		}
	}
	head, err := loadStartupHead(db)
	if err != nil {
		if errors.Is(err, errMissingHeadHeaderNumber) {
			return storedCfg, ghash, nil, err
		}
		return nil, common.Hash{}, nil, err
	}
	genesis, overrideState, err := prepareSetupStoredConfigOverrides(db, ghash, storedCfg, genesis, originalGenesisHash, allowBuiltInCustomRecovery)
	if err != nil {
		return nil, common.Hash{}, nil, err
	}
	newCfg := genesis.chainConfigOrDefault(ghash, storedCfg, overrideState.trustedOverride)
	resolvedCfg, compatErr, err := resolveSetupStoredConfigResult(db, ghash, storedCfg, newCfg, genesis, head, overrideState)
	if err != nil {
		if errors.Is(err, errGenesisConfigConflict) {
			return nil, ghash, nil, err
		}
		return nil, common.Hash{}, nil, err
	}
	return resolvedCfg, ghash, compatErr, nil
}

// logResolvedChainConfig emits the final setup resolution with severity based on err.
func logResolvedChainConfig(err error, chainConfig *params.ChainConfig, genesisHash common.Hash, compatErr *params.ConfigCompatError) {
	logger := log.Info
	if err != nil {
		logger = log.Error
	}
	if chainConfig == nil {
		logger("Resolved chain config", "cfg", "nil", "hash", genesisHash.Hex(), "compatErr", compatErr, "err", err)
	} else {
		logger("Resolved chain config", "hash", genesisHash.Hex(), "chainId", chainConfig.ChainID, "compatErr", compatErr, "err", err)
	}
}

func logPersistedGenesisMetadata(reason string, genesisHash common.Hash, chainConfig *params.ChainConfig) {
	if chainConfig == nil {
		log.Info("Persisted genesis metadata to database", "reason", reason, "hash", genesisHash.Hex(), "cfg", "nil")
	} else {
		log.Info("Persisted genesis metadata to database", "reason", reason, "hash", genesisHash.Hex(), "chainId", chainConfig.ChainID)
	}
}

func logPersistedChainConfig(reason string, genesisHash common.Hash, chainConfig *params.ChainConfig, wroteOverrideMarker bool) {
	if chainConfig == nil {
		log.Info("Persisted chain config to database", "reason", reason, "hash", genesisHash.Hex(), "cfg", "nil", "overrideMarker", wroteOverrideMarker)
	} else {
		log.Info("Persisted chain config to database", "reason", reason, "hash", genesisHash.Hex(), "chainId", chainConfig.ChainID, "overrideMarker", wroteOverrideMarker)
	}
}

// currentXDPoSRoundFromHead extracts XDPoS round context from the current head.
func currentXDPoSRoundFromHead(head *types.Header, cfg *params.ChainConfig) (*uint64, error) {
	if head == nil || cfg == nil || cfg.XDPoS == nil || cfg.XDPoS.V2 == nil || cfg.XDPoS.V2.SwitchBlock == nil {
		return nil, nil
	}
	if head.Number == nil {
		return nil, errors.New("missing head header number")
	}
	round := uint64(0)
	if head.Number.Cmp(cfg.XDPoS.V2.SwitchBlock) <= 0 {
		return &round, nil
	}
	var extra types.ExtraFields_v2
	if err := xdposutils.DecodeBytesExtraFields(head.Extra, &extra); err != nil {
		return nil, err
	}
	round = uint64(extra.Round)
	return &round, nil
}

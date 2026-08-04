// Copyright 2014 The go-ethereum Authors
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
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/common/hexutil"
	"github.com/XinFinOrg/XDPoSChain/common/math"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/startup"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/ethdb"
	"github.com/XinFinOrg/XDPoSChain/log"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/XinFinOrg/XDPoSChain/trie"
)

//go:generate go run github.com/fjl/gencodec -type Genesis -field-override genesisSpecMarshaling -out gen_genesis.go

// Startup routing design notes, including the ASCII state map, live in
// core/startup/doc.go to keep this file's implementation comments short.

var (
	errGenesisNoConfig       = errors.New("genesis has no chain configuration")
	errGenesisConfigConflict = errors.New("provided genesis config conflicts with built-in chain config")
)

// Deprecated: use types.Account instead.
type GenesisAccount = types.Account

// Deprecated: use types.GenesisAlloc instead.
type GenesisAlloc = types.GenesisAlloc

// Genesis specifies the header fields, state of a genesis block. It also defines hard
// fork switch-over blocks through the chain configuration.
type Genesis struct {
	Config     *params.ChainConfig `json:"config"`
	Nonce      uint64              `json:"nonce"`
	Timestamp  uint64              `json:"timestamp"`
	ExtraData  []byte              `json:"extraData"`
	GasLimit   uint64              `json:"gasLimit"   gencodec:"required"`
	Difficulty *big.Int            `json:"difficulty" gencodec:"required"`
	Mixhash    common.Hash         `json:"mixHash"`
	Coinbase   common.Address      `json:"coinbase"`
	Alloc      types.GenesisAlloc  `json:"alloc"      gencodec:"required"`

	// These fields are used for consensus tests. Please don't use them
	// in actual genesis blocks.
	Number     uint64      `json:"number"`
	GasUsed    uint64      `json:"gasUsed"`
	ParentHash common.Hash `json:"parentHash"`
	BaseFee    *big.Int    `json:"baseFeePerGas"`
}

// copy returns a shallow copy of Genesis with an independent Config value.
func (g *Genesis) copy() *Genesis {
	if g != nil {
		cpy := *g
		if g.Config != nil {
			cpy.Config = g.Config.Clone()
		}
		return &cpy
	}
	return nil
}

// field type overrides for gencodec
type genesisSpecMarshaling struct {
	Nonce      math.HexOrDecimal64
	Timestamp  math.HexOrDecimal64
	ExtraData  hexutil.Bytes
	GasLimit   math.HexOrDecimal64
	GasUsed    math.HexOrDecimal64
	Number     math.HexOrDecimal64
	Difficulty *math.HexOrDecimal256
	BaseFee    *math.HexOrDecimal256
	Alloc      map[common.UnprefixedAddress]types.Account
}

// GenesisMismatchError is raised when trying to overwrite an existing
// genesis block with an incompatible one.
type GenesisMismatchError struct {
	Stored, New common.Hash
}

// Error implements error for GenesisMismatchError.
func (e *GenesisMismatchError) Error() string {
	return fmt.Sprintf("database contains incompatible genesis (have %x, new %x)", e.Stored, e.New)
}

type chainConfigOrigin uint8

const (
	chainConfigOriginProvided chainConfigOrigin = iota
	chainConfigOriginStored
)

type builtInChainConfigPolicy uint8

const (
	builtInChainConfigMustMatch builtInChainConfigPolicy = iota
	builtInChainConfigAllowOverride
)

// builtInChainConfigPolicyForOverride picks strict or override policy for built-in hashes.
func builtInChainConfigPolicyForOverride(allowCustomBuiltIn bool) builtInChainConfigPolicy {
	if allowCustomBuiltIn {
		return builtInChainConfigAllowOverride
	}
	return builtInChainConfigMustMatch
}

func builtInNetworkName(hash common.Hash) string {
	switch hash {
	case params.MainnetGenesisHash:
		return "MAINNET"
	case params.TestnetGenesisHash:
		return "TESTNET"
	case params.DevnetGenesisHash:
		return "DEVNET"
	default:
		return "BUILTIN"
	}
}

// builtInGenesisConfigConflictError wraps built-in conflicts with remediation guidance.
func builtInGenesisConfigConflictError(hash common.Hash) error {
	cfg := builtInChainConfigByHash(hash)
	if cfg == nil {
		return errGenesisConfigConflict
	}
	return fmt.Errorf("%w: same-hash custom overrides on built-in networks require --allow-builtin-config-override; builtin=%s chainId=%d; repair by starting from a fresh datadir: delete chaindata and reinitialize with the intended genesis, or rerun with --allow-builtin-config-override using the matching explicit genesis", errGenesisConfigConflict, builtInNetworkName(hash), cfg.ChainID)
}

// resolveProvidedChainConfig resolves a caller-supplied chain config for the
// given genesis hash.
func resolveProvidedChainConfig(hash common.Hash, cfg *params.ChainConfig, policy builtInChainConfigPolicy) (*params.ChainConfig, error) {
	if cfg == nil {
		return nil, nil
	}
	cfg = cfg.CloneForBackfill()
	return resolveChainConfigForGenesisHash(hash, cfg, chainConfigOriginProvided, policy)
}

// resolveStoredChainConfig resolves a persisted chain config for the given
// genesis hash.
func resolveStoredChainConfig(hash common.Hash, cfg *params.ChainConfig) (*params.ChainConfig, error) {
	if cfg == nil {
		return nil, nil
	}
	return resolveChainConfigForGenesisHash(hash, cfg, chainConfigOriginStored, builtInChainConfigAllowOverride)
}

// resolveChainConfigForGenesisHash normalizes a chain config using the genesis
// hash, the config origin, and the built-in policy for same-hash networks.
func resolveChainConfigForGenesisHash(hash common.Hash, cfg *params.ChainConfig, origin chainConfigOrigin, policy builtInChainConfigPolicy) (*params.ChainConfig, error) {
	if cfg == nil {
		return nil, nil
	}
	if builtin := builtInBackfillSourceByHash(hash); builtin != nil {
		hydrated := cfg.BackfillMissingFieldsFrom(builtin)
		if hydrated == nil {
			return nil, nil
		}
		switch origin {
		case chainConfigOriginStored:
			return hydrated, nil
		case chainConfigOriginProvided:
			equal, err := chainConfigJSONEqual(hydrated, builtin)
			if err != nil {
				return nil, err
			}
			if policy == builtInChainConfigMustMatch {
				if !equal {
					return nil, builtInGenesisConfigConflictError(hash)
				}
				return builtin.Clone(), nil
			}
			return hydrated, nil
		default:
			return nil, fmt.Errorf("unsupported chain config origin %d", origin)
		}
	}
	if origin == chainConfigOriginStored {
		if cfg.ChainID == nil {
			return nil, fmt.Errorf("stored custom chain config missing chainId for genesis %s", hash.Hex())
		}
		return hydrateStoredCustomChainConfig(cfg), nil
	}
	hydrated := hydrateProvidedCustomChainConfig(cfg)
	if hydrated == nil {
		return nil, nil
	}
	return clearConsensusOptionalTestChainXDPoS(cfg, hydrated), nil
}

// hydrateProvidedCustomChainConfig resolves caller-supplied custom genesis
// configs. The Localnet chain ID receives automatic Localnet defaults.
// Other custom genesis files keep their explicit values authoritative, but
// custom XDPoS configs still receive the narrow legacy private-chain
// compatibility backfill for fields that older sparse genesis files never
// declared explicitly.
func hydrateProvidedCustomChainConfig(cfg *params.ChainConfig) *params.ChainConfig {
	return hydrateCustomChainConfig(cfg, true)
}

// hydrateStoredCustomChainConfig resolves persisted custom genesis configs.
// Besides the Localnet chain ID shortcut, it may apply the narrow legacy
// compatibility backfill for stored private-chain XDPoS configs that used the
// historical local/private defaults before the ChainConfig migration.
func hydrateStoredCustomChainConfig(cfg *params.ChainConfig) *params.ChainConfig {
	return hydrateCustomChainConfig(cfg, false)
}

// hydrateCustomChainConfig resolves custom configs and optionally applies the
// consensus-optional test-chain XDPoS cleanup at this function boundary.
func hydrateCustomChainConfig(cfg *params.ChainConfig, clearAtBoundary bool) *params.ChainConfig {
	if cfg == nil {
		return nil
	}

	var hydrated *params.ChainConfig
	if localnet := localnetChainConfigByChainID(cfg.ChainID); localnet != nil {
		hydrated = cfg.BackfillMissingFieldsFrom(localnet)
		if hydrated == nil {
			return nil
		}
		if hydrated.TIPTRC21FeeBlock == nil {
			hydrated.TIPTRC21FeeBlock = new(big.Int)
		}
	} else {
		hydrated = hydrateLegacyCompatibleCustomChainConfig(cfg)
	}
	if clearAtBoundary {
		return clearConsensusOptionalTestChainXDPoS(cfg, hydrated)
	}
	return hydrated
}

// hydrateLegacyCompatibleCustomChainConfig backfills only the historical custom
// migration fields that older XDPoS configs may have omitted from persisted
// config.
func hydrateLegacyCompatibleCustomChainConfig(cfg *params.ChainConfig) *params.ChainConfig {
	if cfg == nil {
		return nil
	}
	hydrated := cfg.Clone()
	if backfillSource := customChainConfigBackfillSource(cfg); backfillSource != nil {
		hydrated = cfg.BackfillCustomMigratedFieldsFrom(backfillSource)
		if hydrated == nil {
			return nil
		}
	}
	return hydrated
}

// customChainConfigBackfillSource supplies the narrow custom-network
// compatibility source used to fill only the migrated XDC defaults and
// XDPoS.MaxMasternodesV2.
func customChainConfigBackfillSource(cfg *params.ChainConfig) *params.ChainConfig {
	if cfg == nil || cfg.XDPoS == nil {
		return nil
	}
	return params.LocalnetChainConfig
}

// localnetChainConfigByChainID returns the Localnet config when chainID maps to
// the built-in Localnet profile.
func localnetChainConfigByChainID(chainID *big.Int) *params.ChainConfig {
	if chainID == nil {
		return nil
	}
	if chainID.Cmp(params.LocalnetChainConfig.ChainID) == 0 {
		return params.LocalnetChainConfig
	}
	return nil
}

// clearConsensusOptionalTestChainXDPoS strips injected XDPoS for consensus-optional test chains.
func clearConsensusOptionalTestChainXDPoS(cfg, hydrated *params.ChainConfig) *params.ChainConfig {
	if hydrated == nil {
		return nil
	}
	if cfg.XDPoS == nil && cfg.Ethash == nil && cfg.Clique == nil && isConsensusOptionalTestChain(cfg.ChainID) {
		hydrated.XDPoS = nil
	}
	return hydrated
}

// isConsensusOptionalTestChain reports whether chainID allows a missing engine.
func isConsensusOptionalTestChain(chainID *big.Int) bool {
	if chainID == nil || !chainID.IsUint64() {
		return false
	}
	switch chainID.Uint64() {
	case params.ConsensusOptionalTestChainID:
		return true
	default:
		return false
	}
}

// builtInChainConfigByHash returns the bundled config for a known genesis hash.
func builtInChainConfigByHash(hash common.Hash) *params.ChainConfig {
	switch hash {
	case params.MainnetGenesisHash:
		return params.XDCMainnetChainConfig
	case params.TestnetGenesisHash:
		return params.TestnetChainConfig
	case params.DevnetGenesisHash:
		return params.DevnetChainConfig
	default:
		return nil
	}
}

// builtInBackfillSourceByHash returns the bundled chain config when the hash
// resolves to a built-in genesis definition.
func builtInBackfillSourceByHash(hash common.Hash) *params.ChainConfig {
	genesis := builtInGenesisByHash(hash)
	if genesis == nil || genesis.Config == nil {
		return nil
	}
	return genesis.Config
}

// builtInGenesisByHash returns the bundled genesis for a known genesis hash.
func builtInGenesisByHash(hash common.Hash) *Genesis {
	switch hash {
	case params.MainnetGenesisHash:
		return DefaultGenesisBlock()
	case params.TestnetGenesisHash:
		return DefaultTestnetGenesisBlock()
	case params.DevnetGenesisHash:
		return DefaultDevnetGenesisBlock()
	default:
		return nil
	}
}

// shouldPreferStoredOverrideConfig keeps a trusted stored override when
// the provided genesis only restates the bundled built-in config.
//
// The caller passes storedCfg after resolveStoredChainConfig has already
// hydrated/backfilled any missing built-in fields. Equality here must use
// chainConfigJSONEqual's strong semantic comparison: it takes the versioned
// hashChainConfigSemantic fast path when possible and otherwise falls back to a
// full structured Equal comparison instead of relying on digest equality alone.
func shouldPreferStoredOverrideConfig(hash common.Hash, storedCfg *params.ChainConfig, genesis *Genesis) (bool, error) {
	if storedCfg == nil || genesis == nil || genesis.Config == nil {
		return false, nil
	}
	builtin := builtInChainConfigByHash(hash)
	if builtin == nil {
		return false, nil
	}
	equal, err := chainConfigJSONEqual(genesis.Config, builtin)
	if err != nil {
		return false, err
	}
	return equal, nil
}

// shouldAllowCustomBuiltInConfig reports whether a built-in genesis hash
// may keep caller-supplied custom config values instead of canonicalizing to the bundled config.
// The stored-config heuristic below is only for legacy pre-marker databases;
// current databases must carry an explicit override marker instead of relying on inference.
// Callers that merely restate the canonical built-in config stay on the strict
// built-in path without error. Proven same-hash custom overrides, however,
// return the recovery gate error so callers can surface the rejection reason.
func shouldAllowCustomBuiltInConfig(db ethdb.Database, hash, providedHash common.Hash, providedCfg *params.ChainConfig, allowBuiltInCustomRecovery bool) (bool, error) {
	if hash == (common.Hash{}) {
		if builtInChainConfigByHash(providedHash) != nil {
			if !allowBuiltInCustomRecovery {
				_, err := resolveProvidedChainConfig(providedHash, providedCfg, builtInChainConfigMustMatch)
				if err != nil {
					return false, err
				}
				return false, nil
			}
		}
		return true, nil
	}
	trustedOverride, err := rawdb.ReadChainConfigOverride(db, hash)
	if err != nil {
		return false, err
	}
	if trustedOverride {
		if err := requireBuiltInCustomRecovery(hash, allowBuiltInCustomRecovery); err != nil {
			return false, err
		}
		return true, nil
	}
	if providedCfg != nil && providedHash == hash {
		storedCfg, err := rawdb.ReadChainConfig(db, hash)
		if err != nil && !errors.Is(err, rawdb.ErrChainConfigNotFound) {
			return false, err
		}
		if storedCfg != nil {
			storedCfg, err = resolveStoredChainConfig(hash, storedCfg)
			if err != nil {
				return false, err
			}
			legacyOverride, err := isLegacyStoredCustomBuiltInConfig(hash, storedCfg)
			if err != nil {
				return false, err
			}
			if legacyOverride {
				providedCfg = providedCfg.CloneForBackfill()
				resolvedProvidedCfg, err := resolveProvidedChainConfig(providedHash, providedCfg, builtInChainConfigAllowOverride)
				if err != nil {
					return false, err
				}
				equal, err := chainConfigJSONEqual(resolvedProvidedCfg, storedCfg)
				if err != nil {
					return false, err
				}
				if equal {
					return true, nil
				}
			}
		}
	}
	if _, err := rawdb.ReadChainConfig(db, hash); err != nil && !errors.Is(err, rawdb.ErrChainConfigNotFound) {
		return false, err
	}
	return false, nil
}

// isLegacyStoredCustomBuiltInConfig reports whether a stored config should be
// treated as a pre-marker same-hash custom override for a built-in genesis.
// It is intentionally narrow and exists only to migrate old databases that
// predate explicit override metadata.
// Only configs whose chain ID differs from the bundled chain ID are promoted;
// same-chain-ID drift remains a conflict.
func isLegacyStoredCustomBuiltInConfig(hash common.Hash, cfg *params.ChainConfig) (bool, error) {
	builtin := builtInChainConfigByHash(hash)
	if builtin == nil || cfg == nil || cfg.ChainID == nil || builtin.ChainID == nil {
		return false, nil
	}
	if cfg.ChainID.Cmp(builtin.ChainID) == 0 {
		return false, nil
	}
	equal, err := chainConfigJSONEqual(cfg, builtin)
	if err != nil {
		return false, err
	}
	return !equal, nil
}

// annotateResolvedCustomBuiltInConfig marks and logs active built-in overrides.
func annotateResolvedCustomBuiltInConfig(hash common.Hash, cfg *params.ChainConfig) {
	if cfg == nil {
		return
	}
	builtin := builtInChainConfigByHash(hash)
	if builtin == nil {
		cfg.SetBuiltInGenesisOverride(false)
		return
	}
	equal, err := chainConfigJSONEqual(cfg, builtin)
	if err != nil {
		log.Error("Failed to evaluate custom override for built-in genesis", "hash", hash.Hex(), "err", err)
		return
	}
	overrideActive := !equal
	cfg.SetBuiltInGenesisOverride(overrideActive)
	if overrideActive {
		log.Warn("YOU ARE OVERRIDING BUILTIN CHAIN CONFIG", "builtin", builtInNetworkName(hash), "hash", hash.Hex(), "chainId", cfg.ChainID)
	}
}

type builtInChainConfigFacts struct {
	hasBuiltInConfig        bool
	trustedOverride         bool
	storedMatchesBuiltIn    bool
	candidateMatchesBuiltIn bool
	allowStoredDriftRepair  bool
}

type builtInChainConfigAction struct {
	canonicalizeToBuiltIn bool
	terminalError         error
}

// decideBuiltInChainConfigAction resolves built-in canonicalization vs conflict outcomes.
func decideBuiltInChainConfigAction(facts builtInChainConfigFacts) builtInChainConfigAction {
	if !facts.hasBuiltInConfig || facts.trustedOverride {
		return builtInChainConfigAction{}
	}
	if !facts.candidateMatchesBuiltIn {
		return builtInChainConfigAction{terminalError: startup.ErrGenesisConfigConflict}
	}
	if facts.storedMatchesBuiltIn || facts.allowStoredDriftRepair {
		return builtInChainConfigAction{canonicalizeToBuiltIn: true}
	}
	return builtInChainConfigAction{terminalError: startup.ErrGenesisConfigConflict}
}

// normalizeProvidedGenesisConfig clones and normalizes a caller-provided genesis config.
func normalizeProvidedGenesisConfig(genesis *Genesis, policy builtInChainConfigPolicy) (*Genesis, common.Hash, error) {
	if genesis == nil {
		return nil, common.Hash{}, nil
	}
	genesis = genesis.copy()
	if genesis.Config == nil {
		return nil, common.Hash{}, errGenesisNoConfig
	}
	originalGenesisHash, err := genesis.Hash()
	if err != nil {
		return nil, common.Hash{}, err
	}
	resolvedConfig, err := resolveProvidedChainConfig(originalGenesisHash, genesis.Config, policy)
	if err != nil {
		return nil, originalGenesisHash, err
	}
	genesis.Config = resolvedConfig
	return genesis, originalGenesisHash, nil
}

// decideStoredConfigHeaderAction validates stored-config startup preconditions.
func decideStoredConfigHeaderAction(db ethdb.Reader, hash common.Hash) startup.Action {
	return startup.Decide(startup.Facts{
		CanonicalHash:    hash,
		HasStoredConfig:  true,
		HasGenesisHeader: rawdb.ReadHeader(db, hash, 0) != nil,
	})
}

// isExpectedStoredConfigHeaderAction reports whether the stored-config header
// validation path resolved to the explicit stored startup source without a
// terminal error.
func isExpectedStoredConfigHeaderAction(action startup.Action) bool {
	return action.TerminalError == nil && action.GenesisSource == startup.GenesisSourceStored
}

func expectStoredConfigHeaderAction(action startup.Action) error {
	if action.TerminalError != nil {
		return action.TerminalError
	}
	if !isExpectedStoredConfigHeaderAction(action) || action.AllowCommitGenesis || action.PreferStoredConfig || action.PromoteOverrideMarker {
		panic(fmt.Sprintf("BUG: stored-config header validation returned unexpected action: %+v", action))
	}
	return nil
}

func isExpectedInitialGenesisAction(action startup.Action) bool {
	return action.TerminalError == nil && (action.GenesisSource == startup.GenesisSourceDefaultMainnet || action.GenesisSource == startup.GenesisSourceProvided)
}

func expectInitialGenesisAction(action startup.Action) error {
	if action.TerminalError != nil {
		return action.TerminalError
	}
	if !isExpectedInitialGenesisAction(action) || !action.AllowCommitGenesis || action.PreferStoredConfig || action.PromoteOverrideMarker {
		panic(fmt.Sprintf("BUG: initial startup returned unexpected action: %+v", action))
	}
	return nil
}

func expectSetupMissingConfigAction(action startup.Action) error {
	if action.TerminalError != nil {
		return action.TerminalError
	}
	if !isExpectedStoredConfigHeaderAction(action) || action.AllowCommitGenesis || action.PreferStoredConfig || action.PromoteOverrideMarker {
		panic(fmt.Sprintf("BUG: setup missing-config recovery returned unexpected action: %+v", action))
	}
	return nil
}

// Decision helpers build startup state-machine actions from persisted facts.

// decideMissingConfigAction resolves startup behavior when chain config is absent.
func decideMissingConfigAction(hash common.Hash, hasGenesisHeader, trustedOverride, writable, allowBuiltInCustomRecovery bool) startup.Action {
	facts := startup.Facts{
		CanonicalHash:              hash,
		HasGenesisHeader:           hasGenesisHeader,
		TrustedOverride:            trustedOverride,
		Writable:                   writable,
		AllowBuiltInCustomRecovery: allowBuiltInCustomRecovery,
	}
	return startup.Decide(facts)
}

// decideSetupMissingConfigAction specializes writable missing-config recovery.
// Unlike generic startup.Decide missing-config routing, writable setup may
// repair an override-backed missing config only when the caller supplies the
// authoritative genesis; without that explicit genesis, startup must fail.
func decideSetupMissingConfigAction(hash common.Hash, hasGenesisHeader, trustedOverride, hasProvidedGenesis bool, _ bool) startup.Action {
	if hasProvidedGenesis {
		return startup.Action{GenesisSource: startup.GenesisSourceStored}
	}
	if trustedOverride {
		return startup.Action{TerminalError: startup.ErrGenesisConfigConflict}
	}
	return decideMissingConfigAction(hash, hasGenesisHeader, false, true, false)
}

// selectMissingConfigGenesis chooses provided, built-in, or default genesis for recovery.
func selectMissingConfigGenesis(ghash common.Hash, provided *Genesis) *Genesis {
	if provided != nil {
		log.Info("Writing custom genesis block")
		return provided
	}
	builtin := builtInGenesisByHash(ghash)
	if builtin != nil {
		log.Info("Writing built-in genesis block", "hash", ghash)
		return builtin
	}
	log.Info("Writing default main-net genesis block")
	return DefaultGenesisBlock()
}

// decideStoredOverrideAction evaluates stored-override reconciliation facts.
func decideStoredOverrideAction(hash common.Hash, opts startup.StoredOverrideOpts) startup.Action {
	return startup.Decide(startup.StoredOverrideFacts(hash, opts))
}

// applyStoredOverrideAction applies PreferStoredConfig by dropping provided genesis.
func applyStoredOverrideAction(hash common.Hash, opts startup.StoredOverrideOpts, genesis *Genesis) (*Genesis, startup.Action) {
	action := decideStoredOverrideAction(hash, opts)
	if action.PreferStoredConfig {
		if genesis != nil {
			log.Warn("ignored caller-provided genesis because stored override is authoritative", "hash", hash)
		}
		return nil, action
	}
	return genesis, action
}

// reconcileTrustedStoredOverrideGenesis keeps trusted stored overrides when applicable.
func reconcileTrustedStoredOverrideGenesis(hash common.Hash, storedCfg *params.ChainConfig, genesis *Genesis, opts startup.StoredOverrideOpts) (*Genesis, error) {
	providedRestatesBuiltIn, err := shouldPreferStoredOverrideConfig(hash, storedCfg, genesis)
	if err != nil {
		return nil, err
	}
	opts.HasProvidedGenesis = genesis != nil
	opts.ProvidedRestatesBuiltIn = providedRestatesBuiltIn
	genesis, _ = applyStoredOverrideAction(hash, opts, genesis)
	return genesis, nil
}

// decideInitialStartupAction resolves startup source selection for empty-db paths.
func decideInitialStartupAction(hash common.Hash, hasProvidedGenesis, writable bool) startup.Action {
	facts := startup.Facts{
		CanonicalHash:      hash,
		HasProvidedGenesis: hasProvidedGenesis,
		Writable:           writable,
	}
	return startup.Decide(facts)
}

// selectInitialGenesis maps initial startup action to the concrete genesis source.
func selectInitialGenesis(action startup.Action, provided *Genesis) *Genesis {
	switch action.GenesisSource {
	case startup.GenesisSourceDefaultMainnet:
		log.Info("Writing default main-net genesis block")
		return DefaultGenesisBlock()
	case startup.GenesisSourceProvided:
		log.Info("Writing custom genesis block")
		return provided
	default:
		panic(fmt.Sprintf("BUG: writable initialization returned unexpected genesis source %v", action.GenesisSource))
	}
}

type setupGenesisPath uint8

const (
	setupGenesisPathEmptyDB setupGenesisPath = iota
	setupGenesisPathMissingConfig
	setupGenesisPathStoredConfig
)

// decideSetupGenesisPath classifies writable startup into mutually exclusive paths.
func decideSetupGenesisPath(ghash common.Hash, hasStoredConfig bool) setupGenesisPath {
	if ghash == (common.Hash{}) {
		return setupGenesisPathEmptyDB
	}
	if !hasStoredConfig {
		return setupGenesisPathMissingConfig
	}
	return setupGenesisPathStoredConfig
}

type loadChainConfigPath uint8

const (
	loadChainConfigPathStoredConfig loadChainConfigPath = iota
	loadChainConfigPathStoredMissingConfigNoProvidedGenesis
	loadChainConfigPathProvidedGenesis
	loadChainConfigPathDefaultMainnet
)

// decideLoadChainConfigPath classifies readonly loading into mutually exclusive paths.
func decideLoadChainConfigPath(stored common.Hash, hasStoredConfig, hasProvidedGenesis bool) loadChainConfigPath {
	if stored != (common.Hash{}) {
		if hasStoredConfig {
			return loadChainConfigPathStoredConfig
		}
		if !hasProvidedGenesis {
			return loadChainConfigPathStoredMissingConfigNoProvidedGenesis
		}
	}
	if hasProvidedGenesis {
		return loadChainConfigPathProvidedGenesis
	}
	return loadChainConfigPathDefaultMainnet
}

// chainConfigOrDefault chooses the config that should drive compatibility
// checks for ghash. preferStored keeps a trusted same-hash custom override
// authoritative when no explicit genesis should replace it; otherwise bundled
// configs still win for known built-in genesis hashes.
func (g *Genesis) chainConfigOrDefault(ghash common.Hash, stored *params.ChainConfig, preferStored bool) *params.ChainConfig {
	var cfg *params.ChainConfig
	switch {
	case g != nil:
		cfg = g.Config
	case preferStored && stored != nil:
		cfg = stored
	case ghash == params.MainnetGenesisHash:
		cfg = params.XDCMainnetChainConfig
	case ghash == params.TestnetGenesisHash:
		cfg = params.TestnetChainConfig
	case ghash == params.DevnetGenesisHash:
		cfg = params.DevnetChainConfig
	default:
		cfg = stored
	}
	return cfg.Clone()
}

func (g *Genesis) toBlockWithRoot(root common.Hash) *types.Block {
	head := &types.Header{
		Number:     new(big.Int).SetUint64(g.Number),
		Nonce:      types.EncodeNonce(g.Nonce),
		Time:       g.Timestamp,
		ParentHash: g.ParentHash,
		Extra:      g.ExtraData,
		GasLimit:   g.GasLimit,
		GasUsed:    g.GasUsed,
		BaseFee:    g.BaseFee,
		Difficulty: g.Difficulty,
		MixDigest:  g.Mixhash,
		Coinbase:   g.Coinbase,
		Root:       root,
	}
	if g.GasLimit == 0 {
		head.GasLimit = params.GenesisGasLimit
	}
	if g.Difficulty == nil {
		head.Difficulty = params.GenesisDifficulty
	}
	// Notice: EIP1559Block affects the block hash, so g.Config.EIP1559Block
	// must be set in genesis chain config when EIP-1559 should be active.
	if g.Config != nil && g.Config.IsEIP1559(common.Big0) {
		if g.BaseFee != nil {
			head.BaseFee = g.BaseFee
		} else {
			head.BaseFee = new(big.Int).SetUint64(params.InitialBaseFee)
		}
	}
	return types.NewBlock(head, nil, nil, trie.NewStackTrie(nil))
}

// ToBlockWithError returns the genesis block according to genesis specification.
func (g *Genesis) ToBlockWithError() (*types.Block, error) {
	root, err := hashAlloc(&g.Alloc)
	if err != nil {
		return nil, err
	}
	return g.toBlockWithRoot(root), nil
}

// Hash returns the canonical genesis block hash.
//
// Callers must treat g.Config as hash-relevant input: fork settings can change
// the derived genesis header (for example EIP-1559 activation injects the
// initial BaseFee). Do not mutate or hydrate Config before validating an
// expected genesis hash against the caller-supplied genesis spec.
func (g *Genesis) Hash() (common.Hash, error) {
	block, err := g.ToBlockWithError()
	if err != nil {
		return common.Hash{}, err
	}
	return block.Hash(), nil
}

// ToBlock returns the genesis block according to genesis specification.
func (g *Genesis) ToBlock() *types.Block {
	block, err := g.ToBlockWithError()
	if err != nil {
		panic(err)
	}
	return block
}

// Commit writes the block, state, and canonicalized chain config of a genesis
// specification to the database as the canonical head block. Built-in genesis
// hashes must still resolve to the bundled config.
func (g *Genesis) Commit(db ethdb.Database) (*types.Block, error) {
	return g.commit(db, false, false)
}

// commit writes the genesis block, alloc, and resolved chain config to
// the database, optionally preserving a same-hash custom override instead of
// forcing a built-in genesis hash back to the bundled config. skipHydrate is
// only safe when the caller already normalized g.Config for this genesis hash.
func (g *Genesis) commit(db ethdb.Database, allowCustomBuiltInConfig bool, skipHydrate bool) (*types.Block, error) {
	genesis := g.copy()
	config := genesis.Config
	if config == nil {
		return nil, errors.New("invalid genesis without chain config")
	}
	originalHash, err := genesis.Hash()
	if err != nil {
		return nil, err
	}
	if !skipHydrate {
		config, err = resolveProvidedChainConfig(originalHash, config, builtInChainConfigPolicyForOverride(allowCustomBuiltInConfig))
		if err != nil {
			return nil, err
		}
	}
	genesis.Config = config
	block, err := genesis.ToBlockWithError()
	if err != nil {
		return nil, err
	}
	if block.Number().Sign() != 0 {
		return nil, errors.New("can't commit genesis block with number > 0")
	}
	if err := config.CheckConfigForkOrder(); err != nil {
		return nil, err
	}
	if config.XDPoS != nil && len(genesis.ExtraData) < 32+crypto.SignatureLength {
		return nil, errors.New("can't start XDPoS chain without signers")
	}
	// All the checks have passed, flushAlloc the states derived from the genesis
	// specification as well as the specification itself into the provided database.
	if err := flushAlloc(&genesis.Alloc, db, block.Hash()); err != nil {
		return nil, err
	}
	batch := db.NewBatch()
	rawdb.WriteTd(batch, block.Hash(), block.NumberU64(), genesis.Difficulty)
	rawdb.WriteBlock(batch, block)
	rawdb.WriteReceipts(batch, block.Hash(), block.NumberU64(), nil)
	rawdb.WriteCanonicalHash(batch, block.Hash(), block.NumberU64())
	rawdb.WriteHeadBlockHash(batch, block.Hash())
	rawdb.WriteHeadFastBlockHash(batch, block.Hash())
	rawdb.WriteHeadHeaderHash(batch, block.Hash())
	rawdb.WriteChainConfig(batch, block.Hash(), config)
	if allowCustomBuiltInConfig {
		if builtin := builtInChainConfigByHash(block.Hash()); builtin != nil {
			equal, err := chainConfigJSONEqual(config, builtin)
			if err != nil {
				return nil, err
			}
			if !equal {
				rawdb.WriteChainConfigOverride(batch, block.Hash())
			}
		}
	}
	return block, batch.Write()
}

// MustCommit writes the genesis block and state to db, panicking on error.
// The block is committed as the canonical head block.
func (g *Genesis) MustCommit(db ethdb.Database) *types.Block {
	block, err := g.Commit(db)
	if err != nil {
		panic(err)
	}
	return block
}

// DefaultGenesisBlock returns the XDC mainnet genesis block.
func DefaultGenesisBlock() *Genesis {
	return &Genesis{
		Config:     params.XDCMainnetChainConfig,
		Nonce:      0,
		ExtraData:  hexutil.MustDecode("0x000000000000000000000000000000000000000000000000000000000000000025c65b4b379ac37cf78357c4915f73677022eaffc7d49d0a2cf198deebd6ce581af465944ec8b2bbcfccdea1006a5cfa7d9484b5b293b46964c265c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
		GasLimit:   4700000,
		Difficulty: big.NewInt(1),
		Alloc:      DecodeAllocJson(MainnetAllocData),
		Timestamp:  1559211559,
	}
}

// DefaultTestnetGenesisBlock returns the XDC testnet genesis block.
func DefaultTestnetGenesisBlock() *Genesis {
	return &Genesis{
		Config:     params.TestnetChainConfig,
		Nonce:      0,
		ExtraData:  hexutil.MustDecode("0x00000000000000000000000000000000000000000000000000000000000000003ea0a3555f9b1de983572bff6444aeb1899ec58c4f7900282f3d371d585ab1361205b0940ab1789c942a5885a8844ee5587c8ac5e371fc39ffe618960000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
		GasLimit:   4700000,
		Difficulty: big.NewInt(1),
		Alloc:      DecodeAllocJson(TestnetAllocData),
		Timestamp:  1560417871,
	}
}

// DefaultDevnetGenesisBlock returns the XDC devnet genesis block.
func DefaultDevnetGenesisBlock() *Genesis {
	return &Genesis{
		Config:     params.DevnetChainConfig,
		Nonce:      0,
		ExtraData:  hexutil.MustDecode("0x000000000000000000000000000000000000000000000000000000000000000014a6f54c572a8b97735fa0332e5b4d9423a2ef2f18c6785a9db320c39ce72ef66f395cf87897bda82ab752f85637818e619447a34f112953cbc47e382f1e1ea681f95f9c0191f780714730d752c42c6e54df9aa5dd09e4010e3f8bbc2c89394adf70493e64e580d02446d4052d8bfd826fbd84274dc6635b83b8893d85b7f5a3ed47c38142ca96640a3490de959ecd9c04e87dc5002e90990fa182dc6c72708b9e5c011c619464eba3db4bdd23cbf2dcce66ad7eb8e36187c560bd9c26272c2fcd9a603fe56d5514c9f8f51c5c0406f810327879d5ec3bddfcbc705bd59dcf8bef5b97d967635712011dcaf717e75161d9a01e03710401c4aa75d02455ebb518e01cf342df118e11a82352fb4b3202a0071806f9b80af685e41e28fa809723aa60e63cfca6dc0f701d4abb57f28f3dd1879199e6452d557419f6d77c05ee343df7ef570e349533f7673cd41eea411f5ab4679a97fda1ee970dd71690fac008b2db45965beb60cf620000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
		GasLimit:   4700000,
		Difficulty: big.NewInt(1),
		Alloc:      DecodeAllocJson(DevnetAllocData),
		Timestamp:  1785709299,
	}
}

// DeveloperGenesisBlock returns the 'geth --dev' genesis block.
func DeveloperGenesisBlock(period uint64, faucet common.Address) *Genesis {
	// Override the default period to the user requested one
	config := *params.AllDevChainProtocolChanges
	config.XDPoS.Period = period

	// Assemble and return the genesis with the precompiles and faucet pre-funded
	return &Genesis{
		Config:     &config,
		ExtraData:  append(append(make([]byte, 32), faucet[:]...), make([]byte, crypto.SignatureLength)...),
		GasLimit:   6283185,
		BaseFee:    big.NewInt(params.InitialBaseFee),
		Difficulty: big.NewInt(1),
		Alloc: map[common.Address]types.Account{
			common.BytesToAddress([]byte{1}): {Balance: big.NewInt(1)}, // ECRecover
			common.BytesToAddress([]byte{2}): {Balance: big.NewInt(1)}, // SHA256
			common.BytesToAddress([]byte{3}): {Balance: big.NewInt(1)}, // RIPEMD
			common.BytesToAddress([]byte{4}): {Balance: big.NewInt(1)}, // Identity
			common.BytesToAddress([]byte{5}): {Balance: big.NewInt(1)}, // ModExp
			common.BytesToAddress([]byte{6}): {Balance: big.NewInt(1)}, // ECAdd
			common.BytesToAddress([]byte{7}): {Balance: big.NewInt(1)}, // ECScalarMul
			common.BytesToAddress([]byte{8}): {Balance: big.NewInt(1)}, // ECPairing
			faucet:                           {Balance: new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(9))},
			// Pre-deploy system contracts
			params.HistoryStorageAddress: {Nonce: 1, Code: params.HistoryStorageCode, Balance: common.Big0},
		},
	}
}

// DecodeAllocJson decodes a JSON allocation map into GenesisAlloc.
func DecodeAllocJson(s string) types.GenesisAlloc {
	alloc := types.GenesisAlloc{}
	json.Unmarshal([]byte(s), &alloc)
	return alloc
}

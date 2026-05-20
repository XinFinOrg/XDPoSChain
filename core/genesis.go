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
	xdposutils "github.com/XinFinOrg/XDPoSChain/consensus/XDPoS/utils"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/startup"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/tracing"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/ethdb"
	"github.com/XinFinOrg/XDPoSChain/log"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/XinFinOrg/XDPoSChain/trie"
)

//go:generate go run github.com/fjl/gencodec -type Genesis -field-override genesisSpecMarshaling -out gen_genesis.go

// Startup routing overview
//
// The startup path in this file is split into two decision layers:
//
//   1. startup.Facts -> startup.Action
//      Pure routing for "which source should drive startup right now?"
//
//   2. builtInChainConfigFacts -> builtInChainConfigAction
//      Built-in-only canonicalization for "does the chosen config still need
//      to collapse back to the bundled built-in config?"
//
// The first layer is easiest to reason about as a small state machine over a
// few orthogonal fact dimensions:
//
//   identity: canonical hash empty? provided matches stored? provided restates built-in?
//   storage:  stored chain-config blob present? genesis header present?
//   trust:    override marker present? historical v1 same-hash built-in
//             override path inferred from stored config state?
//   mode:     writable startup or read-only startup?
//
// Those facts map to a small set of routing actions before any fork-order,
// compatibility, or persistence work happens:
//
//   choose genesis source        -> provided / built-in / default mainnet
//   allow commit                 -> only on writable empty-db startup
//   require explicit genesis     -> same-hash override lost its stored config
//   prefer stored config         -> trusted stored override should win
//   promote override marker      -> writable upgrade from the historical v1
//                                    same-hash built-in override path that
//                                    stored only the custom config, not the
//                                    explicit marker
//   terminal error               -> chain-config missing or built-in conflict
//
// ASCII map of the routing layer:
//
//   +------------------- canonical hash present? -------------------+
//   | no                                                          yes |
//   |                                                              |
//   v                                                              v
//   [empty DB]                                           [stored genesis exists]
//   |                                                     |
//   +-- provided genesis? -- yes --> source=provided      +-- stored config missing? -- yes -->
//   |                          no --> source=default           |                              |
//   |                                                         trusted override?           no trusted override
//   +-- writable? --------- yes --> allowCommitGenesis         |                              |
//                              no --> read-only source only    v                              v
//                                                           require explicit          try bundled recovery
//                                                           genesis / not found       or return missing config
//
//   [stored genesis exists, stored config present]
//   |
//   +-- trusted or legacy override?
//          |
//          +-- provided genesis matches stored hash and restates built-in?
//                 |
//                 +-- yes --> prefer stored config
//                 |           + writable + legacy v1 path -> promote explicit
//                 |             override marker
//                 |
//                 +-- no  --> continue with normal compatibility and built-in checks
//
// Everything after that falls through to the existing orchestration below:
// config hydration, built-in canonicalization, compatibility checks, and DB
// writes stay local to this file.

var (
	errGenesisNoConfig         = errors.New("genesis has no chain configuration")
	errGenesisConfigConflict   = errors.New("provided genesis config conflicts with built-in chain config")
	errMissingHeadHeader       = errors.New("missing head header")
	errMissingHeadHeaderNumber = errors.New("missing block number for head header hash")

	defaultGenesisDeps = genesisDeps{
		jsonMarshal: json.Marshal,
		genesisHash: func(g *Genesis) (common.Hash, error) {
			return g.Hash()
		},
		hashChainConfigSemanticVersioned: defaultHashChainConfigSemanticVersioned,
		writeChainConfig:                 rawdb.WriteChainConfig,
		writeChainConfigOverride:         rawdb.WriteChainConfigOverride,
		readChainConfigOverride:          rawdb.ReadChainConfigOverride,
	}
)

type GenesisStartupOptions struct {
	AllowBuiltInCustomRecovery bool
}

type genesisDeps struct {
	jsonMarshal                      func(any) ([]byte, error)
	genesisHash                      func(*Genesis) (common.Hash, error)
	hashChainConfigSemanticVersioned func(*params.ChainConfig) (byte, [32]byte)
	writeChainConfig                 func(ethdb.KeyValueWriter, common.Hash, *params.ChainConfig)
	writeChainConfigOverride         func(ethdb.KeyValueWriter, common.Hash)
	readChainConfigOverride          func(ethdb.KeyValueReader, common.Hash) (bool, error)
}

// Deprecated: use types.Account instead.
type GenesisAccount = types.Account

// Deprecated: use types.GenesisAlloc instead.
type GenesisAlloc = types.GenesisAlloc

type recoveryMode uint8

const (
	recoveryDisabled recoveryMode = iota
	recoveryWritable
)

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

// getGenesisState returns the persisted genesis allocation for blockhash.
//
// If the explicit allocation blob is missing, bundled networks fall back to
// their built-in allocation so startup recovery can reconstruct genesis state.
// Custom networks only use fallbackGenesis when the caller explicitly enables
// writable recovery. Read-only startup must not auto-recover custom genesis
// state from an external genesis file.
func getGenesisState(db ethdb.Database, blockhash common.Hash, fallbackGenesis *Genesis, mode recoveryMode) (alloc types.GenesisAlloc, err error) {
	blob := rawdb.ReadGenesisStateSpec(db, blockhash)
	if len(blob) != 0 {
		if err := alloc.UnmarshalJSON(blob); err != nil {
			return nil, err
		}

		return alloc, nil
	}

	// Genesis allocation is missing and there are several possibilities:
	// the node is legacy which doesn't persist the genesis allocation or
	// the persisted allocation is just lost.
	// - supported networks(mainnet, testnets), recover with defined allocations
	// - private network, can't recover
	var genesis *Genesis
	switch blockhash {
	case params.MainnetGenesisHash:
		genesis = DefaultGenesisBlock()
	case params.TestnetGenesisHash:
		genesis = DefaultTestnetGenesisBlock()
	case params.DevnetGenesisHash:
		genesis = DefaultDevnetGenesisBlock()
	}
	if genesis != nil {
		return genesis.Alloc, nil
	}
	if mode == recoveryWritable && fallbackGenesis != nil {
		normalizedGenesis, err := normalizeRecoveryGenesis(blockhash, fallbackGenesis)
		if err != nil {
			return nil, err
		}
		// SECURITY: Do not relax this hash check. Recovering alloc from a
		// caller-supplied genesis without re-deriving the canonical genesis hash
		// would let mismatched custom-network state be injected into the local
		// chain database.
		if normalizedGenesis != nil {
			hash, err := normalizedGenesis.Hash()
			if err != nil {
				return nil, err
			}
			if hash == blockhash {
				return normalizedGenesis.Alloc, nil
			}
		}
	}

	return nil, nil
}

// hashAlloc computes the state root according to the genesis specification.
func hashAlloc(ga *types.GenesisAlloc) (common.Hash, error) {
	// Create an ephemeral in-memory database for computing hash,
	// all the derived states will be discarded to not pollute disk.
	db := state.NewDatabaseWithConfig(rawdb.NewMemoryDatabase(), nil)
	statedb, err := state.New(types.EmptyRootHash, db)
	if err != nil {
		return common.Hash{}, err
	}
	for addr, account := range *ga {
		if account.Balance != nil {
			statedb.AddBalance(addr, account.Balance, tracing.BalanceIncreaseGenesisBalance)
		}
		statedb.SetCode(addr, account.Code)
		statedb.SetNonce(addr, account.Nonce, tracing.NonceChangeGenesis)
		for key, value := range account.Storage {
			statedb.SetState(addr, key, value)
		}
	}
	return statedb.Commit(0, false)
}

// flushAlloc is very similar to hashAlloc, but the main difference is
// all the generated states will be persisted into the given database.
// Also, the genesis state specification will be flushed as well.
func flushAlloc(ga *types.GenesisAlloc, db ethdb.Database, blockhash common.Hash) error {
	statedb, err := state.New(types.EmptyRootHash, state.NewDatabase(db))
	if err != nil {
		return err
	}
	for addr, account := range *ga {
		if account.Balance != nil {
			statedb.AddBalance(addr, account.Balance, tracing.BalanceIncreaseGenesisBalance)
		}
		statedb.SetCode(addr, account.Code)
		statedb.SetNonce(addr, account.Nonce, tracing.NonceChangeGenesis)
		for key, value := range account.Storage {
			statedb.SetState(addr, key, value)
		}
	}
	root, err := statedb.Commit(0, false)
	if err != nil {
		return err
	}
	err = statedb.Database().TrieDB().Commit(root, true)
	if err != nil {
		return err
	}
	// Marshal the genesis state specification and persist.
	blob, err := json.Marshal(ga)
	if err != nil {
		return err
	}
	rawdb.WriteGenesisStateSpec(db, blockhash, blob)
	return nil
}

// restoreGenesisState restores the persisted genesis allocation for block when
// the allocation blob is missing. It recomputes the genesis root, verifies it
// against the canonical block header, and flushes the recovered state back to
// disk. Writable callers may provide the matching genesis spec as a custom
// recovery fallback when the stored allocation blob is missing. Read-only
// callers must surface ErrReadOnlyGenesisStateRecovery instead of auto-
// recovering custom genesis state.
func restoreGenesisState(db ethdb.Database, block *types.Block, fallbackGenesis *Genesis) error {
	alloc, err := getGenesisState(db, block.Hash(), fallbackGenesis, recoveryWritable)
	if err != nil {
		return fmt.Errorf("failed to load genesis alloc for %s: %w", block.Hash().Hex(), err)
	}
	if alloc == nil {
		return fmt.Errorf("missing genesis state and unrecoverable genesis alloc for hash: %s", block.Hash().Hex())
	}
	root, err := hashAlloc(&alloc)
	if err != nil {
		return fmt.Errorf("failed to hash genesis alloc for %s: %w", block.Hash().Hex(), err)
	}
	if root != block.Root() {
		return fmt.Errorf("genesis alloc root mismatch for %s: have %s want %s", block.Hash().Hex(), root.Hex(), block.Root().Hex())
	}
	if err := flushAlloc(&alloc, db, block.Hash()); err != nil {
		return fmt.Errorf("failed to restore genesis state for %s: %w", block.Hash().Hex(), err)
	}
	return nil
}

// normalizeRecoveryGenesis returns a hydrated copy of fallbackGenesis suitable
// for hash comparison during startup recovery.
func normalizeRecoveryGenesis(blockhash common.Hash, fallbackGenesis *Genesis) (*Genesis, error) {
	if fallbackGenesis == nil {
		return nil, nil
	}
	normalized := fallbackGenesis.copy()
	if normalized == nil || normalized.Config == nil {
		return normalized, nil
	}
	var err error
	normalized.Config, err = resolveProvidedChainConfig(blockhash, normalized.Config, builtInChainConfigPolicyForOverride(builtInChainConfigByHash(blockhash) != nil))
	if err != nil {
		return nil, err
	}
	return normalized, nil
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

func requireBuiltInCustomRecovery(hash common.Hash, allow bool) error {
	if allow || builtInChainConfigByHash(hash) == nil {
		return nil
	}
	return builtInGenesisConfigConflictError(hash)
}

// builtInGenesisConfigConflictError wraps built-in conflicts with remediation guidance.
func builtInGenesisConfigConflictError(hash common.Hash) error {
	cfg := builtInChainConfigByHash(hash)
	if cfg == nil {
		return errGenesisConfigConflict
	}
	return fmt.Errorf("%w: same-hash custom overrides on built-in networks require --allow-builtin-config-override; builtin=%s chainId=%d", errGenesisConfigConflict, builtInNetworkName(hash), cfg.ChainID)
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
	if cfg == nil {
		return nil
	}
	if localnet := localnetChainConfigByChainID(cfg.ChainID); localnet != nil {
		hydrated := cfg.BackfillMissingFieldsFrom(localnet)
		if hydrated == nil {
			return nil
		}
		if hydrated.TIPTRC21FeeBlock == nil {
			hydrated.TIPTRC21FeeBlock = new(big.Int)
		}
		return clearConsensusOptionalTestChainXDPoS(cfg, hydrated)
	}
	hydrated := hydrateLegacyCompatibleCustomChainConfig(cfg)
	return clearConsensusOptionalTestChainXDPoS(cfg, hydrated)
}

// hydrateStoredCustomChainConfig resolves persisted custom genesis configs.
// Besides the Localnet chain ID shortcut, it may apply the narrow legacy
// compatibility backfill for stored private-chain XDPoS configs that used the
// historical local/private defaults before the ChainConfig migration.
func hydrateStoredCustomChainConfig(cfg *params.ChainConfig) *params.ChainConfig {
	if cfg == nil {
		return nil
	}
	if localnet := localnetChainConfigByChainID(cfg.ChainID); localnet != nil {
		hydrated := cfg.BackfillMissingFieldsFrom(localnet)
		if hydrated == nil {
			return nil
		}
		if hydrated.TIPTRC21FeeBlock == nil {
			hydrated.TIPTRC21FeeBlock = new(big.Int)
		}
		return clearConsensusOptionalTestChainXDPoS(cfg, hydrated)
	}
	return hydrateLegacyCompatibleCustomChainConfig(cfg)
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
	return clearConsensusOptionalTestChainXDPoS(cfg, hydrated)
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

// chainConfigJSONEqual compares configs via their canonical JSON encoding.
func chainConfigJSONEqual(a, b *params.ChainConfig) (bool, error) {
	return defaultGenesisDeps.chainConfigJSONEqual(a, b)
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

// shouldPreferStoredOverrideConfigWithDeps keeps a trusted stored override when
// the provided genesis only restates the bundled built-in config.
//
// The caller passes storedCfg after resolveStoredChainConfig has already
// hydrated/backfilled any missing built-in fields. Equality here must use
// chainConfigJSONEqual's strong semantic comparison: it takes the versioned
// hashChainConfigSemantic fast path when possible and otherwise falls back to a
// full structured Equal comparison instead of relying on digest equality alone.
func shouldPreferStoredOverrideConfigWithDeps(deps genesisDeps, hash common.Hash, storedCfg *params.ChainConfig, genesis *Genesis) (bool, error) {
	if storedCfg == nil || genesis == nil || genesis.Config == nil {
		return false, nil
	}
	builtin := builtInChainConfigByHash(hash)
	if builtin == nil {
		return false, nil
	}
	equal, err := deps.chainConfigJSONEqual(genesis.Config, builtin)
	if err != nil {
		return false, err
	}
	return equal, nil
}

// shouldAllowCustomBuiltInConfigWithDeps reports whether a built-in genesis hash
// may keep caller-supplied custom config values instead of canonicalizing to the bundled config.
// The stored-config heuristic below is only for legacy pre-marker databases;
// current databases must carry an explicit override marker instead of relying on inference.
func shouldAllowCustomBuiltInConfigWithDeps(deps genesisDeps, db ethdb.Database, hash, providedHash common.Hash, providedCfg *params.ChainConfig, allowBuiltInCustomRecovery bool) (bool, error) {
	if hash == (common.Hash{}) {
		if builtInChainConfigByHash(providedHash) != nil {
			if err := requireBuiltInCustomRecovery(providedHash, allowBuiltInCustomRecovery); err != nil {
				return false, nil
			}
		}
		return true, nil
	}
	trustedOverride, err := deps.readChainConfigOverride(db, hash)
	if err != nil {
		return false, err
	}
	if trustedOverride {
		if err := requireBuiltInCustomRecovery(hash, allowBuiltInCustomRecovery); err != nil {
			return false, nil
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
				equal, err := deps.chainConfigJSONEqual(resolvedProvidedCfg, storedCfg)
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
	return isLegacyStoredCustomBuiltInConfigWithDeps(defaultGenesisDeps, hash, cfg)
}

// isLegacyStoredCustomBuiltInConfigWithDeps detects pre-marker same-hash custom overrides.
func isLegacyStoredCustomBuiltInConfigWithDeps(deps genesisDeps, hash common.Hash, cfg *params.ChainConfig) (bool, error) {
	builtin := builtInChainConfigByHash(hash)
	if builtin == nil || cfg == nil || cfg.ChainID == nil || builtin.ChainID == nil {
		return false, nil
	}
	if cfg.ChainID.Cmp(builtin.ChainID) == 0 {
		return false, nil
	}
	equal, err := deps.chainConfigJSONEqual(cfg, builtin)
	if err != nil {
		return false, err
	}
	return !equal, nil
}

// annotateResolvedCustomBuiltInConfigWithDeps marks and logs active built-in overrides.
func annotateResolvedCustomBuiltInConfigWithDeps(deps genesisDeps, hash common.Hash, cfg *params.ChainConfig) {
	if cfg == nil {
		return
	}
	builtin := builtInChainConfigByHash(hash)
	if builtin == nil {
		cfg.SetBuiltInGenesisOverride(false)
		return
	}
	equal, err := deps.chainConfigJSONEqual(cfg, builtin)
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
	terminalError         startup.DecisionError
}

// decideBuiltInChainConfigAction resolves built-in canonicalization vs conflict outcomes.
func decideBuiltInChainConfigAction(facts builtInChainConfigFacts) builtInChainConfigAction {
	if !facts.hasBuiltInConfig || facts.trustedOverride {
		return builtInChainConfigAction{}
	}
	if !facts.candidateMatchesBuiltIn {
		return builtInChainConfigAction{terminalError: startup.DecisionErrorGenesisConfigConflict}
	}
	if facts.storedMatchesBuiltIn || facts.allowStoredDriftRepair {
		return builtInChainConfigAction{canonicalizeToBuiltIn: true}
	}
	return builtInChainConfigAction{terminalError: startup.DecisionErrorGenesisConfigConflict}
}

// normalizeProvidedGenesisConfig clones and normalizes a caller-provided genesis config.
func normalizeProvidedGenesisConfig(deps genesisDeps, genesis *Genesis, policy builtInChainConfigPolicy) (*Genesis, common.Hash, error) {
	if genesis == nil {
		return nil, common.Hash{}, nil
	}
	genesis = genesis.copy()
	if genesis.Config == nil {
		return nil, common.Hash{}, errGenesisNoConfig
	}
	originalGenesisHash, err := deps.genesisHash(genesis)
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
	return action.TerminalError == startup.DecisionErrorNone && action.GenesisSource == startup.GenesisSourceStored
}

func expectStoredConfigHeaderAction(action startup.Action) error {
	if action.TerminalError != startup.DecisionErrorNone {
		return action.TerminalError.ToError()
	}
	if !isExpectedStoredConfigHeaderAction(action) || action.AllowCommitGenesis || action.PreferStoredConfig || action.PromoteOverrideMarker {
		panic(fmt.Sprintf("BUG: stored-config header validation returned unexpected action: %+v", action))
	}
	return nil
}

// Decision helpers build startup state-machine actions from persisted facts.

// decideMissingConfigAction resolves startup behavior when chain config is absent.
func decideMissingConfigAction(hash common.Hash, hasGenesisHeader, trustedOverride, writable bool) startup.Action {
	facts := startup.Facts{
		CanonicalHash:    hash,
		HasGenesisHeader: hasGenesisHeader,
		TrustedOverride:  trustedOverride,
		Writable:         writable,
	}
	return startup.Decide(facts)
}

// decideSetupMissingConfigAction specializes missing-config decisions for writable setup.
func decideSetupMissingConfigAction(hash common.Hash, hasGenesisHeader, trustedOverride, hasProvidedGenesis bool) startup.Action {
	if hasProvidedGenesis {
		return startup.Action{}
	}
	return decideMissingConfigAction(hash, hasGenesisHeader, trustedOverride, true)
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
		return nil, action
	}
	return genesis, action
}

// reconcileTrustedStoredOverrideGenesisWithDeps keeps trusted stored overrides when applicable.
func reconcileTrustedStoredOverrideGenesisWithDeps(deps genesisDeps, hash common.Hash, storedCfg *params.ChainConfig, genesis *Genesis, opts startup.StoredOverrideOpts) (*Genesis, error) {
	providedRestatesBuiltIn, err := shouldPreferStoredOverrideConfigWithDeps(deps, hash, storedCfg, genesis)
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

// Load-path execution helpers consume precomputed decisions and state.

// normalizeProvidedGenesisForStoredConfigWithDeps normalizes and validates provided genesis against stored state.
func normalizeProvidedGenesisForStoredConfigWithDeps(deps genesisDeps, stored common.Hash, storedCfg *params.ChainConfig, genesis *Genesis, trustedOverride, allowBuiltInCustomRecovery bool) (*Genesis, common.Hash, error) {
	if genesis == nil {
		return nil, common.Hash{}, nil
	}
	originalHash := common.Hash{}
	var err error
	genesis, originalHash, err = normalizeProvidedGenesisConfig(deps, genesis, builtInChainConfigPolicyForOverride(trustedOverride))
	if err != nil {
		return nil, originalHash, err
	}
	if err := genesis.Config.CheckConfigForkOrder(); err != nil {
		return nil, common.Hash{}, err
	}
	providedHash, err := deps.genesisHash(genesis)
	if err != nil {
		return nil, common.Hash{}, err
	}
	if providedHash != stored && originalHash != stored {
		return nil, providedHash, &GenesisMismatchError{stored, providedHash}
	}
	if trustedOverride {
		if err := requireBuiltInCustomRecovery(stored, allowBuiltInCustomRecovery); err != nil {
			return nil, common.Hash{}, err
		}
		genesis, err = reconcileTrustedStoredOverrideGenesisWithDeps(deps, stored, storedCfg, genesis, startup.StoredOverrideOpts{
			OriginalGenesisHash:        originalHash,
			TrustedOverride:            trustedOverride,
			LegacyStoredOverride:       false,
			Writable:                   false,
			AllowBuiltInCustomRecovery: allowBuiltInCustomRecovery,
		})
		if err != nil {
			return nil, common.Hash{}, err
		}
	}
	return genesis, common.Hash{}, nil
}

// resolveLoadStoredConfigResultWithDeps finalizes readonly stored-config resolution.
func resolveLoadStoredConfigResultWithDeps(db ethdb.Database, deps genesisDeps, stored common.Hash, storedCfg, newCfg *params.ChainConfig, state loadStoredConfigState, genesis *Genesis, returnCompat bool) (cfg *params.ChainConfig, compatErr *params.ConfigCompatError, err error) {
	if returnCompat {
		resolvedCfg, compatErr, err := resolveHeadCompatibleChainConfigWithDeps(db, storedCfg, newCfg, state.trustedOverride, state.builtin, deps)
		if err != nil {
			return nil, nil, err
		}
		return resolvedCfg, compatErr, nil
	}
	if state.trustedOverride || state.builtin == nil {
		if genesis != nil {
			equal, err := deps.chainConfigJSONEqual(storedCfg, genesis.Config)
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
	storedEqual, err := deps.chainConfigJSONEqual(storedCfg, state.builtin)
	if err != nil {
		return nil, nil, err
	}
	if !storedEqual {
		return nil, nil, builtInGenesisConfigConflictError(stored)
	}
	newEqual, err := deps.chainConfigJSONEqual(newCfg, state.builtin)
	if err != nil {
		return nil, nil, err
	}
	if !newEqual {
		return nil, nil, builtInGenesisConfigConflictError(stored)
	}
	return state.builtin.Clone(), nil, nil
}

// resolveLoadStoredMissingConfigNoProvidedGenesisWithDeps handles readonly missing-config recovery.
func resolveLoadStoredMissingConfigNoProvidedGenesisWithDeps(deps genesisDeps, db ethdb.Database, stored common.Hash, allowBuiltInCustomRecovery bool) (cfg *params.ChainConfig, err error) {
	// Missing config metadata is recoverable from bundled defaults only for
	// plain bundled networks. Override-backed same-hash custom chains need
	// their persisted custom config or a matching explicit genesis.
	state, err := prepareLoadStoredConfigStateWithDeps(deps, db, stored, allowBuiltInCustomRecovery)
	if err != nil {
		return nil, err
	}
	action := decideMissingConfigAction(stored, rawdb.ReadHeader(db, stored, 0) != nil, state.trustedOverride, false)
	if action.TerminalError != startup.DecisionErrorNone {
		return nil, action.TerminalError.ToError()
	}
	if state.builtin != nil {
		if err := state.builtin.CheckConfigForkOrder(); err != nil {
			return nil, err
		}
		return state.builtin.Clone(), nil
	}
	return nil, rawdb.ErrChainConfigNotFound
}

// resolveLoadProvidedGenesisWithDeps resolves readonly config directly from provided genesis.
func resolveLoadProvidedGenesisWithDeps(deps genesisDeps, db ethdb.Database, stored common.Hash, genesis *Genesis, allowBuiltInCustomRecovery bool) (cfg *params.ChainConfig, ghash common.Hash, err error) {
	// Load the config from the provided genesis specification.
	originalHash, err := deps.genesisHash(genesis)
	if err != nil {
		return nil, common.Hash{}, err
	}
	allowCustomBuiltIn, allowErr := shouldAllowCustomBuiltInConfigWithDeps(deps, db, stored, originalHash, genesis.Config, allowBuiltInCustomRecovery)
	if allowErr != nil {
		return nil, common.Hash{}, allowErr
	}
	genesis, originalHash, err = normalizeProvidedGenesisConfig(deps, genesis, builtInChainConfigPolicyForOverride(allowCustomBuiltIn))
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
	ghash, err = deps.genesisHash(genesis)
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
	if action.TerminalError != startup.DecisionErrorNone || action.GenesisSource != startup.GenesisSourceDefaultMainnetReadonly || action.AllowCommitGenesis || action.PreferStoredConfig || action.PromoteOverrideMarker {
		panic(fmt.Sprintf("BUG: readonly fallback returned unexpected action: %+v", action))
	}
}

type setupStoredOverrideState struct {
	markerPresent        bool
	legacyStoredOverride bool
	trustedOverride      bool
}

type loadStoredConfigState struct {
	trustedOverride bool
	builtin         *params.ChainConfig
}

// prepareLoadStoredConfigStateWithDeps loads override marker and built-in baseline.
func prepareLoadStoredConfigStateWithDeps(deps genesisDeps, db ethdb.Database, stored common.Hash, allowBuiltInCustomRecovery bool) (loadStoredConfigState, error) {
	trustedOverride, err := deps.readChainConfigOverride(db, stored)
	if err != nil {
		return loadStoredConfigState{}, err
	}
	if trustedOverride {
		if err := requireBuiltInCustomRecovery(stored, allowBuiltInCustomRecovery); err != nil {
			return loadStoredConfigState{}, err
		}
	}
	return loadStoredConfigState{
		trustedOverride: trustedOverride,
		builtin:         builtInChainConfigByHash(stored),
	}, nil
}

// prepareSetupStoredConfigOverridesWithDeps derives setup override state and preferred genesis.
// Here "legacy stored override" means the historical v1 same-hash built-in
// override path where the custom config was already persisted but the explicit
// override marker had not been written yet.
func prepareSetupStoredConfigOverridesWithDeps(deps genesisDeps, db ethdb.Database, ghash common.Hash, storedCfg *params.ChainConfig, genesis *Genesis, originalGenesisHash common.Hash, allowBuiltInCustomRecovery bool) (resolvedGenesis *Genesis, state setupStoredOverrideState, err error) {
	state.markerPresent, err = deps.readChainConfigOverride(db, ghash)
	if err != nil {
		return nil, setupStoredOverrideState{}, err
	}
	if state.markerPresent {
		if err := requireBuiltInCustomRecovery(ghash, allowBuiltInCustomRecovery); err != nil {
			return nil, setupStoredOverrideState{}, err
		}
	}
	state.legacyStoredOverride = false
	if genesis != nil && originalGenesisHash == ghash {
		state.legacyStoredOverride, err = isLegacyStoredCustomBuiltInConfigWithDeps(deps, ghash, storedCfg)
		if err != nil {
			return nil, setupStoredOverrideState{}, err
		}
		if state.legacyStoredOverride {
			equal, err := deps.chainConfigJSONEqual(genesis.Config, storedCfg)
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
		genesis, err = reconcileTrustedStoredOverrideGenesisWithDeps(deps, ghash, storedCfg, genesis, startup.StoredOverrideOpts{
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

// resolveSetupStoredConfigResultWithDeps finalizes writable stored-config reconciliation and persistence.
func resolveSetupStoredConfigResultWithDeps(deps genesisDeps, db ethdb.Database, ghash common.Hash, storedCfg, newCfg *params.ChainConfig, genesis *Genesis, head *types.Header, state setupStoredOverrideState) (cfg *params.ChainConfig, compatErr *params.ConfigCompatError, err error) {
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
			deps.writeChainConfigOverride(db, ghash)
		}
		return newCfg, compatErr, nil
	}
	if builtin := builtInChainConfigByHash(ghash); builtin != nil && !state.trustedOverride {
		storedEqual, err := deps.chainConfigJSONEqual(storedCfg, builtin)
		if err != nil {
			return nil, nil, err
		}
		newEqual, err := deps.chainConfigJSONEqual(newCfg, builtin)
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
		if action.terminalError == startup.DecisionErrorGenesisConfigConflict {
			return nil, nil, builtInGenesisConfigConflictError(ghash)
		}
		if action.canonicalizeToBuiltIn {
			newCfg = builtin.Clone()
		}
	}
	persistResolvedConfig := state.legacyStoredOverride && !state.markerPresent
	resolvedEqual, err := deps.chainConfigJSONEqual(storedCfg, newCfg)
	if err != nil {
		return nil, nil, err
	}
	writeResolvedConfig := !resolvedEqual || persistResolvedConfig
	writeOverrideMarker := state.legacyStoredOverride && !state.markerPresent
	if writeResolvedConfig || writeOverrideMarker {
		batch := db.NewBatch()
		if writeResolvedConfig {
			deps.writeChainConfig(batch, ghash, newCfg)
		}
		if writeOverrideMarker {
			deps.writeChainConfigOverride(batch, ghash)
		}
		if err := batch.Write(); err != nil {
			return nil, nil, err
		}
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
	return setupGenesisBlockWithDeps(db, genesis, defaultGenesisDeps, GenesisStartupOptions{AllowBuiltInCustomRecovery: allowBuiltInCustomRecovery})
}

// setupGenesisBlockWithDeps is SetupGenesisBlock with injectable persistence and comparison helpers.
func setupGenesisBlockWithDeps(db ethdb.Database, genesis *Genesis, deps genesisDeps, opts GenesisStartupOptions) (chainConfig *params.ChainConfig, genesisHash common.Hash, compatErr *params.ConfigCompatError, err error) {
	defer func() {
		annotateResolvedCustomBuiltInConfigWithDeps(deps, genesisHash, chainConfig)
		logResolvedChainConfig(err, chainConfig, genesisHash, compatErr)
	}()

	// Copy the genesis, so we can operate on a copy.
	genesis = genesis.copy()
	ghash := rawdb.ReadCanonicalHash(db, 0)

	var originalGenesisHash common.Hash
	if genesis != nil {
		// Normalize caller-provided config once at entry so all later comparisons,
		// compatibility checks and persistence operate on canonical form.
		originalGenesisHash, err = deps.genesisHash(genesis)
		if err != nil {
			return nil, common.Hash{}, nil, err
		}
		allowCustomBuiltIn, allowErr := shouldAllowCustomBuiltInConfigWithDeps(deps, db, ghash, originalGenesisHash, genesis.Config, opts.AllowBuiltInCustomRecovery)
		if allowErr != nil {
			return nil, common.Hash{}, nil, allowErr
		}
		genesis, originalGenesisHash, err = normalizeProvidedGenesisConfig(deps, genesis, builtInChainConfigPolicyForOverride(allowCustomBuiltIn))
		if err != nil {
			return nil, originalGenesisHash, nil, err
		}
	}

	// Route startup into mutually-exclusive execution branches.
	storedCfg, readErr := rawdb.ReadChainConfig(db, ghash)
	if readErr != nil && !errors.Is(readErr, rawdb.ErrChainConfigNotFound) {
		return nil, common.Hash{}, nil, readErr
	}
	switch decideSetupGenesisPath(ghash, storedCfg != nil) {
	case setupGenesisPathEmptyDB:
		action := decideInitialStartupAction(ghash, genesis != nil, true)
		genesis = selectInitialGenesis(action, genesis)
		block, err := genesis.commitWithDeps(db, true, true, deps)
		if err != nil {
			return nil, common.Hash{}, nil, err
		}
		return genesis.Config.Clone(), block.Hash(), nil, nil

	case setupGenesisPathMissingConfig:
		// Commit the genesis if the genesis block exists in the ancient database
		// but the key-value database is empty without initializing the genesis
		// fields. This scenario can occur when the node is created from scratch
		// with an existing ancient store.
		hasGenesisHeader := rawdb.ReadHeader(db, ghash, 0) != nil
		if !hasGenesisHeader {
			return nil, ghash, nil, startup.DecisionErrorGenesisHeaderNotFound.ToError()
		}
		trustedOverride, err := deps.readChainConfigOverride(db, ghash)
		if err != nil {
			return nil, ghash, nil, err
		}
		if trustedOverride {
			if err := requireBuiltInCustomRecovery(ghash, opts.AllowBuiltInCustomRecovery); err != nil {
				return nil, ghash, nil, err
			}
		}
		missingConfigAction := decideSetupMissingConfigAction(ghash, hasGenesisHeader, trustedOverride, genesis != nil)
		if missingConfigAction.TerminalError != startup.DecisionErrorNone {
			return nil, ghash, nil, missingConfigAction.TerminalError.ToError()
		}
		genesis = selectMissingConfigGenesis(ghash, genesis)
		// Ensure the stored genesis block matches the supplied genesis. Bundled
		// networks may rebuild a missing chain-config blob from the bundled
		// genesis, but override-backed same-hash custom chains must provide a
		// matching explicit genesis instead of silently falling back.
		hash, err := deps.genesisHash(genesis)
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
			deps.writeChainConfig(db, ghash, newCfg)
			if builtin := builtInChainConfigByHash(ghash); builtin != nil {
				equal, err := deps.chainConfigJSONEqual(newCfg, builtin)
				if err != nil {
					return nil, common.Hash{}, nil, err
				}
				if !equal {
					deps.writeChainConfigOverride(db, ghash)
				}
			}
			return newCfg, ghash, nil, nil
		}
		block, err := genesis.commitWithDeps(db, true, true, deps)
		if err != nil {
			return nil, common.Hash{}, nil, err
		}
		return genesis.Config.Clone(), block.Hash(), nil, nil

	case setupGenesisPathStoredConfig:
		// Continue into stored-config reconciliation below.
	}

	storedCfg, err = resolveStoredChainConfig(ghash, storedCfg)
	if err != nil {
		return nil, ghash, nil, err
	}
	if err := expectStoredConfigHeaderAction(decideStoredConfigHeaderAction(db, ghash)); err != nil {
		return nil, ghash, nil, err
	}

	// The genesis block has already been committed previously. Verify that the
	// provided genesis with chain overrides matches the existing one, and update
	// the stored chain config if necessary.
	if genesis != nil {
		hash, err := deps.genesisHash(genesis)
		if err != nil {
			return nil, common.Hash{}, nil, err
		}
		if hash != ghash && originalGenesisHash != ghash {
			return nil, common.Hash{}, nil, &GenesisMismatchError{ghash, hash}
		}
	}

	// Check config compatibility and write the config. Compatibility errors
	// are returned to the caller unless we're already at block zero.
	head, err := loadStartupHead(db)
	if err != nil {
		if errors.Is(err, errMissingHeadHeaderNumber) {
			return storedCfg, ghash, nil, err
		}
		return nil, common.Hash{}, nil, err
	}
	genesis, overrideState, err := prepareSetupStoredConfigOverridesWithDeps(deps, db, ghash, storedCfg, genesis, originalGenesisHash, opts.AllowBuiltInCustomRecovery)
	if err != nil {
		return nil, common.Hash{}, nil, err
	}
	newCfg := genesis.chainConfigOrDefault(ghash, storedCfg, overrideState.trustedOverride)
	resolvedCfg, compatErr, err := resolveSetupStoredConfigResultWithDeps(deps, db, ghash, storedCfg, newCfg, genesis, head, overrideState)
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
//   - cfg: the resolved config (never nil on success)
//   - ghash: the canonical genesis block hash
//   - err: error if config is missing or invalid
func LoadChainConfig(db ethdb.Database, genesis *Genesis) (cfg *params.ChainConfig, ghash common.Hash, err error) {
	return loadChainConfigWithDeps(db, genesis, defaultGenesisDeps)
}

// loadChainConfigWithDeps preserves LoadChainConfig semantics with injectable dependencies.
func loadChainConfigWithDeps(db ethdb.Database, genesis *Genesis, deps genesisDeps) (cfg *params.ChainConfig, ghash common.Hash, err error) {
	cfg, ghash, _, err = loadChainConfigInternal(db, genesis, deps, GenesisStartupOptions{}, false)
	return cfg, ghash, err
}

// loadChainConfigInternal resolves the canonical chain config and optionally returns compat rewind metadata.
func loadChainConfigInternal(db ethdb.Database, genesis *Genesis, deps genesisDeps, opts GenesisStartupOptions, returnCompat bool) (cfg *params.ChainConfig, ghash common.Hash, compatErr *params.ConfigCompatError, err error) {
	defer func() {
		annotateResolvedCustomBuiltInConfigWithDeps(deps, ghash, cfg)
	}()

	// Copy the genesis so input hydration does not mutate the caller-provided object.
	genesis = genesis.copy()

	// Load the stored chain config from the database. It can be nil
	// in case the database is empty. Notably, we only care about the
	// chain config corresponds to the canonical chain.
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
		state, err := prepareLoadStoredConfigStateWithDeps(deps, db, stored, opts.AllowBuiltInCustomRecovery)
		if err != nil {
			return nil, stored, nil, err
		}
		cfg, err := resolveStoredChainConfig(stored, storedcfg)
		if err != nil {
			return nil, stored, nil, err
		}
		genesis, mismatchHash, err := normalizeProvidedGenesisForStoredConfigWithDeps(deps, stored, cfg, genesis, state.trustedOverride, opts.AllowBuiltInCustomRecovery)
		if err != nil {
			if mismatchHash != (common.Hash{}) {
				return nil, mismatchHash, nil, err
			}
			return nil, stored, nil, err
		}

		newCfg := genesis.chainConfigOrDefault(stored, cfg, state.trustedOverride)
		resolvedCfg, resolvedCompatErr, err := resolveLoadStoredConfigResultWithDeps(db, deps, stored, cfg, newCfg, state, genesis, returnCompat)
		if err != nil {
			return nil, stored, nil, err
		}
		return resolvedCfg, stored, resolvedCompatErr, nil

	case loadChainConfigPathStoredMissingConfigNoProvidedGenesis:
		resolvedCfg, err := resolveLoadStoredMissingConfigNoProvidedGenesisWithDeps(deps, db, stored, opts.AllowBuiltInCustomRecovery)
		if err != nil {
			return nil, stored, nil, err
		}
		return resolvedCfg, stored, nil, nil

	case loadChainConfigPathProvidedGenesis:
		resolvedCfg, resolvedHash, err := resolveLoadProvidedGenesisWithDeps(deps, db, stored, genesis, opts.AllowBuiltInCustomRecovery)
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
	return loadChainConfigWithCompatDeps(db, genesis, defaultGenesisDeps, GenesisStartupOptions{AllowBuiltInCustomRecovery: allowBuiltInCustomRecovery})
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

// resolveHeadCompatibleChainConfigWithDeps checks whether candidateCfg can be used at the current head.
func resolveHeadCompatibleChainConfigWithDeps(db ethdb.Database, storedCfg, candidateCfg *params.ChainConfig, trustedOverride bool, builtin *params.ChainConfig, deps genesisDeps) (*params.ChainConfig, *params.ConfigCompatError, error) {
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
		storedEqual, err := deps.chainConfigJSONEqual(storedCfg, builtin)
		if err != nil {
			return nil, nil, err
		}
		newEqual, err := deps.chainConfigJSONEqual(candidateCfg, builtin)
		if err != nil {
			return nil, nil, err
		}
		action := decideBuiltInChainConfigAction(builtInChainConfigFacts{
			hasBuiltInConfig:        true,
			trustedOverride:         trustedOverride,
			storedMatchesBuiltIn:    storedEqual,
			candidateMatchesBuiltIn: newEqual,
		})
		if action.terminalError == startup.DecisionErrorGenesisConfigConflict {
			return nil, nil, builtInGenesisConfigConflictError(rawdb.ReadCanonicalHash(db, 0))
		}
		if action.canonicalizeToBuiltIn {
			candidateCfg = builtin.Clone()
		}
	}
	return candidateCfg, nil, nil
}

// loadChainConfigWithCompatDeps resolves chain config like readonly startup and returns compat metadata.
func loadChainConfigWithCompatDeps(db ethdb.Database, genesis *Genesis, deps genesisDeps, opts GenesisStartupOptions) (cfg *params.ChainConfig, ghash common.Hash, compatErr *params.ConfigCompatError, err error) {
	return loadChainConfigInternal(db, genesis, deps, opts, true)
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
	return g.commitWithDeps(db, false, false, defaultGenesisDeps)
}

// commitWithDeps writes the genesis block, alloc, and resolved chain config to
// the database, optionally preserving a same-hash custom override instead of
// forcing a built-in genesis hash back to the bundled config. skipHydrate is
// only safe when the caller already normalized g.Config for this genesis hash.
// Callers use this internal helper when tests or setup paths need injected
// persistence deps.
func (g *Genesis) commitWithDeps(db ethdb.Database, allowCustomBuiltInConfig bool, skipHydrate bool, deps genesisDeps) (*types.Block, error) {
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
	deps.writeChainConfig(batch, block.Hash(), config)
	if allowCustomBuiltInConfig {
		if builtin := builtInChainConfigByHash(block.Hash()); builtin != nil {
			equal, err := deps.chainConfigJSONEqual(config, builtin)
			if err != nil {
				return nil, err
			}
			if !equal {
				deps.writeChainConfigOverride(batch, block.Hash())
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
		ExtraData:  hexutil.MustDecode("0x0000000000000000000000000000000000000000000000000000000000000000008661dde98c6106224ac8d5e0356d6fdbf3923101346a2d41542d859e03f461ca74a1ff2686884c02729a332e4e16e4f02ff8a416a2006f943e110a066711cbf42f9ead9fca8a27a12f5f11e10f3ed6081f1ab6bfe1e01900e15164a0fe34283d32671c0983ab0acc9c0107031e681d128811f056b4e4150aed5c578e40595111352111472ea1ba55b1aad90fe62f8436d88005e2d69f3caeba10a713cd02a811c8ee9b7383eee8cb7967c60c09f9f5b6aa499d12fe3a241c805a94fecf98e9f2eab7370fb1873715df6e75c7d1cb8af14049caca19ed207cfb98bf180a2d5371a78de6376fdd0b7113d4364976a98e1bfa7d6cc47cf4be7362a288a531d6c621c337602026f1a303c8931793ad4eb38c1f2d45a7076ec62280e7bd75984b8dd8314330fbedbaa48984b45122f69af9d2268dbd79536e12c7af4afb462eaedd258fedd147585f34c5b2897e21ff7f7551340303263f0892e3a8a70c7debc968f66f1f2caca535082686b03018b3b811ac1fb42dbc6b325255e0fad826d5f7bcc51afc06d4284969ab8757f3e689163c2c2884f6c107184a4b9721aa84e7a2e901c81c9e2cc7bd34266d54ccd6d89296f0b8bc99faefc3772d5271b9f4692c1e36a1a862bea311cb6705f5872e3f6d1c0598c2d54c69d4011effc480407230842e67af84716b566b177dcf22d5a1062871d832ec3058a76ce02c06d6ff370882fa96ff42b9aeb6ca32be73ad19e1003eb3ad225d9059522059e36f8932c6cfb950940906a0212ce200092841b7a96dd1334fe0c390ff84448b4be1eb797b22e7ea5162e83a71897dd5f257b8376e37612d41635e63c715543d1daacc23b64751c1114f985912ce2b292ee2753eadc9be2dbc465d3f435adc85c5768e7c973f493fa2e9cab94aa24d536f10c0341edec4b662d0c34968f17a784968f884e2e51057c6fbe992c19d044a76a959b27d1f8c2aaa9d448a92b93be32020204b042ef47e5b12e511d1097eb7cf2e2b21f433304b4cf8b8d730c8f1b90b260f030840e735fe143e4ed19e4e0b08ddc57368ba278be696ac92ed6ab74ed4aa631ef6d9c02ba707782c875d9c44f80a835180f7a3beba24f5f4d70ecaf238aeee127a056d527dbaef13ab0431463d84355b47c4b9e66b5af1565a8d0da480bbc7fee3ad5e17d4e6c5fec0b5b657267ea675c25d669b6529bbbec5cf7e9283a117587a573ddbd2729f60bd4ebc9fb855bcbfb5c9215ad2a5f826c5028d82466dbb9d2a8bb03f1d0a965b5e45373d2c8a7235e4d6c3835fc6a4d00ebd105e6c696185044ce4f35508c04a8c8b3d99857cca61ce0cbd9364ee68e5336286387f2070e6abf69c6356862749cf11ed9b900228937a0172100ddb6563f915e663857b8a9f6a7a0e50cfe148fe310cc565a01d5808f1b0050702c49f150ae55137f90a7d67655cc7b49f4a33330249b82172961275604ef4685008ff89f3b10a85fa57b2accbca976603e7026969067dc17d6a6e5ce5939ab823072961e3b2f06afb44e2268e9ec27e73ebe0c11f79aa83de76fc6b77d1702ae1395c62a4368f7e8af39c02e799c96e851e2a96d094827470d0cf75362028527f3a0b71141ee85dc573b1a8a6eeae8dcc75a8e9d632b0782ffa5fdfb86c95fb891cec0bcd76413a9f38c178cbe4bc26aca957c439e20dc93fb5a9b2def5807974725114d48b6df7a2eb8b9f320addd4a732087e34d797f211ed1343ff9b5a8ff42fa0f3360d018013f4f2ae62c66416e4e0c8e95f0c8f0d1ad2e6830fb3711887f1f3b248c75bacaffe4e5f7fcdb289f5398bc06a32b84df3a2b9168aa6baf44110e88d13512e552e2032662fc8e910992f82a4493863917c67a7670441c22a16f47e85fb217312d6ca7893727b60f3e372bbfd6fdd076cf26e2e739ac737989e2807357ed613456af5d0b0a4c1a95594ba639def92fc6c55f98d09143d067998754237168365a08cc01242805ff9bcff7e46c14f8b454efaf0b1a5824fbc2b2db519039bb6ef9d6ab94110499a88ab8218ace9a7ef792c7527c226edc2183b3644d9abafbb0dce2fe4045ca90c06688201b8d08dafb7acb6efd260247cc56dc5aec68be725279c628f92ace6f5e22342b6d8e2c3f84b4d849bc1462bb173ad579fe5042a3e8d24b32499e80ee2bf5ed151fcae07b743487735e11d3b23bfb92475e90666f10bb0103109820e4907a277bc5492b09f502653308db25d2672ef54675df6a3159502f773c499498655b4210783b2cdf2ea5c878804c1948e94a5b6168cb5805efb3644b56a83569aa233f1a7f61255e247bd268f078c918db93dbce96e3d903dcb0f5f6378be25fe68a64e205de647c9116fc52c53432aba32c0772e0de9829847800de5e88936570c09ce7263c1a9f8f77b0afc5eadc2dc78106879eb3126bc62c205f666038daba72abcd4d23d77e9c774fdebaac34a3cd97fb1bb894f525d1a1f3ea18c592a3b08c3cb578638427389b7c6402d0b1a8de3e89a9b7bc6379a39caf697b91b3e4ea9a227bb940f70d96dc74d1b890db7eddb783b2f7e5dd3f010739df8e1c7c93c8aeaffea97e868168b8c3d754463e6d737c825253cad4cbf989201d7bd369fef887309c1b2cb1269432a080dbcff8053d7759e0c4962bec94dcdff7f7ec050b7a413626289a35616c0bc67a1e9ce49f6ea69bb0237303f90cbeb28a9665415b7cfcfb43f059e39456b29facabded44684cac35b04fd02310501c429f631b3097a4a0da84054a46cfecd483d3c52ebf10d94bca3c97ecfcfca88db84123d881cd6291e5463cbf200f90b9027c303cd84ba1d9b1d9d839d2218a5d313f27344cb7d8a3f1d95ddb83be484441c73848667000e5ce4001aec09d9bdde8431deb1004fbc35c579fd4f51b4c89f571e6de080a32c22019427b55e0326245a4bbe98544bfdf5d49f8477df0a9dbc7e0c6b2dc87e65b87b88ee07ba33902c8678108bd1fb2c79eb5863971f9f3e0cf647a85205c87d1352e19b28c37cfc6de8c33e1c427f8bf873e0bf5195bf78fd7b38ba0c4ced8e3c3c3febd671dc0e0ad3371366d968de46c4024e53e0f04360b4313173a5f266866fd248f94fec0e71ac88ffaf8d4c7b4d63f56a8859fa6f9f8ab85e901cc3175a3749c2d27c6bc051ca7c978626c43e9315c6c526c6acb478c0921fd28bbaa0a64b4c3ea5be13349f0bef623a40a74c3dda20c2c574a5eeabe066c8a4ac6fa52d70e0048ee5cadaa950736ed9221649af1eddbb6210fbc9ed713a757d6b096ee083522d9aad8938dfa7c260c10c9a29d7805b4f0c3bff6dd2e5ef97242ffc54d38be859c3a71b5f843965289b35dc11ce2873636b467bb3fafb699fa80871e330ca3ddb306bd5e6adb972f3303d96cfc1c194f8716d41709fbfe3acfb634c4b25939ddfe3424efa8ed03eae9a2bf4d001692abc1807a6cfe56bae25b109e61e5026b5e4e62c865fc6470f9ff7bb7db2ceb6cc08f718bcba954915bf1774df1fff2331a010cba90682763172b19f57f27831ac70000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
		GasLimit:   4700000,
		Difficulty: big.NewInt(1),
		Alloc:      DecodeAllocJson(DevnetAllocData),
		Timestamp:  1765137783,
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

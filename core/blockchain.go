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

// Package core implements the Ethereum consensus protocol.
package core

import (
	"errors"
	"fmt"
	"io"
	"math/big"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/XinFinOrg/XDPoSChain/XDCx/tradingstate"
	"github.com/XinFinOrg/XDPoSChain/XDCxlending/lendingstate"
	"github.com/XinFinOrg/XDPoSChain/accounts/abi/bind"
	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/common/lru"
	"github.com/XinFinOrg/XDPoSChain/common/mclock"
	"github.com/XinFinOrg/XDPoSChain/common/prque"
	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS/engines/engine_v2"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS/utils"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/tracing"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/ethclient"
	"github.com/XinFinOrg/XDPoSChain/ethdb"
	"github.com/XinFinOrg/XDPoSChain/event"
	"github.com/XinFinOrg/XDPoSChain/internal/syncx"
	internalversion "github.com/XinFinOrg/XDPoSChain/internal/version"
	"github.com/XinFinOrg/XDPoSChain/log"
	"github.com/XinFinOrg/XDPoSChain/metrics"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/XinFinOrg/XDPoSChain/rlp"
	"github.com/XinFinOrg/XDPoSChain/trie"
)

var (
	headBlockGauge     = metrics.NewRegisteredGauge("chain/head/block", nil)
	headHeaderGauge    = metrics.NewRegisteredGauge("chain/head/header", nil)
	headFastBlockGauge = metrics.NewRegisteredGauge("chain/head/receipt", nil)

	chainInfoGauge = metrics.NewRegisteredGaugeInfo("chain/info", nil)

	accountReadTimer   = metrics.NewRegisteredResettingTimer("chain/account/reads", nil)
	accountHashTimer   = metrics.NewRegisteredResettingTimer("chain/account/hashes", nil)
	accountUpdateTimer = metrics.NewRegisteredResettingTimer("chain/account/updates", nil)
	accountCommitTimer = metrics.NewRegisteredResettingTimer("chain/account/commits", nil)

	storageReadTimer   = metrics.NewRegisteredResettingTimer("chain/storage/reads", nil)
	storageHashTimer   = metrics.NewRegisteredResettingTimer("chain/storage/hashes", nil)
	storageUpdateTimer = metrics.NewRegisteredResettingTimer("chain/storage/updates", nil)
	storageCommitTimer = metrics.NewRegisteredResettingTimer("chain/storage/commits", nil)

	triedbCommitTimer = metrics.NewRegisteredTimer("chain/triedb/commits", nil)

	blockInsertTimer     = metrics.NewRegisteredResettingTimer("chain/inserts", nil)
	blockValidationTimer = metrics.NewRegisteredResettingTimer("chain/validation", nil)
	blockExecutionTimer  = metrics.NewRegisteredResettingTimer("chain/execution", nil)
	blockWriteTimer      = metrics.NewRegisteredResettingTimer("chain/write", nil)

	blockReorgMeter     = metrics.NewRegisteredMeter("chain/reorg/executes", nil)
	blockReorgAddMeter  = metrics.NewRegisteredMeter("chain/reorg/add", nil)
	blockReorgDropMeter = metrics.NewRegisteredMeter("chain/reorg/drop", nil)

	blockPrefetchExecuteTimer   = metrics.NewRegisteredTimer("chain/prefetch/executes", nil)
	blockPrefetchInterruptMeter = metrics.NewRegisteredMeter("chain/prefetch/interrupts", nil)

	// Known blocks above the head that were not adopted because they do not beat it: the
	// batch reports success without importing anything, so this is the only count of it (see
	// writeKnownBlock and the prefix adoption of insertSideChain).
	blockKnownNotAdoptedMeter = metrics.NewRegisteredMeter("chain/knownblocks/notadopted", nil)

	// ErrInsertionInterrupted is returned when the chain is terminating or an import was cut
	// short by InterruptInsert. Local - see IsLocalInsertError.
	ErrInsertionInterrupted = errors.New("insertion is interrupted")

	// ErrChainStopped is returned once the chain has been stopped. chainmu is a ClosableMutex,
	// so TryLock waits for another insertion and reports the stopped chain only after Stop
	// closed it. Local - see IsLocalInsertError.
	ErrChainStopped = errors.New("blockchain is stopped")

	// ErrLocalInsertCondition keeps the local conditions that have no sentinel of their own
	// and that a retry cannot repair: a receipt batch the database refused to write, and a
	// stored block whose total difficulty this node no longer holds. insertSideChain raises it
	// too, as a defensive guard for a segment that stops on a block with no stored state - a
	// state the validator contract rules out, see the note there. A block dated ahead of the
	// clock is the one local condition that heals, which is why it carries a sentinel of its
	// own below. See IsLocalInsertError for why callers must not treat it as a consensus
	// failure.
	ErrLocalInsertCondition = errors.New("local insert condition")

	// ErrLocalInsertAheadOfClock is the local condition that heals on its own: the block is
	// dated further ahead of the clock than the future queue may hold, so the queueing fails
	// rather than the block, and a retry once the clock catches up succeeds. Retryable, unlike
	// ErrLocalInsertCondition, so a parked block that failed for this stays parked instead of
	// being evicted on the first tick. insertSideChain wraps consensus.ErrFutureBlock in it.
	ErrLocalInsertAheadOfClock = errors.New("local insert condition: block ahead of this node's clock")

	// ErrLocalInsertRefused is the local condition that cannot heal: this node refused a reorg
	// while adopting a stored block, and refuses it again each time, since the head does not
	// move and the block keeps winning fork choice. Kept apart from ErrLocalInsertCondition
	// because a refusal is a verdict this node reached, not a record it is missing.
	ErrLocalInsertRefused = errors.New("local insert refused")

	errInvalidOldChain = errors.New("invalid old chain")
	errInvalidNewChain = errors.New("invalid new chain")

	// CheckpointCh carries the "an epoch switch block reached the head" signal to the staking
	// loop in cmd/XDC. Every sender goes through SignalCheckpoint, which never waits: the
	// buffer absorbs one pending signal, and a second arriving before it drains is dropped,
	// because the pending one re-reads the head when it is handled and nothing is lost.
	//
	// Sending directly would block the caller, which none of these senders can afford: the
	// import paths and reorg run with the chain mutex held.
	CheckpointCh = make(chan int, 1)
)

const (
	bodyCacheLimit      = 256
	blockCacheLimit     = 256
	receiptsCacheLimit  = 32
	maxFutureBlocks     = 256
	maxTimeFutureBlocks = 30
	TriesInMemory       = 1024

	// BlockChainVersion ensures that an incompatible database forces a resync from scratch.
	//
	// Changelog:
	//
	// - Version 4
	//   The following incompatible database changes were added:
	//   * the `BlockNumber`, `TxHash`, `TxIndex`, `BlockHash` and `Index` fields of log are deleted
	//   * the `Bloom` field of receipt is deleted
	//   * the `BlockIndex` and `TxIndex` fields of txlookup are deleted
	// - Version 5
	//  The following incompatible database changes were added:
	//    * the `TxHash`, `GasCost`, and `ContractAddress` fields are no longer stored for a receipt
	//    * the `TxHash`, `GasCost`, and `ContractAddress` fields are computed by looking up the
	//      receipts' corresponding block
	// - Version 6
	//  The following incompatible database changes were added:
	//    * Transaction lookup information stores the corresponding block number instead of block hash
	// - Version 7
	//  The following incompatible database changes were added:
	//    * New scheme for contract code in order to separate the codes and trie nodes
	BlockChainVersion uint64 = 7

	// Maximum length of chain to cache by block's number
	blocksHashCacheLimit = 900
)

// CacheConfig contains the configuration values for the trie database
// that's resident in a blockchain.
type CacheConfig struct {
	TrieCleanLimit    int           // Memory allowance (MB) to use for caching trie nodes in memory
	TrieCleanPrefetch bool          // Whether to enable heuristic state prefetching for followup blocks
	TrieDirtyLimit    int           // Memory limit (MB) at which to start flushing dirty trie nodes to disk
	TrieDirtyDisabled bool          // Whether to disable trie write caching and GC altogether (archive node)
	TrieTimeLimit     time.Duration // Time limit after which to flush the current in-memory trie to disk
	Preimages         bool          // Whether to store preimage of trie key to the disk
}

type ResultProcessBlock struct {
	logs         []*types.Log
	receipts     []*types.Receipt
	state        *state.StateDB
	tradingState *tradingstate.TradingStateDB
	lendingState *lendingstate.LendingStateDB
	proctime     time.Duration
	usedGas      uint64
}

// BlockChain represents the canonical chain given a database with a genesis
// block. The Blockchain manages chain imports, reverts, chain reorganisations.
//
// Importing blocks in to the block chain happens according to the set of rules
// defined by the two stage Validator. Processing of blocks is done using the
// Processor which processes the included transaction. The validation of the state
// is done in the second part of the Validator. Failing results in aborting of
// the import.
//
// The BlockChain also helps in returning blocks from **any** chain included
// in the database as well as blocks that represents the canonical chain. It's
// important to note that GetBlock can return any block and does not need to be
// included in the canonical one where as GetBlockByNumber always represents the
// canonical chain.
type BlockChain struct {
	chainConfig *params.ChainConfig // Chain & network configuration
	cacheConfig *CacheConfig        // Cache configuration for pruning

	db         ethdb.Database                   // Low level persistent database to store final content in
	XDCxDb     ethdb.XDCxDatabase               // XDCx database
	triegc     *prque.Prque[int64, common.Hash] // Priority queue mapping block numbers to tries to gc
	gcproc     time.Duration                    // Accumulates canonical block processing for trie dumping
	triedb     *trie.Database                   // The database handler for maintaining trie nodes.
	stateCache state.Database                   // State database to reuse between imports (contains state cache)

	hc            *HeaderChain
	rmLogsFeed    event.Feed
	chainFeed     event.Feed
	chainSideFeed event.Feed
	chainHeadFeed event.Feed
	logsFeed      event.Feed
	scope         event.SubscriptionScope
	genesisBlock  *types.Block

	// This mutex synchronizes chain write operations.
	// Readers don't need to take it, they can just read the database.
	chainmu *syncx.ClosableMutex

	currentBlock     atomic.Pointer[types.Header] // Current head of the chain
	currentSnapBlock atomic.Pointer[types.Header] // Current head of snap-sync

	bodyCache        *lru.Cache[common.Hash, *types.Body]         // Cache for the most recent block bodies
	bodyRLPCache     *lru.Cache[common.Hash, rlp.RawValue]        // Cache for the most recent block bodies in RLP encoded format
	receiptsCache    *lru.Cache[common.Hash, types.Receipts]      // Cache for the most recent block receipts
	blockCache       *lru.Cache[common.Hash, *types.Block]        // Cache for the most recent entire blocks
	resultProcess    *lru.Cache[common.Hash, *ResultProcessBlock] // Cache for processed blocks
	calculatingBlock *lru.Cache[common.Hash, *CalculatedBlock]    // Cache for processing blocks
	downloadingBlock *lru.Cache[common.Hash, struct{}]            // Cache for downloading blocks (avoid duplication from fetcher)

	// future blocks are blocks added for later processing
	futureBlocks *lru.Cache[common.Hash, *types.Block]

	wg            sync.WaitGroup
	quit          chan struct{} // shutdown signal, closed in Stop.
	stopping      atomic.Bool   // false if chain is running, true when stopped
	procInterrupt atomic.Bool   // interrupt signaler for block processing

	engine     consensus.Engine
	validator  Validator  // Block and state validator interface
	prefetcher Prefetcher // Block state prefetcher interface
	processor  Processor  // Block transaction processor interface
	vmConfig   vm.Config
	logger     *tracing.Hooks

	IPCEndpoint string
	Client      bind.ContractBackend // Global ipc client instance.

	// Blocks hash array by block number
	// cache field for tracking finality purpose, can't use for tracking block vs block relationship
	blocksHashCache *lru.Cache[uint64, []common.Hash]

	resultTrade         *lru.Cache[common.Hash, interface{}] // trades result: key - takerOrderHash, value: trades corresponding to takerOrder
	rejectedOrders      *lru.Cache[common.Hash, interface{}] // rejected orders: key - takerOrderHash, value: rejected orders corresponding to takerOrder
	resultLendingTrade  *lru.Cache[common.Hash, interface{}]
	rejectedLendingItem *lru.Cache[common.Hash, interface{}]
	finalizedTrade      *lru.Cache[common.Hash, interface{}] // include both trades which force update to closed/liquidated by the protocol
}

type blockchainOpenConfig struct {
	readOnly        bool
	chainConfig     *params.ChainConfig
	genesisHash     common.Hash
	compatErr       *params.ConfigCompatError
	compatPolicy    ChainConfigMismatchPolicy
	recoveryGenesis *Genesis
}

// recoveryGenesisConfigMismatch reports whether recovery genesis carries a
// different config than the resolved startup config that will be used instead.
func recoveryGenesisConfigMismatch(genesis *Genesis, chainConfig *params.ChainConfig) (bool, error) {
	return recoveryGenesisConfigMismatchWith(genesis, chainConfig, chainConfigJSONEqual)
}

func recoveryGenesisConfigMismatchWith(genesis *Genesis, chainConfig *params.ChainConfig, compare func(a, b *params.ChainConfig) (bool, error)) (bool, error) {
	if genesis == nil || genesis.Config == nil || chainConfig == nil {
		return false, nil
	}
	equal, err := compare(genesis.Config, chainConfig)
	if err != nil {
		return false, fmt.Errorf("failed to compare RecoveryGenesis config with resolved chain config: %w", err)
	}
	return !equal, nil
}

// normalizedRecoveryGenesis clones genesis and replaces its config with the
// resolved chainConfig.
func normalizedRecoveryGenesis(genesis *Genesis, chainConfig *params.ChainConfig) (*Genesis, error) {
	return normalizedRecoveryGenesisWith(genesis, chainConfig, chainConfigJSONEqual)
}

func normalizedRecoveryGenesisWith(genesis *Genesis, chainConfig *params.ChainConfig, compare func(a, b *params.ChainConfig) (bool, error)) (*Genesis, error) {
	if genesis == nil {
		return nil, nil
	}
	mismatch, err := recoveryGenesisConfigMismatchWith(genesis, chainConfig, compare)
	if err != nil {
		return nil, err
	}
	if mismatch {
		log.Warn("Ignoring RecoveryGenesis config in favor of resolved chain config")
	}
	normalized := genesis.copy()
	if chainConfig != nil {
		normalized.Config = chainConfig.Clone()
	}
	return normalized, nil
}

var (
	// ErrReadOnlyGenesisStateRecovery reports that opening the chain in readonly
	// mode would require mutating the database to restore missing genesis state.
	// This includes custom chains whose genesis alloc can only be recovered from
	// a caller-provided matching genesis during writable startup.
	ErrReadOnlyGenesisStateRecovery     = errors.New("readonly blockchain open requires genesis state recovery")
	ErrReadOnlyHeadStateRepair          = errors.New("readonly blockchain open requires head state repair")
	ErrReadOnlyBadHashRewind            = errors.New("readonly blockchain open requires bad-hash rewind")
	ErrReadOnlyConfigRewind             = errors.New("readonly blockchain open requires config rewind")
	ErrReadOnlyConfigUpdate             = errors.New("readonly blockchain open requires config update")
	ErrConfigMismatchPolicyExit         = errors.New("chain config mismatch policy is exit")
	errBlockChainOpenMissingGenesisHash = errors.New("blockchain open options require genesis hash when chain config is provided")
)

// NewBlockChain returns a fully initialised writable block chain using startup
// metadata resolved from the database via SetupGenesisBlock.
func NewBlockChain(db ethdb.Database, cacheConfig *CacheConfig, genesis *Genesis, engine consensus.Engine, vmConfig vm.Config) (*BlockChain, error) {
	resolvedCfg, err := resolveBlockChainOpenConfig(db, genesis, false, DefaultChainConfigMismatchPolicy)
	if err != nil {
		return nil, err
	}
	return newBlockChain(db, cacheConfig, engine, vmConfig, resolvedCfg)
}

// NewBlockChainReadOnly returns a fully initialised readonly block chain using
// startup metadata resolved from the database via LoadChainConfigWithCompat.
func NewBlockChainReadOnly(db ethdb.Database, cacheConfig *CacheConfig, genesis *Genesis, engine consensus.Engine, vmConfig vm.Config) (*BlockChain, error) {
	resolvedCfg, err := resolveBlockChainOpenConfig(db, genesis, true, DefaultChainConfigMismatchPolicy)
	if err != nil {
		return nil, err
	}
	return newBlockChain(db, cacheConfig, engine, vmConfig, resolvedCfg)
}

// NewBlockChainResolved opens a writable block chain from caller-supplied
// startup metadata.
func NewBlockChainResolved(db ethdb.Database, cacheConfig *CacheConfig, recoveryGenesis *Genesis, engine consensus.Engine, vmConfig vm.Config, chainConfig *params.ChainConfig, genesisHash common.Hash, compatErr *params.ConfigCompatError, compatPolicy ChainConfigMismatchPolicy) (*BlockChain, error) {
	resolvedCfg, err := newResolvedBlockChainOpenConfig(false, recoveryGenesis, chainConfig, genesisHash, compatErr, compatPolicy)
	if err != nil {
		return nil, err
	}
	return newBlockChain(db, cacheConfig, engine, vmConfig, resolvedCfg)
}

// NewBlockChainReadOnlyResolved opens a readonly block chain from caller-
// supplied startup metadata.
func NewBlockChainReadOnlyResolved(db ethdb.Database, cacheConfig *CacheConfig, recoveryGenesis *Genesis, engine consensus.Engine, vmConfig vm.Config, chainConfig *params.ChainConfig, genesisHash common.Hash, compatErr *params.ConfigCompatError, compatPolicy ChainConfigMismatchPolicy) (*BlockChain, error) {
	resolvedCfg, err := newResolvedBlockChainOpenConfig(true, recoveryGenesis, chainConfig, genesisHash, compatErr, compatPolicy)
	if err != nil {
		return nil, err
	}
	return newBlockChain(db, cacheConfig, engine, vmConfig, resolvedCfg)
}

// resolveBlockChainOpenConfig resolves startup metadata and normalizes
// recovery inputs for writable or readonly opens.
func resolveBlockChainOpenConfig(db ethdb.Database, genesis *Genesis, readOnly bool, compatPolicy ChainConfigMismatchPolicy) (blockchainOpenConfig, error) {
	resolveStartup := SetupGenesisBlock
	if readOnly {
		resolveStartup = LoadChainConfigWithCompat
	}
	chainConfig, genesisHash, compatErr, err := resolveStartup(db, genesis)
	if err != nil {
		return blockchainOpenConfig{}, err
	}
	normalizedCompatPolicy, err := ValidateAndNormalizeCompatPolicy(compatPolicy)
	if err != nil {
		return blockchainOpenConfig{}, err
	}
	if compatErr != nil && normalizedCompatPolicy == MismatchExit {
		return blockchainOpenConfig{}, fmt.Errorf("%w: %v", ErrConfigMismatchPolicyExit, compatErr)
	}
	resolved := blockchainOpenConfig{
		readOnly:        readOnly,
		chainConfig:     chainConfig,
		genesisHash:     genesisHash,
		compatErr:       compatErr,
		compatPolicy:    normalizedCompatPolicy,
		recoveryGenesis: genesis,
	}
	resolved.recoveryGenesis, err = normalizedRecoveryGenesis(resolved.recoveryGenesis, chainConfig)
	if err != nil {
		return blockchainOpenConfig{}, err
	}
	return resolved, nil
}

func newResolvedBlockChainOpenConfig(readOnly bool, recoveryGenesis *Genesis, chainConfig *params.ChainConfig, genesisHash common.Hash, compatErr *params.ConfigCompatError, compatPolicy ChainConfigMismatchPolicy) (blockchainOpenConfig, error) {
	if genesisHash == (common.Hash{}) {
		return blockchainOpenConfig{}, errBlockChainOpenMissingGenesisHash
	}
	normalizedCompatPolicy, err := ValidateAndNormalizeCompatPolicy(compatPolicy)
	if err != nil {
		return blockchainOpenConfig{}, err
	}
	if compatErr != nil && normalizedCompatPolicy == MismatchExit {
		return blockchainOpenConfig{}, fmt.Errorf("%w: %v", ErrConfigMismatchPolicyExit, compatErr)
	}
	normalizedGenesis, err := normalizedRecoveryGenesis(recoveryGenesis, chainConfig)
	if err != nil {
		return blockchainOpenConfig{}, err
	}
	return blockchainOpenConfig{
		readOnly:        readOnly,
		chainConfig:     chainConfig,
		genesisHash:     genesisHash,
		compatErr:       compatErr,
		compatPolicy:    normalizedCompatPolicy,
		recoveryGenesis: normalizedGenesis,
	}, nil
}

// newBlockChain opens a blockchain from already resolved startup metadata,
// optionally applying startup repairs or compatibility rewind work based on cfg.
func newBlockChain(db ethdb.Database, cacheConfig *CacheConfig, engine consensus.Engine, vmConfig vm.Config, cfg blockchainOpenConfig) (*BlockChain, error) {
	var err error
	chainConfig := cfg.chainConfig
	if chainConfig == nil {
		return nil, errors.New("nil chain config returned from SetupGenesisBlock")
	}
	genesisHash := cfg.genesisHash
	compatErr := cfg.compatErr
	compatPolicy := cfg.compatPolicy
	log.Info(strings.Repeat("-", 153))
	for line := range strings.SplitSeq(chainConfig.Description(), "\n") {
		log.Info(line)
	}
	log.Info(strings.Repeat("-", 153))

	if cacheConfig == nil {
		cacheConfig = &CacheConfig{
			TrieCleanLimit: 256,
			TrieDirtyLimit: 256,
			TrieTimeLimit:  5 * time.Minute,
		}
	}

	// Open trie database with provided config
	triedb := trie.NewDatabaseWithConfig(db, &trie.Config{
		Cache:     cacheConfig.TrieCleanLimit,
		Preimages: cacheConfig.Preimages,
	})
	bc := &BlockChain{
		chainConfig: chainConfig,
		cacheConfig: cacheConfig,
		db:          db,
		triedb:      triedb,
		triegc:      prque.New[int64, common.Hash](nil),
		stateCache: state.NewDatabaseWithConfig(db, &trie.Config{
			Cache:     cacheConfig.TrieCleanLimit,
			Preimages: cacheConfig.Preimages,
		}),
		quit:                make(chan struct{}),
		chainmu:             syncx.NewClosableMutex(),
		bodyCache:           lru.NewCache[common.Hash, *types.Body](bodyCacheLimit),
		bodyRLPCache:        lru.NewCache[common.Hash, rlp.RawValue](bodyCacheLimit),
		receiptsCache:       lru.NewCache[common.Hash, types.Receipts](receiptsCacheLimit),
		blockCache:          lru.NewCache[common.Hash, *types.Block](blockCacheLimit),
		futureBlocks:        lru.NewCache[common.Hash, *types.Block](maxFutureBlocks),
		resultProcess:       lru.NewCache[common.Hash, *ResultProcessBlock](blockCacheLimit),
		calculatingBlock:    lru.NewCache[common.Hash, *CalculatedBlock](blockCacheLimit),
		downloadingBlock:    lru.NewCache[common.Hash, struct{}](blockCacheLimit),
		engine:              engine,
		vmConfig:            vmConfig,
		logger:              vmConfig.Tracer,
		blocksHashCache:     lru.NewCache[uint64, []common.Hash](blocksHashCacheLimit),
		resultTrade:         lru.NewCache[common.Hash, interface{}](tradingstate.OrderCacheLimit),
		rejectedOrders:      lru.NewCache[common.Hash, interface{}](tradingstate.OrderCacheLimit),
		resultLendingTrade:  lru.NewCache[common.Hash, interface{}](tradingstate.OrderCacheLimit),
		rejectedLendingItem: lru.NewCache[common.Hash, interface{}](tradingstate.OrderCacheLimit),
		finalizedTrade:      lru.NewCache[common.Hash, interface{}](tradingstate.OrderCacheLimit),
	}
	bc.stateCache = state.NewDatabaseWithNodeDB(bc.db, bc.triedb)
	bc.validator = NewBlockValidator(chainConfig, bc, engine)
	bc.prefetcher = newStatePrefetcher(chainConfig, bc, engine)
	bc.processor = NewStateProcessor(chainConfig, bc, engine)

	bc.hc, err = NewHeaderChain(db, chainConfig, engine, bc.insertStopped)
	if err != nil {
		return nil, err
	}
	bc.genesisBlock = bc.GetBlockByNumber(0)
	if bc.genesisBlock == nil {
		return nil, ErrNoGenesis
	}

	bc.currentBlock.Store(nil)
	bc.currentSnapBlock.Store(nil)

	// Update chain info data metrics
	chainInfoGauge.Update(metrics.GaugeInfoValue{"chain_id": bc.chainConfig.ChainID.String()})

	// Load blockchain state from disk.
	if err := bc.loadLastState(); err != nil {
		return nil, err
	}
	// Make sure the state associated with the block is available.
	head := bc.CurrentBlock()
	if head == nil {
		return nil, errors.New("current block not set after loading chain state")
	}
	if !bc.HasState(head.Root) {
		headBlock := bc.GetBlock(head.Hash(), head.Number.Uint64())
		if headBlock == nil {
			return nil, fmt.Errorf("current block missing: #%d [%x..]", head.Number.Uint64(), head.Hash().Bytes()[:4])
		}
		if head.Number.Uint64() == 0 {
			// Unlike geth, XDPoSChain persists the genesis alloc and can rebuild
			// the genesis state locally instead of waiting for an external sync.
			if cfg.readOnly {
				return nil, fmt.Errorf("%w: hash %s", ErrReadOnlyGenesisStateRecovery, head.Hash())
			}
			log.Info("Genesis state is missing, restoring from stored alloc", "hash", head.Hash())
			if err := restoreGenesisState(bc.db, headBlock, cfg.recoveryGenesis); err != nil {
				return nil, err
			}
			if !bc.HasState(head.Root) {
				return nil, fmt.Errorf("genesis state recovery did not restore root %s", head.Root.Hex())
			}
		} else {
			if cfg.readOnly {
				return nil, fmt.Errorf("%w: number %d hash %s", ErrReadOnlyHeadStateRepair, head.Number.Uint64(), head.Hash())
			}
			log.Warn("Head state missing, repairing", "number", head.Number, "hash", head.Hash())
			if err := bc.repair(&headBlock); err != nil {
				return nil, err
			}
			rawdb.WriteHeadHeaderHash(bc.db, headBlock.Hash())
			bc.hc.SetCurrentHeader(headBlock.Header())
			rawdb.WriteHeadFastBlockHash(bc.db, headBlock.Hash())
			bc.currentSnapBlock.Store(headBlock.Header())
			headFastBlockGauge.Update(int64(headBlock.NumberU64()))
			rawdb.WriteHeadBlockHash(bc.db, headBlock.Hash())
			bc.currentBlock.Store(headBlock.Header())
			headBlockGauge.Update(int64(headBlock.NumberU64()))
		}
	}

	// Check the current state of the block hashes and make sure that we do not have any of the bad blocks in our chain
	for hash := range BadHashes {
		if header := bc.GetHeaderByHash(hash); header != nil {
			// get the canonical block corresponding to the offending header's number
			headerByNumber := bc.GetHeaderByNumber(header.Number.Uint64())
			// make sure the headerByNumber (if present) is in our current canonical chain
			if headerByNumber != nil && headerByNumber.Hash() == header.Hash() {
				if cfg.readOnly {
					return nil, fmt.Errorf("%w: number %d hash %s", ErrReadOnlyBadHashRewind, header.Number.Uint64(), header.Hash())
				}
				log.Error("Found bad hash, rewinding chain", "number", header.Number, "hash", header.ParentHash)
				bc.SetHead(header.Number.Uint64() - 1)
				log.Error("Chain rewind was successful, resuming normal operation")
			}
		}
	}

	if bc.logger != nil && bc.logger.OnBlockchainInit != nil {
		bc.logger.OnBlockchainInit(chainConfig)
	}

	if bc.logger != nil && bc.logger.OnGenesisBlock != nil {
		block := bc.CurrentBlock()
		if block == nil {
			return nil, errors.New("live blockchain tracer requires current block to be set")
		}
		if block.Number != nil && block.Number.Sign() == 0 {
			alloc, err := getGenesisState(bc.db, block.Hash(), cfg.recoveryGenesis, recoveryDisabled)
			if err != nil {
				if errors.Is(err, ErrGenesisAllocUnavailable) {
					return nil, wrapGenesisAllocUnavailable("live blockchain tracer requires genesis alloc to be set", block.Hash())
				}
				return nil, fmt.Errorf("live blockchain tracer requires genesis alloc to be set: %w", err)
			}
			bc.logger.OnGenesisBlock(bc.genesisBlock, alloc)
		}
	}

	// Rewind the chain in case of an incompatible config upgrade.
	// NOTE: MismatchExit is handled in resolveBlockChainOpenConfig /
	// newResolvedBlockChainOpenConfig before any chain state is touched,
	// so it never reaches here.
	if compatErr != nil {
		log.Warn("Mismatched chain config", "err", compatErr)
		switch compatPolicy {
		case MismatchRewindAndUpdate:
			if cfg.readOnly {
				return nil, fmt.Errorf("%w: %v", ErrReadOnlyConfigRewind, compatErr)
			}
			log.Warn("Applying chain config mismatch policy", "policy", compatPolicy, "rewind_to", compatErr.RewindTo, "update_config", true)
			if err := bc.SetHead(compatErr.RewindTo); err != nil {
				return nil, fmt.Errorf("failed to rewind chain: %w", err)
			}
			rawdb.WriteChainConfig(db, genesisHash, chainConfig)
		case MismatchUpdateConfigOnly:
			if cfg.readOnly {
				return nil, fmt.Errorf("%w: %v", ErrReadOnlyConfigUpdate, compatErr)
			}
			log.Warn("Applying chain config mismatch policy", "policy", compatPolicy, "rewind", false, "update_config", true)
			rawdb.WriteChainConfig(db, genesisHash, chainConfig)
		case MismatchIgnoreMismatch:
			log.Warn("Applying chain config mismatch policy", "policy", compatPolicy, "rewind", false, "update_config", false)
		default:
			return nil, fmt.Errorf("invalid chain config mismatch policy %q", compatPolicy)
		}
	}

	// Start future block processor.
	bc.wg.Go(bc.futureBlocksLoop)

	return bc, nil
}

// NewBlockChainEx extend old blockchain, add order state db
func NewBlockChainEx(db ethdb.Database, XDCxDb ethdb.XDCxDatabase, cacheConfig *CacheConfig, genesis *Genesis, engine consensus.Engine, vmConfig vm.Config) (*BlockChain, error) {
	blockchain, err := NewBlockChain(db, cacheConfig, genesis, engine, vmConfig)
	if err != nil {
		return nil, err
	}
	if blockchain != nil {
		blockchain.addXDCxDb(XDCxDb)
	}
	return blockchain, nil
}

// NewBlockChainExReadOnly opens an XDCx-aware readonly blockchain.
func NewBlockChainExReadOnly(db ethdb.Database, XDCxDb ethdb.XDCxDatabase, cacheConfig *CacheConfig, genesis *Genesis, engine consensus.Engine, vmConfig vm.Config) (*BlockChain, error) {
	blockchain, err := NewBlockChainReadOnly(db, cacheConfig, genesis, engine, vmConfig)
	if err != nil {
		return nil, err
	}
	if blockchain != nil {
		blockchain.addXDCxDb(XDCxDb)
	}
	return blockchain, nil
}

// NewBlockChainExResolved opens a writable XDCx-aware blockchain from caller-
// supplied startup metadata.
func NewBlockChainExResolved(db ethdb.Database, XDCxDb ethdb.XDCxDatabase, cacheConfig *CacheConfig, recoveryGenesis *Genesis, engine consensus.Engine, vmConfig vm.Config, chainConfig *params.ChainConfig, genesisHash common.Hash, compatErr *params.ConfigCompatError, compatPolicy ChainConfigMismatchPolicy) (*BlockChain, error) {
	blockchain, err := NewBlockChainResolved(db, cacheConfig, recoveryGenesis, engine, vmConfig, chainConfig, genesisHash, compatErr, compatPolicy)
	if err != nil {
		return nil, err
	}
	if blockchain != nil {
		blockchain.addXDCxDb(XDCxDb)
	}
	return blockchain, nil
}

// NewBlockChainExReadOnlyResolved opens a readonly XDCx-aware blockchain from
// caller-supplied startup metadata.
func NewBlockChainExReadOnlyResolved(db ethdb.Database, XDCxDb ethdb.XDCxDatabase, cacheConfig *CacheConfig, recoveryGenesis *Genesis, engine consensus.Engine, vmConfig vm.Config, chainConfig *params.ChainConfig, genesisHash common.Hash, compatErr *params.ConfigCompatError, compatPolicy ChainConfigMismatchPolicy) (*BlockChain, error) {
	blockchain, err := NewBlockChainReadOnlyResolved(db, cacheConfig, recoveryGenesis, engine, vmConfig, chainConfig, genesisHash, compatErr, compatPolicy)
	if err != nil {
		return nil, err
	}
	if blockchain != nil {
		blockchain.addXDCxDb(XDCxDb)
	}
	return blockchain, nil
}

func (bc *BlockChain) addXDCxDb(XDCxDb ethdb.XDCxDatabase) {
	bc.XDCxDb = XDCxDb
}

// loadLastState loads the last known chain state from the database. This method
// assumes that the chain manager mutex is held.
func (bc *BlockChain) loadLastState() error {
	// Restore the last known head block
	head := rawdb.ReadHeadBlockHash(bc.db)
	if head == (common.Hash{}) {
		// Corrupt or empty database, init from scratch
		log.Warn("Empty database, resetting chain")
		return bc.Reset()
	}
	// Make sure the entire head block is available
	headBlock := bc.GetBlockByHash(head)
	if headBlock == nil {
		// Corrupt or empty database, init from scratch
		log.Warn("Head block missing, resetting chain", "hash", head)
		return bc.Reset()
	}
	// Make sure the auxiliary state associated with the block is available.
	repair := false
	if bc.HasState(headBlock.Root()) {
		engine, ok := bc.Engine().(*XDPoS.XDPoS)
		if ok {
			tradingService := engine.GetXDCXService()
			lendingService := engine.GetLendingService()
			if bc.Config().IsTIPXDCX(headBlock.Number()) && bc.chainConfig.XDPoS != nil && headBlock.NumberU64() > bc.chainConfig.XDPoS.Epoch && tradingService != nil && lendingService != nil {
				author, _ := bc.Engine().Author(headBlock.Header())
				tradingRoot, err := tradingService.GetTradingStateRoot(headBlock, author)
				if err != nil {
					repair = true
				} else {
					if tradingService.GetStateCache() != nil {
						_, err = tradingstate.New(tradingRoot, tradingService.GetStateCache())
						if err != nil {
							repair = true
						}
					}
				}

				if !repair {
					lendingRoot, err := lendingService.GetLendingStateRoot(headBlock, author)
					if err != nil {
						repair = true
					} else {
						if lendingService.GetStateCache() != nil {
							_, err = lendingstate.New(lendingRoot, lendingService.GetStateCache())
							if err != nil {
								repair = true
							}
						}
					}
				}
			}
		}
	}
	if repair {
		// Dangling block without a state associated, init from scratch
		log.Warn("Head state missing, repairing chain", "number", headBlock.Number(), "hash", headBlock.Hash())
		if err := bc.repair(&headBlock); err != nil {
			return err
		}
	}
	// Everything seems to be fine, set as the head block
	bc.currentBlock.Store(headBlock.Header())
	headBlockGauge.Update(int64(headBlock.NumberU64()))

	// Restore the last known head header
	headHeader := headBlock.Header()
	if head := rawdb.ReadHeadHeaderHash(bc.db); head != (common.Hash{}) {
		if header := bc.GetHeaderByHash(head); header != nil {
			headHeader = header
		}
	}
	bc.hc.SetCurrentHeader(headHeader)

	// Restore the last known head fast block
	bc.currentSnapBlock.Store(headBlock.Header())
	headFastBlockGauge.Update(int64(headBlock.NumberU64()))

	if head := rawdb.ReadHeadFastBlockHash(bc.db); head != (common.Hash{}) {
		if block := bc.GetBlockByHash(head); block != nil {
			bc.currentSnapBlock.Store(block.Header())
			headFastBlockGauge.Update(int64(block.NumberU64()))
		}
	}

	// Issue a status log for the user
	var (
		currentSnapBlock = bc.CurrentSnapBlock()

		headerTd = bc.GetTd(headHeader.Hash(), headHeader.Number.Uint64())
		blockTd  = bc.GetTd(headBlock.Hash(), headBlock.NumberU64())
	)
	if headHeader.Hash() != headBlock.Hash() {
		log.Info("Loaded most recent local header", "number", headHeader.Number, "hash", headHeader.Hash(), "td", headerTd, "age", common.PrettyAge(time.Unix(int64(headHeader.Time), 0)))
	}
	log.Info("Loaded most recent local block", "number", headBlock.Number(), "hash", headBlock.Hash(), "td", blockTd, "age", common.PrettyAge(time.Unix(int64(headBlock.Time()), 0)))
	if headBlock.Hash() != currentSnapBlock.Hash() {
		fastTd := bc.GetTd(currentSnapBlock.Hash(), currentSnapBlock.Number.Uint64())
		log.Info("Loaded most recent local snap block", "number", currentSnapBlock.Number, "hash", currentSnapBlock.Hash(), "td", fastTd, "age", common.PrettyAge(time.Unix(int64(currentSnapBlock.Time), 0)))
	}

	return nil
}

// SetHead rewinds the local chain to a new head. Depending on whether the node
// was fast synced or full synced and in which state, the method will try to
// delete minimal data from disk whilst retaining chain consistency.
func (bc *BlockChain) SetHead(head uint64) error {
	if err := bc.setHeadBeyondRoot(head); err != nil {
		return err
	}
	// Send chain head event to update the transaction pool
	header := bc.CurrentBlock()
	block := bc.GetBlock(header.Hash(), header.Number.Uint64())
	if block == nil {
		// This should never happen. In practice, previously currentBlock
		// contained the entire block whereas now only a "marker", so there
		// is an ever so slight chance for a race we should handle.
		log.Error("Current block not found in database", "block", header.Number, "hash", header.Hash())
		return fmt.Errorf("current block missing: #%d [%x..]", header.Number, header.Hash().Bytes()[:4])
	}
	bc.chainHeadFeed.Send(ChainHeadEvent{Block: block})
	return nil
}

// setHeadBeyondRoot rewinds the local chain to a new head with the extra condition
// that the rewind must pass the specified state root. This method is meant to be
// used when rewinding with snapshots enabled to ensure that we go back further than
// persistent disk layer. Depending on whether the node was fast synced or full, and
// in which state, the method will try to delete minimal data from disk whilst
// retaining chain consistency.
func (bc *BlockChain) setHeadBeyondRoot(head uint64) error {
	if !bc.chainmu.TryLock() {
		return ErrChainStopped
	}
	defer bc.chainmu.Unlock()

	// delFn below reuses isGapBlockNumber to pick the snapshots a rewind deletes, and that
	// predicate only matches when 0 < Gap <= Epoch. Outside that range no snapshot is
	// deleted; the leftovers are keyed by block hash, so they are never loaded again - a
	// leak, not a wrong answer.
	if xdpos := bc.chainConfig.XDPoS; xdpos != nil && (xdpos.Epoch == 0 || xdpos.Gap == 0 || xdpos.Gap > xdpos.Epoch) {
		log.Warn("Rewinding with no gap snapshot to delete: the gap predicate cannot match this configuration",
			"epoch", xdpos.Epoch, "gap", xdpos.Gap)
	}

	// Report the header head, not the block head: HeaderChain.SetHead below
	// walks hc.CurrentHeader down to the target, so the header head is the
	// height this rewind starts deleting from. During header-first/snap sync
	// the header head can be ahead of the block head (loadLastState restores
	// the two markers separately), in which case the block head would
	// understate the rewound segment -- and can even sit below the target.
	// rewindFrom carries that height into the completion line below, where it
	// yields the average rate of the whole rewind.
	var rewindFrom uint64
	if current := bc.CurrentHeader(); current != nil {
		rewindFrom = current.Number.Uint64()
	}
	// Announce only a rewind that actually rewinds. SetHead is reached with a
	// target at or above the current header head on ordinary no-op calls (e.g.
	// debug.setHead to the current height), and a Warn there reads like a real
	// rewind took place; the completion line below still reports the
	// operation, with from == the unchanged head.
	if rewindFrom > head {
		log.Warn("Rewinding chain to target", "target", head, "current", rewindFrom)
	}
	start := time.Now()

	updateFn := func(db ethdb.KeyValueWriter, header *types.Header) {
		// Rewind the block chain, ensuring we don't end up with a stateless head block
		if currentBlock := bc.CurrentBlock(); currentBlock != nil && header.Number.Uint64() < currentBlock.Number.Uint64() {
			newHeadBlock := bc.GetBlock(header.Hash(), header.Number.Uint64())
			if newHeadBlock == nil {
				newHeadBlock = bc.genesisBlock
			} else {
				if !bc.HasState(newHeadBlock.Root()) {
					// Rewound state missing, rolled back to before pivot, reset to genesis
					newHeadBlock = bc.genesisBlock
				}
			}
			rawdb.WriteHeadBlockHash(db, newHeadBlock.Hash())

			// Degrade the chain markers if they are explicitly reverted.
			// In theory we should update all in-memory markers in the
			// last step, however the direction of SetHead is from high
			// to low, so it's safe the update in-memory markers directly.
			bc.currentBlock.Store(newHeadBlock.Header())
			headBlockGauge.Update(int64(newHeadBlock.NumberU64()))
		}

		// Rewind the fast block in a simpleton way to the target head
		if currentSnapBlock := bc.CurrentSnapBlock(); currentSnapBlock != nil && header.Number.Uint64() < currentSnapBlock.Number.Uint64() {
			newHeadSnapBlock := bc.GetBlock(header.Hash(), header.Number.Uint64())
			// If either blocks reached nil, reset to the genesis state
			if newHeadSnapBlock == nil {
				newHeadSnapBlock = bc.genesisBlock
			}
			rawdb.WriteHeadFastBlockHash(db, newHeadSnapBlock.Hash())

			// Degrade the chain markers if they are explicitly reverted.
			// In theory we should update all in-memory markers in the
			// last step, however the direction of SetHead is from high
			// to low, so it's safe the update in-memory markers directly.
			bc.currentSnapBlock.Store(newHeadSnapBlock.Header())
			headFastBlockGauge.Update(int64(newHeadSnapBlock.NumberU64()))
		}
	}

	// Rewind the header chain, deleting all block bodies until then
	delFn := func(db ethdb.KeyValueWriter, hash common.Hash, num uint64) {
		// Ignore the error here since light client won't hit this path
		frozen, _ := bc.db.Ancients()
		if num+1 <= frozen {
			// Truncate all relative data(header, total difficulty, body, receipt
			// and canonical hash) from ancient store.
			if err := bc.db.TruncateAncients(num + 1); err != nil {
				log.Crit("Failed to truncate ancient data", "number", num, "err", err)
			}

			// Remove the hash <-> number mapping from the active store.
			rawdb.DeleteHeaderNumber(db, hash)
		} else {
			// Remove relative body and receipts from the active store.
			// The header, total difficulty and canonical hash will be
			// removed in the hc.SetHead function.
			rawdb.DeleteBody(db, hash, num)
			rawdb.DeleteReceipts(db, hash, num)
		}
		if bc.isGapBlockNumber(num) {
			rawdb.DeleteXdposSnapshot(db, hash)
		}
		// Todo(rjl493456442) txlookup, bloombits, etc
	}
	bc.hc.SetHead(head, updateFn, delFn)

	// Clear out any stale content from the caches
	bc.bodyCache.Purge()
	bc.bodyRLPCache.Purge()
	bc.receiptsCache.Purge()
	bc.blockCache.Purge()
	bc.futureBlocks.Purge()
	bc.blocksHashCache.Purge()

	if err := bc.loadLastState(); err != nil {
		return err
	}
	elapsed := time.Since(start)
	// Average rate over the whole rewind, i.e. the starting height down to the
	// target. Note that elapsed also covers the dangling sweep, so this sits
	// below the delete-only rate printed by "Rewound chain" whenever the sweep
	// takes a while.
	var avgRate int64
	if elapsed > 0 && rewindFrom > head {
		avgRate = int64(float64(rewindFrom-head) / elapsed.Seconds())
	}
	log.Info("Chain rewind completed", "target", head, "from", rewindFrom,
		"elapsed", common.PrettyDuration(elapsed.Round(time.Second)), "blk/s(avg)", avgRate)
	return nil
}

// FastSyncCommitHead sets the current head block to the one defined by the hash
// irrelevant what the chain contents were prior.
func (bc *BlockChain) FastSyncCommitHead(hash common.Hash) error {
	// Make sure that both the block as well at its state trie exists
	block := bc.GetBlockByHash(hash)
	if block == nil {
		return fmt.Errorf("non existent block [%x..]", hash[:4])
	}
	root := block.Root()
	if !bc.HasState(root) {
		return fmt.Errorf("non existent state [%x..]", root[:4])
	}
	// If all checks out, manually set the head block.
	if !bc.chainmu.TryLock() {
		return ErrChainStopped
	}
	bc.currentBlock.Store(block.Header())
	headBlockGauge.Update(int64(block.NumberU64()))
	bc.chainmu.Unlock()

	log.Info("Committed new head block", "number", block.Number(), "hash", hash)
	return nil
}

// OrderStateAt returns a new mutable state based on a particular point in time.
func (bc *BlockChain) OrderStateAt(block *types.Block) (*tradingstate.TradingStateDB, error) {
	engine, ok := bc.Engine().(*XDPoS.XDPoS)
	if ok {
		XDCXService := engine.GetXDCXService()
		if bc.Config().IsTIPXDCX(block.Number()) && bc.chainConfig.XDPoS != nil && block.NumberU64() > bc.chainConfig.XDPoS.Epoch && XDCXService != nil {
			author, _ := bc.Engine().Author(block.Header())
			log.Debug("OrderStateAt", "blocknumber", block.Header().Number)
			XDCxState, err := XDCXService.GetTradingState(block, author)
			if err == nil {
				return XDCxState, nil
			} else {
				return nil, err
			}
		} else {
			XDCxState, err := XDCXService.GetEmptyTradingState()
			if err == nil {
				return XDCxState, nil
			} else {
				return nil, err
			}
		}
	}
	return nil, errors.New("fail to get trading state")
}

// LendingStateAt returns a new mutable state based on a particular point in time.
func (bc *BlockChain) LendingStateAt(block *types.Block) (*lendingstate.LendingStateDB, error) {
	engine, ok := bc.Engine().(*XDPoS.XDPoS)
	if ok {
		lendingService := engine.GetLendingService()
		if bc.Config().IsTIPXDCX(block.Number()) && bc.chainConfig.XDPoS != nil && block.NumberU64() > bc.chainConfig.XDPoS.Epoch && lendingService != nil {
			author, _ := bc.Engine().Author(block.Header())
			log.Debug("LendingStateAt", "blocknumber", block.Header().Number)
			lendingState, err := lendingService.GetLendingState(block, author)
			if err == nil {
				return lendingState, nil
			}
			return nil, err
		}
	}
	return nil, errors.New("fail to et lending state")
}

// Reset purges the entire blockchain, restoring it to its genesis state.
func (bc *BlockChain) Reset() error {
	return bc.ResetWithGenesisBlock(bc.genesisBlock)
}

// ResetWithGenesisBlock purges the entire blockchain, restoring it to the
// specified genesis state.
func (bc *BlockChain) ResetWithGenesisBlock(genesis *types.Block) error {
	// Dump the entire block chain and purge the caches
	if err := bc.SetHead(0); err != nil {
		return err
	}
	if !bc.chainmu.TryLock() {
		return ErrChainStopped
	}
	defer bc.chainmu.Unlock()

	// Prepare the genesis block and reinitialise the chain
	batch := bc.db.NewBatch()
	rawdb.WriteTd(batch, genesis.Hash(), genesis.NumberU64(), genesis.Difficulty())
	rawdb.WriteBlock(batch, genesis)
	if err := batch.Write(); err != nil {
		log.Crit("Failed to write genesis block", "err", err)
	}
	bc.writeHeadBlock(genesis, nil)

	// Last update all in-memory chain markers
	bc.genesisBlock = genesis
	bc.currentBlock.Store(bc.genesisBlock.Header())
	headBlockGauge.Update(int64(bc.genesisBlock.NumberU64()))
	bc.hc.SetGenesis(bc.genesisBlock.Header())
	bc.hc.SetCurrentHeader(bc.genesisBlock.Header())
	bc.currentSnapBlock.Store(bc.genesisBlock.Header())
	headFastBlockGauge.Update(int64(bc.genesisBlock.NumberU64()))
	return nil
}

// repair tries to repair the current blockchain by rolling back the current block
// until one with associated state is found. This is needed to fix incomplete db
// writes caused either by crashes/power outages, or simply non-committed tries.
//
// This method only rolls back the current block. The current header and current
// fast block are left intact.
func (bc *BlockChain) repair(head **types.Block) error {
	for {
		// Abort if we've rewound to a head block that does have associated state.
		// RollbackNumber already holds an absolute target by the time repair runs:
		// eth.New resolves a negative --set-head before it opens the chain, so a
		// negative value never reaches this point. A target of 0 (the genesis
		// block, from "--set-head=-<current height>") leaves the repair unbounded
		// in effect, since it cannot rewind past 0 either way. The <= 0 test is
		// kept as a guard: a negative value reaching here would wrap around in the
		// uint64 conversion below and leave the rewind unbounded.
		if (common.RollbackNumber <= 0) || ((*head).Number().Uint64() <= uint64(common.RollbackNumber)) {
			if bc.HasState((*head).Root()) {
				log.Info("Rewound blockchain to past state", "number", (*head).Number(), "hash", (*head).Hash())
				engine, ok := bc.Engine().(*XDPoS.XDPoS)
				if ok {
					tradingService := engine.GetXDCXService()
					lendingService := engine.GetLendingService()
					if bc.Config().IsTIPXDCXReceiver((*head).Number()) && bc.chainConfig.XDPoS != nil && (*head).NumberU64() > bc.chainConfig.XDPoS.Epoch && tradingService != nil && lendingService != nil {
						author, _ := bc.Engine().Author((*head).Header())
						tradingRoot, err := tradingService.GetTradingStateRoot(*head, author)
						if err == nil {
							_, err = tradingstate.New(tradingRoot, tradingService.GetStateCache())
						}
						if err == nil {
							lendingRoot, err := lendingService.GetLendingStateRoot(*head, author)
							if err == nil {
								_, err = lendingstate.New(lendingRoot, lendingService.GetStateCache())
								if err == nil {
									return nil
								}
							}
						}
					} else {
						return nil
					}
				} else {
					return nil
				}
			}
		} else {
			log.Info("Rewound blockchain to past state", "number", (*head).Number(), "hash", (*head).Hash())
		}
		// Otherwise rewind one block and recheck state availability there
		block := bc.GetBlock((*head).ParentHash(), (*head).NumberU64()-1)
		if block == nil {
			panic(fmt.Sprintf("repair fail to get block at number: %v, hash: %v", (*head).NumberU64()-1, (*head).ParentHash()))
		}
		(*head) = block
	}
}

// Export writes the active chain to the given writer.
func (bc *BlockChain) Export(w io.Writer) error {
	return bc.ExportN(w, uint64(0), bc.CurrentBlock().Number.Uint64())
}

// ExportN writes a subset of the active chain to the given writer.
func (bc *BlockChain) ExportN(w io.Writer, first uint64, last uint64) error {
	if !bc.chainmu.TryLock() {
		return ErrChainStopped
	}
	defer bc.chainmu.Unlock()

	if first > last {
		return fmt.Errorf("export failed: first (%d) is greater than last (%d)", first, last)
	}
	log.Info("Exporting batch of blocks", "count", last-first+1)

	start, reported := time.Now(), time.Now()
	for nr := first; nr <= last; nr++ {
		block := bc.GetBlockByNumber(nr)
		if block == nil {
			return fmt.Errorf("export failed on #%d: not found", nr)
		}
		if err := block.EncodeRLP(w); err != nil {
			return err
		}
		if time.Since(reported) >= statsReportLimit {
			log.Info("Exporting blocks", "exported", block.NumberU64()-first, "elapsed", common.PrettyDuration(time.Since(start)))
			reported = time.Now()
		}
	}

	return nil
}

// writeHeadBlock injects a new head block into the current block chain. This method
// assumes that the block is indeed a true head. It will also reset the head
// header and the head fast sync block to this very same block if they are older
// or if they are on a different side chain.
//
// The block and its receipts must already be persisted by the caller; only the
// chain markers are written here. The receipts are read back below to fill the
// XDPoS signing transaction cache, which silently drops the signing
// transactions it cannot find a receipt for.
//
// A non-nil snap is the masternode snapshot of the next epoch for this block and
// is written in the same batch as the markers: a gap block must never become
// canonical without the snapshot its epoch switch reads.
//
// Note, this function assumes that the `mu` mutex is held!
func (bc *BlockChain) writeHeadBlock(block *types.Block, snap *engine_v2.SnapshotV2) {
	blockHash := block.Hash()
	blockNumberU64 := block.NumberU64()

	// Add the block to the canonical chain number scheme and mark as the head
	batch := bc.db.NewBatch()
	rawdb.WriteHeadHeaderHash(batch, blockHash)
	rawdb.WriteHeadFastBlockHash(batch, blockHash)
	rawdb.WriteCanonicalHash(batch, blockHash, blockNumberU64)
	rawdb.WriteTxLookupEntriesByBlock(batch, block)
	rawdb.WriteHeadBlockHash(batch, blockHash)
	if snap != nil {
		blob, err := engine_v2.EncodeSnapshot(snap)
		if err != nil {
			log.Crit("Failed to encode the next-epoch masternode snapshot", "number", blockNumberU64, "hash", blockHash.Hex(), "err", err)
		}
		rawdb.WriteXdposV2Snapshot(batch, snap.Hash, blob)
	}

	// Flush the whole batch into the disk, exit the node if failed
	if err := batch.Write(); err != nil {
		log.Crit("Failed to update chain indexes and markers", "err", err)
	}

	// Update all in-memory chain markers in the last step
	bc.hc.SetCurrentHeader(block.Header())

	bc.currentSnapBlock.Store(block.Header())
	headFastBlockGauge.Update(int64(blockNumberU64))

	bc.currentBlock.Store(block.Header())
	headBlockGauge.Update(int64(block.NumberU64()))

	// Publish the snapshot only now that the batch is on disk: an engine serving
	// a snapshot whose write never landed would mask the very hole this batch
	// closes. The ready line belongs to the same point: it says the set is
	// durable, not merely derived.
	if snap != nil {
		log.Info("Masternodes are ready for the next epoch", "number", blockNumberU64, "hash", blockHash.Hex())
		if engine, ok := bc.Engine().(*XDPoS.XDPoS); ok {
			engine.EngineV2.CacheSnapshot(snap)
		}
	}

	// save cache BlockSigners
	if bc.chainConfig.XDPoS != nil && !bc.chainConfig.IsTIPSigning(block.Number()) {
		engine, ok := bc.Engine().(*XDPoS.XDPoS)
		if ok {
			engine.CacheNoneTIPSigningTxs(block.Header(), block.Transactions(), bc.GetReceiptsByHash(blockHash))
		}
	}
}

// HasFullState checks if state trie is fully present in the database or not.
func (bc *BlockChain) HasFullState(block *types.Block) bool {
	_, err := bc.stateCache.OpenTrie(block.Root())
	if err != nil {
		return false
	}
	engine, _ := bc.Engine().(*XDPoS.XDPoS)
	if bc.Config().IsTIPXDCX(block.Number()) && bc.chainConfig.XDPoS != nil && engine != nil && block.NumberU64() > bc.chainConfig.XDPoS.Epoch {
		tradingService := engine.GetXDCXService()
		lendingService := engine.GetLendingService()
		author, _ := bc.Engine().Author(block.Header())
		if tradingService != nil && !tradingService.HasTradingState(block, author) {
			return false
		}
		if lendingService != nil && !lendingService.HasLendingState(block, author) {
			return false
		}
	}
	return true
}

// HasBlockAndFullState checks if a block and associated state trie is fully present
// in the database or not, caching it if present.
func (bc *BlockChain) HasBlockAndFullState(hash common.Hash, number uint64) bool {
	// Check first that the block itself is known
	block := bc.GetBlock(hash, number)
	if block == nil {
		return false
	}
	return bc.HasFullState(block)
}

// HasExecutedBlock answers whether this node holds the artifacts of executing the block:
// the receipts its execution produced, and the state the header names.
//
// HasBlockAndFullState does not even answer that weaker question: it asks only whether the
// root named by the header resolves in the trie database, and that answer is keyed by the
// root rather than by the block. writeBlockWithoutState stores a sidechain block without its
// state and without its receipts, so a block that names a root which happens to exist is
// taken for one that was executed - and trie.New resolves no node at all for
// types.EmptyRootHash, so naming an empty root is enough. Asking for the receipts as well
// makes such a mistake harder rather than ruled out: see below.
//
// Neither half proves that this node ran the block. Receipts are written by
// InsertReceiptChain too, which is a fast sync completing a header chain: the body and the
// receipts go to disk, the state does not. And a root resolves for reasons that have nothing
// to do with this block - the empty root above, a root shared with a block this node did
// execute, or a pivot state whose synchronisation got far enough to commit the root node
// before it stopped. TestKnownBlockNeverExecutedIsNotReportedAsKnown drives three such roots
// on a block this node never executed, and it is the receipts that keep it from being
// reported as known.
//
// What is left unproven is therefore the fast sync's own range above this node's head -
// see eth/handler.go for when fast sync is allowed at all, and note that it writes receipts
// well before it knows anything about the state. A block there whose root resolves is still
// answered as executed, so an admin import skips it and an import that re-delivers it adopts
// it without running Process or ValidateState over it. Proving more needs a record written
// only by a full execution of that block, and there is none, so what the callers get is a
// narrowing of HasBlockAndFullState and not the execution itself.
//
// The receipts are asked first because the answer is the same either way and this is the
// cheaper of the two: a freezer index probe and a key lookup, where HasBlockAndFullState
// reads and decodes the body and then resolves the state root together with the trading and
// lending states hanging off it.
func (bc *BlockChain) HasExecutedBlock(hash common.Hash, number uint64) bool {
	if !rawdb.HasReceipts(bc.db, hash, number) {
		return false
	}
	return bc.HasBlockAndFullState(hash, number)
}

// AreTwoBlockSamePath check if two blocks are same path
// Assume block 1 is ahead block 2 so we need to check parentHash
func (bc *BlockChain) AreTwoBlockSamePath(bh1 common.Hash, bh2 common.Hash) bool {
	bl1 := bc.GetBlockByHash(bh1)
	bl2 := bc.GetBlockByHash(bh2)
	if bl1 == nil || bl2 == nil {
		return false
	}

	toBlockLevel := bl2.Number().Uint64()
	for bl1.Number().Uint64() > toBlockLevel {
		bl1 = bc.GetBlockByHash(bl1.ParentHash())
		if bl1 == nil {
			return false
		}
	}

	return (bl1.Hash() == bl2.Hash())
}

func (bc *BlockChain) saveData() {
	// Ensure the state of a recent block is also stored to disk before exiting.
	// We're writing three different states to catch different restart scenarios:
	//  - HEAD:     So we don't need to reprocess any blocks in the general case
	//  - HEAD-1:   So we don't do large reorgs if our HEAD becomes an uncle
	//  - HEAD-127: So we have a hard limit on the number of blocks reexecuted
	if !bc.cacheConfig.TrieDirtyDisabled {
		var tradingTriedb *trie.Database
		var lendingTriedb *trie.Database
		var tradingService utils.TradingService
		var lendingService utils.LendingService
		triedb := bc.triedb
		engine, _ := bc.Engine().(*XDPoS.XDPoS)
		if bc.Config().IsTIPXDCX(bc.CurrentBlock().Number) && bc.chainConfig.XDPoS != nil && bc.CurrentBlock().Number.Uint64() > bc.chainConfig.XDPoS.Epoch && engine != nil {
			tradingService = engine.GetXDCXService()
			if tradingService != nil && tradingService.GetStateCache() != nil {
				tradingTriedb = tradingService.GetStateCache().TrieDB()
			}
			lendingService = engine.GetLendingService()
			if lendingService != nil && lendingService.GetStateCache() != nil {
				lendingTriedb = lendingService.GetStateCache().TrieDB()
			}
		}
		for _, offset := range []uint64{0, 1, TriesInMemory - 1} {
			if number := bc.CurrentBlock().Number.Uint64(); number > offset {
				recent := bc.GetBlockByNumber(number - offset)

				log.Info("Writing cached state to disk", "block", recent.Number(), "hash", recent.Hash(), "root", recent.Root())
				if err := triedb.Commit(recent.Root(), true); err != nil {
					log.Error("Failed to commit recent state trie", "err", err)
				}
				if bc.Config().IsTIPXDCXReceiver(recent.Number()) && bc.chainConfig.XDPoS != nil && recent.NumberU64() > bc.chainConfig.XDPoS.Epoch && engine != nil {
					author, _ := bc.Engine().Author(recent.Header())
					if tradingService != nil {
						tradingRoot, _ := tradingService.GetTradingStateRoot(recent, author)
						if !tradingRoot.IsZero() && tradingTriedb != nil {
							if err := tradingTriedb.Commit(tradingRoot, true); err != nil {
								log.Error("Failed to commit trading state recent state trie", "err", err)
							}
						}
					}
					if lendingService != nil {
						lendingRoot, _ := lendingService.GetLendingStateRoot(recent, author)
						if !lendingRoot.IsZero() && lendingTriedb != nil {
							if err := lendingTriedb.Commit(lendingRoot, true); err != nil {
								log.Error("Failed to commit lending state recent state trie", "err", err)
							}
						}
					}
				}
			}
		}
		for !bc.triegc.Empty() {
			triedb.Dereference(bc.triegc.PopItem())
		}
		if tradingTriedb != nil && lendingTriedb != nil {
			if tradingService.GetTriegc() != nil {
				for !tradingService.GetTriegc().Empty() {
					tradingTriedb.Dereference(tradingService.GetTriegc().PopItem())
				}
			}
			if lendingService.GetTriegc() != nil {
				for !lendingService.GetTriegc().Empty() {
					lendingTriedb.Dereference(lendingService.GetTriegc().PopItem())
				}
			}
		}
		if size, _ := triedb.Size(); size != 0 {
			log.Error("Dangling trie nodes after full cleanup")
		}
	}
}

// Stop stops the blockchain service. If any imports are currently in progress
// it will abort them using the procInterrupt.
func (bc *BlockChain) Stop() {
	if !bc.stopping.CompareAndSwap(false, true) {
		return
	}

	// Unsubscribe all subscriptions registered from blockchain.
	bc.scope.Close()

	// Signal shutdown to all goroutines.
	close(bc.quit)
	bc.InterruptInsert(true)

	// Now wait for all chain modifications to end and persistent goroutines to exit.
	//
	// Note: Close waits for the mutex to become available, i.e. any running chain
	// modification will have exited when Close returns. Since we also called StopInsert,
	// the mutex should become available quickly. It cannot be taken again after Close has
	// returned.
	bc.chainmu.Close()
	bc.wg.Wait()
	bc.saveData()
	// Allow tracers to clean-up and release resources.
	if bc.logger != nil && bc.logger.OnClose != nil {
		bc.logger.OnClose()
	}
	// Flush the collected preimages to disk
	if err := bc.stateCache.TrieDB().Close(); err != nil {
		log.Error("Failed to close trie db", "err", err)
	}
	log.Info("Blockchain manager stopped")
}

// InterruptInsert interrupts all insertion methods, causing them to return
// ErrInsertionInterrupted as soon as possible, or resume the chain insertion
// if required.
func (bc *BlockChain) InterruptInsert(on bool) {
	if on {
		bc.procInterrupt.Store(true)
	} else {
		bc.procInterrupt.Store(false)
	}
}

// insertStopped returns true after StopInsert has been called.
func (bc *BlockChain) insertStopped() bool {
	return bc.procInterrupt.Load()
}

func (bc *BlockChain) procFutureBlocks() {
	capacity := bc.futureBlocks.Len()
	if capacity == 0 {
		return
	}
	blocks := make([]*types.Block, 0, capacity)
	for _, hash := range bc.futureBlocks.Keys() {
		if block, exist := bc.futureBlocks.Peek(hash); exist {
			blocks = append(blocks, block)
		}
	}
	if len(blocks) > 0 {
		types.BlockBy(types.Number).Sort(blocks)

		// Insert one by one as chain insertion needs contiguous ancestry between blocks
		for i := range blocks {
			_, err := bc.InsertChain(blocks[i : i+1])
			// let consensus engine handle the last block (e.g. for voting)
			if i == len(blocks)-1 && err == nil {
				engine, ok := bc.Engine().(*XDPoS.XDPoS)
				if ok {
					header := blocks[i].Header()
					err = engine.HandleProposedBlock(bc, header)
					if err != nil {
						log.Info("[procFutureBlocks] handle proposed block has error", "err", err, "block hash", header.Hash(), "number", header.Number)
					}
				}
			}
		}
	}
}

// WriteStatus status of write
type WriteStatus byte

const (
	NonStatTy WriteStatus = iota
	CanonStatTy
	SideStatTy
)

// Rollback is designed to remove a chain of links from the database that aren't
// certain enough to be valid.
func (bc *BlockChain) Rollback(chain []common.Hash) {
	if !bc.chainmu.TryLock() {
		return
	}
	defer bc.chainmu.Unlock()

	batch := bc.db.NewBatch()
	for i := len(chain) - 1; i >= 0; i-- {
		hash := chain[i]

		// Degrade the chain markers if they are explicitly reverted.
		// In theory, we should update all in-memory markers in the
		// last step, however the direction of rollback is from high
		// to low, so it's safe the update in-memory markers directly.
		currentHeader := bc.hc.CurrentHeader()
		if currentHeader.Hash() == hash {
			newHeadHeader := bc.GetHeader(currentHeader.ParentHash, currentHeader.Number.Uint64()-1)
			rawdb.WriteHeadHeaderHash(batch, currentHeader.ParentHash)
			bc.hc.SetCurrentHeader(newHeadHeader)
		}
		if currentSnapBlock := bc.CurrentSnapBlock(); currentSnapBlock.Hash() == hash {
			newFastBlock := bc.GetBlock(currentSnapBlock.ParentHash, currentSnapBlock.Number.Uint64()-1)
			if newFastBlock == nil {
				log.Error("Rollback failed", "number", currentSnapBlock.Number.Uint64()-1, "hash", currentSnapBlock.ParentHash.Hex())
				return
			}
			rawdb.WriteHeadFastBlockHash(batch, currentSnapBlock.ParentHash)
			bc.currentSnapBlock.Store(newFastBlock.Header())
			headFastBlockGauge.Update(int64(newFastBlock.NumberU64()))
		}
		if currentBlock := bc.CurrentBlock(); currentBlock.Hash() == hash {
			newBlock := bc.GetBlock(currentBlock.ParentHash, currentBlock.Number.Uint64()-1)
			if newBlock == nil {
				log.Error("Rollback failed", "number", currentBlock.Number.Uint64()-1, "hash", currentBlock.ParentHash.Hex())
				return
			}
			rawdb.WriteHeadBlockHash(batch, currentBlock.ParentHash)
			bc.currentBlock.Store(newBlock.Header())
			headBlockGauge.Update(int64(newBlock.NumberU64()))
		}
	}
	if err := batch.Write(); err != nil {
		log.Crit("Failed to rollback chain markers", "err", err)
	}
	// TODO: Truncate ancient data which exceeds the current header.
}

// InsertReceiptChain attempts to complete an already existing header chain with
// transaction and receipt data.
//
// The returned index says where the import stopped: a block this node cannot finish (unknown
// header, receipts that do not derive) reports its own index; an interruption reports the
// first block the database does not hold, i.e. the first of the current batch rather than the
// one the loop was on; a write the database refused reports 0, since that batch cannot be
// split and under-reporting cannot make a caller think a block was written.
func (bc *BlockChain) InsertReceiptChain(blockChain types.Blocks, receiptChain []types.Receipts) (int, error) {
	// We don't require the chainMu here since we want to maximize the
	// concurrency of header insertion and receipt insertion.
	bc.wg.Add(1)
	defer bc.wg.Done()

	// Do a sanity check that the provided chain is actually ordered and linked
	for i, block := range blockChain {
		if i != 0 {
			prev := blockChain[i-1]
			if block.NumberU64() != prev.NumberU64()+1 || block.ParentHash() != prev.Hash() {
				log.Error("Non contiguous receipt insert",
					"number", block.Number(), "hash", block.Hash(), "parent", block.ParentHash(),
					"prevnumber", prev.Number(), "prevhash", prev.Hash())
				return 0, fmt.Errorf("non contiguous insert: item %d is #%d [%x..], item %d is #%d [%x..] (parent [%x..])",
					i-1, prev.NumberU64(), prev.Hash().Bytes()[:4],
					i, block.NumberU64(), block.Hash().Bytes()[:4], blockChain[i].ParentHash().Bytes()[:4])
			}
		}
	}

	var (
		stats = struct{ processed, ignored int32 }{}
		start = time.Now()
		bytes = 0
		batch = bc.db.NewBatch()
		// The first block the database does not hold. Everything below it is on disk;
		// every block walked since is pending in the batch or not walked yet.
		firstPending = 0
	)
	for i, block := range blockChain {
		receipts := receiptChain[i]
		// Short circuit insertion if shutting down or processing failed.
		//
		// The index is firstPending, not the cursor: the blocks the batch holds were never
		// written, so reporting the cursor would claim a half-written batch as complete. The
		// sentinel is local, so the downloader reports it as errLocalInsertFailure rather
		// than as errCancelContentProcessing and does not blame the peer.
		if bc.insertStopped() {
			return firstPending, ErrInsertionInterrupted
		}
		blockHash, blockNumber := block.Hash(), block.NumberU64()
		// Short circuit if the owner header is unknown
		if !bc.HasHeader(blockHash, blockNumber) {
			return i, fmt.Errorf("containing header #%d [%x..] unknown", blockNumber, blockHash.Bytes()[:4])
		}
		// Skip if the entire data is already known
		if bc.HasBlock(blockHash, blockNumber) {
			// The block is on disk, so it belongs to the prefix firstPending describes - but
			// only while nothing is pending: a batch already holding writes would reach the
			// database after this block, and counting this one would claim that batch too.
			// firstPending == i says exactly that.
			if firstPending == i {
				firstPending = i + 1
			}
			stats.ignored++
			continue
		}
		// Compute all the non-consensus fields of the receipts
		if err := receipts.DeriveFields(bc.chainConfig, blockHash, blockNumber, block.BaseFee(), block.Transactions()); err != nil {
			return i, fmt.Errorf("failed to derive receipts data: %v", err)
		}
		// Write all the data out into the database
		rawdb.WriteBody(batch, blockHash, blockNumber, block.Body())
		rawdb.WriteReceipts(batch, blockHash, blockNumber, receipts)
		rawdb.WriteTxLookupEntriesByBlock(batch, block)

		// Write everything belongs to the blocks into the database. So that
		// we can ensure all components of body is completed(body, receipts,
		// tx indexes)
		if batch.ValueSize() >= ethdb.IdealBatchSize {
			if err := batch.Write(); err != nil {
				// A write the database refused is this node's condition, not the peer's:
				// it must not become the errInvalidChain the downloader drops the peer with.
				return 0, wrapLocalCondition(err)
			}
			bytes += batch.ValueSize()
			batch.Reset()
			// Everything up to this block went to disk with the batch that just went out.
			firstPending = i + 1
		}
		stats.processed++
	}
	// Write everything belongs to the blocks into the database. So that
	// we can ensure all components of body is completed(body, receipts,
	// tx indexes)
	if batch.ValueSize() > 0 {
		bytes += batch.ValueSize()
		if err := batch.Write(); err != nil {
			// Same as above: the refusal is this node's, not the peer's.
			return 0, wrapLocalCondition(err)
		}
	}

	// Update the head fast sync block if better
	if !bc.chainmu.TryLock() {
		return 0, ErrChainStopped
	}
	head := blockChain[len(blockChain)-1]
	if td := bc.GetTd(head.Hash(), head.NumberU64()); td != nil { // Rewind may have occurred, skip in that case
		currentSnapBlock := bc.CurrentSnapBlock()
		if bc.GetTd(currentSnapBlock.Hash(), currentSnapBlock.Number.Uint64()).Cmp(td) < 0 {
			rawdb.WriteHeadFastBlockHash(bc.db, head.Hash())
			bc.currentSnapBlock.Store(head.Header())
			headFastBlockGauge.Update(int64(head.NumberU64()))
		}
	}
	bc.chainmu.Unlock()

	context := []interface{}{
		"count", stats.processed, "elapsed", common.PrettyDuration(time.Since(start)),
		"number", head.Number(), "hash", head.Hash(), "age", common.PrettyAge(time.Unix(int64(head.Time()), 0)),
		"size", common.StorageSize(bytes),
	}
	if stats.ignored > 0 {
		context = append(context, []interface{}{"ignored", stats.ignored}...)
	}
	log.Info("Imported new block receipts", context...)

	return 0, nil
}

var lastWrite uint64

// writeBlockWithoutState writes only the block and its metadata to the database,
// but does not write any state. This is used to construct competing side forks
// up to the point where they exceed the canonical total difficulty.
func (bc *BlockChain) writeBlockWithoutState(block *types.Block, td *big.Int) (err error) {
	if bc.insertStopped() {
		return ErrInsertionInterrupted
	}

	batch := bc.db.NewBatch()
	rawdb.WriteTd(batch, block.Hash(), block.NumberU64(), td)
	rawdb.WriteBlock(batch, block)
	if err := batch.Write(); err != nil {
		log.Crit("Failed to write block into disk", "err", err)
	}
	return nil
}

// WriteBlockWithState writes the block and all associated state to the database.
func (bc *BlockChain) WriteBlockWithState(block *types.Block, receipts []*types.Receipt, state *state.StateDB, tradingState *tradingstate.TradingStateDB, lendingState *lendingstate.LendingStateDB) (status WriteStatus, err error) {
	// A closed chain mutex is the local condition InsertChain reports as ErrChainStopped.
	if !bc.chainmu.TryLock() {
		return NonStatTy, ErrChainStopped
	}
	defer bc.chainmu.Unlock()
	return bc.writeBlockWithState(block, receipts, state, tradingState, lendingState)
}

// isGapBlockNumber reports whether num is the gap block of its epoch, at which the masternode
// set for the next epoch is refreshed. It asks exactly what engine_v2 asks in UpdateMasternodes
// (num%Epoch == Epoch-Gap), because the three UpdateM1 call sites - writeBlockWithState,
// writeKnownBlock and reorg - turn a rejection from that engine into a log.Crit: a block this
// predicate accepts and the engine refuses halts the node.
//
// The (num+Gap)%Epoch == 0 form kept before, which engine_v1 stores and loads its snapshots
// with, only agrees with the engine for 0 < Gap <= Epoch: with Gap == 0 it holds at every epoch
// boundary, and with Gap > Epoch, where Epoch-Gap underflows, at offsets the engine cannot
// express. Every configuration in params/config_networks.go uses 0 < Gap < Epoch.
//
// setHeadBeyondRoot used the old form to pick the snapshots a rewind deletes and now asks this
// predicate instead, so a chain with Gap == 0 or Gap > Epoch deletes no snapshot and the entries
// engine_v1 wrote stay in the database. They are keyed by block hash, so a rewound block's
// snapshot is never loaded again: leaked, not wrong.
func (bc *BlockChain) isGapBlockNumber(num uint64) bool {
	if bc.chainConfig.XDPoS == nil {
		return false
	}
	epoch, gap := bc.chainConfig.XDPoS.Epoch, bc.chainConfig.XDPoS.Gap
	return epoch != 0 && gap != 0 && gap <= epoch && num%epoch == epoch-gap
}

// isGapBlock reports whether block is the gap block of its epoch.
func (bc *BlockChain) isGapBlock(block *types.Block) bool {
	return bc.isGapBlockNumber(block.NumberU64())
}

// forkChoiceBeatsHead is the fork-choice rule, in the one place it is written: a higher total
// difficulty than the head's, or an equal one with a higher number. writeBlockWithState must
// ask this function rather than spell the comparison out, or a known block could move the head
// onto a chain an executed block would never be allowed to adopt. The second clause is also the
// reduction of the selfish-mining vulnerability
// (http://www.cs.cornell.edu/~ie53/publications/btcProcFC.pdf).
//
// Upstream go-ethereum has no counterpart: its skipBlock decides whether a known block may be
// skipped from the availability of the snapshot state, not from fork choice.
//
// It takes the two total difficulties rather than a block because every caller already holds
// them. A nil on either side is an unknown total difficulty, which cannot be compared and is
// therefore not beating the head; number 0 is the same case.
func forkChoiceBeatsHead(td, headTd *big.Int, number uint64, head *types.Header) bool {
	if head == nil || headTd == nil || td == nil || number == 0 {
		return false
	}
	if cmp := td.Cmp(headTd); cmp != 0 {
		return cmp > 0
	}
	return number > head.Number.Uint64()
}

// blockTd returns the total difficulty this node stored for block: the one it wrote when it
// executed that block, or nil when it holds no such record.
//
// Both callers pass a block this node already has on disk, so the record they want is the
// block's own, written atomically with its body and receipts (see HasExecutedBlock).
// Recomputing it from the parent's record would read a record this node may have lost, and its
// nil says "cannot be compared" - which forkChoiceBeatsHead cannot tell apart from a block that
// lost fork choice, leaving the head where it is with no trace.
func (bc *BlockChain) blockTd(block *types.Block) *big.Int {
	if block.NumberU64() == 0 {
		return nil
	}
	return bc.GetTd(block.Hash(), block.NumberU64())
}

// isEpochSwitchBlock reports whether block is the epoch switch block of its epoch. A chain
// without XDPoS, and an engine that is not XDPoS, have no epoch switch, which is not an
// error; a failure to decode the header is left to the caller to log.
func (bc *BlockChain) isEpochSwitchBlock(block *types.Block) (bool, error) {
	if bc.chainConfig.XDPoS == nil {
		return false, nil
	}
	engine, ok := bc.Engine().(*XDPoS.XDPoS)
	if !ok {
		return false, nil
	}
	isEpochSwitch, _, err := engine.IsEpochSwitch(block.Header())
	return isEpochSwitch, err
}

// notifyEpochSwitchBlock sends a checkpoint notification when block switches the epoch, so
// that the consensus parameters and the masternode set are refreshed. It is a no-op for
// non-XDPoS chains and for engines that are not XDPoS.
//
// An epoch switch this node cannot read is only logged, never reported as a bad block: no
// block this node stored can fail the read (engine_v2 decodes the same extra fields in
// verifyHeader, outside its fullVerify gate, and engine_v1 never fails it), so reportBlock
// would write a block this node already accepted into the bad-block table.
func (bc *BlockChain) notifyEpochSwitchBlock(block *types.Block) {
	isEpochSwitch, err := bc.isEpochSwitchBlock(block)
	if err != nil {
		log.Error("[notifyEpochSwitchBlock] Error while checking if the incoming block is epoch switch block", "Hash", block.Hash(), "Number", block.Number())
		return
	}
	if isEpochSwitch {
		SignalCheckpoint()
	}
}

// SignalCheckpoint wakes the staking loop without ever blocking the caller. The signal is a
// coalescing wake-up, not a queue: the receiver re-reads the chain head when it runs, so a
// signal already pending covers this epoch switch and dropping this one loses nothing. Every
// sender goes through it - the import paths and reorg hold the chain mutex - so a slow
// receiver must never be able to stall them. See CheckpointCh.
func SignalCheckpoint() {
	select {
	case CheckpointCh <- 1:
	default:
	}
}

// cacheSigningTxs caches the signing transactions of a block that is being
// adopted, so that later epoch lookups do not have to rescan the whole block.
// It is a no-op for non-XDPoS chains and for blocks that do not use TIP signing.
func (bc *BlockChain) cacheSigningTxs(block *types.Block) {
	if bc.chainConfig.XDPoS == nil || !bc.chainConfig.IsTIPSigning(block.Number()) {
		return
	}
	engine, ok := bc.Engine().(*XDPoS.XDPoS)
	if !ok {
		return
	}
	engine.CacheSigningTxs(block.Header().Hash(), block.Transactions())
}

// adoptHead writes block as the canonical head, reorganising the chain first when block does
// not sit directly on top of current. reorg deliberately leaves the new head to its caller, so
// this is the single place that writes the head after a reorg.
//
// The reorg error is returned unwrapped so each caller can classify it: writeBlockWithState
// hands it back and the batch fails, writeKnownBlock wraps it in ErrLocalInsertRefused because
// those blocks are already on disk and were executed before.
//
// critMsg is the caller's own text for the log.Crit below, kept verbatim so the message a
// halted node prints still says which adoption path reached the gap block.
func (bc *BlockChain) adoptHead(block *types.Block, current *types.Header, snap *engine_v2.SnapshotV2, critMsg string) error {
	// A block adopted from disk arrives without a set: the write that stored it wrote the set
	// with its markers, but a rewind can take the snapshot with the head, and this adoption is
	// then the only thing that puts it back. Derive it from the block's own state before the
	// head moves, so a failed derivation still leaves the chain where it was.
	if snap == nil && bc.needsNextEpochSnapshot(block.Number()) {
		statedb, err := bc.StateAt(block.Root())
		if err != nil {
			return fmt.Errorf("failed to open the state of gap block %d (%s) for the masternode update: %w",
				block.NumberU64(), block.Hash().Hex(), err)
		}
		derived, err := bc.nextEpochSnapshotOf(statedb, block.NumberU64(), block.Hash())
		if err != nil {
			return err
		}
		snap = derived
	}
	if block.ParentHash() != current.Hash() {
		if err := bc.reorg(current, block.Header()); err != nil {
			return err
		}
	}
	bc.writeHeadBlock(block, snap)
	// A gap block reaching the head still refreshes the masternode set here unless the batch
	// written just above carried it, which is what needsNextEpochSnapshot reports: the v1 set
	// lives in the checkpoint header extra data, and a v2 set just stored must not be read back
	// out of the head state instead.
	//
	// The head is already persisted, so this failure cannot be rolled back and must halt the
	// node: the next epoch validates against the masternode set, and a missing snapshot is
	// only repaired by Initial -> RepairGapSnapshots on the next start. Retrying is not an
	// option either, the gap block being the head and no longer winning fork choice.
	if bc.isGapBlock(block) && !bc.needsNextEpochSnapshot(block.Number()) {
		if err := bc.UpdateM1At(block.Header()); err != nil {
			log.Crit(critMsg, "number", block.Number, "hash", block.Hash().Hex(), "err", err)
		}
	}
	return nil
}

// writeKnownBlock adopts an already stored and executed block as the chain head,
// reorganising the chain if it does not sit on top of the current head. It is meant for
// batches the import loop stopped on because they were already known: those blocks are on
// disk with their state, so adopting one is a marker update, not a re-import.
//
// The check at the top repeats what "known" has to mean as a defensive assertion, every
// caller reaching here from a classification that already asked HasExecutedBlock under the
// same chain mutex. It is kept because adopting a block this node never executed would move
// the head without Process and ValidateState running on it; a block that fails it is left
// where it is.
//
// The decision asks forkChoiceBeatsHead, the same rule writeBlockWithState applies to
// executed blocks, so a known block can never be adopted under a rule an executed one would
// have lost. A block that loses fork choice is simply not adopted and not an error. A head
// this node holds no record for is different: the comparison cannot be made at all, so it is
// reported as the local condition headTd raises instead of leaving the head behind.
//
// Upstream go-ethereum has a helper of the same name but writes the head unconditionally:
// here the block must first win fork choice, because a batch can be re-delivered on a branch
// that must not become canonical.
//
// promoted reports whether this adoption put the block on the canonical chain for the first
// time, which decides whether its logs still have to be delivered: a block that was canonical
// before (a rollback re-import) already had them sent, one that was not (a promoted fork)
// never did. adopted is the stored block that became the head, or nil when the chain does not
// adopt this batch: a block hash covers only its header, so a batch can carry any body under
// the header of a stored block, and callers must announce the block this node holds.
func (bc *BlockChain) writeKnownBlock(block *types.Block) (adopted *types.Block, promoted bool, err error) {
	// The batch, single-block and executed paths all answer this before reaching here; the one
	// caller that does not is insertSideChain's adoption of a stored prefix, which is why the
	// check sits here as well: an interrupted chain must not move the head.
	if bc.insertStopped() {
		return nil, false, ErrInsertionInterrupted
	}

	// Assertion, not a decision: both call sites already asked HasExecutedBlock under this
	// same chain mutex, so this can only fire if a third caller is added without that
	// classification step. Kept because the alternative - adopting a block this node holds no
	// execution artifacts for, with Process and ValidateState never running on it - is the
	// shape #2534 was about. HasExecutedBlock narrows HasBlockAndFullState rather than
	// proving execution, so this is a guard against that shape getting wider again, not a
	// guarantee that every adopted block was executed here. A block that fails the check is
	// left where it is, which is what the chain did with every known block above its head
	// before this path existed.
	if !bc.HasExecutedBlock(block.Hash(), block.NumberU64()) {
		// Warn rather than Debug: keeping the head here looks exactly like the stall this
		// adoption path was added to end.
		log.Warn("[writeKnownBlock] refusing to adopt a block this node holds no execution artifacts for",
			"number", block.NumberU64(), "hash", block.Hash(), "root", block.Root())
		return nil, false, nil
	}
	// Adopt the copy this node executed, not the one the batch carried: ValidateBody answers
	// ErrKnownBlock before it compares the body, so the caller's block may carry any body
	// under a stored header, and everything below has to describe the chain this node holds.
	stored := bc.GetBlock(block.Hash(), block.NumberU64())
	if stored == nil {
		// HasExecutedBlock just checked that the block, its state and its receipts are on
		// disk, so this is a pruned or corrupt database rather than a wrong batch.
		log.Warn("[writeKnownBlock] refusing to adopt a block whose body is not on disk",
			"number", block.NumberU64(), "hash", block.Hash())
		return nil, false, nil
	}
	block = stored
	// The marker has to be read before the head moves: reorg rewrites it.
	promoted = bc.GetCanonicalHash(block.NumberU64()) != block.Hash()
	current := bc.CurrentBlock()
	// The total difficulty stored for this very block is read once and reused by the comparison
	// below. It was written with the receipts HasExecutedBlock just checked, so its absence is
	// this node's condition: read as a block that lost fork choice it would leave the head
	// where it is, silently - the stall this adoption path exists to end.
	td := bc.blockTd(block)
	if td == nil {
		return nil, false, storedBlockMissingTdError(block)
	}
	headTd, err := bc.headTd(current)
	if err != nil {
		// The head's record is missing, so the comparison cannot be made at all: reporting it
		// keeps the same missing record from leaving the head behind silently, as it did on
		// the executed path. insertSideChain adopts a stored prefix through this function.
		return nil, false, err
	}
	if !forkChoiceBeatsHead(td, headTd, block.NumberU64(), current) {
		return nil, false, nil
	}
	if err := bc.adoptHead(block, current, nil, "Fail to update masternodes during writeKnownBlock"); err != nil {
		// The blocks are already on disk and were executed before. A reorg this node refuses
		// - a missing ancestor chain, or the XDPoS committed-block guard - says nothing about
		// the peer that served them, so it must not be turned into a consensus failure by the
		// caller.
		return nil, false, fmt.Errorf("%w: %v", ErrLocalInsertRefused, err)
	}
	// Mirror the head side effects of the canonical import path.
	bc.UpdateBlocksHashCache(block)
	bc.cacheSigningTxs(block)
	bc.notifyEpochSwitchBlock(block)
	bc.futureBlocks.Remove(block.Hash())
	return block, promoted, nil
}

// announceKnownBlock returns the events and logs an adopted known block raises: a ChainEvent
// always, because the head moved, and the block's logs only when it is promoted to the
// canonical chain for the first time (a rollback re-import already delivered them).
//
// Subscribers should therefore treat the two as different: the ChainEvent may repeat, the
// logs never do.
func (bc *BlockChain) announceKnownBlock(block *types.Block, promoted bool) ([]interface{}, []*types.Log) {
	var logs []*types.Log
	if promoted {
		logs = bc.collectLogs(block, false)
	}
	return []interface{}{ChainEvent{block, block.Hash(), logs}}, logs
}

// withChainHeadEvent appends the head event of block, unless the events already carry one: a
// batch raises a single head event, for the highest block that moved the head.
//
// The adoption shape that needs it is the segment with blocks left above it: insertSideChain
// adopts the stored prefix and then imports the rest, and that second import raises its own
// head event for a higher block, which would otherwise move the head twice within one batch.
func withChainHeadEvent(events []interface{}, block *types.Block) []interface{} {
	if block == nil {
		return events
	}
	for _, event := range events {
		if _, ok := event.(ChainHeadEvent); ok {
			return events
		}
	}
	return append(events, ChainHeadEvent{block})
}

// writeBlockWithState writes the block and all associated state to the database,
// but is expects the chain mutex to be held.
func (bc *BlockChain) writeBlockWithState(block *types.Block, receipts []*types.Receipt, state *state.StateDB, tradingState *tradingstate.TradingStateDB, lendingState *lendingstate.LendingStateDB) (status WriteStatus, err error) {
	if bc.insertStopped() {
		return NonStatTy, ErrInsertionInterrupted
	}

	// Calculate the total difficulty of the block
	ptd := bc.GetTd(block.ParentHash(), block.NumberU64()-1)
	if ptd == nil {
		return NonStatTy, consensus.ErrUnknownAncestor
	}
	// Make sure no inconsistent state is leaked during insertion
	externTd := new(big.Int).Add(block.Difficulty(), ptd)

	// The head's total difficulty is read, not assumed away: a record this node is missing
	// is a local condition, not a comparison this block lost. It is read here, before
	// anything is written, for the same reason the parent's total difficulty is asked for
	// above: a missing record must fail the import before the block, its receipts and its
	// state are on disk rather than after.
	currentBlock := bc.CurrentBlock()
	headTd, err := bc.headTd(currentBlock)
	if err != nil {
		return NonStatTy, err
	}

	// Decide whether this block will replace the head before anything is
	// written, because the next-epoch snapshot below must fail before the block
	// reaches the database: a stored block whose head was never advanced is read
	// back as already known by the insertion paths and would not be applied
	// again.
	//
	// The rule itself lives in forkChoiceBeatsHead so that the known-block path adopts a
	// chain exactly when an executed block would, including the same-difficulty split by
	// block number that reduces the vulnerability to selfish mining.
	// Please refer to http://www.cs.cornell.edu/~ie53/publications/btcProcFC.pdf
	canonical := forkChoiceBeatsHead(externTd, headTd, block.NumberU64(), currentBlock)

	// Derive the next-epoch snapshot of a v2 gap block from the state that was
	// just executed, still before the block batch is built: a failed derivation
	// returns here with nothing flushed, so the chain is left exactly where it
	// was instead of pointing at a gap block without a snapshot.
	//
	// The state passed in can no longer serve reads once it is committed below,
	// which is why the derivation happens now rather than after the commit.
	var snap *engine_v2.SnapshotV2
	if canonical && bc.needsNextEpochSnapshot(block.Number()) {
		derived, err := bc.nextEpochSnapshotOf(state, block.NumberU64(), block.Hash())
		if err != nil {
			return NonStatTy, err
		}
		snap = derived
	}

	// Irrelevant of the canonical status, write the block itself to the database.
	//
	// Note all the components of block(td, hash->number map, header, body, receipts)
	// should be written atomically. BlockBatch is used for containing all components.
	blockBatch := bc.db.NewBatch()
	rawdb.WriteTd(blockBatch, block.Hash(), block.NumberU64(), externTd)
	rawdb.WriteBlock(blockBatch, block)
	rawdb.WriteReceipts(blockBatch, block.Hash(), block.NumberU64(), receipts)
	rawdb.WritePreimages(blockBatch, state.Preimages())
	// Keep this commit before bc.reorg below and before writeHeadBlock: the head
	// must never point at a block whose body is not on disk yet.
	if err := blockBatch.Write(); err != nil {
		log.Crit("Failed to write block into disk", "err", err)
	}
	// Commit all cached state changes into underlying memory database.
	root, err := state.Commit(block.NumberU64(), bc.chainConfig.IsEIP158(block.Number()))
	if err != nil {
		return NonStatTy, err
	}

	tradingRoot := common.Hash{}
	if tradingState != nil {
		tradingRoot, err = tradingState.Commit()
		if err != nil {
			return NonStatTy, err
		}
	}
	lendingRoot := common.Hash{}
	if lendingState != nil {
		lendingRoot, err = lendingState.Commit()
		if err != nil {
			return NonStatTy, err
		}
	}

	engine, _ := bc.Engine().(*XDPoS.XDPoS)
	var tradingTrieDb *trie.Database
	var tradingService utils.TradingService
	var lendingTrieDb *trie.Database
	var lendingService utils.LendingService
	if bc.Config().IsTIPXDCXReceiver(block.Number()) && bc.chainConfig.XDPoS != nil && block.NumberU64() > bc.chainConfig.XDPoS.Epoch && engine != nil {
		tradingService = engine.GetXDCXService()
		if tradingService != nil {
			tradingTrieDb = tradingService.GetStateCache().TrieDB()
		}
		lendingService = engine.GetLendingService()
		if lendingService != nil {
			lendingTrieDb = lendingService.GetStateCache().TrieDB()
		}
	}

	// If we're running an archive node, always flush
	if bc.cacheConfig.TrieDirtyDisabled {
		if err := bc.triedb.Commit(root, false); err != nil {
			return NonStatTy, err
		}
		if tradingTrieDb != nil {
			if err := tradingTrieDb.Commit(tradingRoot, false); err != nil {
				return NonStatTy, err
			}
		}
		if lendingTrieDb != nil {
			if err := lendingTrieDb.Commit(lendingRoot, false); err != nil {
				return NonStatTy, err
			}
		}
	} else {
		// Full but not archive node, do proper garbage collection
		bc.triedb.Reference(root, common.Hash{}) // metadata reference to keep trie alive
		bc.triegc.Push(root, -int64(block.NumberU64()))
		if tradingTrieDb != nil {
			tradingTrieDb.Reference(tradingRoot, common.Hash{})
		}
		if tradingService != nil {
			tradingService.GetTriegc().Push(tradingRoot, -int64(block.NumberU64()))
		}
		if lendingTrieDb != nil {
			lendingTrieDb.Reference(lendingRoot, common.Hash{})
		}
		if lendingService != nil {
			lendingService.GetTriegc().Push(lendingRoot, -int64(block.NumberU64()))
		}
		if current := block.NumberU64(); current > TriesInMemory {
			// Find the next state trie we need to commit
			chosen := current - TriesInMemory
			// Only write to disk if we exceeded our memory allowance *and* also have at
			// least a given number of tries gapped.
			//
			//if tradingTrieDb != nil {
			//	size = size + tradingTrieDb.Size()
			//}
			//if lendingTrieDb != nil {
			//	size = size + lendingTrieDb.Size()
			//}
			var (
				nodes, imgs = bc.triedb.Size()
				limit       = common.StorageSize(bc.cacheConfig.TrieDirtyLimit) * 1024 * 1024
			)
			if nodes > limit || imgs > 4*1024*1024 {
				bc.triedb.Cap(limit - ethdb.IdealBatchSize)
			}
			if bc.gcproc > bc.cacheConfig.TrieTimeLimit || chosen > lastWrite+TriesInMemory {
				// If the header is missing (canonical chain behind), we're reorging a low
				// diff sidechain. Suspend committing until this operation is completed.
				header := bc.GetHeaderByNumber(chosen)
				if header == nil {
					log.Warn("Reorg in progress, trie commit postponed", "number", chosen)
				} else {
					// If we're exceeding limits but haven't reached a large enough memory gap,
					// warn the user that the system is becoming unstable.
					if chosen < lastWrite+TriesInMemory && bc.gcproc >= 2*bc.cacheConfig.TrieTimeLimit {
						log.Info("State in memory for too long, committing", "time", bc.gcproc, "allowance", bc.cacheConfig.TrieTimeLimit, "optimum", float64(chosen-lastWrite)/TriesInMemory)
					}
					// Flush an entire trie and restart the counters. A refusal is logged
					// rather than returned: the block is already on disk, and what is
					// collected here is an older trie rather than its state, which the
					// chain's forward path never asks for again once lastWrite passes it.
					if err := bc.triedb.Commit(header.Root, true); err != nil {
						log.Error("Failed to flush the trie being collected", "number", chosen, "root", header.Root, "err", err)
					}
					lastWrite = chosen
					bc.gcproc = 0
					if tradingTrieDb != nil && lendingTrieDb != nil {
						b := bc.GetBlock(header.Hash(), current-TriesInMemory)
						author, _ := bc.Engine().Author(b.Header())
						oldTradingRoot, _ := tradingService.GetTradingStateRoot(b, author)
						oldLendingRoot, _ := lendingService.GetLendingStateRoot(b, author)
						if err := tradingTrieDb.Commit(oldTradingRoot, true); err != nil {
							log.Error("Failed to flush the trading state trie", "number", chosen, "root", oldTradingRoot, "err", err)
						}
						if err := lendingTrieDb.Commit(oldLendingRoot, true); err != nil {
							log.Error("Failed to flush the lending state trie", "number", chosen, "root", oldLendingRoot, "err", err)
						}
					}
				}
			}
			// Garbage collect anything below our required write retention
			for !bc.triegc.Empty() {
				root, number := bc.triegc.Pop()
				if uint64(-number) > chosen {
					bc.triegc.Push(root, number)
					break
				}
				bc.triedb.Dereference(root)
			}
			if tradingService != nil {
				for !tradingService.GetTriegc().Empty() {
					tradingRoot, number := tradingService.GetTriegc().Pop()
					if uint64(-number) > chosen {
						tradingService.GetTriegc().Push(tradingRoot, number)
						break
					}
					tradingTrieDb.Dereference(tradingRoot)
				}
			}
			if lendingService != nil {
				for !lendingService.GetTriegc().Empty() {
					lendingRoot, number := lendingService.GetTriegc().Pop()
					if uint64(-number) > chosen {
						lendingService.GetTriegc().Push(lendingRoot, number)
						break
					}
					lendingTrieDb.Dereference(lendingRoot)
				}
			}
		}
	}

	if !canonical {
		status = SideStatTy
	} else {
		status = CanonStatTy
		// adoptHead reorganises the chain and writes the new head together: reorg leaves the
		// head to its caller, so the two must not be split. The next-epoch set derived above
		// travels with the head write inside adoptHead, so a gap block becomes canonical
		// together with the set its epoch switch reads.
		if err := bc.adoptHead(block, currentBlock, snap, "Fail to update masternodes during writeBlockWithState"); err != nil {
			return NonStatTy, err
		}
	}
	// save cache BlockSigners
	bc.cacheSigningTxs(block)
	bc.futureBlocks.Remove(block.Hash())
	return status, nil
}

// addFutureBlock checks if the block is within the max allowed window to get
// accepted for future processing, and returns an error if the block is too far
// ahead and was not added.
func (bc *BlockChain) addFutureBlock(block *types.Block) error {
	max := uint64(time.Now().Unix()) + maxTimeFutureBlocks
	if block.Time() > max {
		// Nothing is wrong with the block, it is this node's clock that cannot place it yet,
		// so the failure must not become an errInvalidChain that drops the peer that served
		// it. The clock is the one local condition a retry repairs, so the sentinel is the
		// retryable one and procFutureBlocks has to keep the block parked.
		return fmt.Errorf("%w: block time %v is more than %ds ahead of the local clock",
			ErrLocalInsertAheadOfClock, block.Time(), maxTimeFutureBlocks)
	}
	bc.futureBlocks.Add(block.Hash(), block)
	return nil
}

// isQueueableImportErr reports whether a batch tail block should be parked in the
// future queue instead of failing the import.
func isQueueableImportErr(err error) bool {
	return errors.Is(err, consensus.ErrUnknownAncestor) || errors.Is(err, consensus.ErrFutureBlock)
}

// queueFutureTail parks the batch tail in the future queue, starting at the given block whose
// verification error err is queueable, and stops at the first block that fails verification
// with a non-queueable error or at the end of the batch. XDPoS v1/v2 (under full verification)
// check the timestamp before the parent lookup, so children of a future block surface as
// ErrFutureBlock; engines that resolve the parent first, or XDPoS without fullVerify, answer
// ErrUnknownAncestor instead, and the loop accepts both.
//
// It returns the block and error that stopped the queueing (stopped/stopErr) and a non-nil
// abortErr when addFutureBlock rejected the enqueue and the import must fail whole. A non-nil
// stopped always comes with a non-nil stopErr: a block left unqueued has passed verification,
// which needs a stored parent - exactly what the block that stopped the queueing cannot have.
//
// Inside insertChain every future block is consumed here, so the sentinel never reaches a
// caller that has to classify it - IsLocalInsertError states the same from the other side.
func (bc *BlockChain) queueFutureTail(it *insertIterator, block *types.Block, err error) (stopped *types.Block, stopErr, abortErr error) {
	for block != nil && isQueueableImportErr(err) {
		if aerr := bc.addFutureBlock(block); aerr != nil {
			return block, err, aerr
		}
		block, err = it.next()
	}
	return block, err, nil
}

// InsertChain attempts to insert the given batch of blocks in to the canonical
// chain or, otherwise, create a fork. If an error is returned it will return
// the index number of the failing block as well an error describing what went
// wrong.
//
// A nil error does not imply every block was written: a tail failing with
// ErrFutureBlock/ErrUnknownAncestor is parked in the future queue and processed later.
//
// A non-nil error does not imply that nothing was written either. The index returned is the
// first block of the batch that did not make it, and the blocks below it have been dealt with
// (imported, skipped as already known, or written as a side entry), their events and logs
// fired with this call. A caller that has to tell a failed batch from one stopped for this
// node's own condition therefore also asks IsLocalInsertError.
//
// After insertion is done, all accumulated events will be fired.
func (bc *BlockChain) InsertChain(chain types.Blocks) (int, error) {
	// Sanity check that we have something meaningful to import
	if len(chain) == 0 {
		return 0, nil
	}

	// Do a sanity check that the provided chain is actually ordered and linked
	for i := 1; i < len(chain); i++ {
		block, prev := chain[i], chain[i-1]
		if block.NumberU64() != prev.NumberU64()+1 || block.ParentHash() != prev.Hash() {
			// Chain broke ancestry, log a messge (programming error) and skip insertion
			log.Error("Non contiguous block insert",
				"number", block.Number(),
				"hash", block.Hash(),
				"parent", block.ParentHash(),
				"prevnumber", prev.Number(),
				"prevhash", prev.Hash())

			return 0, fmt.Errorf("non contiguous insert: item %d is #%d [%x..], item %d is #%d [%x..] (parent [%x..])", i-1, prev.NumberU64(),
				prev.Hash().Bytes()[:4], i, block.NumberU64(), block.Hash().Bytes()[:4], block.ParentHash().Bytes()[:4])
		}
	}

	// Pre-check passed, start the full block imports.
	if !bc.chainmu.TryLock() {
		return 0, ErrChainStopped
	}
	defer bc.chainmu.Unlock()
	n, events, logs, err := bc.insertChain(chain, true)
	bc.PostChainEvents(events, logs)
	return n, err
}

// insertChain is the internal implementation of InsertChain, which assumes that
// 1) chains are contiguous, and 2) The chain mutex is held.
//
// This method is split out so that import batches that require re-injecting
// historical blocks can do so without releasing the lock, which could lead to
// racey behaviour. If a sidechain import is in progress, and the historic state
// is imported, but then new canon-head is added before the actual sidechain
// completes, then the historic state could be pruned again
func (bc *BlockChain) insertChain(chain types.Blocks, verifySeals bool) (int, []interface{}, []*types.Log, error) {
	// If the chain is terminating, don't even bother starting up.
	if bc.insertStopped() {
		// Report the interruption rather than a success: nothing was imported, and the
		// downloader recognises this sentinel and does not blame the peer.
		return 0, nil, nil, ErrInsertionInterrupted
	}

	// Start a parallel signature recovery (signer will fluke on fork transition, minimal perf loss)
	SenderCacher().RecoverFromBlocks(types.MakeSigner(bc.chainConfig, chain[0].Number()), chain)

	// A queued approach to delivering events. This is generally
	// faster than direct delivery and requires much less mutex
	// acquiring.
	var (
		stats         = insertStats{startTime: mclock.Now()}
		events        = make([]interface{}, 0, len(chain))
		lastCanon     *types.Block
		coalescedLogs []*types.Log
	)
	// Start the parallel header verifier
	headers := make([]*types.Header, len(chain))
	seals := make([]bool, len(chain))

	for i, block := range chain {
		headers[i] = block.Header()
		seals[i] = verifySeals
		bc.downloadingBlock.Add(block.Hash(), struct{}{})
	}
	// The marks only keep the fetcher off the blocks this call is importing, so they cover
	// this call and nothing else: a block that left insertChain, imported or not, is not
	// being downloaded any more. Clearing them on the way out is what stops a later
	// delivery of the same block from being answered by the mark alone - insertBlock reads
	// it before anything else and reports success without touching the head, which a block
	// that left this call has no reason to get, and which is enough to keep a head that
	// sits below an already executed block from advancing.
	defer func() {
		for _, block := range chain {
			bc.downloadingBlock.Remove(block.Hash())
		}
	}()
	verifier := consensus.ChainReader(bc)
	if _, ok := bc.engine.(*XDPoS.XDPoS); ok {
		verifier = XDPoS.NewVerifyHeadersChainReader(bc, headers, chain)
	}
	abort, results := bc.engine.VerifyHeaders(verifier, headers, seals)
	defer close(abort)

	// Peek the error for the first block to decide the directing import logic
	it := newInsertIterator(chain, results, bc.validator)

	block, err := it.next()
	switch {
	// First block is pruned, insert as sidechain and reorg only if TD grows enough
	case errors.Is(err, consensus.ErrPrunedAncestor):
		return bc.insertSideChain(block, it, verifySeals)

	// First block is future, shove it (and all children) to the future queue (unknown ancestor)
	case errors.Is(err, consensus.ErrFutureBlock) || (errors.Is(err, consensus.ErrUnknownAncestor) && bc.futureBlocks.Contains(it.first().ParentHash())):
		stopped, stopErr, abortErr := bc.queueFutureTail(it, block, err)
		if abortErr != nil {
			return it.index, events, coalescedLogs, abortErr
		}
		// The queueing stopped at a block that failed verification with a non-queueable
		// error. Record the reject like the tail path below: classifyInsertErr is what says
		// the local conditions and a future timestamp are legitimate states.
		bc.reportBlockIfFault(stopped, stopErr)
		return it.index, events, coalescedLogs, stopErr

	// First block (and state) is known
	//   1. We did a roll-back, and should now do a re-import
	//   2. The block is stored as a sidechain, and is lying about it's stateroot, and passes a stateroot
	// 	    from the canonical chain, which has not been verified.
	case errors.Is(err, ErrKnownBlock):
		// Skip all known blocks that the chain would not adopt anyway, comparing each against
		// the current head. Nothing in the loop moves the head, so the head and its total
		// difficulty are read once for the whole run, and a block's own record once for the
		// two questions asked about it: re-delivering thousands of known blocks would
		// otherwise pay two lookups per block.
		// A head this node holds no record for cannot be compared against, and reading that
		// as "does not beat the head" would silently report every known block as one it would
		// not adopt. The missing record is this node's condition, so it is reported as one.
		head := bc.CurrentBlock()
		headTd, headErr := bc.headTd(head)
		if headErr != nil {
			return it.index, events, coalescedLogs, headErr
		}
		for block != nil && errors.Is(err, ErrKnownBlock) {
			// The block's total difficulty is read once for both questions below: whether it
			// can be compared at all, and whether it wins fork choice.
			td := bc.blockTd(block)
			// blockTd answers nil for two different things: a block this node holds no record
			// for, and the genesis block. The rule below folds both into "does not beat the
			// head", but only the first is this node's condition - report it, and leave the
			// genesis block to the skip the rule gives it.
			if block.NumberU64() != 0 && td == nil {
				return it.index, events, coalescedLogs, storedBlockMissingTdError(block)
			}
			// A block that wins fork choice stops the skip here: the import loop below adopts
			// it with writeKnownBlock and carries on with the rest of the batch.
			if forkChoiceBeatsHead(td, headTd, block.NumberU64(), head) {
				break
			}
			// A known block that loses fork choice now loses it later too - the head only
			// moves forward here - so leaving it parked would have procFutureBlocks re-verify
			// it on every tick. Dropping it is safe: ErrKnownBlock means the block and its
			// state are on disk, so a batch carrying it again adopts it on this very path.
			//
			// Counted above the head only, as in the import loop below: a known block below
			// it is the routine skip of an already canonical block. The meter is what makes a
			// stalled sync visible, so it must not be paid for by every re-delivered range.
			bc.futureBlocks.Remove(block.Hash())
			if block.NumberU64() > head.Number.Uint64() {
				blockKnownNotAdoptedMeter.Mark(1)
			}
			stats.ignored++
			block, err = it.next()
		}
		// A stop of this loop is left to the tail of the import loop below, which reports the
		// block it ended on through the same table; reporting it here as well would write the
		// same bad block twice, since reportBlock overwrites the entry and increments again.
		// A known block that wins fork choice is not skipped: it falls through to the import
		// loop below, which adopts it with writeKnownBlock and carries on with the batch.

	// Some other error occurred, abort
	case err != nil:
		// The table decides whether the block is at fault, as it does for the two queue-stop
		// paths. Behaviourally identical today, but it keeps the "is this a bad block" answer
		// in one place if a local sentinel ever becomes reachable from verification.
		bc.reportBlockIfFault(block, err)
		return it.index, events, coalescedLogs, err
	}

	// Whether this batch has already logged a block it refuses to adopt: the meter counts them,
	// the log names one per batch. See the adoption branch of the import loop.
	notAdoptedWarned := false

	// No validation errors for the first block (or chain prefix skipped)
	for ; block != nil && (err == nil || errors.Is(err, ErrKnownBlock)); block, err = it.next() {
		// If the chain is terminating, stop processing blocks
		if bc.insertStopped() {
			log.Debug("Premature abort during blocks processing")
			// Report the interruption instead of leaving err nil: InterruptInsert documents
			// that insertion methods return ErrInsertionInterrupted, and the caller would
			// otherwise believe the remaining blocks were imported.
			err = ErrInsertionInterrupted
			break
		}
		// If the header is a banned one, straight out abort
		if BadHashes[block.Hash()] {
			bc.reportBlock(block, nil, ErrDenylistedHash)
			return it.index, events, coalescedLogs, ErrDenylistedHash
		}
		// The block and its state are already stored, so re-executing would only reproduce
		// what is on disk. It still has to become the head, but only if it wins the same fork
		// choice an executed block would.
		if errors.Is(err, ErrKnownBlock) {
			log.Debug("Writing previously known block", "number", block.Number(), "hash", block.Hash())
			adoptedBlock, promoted, adoptErr := bc.writeKnownBlock(block)
			if adoptErr != nil {
				return it.index, events, coalescedLogs, adoptErr
			}
			if adoptedBlock == nil {
				// The block is executed and on disk, this node simply does not adopt this
				// branch. The batch still reports success, so the count is the only trace of a
				// sync that keeps delivering ranges without the head moving.
				//
				// Counted above the head only, like the skip loop above: a known block below it
				// is the routine skip of an already canonical block.
				//
				// Drop it from the future queue for the reason the skip loop above gives: a
				// block that loses fork choice now loses it later too.
				bc.futureBlocks.Remove(block.Hash())
				// The head is read once for the fork-choice meter and the log below: the two
				// cannot disagree about which head the batch failed to beat. It is nil only
				// before the genesis block this node stores at construction is in place, when
				// no import path can run; the check is what keeps the log from dereferencing
				// it there.
				if head := bc.CurrentBlock(); head != nil {
					if block.NumberU64() > head.Number.Uint64() {
						blockKnownNotAdoptedMeter.Mark(1)
					}
					// The log tells once per batch what the meter counts per block: a
					// re-delivered range takes this path for every block above the head.
					if !notAdoptedWarned {
						log.Warn("Batch is already imported but does not beat the head",
							"head", head.Number, "batch", block.Number())
						notAdoptedWarned = true
					}
				}
				stats.ignored++
				continue
			}
			// The head has advanced, so consumers of chain events must be notified
			// even for an adopted known block - and with the stored block, not with the
			// one the batch handed in. See writeKnownBlock.
			blockEvents, blockLogs := bc.announceKnownBlock(adoptedBlock, promoted)
			events = append(events, blockEvents...)
			coalescedLogs = append(coalescedLogs, blockLogs...)
			stats.processed++
			lastCanon = adoptedBlock
			continue
		}
		// Retrieve the parent block and it's state to execute on top
		start := time.Now()
		parent := it.previous()
		if parent == nil {
			parent = bc.GetHeader(block.ParentHash(), block.NumberU64()-1)
		}
		// Create a new statedb using the parent block and report an error if it fails.
		//
		// stateErr rather than err: err is the loop's own - the loop condition and the post
		// statement carry it, and the ErrInsertionInterrupted assignment above writes it.
		// The two are different values and have to keep different names.
		statedb, stateErr := state.NewWithChainConfig(parent.Root, bc.stateCache, bc.chainConfig)
		if stateErr != nil {
			return it.index, events, coalescedLogs, stateErr
		}

		// If we have a followup block, run that against the current state to pre-cache
		// transactions and probabilistically some of the account/storage trie nodes.
		var followupInterrupt atomic.Bool
		if bc.cacheConfig.TrieCleanPrefetch {
			if followup, err := it.peek(); followup != nil && err == nil {
				throwaway, _ := state.NewWithChainConfig(parent.Root, bc.stateCache, bc.chainConfig)

				go func(start time.Time, followup *types.Block, throwaway *state.StateDB, interrupt *atomic.Bool) {
					// Disable tracing for prefetcher executions.
					vmCfg := bc.vmConfig
					vmCfg.Tracer = nil
					bc.prefetcher.Prefetch(followup, throwaway, vmCfg, interrupt)

					blockPrefetchExecuteTimer.Update(time.Since(start))
					if interrupt.Load() {
						blockPrefetchInterruptMeter.Mark(1)
					}
				}(time.Now(), followup, throwaway, &followupInterrupt)
			}
		}

		// The traced section of block import.
		res, err := bc.processBlock(block, parent, statedb)
		followupInterrupt.Store(true)
		if err != nil {
			return it.index, events, coalescedLogs, err
		}
		// Report the import stats before returning the various results
		stats.processed++
		stats.usedGas += res.usedGas

		switch res.status {
		case CanonStatTy:
			log.Debug("Inserted new block from downloader", "number", block.Number(), "hash", block.Hash(), "uncles", len(block.Uncles()),
				"txs", len(block.Transactions()), "gas", block.GasUsed(), "elapsed", common.PrettyDuration(time.Since(start)))

			coalescedLogs = append(coalescedLogs, res.logs...)
			events = append(events, ChainEvent{block, block.Hash(), res.logs})
			lastCanon = block

			// Only count canonical blocks for GC processing time
			bc.gcproc += res.procTime
			bc.UpdateBlocksHashCache(block)
		case SideStatTy:
			log.Debug("Inserted forked block from downloader", "number", block.Number(), "hash", block.Hash(), "diff", block.Difficulty(), "elapsed",
				common.PrettyDuration(time.Since(start)), "txs", len(block.Transactions()), "gas", block.GasUsed(), "uncles", len(block.Uncles()))
			events = append(events, ChainSideEvent{block})
			bc.UpdateBlocksHashCache(block)
		}

		dirty, _ := bc.triedb.Size()
		stats.report(chain, it.index, dirty)
		bc.notifyEpochSwitchBlock(block)
	}

	// The loop can also end on a block of its own: the post statement advanced onto the next
	// block of the batch and that block failed header verification or body validation. The loop
	// body only ever sees blocks that passed, so nothing has recorded this one yet. The caller
	// blames the peer for the error the loop ended on, and the block it is blamed for belongs in
	// the bad-block database, not only in what the caller is told about the failure.
	//
	// The guard is what says "the loop ended on a block, on an error": a drained batch ends with
	// a nil block and a nil error, and classifyInsertErr answers no for a known block and for
	// every local sentinel the loop can break on, so those are no-ops here.
	if err != nil && block != nil {
		bc.reportBlockIfFault(block, err)
	}

	// Any blocks remaining here? The only ones we care about are the future ones.
	//
	// Only a future block is parked here, unlike the first-block case of the switch above,
	// which also accepts ErrUnknownAncestor when the parent is itself parked. This gate does
	// not need that case: a batch is contiguous, so chain[i]'s parent is the chain[i-1] that
	// was imported just before it, and the parent lookup cannot fail in the middle of it. A
	// block that cannot be linked here therefore is not a future block, and reporting it is
	// what lets the downloader hold the peer to it.
	if block != nil && errors.Is(err, consensus.ErrFutureBlock) {
		var abortErr error
		block, err, abortErr = bc.queueFutureTail(it, block, err)
		if abortErr != nil {
			return it.index, events, coalescedLogs, abortErr
		}
		// The queueing stopped at a block that failed verification with a non-queueable
		// error. Record the reject like the first-block failure path: classifyInsertErr is
		// what says the local conditions and a future timestamp are legitimate states.
		bc.reportBlockIfFault(block, err)
		// A stop on ErrKnownBlock is reported instead of adopted here, and this tail is the
		// only place the sentinel can leave insertChain: the loop above consumes every known
		// block it meets. That block is on disk with its state and the head sits below it, so
		// the next batch picks it up, takes the ErrKnownBlock case above and adopts it. Adding
		// a second adoption site would buy nothing for a shape the downloader does not produce
		// (its batches are contiguous and split at gap blocks), and the sentinel is local, so
		// the downloader ends the cycle instead of blaming the peer.
		//
		// Reaching this tail takes a block dated ahead of this node's clock, which is what
		// parked the queueing: the file importers replay historical blocks and never meet the
		// shape.
	}

	// Append a single chain head event if we've progressed the chain
	if lastCanon != nil && bc.CurrentBlock().Hash() == lastCanon.Hash() {
		log.Debug("New ChainHeadEvent ", "number", lastCanon.NumberU64(), "hash", lastCanon.Hash())
		events = append(events, ChainHeadEvent{lastCanon})
	}
	// Surface what stopped the batch before the caller turns it into a peer drop: the
	// downloader only logs this at debug level, which used to leave no usable trace.
	//
	// Only a failure the caller will blame on the peer is worth a warning. A local condition
	// says nothing about the blocks, and the downloader ends the cycle for it
	// instead of dropping the peer - the same predicate as the reportBlock exclusion above.
	if err != nil && block != nil && !IsLocalInsertError(err) {
		log.Warn("Blockchain import aborted", "number", block.Number(), "hash", block.Hash(),
			"index", it.index, "batch", len(chain), "err", err)
	}
	return it.index, events, coalescedLogs, err
}

// blockProcessingResult is a summary of block processing
// used for updating the stats.
type blockProcessingResult struct {
	usedGas  uint64
	procTime time.Duration
	status   WriteStatus
	logs     []*types.Log
}

// processBlock executes and validates the given block. If there was no error
// it writes the block and associated state to database.
func (bc *BlockChain) processBlock(block *types.Block, parent *types.Header, statedb *state.StateDB) (_ *blockProcessingResult, blockEndErr error) {
	var (
		err       error
		startTime = time.Now()
	)
	// TODO(daniel): implement CurrentFinalBlock() and CurrentSafeBlock(), ref PR #29189
	if bc.logger != nil && bc.logger.OnBlockStart != nil {
		td := bc.GetTd(block.ParentHash(), block.NumberU64()-1)
		bc.logger.OnBlockStart(tracing.BlockEvent{
			Block: block,
			TD:    td,
			// Finalized: bc.CurrentFinalBlock(),
			// Safe:      bc.CurrentSafeBlock(),
		})
	}
	if bc.logger != nil && bc.logger.OnBlockEnd != nil {
		defer func() {
			bc.logger.OnBlockEnd(blockEndErr)
		}()
	}

	// Process block using the parent state as reference point.
	pstart := time.Now()
	isTIPXDCXReceiver := bc.Config().IsTIPXDCXReceiver(block.Number())
	tradingState, lendingState, err := bc.processTradingAndLendingStates(isTIPXDCXReceiver, block, parent, statedb)
	if err != nil {
		bc.reportBlock(block, nil, err)
		return nil, err
	}
	feeCapacity := statedb.GetTRC21FeeCapacityFromStateWithCache(parent.Root)
	receipts, logs, usedGas, err := bc.processor.Process(block, statedb, tradingState, bc.vmConfig, feeCapacity)
	if err != nil {
		bc.reportBlock(block, receipts, err)
		return nil, err
	}
	ptime := time.Since(pstart)

	vstart := time.Now()
	// Validate the state using the default validator
	err = bc.validator.ValidateState(block, statedb, receipts, usedGas)
	if err != nil {
		bc.reportBlock(block, receipts, err)
		return nil, err
	}
	vtime := time.Since(vstart)
	proctime := time.Since(startTime) // processing + validation

	// Update the metrics touched during block processing and validation
	accountReadTimer.Update(statedb.AccountReads)                                     // Account reads are complete(in processing)
	storageReadTimer.Update(statedb.StorageReads)                                     // Storage reads are complete(in processing)
	accountUpdateTimer.Update(statedb.AccountUpdates)                                 // Account updates are complete(in validation)
	storageUpdateTimer.Update(statedb.StorageUpdates)                                 // Storage updates are complete(in validation)
	accountHashTimer.Update(statedb.AccountHashes)                                    // Account hashes are complete(in validation)
	storageHashTimer.Update(statedb.StorageHashes)                                    // Storage hashes are complete(in validation)
	triedbCommitTimer.Update(statedb.TrieDBCommits)                                   // Triedb commits are complete, we can mark them
	triehash := statedb.AccountHashes + statedb.StorageHashes                         // The time spent on tries hashing
	trieUpdate := statedb.AccountUpdates + statedb.StorageUpdates                     // The time spent on tries update
	blockExecutionTimer.Update(ptime - (statedb.AccountReads + statedb.StorageReads)) // The time spent on EVM processing
	blockValidationTimer.Update(vtime - (triehash + trieUpdate))                      // The time spent on block validation

	// Write the block to the chain and get the status.
	var (
		wstart = time.Now()
		status WriteStatus
	)
	status, err = bc.writeBlockWithState(block, receipts, statedb, tradingState, lendingState)
	if err != nil {
		return nil, err
	}
	// Update the metrics touched during block commit
	accountCommitTimer.Update(statedb.AccountCommits) // Account commits are complete, we can mark them
	storageCommitTimer.Update(statedb.StorageCommits) // Storage commits are complete, we can mark them

	blockWriteTimer.Update(time.Since(wstart) - statedb.AccountCommits - statedb.StorageCommits)
	elapsed := time.Since(startTime) + 1 // prevent zero division
	blockInsertTimer.Update(elapsed)

	return &blockProcessingResult{usedGas: usedGas, procTime: proctime, status: status, logs: logs}, nil
}

// headTd reads the total difficulty of head. A head this node holds no record for is reported as a
// local condition instead of dereferenced - big.Int panics on a nil receiver, and a missing record
// for our own head is this node's condition, not the blocks' - which keeps it out of the
// peer-blame and bad-block paths of the classification.
func (bc *BlockChain) headTd(head *types.Header) (*big.Int, error) {
	if head == nil {
		return nil, localConditionf("no head block")
	}
	td := bc.GetTd(head.Hash(), head.Number.Uint64())
	if td == nil {
		return nil, localConditionf("no total difficulty for head %d (%v)", head.Number.Uint64(), head.Hash())
	}
	return td, nil
}

// insertSideChain is called when an import batch hits upon a pruned ancestor
// error, which happens when a sidechain with a sufficiently old fork-block is
// found.
//
// The method writes all (header-and-body-valid) blocks to disk, then tries to
// switch over to the new chain if the TD exceeded the current chain.
//
// verifySeals is the level the batch was verified at. The blocks the scan never reaches are
// remote data this node holds no verification result for, so they are verified at that same
// level when imported below; only the blocks read back out of the local database are
// re-imported with it off. Every index it returns is relative to the batch the caller handed
// in, never to a segment rebuilt from stored ancestors.
func (bc *BlockChain) insertSideChain(block *types.Block, it *insertIterator, verifySeals bool) (int, []interface{}, []*types.Log, error) {
	var (
		externTd *big.Int
		current  = bc.CurrentBlock().Number.Uint64()
	)
	// The first sidechain block error is already verified to be ErrPrunedAncestor.
	// Since we don't import them here, we expect ErrUnknownAncestor for the remaining
	// ones. Any other errors means that the block is invalid, and should not be written
	// to disk.
	err := consensus.ErrPrunedAncestor
	for ; block != nil && (errors.Is(err, consensus.ErrPrunedAncestor)); block, err = it.next() {
		// Check the canonical state root for that number
		if number := block.NumberU64(); current >= number {
			if canonical := bc.GetBlockByNumber(number); canonical != nil && canonical.Root() == block.Root() {
				// This is most likely a shadow-state attack. When a fork is imported into the
				// database, and it eventually reaches a block height which is not pruned, we
				// just found that the state already exist! This means that the sidechain block
				// refers to a state which already exists in our canon chain.
				//
				// If left unchecked, we would now proceed importing the blocks, without actually
				// having verified the state of the previous blocks.
				log.Warn("Sidechain ghost-state attack detected", "number", block.NumberU64(), "sideroot", block.Root(), "canonroot", canonical.Root())

				// If someone legitimately side-mines blocks, they would still be imported as usual. However,
				// we cannot risk writing unverified blocks to disk when they obviously target the pruning
				// mechanism.
				return it.index, nil, nil, errors.New("sidechain ghost-state attack")
			}
		}
		if externTd == nil {
			externTd = bc.GetTd(block.ParentHash(), block.NumberU64()-1)
			if externTd == nil {
				// Without the parent's total difficulty the segment cannot be weighed
				// against the head, and nothing about the blocks says they are bad: this
				// node simply has no number to compare.
				log.Warn("Sidechain segment has no comparable total difficulty",
					"number", block.NumberU64(), "parent", block.ParentHash(), "index", it.index)
				return it.index, nil, nil, ErrLocalInsertCondition
			}
		}
		externTd = new(big.Int).Add(externTd, block.Difficulty())

		if !bc.HasBlock(block.Hash(), block.NumberU64()) {
			start := time.Now()
			if err := bc.writeBlockWithoutState(block, externTd); err != nil {
				return it.index, nil, nil, err
			}
			log.Debug("Inserted sidechain block", "number", block.Number(), "hash", block.Hash(),
				"diff", block.Difficulty(), "elapsed", common.PrettyDuration(time.Since(start)),
				"txs", len(block.Transactions()), "gas", block.GasUsed(), "uncles", len(block.Uncles()),
				"root", block.Root())
		}
	}
	// At this point, we've written all sidechain blocks to database. Loop ended
	// either on some other error or all were processed.
	//
	// A block that failed verification or body validation is not one of those: report it
	// right away, because rebuilding the prefix below would report a partial import as a
	// success. ErrUnknownAncestor is how a pruned segment ends normally, so it falls through
	// to the reimport below.
	if err != nil && !errors.Is(err, consensus.ErrUnknownAncestor) && !errors.Is(err, ErrKnownBlock) {
		// ErrFutureBlock reaches this branch only for a block dated ahead of this node's clock:
		// both engines compare the timestamp before they look up the parent, so the parent is
		// never consulted. It is not queued either - a side entry is not the future chain - and
		// the clock is this node's, not the peer's. The wrap is ErrLocalInsertAheadOfClock
		// rather than ErrLocalInsertCondition because the clock catches up, so a parked block
		// has to wait rather than be evicted on the first tick.
		//
		// The reject is recorded through the same table as the stops of insertChain: this is the
		// one place a batch ends without asking it, and asking before the wrap is safe.
		bc.reportBlockIfFault(block, err)
		if errors.Is(err, consensus.ErrFutureBlock) {
			return it.index, nil, nil, fmt.Errorf("%w: %w", ErrLocalInsertAheadOfClock, err)
		}
		return it.index, nil, nil, err
	}
	// The scan stopped on a block already on disk with its state. Nothing after it was
	// looked at, so the reimport below would report a partial import as a success: it only
	// rebuilds it.previous() and its ancestors.
	//
	// Adopt the longest prefix of the tail that this node executed as well (it was imported,
	// only the head did not follow) and import the rest on top of it. The prefix cannot come
	// out empty: ErrKnownBlock is what ValidateBody reports for an executed block.
	if errors.Is(err, ErrKnownBlock) {
		stored := it.index
		for stored < len(it.chain) && bc.HasExecutedBlock(it.chain[stored].Hash(), it.chain[stored].NumberU64()) {
			stored++
		}
		if stored == it.index {
			// Defensive guard rather than a state the validator contract can produce. Bailing
			// out is what keeps the head in place here: adopting it.chain[stored-1] would move
			// it onto the block below the one that stopped the scan. A stop like this would
			// say nothing about the blocks, so it must not become an error the downloader
			// turns into an errInvalidChain that drops the peer.
			log.Warn("Sidechain segment stopped on a block that is not stored",
				"number", it.chain[it.index].NumberU64(), "hash", it.chain[it.index].Hash(),
				"index", it.index, "head", bc.CurrentBlock().Number.Uint64())
			return it.index, nil, nil, localConditionf("sidechain segment stopped on a block that is not stored")
		}
		// Adopting the last stored block also moves the head over the blocks reorg rewrites
		// in between, whose logs go out through its rebirth logs.
		adoptedBlock, promoted, adoptErr := bc.writeKnownBlock(it.chain[stored-1])
		if adoptErr != nil {
			return it.index, nil, nil, adoptErr
		}
		var (
			events []interface{}
			logs   []*types.Log
		)
		// The block that moved the head. Its head event is announced once the batch is done:
		// the import below can move the head further, and a batch raises a single head event
		// for the highest block that moved it. See withChainHeadEvent.
		var adoptedHead *types.Block
		if adoptedBlock != nil {
			adoptedHead = adoptedBlock
			log.Debug("Adopted an already imported batch", "number", adoptedHead.NumberU64(), "hash", adoptedHead.Hash())
			// The adopted block moves the head, so it is announced like an adopted known block
			// of the canonical import path; the blocks reorg rewrote are announced by its
			// rebirth logs.
			events, logs = bc.announceKnownBlock(adoptedHead, promoted)
		} else {
			// Not an error: the blocks are on disk and this node simply does not adopt this
			// branch. The batch still reports success and the head stays where it is, so the
			// count has to be visible - above the head only, like the skip loop of the
			// canonical import path.
			if head := bc.CurrentBlock(); head != nil && it.chain[stored-1].NumberU64() > head.Number.Uint64() {
				blockKnownNotAdoptedMeter.Mark(1)
			}
			log.Warn("Batch is already imported but does not beat the head",
				"head", bc.CurrentBlock().Number, "batch", it.chain[stored-1].Number())
		}
		if stored < len(it.chain) {
			// Nothing above the stored prefix was looked at yet, and the block the scan stopped
			// on has its state, so the rest executes on top of it like any other batch. These
			// blocks come from the batch the caller handed in and the scan pulled no verification
			// result for them, so they are verified at that batch's level: importing them with it
			// off would let a block through the engine knows to reject.
			n, moreEvents, moreLogs, err := bc.insertChain(it.chain[stored:], verifySeals)
			events = append(events, moreEvents...)
			logs = append(logs, moreLogs...)
			if err != nil {
				// The sub-batch counts from it.chain[stored:]; map the failing index back to the
				// batch the caller handed in.
				return stored + n, withChainHeadEvent(events, adoptedHead), logs, err
			}
		}
		// The whole batch was consumed: the stored prefix ended in the adopted block and the
		// rest was imported on top of it, so the index is the batch length.
		return len(it.chain), withChainHeadEvent(events, adoptedHead), logs, nil
	}
	// If the externTd was larger than our local TD, we now need to reimport the previous
	// blocks to regenerate the required state
	localTd, localErr := bc.headTd(bc.CurrentBlock())
	if localErr != nil {
		return it.index, nil, nil, localErr
	}
	if localTd.Cmp(externTd) > 0 {
		log.Info("Sidechain written to disk", "start", it.first().NumberU64(), "end", it.previous().Number, "sidetd", externTd, "localtd", localTd)
		return it.index, nil, nil, err
	}
	// Gather all the sidechain hashes (full blocks may be memory heavy)
	var (
		hashes  []common.Hash
		numbers []uint64
	)
	parent := it.previous()
	for parent != nil && !bc.HasState(parent.Root) {
		hashes = append(hashes, parent.Hash())
		numbers = append(numbers, parent.Number.Uint64())

		parent = bc.GetHeader(parent.ParentHash, parent.Number.Uint64()-1)
	}
	if parent == nil {
		// The numbers this node is missing, not the blocks, are what stopped the walk, so the
		// failure is local for the same reason the empty segment above is.
		return it.index, nil, nil, localConditionf("segment has no stored ancestor")
	}
	// Import all the pruned blocks to make the state available
	var (
		blocks []*types.Block
		memory uint64
	)
	for i := len(hashes) - 1; i >= 0; i-- {
		// Append the next block to our batch
		block := bc.GetBlock(hashes[i], numbers[i])

		blocks = append(blocks, block)
		memory += block.Size()

		// If memory use grew too large, import and continue. Sadly we need to discard
		// all raised events and logs from notifications since we're too heavy on the
		// memory here.
		if len(blocks) >= 2048 || memory > 64*1024*1024 {
			log.Info("Importing heavy sidechain segment", "blocks", len(blocks), "start", blocks[0].NumberU64(), "end", block.NumberU64())
			// insertChain also reports a block that fails verification or body
			// validation in the middle of the segment: abort the sidechain import
			// instead of continuing with a state that can only be rebuilt partially.
			if _, _, _, err := bc.insertChain(blocks, false); err != nil {
				// The index handed back is the batch's, not the re-imported segment's:
				// the segment is rebuilt from stored ancestors, so it has no offset into
				// the batch. it.index is the first block this batch has not consumed.
				return it.index, nil, nil, err
			}
			blocks, memory = blocks[:0], 0

			// If the chain is terminating, stop processing blocks
			if bc.insertStopped() {
				log.Debug("Abort during blocks processing")
				// Report the interruption instead of a success, see the entry guard of
				// insertChain: the rest of the segment was not imported. Same index as
				// the failure above, for the same reason.
				return it.index, nil, nil, ErrInsertionInterrupted
			}
		}
	}
	if len(blocks) > 0 {
		log.Info("Importing sidechain segment", "start", blocks[0].NumberU64(), "end", blocks[len(blocks)-1].NumberU64())
		// The error of a partially imported segment is propagated as well, see the
		// comment on the heavy segment import above. The index is the batch's for the
		// same reason as there: the segment is rebuilt from stored ancestors, so its own
		// offset says nothing about where this batch stopped.
		_, events, logs, err := bc.insertChain(blocks, false)
		if err != nil {
			return it.index, nil, nil, err
		}
		// Unlike the heavy chunks above, the last segment keeps its events and logs: it is
		// the end of this batch, not a chunk dropped to stay within the memory allowance.
		return it.index, events, logs, nil
	}
	return it.index, nil, nil, nil
}

func (bc *BlockChain) InsertBlock(block *types.Block) error {
	events, logs, err := bc.insertBlock(block)
	bc.PostChainEvents(events, logs)
	return err
}

func (bc *BlockChain) PrepareBlock(block *types.Block) (err error) {
	defer log.Debug("Done prepare block ", "number", block.NumberU64(), "hash", block.Hash(), "validator", block.Header().Validator, "err", err)
	// The caches are keyed by HashNoValidator, not by Hash: the result of preparing a block
	// depends on its header alone, and XDPoS signs the header with a validator signature
	// that getResultBlock and insertBlock both take off before they look a result up. Asking
	// by Hash here would miss every entry those two write.
	if _, ok := bc.resultProcess.Get(block.HashNoValidator()); ok {
		log.Debug("Stop prepare a block because the result cached", "number", block.NumberU64(), "hash", block.Hash(), "validator", block.Header().Validator)
		return nil
	}
	if _, ok := bc.calculatingBlock.Get(block.HashNoValidator()); ok {
		log.Debug("Stop prepare a block because inserting", "number", block.NumberU64(), "hash", block.Hash(), "validator", block.Header().Validator)
		return nil
	}
	err = bc.engine.VerifyHeader(bc, block.Header(), false)
	if err != nil {
		return err
	}
	// The events of the pruned ancestors this call had to re-import belong to this call as
	// well: the segment can promote one of those stored ancestors to the head before a later
	// block of it fails, and a caller that only returned the error would leave subscribers
	// following the head on a head the chain has already left. Same contract as the insertion
	// paths, and empty for every other path, the rebuild being the only source of them.
	result, prepareEvents, prepareLogs, err := bc.getResultBlock(block, false)
	bc.PostChainEvents(prepareEvents, prepareLogs)
	switch err {
	case nil:
		// Stored under the same key getResultBlock and insertBlock look a prepared result up
		// with, so that the precomputation this function exists for is actually reused.
		bc.resultProcess.Add(block.HashNoValidator(), result)
		return nil
	case ErrKnownBlock:
		// Benign: the block (and its state) is already on disk, so there is nothing to
		// prepare. getResultBlock answers the same when the head already sits at or above
		// this block (see its ErrKnownBlock case), which is the same "nothing to prepare"
		// answer; insertBlock does not swallow it.
		return nil
	case ErrStopPreparingBlock:
		log.Debug("Stop prepare a block because calculating", "number", block.NumberU64(), "hash", block.Hash(), "validator", block.Header().Validator)
		return nil
	default:
		return err
	}
}

// stampedResultWithBlock returns a copy of a result whose receipts and logs are stamped
// with the hash of the block it is reused for. A result is prepared from the block as it
// was propagated, before XDPoS adds the validator signature - which is why the caches are
// keyed by HashNoValidator - and the signature is part of the hash the block is inserted
// under. Reusing a result as it was computed would hence publish the pre-signature hash to
// every subscriber of its logs, and that block is never written anywhere. The cached result
// is shared with every insert that reuses it, so it is copied instead of being stamped: the
// hash it is inserted under is the only thing two blocks sharing the key differ in, and
// stamping the entry in place would let a second insertion overwrite the hash the first one
// publishes - and restamp the logs a subscriber already holds.
func stampedResultWithBlock(result *ResultProcessBlock, block *types.Block) *ResultProcessBlock {
	hash := block.Hash()
	stamped := *result
	stamped.receipts = make(types.Receipts, len(result.receipts))
	// The logs a result publishes are the very objects held by its receipts, which
	// ProcessBlockNoValidator fills as receipt.Logs. Rebuilding the slice out of the copied
	// receipts keeps that aliasing, so one pass over the receipts covers the logs as well.
	stamped.logs = make([]*types.Log, 0, len(result.logs))
	for i, receipt := range result.receipts {
		copied := *receipt
		copied.BlockHash = hash
		copied.Logs = make([]*types.Log, len(receipt.Logs))
		for j, receiptLog := range receipt.Logs {
			copiedLog := *receiptLog
			copiedLog.BlockHash = hash
			copied.Logs[j] = &copiedLog
			stamped.logs = append(stamped.logs, &copiedLog)
		}
		stamped.receipts[i] = &copied
	}
	return &stamped
}

func (bc *BlockChain) getResultBlock(block *types.Block, verifiedM2 bool) (*ResultProcessBlock, []interface{}, []*types.Log, error) {
	// The events and logs of the pruned ancestors this call had to re-import to make the
	// block calculable. They are handed back to the caller rather than dropped: the
	// segment can promote one of those stored ancestors to the head before a later block
	// of it fails, and the head event of that movement has to reach the subscribers even
	// though this call fails. geth discards them here - only the outermost InsertChain
	// posts events - which loses the head as well.
	var nestedEvents []interface{}
	var nestedLogs []*types.Log
	var calculatedBlock *CalculatedBlock
	if verifiedM2 {
		if result, ok := bc.resultProcess.Get(block.HashNoValidator()); ok {
			log.Debug("Get result block from cache ", "number", block.NumberU64(), "hash", block.Hash(), "hash no validator", block.HashNoValidator())
			return stampedResultWithBlock(result, block), nil, nil, nil
		}
		log.Debug("Not found cache prepare block ", "number", block.NumberU64(), "hash", block.Hash(), "validator", block.HashNoValidator())
		if calculatedBlock, _ := bc.calculatingBlock.Get(block.HashNoValidator()); calculatedBlock != nil {
			calculatedBlock.stop.Store(true)
		}
	}
	calculatedBlock = &CalculatedBlock{block: block}
	bc.calculatingBlock.Add(block.HashNoValidator(), calculatedBlock)
	// Start the parallel header verifier
	// If the chain is terminating, stop processing blocks
	if bc.insertStopped() {
		log.Debug("Premature abort during blocks processing")
		return nil, nil, nil, ErrInsertionInterrupted
	}
	// If the header is a banned one, straight out abort
	if BadHashes[block.Hash()] {
		bc.reportBlock(block, nil, ErrDenylistedHash)
		return nil, nil, nil, ErrDenylistedHash
	}
	// Wait for the block's verification to complete
	bstart := time.Now()
	err := bc.validator.ValidateBody(block)
	switch {
	case errors.Is(err, ErrKnownBlock):
		// Block and state both already known. However if the current block is below
		// this number we did a rollback and we should reimport it nonetheless.
		if bc.CurrentBlock().Number.Uint64() >= block.NumberU64() {
			return nil, nil, nil, ErrKnownBlock
		}
	case errors.Is(err, consensus.ErrPrunedAncestor):
		// Block competing with the canonical chain, store in the db, but don't process
		// until the competitor TD goes above the canonical TD. The competitor's total
		// difficulty is read first: it is the number this comparison is about.
		parentTd := bc.GetTd(block.ParentHash(), block.NumberU64()-1)
		if parentTd == nil {
			// big.Int.Add dereferences its operands, so a parent whose total difficulty
			// is not stored used to panic here instead of failing the call. The record
			// lives in this node rather than in the block, so the failure is reported as
			// a local condition: a bare error would have the classification blame the
			// blocks for it and hold the peer to it.
			return nil, nil, nil, parentMissingTdError(block)
		}
		externTd := new(big.Int).Add(parentTd, block.Difficulty())

		localTd, localErr := bc.headTd(bc.CurrentBlock())
		if localErr != nil {
			return nil, nil, nil, localErr
		}
		if localTd.Cmp(externTd) > 0 {
			return nil, nil, nil, err
		}
		// Competitor chain beat canonical, gather all blocks from the common ancestor
		var winner []*types.Block

		parent := bc.GetBlock(block.ParentHash(), block.NumberU64()-1)
		if parent == nil {
			return nil, nil, nil, fmt.Errorf("fail to get parent block at number: %v, hash: %v", block.NumberU64()-1, block.ParentHash())
		}
		for !bc.HasFullState(parent) {
			winner = append(winner, parent)
			parent = bc.GetBlock(parent.ParentHash(), parent.NumberU64()-1)
		}
		// fix issue #1765, return at once if winner is empty
		if len(winner) == 0 {
			return nil, nil, nil, errors.New("winner is empty")
		}
		for j := 0; j < len(winner)/2; j++ {
			winner[j], winner[len(winner)-1-j] = winner[len(winner)-1-j], winner[j]
		}
		log.Debug("Number block need calculated again", "number", block.NumberU64(), "hash", block.Hash().Hex(), "winners", len(winner))
		// Import all the pruned blocks to make the state available. This writes the chain -
		// the segment is executed and the head it produces is adopted - so it takes the same
		// mutex the import entry points take: neither caller of getResultBlock holds it yet,
		// PrepareBlock never taking it and insertBlock taking it only afterwards.
		// During reorg, we use verifySeals=false
		// insertChain reports blocks failing in the middle of the segment as well, and
		// the block cannot be calculated on a torn state, so the error is propagated.
		// It is returned unwrapped so that the callers see the original sentinel.
		// Its events and logs are kept out of the local scope on purpose: the segment can
		// move the head, and the caller has to be able to post them whether or not this
		// call gets past the error below.
		if !bc.chainmu.TryLock() {
			return nil, nil, nil, ErrChainStopped
		}
		_, nestedEvents, nestedLogs, err = bc.insertChain(winner, false)
		bc.chainmu.Unlock()
		if err != nil {
			return nil, nestedEvents, nestedLogs, err
		}
	case err != nil:
		// The table decides whether the block is at fault, as it does at every other stop of
		// the insertion paths: a ValidateBody failure is the block's, so it is reported.
		bc.reportBlockIfFault(block, err)
		return nil, nil, nil, err
	}
	var parent = bc.GetHeader(block.ParentHash(), block.NumberU64()-1)
	// Create a new statedb using the parent block and report an error if it fails.
	statedb, err := state.NewWithChainConfig(parent.Root, bc.stateCache, bc.chainConfig)
	if err != nil {
		return nil, nestedEvents, nestedLogs, err
	}
	// Process block using the parent state as reference point.
	isTIPXDCX := bc.Config().IsTIPXDCX(block.Number())
	tradingState, lendingState, err := bc.processTradingAndLendingStates(isTIPXDCX, block, parent, statedb)
	if err != nil {
		bc.reportBlock(block, nil, err)
		return nil, nestedEvents, nestedLogs, err
	}
	feeCapacity := statedb.GetTRC21FeeCapacityFromStateWithCache(parent.Root)
	receipts, logs, usedGas, err := bc.processor.ProcessBlockNoValidator(calculatedBlock, statedb, tradingState, bc.vmConfig, feeCapacity)
	process := time.Since(bstart)
	if err != nil {
		if !errors.Is(err, ErrStopPreparingBlock) {
			bc.reportBlock(block, receipts, err)
		}
		return nil, nestedEvents, nestedLogs, err
	}
	// Validate the state using the default validator
	err = bc.Validator().ValidateState(block, statedb, receipts, usedGas)
	if err != nil {
		bc.reportBlock(block, receipts, err)
		return nil, nestedEvents, nestedLogs, err
	}
	proctime := time.Since(bstart)
	log.Debug("Calculate new block", "number", block.Number(), "hash", block.Hash(), "uncles", len(block.Uncles()),
		"txs", len(block.Transactions()), "gas", block.GasUsed(), "elapsed", common.PrettyDuration(time.Since(bstart)), "process", process)
	return &ResultProcessBlock{receipts: receipts, logs: logs, state: statedb, tradingState: tradingState, lendingState: lendingState, proctime: proctime, usedGas: usedGas}, nestedEvents, nestedLogs, nil
}

// UpdateBlocksHashCache update BlocksHashCache by block number
func (bc *BlockChain) UpdateBlocksHashCache(block *types.Block) []common.Hash {
	blockNumber := block.Number().Uint64()
	cached, ok := bc.blocksHashCache.Get(blockNumber)

	if ok {
		if slices.Contains(cached, block.Hash()) {
			return cached
		}
		hashArr := cached
		hashArr = append(hashArr, block.Hash())
		bc.blocksHashCache.Remove(blockNumber)
		bc.blocksHashCache.Add(blockNumber, hashArr)
		return hashArr
	}

	hashArr := []common.Hash{
		block.Hash(),
	}
	bc.blocksHashCache.Add(blockNumber, hashArr)
	return hashArr
}

// blockAlreadyImported reports whether the import can be skipped for the block: the block
// and the state execution leaves behind are both on disk for it.
func (bc *BlockChain) blockAlreadyImported(block *types.Block) bool {
	return bc.HasBlockAndFullState(block.Hash(), block.NumberU64())
}

// insertChain will execute the actual chain insertion and event aggregation. The
// only reason this method exists as a separate one is to make locking cleaner
// with deferred statements.
func (bc *BlockChain) insertBlock(block *types.Block) ([]interface{}, []*types.Log, error) {
	var (
		stats         = insertStats{startTime: mclock.Now()}
		events        = make([]interface{}, 0, 1)
		coalescedLogs []*types.Log
	)
	if _, ok := bc.downloadingBlock.Get(block.Hash()); ok {
		log.Debug("Stop fetcher a block because downloading", "number", block.NumberU64(), "hash", block.Hash())
		return events, coalescedLogs, nil
	}
	result, blockEvents, blockLogs, err := bc.getResultBlock(block, true)
	// The events of the pruned ancestors that had to be re-imported belong to this call too,
	// and are posted on the failing path as well: a segment that promoted a stored ancestor
	// to the head before failing has moved the head.
	events = append(events, blockEvents...)
	coalescedLogs = append(coalescedLogs, blockLogs...)
	if err != nil {
		return events, coalescedLogs, err
	}
	defer bc.resultProcess.Remove(block.HashNoValidator())
	bc.wg.Add(1)
	defer bc.wg.Done()
	// Write the block to the chain and get the status.
	if !bc.chainmu.TryLock() {
		// A closed mutex means Stop, and the rebuild above may have moved the head: the
		// events go back like they do on the interrupted branch below.
		return events, coalescedLogs, ErrChainStopped
	}
	defer bc.chainmu.Unlock()
	if bc.blockAlreadyImported(block) {
		return events, coalescedLogs, nil
	}
	status, err := bc.writeBlockWithState(block, result.receipts, result.state, result.tradingState, result.lendingState)

	if err != nil {
		return events, coalescedLogs, err
	}
	switch status {
	case CanonStatTy:
		log.Debug("Inserted new block from fetcher", "number", block.Number(), "hash", block.Hash(), "uncles", len(block.Uncles()),
			"txs", len(block.Transactions()), "gas", block.GasUsed(), "elapsed", common.PrettyDuration(time.Since(block.ReceivedAt)))
		coalescedLogs = append(coalescedLogs, result.logs...)
		events = append(events, ChainEvent{block, block.Hash(), result.logs})
		// Only count canonical blocks for GC processing time
		bc.gcproc += result.proctime
		bc.UpdateBlocksHashCache(block)
	case SideStatTy:
		log.Debug("Inserted forked block from fetcher", "number", block.Number(), "hash", block.Hash(), "diff", block.Difficulty(), "elapsed",
			common.PrettyDuration(time.Since(block.ReceivedAt)), "txs", len(block.Transactions()), "gas", block.GasUsed(), "uncles", len(block.Uncles()))
		blockInsertTimer.Update(result.proctime)
		events = append(events, ChainSideEvent{block})
		bc.UpdateBlocksHashCache(block)
	}
	stats.processed++
	stats.usedGas += result.usedGas
	dirty, _ := bc.triedb.Size()
	stats.report(types.Blocks{block}, 0, dirty)
	bc.notifyEpochSwitchBlock(block)
	// Append a single chain head event if we've progressed the chain
	if status == CanonStatTy && bc.CurrentBlock().Hash() == block.Hash() {
		events = append(events, ChainHeadEvent{block})
		log.Debug("New ChainHeadEvent from fetcher ", "number", block.NumberU64(), "hash", block.Hash())
	}
	return events, coalescedLogs, nil
}

// collectLogs collects the logs that were generated or removed during
// the processing of a block. These logs are later announced as deleted or reborn.
func (bc *BlockChain) collectLogs(b *types.Block, removed bool) []*types.Log {
	receipts := rawdb.ReadRawReceipts(bc.db, b.Hash(), b.NumberU64())
	if err := receipts.DeriveFields(bc.chainConfig, b.Hash(), b.NumberU64(), b.BaseFee(), b.Transactions()); err != nil {
		log.Error("Failed to derive block receipts fields", "hash", b.Hash(), "number", b.NumberU64(), "err", err)
	}

	var logs []*types.Log
	for _, receipt := range receipts {
		for _, log := range receipt.Logs {
			if removed {
				log.Removed = true
			}
			logs = append(logs, log)
		}
	}
	return logs
}

// reorg takes two blocks, an old chain and a new chain and will reconstruct the
// blocks and inserts them to be part of the new canonical chain and accumulates
// potential missing transactions and post an event about them.
//
// The new head block is deliberately not processed here: the caller has to write it with
// writeHeadBlock once reorg returns successfully, and must not write it a second time.
// adoptHead is the single caller that does so today.
//
// A failed reorg can leave the head on one of the blocks it promoted: the forward loop writes
// the head of every block it walks past, so a later block whose body this node does not hold
// (errInvalidNewChain) returns with the head marker still on the previous one. That block is on
// the new chain and this node holds it, so the head is not corrupt - it is simply not the one
// the caller asked to adopt, and no head event is raised for it.
func (bc *BlockChain) reorg(oldHead, newHead *types.Header) error {
	log.Warn("Reorg", "OldHash", oldHead.Hash().Hex(), "OldNum", oldHead.Number, "NewHash", newHead.Hash().Hex(), "NewNum", newHead.Number)

	var (
		newChain    []*types.Header
		oldChain    []*types.Header
		commonBlock *types.Header
	)

	// Reduce the longer chain to the same number as the shorter one
	if oldHead.Number.Uint64() > newHead.Number.Uint64() {
		// Old chain is longer, gather all transactions and logs as deleted ones
		for ; oldHead != nil && oldHead.Number.Uint64() != newHead.Number.Uint64(); oldHead = bc.GetHeader(oldHead.ParentHash, oldHead.Number.Uint64()-1) {
			oldChain = append(oldChain, oldHead)
		}
	} else {
		// New chain is longer, stash all blocks away for subsequent insertion
		for ; newHead != nil && newHead.Number.Uint64() != oldHead.Number.Uint64(); newHead = bc.GetHeader(newHead.ParentHash, newHead.Number.Uint64()-1) {
			newChain = append(newChain, newHead)
		}
	}
	if oldHead == nil {
		return errInvalidOldChain
	}
	if newHead == nil {
		return errInvalidNewChain
	}

	// Both sides of the reorg are at the same number, reduce both until the common
	// ancestor is found
	for {
		// If the common ancestor was found, bail out
		if oldHead.Hash() == newHead.Hash() {
			commonBlock = oldHead
			break
		}
		// Remove an old block as well as stash away a new block
		oldChain = append(oldChain, oldHead)
		newChain = append(newChain, newHead)

		// Step back with both chains
		oldHead = bc.GetHeader(oldHead.ParentHash, oldHead.Number.Uint64()-1)
		if oldHead == nil {
			return errInvalidOldChain
		}
		newHead = bc.GetHeader(newHead.ParentHash, newHead.Number.Uint64()-1)
		if newHead == nil {
			return errInvalidNewChain
		}
	}

	// Ensure XDPoS engine committed block will be not reverted
	if xdpos, ok := bc.Engine().(*XDPoS.XDPoS); ok {
		latestCommittedBlock := xdpos.EngineV2.GetLatestCommittedBlockInfo()
		if latestCommittedBlock != nil {
			cmp := commonBlock.Number.Cmp(latestCommittedBlock.Number)
			if cmp < 0 {
				for _, oldBlock := range oldChain {
					if oldBlock.Number.Cmp(latestCommittedBlock.Number) == 0 {
						if oldBlock.Hash() != latestCommittedBlock.Hash {
							log.Error("Impossible reorg, please file an issue", "OldNum", oldBlock.Number, "OldHash", oldBlock.Hash().Hex(), "LatestCommittedHash", latestCommittedBlock.Hash.Hex())
						} else {
							log.Warn("Stop reorg, blockchain is under forking attack", "OldCommittedNum", oldBlock.Number, "OldCommittedHash", oldBlock.Hash().Hex())
							return fmt.Errorf("stop reorg, blockchain is under forking attack. OldCommitted num %d, hash %s", oldBlock.Number, oldBlock.Hash().Hex())
						}
					}
				}
			} else if cmp == 0 {
				if commonBlock.Hash() != latestCommittedBlock.Hash {
					log.Error("Impossible reorg, please file an issue", "OldNum", commonBlock.Number.Uint64(), "OldHash", commonBlock.Hash().Hex(), "LatestCommittedHash", latestCommittedBlock.Hash.Hex())
				}
			}
		}
	}

	// Derive the next-epoch masternode set of every v2 gap block of the new
	// chain before any side effect: the head is not advanced, no event is
	// emitted, and the reorg-detected log entries and their meters below have
	// not run yet, so a failed derivation leaves the chain exactly where it was
	// and the cleanup below is never skipped. The "Reorg" warning at the top of
	// this function is logged before this loop and announces the attempt, not
	// its outcome. Handing the sets to the apply loop keeps each of them in the
	// same batch as the chain markers of its block, which is what makes a gap
	// block canonical together with the snapshot its epoch switch reads.
	//
	// The derivation is anchored at each block's own committed state and never
	// reads the head, so deriving in this order is safe. There is no second
	// source for a block whose state cannot be read, so that block fails the
	// reorg instead of leaving the chain with a set that belongs to another
	// block.
	//
	// The v1 sets are not derived here: they are read back from the checkpoint
	// header extra data and stay on their own path in the apply loop below.
	snapshots := make(map[common.Hash]*engine_v2.SnapshotV2, len(newChain))
	for i := len(newChain) - 1; i >= 1; i-- {
		header := newChain[i]
		if !bc.needsNextEpochSnapshot(header.Number) {
			continue
		}
		if _, ok := snapshots[header.Hash()]; ok {
			continue
		}
		// A set the database already holds does not have to be derived again:
		// the derivation is deterministic, so the stored set is the one this
		// loop would produce. Skipping it also keeps the loop from failing the
		// reorg over a state that is no longer readable, which is the common
		// case for a gap block that was canonical before the rollback.
		//
		// A probe that fails is not a missing set, and is not read as one: the
		// same read failure would let this loop derive over a set it cannot see,
		// or fail the reorg on the state below when the stored set was the very
		// thing that should have spared it. It fails here instead, before any
		// side effect, the way the startup repair leaves a set it cannot probe
		// alone.
		has, err := rawdb.HasXdposV2Snapshot(bc.db, header.Hash())
		if err != nil {
			return fmt.Errorf("failed to read the stored next-epoch snapshot of gap block %d (%s): %w",
				header.Number.Uint64(), header.Hash().Hex(), err)
		}
		if has {
			continue
		}
		statedb, err := bc.StateAt(header.Root)
		if err != nil {
			return fmt.Errorf("failed to open state of gap block %d (%s) for the masternode update: %w",
				header.Number.Uint64(), header.Hash().Hex(), err)
		}
		snap, err := bc.nextEpochSnapshotOf(statedb, header.Number.Uint64(), header.Hash())
		if err != nil {
			return err
		}
		snapshots[header.Hash()] = snap
	}

	// Ensure the user sees large reorgs
	if len(oldChain) > 0 && len(newChain) > 0 {
		logFn := log.Info
		msg := "Chain reorg detected"
		if len(oldChain) > 63 {
			msg = "Large chain reorg detected"
			logFn = log.Warn
		}
		logFn(msg, "number", commonBlock.Number, "hash", commonBlock.Hash().Hex(),
			"drop", len(oldChain), "dropfrom", oldChain[0].Hash().Hex(), "add", len(newChain), "addfrom", newChain[0].Hash().Hex())
		blockReorgAddMeter.Mark(int64(len(newChain)))
		blockReorgDropMeter.Mark(int64(len(oldChain)))
		blockReorgMeter.Mark(1)
	} else if len(newChain) > 0 {
		// Special case happens in the post merge stage that current head is
		// the ancestor of new head while these two blocks are not consecutive
		log.Info("Extend chain", "add", len(newChain), "number", newChain[0].Number, "hash", newChain[0].Hash())
		blockReorgAddMeter.Mark(int64(len(newChain)))
	} else {
		// len(newChain) == 0 && len(oldChain) > 0
		// rewind the canonical chain to a lower point.
		log.Error("Impossible reorg, please file an issue", "oldnum", oldHead.Number, "oldhash", oldHead.Hash(), "oldblocks", len(oldChain), "newnum", newHead.Number, "newhash", newHead.Hash(), "newblocks", len(newChain))
	}

	// Acquire the tx-lookup lock before mutation. This step is essential
	// as the txlookups should be changed atomically, and all subsequent
	// reads should be blocked until the mutation is complete.
	// bc.txLookupLock.Lock()

	// Reorg can be executed, start reducing the chain's old blocks and appending
	// the new blocks
	var (
		deletedTxs []common.Hash
		rebirthTxs []common.Hash

		deletedLogs []*types.Log
		rebirthLogs []*types.Log
	)

	// Deleted log emission on the API uses forward order, which is borked, but
	// we'll leave it in for legacy reasons.
	//
	// TODO(karalabe): This should be nuked out, no idea how, deprecate some APIs?
	//
	// The removals are delivered synchronously, like the reborn logs below and the
	// canonical logs in PostChainEvents. Spawning the send let a subscriber observe
	// the logs of the new chain before the removals of the blocks they revert
	// (geth #19396).
	{
		for i := len(oldChain) - 1; i >= 0; i-- {
			block := bc.GetBlock(oldChain[i].Hash(), oldChain[i].Number.Uint64())
			if block == nil {
				return errInvalidOldChain // Corrupt database, mostly here to avoid weird panics
			}
			if logs := bc.collectLogs(block, true); len(logs) > 0 {
				deletedLogs = append(deletedLogs, logs...)
			}
			if len(deletedLogs) > 512 {
				bc.rmLogsFeed.Send(RemovedLogsEvent{deletedLogs})
				deletedLogs = nil
			}
			// TODO(daniel): remove chainSideFeed, reference PR #30601
			// Also send event for blocks removed from the canon chain.
			// bc.chainSideFeed.Send(ChainSideEvent{Block: block})
		}
		if len(deletedLogs) > 0 {
			bc.rmLogsFeed.Send(RemovedLogsEvent{deletedLogs})
		}
	}

	// Undo old blocks in reverse order
	for i := 0; i < len(oldChain); i++ {
		// Collect all the deleted transactions
		block := bc.GetBlock(oldChain[i].Hash(), oldChain[i].Number.Uint64())
		if block == nil {
			return errInvalidOldChain // Corrupt database, mostly here to avoid weird panics
		}
		for _, tx := range block.Transactions() {
			deletedTxs = append(deletedTxs, tx.Hash())
		}
		// Collect deleted logs and emit them for new integrations
		// if logs := bc.collectLogs(block, true); len(logs) > 0 {
		// 	slices.Reverse(logs) // Emit revertals latest first, older then
		// }
	}

	// The new head (newChain[0]) is not applied by this function - the caller writes it once
	// the reorg is done - but its transactions still belong to the rebirth set: the difference
	// below drops the transactions of the rewound blocks from the lookup table, and leaving
	// the head's out would delete entries the caller is about to write back. Collect them
	// before the loop, whose bounds skip the head.
	if len(newChain) > 0 {
		head := bc.GetBlock(newChain[0].Hash(), newChain[0].Number.Uint64())
		if head == nil {
			return errInvalidNewChain // Corrupt database, mostly here to avoid weird panics
		}
		for _, tx := range head.Transactions() {
			rebirthTxs = append(rebirthTxs, tx.Hash())
		}
	}
	// Apply the rest of the new blocks in forward order. The loop stops at index 1, the
	// upstream bound: this function does not handle the new chain head, so neither its markers
	// nor, for a gap block, its UpdateM1 are written here.
	for i := len(newChain) - 1; i >= 1; i-- {
		// Collect all the included transactions
		block := bc.GetBlock(newChain[i].Hash(), newChain[i].Number.Uint64())
		if block == nil {
			return errInvalidNewChain // Corrupt database, mostly here to avoid weird panics
		}
		for _, tx := range block.Transactions() {
			rebirthTxs = append(rebirthTxs, tx.Hash())
		}
		// Collect inserted logs and emit them, but only for blocks promoted to the canonical
		// chain for the first time. A rollback only rewinds the head markers and leaves the
		// canonical mappings in place, so re-importing a known block across them lands here
		// with those retained blocks as intermediates; their logs were already delivered.
		if bc.GetCanonicalHash(block.NumberU64()) != block.Hash() {
			if logs := bc.collectLogs(block, false); len(logs) > 0 {
				rebirthLogs = append(rebirthLogs, logs...)
			}
			if len(rebirthLogs) > 512 {
				bc.logsFeed.Send(rebirthLogs)
				rebirthLogs = nil
			}
		}
		// Update the head block. The body is on disk already: the ancestors were
		// persisted by the writeBlockWithState call that imported them, and the
		// head by the block batch committed before reorg was entered. The GetBlock
		// above only guards a corrupt database, it is not what writes the body.
		// Keep that order, or the markers written here can outlive the block
		// they point at.
		//
		// The next-epoch masternode set of this block was derived before any side
		// effect, so advancing the head here can no longer fail: the set travels
		// in the same batch as the chain markers. A set taken from the database
		// instead travels with the block that is already stored with it.
		bc.writeHeadBlock(block, snapshots[block.Hash()])
		// prepare set of masternodes for the next epoch
		// Only the v1 era refreshes here: the head walk behind this loop is not
		// evidence about the missing set, since a stored one is skipped above.
		// Asking for a v2 refresh would store that same set straight to the
		// database again, outside the batch just written, and cache it there.
		// The refresh stays behind the head write because the head is what it
		// refreshes.
		if bc.isGapBlock(block) && !bc.needsNextEpochSnapshot(block.Number()) {
			if err := bc.UpdateM1At(block.Header()); err != nil {
				log.Crit("Fail to update masternodes during reorg", "number", block.Number, "hash", block.Hash().Hex(), "err", err)
			}
		}
		// An epoch switch block reaches the canonical chain here whenever this reorg rewrites
		// one: the staking loop in cmd/XDC has to revalidate the consensus parameters and the
		// masternode duty for the new epoch. The import paths signal only for the block they
		// process, so a head that jumps over the epoch boundary would leave the staking loop on
		// the previous epoch's parameters until the next epoch switch block arrived. The signal
		// coalesces - see SignalCheckpoint - so a second one from a rollback re-import costs
		// nothing.
		//
		// A header the engine cannot decode is only logged here, as notifyEpochSwitchBlock
		// does - see its doc for why neither reports a block this node already has.
		if isEpochSwitch, err := bc.isEpochSwitchBlock(block); err != nil {
			log.Error("[reorg] Error while checking if a promoted block is an epoch switch block", "Hash", block.Hash(), "Number", block.Number())
		} else if isEpochSwitch {
			SignalCheckpoint()
		}
	}
	if len(rebirthLogs) > 0 {
		bc.logsFeed.Send(rebirthLogs)
	}

	// Delete useless indexes right now which includes the non-canonical
	// transaction indexes, canonical chain indexes which above the head.
	batch := bc.db.NewBatch()
	for _, tx := range types.HashDifference(deletedTxs, rebirthTxs) {
		rawdb.DeleteTxLookupEntry(batch, tx)
	}
	// Delete all hash markers that are not part of the new canonical chain.
	// reorg deliberately does not write the new chain head - its callers do - so the new
	// head's own marker is the first one that may go. This matches upstream go-ethereum
	// (core/blockchain.go, reorg); keep the two in sync when backporting. Three shapes:
	// len(newChain) == 0 is a pure rewind, len(newChain) == 1 means newChain[0] sits directly
	// above commonBlock, and len(newChain) > 1 means newChain[1] is the head minus one.
	number := commonBlock.Number
	if len(newChain) > 1 {
		number = newChain[1].Number
	}
	for i := number.Uint64() + 1; ; i++ {
		hash := rawdb.ReadCanonicalHash(bc.db, i)
		if hash == (common.Hash{}) {
			break
		}
		rawdb.DeleteCanonicalHash(batch, i)
	}
	if err := batch.Write(); err != nil {
		log.Crit("Failed to delete useless indexes", "err", err)
	}

	// Reset the tx lookup cache to clear stale txlookup cache.
	// bc.txLookupCache.Purge()

	// Release the tx-lookup lock after mutation.
	// bc.txLookupLock.Unlock()

	return nil
}

// PostChainEvents iterates over the events generated by a chain insertion and
// posts them into the event feed.
// TODO: Should not expose PostChainEvents. The chain events should be posted in WriteBlock.
func (bc *BlockChain) PostChainEvents(events []interface{}, logs []*types.Log) {
	// post event logs for further processing
	if logs != nil {
		bc.logsFeed.Send(logs)
	}
	for _, event := range events {
		switch ev := event.(type) {
		case ChainEvent:
			bc.chainFeed.Send(ev)

		case ChainHeadEvent:
			bc.chainHeadFeed.Send(ev)

		case ChainSideEvent:
			bc.chainSideFeed.Send(ev)
		}
	}
}

// futureBlocksLoop processes the 'future block' queue.
func (bc *BlockChain) futureBlocksLoop() {
	futureTimer := time.NewTicker(100 * time.Millisecond)
	defer futureTimer.Stop()

	for {
		select {
		case <-futureTimer.C:
			bc.procFutureBlocks()
		case <-bc.quit:
			return
		}
	}
}

// reportBlockIfFault records block as a bad block when err is a failure the classification
// blames on the block, and does nothing for the local conditions and for a nil error: the
// single place the insertion paths ask the question, so a sentinel registered in
// classifyInsertErr is answered the same way wherever it stops a batch.
func (bc *BlockChain) reportBlockIfFault(block *types.Block, err error) {
	if block == nil || err == nil || !classifyInsertErr(err).badBlock {
		return
	}
	bc.reportBlock(block, nil, err)
}

// reportBlock logs a bad block error.
func (bc *BlockChain) reportBlock(block *types.Block, receipts types.Receipts, err error) {
	rawdb.WriteBadBlock(bc.db, block)

	commit := "unknown"
	if vcs, ok := internalversion.VCS(); ok && vcs.Commit != "" {
		commit = vcs.Commit
	}

	var roundNumber = types.Round(0)
	engine, ok := bc.Engine().(*XDPoS.XDPoS)
	if ok {
		var err error
		roundNumber, err = engine.EngineV2.GetRoundNumber(block.Header())
		if err != nil {
			log.Error("reportBlock", "GetRoundNumber", err)
		}
	}

	var receiptString string
	for i, receipt := range receipts {
		receiptString += fmt.Sprintf("\n  %d: cumulative: %v gas: %v contract: %v status: %v tx: %v logs: %v bloom: %x state: %x",
			i, receipt.CumulativeGasUsed, receipt.GasUsed, receipt.ContractAddress.Hex(),
			receipt.Status, receipt.TxHash.Hex(), receipt.Logs, receipt.Bloom, receipt.PostState)
	}
	log.Error(fmt.Sprintf(`
########## BAD BLOCK #########
Version: %v
Commit: %v
Number: %v
Hash: %#x
Round: %v
Error: %v
%s
Receipts: %v
##############################
`, internalversion.WithMeta, commit, block.Number(), block.Hash(), roundNumber, err, bc.chainConfig.Description(), receiptString))
}

// InsertHeaderChain attempts to insert the given header chain in to the local
// chain, possibly creating a reorg. If an error is returned, it will return the
// index number of the failing header as well an error describing what went wrong.
//
// The verify parameter can be used to fine tune whether nonce verification
// should be done or not. The reason behind the optional check is because some
// of the header retrieval mechanisms already need to verify nonces, as well as
// because nonces can be verified sparsely, not needing to check each.
func (bc *BlockChain) InsertHeaderChain(chain []*types.Header, checkFreq int) (int, error) {
	start := time.Now()
	if i, err := bc.hc.ValidateHeaderChain(chain, checkFreq); err != nil {
		return i, err
	}

	if !bc.chainmu.TryLock() {
		return 0, ErrChainStopped
	}
	defer bc.chainmu.Unlock()

	whFunc := func(header *types.Header) error {
		_, err := bc.hc.WriteHeader(header)
		return err
	}

	return bc.hc.InsertHeaderChain(chain, whFunc, start)
}

// SetChainConfig sets the chain config for test.
func (bc *BlockChain) SetChainConfig(config *params.ChainConfig) {
	bc.chainConfig = config
}

// Get current IPC Client.
func (bc *BlockChain) GetClient() (bind.ContractBackend, error) {
	if bc.Client == nil {
		// Inject ipc client global instance.
		client, err := ethclient.Dial(bc.IPCEndpoint)
		if err != nil {
			log.Error("Fail to connect IPC", "error", err)
			return nil, err
		}
		bc.Client = client
	}

	return bc.Client, nil
}

// isNextEpochGapBlock reports whether the block at number is the gap block of
// its epoch, i.e. the block whose committed state the masternode set of the next
// epoch is derived from. A schedule without a usable gap offset has no gap block
// at all, which also keeps the modulo below from dividing by zero.
//
// A usable offset is positive and smaller than the epoch. Gap == 0 and
// Gap > Epoch designate no gap block either way - number%Epoch is never the epoch
// itself, and Epoch-Gap wraps - so nothing changes for them. Gap == Epoch is the
// one schedule this predicate moves: it puts the gap block on the epoch switch
// itself, so the offset is refused here and no height owes the v2 snapshot this
// predicate asks about any more, where the predicate the callers used before this
// change ((number % Epoch) == (Epoch - Gap)) fired on every epoch switch. The
// masternode refresh is not this predicate's to refuse: the two UpdateM1 call
// sites ask isGapBlockNumber, which accepts Gap == Epoch because that is what
// engine_v2.UpdateMasternodes itself accepts (number%Epoch == Epoch-Gap, with no
// bound on Gap), so a Gap == Epoch schedule still refreshes at every epoch switch
// - unlike the isNextEpochGapBlock gate those call sites used before. The
// other readers of that schedule do not move with it: the v1 engine still loads
// and stores its checkpoint snapshot on (number+Gap)%Epoch == 0, and the v2 lookup
// resolves an epoch switch back to the previous switch, so a Gap == Epoch network
// would find them looking for a snapshot this code no longer writes. No built-in
// network uses one.
func (bc *BlockChain) isNextEpochGapBlock(number uint64) bool {
	if bc.chainConfig.XDPoS == nil || bc.chainConfig.XDPoS.Epoch == 0 ||
		bc.chainConfig.XDPoS.Gap == 0 || bc.chainConfig.XDPoS.Gap >= bc.chainConfig.XDPoS.Epoch {
		return false
	}
	return (number % bc.chainConfig.XDPoS.Epoch) == (bc.chainConfig.XDPoS.Epoch - bc.chainConfig.XDPoS.Gap)
}

// needsNextEpochSnapshot reports whether the block at number owes the v2
// masternode snapshot of the next epoch. The snapshot travels in the same batch
// as the chain markers of that block, so only the v2 era asks for one: the v1
// set is read back from the checkpoint header extra data and is refreshed
// through UpdateM1At instead.
func (bc *BlockChain) needsNextEpochSnapshot(number *big.Int) bool {
	return bc.isNextEpochGapBlock(number.Uint64()) &&
		bc.chainConfig.XDPoS.BlockConsensusVersion(number) == params.ConsensusEngineVersion2
}

// nextEpochSnapshotOf derives the masternode snapshot of the next epoch from a
// state committed at the given block. It writes nothing: the caller either hands
// the result to writeHeadBlock or keeps it for the reorg it is about to apply,
// and either way it lands in the same batch as the chain markers of that block,
// so that a gap block can never become canonical without the snapshot its epoch
// switch reads.
//
// The state always has to be the one committed at this very block, and it is
// passed in rather than re-opened here: the extension path still holds the state
// it has just executed, while the reorg path re-opens it from the block root.
// There is no second source anchored at the block, so a state that cannot be
// read fails the derivation instead of producing a set that belongs to another
// block. The ready line is not logged here: deriving is not yet storing, and it
// is writeHeadBlock that reports the set once its batch is on disk.
func (bc *BlockChain) nextEpochSnapshotOf(statedb *state.StateDB, number uint64, hash common.Hash) (*engine_v2.SnapshotV2, error) {
	snap, err := engine_v2.BuildSnapshotFromState(statedb, number, hash)
	if err != nil {
		return nil, fmt.Errorf("failed to derive the next-epoch masternodes of gap block %d (%s): %w",
			number, hash.Hex(), err)
	}
	log.Info("Updating the next-epoch masternodes", "number", number, "hash", hash.Hex(), "candidates", len(snap.NextEpochCandidates))
	return snap, nil
}

// UpdateM1At refreshes the masternode set of the next epoch for the given
// header. The header is passed in instead of being read from the chain head, so
// that both refresh paths name the block they refresh rather than looking the
// head up a second time.
//
// The refresh itself is the v1 one and is unchanged: the candidates and their
// stakes are read off the state committed at that header, and the result is
// handed to the engine, which keys the v1 set by that very block and keeps it in
// memory. The header therefore has to be the block whose set this refreshes:
// candidates read from anywhere else would be stored as the set of a block they
// did not come from. There is nothing to persist: the v1 set is read back from
// the checkpoint header extra data. Callers therefore keep their position behind
// the head write and pass the header of the block they just made canonical.
func (bc *BlockChain) UpdateM1At(header *types.Header) error {
	engine, ok := bc.Engine().(*XDPoS.XDPoS)
	if bc.Config().XDPoS == nil || !ok {
		return ErrNotXDPoS
	}
	if header == nil {
		return errors.New("nil header in UpdateM1At")
	}
	log.Info("It's time to update new set of masternodes for the next epoch...")
	// Read the candidates and their stakes off the state committed at this
	// header, which is the block this refresh is for. The stakes used to come
	// back from the voting contract over this node's own IPC endpoint: that cost
	// an eth_call per candidate while the chain write lock was held, and it is
	// also what made the refresh depend on an IPC endpoint at all (a node
	// started with --ipcdisable fails the refresh, and the callers turn that
	// failure into log.Crit).
	stateDB, err := bc.StateAt(header.Root)
	if err != nil {
		return fmt.Errorf("failed to open the state of the block for the masternode update: %w", err)
	}

	var ms []utils.Masternode
	// GetCandidates skips the zero entries of the candidates array itself, so
	// there is nothing to filter out here.
	for _, candidate := range stateDB.GetCandidates() {
		ms = append(ms, utils.Masternode{Address: candidate, Stake: stateDB.GetCandidateCap(candidate)})
	}
	// GetCandidates and GetCandidateCap return zero values when the voting
	// contract storage cannot be read, memoizing the failure in StateDB.Error().
	// A set derived from such reads would be empty or partial, so surface the
	// read error instead: there is no IPC fallback for the candidates any more,
	// and the call sites stop the node on any error returned here.
	if err := stateDB.Error(); err != nil {
		return fmt.Errorf("reading the masternodes of the block from state: %w", err)
	}
	if len(ms) == 0 {
		log.Error("No masternode found. Stopping node")
		return errors.New("no masternode found")
	} else {
		utils.SortMasternodesByStakeDesc(ms)
		log.Info("Updating new set of masternodes")
		// The candidates above came from the state committed at this header, so
		// the set the engine stores for that block is derived from that block's
		// own state rather than from wherever the head points.
		err = engine.UpdateMasternodes(bc, header, ms)
		if err != nil {
			return err
		}
		log.Info("Masternodes are ready for the next epoch", "number", header.Number.Uint64(), "hash", header.Hash().Hex())
	}
	return nil
}

func (bc *BlockChain) AddMatchingResult(txHash common.Hash, matchingResults map[common.Hash]tradingstate.MatchingResult) {
	for hash, result := range matchingResults {
		cacheKey := crypto.Keccak256Hash(txHash.Bytes(), hash.Bytes())
		bc.resultTrade.Add(cacheKey, result.Trades)
		bc.rejectedOrders.Add(cacheKey, result.Rejects)
	}
}

func (bc *BlockChain) AddLendingResult(txHash common.Hash, lendingResults map[common.Hash]lendingstate.MatchingResult) {
	for hash, result := range lendingResults {
		bc.resultLendingTrade.Add(crypto.Keccak256Hash(txHash.Bytes(), hash.Bytes()), result.Trades)
		bc.rejectedLendingItem.Add(crypto.Keccak256Hash(txHash.Bytes(), hash.Bytes()), result.Rejects)
	}
}

func (bc *BlockChain) AddFinalizedTrades(txHash common.Hash, trades map[common.Hash]*lendingstate.LendingTrade) {
	bc.finalizedTrade.Add(txHash, trades)
}

// processTradingAndLendingStates processes the trading and lending states for a given block in the blockchain.
//
// Parameters:
//   - isValidBlockNumber: A boolean indicating whether the block number is valid for processing trading and lending states.
//   - block: The current block being processed.
//   - parent: The parent block of the current block.
//   - statedb: The current state database for the blockchain.
//
// Returns:
//   - *tradingstate.TradingStateDB: The updated trading state database, if applicable.
//   - *lendingstate.LendingStateDB: The updated lending state database, if applicable.
//   - error: An error if any issues occur during processing.
//
// The function performs the following operations:
//  1. Validates if the block number is eligible for trading and lending state processing based on the blockchain configuration.
//  2. Retrieves the block author and validates the block header.
//  3. Fetches the trading and lending services from the consensus engine.
//  4. Retrieves the trading and lending states of the parent block.
//  5. Handles epoch switch logic, including updating medium prices for trading services if the block is an epoch switch block.
//  6. Validates trading and lending orders using the block's transactions and state.
//  7. Processes liquidation data for lending trades if the block is a liquidation block.
//  8. Verifies the integrity of the trading and lending state roots by comparing the computed roots with the expected roots.
func (bc *BlockChain) processTradingAndLendingStates(isValidBlockNumber bool, block *types.Block, parent *types.Header, statedb *state.StateDB) (*tradingstate.TradingStateDB, *lendingstate.LendingStateDB, error) {
	if !isValidBlockNumber || bc.chainConfig.XDPoS == nil || block.NumberU64() <= bc.chainConfig.XDPoS.Epoch {
		return nil, nil, nil
	}

	engine, _ := bc.Engine().(*XDPoS.XDPoS)
	if engine == nil {
		return nil, nil, nil
	}

	author, err := bc.Engine().Author(block.Header()) // Ignore error, we're past header validation
	if err != nil {
		return nil, nil, err
	}

	tradingService := engine.GetXDCXService()
	lendingService := engine.GetLendingService()
	if tradingService == nil || lendingService == nil {
		return nil, nil, nil
	}

	parentAuthor, _ := bc.Engine().Author(parent)
	parentBlock := bc.GetBlock(parent.Hash(), parent.Number.Uint64())
	tradingState, err := tradingService.GetTradingState(parentBlock, parentAuthor)
	if err != nil {
		return nil, nil, err
	}
	lendingState, err := lendingService.GetLendingState(parentBlock, parentAuthor)
	if err != nil {
		return nil, nil, err
	}

	isEpochSwithBlock, epochNumber, err := engine.IsEpochSwitch(block.Header())
	if err != nil {
		log.Error("[insertChain] Error while checking if the incoming block is epoch switch block", "Hash", block.Hash(), "Number", block.Number())
		return tradingState, lendingState, err
	}

	if isEpochSwithBlock {
		if err := tradingService.UpdateMediumPriceBeforeEpoch(epochNumber, tradingState, statedb); err != nil {
			return tradingState, lendingState, err
		}
	} else {
		txMatchBatchData, err := ExtractTradingTransactions(block.Transactions())
		if err != nil {
			return tradingState, lendingState, err
		}
		for _, txMatchBatch := range txMatchBatchData {
			log.Debug("Verify matching transaction", "txHash", txMatchBatch.TxHash.Hex())
			err := bc.validator.ValidateTradingOrder(statedb, tradingState, txMatchBatch, author, block.Header())
			if err != nil {
				return tradingState, lendingState, err
			}
		}
		batches, err := ExtractLendingTransactions(block.Transactions())
		if err != nil {
			return tradingState, lendingState, err
		}
		for _, batch := range batches {
			log.Debug("Verify matching transaction", "txHash", batch.TxHash.Hex())
			err := bc.validator.ValidateLendingOrder(statedb, lendingState, tradingState, batch, author, block.Header())
			if err != nil {
				return tradingState, lendingState, err
			}
		}
		// liquidate / finalize open lendingTrades
		if block.Number().Uint64()%bc.chainConfig.XDPoS.Epoch == common.LiquidateLendingTradeBlock {
			_, _, _, _, _, err := lendingService.ProcessLiquidationData(block.Header(), bc, statedb, tradingState, lendingState)
			if err != nil {
				return tradingState, lendingState, fmt.Errorf("failed to ProcessLiquidationData. Err: %v", err)
			}
		}
	}

	if tradingState != nil {
		gotRoot := tradingState.IntermediateRoot()
		expectRoot, _ := tradingService.GetTradingStateRoot(block, author)
		parentRoot, _ := tradingService.GetTradingStateRoot(parentBlock, parentAuthor)
		if gotRoot != expectRoot {
			err = fmt.Errorf("invalid XDCx trading state merke trie got : %s , expect : %s ,parent : %s", gotRoot.Hex(), expectRoot.Hex(), parentRoot.Hex())
			return tradingState, lendingState, err
		}
		log.Debug("XDCX Trading State Root", "number", block.NumberU64(), "parent", parentRoot.Hex(), "nextRoot", expectRoot.Hex())
	}

	if lendingState != nil && tradingState != nil {
		gotRoot := lendingState.IntermediateRoot()
		expectRoot, _ := lendingService.GetLendingStateRoot(block, author)
		parentRoot, _ := lendingService.GetLendingStateRoot(parentBlock, parentAuthor)
		if gotRoot != expectRoot {
			err = fmt.Errorf("invalid lending state merke trie got: %s, expect: %s, parent: %s", gotRoot.Hex(), expectRoot.Hex(), parentRoot.Hex())
			return tradingState, lendingState, err
		}
		log.Debug("XDCX Lending State Root", "number", block.NumberU64(), "parent", parentRoot.Hex(), "nextRoot", expectRoot.Hex())
	}

	return tradingState, lendingState, nil
}

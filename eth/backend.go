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

// Package eth implements the Ethereum protocol.
package eth

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/XinFinOrg/XDPoSChain/XDCx"
	"github.com/XinFinOrg/XDPoSChain/XDCxlending"
	"github.com/XinFinOrg/XDPoSChain/accounts"
	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/common/hexutil"
	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS/utils"
	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/contracts"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/bloombits"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/txpool"
	"github.com/XinFinOrg/XDPoSChain/core/txpool/legacypool"
	"github.com/XinFinOrg/XDPoSChain/core/txpool/locals"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/eth/downloader"
	"github.com/XinFinOrg/XDPoSChain/eth/ethconfig"
	"github.com/XinFinOrg/XDPoSChain/eth/filters"
	"github.com/XinFinOrg/XDPoSChain/eth/gasprice"
	"github.com/XinFinOrg/XDPoSChain/eth/hooks"
	"github.com/XinFinOrg/XDPoSChain/eth/tracers"
	"github.com/XinFinOrg/XDPoSChain/ethdb"
	"github.com/XinFinOrg/XDPoSChain/event"
	"github.com/XinFinOrg/XDPoSChain/internal/ethapi"
	"github.com/XinFinOrg/XDPoSChain/internal/version"
	"github.com/XinFinOrg/XDPoSChain/log"
	"github.com/XinFinOrg/XDPoSChain/miner"
	"github.com/XinFinOrg/XDPoSChain/node"
	"github.com/XinFinOrg/XDPoSChain/p2p"
	"github.com/XinFinOrg/XDPoSChain/p2p/enr"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/XinFinOrg/XDPoSChain/rlp"
	"github.com/XinFinOrg/XDPoSChain/rpc"
	ver "github.com/XinFinOrg/XDPoSChain/version"
)

// Ethereum implements the Ethereum full node service.
type Ethereum struct {
	// core protocol objects
	config         *ethconfig.Config
	txPool         *txpool.TxPool
	localTxTracker *locals.TxTracker
	blockchain     *core.BlockChain

	// Channel for shutting down the service
	shutdownChan chan bool

	orderPool       *legacypool.OrderPool
	lendingPool     *legacypool.LendingPool
	protocolManager *ProtocolManager

	// DB interfaces
	chainDb ethdb.Database // Block chain database

	eventMux       *event.TypeMux
	engine         consensus.Engine
	accountManager *accounts.Manager

	bloomRequests chan chan *bloombits.Retrieval // Channel receiving bloom data retrieval requests
	bloomIndexer  *core.ChainIndexer             // Bloom indexer operating during block imports

	APIBackend *EthAPIBackend

	miner     *miner.Miner
	gasPrice  *big.Int
	etherbase common.Address

	networkId     uint64
	netRPCService *ethapi.NetAPI

	p2pServer *p2p.Server

	lock    sync.RWMutex // Protects the variadic fields (e.g. gas price and etherbase)
	XDCX    *XDCx.XDCX
	Lending *XDCxlending.Lending
}

// New creates a new Ethereum object (including the
// initialisation of the common Ethereum object)
func New(stack *node.Node, config *ethconfig.Config, XDCXServ *XDCx.XDCX, lendingServ *XDCxlending.Lending) (*Ethereum, error) {
	// Ensure configuration values are compatible and sane
	if config.SyncMode == downloader.LightSync {
		return nil, errors.New("can't run eth.Ethereum in light sync mode, light mode has been deprecated")
	}
	if !config.SyncMode.IsValid() {
		return nil, fmt.Errorf("invalid sync mode %d", config.SyncMode)
	}
	if config.Miner.GasCeil == 0 {
		log.Warn("Sanitizing invalid miner gas limit", "provided", config.Miner.GasCeil, "updated", ethconfig.Defaults.Miner.GasCeil)
		config.Miner.GasCeil = ethconfig.Defaults.Miner.GasCeil
	}
	if config.Miner.GasPrice == nil || config.Miner.GasPrice.Cmp(common.Big0) < 0 {
		log.Warn("Sanitizing invalid miner gas price", "provided", config.Miner.GasPrice, "updated", ethconfig.Defaults.Miner.GasPrice)
		config.Miner.GasPrice = new(big.Int).Set(ethconfig.Defaults.Miner.GasPrice)
	}

	chainDb, err := stack.OpenDatabase("chaindata", config.DatabaseCache, config.DatabaseHandles, "eth/db/chaindata/", false)
	if err != nil {
		return nil, err
	}
	// Resolve the effective chain config before constructing the consensus engine.
	// NewBlockChainEx reruns SetupGenesisBlock and applies any required rewind.
	chainConfig, genesisHash, compatErr, err := core.SetupGenesisBlockWithOverride(chainDb, config.Genesis, config.AllowBuiltInCustomRecovery)
	if err != nil {
		return nil, err
	}
	if chainConfig == nil {
		return nil, fmt.Errorf("nil chain config returned from SetupGenesisBlock (err=%v)", err)
	}

	// Set networkID to chainID by default.
	networkID := config.NetworkId
	if networkID == 0 {
		networkID = chainConfig.ChainID.Uint64()
	}
	engine, err := CreateConsensusEngine(stack, chainConfig, chainDb)
	if err != nil {
		return nil, err
	}
	logXDPoSConfig(chainConfig, compatErr)

	// Assemble the Ethereum object.
	eth := &Ethereum{
		config:         config,
		chainDb:        chainDb,
		eventMux:       stack.EventMux(),
		accountManager: stack.AccountManager(),
		engine:         engine,
		shutdownChan:   make(chan bool),
		networkId:      networkID,
		gasPrice:       config.Miner.GasPrice,
		etherbase:      config.Miner.Etherbase,
		bloomRequests:  make(chan chan *bloombits.Retrieval),
		bloomIndexer:   NewBloomIndexer(chainDb, params.BloomBitsBlocks, params.BloomConfirms),
		p2pServer:      stack.Server(),
	}
	// Inject XDCX Service into main Eth Service.
	if XDCXServ != nil {
		eth.XDCX = XDCXServ
	}
	if lendingServ != nil {
		eth.Lending = lendingServ
	}

	bcVersion := rawdb.ReadDatabaseVersion(chainDb)
	var dbVer = "<nil>"
	if bcVersion != nil {
		dbVer = fmt.Sprintf("%d", *bcVersion)
	}
	log.Info("Initialising Ethereum protocol", "versions", ProtocolVersions, "network", networkID, "dbversion", dbVer)

	// Create BlockChain object.
	if !config.SkipBcVersionCheck {
		if bcVersion != nil && *bcVersion > core.BlockChainVersion {
			return nil, fmt.Errorf("database version is v%d, XDC %s only supports v%d", *bcVersion, version.WithMeta, core.BlockChainVersion)
		} else if bcVersion == nil || *bcVersion < core.BlockChainVersion {
			if bcVersion != nil { // only print warning on upgrade, not on init
				log.Warn("Upgrade blockchain database version", "from", dbVer, "to", core.BlockChainVersion)
			}
			rawdb.WriteDatabaseVersion(chainDb, core.BlockChainVersion)
		}
	}

	badBlocks := rawdb.ReadAllBadBlocks(chainDb)
	log.Info("Bad blocks in db", "count", len(badBlocks))
	for i, block := range badBlocks {
		log.Info("Bad block in db", "i", i, "number", block.Number(), "hash", block.Hash().Hex())
	}
	if config.DeleteAllBadBlocks {
		if len(badBlocks) == 0 {
			log.Warn("No bad blocks in db to delete")
		} else {
			rawdb.DeleteBadBlocks(chainDb)
			log.Info(fmt.Sprintf("Deleted %d bad blocks in db", len(badBlocks)))
		}
	}

	var (
		vmConfig    = vm.Config{EnablePreimageRecording: config.EnablePreimageRecording}
		cacheConfig = &core.CacheConfig{
			TrieCleanLimit:    config.TrieCleanCache,
			TrieCleanPrefetch: config.Prefetch,
			TrieDirtyLimit:    config.TrieDirtyCache,
			TrieDirtyDisabled: config.NoPruning,
			TrieTimeLimit:     config.TrieTimeout,
			Preimages:         config.Preimages,
		}
	)
	if config.VMTrace != "" {
		traceConfig := json.RawMessage("{}")
		if config.VMTraceJsonConfig != "" {
			traceConfig = json.RawMessage(config.VMTraceJsonConfig)
		}
		t, err := tracers.LiveDirectory.New(config.VMTrace, traceConfig)
		if err != nil {
			return nil, fmt.Errorf("Failed to create tracer %s: %v", config.VMTrace, err)
		}
		vmConfig.Tracer = t
	}
	if chainConfig.XDPoS != nil {
		c := eth.engine.(*XDPoS.XDPoS)
		c.GetXDCXService = func() utils.TradingService {
			return eth.XDCX
		}
		c.GetLendingService = func() utils.LendingService {
			return eth.Lending
		}
	}
	compatPolicy := core.ChainConfigMismatchPolicy(config.ChainConfigMismatchPolicy)

	// A negative --set-head value is an offset from the current head, but the
	// head is not final until the chain is open: NewBlockChainExResolved below
	// runs repair, which rewinds the head on its own when the head state is
	// missing. Resolve the offset against the head recorded on disk first, so
	// that repair and the SetHead call afterwards aim at the same block.
	rollbackRequest := common.RollbackNumber
	rollbackTarget := uint64(0)
	if rollbackRequest != 0 {
		head, recorded := rollbackHeadNumber(chainDb)
		if !recorded && rollbackRequest < 0 {
			return nil, fmt.Errorf("can't roll back %d blocks: the datadir has no head block number recorded", -rollbackRequest)
		}
		rollbackTarget, err = resolveRollbackTarget(rollbackRequest, head)
		if err != nil {
			return nil, err
		}
		// From here on the request is an absolute target, which is the only form
		// repair knows how to bound its rewind with. A target of 0 means the
		// genesis block, and repair cannot rewind past it either way.
		common.RollbackNumber = int64(rollbackTarget)
	}

	eth.blockchain, err = core.NewBlockChainExResolved(
		chainDb,
		XDCXServ.GetLevelDB(),
		cacheConfig,
		config.Genesis,
		eth.engine,
		vmConfig,
		chainConfig,
		genesisHash,
		compatErr,
		compatPolicy,
	)
	if err != nil {
		return nil, err
	}

	// Rollback according to SetHeadFlag
	if rollbackRequest != 0 {
		common.RollbackNumber = 0
		currentBlock := eth.blockchain.CurrentBlock()
		if currentBlock == nil {
			return nil, fmt.Errorf("not find current block when rollback to %d", rollbackTarget)
		}
		currentNumber := currentBlock.Number.Uint64()
		if rollbackTarget > currentNumber {
			return nil, fmt.Errorf("can't rollback to %d which is greater than current %d", rollbackTarget, currentNumber)
		}
		log.Warn("Start rollback", "requested", rollbackRequest, "target", rollbackTarget, "current", currentNumber)
		err := eth.blockchain.SetHead(rollbackTarget)
		if err != nil {
			return nil, fmt.Errorf("fail to rollback: target=%d, current=%d, err: %w", rollbackTarget, currentNumber, err)
		}
		log.Warn("Rollback completed", "target", rollbackTarget)
	}

	if engine, ok := eth.blockchain.Engine().(*XDPoS.XDPoS); ok {
		err := engine.Initial(eth.blockchain, eth.blockchain.CurrentHeader())
		if err != nil {
			return nil, err
		}
	}

	eth.bloomIndexer.Start(eth.blockchain)

	// TxPool
	if config.TxPool.Journal != "" {
		config.TxPool.Journal = stack.ResolvePath(config.TxPool.Journal)
	}
	legacyPool := legacypool.New(config.TxPool, eth.blockchain)
	eth.orderPool = legacypool.NewOrderPool(eth.blockchain.Config(), eth.blockchain)
	eth.lendingPool = legacypool.NewLendingPool(eth.blockchain.Config(), eth.blockchain)

	eth.txPool, err = txpool.New(config.TxPool.PriceLimit, eth.blockchain, []txpool.SubPool{legacyPool})
	if err != nil {
		return nil, err
	}

	if !config.TxPool.NoLocals {
		rejournal := config.TxPool.Rejournal
		if rejournal < time.Second {
			log.Warn("Sanitizing invalid txpool journal time", "provided", rejournal, "updated", time.Second)
			rejournal = time.Second
		}
		eth.localTxTracker = locals.New(config.TxPool.Journal, rejournal, eth.blockchain.Config(), eth.txPool)
		eth.txPool.SetLocalTracker(eth.localTxTracker)
		stack.RegisterLifecycle(eth.localTxTracker)
	}

	if eth.protocolManager, err = NewProtocolManagerEx(eth.blockchain.Config(), config.SyncMode, networkID, eth.eventMux, eth.txPool, eth.orderPool, eth.lendingPool, eth.engine, eth.blockchain, chainDb); err != nil {
		return nil, err
	}
	// Set fast sync pivot block if configured
	if config.FastSyncPivotNumber != 0 {
		eth.protocolManager.downloader.SetPivotBlock(config.FastSyncPivotNumber, config.FastSyncPivotHash, config.FastSyncPivotRoot)
	}
	eth.miner = miner.New(eth, &config.Miner, eth.blockchain.Config(), eth.EventMux(), eth.engine, stack.Config().AnnounceTxs)
	eth.miner.SetExtra(makeExtraData(config.Miner.ExtraData))

	var xdPoS *XDPoS.XDPoS = nil
	if chainConfig.XDPoS != nil {
		xdPoS = eth.engine.(*XDPoS.XDPoS)
	}
	eth.APIBackend = &EthAPIBackend{
		allowUnprotectedTxs: stack.Config().AllowUnprotectedTxs,
		eth:                 eth,
		gpo:                 nil,
		XDPoS:               xdPoS,
	}

	if eth.APIBackend.allowUnprotectedTxs {
		log.Info("Unprotected transactions allowed")
	}
	eth.APIBackend.gpo = gasprice.NewOracle(eth.APIBackend, config.GPO, config.Miner.GasPrice)

	// Set global ipc endpoint.
	eth.blockchain.IPCEndpoint = stack.IPCEndpoint()

	if chainConfig.XDPoS != nil {
		c := eth.engine.(*XDPoS.XDPoS)
		signHook := func(block *types.Block) error {
			eb, err := eth.Etherbase()
			if err != nil {
				log.Error("Cannot get etherbase for append m2 header", "err", err)
				return fmt.Errorf("etherbase missing: %v", err)
			}
			ok := eth.txPool.IsSigner(eb)
			if !ok {
				return nil
			}
			if block.NumberU64()%common.MergeSignRange == 0 || !chainConfig.IsTIP2019(block.Number()) {
				if err := contracts.CreateTransactionSign(chainConfig, eth.txPool, eth.accountManager, block, chainDb, eb); err != nil {
					return fmt.Errorf("fail to create tx sign for importing block: %v", err)
				}
			}
			return nil
		}

		appendM2HeaderHook := func(block *types.Block) (*types.Block, bool, error) {
			eb, err := eth.Etherbase()
			if err != nil {
				log.Error("Cannot get etherbase for append m2 header", "err", err)
				return block, false, fmt.Errorf("etherbase missing: %v", err)
			}
			m1, err := c.RecoverSigner(block.Header())
			if err != nil {
				return block, false, fmt.Errorf("can't get block creator: %v", err)
			}
			m2, err := c.GetValidator(m1, eth.blockchain, block.Header())
			if err != nil {
				return block, false, fmt.Errorf("can't get block validator: %v", err)
			}
			if m2 == eb {
				wallet, err := eth.accountManager.Find(accounts.Account{Address: eb})
				if err != nil {
					log.Error("Can't find coinbase account wallet", "err", err)
					return block, false, err
				}
				header := block.Header()
				sighash, err := wallet.SignHash(accounts.Account{Address: eb}, c.SigHash(header).Bytes())
				if err != nil || sighash == nil {
					log.Error("Can't get signature hash of m2", "sighash", sighash, "err", err)
					return block, false, err
				}
				header.Validator = sighash
				return types.NewBlockWithHeader(header).WithBody(*block.Body()), true, nil
			}
			return block, false, nil
		}

		eth.protocolManager.blockFetcher.SetSignHook(signHook)
		eth.protocolManager.blockFetcher.SetAppendM2HeaderHook(appendM2HeaderHook)

		/*
			XDPoS1.0 Specific hooks
		*/
		hooks.AttachConsensusV1Hooks(c, eth.blockchain, chainConfig)
		hooks.AttachConsensusV2Hooks(c, eth.blockchain, chainConfig)

		// Let the consensus engine know when the node is downloading the chain,
		// so it can downgrade otherwise-noisy "missing snapshot" logs to Debug
		// during sync and only Warn when it happens at a synced head.
		c.EngineV2.HookSyncing = func() bool {
			return eth.Downloader().Synchronising()
		}

		isSigner := func(address common.Address) bool {
			// During sync the head snapshot isn't built yet, so IsAuthorisedAddress
			// would fail and spam "[IsAuthorisedAddress] Can't get snapshot". The
			// signer check is meaningless before the chain is synced, so skip it; it
			// is re-evaluated normally once syncing completes.
			if eth.Downloader().Synchronising() {
				return false
			}
			return c.IsAuthorisedAddress(eth.blockchain, eth.blockchain.CurrentHeader(), address)
		}
		eth.txPool.SetSigner(isSigner)
	}
	// Start the RPC service
	eth.netRPCService = ethapi.NewNetAPI(eth.p2pServer, eth.NetVersion())

	// Register the backend on the node
	stack.RegisterAPIs(eth.APIs())
	stack.RegisterProtocols(eth.Protocols())
	stack.RegisterLifecycle(eth)
	return eth, nil
}

// rollbackHeadNumber reports the head block number recorded on disk, before the
// chain is opened and before any startup repair can rewind it. The second return
// value is false when the datadir carries no head block number at all, which is
// the case a fresh datadir is in; the height is then reported as zero. Nothing is
// logged here, because only the caller knows whether a missing head is fatal: a
// relative request cannot be resolved without one, an absolute one does not need
// it at all.
func rollbackHeadNumber(db ethdb.KeyValueReader) (uint64, bool) {
	head := rawdb.ReadHeadBlockHash(db)
	if number := rawdb.ReadHeaderNumber(db, head); number != nil {
		return *number, true
	}
	// A head hash without a number index means the database has no usable head
	// yet. Report it as height zero and let the caller reject any request that
	// cannot be satisfied from there.
	return 0, false
}

// resolveRollbackTarget turns a --set-head request into an absolute target block
// number. A positive value is the target itself; a negative value is the number
// of blocks to count back from headNumber.
func resolveRollbackTarget(request int64, headNumber uint64) (uint64, error) {
	if request > 0 {
		return uint64(request), nil
	}
	if request == 0 {
		return 0, errors.New("rollback target must not be 0")
	}
	// parseSetHead rejects math.MinInt64 itself, because its magnitude does not
	// fit an int64, so the negation below cannot overflow. Should such a value
	// ever arrive here anyway, uint64(math.MinInt64) is 1<<63, far above any
	// recorded head, and the offset check would reject it.
	offset := uint64(-request)
	if offset > headNumber {
		return 0, fmt.Errorf("can't rollback %d blocks from current %d", offset, headNumber)
	}
	return headNumber - offset, nil
}

func makeExtraData(extra []byte) []byte {
	if len(extra) == 0 {
		// create default extradata
		extra, _ = rlp.EncodeToBytes([]interface{}{
			uint(ver.Major<<16 | ver.Minor<<8 | ver.Patch),
			"XDC",
			runtime.Version(),
			runtime.GOOS,
		})
	}
	if uint64(len(extra)) > params.MaximumExtraDataSize {
		log.Warn("Miner extra data exceed limit", "extra", hexutil.Bytes(extra), "limit", params.MaximumExtraDataSize)
		extra = nil
	}
	return extra
}

// CreateConsensusEngine creates the required type of consensus engine instance for an Ethereum service
func CreateConsensusEngine(stack *node.Node, chainConfig *params.ChainConfig, db ethdb.Database) (consensus.Engine, error) {
	// If delegated-proof-of-stake is requested, set it up
	if chainConfig.XDPoS != nil {
		return XDPoS.New(chainConfig, db)
	}

	return ethash.NewFaker(), nil
}

// APIs return the collection of RPC services the ethereum package offers.
// NOTE, some of these services probably need to be moved to somewhere else.
func (e *Ethereum) APIs() []rpc.API {
	apis := ethapi.GetAPIs(e.APIBackend, e.BlockChain())

	// Append any APIs exposed explicitly by the consensus engine
	apis = append(apis, e.engine.APIs(e.BlockChain())...)

	// Append all the local APIs and return
	return append(apis, []rpc.API{
		{
			Namespace: "eth",
			Service:   NewEthereumAPI(e),
		}, {
			Namespace: "miner",
			Service:   NewMinerAPI(e),
		}, {
			Namespace: "eth",
			Service:   downloader.NewDownloaderAPI(e.protocolManager.downloader, e.eventMux),
		}, {
			Namespace: "eth",
			Service:   filters.NewFilterAPI(filters.NewFilterSystem(e.APIBackend, filters.Config{LogCacheSize: e.config.FilterLogCacheSize}), false),
		}, {
			Namespace: "admin",
			Service:   NewAdminAPI(e),
		}, {
			Namespace: "debug",
			Service:   NewDebugAPI(e),
		}, {
			Namespace: "net",
			Service:   e.netRPCService,
		},
	}...)
}

func logXDPoSConfig(chainConfig *params.ChainConfig, compatErr *params.ConfigCompatError) {
	if compatErr != nil || chainConfig == nil || chainConfig.XDPoS == nil || chainConfig.XDPoS.V2 == nil {
		return
	}

	log.Info("Load xdc config", "config.V2", chainConfig.XDPoS.V2.StableLogValue())
}

func (e *Ethereum) ResetWithGenesisBlock(gb *types.Block) {
	e.blockchain.ResetWithGenesisBlock(gb)
}

func (e *Ethereum) Etherbase() (eb common.Address, err error) {
	e.lock.RLock()
	etherbase := e.etherbase
	e.lock.RUnlock()

	if etherbase != (common.Address{}) {
		return etherbase, nil
	}
	if wallets := e.AccountManager().Wallets(); len(wallets) > 0 {
		if accounts := wallets[0].Accounts(); len(accounts) > 0 {
			etherbase := accounts[0].Address

			e.lock.Lock()
			e.etherbase = etherbase
			e.lock.Unlock()

			log.Info("Etherbase automatically configured", "address", etherbase)
			return etherbase, nil
		}
	}
	return common.Address{}, errors.New("etherbase must be explicitly specified")
}

// set in js console via admin interface or wrapper from cli flags
func (e *Ethereum) SetEtherbase(etherbase common.Address) {
	e.lock.Lock()
	e.etherbase = etherbase
	e.lock.Unlock()

	e.miner.SetEtherbase(etherbase)
}

// ValidateMasternode checks if node's address is in set of masternodes
func (e *Ethereum) ValidateMasternode() (bool, error) {
	eb, err := e.Etherbase()
	if err != nil {
		return false, err
	}
	if e.blockchain.Config().XDPoS != nil {
		//check if miner's wallet is in set of validators
		c := e.engine.(*XDPoS.XDPoS)

		authorized := c.IsAuthorisedAddress(e.blockchain, e.blockchain.CurrentHeader(), eb)
		if !authorized {
			//This miner doesn't belong to set of validators
			return false, nil
		}
	} else {
		return false, errors.New("only verify masternode permission in XDPoS protocol")
	}
	return true, nil
}

func (e *Ethereum) StartStaking(local bool) error {
	eb, err := e.Etherbase()
	if err != nil {
		log.Error("Cannot start mining without etherbase", "err", err)
		return fmt.Errorf("etherbase missing: %v", err)
	}
	if XDPoS, ok := e.engine.(*XDPoS.XDPoS); ok {
		wallet, err := e.accountManager.Find(accounts.Account{Address: eb})
		if wallet == nil || err != nil {
			log.Error("Etherbase account unavailable locally", "address", eb, "err", err)
			return fmt.Errorf("signer missing: %v", err)
		}
		XDPoS.Authorize(eb, wallet.SignHash)
	}
	if local {
		// If local (CPU) mining is started, we can disable the transaction rejection
		// mechanism introduced to speed sync times. CPU mining on mainnet is ludicrous
		// so noone will ever hit this path, whereas marking sync done on CPU mining
		// will ensure that private networks work in single miner mode too.
		atomic.StoreUint32(&e.protocolManager.acceptTxs, 1)
	}
	go e.miner.Start(eb)
	return nil
}

func (e *Ethereum) StopStaking() {
	e.miner.Stop()
}

func (e *Ethereum) IsStaking() bool     { return e.miner.Mining() }
func (e *Ethereum) Miner() *miner.Miner { return e.miner }

func (e *Ethereum) AccountManager() *accounts.Manager  { return e.accountManager }
func (e *Ethereum) BlockChain() *core.BlockChain       { return e.blockchain }
func (e *Ethereum) TxPool() *txpool.TxPool             { return e.txPool }
func (e *Ethereum) EventMux() *event.TypeMux           { return e.eventMux }
func (e *Ethereum) Engine() consensus.Engine           { return e.engine }
func (e *Ethereum) ChainDb() ethdb.Database            { return e.chainDb }
func (e *Ethereum) IsListening() bool                  { return true } // Always listening
func (e *Ethereum) EthVersion() int                    { return int(ProtocolVersions[0]) }
func (e *Ethereum) NetVersion() uint64                 { return e.networkId }
func (e *Ethereum) Downloader() *downloader.Downloader { return e.protocolManager.downloader }
func (e *Ethereum) BloomIndexer() *core.ChainIndexer   { return e.bloomIndexer }

// Protocols returns all the currently configured
func (e *Ethereum) Protocols() []p2p.Protocol {
	protos := make([]p2p.Protocol, len(ProtocolVersions))
	for i, vsn := range ProtocolVersions {
		protos[i] = e.protocolManager.makeProtocol(vsn)
		protos[i].Attributes = []enr.Entry{e.currentEthEntry()}
	}
	return protos
}

// Start implements node.Lifecycle, starting all internal goroutines needed by the
// Ethereum protocol implementation.
func (e *Ethereum) Start() error {
	e.startEthEntryUpdate(e.p2pServer.LocalNode())

	// Start the bloom bits servicing goroutines
	e.startBloomHandlers(params.BloomBitsBlocks)

	// Figure out a max peers count based on the server limits
	maxPeers := e.p2pServer.MaxPeers
	if e.config.LightServ > 0 {
		if e.config.LightPeers >= e.p2pServer.MaxPeers {
			return fmt.Errorf("invalid peer config: light peer count (%d) >= total peer count (%d)", e.config.LightPeers, e.p2pServer.MaxPeers)
		}
		maxPeers -= e.config.LightPeers
	}
	// Start the networking layer and the light server if requested
	e.protocolManager.Start(maxPeers)
	return nil
}

// Stop implements node.Lifecycle, terminating all internal goroutines used by the
// Ethereum protocol.
func (e *Ethereum) Stop() error {
	log.Info("Stopping Ethereum bloomIndexer start")
	e.bloomIndexer.Close()
	log.Info("Ethereum bloomIndexer stopped")

	log.Info("Stopping Ethereum blockchain start")
	e.blockchain.Stop()
	log.Info("Ethereum blockchain stopped")

	log.Info("Stopping Ethereum protocolManager start")
	e.protocolManager.Stop()
	log.Info("Ethereum protocolManager stopped")

	log.Info("Stopping Ethereum txPool start")
	e.txPool.Close()
	log.Info("Ethereum txPool stopped")

	log.Info("Stopping Ethereum shutdownChan start")
	close(e.shutdownChan)
	log.Info("Ethereum shutdownChan stopped")

	log.Info("Stopping Ethereum miner start")
	e.miner.Stop()
	log.Info("Ethereum miner stopped")

	log.Info("Stopping Ethereum eventMux start")
	e.eventMux.Stop()
	log.Info("Ethereum eventMux stopped")

	log.Info("Stopping Ethereum chainDb start")
	e.chainDb.Close()
	log.Info("Ethereum chainDb stopped")

	return nil
}

func (e *Ethereum) GetPeer() int {
	return len(e.protocolManager.peers.peers)
}

func (e *Ethereum) GetXDCX() *XDCx.XDCX {
	return e.XDCX
}

func (e *Ethereum) OrderPool() *legacypool.OrderPool {
	return e.orderPool
}

func (e *Ethereum) GetXDCXLending() *XDCxlending.Lending {
	return e.Lending
}

// LendingPool geth eth lending pool
func (e *Ethereum) LendingPool() *legacypool.LendingPool {
	return e.lendingPool
}

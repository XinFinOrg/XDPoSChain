// Copyright 2015 The go-ethereum Authors
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
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"math/big"
	"sync/atomic"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/consensus/misc"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/tracing"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/types/bal"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/internal/telemetry"
	"github.com/XinFinOrg/XDPoSChain/log"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/XinFinOrg/XDPoSChain/trie"
	"github.com/holiman/uint256"
)

// StateProcessor is a basic Processor, which takes care of transitioning
// state from one point to another.
//
// StateProcessor implements Processor.
type StateProcessor struct {
	chain ChainContext // Chain context interface
}

// NewStateProcessor initialises a new StateProcessor.
func NewStateProcessor(chain ChainContext) *StateProcessor {
	return &StateProcessor{
		chain: chain,
	}
}

// chainConfig returns the chain configuration.
func (p *StateProcessor) chainConfig() *params.ChainConfig {
	return p.chain.Config()
}

// getCoinbaseOwner resolves the TRC21 fee recipient for the block. After
// TIPTRC21Fee (Apothem 23,779,191; mainnet 38,383,838), the masternode's
// owner — looked up from the validator contract (0x88) via GetCandidateOwner —
// receives the transaction-fee credit instead of the masternode itself. When
// no owner is registered the candidate-owner lookup returns the zero address
// and state_transition.go falls back to the standard coinbase routing.
// Mirrors XDPoSChain v2.6.8 core/state_processor.go getCoinbaseOwner.
func getCoinbaseOwner(engine consensus.Engine, statedb *state.StateDB, header *types.Header) common.Address {
	beneficiary, _ := engine.Author(header)
	return state.GetCandidateOwner(statedb, beneficiary)
}

// Process processes the state changes according to the Ethereum rules by running
// the transaction messages using the statedb and applying any rewards to both
// the processor (coinbase) and any included uncles.
//
// Process returns the receipts and logs accumulated during the process and
// returns the amount of gas that was used in the process. If any of the
// transactions failed to execute due to insufficient gas it will return an error.
func (p *StateProcessor) Process(ctx context.Context, block *types.Block, statedb *state.StateDB, jumpDestCache vm.JumpDestCache, cfg vm.Config, execIndex *atomic.Int64) (*ProcessResult, error) {
	// XDC: capture pre-tx state for the XDPoS engine reward calculation.
	// Reward computation at checkpoint blocks must read account balances
	// BEFORE tx execution; without this, reward calculation uses post-tx
	// state and merkle root diverges at every Epoch checkpoint.
	parentState := statedb.Copy()
	var (
		config      = p.chainConfig()
		receipts    = make(types.Receipts, 0, len(block.Transactions()))
		header      = block.Header()
		blockHash   = block.Hash()
		blockNumber = block.Number()
		allLogs     []*types.Log
		gp          = NewGasPool(block.GasLimit())
	)
	var tracingStateDB = vm.StateDB(statedb)
	if hooks := cfg.Tracer; hooks != nil {
		tracingStateDB = state.NewHookedState(statedb, hooks)
	}
	// Mutate the block and state according to any hard-fork specs
	if config.DAOForkSupport && config.DAOForkBlock != nil && config.DAOForkBlock.Cmp(block.Number()) == 0 {
		misc.ApplyDAOHardFork(tracingStateDB)
	}

	// XDC: at the TIPSigning fork block (mainnet 3,000,000; Apothem
	// 23,779,191), canonical XDPoSChain wipes the BlockSigners contract
	// (0x89). After this block, signing transactions are handled by
	// ApplySigningTransaction without invoking the contract's EVM code,
	// so the on-chain code+storage at 0x89 is no longer needed and
	// removing it shrinks the state trie. We MUST match the canonical
	// behaviour exactly or the state root diverges at the fork block.
	//
	// Implementation note: the IntermediateRoot(false) call BEFORE
	// SelfDestruct is required for pathdb correctness. Modern geth's
	// pathdb commits mutations against the trie that was opened during
	// the previous IntermediateRoot. Without first opening the trie here
	// (against the pre-deletion originalRoot), the subsequent
	// SelfDestruct + Finalise + IntermediateRoot path leaves the trie in
	// a state where the deletion is recorded in mutations but does not
	// produce the canonical post-deletion root.
	//
	// This must run in exactly this order, and before the parent-header
	// lookup below has any chance to matter: IntermediateRoot(false) →
	// SelfDestruct → Finalise(true) → IntermediateRoot(true).
	if common.TIPSigning.Cmp(block.Number()) == 0 {
		_ = statedb.IntermediateRoot(false)
		statedb.SelfDestruct(common.BlockSignersBinary)
		statedb.Finalise(true)
		_ = statedb.IntermediateRoot(true)
	}

	parent := p.chain.GetHeader(block.ParentHash(), block.NumberU64()-1)
	if parent == nil {
		return nil, fmt.Errorf("missing parent %#x", block.ParentHash())
	}
	var (
		context         = NewEVMBlockContext(header, p.chain, nil)
		signer          = types.MakeSigner(config, header.Number, header.Time)
		evm             = vm.NewEVM(context, tracingStateDB, config, cfg)
		blockAccessList = bal.NewConstructionBlockAccessList()
	)
	defer evm.Release()

	if jumpDestCache != nil {
		evm.SetJumpDestCache(jumpDestCache)
	}
	// Run the pre-execution system calls
	blockAccessList.Merge(PreExecution(ctx, block.BeaconRoot(), parent, config, evm, block.Number(), block.Time()))

	// XDC: resolve TRC21 fee recipient once per block. After TIPTRC21Fee
	// (Apothem 23,779,191), the masternode's registered candidate-owner —
	// looked up from the validator contract (0x88) — receives the per-tx
	// gas-fee credit instead of the masternode. Computed before the loop so
	// that within-block balance mutations on the owner do not influence the
	// lookup. Passed through to ApplyTransactionWithEVM where it routes the
	// fee in state_transition.go.
	coinbaseOwner := getCoinbaseOwner(p.chain.Engine(), statedb, header)

	// Iterate over and process the individual transactions
	for i, tx := range block.Transactions() {
		// Publish the progress, letting the prefetcher skip caught up work.
		// Must come before the XDC dispatch shortcuts below: a block composed
		// entirely of special (0x89/0x92/0x93) txs that `continue` past the
		// normal path would otherwise never publish progress, stalling the
		// coordinated prefetcher against a never-advancing index.
		if execIndex != nil {
			execIndex.Store(int64(i))
		}
		statedb.SetTxContext(tx.Hash(), i, uint32(i))

		// XDC: signing transactions at the TIPSigning fork are routed to
		// ApplySigningTransaction, which bumps the sender's nonce and emits a
		// minimal receipt without invoking the EVM (zero gas). The contract
		// at 0x89 (BlockSignersBinary) is wiped at TIPSigning, so dispatching
		// here through EVM would fail. Canonical XDPoSChain mirrors this exact
		// dispatch and the parity gates depend on it producing byte-identical
		// receipts.
		if to := tx.To(); to != nil && *to == common.BlockSignersBinary && config.IsTIPSigning(blockNumber) {
			receipt, err := ApplySigningTransaction(config, statedb, blockNumber, blockHash, tx, gp.Used())
			if err != nil {
				return nil, fmt.Errorf("could not apply signing tx %d [%v]: %w", i, tx.Hash().Hex(), err)
			}
			receipts = append(receipts, receipt)
			allLogs = append(allLogs, receipt.Logs...)
			continue
		}

		// XDC: between TIPXDCX (Apothem 23,779,191) and TIPXDCXReceiverDisable
		// (Apothem 66,825,000), transactions targeting TradingStateAddrBinary
		// (0x92) or XDCXLendingAddressBinary (0x93) are emitted by the XDCx
		// subsystem as "empty" notifier transactions. Canonical XDPoSChain
		// routes them to ApplyEmptyTransaction: no EVM execution, zero gas,
		// minimal receipt with a single log carrying only the To address.
		// Running them through the normal EVM path produces a non-zero gas
		// receipt and diverges from canonical at the very first TIPXDCX block.
		if config.IsTIPXDCXReceiver(blockNumber) {
			if to := tx.To(); to != nil && (*to == common.TradingStateAddrBinary || *to == common.XDCXLendingAddressBinary) {
				receipt, err := ApplyEmptyTransaction(config, statedb, blockNumber, blockHash, tx, gp.Used())
				if err != nil {
					return nil, fmt.Errorf("could not apply empty tx %d [%v]: %w", i, tx.Hash().Hex(), err)
				}
				receipts = append(receipts, receipt)
				allLogs = append(allLogs, receipt.Logs...)
				continue
			}
		}

		msg, err := TransactionToMessage(tx, signer, header.BaseFee)
		if err != nil {
			return nil, fmt.Errorf("could not apply tx %d [%v]: %w", i, tx.Hash().Hex(), err)
		}
		statedb.SetTxContext(tx.Hash(), i, uint32(i+1))
		_, _, spanEnd := telemetry.StartSpan(ctx, "core.ApplyTransactionWithEVM",
			telemetry.StringAttribute("tx.hash", tx.Hash().Hex()),
			telemetry.IntAttribute("tx.index", i),
		)
		receipt, bal, err := ApplyTransactionWithEVM(msg, gp, statedb, blockNumber, blockHash, context.Time, tx, evm, coinbaseOwner)
		if err != nil {
			spanEnd(&err)
			return nil, fmt.Errorf("could not apply tx %d [%v]: %w", i, tx.Hash().Hex(), err)
		}
		receipts = append(receipts, receipt)
		allLogs = append(allLogs, receipt.Logs...)
		blockAccessList.Merge(bal)
		spanEnd(nil)
	}
	requests, bal, err := PostExecution(ctx, config, block.Number(), block.Time(), allLogs, evm, uint32(len(block.Transactions())+1))
	if err != nil {
		return nil, err
	}
	blockAccessList.Merge(bal)

	// XDC: Set parentState on the engine for reward calculation.
	if xdposEngine, ok := p.chain.Engine().(interface{ SetParentState(*state.StateDB) }); ok {
		xdposEngine.SetParentState(parentState)
	}

	// Finalize the block, applying any consensus engine specific extras
	// (e.g. block rewards).
	p.chain.Engine().Finalize(p.chain, header, tracingStateDB, block.Body(), uint32(len(block.Transactions())+1), blockAccessList)

	return &ProcessResult{
		Receipts: receipts,
		Requests: requests,
		Logs:     allLogs,
		GasUsed:  gp.Used(),
		Bal:      blockAccessList,
	}, nil
}

// PreExecution processes pre-execution state changes and system calls.
func PreExecution(ctx context.Context, beaconRoot *common.Hash, parent *types.Header, config *params.ChainConfig, evm *vm.EVM, number *big.Int, time uint64) *bal.ConstructionBlockAccessList {
	_, _, spanEnd := telemetry.StartSpan(ctx, "core.preExecution")
	defer spanEnd(nil)

	var blockAccessList *bal.ConstructionBlockAccessList
	if config.IsAmsterdam(number, time) {
		blockAccessList = bal.NewConstructionBlockAccessList()

		// EIP-7997: insert the deterministic deployment factory at the Amsterdam
		// activation block via an irregular state transition.
		if !config.IsAmsterdam(parent.Number, parent.Time) {
			misc.ApplyEIP7997(evm.StateDB)
		}
	}
	// EIP-4788
	if beaconRoot != nil {
		ProcessBeaconBlockRoot(*beaconRoot, evm, blockAccessList)
	}
	// EIP-2935: serve parent block hash from state. Upstream gates this on
	// Prague/UBT; on XDC the ring is also populated from Bogotá onward so
	// EIP-7709's state-serving BLOCKHASH has history to read.
	if config.IsPrague(number, time) || config.IsUBT(number, time) || config.IsBogota(number, time) {
		ProcessParentBlockHash(parent.Hash(), evm, blockAccessList)
	}
	return blockAccessList
}

// PostExecution processes post-execution system calls when Prague is enabled.
// If Prague is not activated, it returns null requests to differentiate from
// empty requests.
func PostExecution(ctx context.Context, config *params.ChainConfig, number *big.Int, time uint64, allLogs []*types.Log, evm *vm.EVM, blockAccessIndex uint32) (requests [][]byte, blockAccessList *bal.ConstructionBlockAccessList, err error) {
	_, _, spanEnd := telemetry.StartSpan(ctx, "core.postExecution")
	defer spanEnd(&err)

	if config.IsAmsterdam(number, time) {
		blockAccessList = bal.NewConstructionBlockAccessList()
	}
	rules := config.Rules(number, true, time) // IsMerge is always true
	// Read requests if Prague is enabled.
	if config.IsPrague(number, time) {
		requests = [][]byte{}
		// EIP-6110
		if err := ParseDepositLogs(&requests, allLogs, config); err != nil {
			return nil, nil, fmt.Errorf("failed to parse deposit logs: %w", err)
		}
		// EIP-7002
		if err := ProcessWithdrawalQueue(&requests, rules, evm, blockAccessIndex, blockAccessList); err != nil {
			return nil, nil, fmt.Errorf("failed to process withdrawal queue: %w", err)
		}
		// EIP-7251
		if err := ProcessConsolidationQueue(&requests, rules, evm, blockAccessIndex, blockAccessList); err != nil {
			return nil, nil, fmt.Errorf("failed to process consolidation queue: %w", err)
		}
	}

	if config.IsAmsterdam(number, time) {
		// EIP-8282
		if err := ProcessBuilderDepositQueue(&requests, rules, evm, blockAccessIndex, blockAccessList); err != nil {
			return nil, nil, fmt.Errorf("failed to process builder deposit queue: %w", err)
		}
		if err := ProcessBuilderExitQueue(&requests, rules, evm, blockAccessIndex, blockAccessList); err != nil {
			return nil, nil, fmt.Errorf("failed to process builder exit queue: %w", err)
		}
	}
	return requests, blockAccessList, nil
}

// ApplyTransactionWithEVM attempts to apply a transaction to the given state database
// and uses the input parameters for its environment similar to ApplyTransaction. However,
// this method takes an already created EVM instance as input.
//
// The optional owner parameter (XDC) specifies the coinbase-owner address used for
// TRC21 fee routing post-TIPTRC21Fee. When no owner is supplied behaviour is
// bit-identical to upstream v1.17.4 (refs #740/#742).
func ApplyTransactionWithEVM(msg *Message, gp *GasPool, statedb *state.StateDB, blockNumber *big.Int, blockHash common.Hash, blockTime uint64, tx *types.Transaction, evm *vm.EVM, owner ...common.Address) (receipt *types.Receipt, bal *bal.ConstructionBlockAccessList, err error) {
	if hooks := evm.Config.Tracer; hooks != nil {
		if hooks.OnTxStart != nil {
			hooks.OnTxStart(evm.GetVMContext(), tx, msg.From)
		}
		if hooks.OnTxEnd != nil {
			defer func() { hooks.OnTxEnd(receipt, err) }()
		}
	}
	// Apply the transaction to the current state (included in the env).
	// Thread the optional owner through to ApplyMessage for TRC21 fee routing.
	result, err := ApplyMessage(evm, msg, gp, owner...)
	if err != nil {
		return nil, nil, err
	}
	// Update the state with pending changes.
	var root []byte
	if evm.ChainConfig().IsByzantium(blockNumber) {
		bal = evm.StateDB.Finalise(true)
	} else {
		root = statedb.IntermediateRoot(evm.ChainConfig().IsEIP158(blockNumber)).Bytes()
	}
	// Merge the tx-local access event into the "block-local" one, in order to collect
	// all values, so that the witness can be built.
	if statedb.Database().Type().Is(state.TypeUBT) {
		statedb.AccessEvents().Merge(evm.AccessEvents)
	}
	return MakeReceipt(evm, result, statedb, blockNumber, blockHash, blockTime, tx, gp.CumulativeUsed(), root), bal, nil
}

// MakeReceipt generates the receipt object for a transaction given its execution result.
func MakeReceipt(evm *vm.EVM, result *ExecutionResult, statedb *state.StateDB, blockNumber *big.Int, blockHash common.Hash, blockTime uint64, tx *types.Transaction, cumulativeGas uint64, root []byte) *types.Receipt {
	// Create a new receipt for the transaction, storing the intermediate root
	// and gas used by the tx.
	//
	// The cumulative gas used equals the sum of gasUsed across all preceding
	// txs with refunded gas deducted.
	receipt := &types.Receipt{Type: tx.Type(), PostState: root, CumulativeGasUsed: cumulativeGas}
	if result.Failed() {
		receipt.Status = types.ReceiptStatusFailed
	} else {
		receipt.Status = types.ReceiptStatusSuccessful
	}
	receipt.TxHash = tx.Hash()

	// GasUsed = max(tx_gas_used - gas_refund, calldata_floor_gas_cost), unchanged
	// in the Amsterdam fork.
	receipt.GasUsed = result.UsedGas

	if tx.Type() == types.BlobTxType {
		receipt.BlobGasUsed = uint64(len(tx.BlobHashes()) * params.BlobTxBlobGasPerBlob)
		receipt.BlobGasPrice = evm.Context.BlobBaseFee
	}

	// If the transaction created a contract, store the creation address in
	// the receipt. Frame transactions never create contracts.
	if tx.To() == nil && tx.Type() != types.FrameTxType {
		receipt.ContractAddress = crypto.CreateAddress(evm.TxContext.Origin, tx.Nonce())
	}

	// Set the receipt logs and create the bloom filter.
	receipt.Logs = statedb.GetLogs(tx.Hash(), blockNumber.Uint64(), blockHash, blockTime)
	receipt.Bloom = types.CreateBloom(receipt)
	receipt.BlockHash = blockHash
	receipt.BlockNumber = blockNumber
	receipt.TransactionIndex = uint(statedb.TxIndex())

	// EIP-8141: attach the frame receipts and the fee payer. The
	// transaction's logs are the concatenation of the frame logs in frame
	// order (the driver discards rolled-back logs via the state journal), so
	// the per-frame grouping must partition receipt.Logs exactly.
	if tx.Type() == types.FrameTxType {
		if result.Payer != nil {
			receipt.Payer = result.Payer
		}
		if len(result.FrameReceipts) > 0 {
			receipt.FrameReceipts = make([]*types.FrameReceipt, len(result.FrameReceipts))
			frameLogCount := 0
			for i := range result.FrameReceipts {
				receipt.FrameReceipts[i] = &result.FrameReceipts[i]
				frameLogCount += len(result.FrameReceipts[i].Logs)
			}
			if frameLogCount != len(receipt.Logs) {
				log.Error("FrameTx receipt log mismatch", "tx", tx.Hash(),
					"frameLogs", frameLogCount, "txLogs", len(receipt.Logs))
			}
			// The payload carries no transaction-level status; derive one
			// from the per-frame statuses for interfaces that need it.
			receipt.Status = types.DeriveFrameTxStatus(receipt.FrameReceipts)
		}
	}
	return receipt
}

// ApplyTransaction attempts to apply a transaction to the given state database
// and uses the input parameters for its environment. It returns the receipt
// for the transaction and an error if the transaction failed,
// indicating the block was invalid.
func ApplyTransaction(evm *vm.EVM, gp *GasPool, statedb *state.StateDB, header *types.Header, tx *types.Transaction) (*types.Receipt, *bal.ConstructionBlockAccessList, error) {
	msg, err := TransactionToMessage(tx, types.MakeSigner(evm.ChainConfig(), header.Number, header.Time), header.BaseFee)
	if err != nil {
		return nil, nil, err
	}
	// Create a new context to be used in the EVM environment
	return ApplyTransactionWithEVM(msg, gp, statedb, header.Number, header.Hash(), header.Time, tx, evm)
}

// systemCallGasBudget returns the gas budget for system calls.
func systemCallGasBudget(evm *vm.EVM) (gasLimit uint64, gasBudget vm.GasBudget) {
	if !evm.GetRules().IsAmsterdam {
		gasLimit = 30_000_000
		gasBudget = vm.NewGasBudget(gasLimit, 0)
	} else {
		// SYSTEM_MAX_SSTORES_PER_CALL = 16 is the upper bound on the number of
		// new storage slots a single system call is expected to write.
		stateBudget := params.SystemMaxSStoresPerCall * evm.Context.CostPerStateByte * params.StorageCreationSize
		gasLimit = 30_000_000
		gasBudget = vm.NewGasBudget(gasLimit, stateBudget)
	}
	return gasLimit, gasBudget
}

// ProcessBeaconBlockRoot applies the EIP-4788 system call to the beacon block root
// contract. This method is exported to be used in tests.
func ProcessBeaconBlockRoot(beaconRoot common.Hash, evm *vm.EVM, blockAccessList *bal.ConstructionBlockAccessList) {
	if tracer := evm.Config.Tracer; tracer != nil {
		onSystemCallStart(tracer, evm.GetVMContext())
		if tracer.OnSystemCallEnd != nil {
			defer tracer.OnSystemCallEnd()
		}
	}
	gasLimit, gasBudget := systemCallGasBudget(evm)
	msg := &Message{
		From:      params.SystemAddress,
		GasLimit:  gasLimit,
		GasPrice:  uint256.NewInt(0),
		GasFeeCap: uint256.NewInt(0),
		GasTipCap: uint256.NewInt(0),
		To:        &params.BeaconRootsAddress,
		Data:      beaconRoot[:],
	}
	evm.SetTxContext(NewEVMTxContext(msg))
	evm.StateDB.Prepare(evm.GetRules(), common.Address{}, common.Address{}, nil, nil, nil)
	evm.StateDB.SetTxContext(common.Hash{}, 0, 0)
	evm.StateDB.AddAddressToAccessList(params.BeaconRootsAddress)
	_, _, _ = evm.Call(msg.From, *msg.To, msg.Data, gasBudget, common.U2560)
	if evm.StateDB.AccessEvents() != nil {
		evm.StateDB.AccessEvents().Merge(evm.AccessEvents)
	}
	blockAccessList.Merge(evm.StateDB.Finalise(true))
}

// ProcessParentBlockHash stores the parent block hash in the history storage contract
// as per EIP-2935/7709.
func ProcessParentBlockHash(prevHash common.Hash, evm *vm.EVM, blockAccessList *bal.ConstructionBlockAccessList) {
	// EIP-2935: if the history contract already carries code, it must be the
	// canonical bytecode. (Guards against a mis-seeded genesis alloc.)
	code := evm.StateDB.GetCode(params.HistoryStorageAddress)
	if len(code) > 0 && !bytes.Equal(code, params.HistoryStorageCode) {
		panic(fmt.Sprintf("history storage code mismatch: have %s want %s",
			crypto.Keccak256Hash(code), crypto.Keccak256Hash(params.HistoryStorageCode)))
	}

	// XDC activates Prague by BLOCK number and does NOT ship the history contract
	// in genesis. So at/after the Prague block, if the contract is absent, deploy
	// it and backfill the recent block-hash ring buffer directly — this is the
	// per-block state mutation canonical XDPoSChain applies at the Prague block
	// (e.g. devnet 5551 block 50,000 → stateRoot c0060c78…). Upstream time-based
	// Prague chains ship the contract pre-deployed, so len(code) > 0 and this is
	// skipped. Refs XDCIndia/ethOne#39.
	blockNumber := evm.Context.BlockNumber
	if len(code) == 0 && blockNumber != nil {
		forkBlock := evm.ChainConfig().PragueBlock
		bogota := evm.ChainConfig().IsBogota(blockNumber, evm.Context.Time)
		if (forkBlock != nil && blockNumber.Cmp(forkBlock) >= 0) || bogota {
			if !evm.StateDB.Exist(params.HistoryStorageAddress) {
				evm.StateDB.CreateAccount(params.HistoryStorageAddress)
			}
			if evm.StateDB.GetNonce(params.HistoryStorageAddress) == 0 {
				evm.StateDB.SetNonce(params.HistoryStorageAddress, 1, tracing.NonceChangeUnspecified)
			}
			evm.StateDB.SetCode(params.HistoryStorageAddress, params.HistoryStorageCode, tracing.CodeChangeGenesis)
			if blockNumber.Sign() > 0 {
				end := blockNumber.Uint64() - 1
				start := end
				if bogota && forkBlock == nil {
					// EIP-7709 (Bogotá without Prague): no fork-block bound
					// exists to limit the backfill, so fill the full window
					// available from genesis (saturating at HISTORY_SERVE_
					// WINDOW) — the first Bogotá block must be able to serve
					// its whole BLOCKHASH window immediately.
					if end+1 > params.HistoryServeWindow {
						start = end + 1 - params.HistoryServeWindow
					} else {
						start = 0
					}
				} else if end+1 > params.HistoryServeWindow {
					start = end + 1 - params.HistoryServeWindow
				}
				if forkBlock != nil && forkBlock.Sign() > 0 {
					if forkStart := forkBlock.Uint64() - 1; forkStart > start {
						start = forkStart
					}
				}
				for n := start; n <= end; n++ {
					hash := evm.Context.GetHash(n)
					if hash == (common.Hash{}) {
						continue
					}
					evm.StateDB.SetState(params.HistoryStorageAddress, historyStorageKey(n), hash)
				}
			}
		}
	}

	if tracer := evm.Config.Tracer; tracer != nil {
		onSystemCallStart(tracer, evm.GetVMContext())
		if tracer.OnSystemCallEnd != nil {
			defer tracer.OnSystemCallEnd()
		}
	}
	gasLimit, gasBudget := systemCallGasBudget(evm)
	msg := &Message{
		From:      params.SystemAddress,
		GasLimit:  gasLimit,
		GasPrice:  uint256.NewInt(0),
		GasFeeCap: uint256.NewInt(0),
		GasTipCap: uint256.NewInt(0),
		To:        &params.HistoryStorageAddress,
		Data:      prevHash.Bytes(),
	}
	evm.SetTxContext(NewEVMTxContext(msg))
	evm.StateDB.Prepare(evm.GetRules(), common.Address{}, common.Address{}, nil, nil, nil)
	evm.StateDB.SetTxContext(common.Hash{}, 0, 0)
	evm.StateDB.AddAddressToAccessList(params.HistoryStorageAddress)
	_, _, err := evm.Call(msg.From, *msg.To, msg.Data, gasBudget, common.U2560)
	if err != nil {
		panic(err)
	}
	if evm.StateDB.AccessEvents() != nil {
		evm.StateDB.AccessEvents().Merge(evm.AccessEvents)
	}
	blockAccessList.Merge(evm.StateDB.Finalise(true))
}

// historyStorageKey maps a block number to its slot in the EIP-2935 history
// ring buffer (HISTORY_SERVE_WINDOW entries).
func historyStorageKey(number uint64) common.Hash {
	ringIndex := number % params.HistoryServeWindow
	var key common.Hash
	binary.BigEndian.PutUint64(key[24:], ringIndex)
	return key
}

// ProcessWithdrawalQueue calls the EIP-7002 withdrawal queue contract.
// It returns the opaque request data returned by the contract.
func ProcessWithdrawalQueue(requests *[][]byte, rules params.Rules, evm *vm.EVM, blockAccessIndex uint32, blockAccessList *bal.ConstructionBlockAccessList) error {
	return processRequestsSystemCall(requests, rules, evm, 0x01, params.WithdrawalQueueAddress, blockAccessIndex, blockAccessList)
}

// ProcessConsolidationQueue calls the EIP-7251 consolidation queue contract.
// It returns the opaque request data returned by the contract.
func ProcessConsolidationQueue(requests *[][]byte, rules params.Rules, evm *vm.EVM, blockAccessIndex uint32, blockAccessList *bal.ConstructionBlockAccessList) error {
	return processRequestsSystemCall(requests, rules, evm, 0x02, params.ConsolidationQueueAddress, blockAccessIndex, blockAccessList)
}

// ProcessBuilderDepositQueue calls the EIP-8282 builder deposit contract.
// It returns the opaque request data returned by the contract.
func ProcessBuilderDepositQueue(requests *[][]byte, rules params.Rules, evm *vm.EVM, blockAccessIndex uint32, blockAccessList *bal.ConstructionBlockAccessList) error {
	return processRequestsSystemCall(requests, rules, evm, 0x03, params.BuilderDepositAddress, blockAccessIndex, blockAccessList)
}

// ProcessBuilderExitQueue calls the EIP-8282 builder exit contract.
// It returns the opaque request data returned by the contract.
func ProcessBuilderExitQueue(requests *[][]byte, rules params.Rules, evm *vm.EVM, blockAccessIndex uint32, blockAccessList *bal.ConstructionBlockAccessList) error {
	return processRequestsSystemCall(requests, rules, evm, 0x04, params.BuilderExitAddress, blockAccessIndex, blockAccessList)
}

func processRequestsSystemCall(requests *[][]byte, rules params.Rules, evm *vm.EVM, requestType byte, addr common.Address, blockAccessIndex uint32, blockAccessList *bal.ConstructionBlockAccessList) error {
	if tracer := evm.Config.Tracer; tracer != nil {
		onSystemCallStart(tracer, evm.GetVMContext())
		if tracer.OnSystemCallEnd != nil {
			defer tracer.OnSystemCallEnd()
		}
	}
	gasLimit, gasBudget := systemCallGasBudget(evm)
	msg := &Message{
		From:      params.SystemAddress,
		GasLimit:  gasLimit,
		GasPrice:  uint256.NewInt(0),
		GasFeeCap: uint256.NewInt(0),
		GasTipCap: uint256.NewInt(0),
		To:        &addr,
	}
	evm.SetTxContext(NewEVMTxContext(msg))
	evm.StateDB.Prepare(rules, common.Address{}, common.Address{}, nil, nil, nil)
	evm.StateDB.SetTxContext(common.Hash{}, 0, blockAccessIndex)
	evm.StateDB.AddAddressToAccessList(addr)
	ret, _, err := evm.Call(msg.From, *msg.To, msg.Data, gasBudget, common.U2560)
	if evm.StateDB.AccessEvents() != nil {
		evm.StateDB.AccessEvents().Merge(evm.AccessEvents)
	}
	bal := evm.StateDB.Finalise(true)
	if err != nil {
		return fmt.Errorf("system call failed to execute: %v", err)
	}
	blockAccessList.Merge(bal)

	if len(ret) == 0 {
		return nil // skip empty output
	}
	// Append prefixed requestsData to the requests list.
	requestsData := make([]byte, len(ret)+1)
	requestsData[0] = requestType
	copy(requestsData[1:], ret)
	*requests = append(*requests, requestsData)
	return nil
}

var depositTopic = common.HexToHash("0x649bbc62d0e31342afea4e5cd82d4049e7e1ee912fc0889aa790803be39038c5")

// ParseDepositLogs extracts the EIP-6110 deposit values from logs emitted by
// BeaconDepositContract.
func ParseDepositLogs(requests *[][]byte, logs []*types.Log, config *params.ChainConfig) error {
	deposits := make([]byte, 1) // note: first byte is 0x00 (== deposit request type)
	for _, log := range logs {
		if log.Address == config.DepositContractAddress && len(log.Topics) > 0 && log.Topics[0] == depositTopic {
			request, err := types.DepositLogToRequest(log.Data)
			if err != nil {
				return fmt.Errorf("unable to parse deposit data: %v", err)
			}
			deposits = append(deposits, request...)
		}
	}
	if len(deposits) > 1 {
		*requests = append(*requests, deposits)
	}
	return nil
}

func onSystemCallStart(tracer *tracing.Hooks, ctx *tracing.VMContext) {
	if tracer.OnSystemCallStartV2 != nil {
		tracer.OnSystemCallStartV2(ctx)
	} else if tracer.OnSystemCallStart != nil {
		tracer.OnSystemCallStart()
	}
}

// AssembleBlock finalizes the state and assembles the block with provided
// body and receipts.
func AssembleBlock(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB, body *types.Body, receipts []*types.Receipt, blockAccessList *bal.ConstructionBlockAccessList) *types.Block {
	// Assign the post-transition state root
	header.Root = state.IntermediateRoot(chain.Config().IsEIP158(header.Number))

	if !chain.Config().IsAmsterdam(header.Number, header.Time) {
		return types.NewBlock(header, body, receipts, trie.NewStackTrie(nil))
	}
	// Assign the BlockAccessListHash if Amsterdam has been enabled
	bal := blockAccessList.ToEncodingObj()
	balHash := bal.Hash()
	header.BlockAccessListHash = &balHash
	return types.NewBlock(header, body, receipts, trie.NewStackTrie(nil)).WithAccessListUnsafe(bal)
}

// ApplySigningTransaction handles XDC signing transactions at the tipSigning
// fork. Signing transactions to BlockSignersBinary (0x89) are processed without
// consuming gas — matches XDPoSChain behavior at block >= tipSigning
// (3,000,000 on mainnet). The EVM is bypassed entirely; only the sender's nonce
// is bumped and a minimal log is emitted.
//
// The optional cumulativeGasUsed parameter (XDC) is the receipt's cumulative
// gas counter at this index; passed by Process() from gp.CumulativeUsed().
// usedGas is NOT modified (signing txs consume zero gas). Refs #740/#742.
func ApplySigningTransaction(config *params.ChainConfig, statedb *state.StateDB, blockNumber *big.Int, blockHash common.Hash, tx *types.Transaction, cumulativeGasUsed uint64) (*types.Receipt, error) {
	var root []byte
	if config.IsByzantium(blockNumber) {
		statedb.Finalise(true)
	} else {
		root = statedb.IntermediateRoot(config.IsEIP158(blockNumber)).Bytes()
	}
	from, err := types.Sender(types.MakeSigner(config, blockNumber, 0), tx)
	if err != nil {
		return nil, err
	}
	nonce := statedb.GetNonce(from)
	if nonce != tx.Nonce() {
		return nil, fmt.Errorf("signing tx nonce mismatch: state=%d tx=%d", nonce, tx.Nonce())
	}
	statedb.SetNonce(from, nonce+1, tracing.NonceChangeUnspecified)

	// Canonical XDPoSChain emits a minimal log with only Address (=
	// BlockSignersBinary) and BlockNumber set. The signing path short-circuits
	// EVM execution entirely, so the BlockSigner contract's
	// Sign(address,uint256,bytes32) event never actually fires on canonical —
	// only the Address bit contributes to the bloom. PR #654 attempted to mint
	// the contract's event manually, but canonical does not, so the rich form
	// caused bloom/receipt-root divergence past TIPSigning.
	sigLog := &types.Log{
		Address:     common.BlockSignersBinary,
		BlockNumber: blockNumber.Uint64(),
	}
	statedb.AddLog(sigLog)

	// Build receipt — gasUsed=0, cumulativeGasUsed unchanged.
	receipt := &types.Receipt{
		Type:              tx.Type(),
		PostState:         root,
		Status:            types.ReceiptStatusSuccessful,
		CumulativeGasUsed: cumulativeGasUsed,
		TxHash:            tx.Hash(),
		GasUsed:           0,
		BlockHash:         blockHash,
		BlockNumber:       blockNumber,
		TransactionIndex:  uint(statedb.TxIndex()),
	}
	receipt.Logs = statedb.GetLogs(tx.Hash(), blockNumber.Uint64(), blockHash, 0)
	receipt.Bloom = types.CreateBloom(receipt)
	return receipt, nil
}

// ApplyEmptyTransaction handles XDCx "empty" notifier transactions emitted
// between TIPXDCX (Apothem 23,779,191; mainnet 38,383,838) and
// TIPXDCXReceiverDisable (Apothem 66,825,000; mainnet 80,370,900) that target
// the XDCx trading-state (0x92) or lending-engine (0x93) contracts. Canonical
// XDPoSChain records the receipt with zero gas, a minimal single log carrying
// only the To address, and no nonce bump. cumulativeGasUsed is passed through
// unchanged. Without this dispatch the tx is run through the EVM, the receipt
// reports non-zero gas, and the state root + receipts root diverge starting
// at the very first TIPXDCX block.
func ApplyEmptyTransaction(config *params.ChainConfig, statedb *state.StateDB, blockNumber *big.Int, blockHash common.Hash, tx *types.Transaction, cumulativeGasUsed uint64) (*types.Receipt, error) {
	var root []byte
	if config.IsByzantium(blockNumber) {
		statedb.Finalise(true)
	} else {
		root = statedb.IntermediateRoot(config.IsEIP158(blockNumber)).Bytes()
	}

	emptyLog := &types.Log{
		BlockNumber: blockNumber.Uint64(),
	}
	if to := tx.To(); to != nil {
		emptyLog.Address = *to
	}
	statedb.AddLog(emptyLog)

	receipt := &types.Receipt{
		Type:              tx.Type(),
		PostState:         root,
		Status:            types.ReceiptStatusSuccessful,
		CumulativeGasUsed: cumulativeGasUsed,
		TxHash:            tx.Hash(),
		GasUsed:           0,
		BlockHash:         blockHash,
		BlockNumber:       blockNumber,
		TransactionIndex:  uint(statedb.TxIndex()),
	}
	receipt.Logs = statedb.GetLogs(tx.Hash(), blockNumber.Uint64(), blockHash, 0)
	receipt.Bloom = types.CreateBloom(receipt)
	return receipt, nil
}

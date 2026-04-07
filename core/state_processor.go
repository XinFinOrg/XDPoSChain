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
	"encoding/binary"
	"fmt"
	"math/big"
	"runtime"
	"sync"

	"github.com/XinFinOrg/XDPoSChain/XDCx/tradingstate"
	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/consensus/misc"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/tracing"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/log"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// StateProcessor is a basic Processor, which takes care of transitioning
// state from one point to another.
//
// StateProcessor implements Processor.
type StateProcessor struct {
	config *params.ChainConfig // Chain configuration options
	bc     *BlockChain         // Canonical block chain
	engine consensus.Engine    // Consensus engine used for block rewards
}
type CalculatedBlock struct {
	block *types.Block
	stop  bool
}

// NewStateProcessor initialises a new StateProcessor.
func NewStateProcessor(config *params.ChainConfig, bc *BlockChain, engine consensus.Engine) *StateProcessor {
	return &StateProcessor{
		config: config,
		bc:     bc,
		engine: engine,
	}
}

// Process processes the state changes according to the Ethereum rules by running
// the transaction messages using the statedb and applying any rewards to both
// the processor (coinbase) and any included uncles.
//
// Process returns the receipts and logs accumulated during the process and
// returns the amount of gas that was used in the process. If any of the
// transactions failed to execute due to insufficient gas it will return an error.
func (p *StateProcessor) Process(block *types.Block, statedb *state.StateDB, tradingState *tradingstate.TradingStateDB, cfg vm.Config, tokensFee map[common.Address]*big.Int) (types.Receipts, []*types.Log, uint64, error) {
	var (
		receipts    = make([]*types.Receipt, 0, len(block.Transactions()))
		usedGas     = new(uint64)
		header      = block.Header()
		blockHash   = block.Hash()
		blockNumber = block.Number()
		allLogs     []*types.Log
		gp          = new(GasPool).AddGas(block.GasLimit())
	)

	var tracingStateDB = vm.StateDB(statedb)
	if hooks := cfg.Tracer; hooks != nil {
		tracingStateDB = state.NewHookedState(statedb, hooks)
	}

	// Mutate the block and state according to any hard-fork specs
	if p.config.DAOForkSupport && p.config.DAOForkBlock != nil && p.config.DAOForkBlock.Cmp(block.Number()) == 0 {
		misc.ApplyDAOHardFork(tracingStateDB)
	}
	if common.TIPSigning.Cmp(blockNumber) == 0 {
		statedb.DeleteAddress(common.BlockSignersBinary)
	}
	parentState := statedb.Copy()
	InitSignerInTransactions(p.config, header, block.Transactions())
	balanceUpdated := map[common.Address]*big.Int{}
	totalFeeUsed := big.NewInt(0)

	// Apply pre-execution system calls.
	context := NewEVMBlockContext(header, p.bc, nil)
	evm := vm.NewEVM(context, tracingStateDB, tradingState, p.config, cfg)
	signer := types.MakeSigner(p.config, blockNumber)
	coinbaseOwner := getCoinbaseOwner(p.bc, statedb, header, nil)

	if p.config.IsPrague(block.Number()) {
		ProcessParentBlockHash(block.ParentHash(), evm)
	}

	// Iterate over and process the individual transactions
	for i, tx := range block.Transactions() {
		// check denylist txs after hf
		if block.Number().Uint64() >= common.DenylistHFNumber {
			// check if sender is in denylist
			if common.IsInDenylist(tx.From()) {
				return nil, nil, 0, fmt.Errorf("block contains transaction with sender in denylist: %v", tx.From().Hex())
			}
			// check if receiver is in denylist
			if common.IsInDenylist(tx.To()) {
				return nil, nil, 0, fmt.Errorf("block contains transaction with receiver in denylist: %v", tx.To().Hex())
			}
		}
		// validate minFee slot for XDCZ
		if tx.IsXDCZApplyTransaction() {
			copyState := statedb.Copy()
			if err := ValidateXDCZApplyTransaction(p.bc, block.Number(), copyState, common.BytesToAddress(tx.Data()[4:])); err != nil {
				return nil, nil, 0, err
			}
		}
		// validate balance slot, token decimal for XDCX
		if tx.IsXDCXApplyTransaction() {
			copyState := statedb.Copy()
			if err := ValidateXDCXApplyTransaction(p.bc, block.Number(), copyState, common.BytesToAddress(tx.Data()[4:])); err != nil {
				return nil, nil, 0, err
			}
		}

		var balanceFee *big.Int
		if tx.To() != nil {
			if value, ok := tokensFee[*tx.To()]; ok {
				balanceFee = value
			}
		}
		msg, err := TransactionToMessage(tx, signer, balanceFee, blockNumber, header.BaseFee)
		if err != nil {
			return nil, nil, 0, err
		}
		statedb.SetTxContext(tx.Hash(), i)

		receipt, gas, tokenFeeUsed, err := ApplyTransactionWithEVM(msg, gp, statedb, blockNumber, blockHash, tx, usedGas, evm, balanceFee, coinbaseOwner)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("could not apply tx %d [%v]: %w", i, tx.Hash().Hex(), err)
		}
		receipts = append(receipts, receipt)
		allLogs = append(allLogs, receipt.Logs...)
		if tokenFeeUsed {
			fee := common.GetGasFee(block.Header().Number.Uint64(), gas)
			tokensFee[*tx.To()] = new(big.Int).Sub(tokensFee[*tx.To()], fee)
			balanceUpdated[*tx.To()] = tokensFee[*tx.To()]
			totalFeeUsed = totalFeeUsed.Add(totalFeeUsed, fee)
		}
	}
	tracingStateDB.UpdateTRC21Fee(balanceUpdated, totalFeeUsed)

	// Finalize the block, applying any consensus engine specific extras (e.g. block rewards)
	p.engine.Finalize(p.bc, header, tracingStateDB, parentState, block.Transactions(), block.Uncles(), receipts)

	return receipts, allLogs, *usedGas, nil
}

func (p *StateProcessor) ProcessBlockNoValidator(cBlock *CalculatedBlock, statedb *state.StateDB, tradingState *tradingstate.TradingStateDB, cfg vm.Config, tokensFee map[common.Address]*big.Int) (types.Receipts, []*types.Log, uint64, error) {
	block := cBlock.block
	var (
		receipts    types.Receipts
		usedGas     = new(uint64)
		header      = block.Header()
		blockHash   = block.Hash()
		blockNumber = block.Number()
		allLogs     []*types.Log
		gp          = new(GasPool).AddGas(block.GasLimit())
	)

	var tracingStateDB = vm.StateDB(statedb)
	if hooks := cfg.Tracer; hooks != nil {
		tracingStateDB = state.NewHookedState(statedb, hooks)
	}

	// Mutate the block and state according to any hard-fork specs
	if p.config.DAOForkSupport && p.config.DAOForkBlock != nil && p.config.DAOForkBlock.Cmp(block.Number()) == 0 {
		misc.ApplyDAOHardFork(tracingStateDB)
	}
	if common.TIPSigning.Cmp(blockNumber) == 0 {
		statedb.DeleteAddress(common.BlockSignersBinary)
	}
	if cBlock.stop {
		return nil, nil, 0, ErrStopPreparingBlock
	}
	parentState := statedb.Copy()
	InitSignerInTransactions(p.config, header, block.Transactions())
	balanceUpdated := map[common.Address]*big.Int{}
	totalFeeUsed := big.NewInt(0)

	if cBlock.stop {
		return nil, nil, 0, ErrStopPreparingBlock
	}

	// Apply pre-execution system calls.
	context := NewEVMBlockContext(header, p.bc, nil)
	evm := vm.NewEVM(context, tracingStateDB, tradingState, p.config, cfg)
	signer := types.MakeSigner(p.config, blockNumber)
	coinbaseOwner := getCoinbaseOwner(p.bc, statedb, header, nil)

	if p.config.IsPrague(block.Number()) {
		ProcessParentBlockHash(block.ParentHash(), evm)
	}

	// Iterate over and process the individual transactions
	receipts = make([]*types.Receipt, block.Transactions().Len())
	for i, tx := range block.Transactions() {
		// check denylist txs after hf
		if block.Number().Uint64() >= common.DenylistHFNumber {
			// check if sender is in denylist
			if common.IsInDenylist(tx.From()) {
				return nil, nil, 0, fmt.Errorf("block contains transaction with sender in denylist: %v", tx.From().Hex())
			}
			// check if receiver is in denylist
			if common.IsInDenylist(tx.To()) {
				return nil, nil, 0, fmt.Errorf("block contains transaction with receiver in denylist: %v", tx.To().Hex())
			}
		}
		// validate minFee slot for XDCZ
		if tx.IsXDCZApplyTransaction() {
			copyState := statedb.Copy()
			if err := ValidateXDCZApplyTransaction(p.bc, block.Number(), copyState, common.BytesToAddress(tx.Data()[4:])); err != nil {
				return nil, nil, 0, err
			}
		}
		// validate balance slot, token decimal for XDCX
		if tx.IsXDCXApplyTransaction() {
			copyState := statedb.Copy()
			if err := ValidateXDCXApplyTransaction(p.bc, block.Number(), copyState, common.BytesToAddress(tx.Data()[4:])); err != nil {
				return nil, nil, 0, err
			}
		}
		var balanceFee *big.Int
		if tx.To() != nil {
			if value, ok := tokensFee[*tx.To()]; ok {
				balanceFee = value
			}
		}
		msg, err := TransactionToMessage(tx, signer, balanceFee, blockNumber, header.BaseFee)
		if err != nil {
			return nil, nil, 0, err
		}
		statedb.SetTxContext(tx.Hash(), i)

		receipt, gas, tokenFeeUsed, err := ApplyTransactionWithEVM(msg, gp, statedb, blockNumber, blockHash, tx, usedGas, evm, balanceFee, coinbaseOwner)
		if err != nil {
			return nil, nil, 0, err
		}
		if cBlock.stop {
			return nil, nil, 0, ErrStopPreparingBlock
		}
		receipts[i] = receipt
		allLogs = append(allLogs, receipt.Logs...)
		if tokenFeeUsed {
			fee := common.GetGasFee(block.Header().Number.Uint64(), gas)
			tokensFee[*tx.To()] = new(big.Int).Sub(tokensFee[*tx.To()], fee)
			balanceUpdated[*tx.To()] = tokensFee[*tx.To()]
			totalFeeUsed = totalFeeUsed.Add(totalFeeUsed, fee)
		}
	}
	tracingStateDB.UpdateTRC21Fee(balanceUpdated, totalFeeUsed)

	// Finalize the block, applying any consensus engine specific extras (e.g. block rewards)
	p.engine.Finalize(p.bc, header, tracingStateDB, parentState, block.Transactions(), block.Uncles(), receipts)
	return receipts, allLogs, *usedGas, nil
}

// ApplyTransactionWithEVM attempts to apply a transaction to the given state database
// and uses the input parameters for its environment similar to ApplyTransaction. However,
// this method takes an already created EVM instance as input.
func ApplyTransactionWithEVM(msg *Message, gp *GasPool, statedb *state.StateDB, blockNumber *big.Int, blockHash common.Hash, tx *types.Transaction, usedGas *uint64, evm *vm.EVM, balanceFee *big.Int, coinbaseOwner common.Address) (receipt *types.Receipt, gasUsed uint64, tokenFeeUsed bool, err error) {
	if hooks := evm.Config.Tracer; hooks != nil {
		if hooks.OnTxStart != nil {
			// OnTxStart runs before ApplyMessage, so the execution tx context must be visible
			// here too. This is XDPoS-specific because msg.GasPrice can differ from the raw tx.
			evm.SetTxContext(NewEVMTxContext(msg))
			hooks.OnTxStart(evm.GetVMContext(), tx, msg.From)
		}
		if hooks.OnTxEnd != nil {
			defer func() { hooks.OnTxEnd(receipt, err) }()
		}
	}

	to := tx.To()
	config := evm.ChainConfig()
	if to != nil {
		if *to == common.BlockSignersBinary && config.IsTIPSigning(blockNumber) {
			return ApplySignTransaction(msg, config, statedb, blockNumber, blockHash, tx, usedGas, evm)
		}
		if *to == common.TradingStateAddrBinary && config.IsTIPXDCXReceiver(blockNumber) {
			return ApplyEmptyTransaction(msg, config, statedb, blockNumber, blockHash, tx, usedGas, evm)
		}
		if *to == common.XDCXLendingAddressBinary && config.IsTIPXDCXReceiver(blockNumber) {
			return ApplyEmptyTransaction(msg, config, statedb, blockNumber, blockHash, tx, usedGas, evm)
		}
	}
	if tx.IsTradingTransaction() && config.IsTIPXDCXReceiver(blockNumber) {
		return ApplyEmptyTransaction(msg, config, statedb, blockNumber, blockHash, tx, usedGas, evm)
	}
	if tx.IsLendingFinalizedTradeTransaction() && config.IsTIPXDCXReceiver(blockNumber) {
		return ApplyEmptyTransaction(msg, config, statedb, blockNumber, blockHash, tx, usedGas, evm)
	}

	applyHistoricalBalanceBypass(statedb, blockNumber, msg.From)

	// Apply the transaction to the current state (included in the env)
	result, err := ApplyMessage(evm, msg, gp, coinbaseOwner)
	if err != nil {
		return nil, 0, false, err
	}

	// Update the state with pending changes.
	var root []byte
	if config.IsByzantium(blockNumber) {
		evm.StateDB.Finalise(true)
	} else {
		root = statedb.IntermediateRoot(config.IsEIP158(blockNumber)).Bytes()
	}
	*usedGas += result.UsedGas

	if balanceFee != nil && result.Failed() {
		statedb.PayFeeWithTRC21TxFail(msg.From, *to)
	}

	return MakeReceipt(evm, result, statedb, blockNumber, blockHash, tx, *usedGas, root), result.UsedGas, balanceFee != nil, nil
}

// MakeReceipt generates the receipt object for a transaction given its execution result.
func MakeReceipt(evm *vm.EVM, result *ExecutionResult, statedb *state.StateDB, blockNumber *big.Int, blockHash common.Hash, tx *types.Transaction, usedGas uint64, root []byte) *types.Receipt {
	// Create a new receipt for the transaction, storing the intermediate root and gas used
	// by the tx.
	receipt := &types.Receipt{Type: tx.Type(), PostState: root, CumulativeGasUsed: usedGas}
	if result.Failed() {
		receipt.Status = types.ReceiptStatusFailed
	} else {
		receipt.Status = types.ReceiptStatusSuccessful
	}
	receipt.TxHash = tx.Hash()
	receipt.GasUsed = result.UsedGas

	// If the transaction created a contract, store the creation address in the receipt.
	if tx.To() == nil {
		receipt.ContractAddress = crypto.CreateAddress(evm.TxContext.Origin, tx.Nonce())
	}

	// Set the receipt logs and create the bloom filter.
	receipt.Logs = statedb.GetLogs(tx.Hash(), blockNumber.Uint64(), blockHash)
	receipt.Bloom = types.CreateBloom(types.Receipts{receipt})
	receipt.BlockHash = blockHash
	receipt.BlockNumber = blockNumber
	receipt.TransactionIndex = uint(statedb.TxIndex())
	return receipt
}

func getCoinbaseOwner(bc *BlockChain, statedb *state.StateDB, header *types.Header, author *common.Address) common.Address {
	// If we don't have an explicit author (i.e. not mining), extract from the header
	var beneficiary common.Address
	if author == nil {
		beneficiary, _ = bc.Engine().Author(header) // Ignore error, we're past header validation
	} else {
		beneficiary = *author
	}
	return statedb.GetOwner(beneficiary)
}

// ApplyTransaction attempts to apply a transaction to the given state database
// and uses the input parameters for its environment. It returns the receipt
// for the transaction, gas used and an error if the transaction failed,
// indicating the block was invalid.
func ApplyTransaction(tokensFee map[common.Address]*big.Int, evm *vm.EVM, gp *GasPool, statedb *state.StateDB, header *types.Header, tx *types.Transaction, usedGas *uint64) (*types.Receipt, uint64, bool, error) {
	var balanceFee *big.Int
	if tx.To() != nil {
		if value, ok := tokensFee[*tx.To()]; ok {
			balanceFee = value
		}
	}

	signer := types.MakeSigner(evm.ChainConfig(), header.Number)
	msg, err := TransactionToMessage(tx, signer, balanceFee, header.Number, header.BaseFee)
	if err != nil {
		return nil, 0, false, err
	}
	coinbaseOwner := statedb.GetOwner(evm.Context.Coinbase)
	return ApplyTransactionWithEVM(msg, gp, statedb, header.Number, header.Hash(), tx, usedGas, evm, balanceFee, coinbaseOwner)
}

func ApplySignTransaction(msg *Message, config *params.ChainConfig, statedb *state.StateDB, blockNumber *big.Int, blockHash common.Hash, tx *types.Transaction, usedGas *uint64, evm *vm.EVM) (receipt *types.Receipt, gasUsed uint64, tokenFeeUsed bool, err error) {
	// Update the state with pending changes
	var root []byte
	if config.IsByzantium(blockNumber) {
		statedb.Finalise(true)
	} else {
		root = statedb.IntermediateRoot(config.IsEIP158(blockNumber)).Bytes()
	}
	// Defensive fallback: msg.From should already be populated by the caller through one of these paths:
	// 1. Normal block processing: TransactionToMessage recovers from via signature (types.Sender)
	// 2. TraceCall/debug_traceCall: args.ToMessage directly uses the provided args.From parameter
	// This zero-check should rarely execute. If it does, signature recovery is attempted as a last resort,
	// which will fail if the transaction lacks a valid signature (e.g., unsigned simulation transactions).
	from := msg.From
	if from.IsZero() {
		var err error
		from, err = types.Sender(types.MakeSigner(config, blockNumber), tx)
		if err != nil {
			return nil, 0, false, err
		}
	}
	nonce := statedb.GetNonce(from)
	// For tracing/simulation calls (e.g., debug_traceCall), SkipNonceChecks is true,
	// so nonce checks and incrementing are skipped, allowing the transaction to be processed
	// regardless of the current account nonce. For regular transactions, nonce checks are enforced.
	if !msg.SkipNonceChecks {
		if nonce < tx.Nonce() {
			return nil, 0, false, ErrNonceTooHigh
		} else if nonce > tx.Nonce() {
			return nil, 0, false, ErrNonceTooLow
		}
		// Only increment the nonce for real transactions.
		statedb.SetNonce(from, nonce+1, tracing.NonceChangeEoACall)
	}
	// Create a new receipt for the transaction, storing the intermediate root and gas used by the tx
	// based on the eip phase, we're passing whether the root touch-delete accounts.
	receipt = types.NewReceipt(root, false, *usedGas)
	receipt.TxHash = tx.Hash()
	receipt.GasUsed = 0
	// if the transaction created a contract, store the creation address in the receipt.
	// Set the receipt logs and create a bloom for filtering
	log := &types.Log{}
	log.Address = common.BlockSignersBinary
	log.BlockNumber = blockNumber.Uint64()
	statedb.AddLog(log)
	receipt.Logs = statedb.GetLogs(tx.Hash(), blockNumber.Uint64(), blockHash)
	receipt.Bloom = types.CreateBloom(types.Receipts{receipt})
	receipt.BlockHash = blockHash
	receipt.BlockNumber = blockNumber
	receipt.TransactionIndex = uint(statedb.TxIndex())
	return receipt, 0, false, nil
}

func ApplyEmptyTransaction(msg *Message, config *params.ChainConfig, statedb *state.StateDB, blockNumber *big.Int, blockHash common.Hash, tx *types.Transaction, usedGas *uint64, evm *vm.EVM) (receipt *types.Receipt, gasUsed uint64, tokenFeeUsed bool, err error) {
	// Update the state with pending changes
	var root []byte
	if config.IsByzantium(blockNumber) {
		statedb.Finalise(true)
	} else {
		root = statedb.IntermediateRoot(config.IsEIP158(blockNumber)).Bytes()
	}
	// Create a new receipt for the transaction, storing the intermediate root and gas used by the tx
	// based on the eip phase, we're passing whether the root touch-delete accounts.
	receipt = types.NewReceipt(root, false, *usedGas)
	receipt.TxHash = tx.Hash()
	receipt.GasUsed = 0
	// if the transaction created a contract, store the creation address in the receipt.
	// Set the receipt logs and create a bloom for filtering
	log := &types.Log{}
	log.Address = *tx.To()
	log.BlockNumber = blockNumber.Uint64()
	statedb.AddLog(log)
	receipt.Logs = statedb.GetLogs(tx.Hash(), blockNumber.Uint64(), blockHash)
	receipt.Bloom = types.CreateBloom(types.Receipts{receipt})
	receipt.BlockHash = blockHash
	receipt.BlockNumber = blockNumber
	receipt.TransactionIndex = uint(statedb.TxIndex())
	return receipt, 0, false, nil
}

func InitSignerInTransactions(config *params.ChainConfig, header *types.Header, txs types.Transactions) {
	if txs.Len() == 0 {
		return
	}
	nWorker := min(runtime.NumCPU(), txs.Len())
	signer := types.MakeSigner(config, header.Number)
	chunkSize := txs.Len() / nWorker
	if txs.Len()%nWorker != 0 {
		chunkSize++
	}
	wg := sync.WaitGroup{}
	for i := 0; i < nWorker; i++ {
		from := i * chunkSize
		to := from + chunkSize
		if to > txs.Len() {
			to = txs.Len()
		}
		wg.Go(func() {
			for j := from; j < to; j++ {
				types.CacheSigner(signer, txs[j])
			}
		})
	}
	wg.Wait()
}

// ProcessParentBlockHash writes the parent hash to the EIP-2935 history contract
// and enforces the expected code, with a one-time Prague backfill if missing.
func ProcessParentBlockHash(prevHash common.Hash, evm *vm.EVM) {
	// Verify history contract code matches the expected bytecode
	code := evm.StateDB.GetCode(params.HistoryStorageAddress)
	if len(code) > 0 && !bytes.Equal(code, params.HistoryStorageCode) {
		log.Error("History storage code mismatch",
			"have", crypto.Keccak256Hash(code),
			"want", crypto.Keccak256Hash(params.HistoryStorageCode),
		)
		panic("history storage code mismatch")
	}

	blockNumber := evm.Context.BlockNumber
	if blockNumber == nil || !evm.ChainConfig().IsPrague(blockNumber) {
		return
	}
	forkBlock := evm.ChainConfig().PragueBlock
	if forkBlock == nil {
		forkBlock = common.PragueBlock
	}
	if forkBlock == nil || blockNumber.Cmp(forkBlock) < 0 {
		return
	}

	// Only deploy and backfill if the contract is missing at/after Prague activation.
	if len(code) == 0 {
		if !evm.StateDB.Exist(params.HistoryStorageAddress) {
			evm.StateDB.CreateAccount(params.HistoryStorageAddress)
		}
		if evm.StateDB.GetNonce(params.HistoryStorageAddress) == 0 {
			evm.StateDB.SetNonce(params.HistoryStorageAddress, 1, tracing.NonceChangeUnspecified)
		}
		evm.StateDB.SetCode(params.HistoryStorageAddress, params.HistoryStorageCode)

		if blockNumber.Sign() > 0 {
			end := blockNumber.Uint64() - 1
			start := end
			if end+1 > params.HistoryServeWindow {
				start = end + 1 - params.HistoryServeWindow
			}
			if forkBlock.Sign() > 0 {
				forkStart := forkBlock.Uint64() - 1
				if forkStart > start {
					start = forkStart
				}
			}
			for n := start; n <= end; n++ {
				hash := evm.Context.GetHash(n)
				if hash == (common.Hash{}) {
					log.Debug("History backfill missing hash", "number", n)
					continue
				}
				evm.StateDB.SetState(params.HistoryStorageAddress, historyStorageKey(n), hash)
			}
		}
	}

	if tracer := evm.Config.Tracer; tracer != nil {
		onSystemCallStart(tracer, evm.GetVMContext())
		if tracer.OnSystemCallEnd != nil {
			defer tracer.OnSystemCallEnd()
		}
	}

	msg := &Message{
		From:      params.SystemAddress,
		GasLimit:  30_000_000,
		GasPrice:  common.Big0,
		GasFeeCap: common.Big0,
		GasTipCap: common.Big0,
		To:        &params.HistoryStorageAddress,
		Data:      prevHash.Bytes(),
	}
	evm.SetTxContext(NewEVMTxContext(msg))
	evm.StateDB.AddAddressToAccessList(params.HistoryStorageAddress)
	_, _, err := evm.Call(msg.From, *msg.To, msg.Data, 30_000_000, common.U2560)
	if err != nil {
		panic(err)
	}
	evm.StateDB.Finalise(true)
}

func historyStorageKey(number uint64) common.Hash {
	ringIndex := number % params.HistoryServeWindow
	var key common.Hash
	binary.BigEndian.PutUint64(key[24:], ringIndex)
	return key
}

func onSystemCallStart(tracer *tracing.Hooks, ctx *tracing.VMContext) {
	if tracer.OnSystemCallStartV2 != nil {
		tracer.OnSystemCallStartV2(ctx)
	} else if tracer.OnSystemCallStart != nil {
		tracer.OnSystemCallStart()
	}
}

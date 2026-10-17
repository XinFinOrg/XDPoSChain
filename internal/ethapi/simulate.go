// Copyright 2023 The go-ethereum Authors
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

package ethapi

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math/big"
	"time"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/common/hexutil"
	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/consensus/misc/eip1559"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/internal/ethapi/override"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/XinFinOrg/XDPoSChain/rpc"
	"github.com/XinFinOrg/XDPoSChain/trie"
)

const (
	// maxSimulateBlocks is the maximum number of blocks that can be simulated
	// in a single request.
	maxSimulateBlocks = 256

	// maxSimulateCallsPerBlock is the maximum number of calls allowed in a
	// single simulated block.
	maxSimulateCallsPerBlock = 5000

	// maxSimulateTotalCalls is the maximum total number of calls allowed
	// across all simulated blocks in a single request.
	maxSimulateTotalCalls = 10000

	// timestampIncrement is the default increment between block timestamps.
	timestampIncrement = 1
)

// simBlock is a batch of calls to be simulated sequentially.
type simBlock struct {
	BlockOverrides *override.BlockOverrides
	StateOverrides *override.StateOverride
	Calls          []TransactionArgs
}

// simCallResult is the result of a simulated call.
type simCallResult struct {
	ReturnValue hexutil.Bytes  `json:"returnData"`
	Logs        []*types.Log   `json:"logs"`
	GasUsed     hexutil.Uint64 `json:"gasUsed"`
	MaxUsedGas  hexutil.Uint64 `json:"maxUsedGas"`
	Status      hexutil.Uint64 `json:"status"`
	Error       *callError     `json:"error,omitempty"`
}

func (r *simCallResult) MarshalJSON() ([]byte, error) {
	type callResultAlias simCallResult
	// Marshal logs to be an empty array instead of nil when empty
	if r.Logs == nil {
		r.Logs = []*types.Log{}
	}
	return json.Marshal((*callResultAlias)(r))
}

// simOpts are the inputs to eth_simulateV1.
type simOpts struct {
	BlockStateCalls        []simBlock
	TraceTransfers         bool
	Validation             bool
	ReturnFullTransactions bool
}

// simulator is a stateful object that simulates a series of blocks.
// it is not safe for concurrent use.
type simulator struct {
	b              Backend
	state          *state.StateDB
	base           *types.Header
	chainConfig    *params.ChainConfig
	gp             *core.GasPool
	traceTransfers bool
	validate       bool
	fullTx         bool
}

// execute runs the simulation of a series of blocks.
func (sim *simulator) execute(ctx context.Context, blocks []simBlock) ([]map[string]interface{}, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var (
		cancel  context.CancelFunc
		timeout = sim.b.RPCEVMTimeout()
	)
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, timeout)
	} else {
		ctx, cancel = context.WithCancel(ctx)
	}
	// Make sure the context is cancelled when the call has completed
	// this makes sure resources are cleaned up.
	defer cancel()

	var err error
	blocks, err = sim.sanitizeChain(blocks)
	if err != nil {
		return nil, err
	}
	// Prepare block headers with preliminary fields for the response.
	headers, err := sim.makeHeaders(blocks)
	if err != nil {
		return nil, err
	}
	var (
		results = make([]map[string]interface{}, len(blocks))
		parent  = sim.base
		// Assume same total difficulty for all simulated blocks.
		td = sim.b.GetTd(ctx, sim.base.Hash())
	)
	for bi, block := range blocks {
		result, callResults, err := sim.processBlock(ctx, &block, headers[bi], parent, headers[:bi], timeout)
		if err != nil {
			return nil, err
		}
		enc := RPCMarshalBlock(result, true, sim.fullTx, sim.chainConfig)
		enc["totalDifficulty"] = (*hexutil.Big)(td)
		enc["calls"] = callResults
		results[bi] = enc

		parent = headers[bi]
	}
	return results, nil
}

func (sim *simulator) processBlock(ctx context.Context, block *simBlock, header, parent *types.Header, headers []*types.Header, timeout time.Duration) (*types.Block, []simCallResult, error) {
	// Set header fields that depend only on parent block.
	// Parent hash is needed for evm.GetHashFn to work.
	header.ParentHash = parent.Hash()
	if sim.chainConfig.IsEIP1559(header.Number) {
		// In non-validation mode base fee is set to 0 if it is not overridden.
		// This is because it creates an edge case in EVM where gasPrice < baseFee.
		// Base fee could have been overridden.
		if header.BaseFee == nil {
			if sim.validate {
				header.BaseFee = eip1559.CalcBaseFee(sim.chainConfig, header)
			} else {
				header.BaseFee = big.NewInt(0)
			}
		}
	}
	blockContext := core.NewEVMBlockContext(header, sim.newSimulatedChainContext(ctx, headers), nil)
	precompiles := sim.activePrecompiles(header)
	// The block level state changes below own the Multicall3 account, the EIP-2935 history
	// contract and the legacy block signers account, so an override of one of them would be
	// undone by the block or trip the panic that guards a diverging install. Refuse it here,
	// where the caller can be told, instead of running the block from a pre-state the caller
	// did not choose.
	if err := rejectOwnedAccountOverrides(sim.chainConfig, sim.state, header, block.StateOverrides); err != nil {
		return nil, nil, err
	}
	// State overrides are applied prior to execution of a block
	if err := block.StateOverrides.Apply(sim.state, precompiles); err != nil {
		return nil, nil, err
	}
	var (
		gasUsed     uint64
		txes        = make([]*types.Transaction, len(block.Calls))
		callResults = make([]simCallResult, len(block.Calls))
		receipts    = make([]*types.Receipt, len(block.Calls))
		// Block hash will be repaired after execution.
		tracer   = newTracer(sim.traceTransfers, blockContext.BlockNumber.Uint64(), common.Hash{}, common.Hash{}, 0)
		vmConfig = &vm.Config{
			NoBaseFee: !sim.validate,
			Tracer:    tracer.Hooks(),
		}
	)
	var tracingStateDB = vm.StateDB(sim.state)
	if hooks := tracer.Hooks(); hooks != nil {
		tracingStateDB = state.NewHookedState(sim.state, hooks)
	}
	evm := vm.NewEVM(blockContext, tracingStateDB, nil, sim.chainConfig, *vmConfig)
	// It is possible to override precompiles with EVM bytecode, or
	// move them to another address.
	if precompiles != nil {
		evm.SetPrecompiles(precompiles)
	}
	// Block level state changes block processing applies before the first transaction of a
	// block: TIPSigning removes the legacy block signers account at its activation block,
	// Multicall3 is installed at the one that activates Prague. A simulated block starts from
	// the base state, so selecting the activation block's parent reproduces either change.
	core.ApplyTIPSigningHardFork(sim.chainConfig, sim.state, header.Number)
	core.ApplyMulticall3HardFork(sim.chainConfig, sim.state, header.Number)
	// EIP-2935 parent hash history, written after those changes the way block processing does.
	if sim.chainConfig.IsPrague(header.Number) {
		core.ProcessParentBlockHash(header.ParentHash, evm)
	}
	for i, call := range block.Calls {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		if err := sim.sanitizeCall(&call, sim.state, header, blockContext, &gasUsed); err != nil {
			return nil, nil, err
		}
		tx := call.ToTransaction(types.DynamicFeeTxType)
		txes[i] = tx
		tracer.reset(tx.Hash(), uint(i))
		// EoA check is always skipped, even in validation mode.
		msg := call.ToMessage(sim.b, header.BaseFee, !sim.validate)
		result, err := applyMessageWithEVM(ctx, evm, msg, timeout, sim.gp)
		if err != nil {
			txErr := txValidationError(err)
			return nil, nil, txErr
		}
		// Update the state with pending changes.
		var root []byte
		if sim.chainConfig.IsByzantium(blockContext.BlockNumber) {
			tracingStateDB.Finalise(true)
		} else {
			root = sim.state.IntermediateRoot(sim.chainConfig.IsEIP158(blockContext.BlockNumber)).Bytes()
		}
		gasUsed += result.UsedGas
		receipts[i] = core.MakeReceipt(evm, result, sim.state, blockContext.BlockNumber, common.Hash{}, tx, gasUsed, root)
		logs := tracer.Logs()
		callRes := simCallResult{ReturnValue: result.Return(), Logs: logs, GasUsed: hexutil.Uint64(result.UsedGas), MaxUsedGas: hexutil.Uint64(result.MaxUsedGas)}
		if result.Failed() {
			callRes.Status = hexutil.Uint64(types.ReceiptStatusFailed)
			if errors.Is(result.Err, vm.ErrExecutionReverted) {
				// If the result contains a revert reason, try to unpack it.
				revertErr := newRevertError(result.Revert())
				callRes.Error = &callError{Message: revertErr.Error(), Code: revertErr.ErrorCode(), Data: revertErr.ErrorData().(string)}
			} else {
				callRes.Error = &callError{Message: result.Err.Error(), Code: errCodeVMError}
			}
		} else {
			callRes.Status = hexutil.Uint64(types.ReceiptStatusSuccessful)
		}
		callResults[i] = callRes
	}
	header.Root = sim.state.IntermediateRoot(true)
	header.GasUsed = gasUsed
	b := types.NewBlock(header, &types.Body{Transactions: txes}, receipts, trie.NewStackTrie(nil))
	repairLogs(callResults, b.Hash())
	return b, callResults, nil
}

// ownedOverrideError builds the error a refused state override gets. The clause names the
// block level change that owns the field, so the caller can tell which account to drop
// from the request.
func ownedOverrideError(address common.Address, field, clause string) error {
	return &invalidParamsError{message: fmt.Sprintf("state override of %v sets %s, %s", address, field, clause)}
}

// rejectOwnedAccountOverrides refuses a state override of an account a block level state
// change writes at the block being simulated. Those changes run after the caller's
// overrides, so an override of an account they own either trips the panic that guards a
// diverging install — eth_simulateV1 answers "method handler crashed" and the server logs
// a stack trace per call — or is silently undone by it, which nothing in the response can
// show. Refusing it here names the account and the change instead.
//
// The accounts a block level change owns at a block, and what it writes there:
//
//   - Multicall3: a Prague block installs the canonical code, and raises the nonce of an
//     account that has none.
//   - the EIP-2935 history contract: a Prague block writes the parent hash of the block
//     into its ring buffer, and deploys and backfills the contract when the state holds no
//     code for it.
//   - the legacy block signers account: the block that activates TIPSigning removes it.
//
// A field no change writes stays overridable, the way it is for every other account: the
// balance of an installed contract, the nonce of one that already carries the code, the
// storage of one that exists outside the slots the block writes, and an override entry
// that sets no field at all. The rules mirror core.ApplyTIPSigningHardFork,
// core.ApplyMulticall3HardFork and core.ProcessParentBlockHash, which the tests in
// simulate_owned_overrides_test.go pin against them.
func rejectOwnedAccountOverrides(config *params.ChainConfig, statedb *state.StateDB, header *types.Header, overrides *override.StateOverride) error {
	if overrides == nil {
		return nil
	}
	number := header.Number

	// A Prague block installs the system contracts the fork introduces, whatever the
	// caller asked them to be.
	if config.IsPrague(number) {
		// The install only raises the nonce while the account has no code, so the nonce
		// stays overridable once the account carries the canonical one.
		if account, ok := (*overrides)[params.Multicall3Address]; ok {
			if account.Code != nil {
				return ownedOverrideError(params.Multicall3Address, "code", "which the Prague Multicall3 install owns")
			}
			if account.Nonce != nil && len(statedb.GetCode(params.Multicall3Address)) == 0 {
				return ownedOverrideError(params.Multicall3Address, "the nonce", "which the Prague Multicall3 install owns")
			}
		}
		if account, ok := (*overrides)[params.HistoryStorageAddress]; ok {
			if account.Code != nil {
				return ownedOverrideError(params.HistoryStorageAddress, "code", "which the Prague EIP-2935 history install owns")
			}
			if account.Nonce != nil && len(statedb.GetCode(params.HistoryStorageAddress)) == 0 {
				return ownedOverrideError(params.HistoryStorageAddress, "the nonce", "which the Prague EIP-2935 history install owns")
			}
			for _, storage := range []map[common.Hash]common.Hash{account.State, account.StateDiff} {
				for slot := range storage {
					if historyStorageSlotIsWritten(config, statedb, number, slot) {
						return ownedOverrideError(params.HistoryStorageAddress, fmt.Sprintf("storage slot %v", slot), "which the Prague EIP-2935 history write owns")
					}
				}
			}
		}
	}

	// The block that activates TIPSigning removes the legacy block signers account the way
	// misc.ApplyDAOHardFork mutates the state at the DAO fork block, so every field of an
	// override of it is undone at that block. The removal happens at the activation block
	// alone: the account is overridable again from the block after it.
	if number.Sign() > 0 && config.TIPSigningBlock != nil && config.TIPSigningBlock.Cmp(number) == 0 {
		if account, ok := (*overrides)[common.BlockSignersBinary]; ok {
			for _, field := range []struct {
				name string
				set  bool
			}{
				{"the nonce", account.Nonce != nil},
				{"code", account.Code != nil},
				{"the balance", account.Balance != nil},
				{"storage", account.State != nil},
				{"a storage diff", account.StateDiff != nil},
				{"a precompile move", account.MovePrecompileTo != nil},
			} {
				if field.set {
					return ownedOverrideError(common.BlockSignersBinary, field.name, "which the block that activates TIPSigning removes with the account")
				}
			}
		}
	}
	return nil
}

// historyStorageSlotIsWritten reports whether slot is one ProcessParentBlockHash writes
// into the EIP-2935 history contract at blockNumber. The block always writes the slot of
// its own parent hash, and when the state holds no code for the contract it also deploys
// it and backfills every slot the serve window reaches, which are the ring positions of
// the block numbers from start to blockNumber-1. core computes the same arithmetic in
// ProcessParentBlockHash; TestHistoryStorageWrittenSlots pins the boundary between a slot
// the block writes and one it leaves alone. A slot the backfill would skip, because the
// hash of its block is unavailable, counts as written here, so the caller is refused
// rather than left holding a slot a later block may fill. A simulated block is never
// block zero, which sanitizeChain numbers from the base block up, so the write of block
// zero is out of reach here.
func historyStorageSlotIsWritten(config *params.ChainConfig, statedb *state.StateDB, blockNumber *big.Int, slot common.Hash) bool {
	if blockNumber.Sign() == 0 || !config.IsPrague(blockNumber) {
		return false
	}
	// The ring position a slot the contract reads carries sits in the low bytes of the
	// key, the way core.historyStorageKey builds it. A key with anything above that is a
	// slot the block never writes.
	for i := 0; i < common.HashLength-8; i++ {
		if slot[i] != 0 {
			return false
		}
	}
	ring := binary.BigEndian.Uint64(slot[common.HashLength-8:])

	// The parent hash of the block itself lands in the ring position of the block below it.
	number := blockNumber.Uint64()
	end := number - 1
	if ring == end%params.HistoryServeWindow {
		return true
	}
	// The deploy and the backfill run only while the state holds no code for the
	// contract, the same condition ProcessParentBlockHash checks.
	if len(statedb.GetCode(params.HistoryStorageAddress)) > 0 {
		return false
	}
	start := end
	if end+1 > params.HistoryServeWindow {
		start = end + 1 - params.HistoryServeWindow
	}
	// Prague can activate at block zero, where forkBlock-1 would underflow.
	if forkBlock := config.PragueBlock; forkBlock.Sign() > 0 {
		if forkStart := forkBlock.Uint64() - 1; forkStart > start {
			start = forkStart
		}
	}
	// The window covers at most HistoryServeWindow block numbers, so their ring positions
	// wrap around the ring at most once.
	if end-start+1 >= params.HistoryServeWindow {
		return true
	}
	startRing, endRing := start%params.HistoryServeWindow, end%params.HistoryServeWindow
	if startRing <= endRing {
		return ring >= startRing && ring <= endRing
	}
	return ring >= startRing || ring <= endRing
}

// repairLogs updates the block hash in the logs present in the result of
// a simulated block. This is needed as during execution when logs are collected
// the block hash is not known.
func repairLogs(calls []simCallResult, hash common.Hash) {
	for i := range calls {
		for j := range calls[i].Logs {
			calls[i].Logs[j].BlockHash = hash
		}
	}
}

func (sim *simulator) sanitizeCall(call *TransactionArgs, state vm.StateDB, header *types.Header, blockContext vm.BlockContext, gasUsed *uint64) error {
	if call.Nonce == nil {
		nonce := state.GetNonce(call.from())
		call.Nonce = (*hexutil.Uint64)(&nonce)
	}
	// Let the call run wild unless explicitly specified.
	if call.Gas == nil {
		remaining := blockContext.GasLimit - *gasUsed
		call.Gas = (*hexutil.Uint64)(&remaining)
	}
	if *gasUsed+uint64(*call.Gas) > blockContext.GasLimit {
		return &blockGasLimitReachedError{fmt.Sprintf("block gas limit reached: %d >= %d", *gasUsed, blockContext.GasLimit)}
	}
	// A set-code transaction needs the EIP-1559 fee fields, so gasPrice cannot be
	// combined with an authorization list. sanitizeCall runs CallDefaults rather
	// than setFeeDefaults, so without this the pair is downgraded to a legacy
	// transaction in the block handed back to the caller, while the call itself
	// applies the authorization list.
	if call.GasPrice != nil && call.AuthorizationList != nil {
		return errors.New("both gasPrice and authorizationList specified")
	}
	// The same downgrade happens when the request omits gasPrice and the
	// simulated header has no base fee: CallDefaults then fills a zero gasPrice,
	// which ToTransaction reads as a legacy request. A set-code transaction
	// cannot be built without the EIP-1559 fee fields, so reject the request
	// instead of returning a block whose transactions do not describe the
	// execution.
	if call.AuthorizationList != nil && header.BaseFee == nil {
		return errors.New("authorizationList requires a base fee")
	}
	if err := call.CallDefaults(sim.gp.Gas(), header.BaseFee, sim.chainConfig.ChainID); err != nil {
		return err
	}
	return nil
}

func (sim *simulator) activePrecompiles(base *types.Header) vm.PrecompiledContracts {
	var (
		rules = sim.chainConfig.Rules(base.Number)
	)
	return maps.Clone(vm.ActivePrecompiledContracts(rules))
}

// sanitizeChain checks the chain integrity. Specifically it checks that
// block numbers and timestamp are strictly increasing, setting default values
// when necessary. Gaps in block numbers are filled with empty blocks.
// Note: It modifies the block's override object.
func (sim *simulator) sanitizeChain(blocks []simBlock) ([]simBlock, error) {
	var (
		res           = make([]simBlock, 0, len(blocks))
		base          = sim.base
		prevNumber    = base.Number
		prevTimestamp = base.Time
	)
	for _, block := range blocks {
		if block.BlockOverrides == nil {
			block.BlockOverrides = new(override.BlockOverrides)
		}
		if block.BlockOverrides.Number == nil {
			n := new(big.Int).Add(prevNumber, big.NewInt(1))
			block.BlockOverrides.Number = (*hexutil.Big)(n)
		}
		diff := new(big.Int).Sub(block.BlockOverrides.Number.ToInt(), prevNumber)
		if diff.Cmp(common.Big0) <= 0 {
			return nil, &invalidBlockNumberError{fmt.Sprintf("block numbers must be in order: %d <= %d", block.BlockOverrides.Number.ToInt().Uint64(), prevNumber)}
		}
		if total := new(big.Int).Sub(block.BlockOverrides.Number.ToInt(), base.Number); total.Cmp(big.NewInt(maxSimulateBlocks)) > 0 {
			return nil, &clientLimitExceededError{message: "too many blocks"}
		}
		if diff.Cmp(big.NewInt(1)) > 0 {
			// Fill the gap with empty blocks.
			gap := new(big.Int).Sub(diff, big.NewInt(1))
			// Assign block number to the empty blocks.
			for i := uint64(0); i < gap.Uint64(); i++ {
				n := new(big.Int).Add(prevNumber, big.NewInt(int64(i+1)))
				t := prevTimestamp + timestampIncrement
				b := simBlock{BlockOverrides: &override.BlockOverrides{Number: (*hexutil.Big)(n), Time: (*hexutil.Uint64)(&t)}}
				prevTimestamp = t
				res = append(res, b)
			}
		}
		// Only append block after filling a potential gap.
		prevNumber = block.BlockOverrides.Number.ToInt()
		var t uint64
		if block.BlockOverrides.Time == nil {
			t = prevTimestamp + timestampIncrement
			block.BlockOverrides.Time = (*hexutil.Uint64)(&t)
		} else {
			t = uint64(*block.BlockOverrides.Time)
			if t <= prevTimestamp {
				return nil, &invalidBlockTimestampError{fmt.Sprintf("block timestamps must be in order: %d <= %d", t, prevTimestamp)}
			}
		}
		prevTimestamp = t
		res = append(res, block)
	}
	return res, nil
}

// makeHeaders makes header object with preliminary fields based on a simulated block.
// Some fields have to be filled post-execution.
// It assumes blocks are in order and numbers have been validated.
func (sim *simulator) makeHeaders(blocks []simBlock) ([]*types.Header, error) {
	var (
		res    = make([]*types.Header, len(blocks))
		base   = sim.base
		header = base
	)
	for bi, block := range blocks {
		if block.BlockOverrides == nil || block.BlockOverrides.Number == nil {
			return nil, errors.New("empty block number")
		}
		overrides := block.BlockOverrides

		header = overrides.MakeHeader(&types.Header{
			UncleHash:   types.EmptyUncleHash,
			ReceiptHash: types.EmptyReceiptsHash,
			TxHash:      types.EmptyTxsHash,
			Coinbase:    header.Coinbase,
			Difficulty:  header.Difficulty,
			GasLimit:    header.GasLimit,
		})
		res[bi] = header
	}
	return res, nil
}

func (sim *simulator) newSimulatedChainContext(ctx context.Context, headers []*types.Header) *ChainContext {
	return NewChainContext(ctx, &simBackend{base: sim.base, b: sim.b, headers: headers})
}

type simBackend struct {
	b       ChainContextBackend
	base    *types.Header
	headers []*types.Header
}

func (b *simBackend) Engine() consensus.Engine {
	return b.b.Engine()
}

func (b *simBackend) HeaderByNumber(ctx context.Context, number rpc.BlockNumber) (*types.Header, error) {
	if uint64(number) == b.base.Number.Uint64() {
		return b.base, nil
	}
	if uint64(number) < b.base.Number.Uint64() {
		// Resolve canonical header.
		return b.b.HeaderByNumber(ctx, number)
	}
	// Simulated block.
	for _, header := range b.headers {
		if header.Number.Uint64() == uint64(number) {
			return header, nil
		}
	}
	return nil, errors.New("header not found")
}

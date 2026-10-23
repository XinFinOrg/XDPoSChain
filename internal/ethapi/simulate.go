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
	"slices"
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

// requestSpan is the request level view the owner guard judges an override against: the
// first Prague-active block, when the request holds one, and the last block. The last
// block is always set.
type requestSpan struct {
	firstPrague *big.Int
	lastBlock   *big.Int
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
	// Every block of the request runs on one state, so an override planted on an earlier
	// block is still in effect when a later block runs its block level hooks. The guard
	// needs the request level view of that: the first Prague-active block, whose changes
	// the request cannot undo, and the last block.
	span := requestSpan{lastBlock: new(big.Int).Set(headers[len(headers)-1].Number)}
	for _, header := range headers {
		if sim.chainConfig.IsPrague(header.Number) {
			span.firstPrague = new(big.Int).Set(header.Number)
			break
		}
	}
	var (
		results = make([]map[string]interface{}, len(blocks))
		parent  = sim.base
		// Assume same total difficulty for all simulated blocks.
		td = sim.b.GetTd(ctx, sim.base.Hash())
	)
	for bi, block := range blocks {
		result, callResults, err := sim.processBlock(ctx, &block, headers[bi], parent, headers[:bi], span, timeout)
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

func (sim *simulator) processBlock(ctx context.Context, block *simBlock, header, parent *types.Header, headers []*types.Header, span requestSpan, timeout time.Duration) (*types.Block, []simCallResult, error) {
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
	if err := rejectOwnedAccountOverrides(sim.chainConfig, sim.state, precompiles, header, span, block.StateOverrides); err != nil {
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
	// Block level state changes, applied the way block processing does.
	core.ApplyBlockLevelHooks(header.ParentHash, evm)
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

// ownedOverrideError names the block level change that owns the field.
func ownedOverrideError(address common.Address, field, clause string) error {
	return &invalidParamsError{message: fmt.Sprintf("state override of %v sets %s, %s", address, field, clause)}
}

// crossBlockOverrideError names the block of the request that writes the field: the change
// runs at another block than the one the override landed on, which the caller cannot see.
func crossBlockOverrideError(address common.Address, field string, writer *big.Int) error {
	return &invalidParamsError{message: fmt.Sprintf("state override of %v sets %s; block %v of the request writes it", address, field, writer)}
}

// crossBlockRemovalError names the block of the request that removes the account, which
// drops an override the request planted on an earlier block.
func crossBlockRemovalError(address common.Address, field string, activation *big.Int) error {
	return &invalidParamsError{message: fmt.Sprintf("state override of %v sets %s; the block that activates TIPSigning at %v removes the account with it", address, field, activation)}
}

// pragueHookOwner returns the block whose Prague block level hooks the guard has to check:
// the simulated block when Prague is active there, otherwise the first Prague-active block
// of the request, whose changes carry into the simulated one. It returns nil when the
// request holds no Prague-active block.
func pragueHookOwner(config *params.ChainConfig, number, firstPrague *big.Int) *big.Int {
	if config.IsPrague(number) {
		return number
	}
	// firstPrague comes from a Prague-active header, so only its order needs checking.
	if firstPrague != nil && number.Cmp(firstPrague) < 0 {
		return firstPrague
	}
	return nil
}

// rejectOwnedAccountOverrides refuses an override of a field a block level hook writes,
// which would silently undo it or trip the consensus panic. A Prague block owns
// Multicall3 and the history contract (nonce, parent hash write), the TIPSigning activation
// block the block signers account. The request runs every block on one state, so the change
// of a later block owns its fields as well: the guard judges the simulated block against
// the block the change runs at, and names that block when it is not the simulated one.
// Fields a block does not write stay overridable, except a precompile move onto the history
// contract, which drops the write; a move from an account the EVM does not serve as a
// precompile cannot shadow it, and override.Apply rejects that move itself.
func rejectOwnedAccountOverrides(config *params.ChainConfig, statedb *state.StateDB, precompiles vm.PrecompiledContracts, header *types.Header, span requestSpan, overrides *override.StateOverride) error {
	if overrides == nil {
		return nil
	}
	if err := rejectPragueOwnedOverrides(config, statedb, precompiles, header.Number, span, overrides); err != nil {
		return err
	}
	return rejectTIPSigningRemovalOverrides(config, header.Number, span, overrides)
}

// rejectPragueOwnedOverrides refuses an override of a field the Prague block level hooks
// write at the owning block pragueHookOwner returns: the Multicall3 and history installs
// own code and a raised nonce, the parent hash write owns the ring positions the request
// fills, and a precompile move onto the history contract drops that write.
func rejectPragueOwnedOverrides(config *params.ChainConfig, statedb *state.StateDB, precompiles vm.PrecompiledContracts, number *big.Int, span requestSpan, overrides *override.StateOverride) error {
	owner := pragueHookOwner(config, number, span.firstPrague)
	if owner == nil {
		return nil
	}
	atBlock := owner.Cmp(number) == 0
	// The change at the simulated block needs no block number in the wording; one that
	// runs at another block of the request does, since the caller cannot see it.
	refuse := func(addr common.Address, field, clause string) error {
		if atBlock {
			return ownedOverrideError(addr, field, clause)
		}
		return crossBlockOverrideError(addr, field, owner)
	}
	if account, ok := (*overrides)[params.Multicall3Address]; ok {
		if account.Code != nil {
			return refuse(params.Multicall3Address, "code", "which the Prague Multicall3 install owns")
		}
		if account.Nonce != nil && len(statedb.GetCode(params.Multicall3Address)) == 0 {
			return refuse(params.Multicall3Address, "the nonce", "which the Prague Multicall3 install owns")
		}
	}
	if account, ok := (*overrides)[params.HistoryStorageAddress]; ok {
		// Refused whatever the bytes are: canonical code would skip the backfill.
		if account.Code != nil {
			return refuse(params.HistoryStorageAddress, "code", "which the Prague EIP-2935 history install owns")
		}
		// Only a zero nonce is raised, so a nonzero one survives.
		if account.Nonce != nil && len(statedb.GetCode(params.HistoryStorageAddress)) == 0 && *account.Nonce == 0 {
			return refuse(params.HistoryStorageAddress, "the nonce", "which the Prague EIP-2935 history install owns")
		}
		// A replacement wipes every slot, the written one included.
		if account.State != nil {
			return refuse(params.HistoryStorageAddress, "a state replacement", "which the Prague EIP-2935 history write owns")
		}
		// The owning block writes one ring position, and so does every block of the
		// request after it: the request shares one state, so their writes replace
		// whatever the override leaves in the same position.
		for _, slot := range slices.SortedFunc(maps.Keys(account.StateDiff), common.Hash.Cmp) {
			field := fmt.Sprintf("storage slot %v", slot)
			if atBlock && historyStorageSlotIsWritten(config, statedb, number, slot) {
				return refuse(params.HistoryStorageAddress, field, "which the Prague EIP-2935 history write owns")
			}
			if writer := historyRingOwner(slot, owner, span.lastBlock); writer != nil {
				return crossBlockOverrideError(params.HistoryStorageAddress, field, writer)
			}
		}
	}
	// A move onto the history contract shadows it, so the parent hash write is dropped.
	// The destination decides, not the named account, hence the address-ordered scan.
	// Only a source the EVM serves as a precompile can shadow the contract; for any
	// other one override.Apply rejects the move itself, before it runs. A move onto
	// Multicall3 stays allowed: the install is a state write. Each block carries its own
	// precompile set, so a move at an earlier block shadows nothing at the owning one.
	if atBlock {
		for _, source := range slices.SortedFunc(maps.Keys(*overrides), common.Address.Cmp) {
			dest := (*overrides)[source].MovePrecompileTo
			if dest == nil || *dest != params.HistoryStorageAddress {
				continue
			}
			if _, ok := precompiles[source]; !ok {
				continue
			}
			return ownedOverrideError(source, fmt.Sprintf("a precompile move onto %v", *dest), "whose account the Prague EIP-2935 history write owns")
		}
	}
	return nil
}

// rejectTIPSigningRemovalOverrides refuses an override of the block signers account: the
// TIPSigning activation block removes it, at that block running the change, and on an
// earlier block of the request dropping the override into which the shared state carries it.
func rejectTIPSigningRemovalOverrides(config *params.ChainConfig, number *big.Int, span requestSpan, overrides *override.StateOverride) error {
	if activation := config.TIPSigningBlock; activation != nil && activation.Sign() > 0 {
		if account, ok := (*overrides)[common.BlockSignersBinary]; ok {
			atActivation := activation.Cmp(number) == 0
			crossBlock := number.Cmp(activation) < 0 && activation.Cmp(span.lastBlock) <= 0
			if atActivation || crossBlock {
				// An empty map sets no field at the activation block, where the same block
				// removes the account, while on an earlier block it still clears the storage
				// the calls run with until the activation block.
				storageSet := len(account.State) > 0
				if crossBlock {
					storageSet = account.State != nil
				}
				refuse := func(field, clause string) error {
					if atActivation {
						return ownedOverrideError(common.BlockSignersBinary, field, clause)
					}
					return crossBlockRemovalError(common.BlockSignersBinary, field, activation)
				}
				for _, field := range []struct {
					name string
					set  bool
				}{
					{"the nonce", account.Nonce != nil},
					{"code", account.Code != nil},
					{"the balance", account.Balance != nil},
					{"storage", storageSet},
					{"a storage diff", len(account.StateDiff) > 0},
				} {
					if field.set {
						return refuse(field.name, "which the block that activates TIPSigning removes with the account")
					}
				}
			}
		}
	}
	return nil
}

// historyParentRing returns the ring position the parent hash of the given block occupies.
func historyParentRing(number uint64) uint64 {
	return (number - 1) % params.HistoryServeWindow
}

// historyStorageSlotIsWritten reports whether slot is one ProcessParentBlockHash writes at
// blockNumber: the parent hash slot, plus the deploy and backfill slots. Skipped slots count.
func historyStorageSlotIsWritten(config *params.ChainConfig, statedb *state.StateDB, blockNumber *big.Int, slot common.Hash) bool {
	if blockNumber.Sign() == 0 {
		return false
	}
	ring, ok := historyRingPosition(slot)
	if !ok {
		return false
	}

	// The parent hash lands in the ring position of the block below.
	number := blockNumber.Uint64()
	end := number - 1
	if ring == historyParentRing(number) {
		return true
	}
	// The deploy and backfill run only while the contract has no code.
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
	// The window wraps the ring at most once.
	if end-start+1 >= params.HistoryServeWindow {
		return true
	}
	startRing, endRing := start%params.HistoryServeWindow, end%params.HistoryServeWindow
	if startRing <= endRing {
		return ring >= startRing && ring <= endRing
	}
	return ring >= startRing || ring <= endRing
}

// historyRingPosition returns the ring position the slot names, and false for any other key.
func historyRingPosition(slot common.Hash) (uint64, bool) {
	// The ring position sits in the low bytes, as core.historyStorageKey builds it.
	for i := range common.HashLength - 8 {
		if slot[i] != 0 {
			return 0, false
		}
	}
	ring := binary.BigEndian.Uint64(slot[common.HashLength-8:])
	// The contract wraps the ring at the serve window.
	return ring, ring < params.HistoryServeWindow
}

// historyRingOwner returns the first block in [from, lastBlock] whose parent hash write lands in
// the ring position the slot names, or nil when the slot names no ring position or no block
// of the range writes it. from is a block of the request, so the scan never reaches block
// zero, which has no parent hash to write. The scan stays short, since a request holds at most
// maxSimulateBlocks blocks, and reads no state: before the deploy the contract has no code,
// so a probe of the snapshot would mis-place the activation block's backfill.
func historyRingOwner(slot common.Hash, from, lastBlock *big.Int) *big.Int {
	ring, ok := historyRingPosition(slot)
	if !ok {
		return nil
	}
	for number := new(big.Int).Set(from); number.Cmp(lastBlock) <= 0; number.Add(number, common.Big1) {
		if historyParentRing(number.Uint64()) == ring {
			return new(big.Int).Set(number)
		}
	}
	return nil
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
	// An empty JSON access list ("accessList": []) decodes to a non-nil empty
	// slice. ToMessage already treats it like an omitted list; normalize it here
	// so ToTransaction, which runs before ToMessage, picks the same transaction
	// type instead of a type-1 one the pool rejects before the fork.
	if call.AccessList != nil && len(*call.AccessList) == 0 {
		call.AccessList = nil
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

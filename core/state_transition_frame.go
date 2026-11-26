// Copyright 2026 The go-ethereum Authors
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
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/tracing"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/holiman/uint256"
)

// This file implements the EIP-8141 frame-transaction execution core: the
// frame loop (specification "Behavior" section), atomic batch rollback,
// approval-context journaling, two-dimensional frame gas accounting and the
// fee settlement ("Gas Accounting" section). The transaction-level receipt
// encoding is a later milestone.

// frameStatus values for frame receipts (EIP-8141 "Receipt Encoding").
const (
	frameStatusFailure = 0
	frameStatusSuccess = 1
	frameStatusSkipped = 2 // skipped due to a failed atomic batch
)

// emptyCodeHash is the keccak256 hash of empty code; a frame target with this
// code hash executes the EIP-8141 default code.
var emptyCodeHash = common.HexToHash("0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")

// approvalCheckpoint journals the transaction-scoped approval context so a
// reverted frame (or unrolled atomic batch) can restore it exactly.
type approvalCheckpoint struct {
	payer          common.Address
	payerSet       bool
	senderApproved bool
	senderNonce    uint64
}

// logCounter is implemented by *state.StateDB; it lets the frame driver
// capture per-frame logs without extending the vm.StateDB interface.
type logCounter interface {
	Logs() []*types.Log
}

// executeFrameTx processes an EIP-8141 frame transaction (specification
// "Behavior" and "Gas Accounting" sections). It runs the frame loop, enforces
// mode semantics, rolls back atomic batches, settles the two-dimensional gas
// accounting, and collects fees from the payer.
func (st *stateTransition) executeFrameTx(rules params.Rules) (*ExecutionResult, error) {
	msg := st.msg
	ftx := msg.FrameTx
	if ftx == nil || !rules.IsFrameTx {
		return nil, fmt.Errorf("%w: frame transaction outside of the FrameTx fork", types.ErrTxTypeNotSupported)
	}
	// 1. Ensure tx.nonce == state[tx.sender].nonce. The nonce is only
	// incremented by APPROVE, not here.
	if !msg.SkipNonceChecks {
		stNonce := st.state.GetNonce(ftx.Sender)
		if stNonce != msg.Nonce {
			return nil, fmt.Errorf("%w: address %v, tx: %d state: %d", ErrNonceTooHigh, ftx.Sender.Hex(), msg.Nonce, stNonce)
		}
	}
	// 2-3. Canonical signature hash and protocol-level validation of every
	// signature entry, plus the EIP-7825 gas-limit constraint.
	tx := types.NewTx(ftx)
	if err := types.ValidateFrameSignatures(tx); err != nil {
		return nil, err
	}
	if err := types.ValidateFrameGasLimits(tx); err != nil {
		return nil, err
	}
	sigHash := ftx.SigHash()

	// EIP-8141 "Gas Accounting / Fee budget": tx.fees.max_fee is a single
	// aggregate budget covering execution, state, and blob gas. The
	// transaction is invalid if it is below required_max_fee
	// (= max_gas * base_fee_per_gas, plus the blob component). max_cost is
	// what APPRVE collects from the payer; maxPriorityFee is the
	// room-limited aggregate min(tipCap * max_gas, max_fee - required_max_fee).
	baseFee := big.NewInt(0)
	if st.evm.Context.BaseFee != nil {
		baseFee = st.evm.Context.BaseFee
	}
	blobBaseFee := big.NewInt(0)
	if st.evm.Context.BlobBaseFee != nil {
		blobBaseFee = st.evm.Context.BlobBaseFee
	}
	blobGas := uint64(len(ftx.BlobHashes)) * params.BlobTxBlobGasPerBlob
	maxGas := ftx.MaxGas()

	requiredMaxFee := ftx.RequiredMaxFee(baseFee, blobBaseFee)
	maxFee := ftx.Fees.GasFeeCap.ToBig()
	if maxFee.Cmp(requiredMaxFee) < 0 {
		return nil, fmt.Errorf("%w: address %v, maxFee: %v, required: %v", ErrFeeCapTooLow, ftx.Sender.Hex(), maxFee, requiredMaxFee)
	}
	maxPriorityFee := new(big.Int).Mul(new(big.Int).SetUint64(maxGas), ftx.Fees.GasTipCap.ToBig())
	if room := new(big.Int).Sub(maxFee, requiredMaxFee); maxPriorityFee.Cmp(room) > 0 {
		maxPriorityFee.Set(room)
	}
	maxCost := new(big.Int).Add(requiredMaxFee, maxPriorityFee)

	// GASPRICE returns base_fee_per_gas + max_priority_fee // max_gas for
	// every frame (EIP-8141 "Fee budget").
	if maxGas > 0 {
		effectivePrice := new(big.Int).Add(baseFee, new(big.Int).Div(new(big.Int).Set(maxPriorityFee), new(big.Int).SetUint64(maxGas)))
		st.evm.TxContext.GasPrice = uint256.MustFromBig(effectivePrice)
	}

	// EIP-8037 block-level reservation ("Block-level gas accounting"): the
	// worst case of each dimension must fit the remaining block capacity.
	execReservation := ftx.IntrinsicGas()
	for i := range ftx.Frames {
		execReservation += ftx.Frames[i].Limits.Execution
	}
	if floor := ftx.CalldataFloorGas(); floor > execReservation {
		execReservation = floor
	}
	var stateReservation uint64
	for i := range ftx.Frames {
		stateReservation += ftx.Frames[i].Limits.State
	}
	if err := st.gp.CheckGasAmsterdam(execReservation, stateReservation); err != nil {
		return nil, err
	}

	// Initialize the access list as in EIP-2929/EIP-3651: tx.sender, the
	// coinbase and precompiles warm; accessed_storage_keys empty (no access
	// list).
	st.state.Prepare(rules, ftx.Sender, st.evm.Context.Coinbase, nil, vm.ActivePrecompiles(rules), nil)

	fc := &vm.FrameContext{
		Tx:                   ftx,
		SigHash:              sigHash,
		MaxCost:              maxCost,
		MaxPriorityFeePerGas: new(big.Int).Div(maxPriorityFee, new(big.Int).SetUint64(maxGas)),
		Receipts:             make([]vm.FrameReceipt, len(ftx.Frames)),
	}
	st.evm.SetFrameContext(fc)

	// Transaction-level snapshot: any transaction-invalid outcome (failed
	// VERIFY frame, unapproved SENDER frame, missing payer) unrolls the whole
	// transaction, including all APPROVE effects (EIP-8141 Behavior).
	txSnapshot := st.state.Snapshot()

	intrinsicGas := ftx.IntrinsicGas()

	// Per-frame state snapshots, used by atomic-batch rollback to revert to
	// the first frame of the batch. Approval checkpoints are journaled
	// alongside: a batch rollback restores the approval context to the batch
	// start as well (the state journal alone cannot undo fc's tx-scoped
	// fields).
	frameSnapshots := make([]int, len(ftx.Frames))
	checkpoints := make([]approvalCheckpoint, len(ftx.Frames))

	// Execute the frames. Atomic batches are maximal contiguous sequences
	// [i, j] with j > i where frames i..j-1 carry ATOMIC_BATCH_FLAG and
	// frame j does not.
	for i := 0; i < len(ftx.Frames); i++ {
		frame := &ftx.Frames[i]

		// SENDER frames require prior execution approval; otherwise the
		// transaction is invalid (EIP-8141 Behavior).
		if frame.Mode == types.FrameModeSender && !fc.SenderApproved {
			st.state.RevertToSnapshot(txSnapshot)
			st.evm.SetFrameContext(nil)
			return nil, fmt.Errorf("frame %d: SENDER frame without sender approval", i)
		}

		fc.FrameIdx = i
		frameSnapshots[i] = st.state.Snapshot()

		// Journal the approval context alongside the frame's state changes.
		checkpoints[i] = approvalCheckpoint{
			payer:          fc.Payer,
			payerSet:       fc.PayerSet,
			senderApproved: fc.SenderApproved,
			senderNonce:    st.state.GetNonce(ftx.Sender),
		}
		var logsBefore int
		if lg, ok := st.state.(logCounter); ok {
			logsBefore = len(lg.Logs())
		}

		receipt, vmerr := st.executeFrame(rules, fc, frame, i)
		if lg, ok := st.state.(logCounter); ok && vmerr == nil {
			all := lg.Logs()
			if len(all) > logsBefore {
				receipt.Logs = append(receipt.Logs, all[logsBefore:]...)
			}
		}
		fc.Receipts[i] = receipt

		if vmerr == nil {
			continue
		}
		// The frame failed: discard its approval context.
		st.restoreApprovalCheckpoint(fc, &checkpoints[i])

		if frame.Mode == types.FrameModeVerify {
			// A failed VERIFY frame invalidates the whole transaction; this
			// unrolls any effects of APPROVE as well (EIP-8141 Behavior).
			st.state.RevertToSnapshot(txSnapshot)
			st.evm.SetFrameContext(nil)
			return nil, fmt.Errorf("frame %d: VERIFY frame failed: %v", i, vmerr)
		}
		if frame.Flags&types.FrameAtomicBatchFlag == 0 {
			// No atomic batch: revert the individual frame.
			st.state.RevertToSnapshot(frameSnapshots[i])
			continue
		}
		// Unroll the associated atomic batch: roll the state back to the
		// condition immediately before the batch began and skip the
		// remaining frames in the batch.
		batchStart := i
		for batchStart > 0 && ftx.Frames[batchStart-1].Flags&types.FrameAtomicBatchFlag != 0 {
			batchStart--
		}
		batchEnd := i
		for batchEnd+1 < len(ftx.Frames) && ftx.Frames[batchEnd].Flags&types.FrameAtomicBatchFlag != 0 {
			batchEnd++
		}
		st.state.RevertToSnapshot(frameSnapshots[batchStart])
		// The batch's APPROVE effects roll back with the state; restore the
		// approval context journaled at the batch's first frame.
		st.restoreApprovalCheckpoint(fc, &checkpoints[batchStart])
		// Frames before batchStart are unaffected by the rollback.
		for k := batchStart; k <= batchEnd; k++ {
			receipt := &fc.Receipts[k]
			if k < i {
				// Frames that executed before the failure retain their
				// execution status and execution gas, with empty logs and
				// zero state gas.
				receipt.GasUsedState = 0
				receipt.Logs = nil
				continue
			}
			if k == i {
				// The failed frame retains its failure status; its state gas
				// and logs are zeroed by the rollback.
				receipt.GasUsedState = 0
				receipt.Logs = nil
				continue
			}
			// Frames that never executed are skipped (status 0x2); their
			// budgets are refunded at settlement.
			receipt.Status = frameStatusSkipped
			receipt.GasUsedExecution = 0
			receipt.GasUsedState = 0
			receipt.Logs = nil
		}
		i = batchEnd
	}
	st.evm.SetFrameContext(nil)

	// After executing all frames, payer must have been set.
	if !fc.PayerSet {
		st.state.RevertToSnapshot(txSnapshot)
		return nil, fmt.Errorf("frame transaction invalid: no frame set the payer")
	}

	res, err := st.settleFrameTx(rules, fc, intrinsicGas, maxCost, baseFee, blobBaseFee, blobGas)
	if err != nil {
		st.state.RevertToSnapshot(txSnapshot)
		return nil, err
	}
	res.FrameReceipts = fc.Receipts
	payer := fc.Payer
	res.Payer = &payer
	return res, nil
}

// executeFrame runs a single frame and returns its receipt. A nil error
// indicates success; ErrExecutionReverted indicates a revert; any other error
// indicates an exceptional halt.
func (st *stateTransition) executeFrame(rules params.Rules, fc *vm.FrameContext, frame *types.Frame, index int) (vm.FrameReceipt, error) {
	evm := st.evm
	ftx := fc.Tx
	receipt := vm.FrameReceipt{}

	resolvedTarget := fc.ResolvedTarget(index)

	// The frame's two independent gas pools (EIP-8141 "Frame gas pools").
	// StrictState enforces pool independence: a state-gas charge can never
	// borrow from execution gas.
	budget := vm.NewGasBudget(frame.Limits.Execution, frame.Limits.State)
	budget.StrictState = true

	// Charge the resolved target's warm/cold account access from gas_left,
	// before the balance check and before dispatch.
	accessGas := params.WarmStorageReadCostEIP2929
	if !evm.StateDB.AddressInAccessList(resolvedTarget) {
		accessGas = params.ColdAccountAccessCostEIP2929
		evm.StateDB.AddAddressToAccessList(resolvedTarget)
	}
	if !budget.ChargeRegularOnly(accessGas) {
		// The frame halts exceptionally: the entire execution pool is
		// consumed; the state pool is untouched.
		receipt.Status = frameStatusFailure
		receipt.GasUsedExecution = frame.Limits.Execution
		return receipt, vm.ErrOutOfGas
	}

	// Set the frame's caller (EIP-8141 Behavior): SENDER frames run as
	// tx.sender; DEFAULT/VERIFY frames run as ENTRY_POINT. ORIGIN returns
	// the frame's caller throughout all call depths.
	var caller common.Address
	switch frame.Mode {
	case types.FrameModeSender:
		caller = ftx.Sender
	case types.FrameModeDefault, types.FrameModeVerify:
		caller = vm.FrameEntryPoint
	}
	evm.TxContext.Origin = caller

	// EIP-8141 Behavior: the frame reverts (consuming the gas charged so
	// far) if the caller does not have sufficient balance to transfer
	// frame.value. This balance check precedes the account-creation charge
	// and the dispatch. VERIFY frames execute as STATICCALL and transfer no
	// value, so the check applies only to DEFAULT/SENDER frames.
	value := frameValue(frame)
	if !value.IsZero() && frame.Mode != types.FrameModeVerify {
		if balance := evm.StateDB.GetBalance(caller); balance.Cmp(value) < 0 {
			receipt.Status = frameStatusFailure
			receipt.GasUsedExecution = frame.Limits.Execution - budget.RegularGas
			return receipt, vm.ErrInsufficientBalance
		}
	}

	// Frame-level account creation charge: if frame.value > 0 and the
	// resolved target does not exist, STATE_BYTES_PER_NEW_ACCOUNT * CPSB
	// state gas is charged after the balance check and before the frame's
	// code executes (EIP-8141 Behavior; EIP-2780 pricing).
	if !value.IsZero() && !evm.StateDB.Exist(resolvedTarget) {
		cost := params.AccountCreationSize * evm.Context.CostPerStateByte
		if _, ok := budget.ChargeState(cost); !ok {
			receipt.Status = frameStatusFailure
			receipt.GasUsedExecution = frame.Limits.Execution
			return receipt, vm.ErrOutOfGas
		}
	}

	// Protocol-defined evaluation of the expiry verifier (EIP-8141 "Expiry
	// Verifier Frame"). A VERIFY frame whose target is EXPIRY_VERIFIER is
	// evaluated directly when no code is deployed there: clients may omit
	// the explicit EVM execution provided the externally observable result
	// is identical to executing the canonical runtime. The canonical
	// runtime gas is charged so direct evaluation is a pricing no-op
	// (EIP-8141: protocol-defined evaluation is an optimization, never a
	// pricing change). If code IS deployed at EXPIRY_VERIFIER it executes
	// normally through the ordinary dispatch below.
	codeHash := evm.StateDB.GetCodeHash(resolvedTarget)
	if frame.Mode == types.FrameModeVerify && frame.Target != nil && *frame.Target == types.FrameExpiryVerifier &&
		(codeHash == emptyCodeHash || codeHash == (common.Hash{})) {
		return st.executeExpiryVerifier(evm, &budget, frame)
	}

	// Dispatch: precompile, default code, or an ordinary call (which also
	// covers EIP-7702 delegation designators).
	var result vm.GasBudget
	var err error

	switch {
	case evm.PrecompileAt(resolvedTarget):
		if frame.Mode == types.FrameModeVerify {
			_, result, err = evm.StaticCall(caller, resolvedTarget, frame.Data, budget)
		} else {
			_, result, err = evm.Call(caller, resolvedTarget, frame.Data, budget, value)
		}
	case codeHash == emptyCodeHash || codeHash == (common.Hash{}):
		// Default code (EIP-8141 "Default code").
		if frame.Mode == types.FrameModeVerify {
			err = st.runDefaultVerifyCode(fc, frame, index, &budget)
			result = budget
		} else {
			// SENDER and DEFAULT frames against default (empty) code
			// execute as a call to empty code: the frame's value
			// transfer still applies. The caller's balance for the
			// transfer was checked above (EIP-8141 Behavior).
			if !value.IsZero() {
				Transfer(evm.StateDB, caller, resolvedTarget, value, &rules)
			}
			result = budget
		}
	default:
		if frame.Mode == types.FrameModeVerify {
			// VERIFY frames execute as STATICCALL, disallowing state
			// manipulation; only APPRVE may modify state or context.
			_, result, err = evm.StaticCall(caller, resolvedTarget, frame.Data, budget)
		} else {
			_, result, err = evm.Call(caller, resolvedTarget, frame.Data, budget, value)
		}
	}

	if err != nil {
		receipt.Status = frameStatusFailure
		if err == vm.ErrExecutionReverted || err == vm.ErrInsufficientBalance {
			// Revert (including the insufficient-balance frame value
			// revert): leftover execution gas is returned; attributed state
			// gas is zero.
			receipt.GasUsedExecution = frame.Limits.Execution - result.RegularGas
		} else {
			// Exceptional halt: the entire execution pool is consumed.
			receipt.GasUsedExecution = frame.Limits.Execution
		}
		return receipt, err
	}
	// Success.
	receipt.Status = frameStatusSuccess
	receipt.GasUsedExecution = frame.Limits.Execution - result.RegularGas
	receipt.GasUsedState = frame.Limits.State - result.StateGas
	return receipt, nil
}

// Canonical expiry verifier runtime instruction costs (EIP-8141 "Expiry
// Verifier Frame"), derived from the canonical bytecode
// 0x60083614600a575f5ffd5b5f3560c01c4211601657005b5f5ffd under the
// post-Berlin gas schedule:
//
//	size check    (PUSH1, CALLDATASIZE, EQ, PUSH1, JUMPI):                  21
//	size revert   (PUSH0, PUSH0, REVERT):                                    4 -> 25
//	check body    (JUMPDEST, PUSH0, CALLDATALOAD, PUSH1, SHR,
//	               TIMESTAMP, GT, PUSH1, JUMPI):                            30
//	success       (STOP):                                                    0 -> 51
//	deadline revert (JUMPDEST, PUSH0, PUSH0, REVERT):                        5 -> 56
const (
	expiryVerifyGasSuccess        = 51
	expiryVerifyGasSizeRevert     = 25
	expiryVerifyGasDeadlineRevert = 56
)

// executeExpiryVerifier performs the protocol-defined direct evaluation of
// the canonical expiry verifier runtime for a VERIFY frame targeting
// EXPIRY_VERIFIER when no code is deployed there (EIP-8141 "Expiry Verifier
// Frame": clients may omit the explicit EVM execution provided the
// externally observable result is identical to executing the canonical
// contract). Verification succeeds when the calldata is exactly
// EXPIRY_DATA_LENGTH bytes and block.timestamp <= the big-endian deadline,
// and reverts otherwise. The canonical instruction costs are charged so
// direct evaluation is never a pricing change.
func (st *stateTransition) executeExpiryVerifier(evm *vm.EVM, budget *vm.GasBudget, frame *types.Frame) (vm.FrameReceipt, error) {
	receipt := vm.FrameReceipt{}
	var gas uint64
	switch {
	case len(frame.Data) != types.FrameExpiryDataLength:
		gas = expiryVerifyGasSizeRevert
	case evm.Context.Time > binary.BigEndian.Uint64(frame.Data):
		gas = expiryVerifyGasDeadlineRevert
	default:
		gas = expiryVerifyGasSuccess
	}
	if !budget.ChargeRegularOnly(gas) {
		// Exceptional halt: the entire execution pool is consumed.
		receipt.Status = frameStatusFailure
		receipt.GasUsedExecution = frame.Limits.Execution
		return receipt, vm.ErrOutOfGas
	}
	if gas != expiryVerifyGasSuccess {
		// Canonical REVERT: leftover execution gas is returned; the VERIFY
		// failure invalidates the transaction in the frame loop.
		receipt.Status = frameStatusFailure
		receipt.GasUsedExecution = frame.Limits.Execution - budget.RegularGas
		return receipt, vm.ErrExecutionReverted
	}
	receipt.Status = frameStatusSuccess
	receipt.GasUsedExecution = frame.Limits.Execution - budget.RegularGas
	receipt.GasUsedState = frame.Limits.State - budget.StateGas
	return receipt, nil
}

// runDefaultVerifyCode implements the EIP-8141 default code for VERIFY-mode
// frames targeting accounts without code. It applies APPROVE(allowed_scope)
// directly: the default code draws no execution gas of its own.
func (st *stateTransition) runDefaultVerifyCode(fc *vm.FrameContext, frame *types.Frame, index int, budget *vm.GasBudget) error {
	ftx := fc.Tx
	allowedScope := uint64(frame.Flags & types.FrameApproveScopeMask)
	if allowedScope == vm.ApproveScopeNone {
		return vm.ErrExecutionReverted
	}
	sigIndex := 1
	if allowedScope&vm.ApproveScopeExecution != 0 {
		sigIndex = 0
	}
	if sigIndex >= len(ftx.Signatures) {
		return vm.ErrExecutionReverted
	}
	sig := &ftx.Signatures[sigIndex]
	if sig.Scheme != types.FrameSigSchemeSecp256k1 || len(sig.Msg) != 0 {
		return vm.ErrExecutionReverted
	}
	signer, err := ftx.ResolvedSigner(sigIndex)
	if err != nil || signer != fc.ResolvedTarget(index) {
		return vm.ErrExecutionReverted
	}
	return st.applyApproveEffects(fc, index, allowedScope, budget)
}

// applyApproveEffects applies the APPROVE scope effects shared by the opcode
// implementation and the default code: scope precondition checks, the
// conditional sender-account-creation state-gas charge, the sender nonce
// increment, and payer collection of the transaction's max_cost.
func (st *stateTransition) applyApproveEffects(fc *vm.FrameContext, index int, scope uint64, budget *vm.GasBudget) error {
	evm := st.evm
	resolvedTarget := fc.ResolvedTarget(index)
	sender := fc.Tx.Sender

	if scope&vm.ApproveScopeExecution != 0 {
		if fc.SenderApproved || fc.PayerSet {
			return vm.ErrExecutionReverted
		}
		if resolvedTarget != sender {
			return vm.ErrExecutionReverted
		}
	}
	if scope&vm.ApproveScopePayment != 0 {
		if fc.PayerSet {
			return vm.ErrExecutionReverted
		}
		if balance := evm.StateDB.GetBalance(resolvedTarget); fc.MaxCost != nil && balance.CmpBig(fc.MaxCost) < 0 {
			return vm.ErrExecutionReverted
		}
		if scope&vm.ApproveScopeExecution == 0 && !fc.SenderApproved {
			return vm.ErrExecutionReverted
		}
		// Immediately before incrementing the sender's nonce, charge the
		// sender-account-creation state gas if tx.sender does not exist.
		if evm.StateDB.Empty(sender) {
			cost := params.AccountCreationSize * evm.Context.CostPerStateByte
			if _, ok := budget.ChargeState(cost); !ok {
				return vm.ErrOutOfGas
			}
		}
		evm.StateDB.SetNonce(sender, evm.StateDB.GetNonce(sender)+1, tracing.NonceChangeApproval)
		fc.Payer = resolvedTarget
		fc.PayerSet = true
		if fc.MaxCost != nil && fc.MaxCost.Sign() > 0 {
			evm.StateDB.SubBalance(resolvedTarget, uint256.MustFromBig(fc.MaxCost), tracing.BalanceDecreaseGasBuy)
		}
	}
	if scope&vm.ApproveScopeExecution != 0 {
		fc.SenderApproved = true
	}
	return nil
}

// restoreApprovalCheckpoint restores the approval context journaled at frame
// entry.
func (st *stateTransition) restoreApprovalCheckpoint(fc *vm.FrameContext, cp *approvalCheckpoint) {
	st.state.SetNonce(fc.Tx.Sender, cp.senderNonce, tracing.NonceChangeRevert)
	fc.Payer, fc.PayerSet, fc.SenderApproved = cp.payer, cp.payerSet, cp.senderApproved
}

// frameValue returns the frame's value, or zero for value-less frames.
func frameValue(frame *types.Frame) *uint256.Int {
	if frame.Value != nil {
		return frame.Value
	}
	return new(uint256.Int)
}

// settleFrameTx performs the EIP-8141 "Transaction settlement" fee and gas
// accounting after all frames have executed.
func (st *stateTransition) settleFrameTx(rules params.Rules, fc *vm.FrameContext, intrinsicGas uint64, maxCost, baseFee, blobBaseFee *big.Int, blobGas uint64) (*ExecutionResult, error) {
	ftx := fc.Tx

	// tx_unused_gas: execution and state gas left in frame pools at frame
	// exit, plus skipped-frame budgets.
	var unusedGas, txStateGas, totalFrameGas uint64
	for i := range ftx.Frames {
		frame := &ftx.Frames[i]
		receipt := &fc.Receipts[i]
		unusedGas += (frame.Limits.Execution - receipt.GasUsedExecution) + (frame.Limits.State - receipt.GasUsedState)
		txStateGas += receipt.GasUsedState
		totalFrameGas += frame.Limits.Execution + frame.Limits.State
	}
	// standard_gas_limit = intrinsic + total frame gas.
	standardGasLimit := intrinsicGas + totalFrameGas
	gasUsedBeforeRefund := standardGasLimit - unusedGas

	// Storage refund (EIP-3529), capped at 1/5 of the pre-refund usage.
	// EIP-3298 (protocol decision D4, approved 2026-11-10): under Bogotá
	// no refunds apply — align frame settlement with the standard path
	// (calcRefund) instead of keeping a live 1/5-cap branch.
	var refund uint64
	if !rules.IsBogota {
		refund = gasUsedBeforeRefund / params.RefundQuotientEIP3529
		if refund > st.state.GetRefund() {
			refund = st.state.GetRefund()
		}
	}
	gasUsedAfterRefund := gasUsedBeforeRefund - refund

	// The calldata floor applies against the transaction's execution
	// component (EIP-8141 "Transaction settlement").
	floorGas := ftx.CalldataFloorGas()
	txExecutionGas := gasUsedAfterRefund - txStateGas
	if txExecutionGas < floorGas {
		txExecutionGas = floorGas
	}
	gasUsed := txExecutionGas + txStateGas

	// Payer settlement: the payer is returned max_cost minus the actual
	// fees; the base-fee portion is burned.
	baseFeePaid := new(big.Int).Mul(new(big.Int).SetUint64(gasUsed), baseFee)
	if blobGas > 0 {
		baseFeePaid.Add(baseFeePaid, new(big.Int).Mul(new(big.Int).SetUint64(blobGas), blobBaseFee))
	}
	// priority_fee_paid = min(max_priority_fee_per_gas * gas_used,
	// max_cost - base_fee_paid): the per-gas rate is the user-specified
	// max_priority_fee_per_gas, not the admission-adjusted aggregate
	// divided by max_gas (EIP-8141 "Transaction settlement"). gas_used <=
	// max_gas, so the room is never negative and the payer never pays
	// more than tx.fees.max_fee.
	priorityFeePaid := new(big.Int).Mul(new(big.Int).SetUint64(gasUsed), ftx.Fees.GasTipCap.ToBig())
	if room := new(big.Int).Sub(maxCost, baseFeePaid); priorityFeePaid.Cmp(room) > 0 {
		priorityFeePaid.Set(room)
	}
	payerRefund := new(big.Int).Sub(maxCost, baseFeePaid)
	payerRefund.Sub(payerRefund, priorityFeePaid)

	if payerRefund.Sign() > 0 {
		st.state.AddBalance(fc.Payer, uint256.MustFromBig(payerRefund), tracing.BalanceIncreaseGasReturn)
	}
	if priorityFeePaid.Sign() > 0 {
		st.state.AddBalance(st.evm.Context.Coinbase, uint256.MustFromBig(priorityFeePaid), tracing.BalanceIncreaseRewardTransactionFee)
	}

	// Block-level accounting (EIP-8141 "Block-level gas accounting"): the
	// execution dimension counts pre-refund usage, the state dimension is
	// net.
	blockExecutionGas := gasUsedBeforeRefund - txStateGas
	if blockExecutionGas < floorGas {
		blockExecutionGas = floorGas
	}
	if err := st.gp.ChargeGasAmsterdam(blockExecutionGas, txStateGas, gasUsed); err != nil {
		return nil, err
	}

	return &ExecutionResult{
		UsedGas:    gasUsed,
		MaxUsedGas: gasUsedBeforeRefund,
	}, nil
}

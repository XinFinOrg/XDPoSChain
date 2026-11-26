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

package vm

import (
	"errors"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/tracing"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/holiman/uint256"
)

// This file implements the EIP-8141 frame-transaction instructions:
// APPRVE (0xaa), TXPARAM (0xb0), FRAMEDATALOAD (0xb1), FRAMEDATACOPY (0xb2),
// FRAMEPARAM (0xb3), SIGPARAM (0xb4) and SIGDATACOPY (0xb5).
//
// Per the specification ("Introspection"): these instructions are defined
// only during the execution of a frame transaction; executing any of them in
// the context of any other transaction type results in an exceptional halt.

// approveScope constants (EIP-8141 "APPROVE Instruction": Scope Operand).
const (
	ApproveScopeNone                = 0x0
	ApproveScopePayment             = 0x1
	ApproveScopeExecution           = 0x2
	ApproveScopeExecutionAndPayment = 0x3
)

var (
	// ErrInvalidFrameParam is the exceptional halt for undefined TXPARAM /
	// FRAMEPARAM parameters and out-of-bounds frame indexes.
	ErrInvalidFrameParam = errors.New("invalid frame parameter")

	// ErrInvalidSigParam is the exceptional halt for undefined SIGPARAM
	// parameters, out-of-bounds signature indexes, and attempts to access
	// non-introspectable signature metadata.
	ErrInvalidSigParam = errors.New("invalid signature parameter")
)

// opFrameApprove implements APPRVE (0xaa). It exits the current EVM call
// frame successfully, designates the call frame's return data from memory,
// and updates the transaction-scoped approval context.
func opFrameApprove(pc *uint64, evm *EVM, scope *ScopeContext) ([]byte, error) {
	fc := evm.frameContext()
	if fc == nil {
		return nil, errFrameOpcodeNonFrameTx
	}
	offset, length := scope.Stack.pop2()
	scopeValue := scope.Stack.pop()

	frame := &fc.Tx.Frames[fc.FrameIdx]
	resolvedTarget := fc.ResolvedTarget(fc.FrameIdx)

	// ADDRESS must be the frame's resolved target.
	if scope.Contract.Address() != resolvedTarget {
		return nil, ErrExecutionReverted
	}
	// scope must be non-zero and within the caller's allowed scopes
	// (frame.flags & APPROVE_SCOPE_MASK).
	allowed := uint64(frame.Flags & types.FrameApproveScopeMask)
	s := scopeValue.Uint64()
	if s == 0 || s&^allowed != 0 {
		return nil, ErrExecutionReverted
	}

	sender := fc.Tx.Sender
	switch s {
	case ApproveScopeExecution:
		if fc.SenderApproved {
			return nil, ErrExecutionReverted
		}
		if resolvedTarget != sender {
			return nil, ErrExecutionReverted
		}
		fc.SenderApproved = true
	case ApproveScopePayment:
		// PAYMENT-only requires a prior EXECUTION approval (EIP-8141
		// APPROVE Instruction: "If sender_approved == false, revert").
		// The combined scope below does not.
		if !fc.SenderApproved {
			return nil, ErrExecutionReverted
		}
		if err := approvePaymentPreconditions(evm, fc, resolvedTarget); err != nil {
			return nil, err
		}
		if err := approveSenderCreationCharge(evm, scope, sender); err != nil {
			// Exceptional halt without applying any approval effects.
			return nil, err
		}
		applyPaymentApproval(evm, fc, resolvedTarget, sender)
	case ApproveScopeExecutionAndPayment:
		if fc.SenderApproved || fc.PayerSet {
			return nil, ErrExecutionReverted
		}
		if resolvedTarget != sender {
			return nil, ErrExecutionReverted
		}
		if err := approvePaymentPreconditions(evm, fc, resolvedTarget); err != nil {
			return nil, err
		}
		if err := approveSenderCreationCharge(evm, scope, sender); err != nil {
			return nil, err
		}
		fc.SenderApproved = true
		applyPaymentApproval(evm, fc, resolvedTarget, sender)
	default:
		return nil, ErrExecutionReverted
	}
	ret := scope.Memory.GetCopy(offset.Uint64(), length.Uint64())
	return ret, errStopToken
}

// approvePaymentPreconditions performs the APPROVE payment precondition
// checks shared by PAYMENT (0x1) and EXECUTION_AND_PAYMENT (0x3): no payer
// may be set yet and the resolved payer must cover the transaction's
// max_cost. Per EIP-8141, requiring a prior EXECUTION approval is specific
// to PAYMENT-only and is enforced by the PAYMENT case itself.
func approvePaymentPreconditions(evm *EVM, fc *FrameContext, resolvedTarget common.Address) error {
	if fc.PayerSet {
		return ErrExecutionReverted
	}
	if balance := evm.StateDB.GetBalance(resolvedTarget); fc.MaxCost != nil && balance.CmpBig(fc.MaxCost) < 0 {
		return ErrExecutionReverted
	}
	return nil
}

// approveSenderCreationCharge charges STATE_BYTES_PER_NEW_ACCOUNT * CPSB
// state gas when the sender account does not exist, immediately before the
// nonce increment.
func approveSenderCreationCharge(evm *EVM, scope *ScopeContext, sender common.Address) error {
	if evm.StateDB.Empty(sender) {
		cost := params.AccountCreationSize * evm.Context.CostPerStateByte
		if _, ok := scope.Contract.Gas.ChargeState(cost); !ok {
			return ErrOutOfGas
		}
	}
	return nil
}

// applyPaymentApproval increments the sender's nonce, records the payer, and
// collects the transaction's max_cost from it.
func applyPaymentApproval(evm *EVM, fc *FrameContext, resolvedTarget, sender common.Address) {
	evm.StateDB.SetNonce(sender, evm.StateDB.GetNonce(sender)+1, tracing.NonceChangeApproval)
	fc.Payer = resolvedTarget
	fc.PayerSet = true
	if fc.MaxCost != nil && fc.MaxCost.Sign() > 0 {
		evm.StateDB.SubBalance(resolvedTarget, uint256.MustFromBig(fc.MaxCost), tracing.BalanceDecreaseGasBuy)
	}
}

// opTxParam implements TXPARAM (0xb0). Parameter numbering follows the
// EIP-8141 "TXPARAM Instruction" table exactly.
func opTxParam(pc *uint64, evm *EVM, scope *ScopeContext) ([]byte, error) {
	fc := evm.frameContext()
	if fc == nil {
		return nil, errFrameOpcodeNonFrameTx
	}
	tx := fc.Tx
	var result *uint256.Int
	switch scope.Stack.back(0).Uint64() {
	case 0x00: // TXPARAM_TYPE: current transaction type
		result = new(uint256.Int).SetUint64(uint64(types.FrameTxType))
		scope.Stack.pop()
	case 0x01: // TXPARAM_NONCE
		result = new(uint256.Int).SetUint64(tx.Nonce)
		scope.Stack.pop()
	case 0x02: // TXPARAM_SENDER
		result = new(uint256.Int).SetBytes(tx.Sender.Bytes())
		scope.Stack.pop()
	case 0x03: // TXPARAM_MAX_PRIORITY_FEE_PER_GAS
		result = new(uint256.Int).Set(tx.Fees.GasTipCap)
		scope.Stack.pop()
	case 0x04: // TXPARAM_MAX_FEE
		result = new(uint256.Int).Set(tx.Fees.GasFeeCap)
		scope.Stack.pop()
	case 0x07: // TXPARAM_BLOB_COUNT
		result = new(uint256.Int).SetUint64(uint64(len(tx.BlobHashes)))
		scope.Stack.pop()
	case 0x08: // TXPARAM_SIG_HASH
		result = new(uint256.Int).SetBytes(fc.SigHash.Bytes())
		scope.Stack.pop()
	case 0x09: // TXPARAM_FRAME_COUNT
		result = new(uint256.Int).SetUint64(uint64(len(tx.Frames)))
		scope.Stack.pop()
	case 0x0a: // TXPARAM_CURRENT_FRAME_INDEX
		result = new(uint256.Int).SetUint64(uint64(fc.FrameIdx))
		scope.Stack.pop()
	case 0x0b: // TXPARAM_SIGNATURE_COUNT
		result = new(uint256.Int).SetUint64(uint64(len(tx.Signatures)))
		scope.Stack.pop()
	case 0x0c: // TXPARAM_STATE_GAS_LEFT
		result = new(uint256.Int).SetUint64(scope.Contract.Gas.StateGas)
		scope.Stack.pop()
	default:
		return nil, ErrInvalidFrameParam
	}
	scope.Stack.push(result)
	return nil, nil
}

// opFrameDataLoad implements FRAMEDATALOAD (0xb1).
func opFrameDataLoad(pc *uint64, evm *EVM, scope *ScopeContext) ([]byte, error) {
	fc := evm.frameContext()
	if fc == nil {
		return nil, errFrameOpcodeNonFrameTx
	}
	offset, frameIndex := scope.Stack.pop2()
	idx := frameIndex.Uint64()
	if idx >= uint64(len(fc.Tx.Frames)) {
		return nil, ErrInvalidFrameParam
	}
	data := fc.Tx.Frames[idx].Data
	var x uint256.Int
	if off, overflow := offset.Uint64WithOverflow(); !overflow {
		x.SetBytes(getData(data, off, 32))
	}
	scope.Stack.push(&x)
	return nil, nil
}

// opFrameDataCopy implements FRAMEDATACOPY (0xb2).
func opFrameDataCopy(pc *uint64, evm *EVM, scope *ScopeContext) ([]byte, error) {
	fc := evm.frameContext()
	if fc == nil {
		return nil, errFrameOpcodeNonFrameTx
	}
	memOffset, dataOffset, length, frameIndex := scope.Stack.pop4()
	idx := frameIndex.Uint64()
	if idx >= uint64(len(fc.Tx.Frames)) {
		return nil, ErrInvalidFrameParam
	}
	data := fc.Tx.Frames[idx].Data
	dataOffset64, overflow := dataOffset.Uint64WithOverflow()
	if overflow {
		dataOffset64 = ^uint64(0)
	}
	scope.Memory.Set(memOffset.Uint64(), length.Uint64(), getData(data, dataOffset64, length.Uint64()))
	return nil, nil
}

// opFrameParam implements FRAMEPARAM (0xb3).
func opFrameParam(pc *uint64, evm *EVM, scope *ScopeContext) ([]byte, error) {
	fc := evm.frameContext()
	if fc == nil {
		return nil, errFrameOpcodeNonFrameTx
	}
	frameIndex, param := scope.Stack.pop2()
	idx := frameIndex.Uint64()
	if idx >= uint64(len(fc.Tx.Frames)) {
		return nil, ErrInvalidFrameParam
	}
	frame := &fc.Tx.Frames[idx]
	result := new(uint256.Int)
	switch param.Uint64() {
	case 0x00: // FRAMEPARAM_RESOLVED_TARGET
		result.SetBytes(fc.ResolvedTarget(int(idx)).Bytes())
	case 0x01: // FRAMEPARAM_EXECUTION_GAS_LIMIT
		result.SetUint64(frame.Limits.Execution)
	case 0x02: // FRAMEPARAM_MODE
		result.SetUint64(uint64(frame.Mode))
	case 0x03: // FRAMEPARAM_FLAGS
		result.SetUint64(uint64(frame.Flags))
	case 0x04: // FRAMEPARAM_DATA_LENGTH
		result.SetUint64(uint64(len(frame.Data)))
	case 0x05: // FRAMEPARAM_STATUS
		if idx >= uint64(fc.FrameIdx) {
			return nil, ErrInvalidFrameParam
		}
		result.SetUint64(uint64(fc.Receipts[idx].Status))
	case 0x06: // FRAMEPARAM_ALLOWED_SCOPE
		result.SetUint64(uint64(frame.Flags & types.FrameApproveScopeMask))
	case 0x07: // FRAMEPARAM_ATOMIC_BATCH
		result.SetUint64(uint64((frame.Flags >> 2) & 0x01))
	case 0x08: // FRAMEPARAM_VALUE
		if frame.Value != nil {
			result.Set(frame.Value)
		}
	case 0x09: // FRAMEPARAM_STATE_GAS_LIMIT
		result.SetUint64(frame.Limits.State)
	case 0x0a: // FRAMEPARAM_EXECUTION_GAS_USED
		if idx >= uint64(fc.FrameIdx) {
			return nil, ErrInvalidFrameParam
		}
		result.SetUint64(fc.Receipts[idx].GasUsedExecution)
	case 0x0b: // FRAMEPARAM_STATE_GAS_USED
		if idx >= uint64(fc.FrameIdx) {
			return nil, ErrInvalidFrameParam
		}
		result.SetUint64(fc.Receipts[idx].GasUsedState)
	default:
		return nil, ErrInvalidFrameParam
	}
	scope.Stack.push(result)
	return nil, nil
}

// opSigParam implements SIGPARAM (0xb4).
func opSigParam(pc *uint64, evm *EVM, scope *ScopeContext) ([]byte, error) {
	fc := evm.frameContext()
	if fc == nil {
		return nil, errFrameOpcodeNonFrameTx
	}
	sigIndex, param := scope.Stack.pop2()
	idx := sigIndex.Uint64()
	if idx >= uint64(len(fc.Tx.Signatures)) {
		return nil, ErrInvalidSigParam
	}
	sig := &fc.Tx.Signatures[idx]
	result := new(uint256.Int)
	switch param.Uint64() {
	case 0x00: // SIGPARAM_RESOLVED_SIGNER
		if sig.Scheme == types.FrameSigSchemeArbitrary {
			return nil, ErrInvalidSigParam
		}
		if len(sig.Signer) == 0 {
			result.SetBytes(fc.Tx.Sender.Bytes())
		} else {
			result.SetBytes(common.BytesToAddress(sig.Signer).Bytes())
		}
	case 0x01: // SIGPARAM_SCHEME
		result.SetUint64(uint64(sig.Scheme))
	case 0x02: // SIGPARAM_MSG
		if len(sig.Msg) != 0 && len(sig.Msg) != 32 {
			return nil, ErrInvalidSigParam
		}
		result.SetBytes(sig.Msg)
	case 0x03: // SIGPARAM_SIGNATURE_LENGTH (ARBITRARY only)
		if sig.Scheme != types.FrameSigSchemeArbitrary {
			return nil, ErrInvalidSigParam
		}
		result.SetUint64(uint64(len(sig.Signature)))
	default:
		return nil, ErrInvalidSigParam
	}
	scope.Stack.push(result)
	return nil, nil
}

// opSigDataCopy implements SIGDATACOPY (0xb5). Only ARBITRARY signature
// bytes are introspectable.
func opSigDataCopy(pc *uint64, evm *EVM, scope *ScopeContext) ([]byte, error) {
	fc := evm.frameContext()
	if fc == nil {
		return nil, errFrameOpcodeNonFrameTx
	}
	memOffset, dataOffset, length, sigIndex := scope.Stack.pop4()
	idx := sigIndex.Uint64()
	if idx >= uint64(len(fc.Tx.Signatures)) {
		return nil, ErrInvalidSigParam
	}
	sig := &fc.Tx.Signatures[idx]
	if sig.Scheme != types.FrameSigSchemeArbitrary {
		return nil, ErrInvalidSigParam
	}
	dataOffset64, overflow := dataOffset.Uint64WithOverflow()
	if overflow {
		dataOffset64 = ^uint64(0)
	}
	scope.Memory.Set(memOffset.Uint64(), length.Uint64(), getData(sig.Signature, dataOffset64, length.Uint64()))
	return nil, nil
}

// enable8141 enables the EIP-8141 frame-transaction instructions. The
// instructions are defined only during the execution of a frame transaction;
// outside of one they halt exceptionally (see errFrameOpcodeNonFrameTx).
func enable8141(jt *JumpTable) {
	jt[APPROVE] = &operation{
		execute:    opFrameApprove,
		dynamicGas: gasReturn,
		minStack:   minStack(3, 0),
		maxStack:   maxStack(3, 0),
		memorySize: memoryReturn,
	}
	jt[TXPARAM] = &operation{
		execute:     opTxParam,
		constantGas: GasQuickStep,
		minStack:    minStack(1, 1),
		maxStack:    maxStack(1, 1),
	}
	jt[FRAMEDATALOAD] = &operation{
		execute:     opFrameDataLoad,
		constantGas: GasFastestStep,
		minStack:    minStack(2, 1),
		maxStack:    maxStack(2, 1),
	}
	jt[FRAMEDATACOPY] = &operation{
		execute:     opFrameDataCopy,
		constantGas: GasFastestStep,
		dynamicGas:  gasCallDataCopy,
		minStack:    minStack(4, 0),
		maxStack:    maxStack(4, 0),
		memorySize:  memoryCallDataCopy,
	}
	jt[FRAMEPARAM] = &operation{
		execute:     opFrameParam,
		constantGas: GasQuickStep,
		minStack:    minStack(2, 1),
		maxStack:    maxStack(2, 1),
	}
	jt[SIGPARAM] = &operation{
		execute:     opSigParam,
		constantGas: GasQuickStep,
		minStack:    minStack(2, 1),
		maxStack:    maxStack(2, 1),
	}
	jt[SIGDATACOPY] = &operation{
		execute:     opSigDataCopy,
		constantGas: GasFastestStep,
		dynamicGas:  gasCallDataCopy,
		minStack:    minStack(4, 0),
		maxStack:    maxStack(4, 0),
		memorySize:  memoryCallDataCopy,
	}
}

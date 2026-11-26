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
	"math/big"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/types"
)

// FrameEntryPoint is the EIP-8141 ENTRY_POINT address: the caller of
// DEFAULT and VERIFY frames, and the value returned by ORIGIN in those modes.
var FrameEntryPoint = common.Address{0xaa}

// errFrameOpcodeNonFrameTx is returned by the EIP-8141 frame opcodes when
// they execute outside of a frame transaction. Per the specification this is
// an exceptional halt.
var errFrameOpcodeNonFrameTx = errors.New("frame opcode in non-frame transaction")

// FrameReceipt is the EIP-8141 per-frame receipt: [status, gas_used, logs].
// Status is 0 for a failed frame, 1 for a successful frame and 0x2 for a frame
// skipped due to a failed atomic batch. The canonical type and its RLP/JSON
// encodings live in core/types; this alias keeps the vm API unchanged.
type FrameReceipt = types.FrameReceipt

// FrameContext carries the EIP-8141 frame-transaction execution state shared
// between the frame driver (core package) and the frame opcodes. A non-nil
// FrameContext on the EVM marks the current execution as a frame transaction.
type FrameContext struct {
	Tx             *types.FrameTx // the transaction payload
	SigHash        common.Hash    // compute_sig_hash(tx)
	FrameIdx       int            // currently executing frame index
	Payer          common.Address
	PayerSet       bool
	SenderApproved bool

	// MaxCost is the worst-case amount collected from the payer on
	// APPROVE(APPROVE_PAYMENT). MaxPriorityFeePerGas is the effective
	// priority-fee-per-gas implied by the fee budget. Both are computed by
	// the frame driver before execution.
	MaxCost              *big.Int
	MaxPriorityFeePerGas *big.Int

	// Receipts holds one entry per transaction frame, in frame order.
	Receipts []FrameReceipt
}

// ResolvedTarget returns the target of frame i, defaulting to tx.sender when
// the frame carries no explicit target (EIP-8141 Behavior: "resolved_target =
// frame.target if frame.target is not None else tx.sender").
func (fc *FrameContext) ResolvedTarget(i int) common.Address {
	if i < 0 || i >= len(fc.Tx.Frames) {
		return common.Address{}
	}
	if t := fc.Tx.Frames[i].Target; t != nil {
		return *t
	}
	return fc.Tx.Sender
}

// frameContext returns the active frame context, or nil when the EVM is not
// executing a frame transaction.
func (evm *EVM) frameContext() *FrameContext {
	return evm.frameCtx
}

// PrecompileAt reports whether addr hosts an active precompiled contract at
// the current fork.
func (evm *EVM) PrecompileAt(addr common.Address) bool {
	_, ok := evm.precompile(addr)
	return ok
}

// SetFrameContext attaches (or detaches, with nil) the frame-transaction
// execution context. It must be called before the first frame executes.
func (evm *EVM) SetFrameContext(fc *FrameContext) {
	evm.frameCtx = fc
}

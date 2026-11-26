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
	"fmt"
	"math/big"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/tracing"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
)

// codeLookup abstracts the state access the target rule needs.
type codeLookup interface {
	GetCode(common.Address) []byte
}

// frameValidationTracer enforces the EIP-8141 "Validation Trace Rules"
// during validation-prefix simulation: banned opcodes with the
// specification-defined exceptions, storage writes outside tx.sender (except
// in the first deploy frame), code installation outside tx.sender, and
// CALL*/EXTCODE* targeting nonexistent, non-precompile, or EIP-7702
// delegated addresses (except tx.sender default-code behavior).
//
// The tracer observes nested calls: every opcode of every call depth inside
// the simulated frame is checked, so indirect execution paths (library
// DELEGATECALLs, helper contracts) are covered.
type frameValidationTracer struct {
	sender        common.Address
	deployFrame   bool       // current top-level frame is the first deploy frame
	allowTime     bool       // TIMESTAMP permitted (canonical expiry verifier frame)
	state         codeLookup // state for the target rule
	precompileSet map[common.Address]bool

	violation  error
	pendingGas bool // previous opcode was GAS; awaiting the CALL* verdict
}

// bannedValidationOpcodes is the EIP-8141 "Banned Opcodes" list. Opcodes
// with specification-defined exceptions are handled separately in
// OnOpcode: GAS (0x5A), TIMESTAMP (0x42), CREATE (0xF0), CREATE2 (0xF5),
// SSTORE (0x55, write rule via OnStorageChange), and SETDELEGATE (0xF6) is
// not an opcode in this client, where it executes as an undefined opcode
// and halts the frame (rejecting the transaction).
var bannedValidationOpcodes = map[byte]string{
	0x3A: "GASPRICE",
	0x40: "BLOCKHASH",
	0x41: "COINBASE",
	0x43: "NUMBER",
	0x44: "PREVRANDAO",
	0x45: "GASLIMIT",
	0x48: "BASEFEE",
	0x4A: "BLOBBASEFEE",
	0x4B: "SLOTNUM",
	0xFE: "INVALID",
	0xFF: "SELFDESTRUCT",
	0x31: "BALANCE",
	0x47: "SELFBALANCE",
}

// callFamily reports whether op is a *CALL instruction (the GAS exception
// and the CALL* target rule).
func callFamily(op byte) bool {
	switch vm.OpCode(op) {
	case vm.CALL, vm.CALLCODE, vm.DELEGATECALL, vm.STATICCALL:
		return true
	}
	return false
}

func (t *frameValidationTracer) fail(format string, args ...interface{}) {
	if t.violation == nil {
		t.violation = fmt.Errorf("frame validation: "+format, args...)
	}
}

// OnOpcode enforces the banned-opcode list and the EXTCODE* target rule.
// The stack arguments are inspected before opcode execution.
func (t *frameValidationTracer) OnOpcode(pc uint64, op byte, gas, cost uint64, scope tracing.OpContext, rData []byte, depth int, err error) {
	if t.violation != nil {
		return
	}
	// Resolve the deferred GAS verdict: GAS is banned unless immediately
	// followed by a *CALL instruction.
	if t.pendingGas {
		t.pendingGas = false
		if !callFamily(op) {
			t.fail("GAS opcode not followed by a CALL")
			return
		}
	}
	switch vm.OpCode(op) {
	case vm.GAS:
		t.pendingGas = true
	case vm.TIMESTAMP:
		if !t.allowTime {
			t.fail("TIMESTAMP opcode banned during validation")
		}
	case vm.CREATE, vm.CREATE2:
		if !t.deployFrame {
			t.fail("%v opcode banned outside the first deploy frame", vm.OpCode(op))
		}
	case vm.SSTORE:
		// In non-deploy frames the STATICCALL write protection would revert
		// anyway; report the precise rule instead. In the deploy frame the
		// address restriction (tx.sender only) is enforced through
		// OnStorageChange.
		if !t.deployFrame {
			t.fail("SSTORE opcode banned outside the first deploy frame")
		}
	case vm.EXTCODESIZE, vm.EXTCODEHASH, vm.EXTCODECOPY:
		// Target address on the stack: top for SIZE/HASH, 4th for COPY.
		stack := scope.StackData()
		idx := len(stack) - 1
		if vm.OpCode(op) == vm.EXTCODECOPY {
			idx = len(stack) - 4
		}
		if idx >= 0 && idx < len(stack) {
			t.checkCallTarget(common.Address(stack[idx].Bytes20()), vm.OpCode(op).String())
		}
	default:
		if name, banned := bannedValidationOpcodes[op]; banned {
			t.fail("%s opcode banned during validation", name)
		}
	}
}

// OnEnter enforces the CALL* target rule for nested calls. The top-level
// frame call itself is checked as well: its target was shape-checked, and
// the rule permits existing contracts, precompiles, and tx.sender.
func (t *frameValidationTracer) OnEnter(depth int, typ byte, from common.Address, to common.Address, input []byte, gas uint64, value *big.Int) {
	if t.violation != nil {
		return
	}
	if callFamily(typ) {
		t.checkCallTarget(to, vm.OpCode(typ).String())
	}
}

// OnStorageChange enforces the state-write rule: SSTOREs are permitted only
// to tx.sender's storage, and only inside the first deploy frame
// (EIP-8141 "Validation Trace Rules": (b) exception).
func (t *frameValidationTracer) OnStorageChange(addr common.Address, slot common.Hash, prev, new common.Hash) {
	if t.violation != nil {
		return
	}
	if addr != t.sender || !t.deployFrame {
		t.fail("SSTORE to %s outside tx.sender storage in the first deploy frame", addr)
	}
}

// OnCodeChange enforces that code installation during the validation prefix
// targets tx.sender only, and only inside the first deploy frame (the
// CREATE/CREATE2 exception is tied to installing code at tx.sender).
func (t *frameValidationTracer) OnCodeChange(addr common.Address, prevCodeHash common.Hash, prevCode []byte, codeHash common.Hash, code []byte) {
	if t.violation != nil {
		return
	}
	if addr != t.sender || !t.deployFrame {
		t.fail("code installation at %s outside the first deploy frame", addr)
	}
}

// checkCallTarget enforces: CALL*/EXTCODE* may target an existing contract
// or a precompile, but not a nonexistent account, and not an address using
// an EIP-7702 delegation — except tx.sender default-code behavior.
func (t *frameValidationTracer) checkCallTarget(to common.Address, op string) {
	if to == t.sender {
		return // tx.sender default-code behavior
	}
	if t.state == nil {
		return
	}
	// Checked via the state accessor installed by the simulator.
	code := t.state.GetCode(to)
	if len(code) == 0 {
		if !t.precompileSet[to] {
			t.fail("%s targets nonexistent account %s", op, to)
		}
		return
	}
	if _, delegated := types.ParseDelegation(code); delegated {
		t.fail("%s targets EIP-7702 delegated address %s", op, to)
	}
}

// Hooks returns the tracing.Hooks the simulator installs on the EVM.
func (t *frameValidationTracer) Hooks() *tracing.Hooks {
	return &tracing.Hooks{
		OnOpcode:        t.OnOpcode,
		OnEnter:         t.OnEnter,
		OnStorageChange: t.OnStorageChange,
		OnCodeChange:    t.OnCodeChange,
	}
}

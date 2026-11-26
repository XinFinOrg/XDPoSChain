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

// EIP-5920 (PAY opcode): value transfer to a 20-byte address without
// executing recipient code, activated in the Bogotá instruction set.
//
// Spec: https://eips.ethereum.org/EIPS/eip-5920
//
// Design notes (see hegota-research-20261107/EIP5920_DESIGN_NOTE.md):
//   - Metering uses the EIP-5920 canonical constants as regular gas
//     (EIP-2929 warm constant + cold delta, EELS GAS_CALL_VALUE,
//     GAS_NEW_ACCOUNT); it does not route through the EIP-8037 state-gas
//     split, matching the pinned spec's cost table.
//   - Account "existence" for the GAS_NEW_ACCOUNT branch uses EIP-161
//     emptiness (StateDB.Empty), per the rationale documented in
//     stateGasCall8037: EIP-161-empty accounts appearing transiently must
//     still be charged when funded.
//   - Under Amsterdam, a non-zero PAY to a different address emits an
//     EIP-7708-style EthTransferLog, mirroring opSelfdestruct6780.
//   - Precondition: the chain has no empty accounts (EIP-7523), which the
//     XDC presets satisfy via EIP-158/161.

package vm

import (
	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/tracing"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/holiman/uint256"
)

// gasPay prices PAY (EIP-5920). The warm cost is charged as constantGas;
// here we charge only the cold delta over it, plus the value-transfer and
// new-account components. As a side effect the address is added to the
// access list (rolled back by the interpreter if execution aborts).
func gasPay(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (GasCosts, error) {
	var gas uint64
	addr := common.Address(stack.back(0).Bytes20())
	if !evm.StateDB.AddressInAccessList(addr) {
		// If the caller cannot afford the cost, this change will be rolled back.
		evm.StateDB.AddAddressToAccessList(addr)
		gas = params.ColdAccountAccessCostEIP2929 - params.WarmStorageReadCostEIP2929
	}
	if val := stack.back(1); !val.IsZero() {
		gas += params.CallValueTransferGas
		// Exist check per EIP-161 (nonce, balance, code all zero means the
		// account does not exist for charging purposes). See stateGasCall8037.
		if evm.StateDB.Empty(addr) {
			gas += params.CallNewAccountGas
		}
	}
	return GasCosts{RegularGas: gas}, nil
}

// opPay implements PAY (EIP-5920): pops addr (top) and val, transfers val
// wei to addr without executing recipient code, and pushes 1 on success or
// 0 on insufficient balance. It halts exceptionally in static frames
// (EIP-214) and when addr has any of the high 12 bytes set.
func opPay(pc *uint64, evm *EVM, scope *ScopeContext) ([]byte, error) {
	if evm.readOnly {
		return nil, ErrWriteProtection
	}
	addr, val := scope.Stack.pop2()
	if addr.BitLen() > 160 {
		return nil, ErrPayInvalidAddress
	}
	beneficiary := common.Address(addr.Bytes20())
	this := scope.Contract.Address()

	if evm.StateDB.GetBalance(this).Lt(val) {
		// Insufficient balance: push 0, do not revert the frame.
		zero := uint256.NewInt(0)
		scope.Stack.push(zero)
		return nil, nil
	}
	if this != beneficiary {
		evm.StateDB.SubBalance(this, val, tracing.BalanceChangeTransfer)
		evm.StateDB.AddBalance(beneficiary, val, tracing.BalanceChangeTransfer)
		// EIP-7708: emit a transfer log for the moved balance, mirroring
		// the Amsterdam SELFDESTRUCT convention.
		if evm.chainRules.IsAmsterdam && !val.IsZero() {
			evm.StateDB.AddLog(types.EthTransferLog(this, beneficiary, val))
		}
	}
	one := uint256.NewInt(1)
	scope.Stack.push(one)
	return nil, nil
}

// enable5920 enables EIP-5920 (PAY opcode) on the given jump table.
func enable5920(jt *JumpTable) {
	jt[PAY] = &operation{
		execute:     opPay,
		constantGas: params.WarmStorageReadCostEIP2929,
		dynamicGas:  gasPay,
		minStack:    minStack(2, 1),
		maxStack:    maxStack(2, 1),
	}
}

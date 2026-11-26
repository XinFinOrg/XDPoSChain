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
	"math"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// EIP-8279 implements a runtime byte-access-list (BAL) meter that augments
// the Bogotá EIP-8131 transaction content floor:
//
//	floor = tx_floor + 64 × (51×authorizations + runtimeMeteredBytes)
//
// where tx_floor is the static EIP-8131 unified content floor. The runtime
// meter accumulates BAL bytes triggered by execution — account touches
// (BALANCE, EXTCODESIZE, CALL-family addresses), storage keys and value
// departures (SLOAD/SSTORE), value-transfer balance pairs (nonzero-value
// CALL, endowment-bearing CREATE/CREATE2, nonzero-balance SELFDESTRUCT),
// account nonces (CREATE/CREATE2) and deployed code (CREATE/CREATE2) —
// charging each distinct item at most once per transaction where the BAL
// semantics require deduplication. The execution-gas budget is
// min(tx.gas, params.MaxTxGas): whenever the running floor would exceed the
// budget, execution halts with ErrOutOfGas before the offending BAL
// insertion is retained. Reverted frames do not roll back metering already
// (meter is carried by the EVM, not journaled in StateDB).

// balStorageSlot identifies a (account, key) pair in the meter's first-touch
// sets.
type balStorageSlot struct {
	addr common.Address
	key  common.Hash
}

// BALMeter is the EIP-8279 per-transaction runtime meter. A nil *BALMeter on
// the EVM means metering is inactive (pre-Bogotá activation, system calls and
// EIP-8141 frame transactions).
type BALMeter struct {
	floor  uint64 // static EIP-8131 floor including the 51 B/auth seed term (gas)
	budget uint64 // execution-gas budget: min(tx.gas, params.MaxTxGas)
	bytes  uint64 // cumulative metered BAL bytes

	accounts map[common.Address]struct{} // account first-touch set (20 B each)
	slots    map[balStorageSlot]struct{} // storage key first-touch set (32 B each)
	values   map[balStorageSlot]struct{} // slots whose value bytes were metered (32 B, once per slot)
}

// NewBALMeter creates a meter anchored at the static EIP-8131 floor (which
// already includes the 51 B/authorization seed term) for a transaction with
// the given gas limit.
func NewBALMeter(floor, txGasLimit uint64) *BALMeter {
	budget := txGasLimit
	if budget > params.MaxTxGas {
		budget = params.MaxTxGas
	}
	return &BALMeter{
		floor:    floor,
		budget:   budget,
		accounts: make(map[common.Address]struct{}),
		slots:    make(map[balStorageSlot]struct{}),
		values:   make(map[balStorageSlot]struct{}),
	}
}

// add meters n BAL bytes, enforcing the execution-gas budget. It returns
// false — and retains nothing — when the running floor would exceed
// min(tx.gas, 2^24). The comparison floor + 64×nb > budget is evaluated as
// nb > (budget-floor)/64, which is exact in integer arithmetic and cannot
// overflow.
func (m *BALMeter) add(n uint64) bool {
	if n == 0 {
		return true
	}
	if m.bytes > math.MaxUint64-n {
		return false
	}
	nb := m.bytes + n
	if m.floor >= m.budget {
		return false
	}
	if nb > (m.budget-m.floor)/64 {
		return false
	}
	m.bytes = nb
	return true
}

// AddAccount meters a first-touch account address (20 B). Repeat touches of
// the same address within the transaction are free.
func (m *BALMeter) AddAccount(addr common.Address) bool {
	if _, ok := m.accounts[addr]; ok {
		return true
	}
	if !m.add(common.AddressLength) {
		return false
	}
	m.accounts[addr] = struct{}{}
	return true
}

// AddStorageKey meters a first-touch storage key (32 B) of the given account.
func (m *BALMeter) AddStorageKey(addr common.Address, key common.Hash) bool {
	s := balStorageSlot{addr, key}
	if _, ok := m.slots[s]; ok {
		return true
	}
	if !m.add(common.HashLength) {
		return false
	}
	m.slots[s] = struct{}{}
	return true
}

// AddStorageValue meters the 32 B value contribution of a slot when its value
// departs from the original (i.e. the BAL records a value change). Per the
// pinned draft, value bytes are charged at most once per slot: net-zero
// round trips (restore-to-original) refund neither execution gas nor
// metering, and a later second departure of the same slot is deduplicated.
func (m *BALMeter) AddStorageValue(addr common.Address, key common.Hash) bool {
	s := balStorageSlot{addr, key}
	if _, ok := m.values[s]; ok {
		return true
	}
	if !m.add(common.HashLength) {
		return false
	}
	m.values[s] = struct{}{}
	return true
}

// AddBalancePair meters the sender+recipient balance changes (2×32 B) of a
// value transfer. Unlike account touches, balance changes are metered per
// event: every distinct value transfer contributes its own pair.
func (m *BALMeter) AddBalancePair() bool {
	return m.add(2 * common.HashLength)
}

// AddNonce meters an account nonce addition (8 B), used by CREATE/CREATE2
// for both the creator and the new contract nonces.
func (m *BALMeter) AddNonce() bool {
	return m.add(8)
}

// AddCode meters n deployed-code bytes (used by successful CREATE/CREATE2).
func (m *BALMeter) AddCode(n uint64) bool {
	return m.add(n)
}

// RuntimeFloor returns the full EIP-8279 floor: the static floor plus 64 gas
// per metered runtime byte. The result saturates at math.MaxUint64 instead
// of wrapping.
func (m *BALMeter) RuntimeFloor() uint64 {
	if m.bytes > (math.MaxUint64-m.floor)/64 {
		return math.MaxUint64
	}
	return m.floor + m.bytes*64
}

// The meterX helpers below are the nil-safe wiring used by the opcode
// handlers: when the EVM carries no meter (pre-Bogotá, system call, frame
// transaction) they are silent no-ops returning success.

func (evm *EVM) meterAccount(addr common.Address) bool {
	return evm.meter == nil || evm.meter.AddAccount(addr)
}

func (evm *EVM) meterStorageKey(addr common.Address, key common.Hash) bool {
	return evm.meter == nil || evm.meter.AddStorageKey(addr, key)
}

func (evm *EVM) meterStorageValue(addr common.Address, key common.Hash) bool {
	return evm.meter == nil || evm.meter.AddStorageValue(addr, key)
}

func (evm *EVM) meterBalancePair() bool {
	return evm.meter == nil || evm.meter.AddBalancePair()
}

func (evm *EVM) meterNonce() bool {
	return evm.meter == nil || evm.meter.AddNonce()
}

func (evm *EVM) meterCode(n uint64) bool {
	return evm.meter == nil || evm.meter.AddCode(n)
}

// SetBALMeter installs (or clears, with nil) the EIP-8279 runtime meter on
// the EVM. Called once per user transaction from state transition when the
// Bogotá rules are active; the meter must not be installed on the EIP-8141
// frame path or for system calls.
func (evm *EVM) SetBALMeter(m *BALMeter) {
	evm.meter = m
}

// BALMeter returns the EIP-8279 runtime meter carried by this EVM, or nil
// when metering is inactive. Used by the state transition for end-of-tx
// settlement.
func (evm *EVM) BALMeter() *BALMeter {
	return evm.meter
}

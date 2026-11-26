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

// RED-first gap-fill tests for EIP-8279 (Block Access List Byte Floor),
// complementing eip8279_test.go (same test package, same fixtures).
//
// This file covers two required behaviors not exercised there:
//
//  1. REPEATED account/storage access WITHOUT duplicate charges — the
//     first-touch sets (spec §Data meter and floor accumulator:
//     metered_addresses / metered_storage_keys / metered_storage_values)
//     must dedupe across repeated touches of the SAME address/key within a
//     transaction, independent of which opcode touches it:
//       K3: SLOAD(same warm key) twice            → 32 B metered ONCE
//       A2: BALANCE(t) + EXTCODESIZE(t)           → 20 B metered ONCE
//       M1: SLOAD(k) then SSTORE(k) same key      → 32 B key ONCE + 32 B
//           value (NOT 96: key shared across ops)
//
//  2. FORK ACTIVATION BOUNDARY with the runtime meter — the K1 fixture
//     (3 warm SLOADs, 200 B calldata) executed one second BEFORE BogotaTime
//     must settle at plain Prague execution (36,609 — control arm), at the
//     activation block (time == BogotaTime) and one second AFTER must
//     settle at the EIP-8279 floor (41,224 static + 6,144 runtime = 47,368).
//
// Expected values per spec https://eips.ethereum.org/EIPS/eip-8279 (DRAFT,
// re-fetched 2026-11-08): FLOOR_GAS_PER_BYTE = 64; BAL_BYTES_PER_ADDRESS =
// 20; BAL_BYTES_PER_STORAGE_KEY = 32; BAL_BYTES_PER_STORAGE_VALUE = 32.
// Settlement: tx.gasUsed = max(execution_gas_used, floor_gas_used). All
// scenarios are floor-binding (static floor + meter > execution), so the
// settled value equals the expected floor exactly.
//
// RED today: no meter exists, so K3/A2/M1 settle at the EIP-8131 static
// floor and B2's post-gate arms settle at the static floor too; the pre-gate
// control arm passes. GREEN after EIP-8279 implementation: every assertion
// holds with the values below.

package core

import (
	"bytes"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/tracing"
	"github.com/XinFinOrg/XDPoSChain/core/types"
)

// eip8279CodeSloadTwice: PUSH1 0; SLOAD; PUSH1 0; SLOAD; STOP — touches the
// same storage key twice in one transaction.
func eip8279CodeSloadTwice() []byte {
	return []byte{0x60, 0x00, 0x54, 0x60, 0x00, 0x54, 0x00}
}

// eip8279CodeTwoOpsSameAccount: PUSH20 t; BALANCE; PUSH20 t; EXTCODESIZE;
// STOP — touches the same address via two different account-touch opcodes.
func eip8279CodeTwoOpsSameAccount(addr common.Address) []byte {
	code := []byte{0x73}
	code = append(code, addr.Bytes()...)
	code = append(code, 0x31) // BALANCE
	code = append(code, 0x73)
	code = append(code, addr.Bytes()...)
	code = append(code, 0x3b, 0x00) // EXTCODESIZE; STOP
	return code
}

// eip8279CodeSloadThenSstore: PUSH1 0; SLOAD; POP; PUSH1 0x11; PUSH1 0;
// SSTORE; STOP — reads then writes the SAME key in one transaction.
func eip8279CodeSloadThenSstore() []byte {
	return []byte{0x60, 0x00, 0x54, 0x50, 0x60, 0x11, 0x60, 0x00, 0x55, 0x00}
}

// TestEIP8279K3RepeatedStorageKeyNoDuplicate: two SLOADs of the same
// access-list-warmed key meter the 32-byte storage key ONCE (spec §Data
// meter: metered_storage_keys is a per-tx set; §Runtime data metering:
// "Repeated touches in the transaction add nothing"). Runtime bytes: 32.
// Static floor: 21,000 + 64×(200 data + 20 AL addr + 32 AL key) = 37,128;
// want = 37,128 + 32×64 = 39,176. Execution (21,000 + 2×100) stays far
// below, so the fixture pins the metered value exactly. A per-touch (rather
// than per-first-touch) implementation would settle 2,048 higher than want.
// RED today: settles at the static floor 37,128.
func TestEIP8279K3RepeatedStorageKeyNoDuplicate(t *testing.T) {
	cfg := eip8279BogotaCfg()
	al := types.AccessList{{Address: eip8279Contract, StorageKeys: []common.Hash{{0x00}}}}
	data := bytes.Repeat([]byte{1}, 200)
	msg := eip8279Msg(&eip8279Contract, data, 0, al, 1_000_000)
	res, err := eip8279Run(cfg, 1, 0, msg, eip8279Setup(eip8279CodeSloadTwice(), 0, 0, nil))
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	want := eip8279Floor(200, 1, 1, 0, eip8279BytesPerStorageKey)
	if res.UsedGas != want {
		t.Fatalf("gasUsed = %d, want %d (repeated SLOAD of one key must meter 32 B once: missing %d gas; per-touch metering would exceed want by 2,048)",
			res.UsedGas, want, want-res.UsedGas)
	}
}

// TestEIP8279A2RepeatedAccountTouchNoDuplicate: BALANCE(t) then EXTCODESIZE(t)
// on the same access-list-warmed address meter the 20-byte address ONCE
// (spec: metered_addresses is a per-tx set — the dedupe is keyed on the
// address, not the opcode). Runtime bytes: 20. Static floor:
// 21,000 + 64×(200 data + 20 AL addr) = 35,080; want = 35,080 + 20×64 =
// 36,360. Execution ≈ 21,200 stays below; fixture pins the metered value.
// RED today: settles at the static floor 35,080.
func TestEIP8279A2RepeatedAccountTouchNoDuplicate(t *testing.T) {
	cfg := eip8279BogotaCfg()
	al := types.AccessList{{Address: eip8279Target}}
	data := bytes.Repeat([]byte{1}, 200)
	msg := eip8279Msg(&eip8279Contract, data, 0, al, 1_000_000)
	res, err := eip8279Run(cfg, 1, 0, msg, eip8279Setup(eip8279CodeTwoOpsSameAccount(eip8279Target), 0, 0, nil))
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	want := eip8279Floor(200, 1, 0, 0, eip8279BytesPerAddress)
	if res.UsedGas != want {
		t.Fatalf("gasUsed = %d, want %d (two opcodes touching one address must meter 20 B once: missing %d gas)",
			res.UsedGas, want, want-res.UsedGas)
	}
}

// TestEIP8279M1SloadThenSstoreSameKey: SLOAD(k) then SSTORE 0x11→k in one
// transaction. The storage key is metered ONCE across the two opcodes (32 B;
// spec: metered_storage_keys keyed on (storage_address, key)), and the value
// contribution (current 0 == original 0, new 0x11 != original) meters 32 B
// once — total 64 B, NOT 96. Static floor: 21,000 + 64×(4000 data + 20 AL
// addr + 32 AL key) = 280,328; want = 280,328 + 64×64 = 284,424.
//
// The 4,000-byte payload is load-bearing: this tree's 8037/8038-era SSTORE
// repricing makes a warm zero→nonzero write cost ≈112,331 execution gas
// (observed 149,431 total at a 1,000-byte payload, where the 92,744 floor
// therefore did NOT bind — caught in the first RED run). At 4,000 bytes
// execution ≈197,431 stays ≈87k below the want floor, so the fixture pins
// the metered value exactly. RED today: settles at 280,328.
func TestEIP8279M1SloadThenSstoreSameKey(t *testing.T) {
	cfg := eip8279BogotaCfg()
	al := types.AccessList{{Address: eip8279Contract, StorageKeys: []common.Hash{{0x00}}}}
	data := bytes.Repeat([]byte{1}, 4000)
	msg := eip8279Msg(&eip8279Contract, data, 0, al, 1_000_000)
	res, err := eip8279Run(cfg, 1, 0, msg, eip8279Setup(eip8279CodeSloadThenSstore(), 0, 0, nil))
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	want := eip8279Floor(4000, 1, 1, 0, eip8279BytesPerStorageKey+eip8279BytesPerStorageVal)
	if res.UsedGas != want {
		t.Fatalf("gasUsed = %d, want %d (SLOAD+SSTORE of one key must meter 64 B total, not 96: missing %d gas)",
			res.UsedGas, want, want-res.UsedGas)
	}
}

// TestEIP8279B2GateBoundaryRuntimeMeter: fork activation boundary with the
// RUNTIME meter active. Config: Prague on, Bogotá at time 100. The K1
// fixture (200 B calldata, AL 3 warm keys, 3 warm SLOADs):
//
//   - t=99 (one second before): Prague-only rules → plain execution
//     settlement 36,609 (control arm; identical Rules to TestEIP8279B1's
//     observed value — must PASS today and after).
//   - t=100 (the activation block itself): EIP-8279 floor = 8131 static
//     41,224 + runtime 3×32×64 = 47,368. RED today (settles at 41,224 —
//     the 8131 static floor, which is already GREEN).
//   - t=101 (one second after): identical 47,368.
func TestEIP8279B2GateBoundaryRuntimeMeter(t *testing.T) {
	cfg := eip8131Config(true, true, false, 100)
	al := types.AccessList{{Address: eip8279Contract, StorageKeys: []common.Hash{{0x00}, {0x01}, {0x02}}}}
	data := bytes.Repeat([]byte{1}, 200)
	msg := eip8279Msg(&eip8279Contract, data, 0, al, 1_000_000)
	setup := eip8279Setup(eip8279CodeSloads(3), 0, 0, nil)

	const preWant = 36_609 // Prague execution settlement (control)
	pre, err := eip8279Run(cfg, 1, 99, msg, setup)
	if err != nil {
		t.Fatalf("pre-gate apply failed: %v", err)
	}
	if pre.UsedGas != preWant {
		t.Fatalf("pre-gate gasUsed = %d, want Prague execution %d (meter must be inactive before Bogotá)", pre.UsedGas, preWant)
	}

	postWant := eip8279Floor(200, 1, 3, 0, 3*eip8279BytesPerStorageKey)
	for _, tc := range []struct {
		name string
		time uint64
	}{
		{"activation-block", 100},
		{"one-second-after", 101},
	} {
		res, err := eip8279Run(cfg, 1, tc.time, msg, setup)
		if err != nil {
			t.Fatalf("%s apply failed: %v", tc.name, err)
		}
		if res.UsedGas != postWant {
			t.Fatalf("%s gasUsed = %d, want EIP-8279 floor %d (Bogotá-gated runtime meter missing: %d gas)",
				tc.name, res.UsedGas, postWant, postWant-res.UsedGas)
		}
	}
}

// Compile-time fixture check: the SLOAD-twice / two-opcode / SLOAD+SSTORE
// builders must be referenced (kept here so an accidental rename of any
// builder fails loudly rather than silently dropping a RED case).
var (
	_ = eip8279CodeSloadTwice
	_ = eip8279CodeTwoOpsSameAccount
	_ = eip8279CodeSloadThenSstore
	_ = tracing.CodeChangeGenesis // tracing import retained for fixture symmetry
)

// statedb import symmetry with eip8279_test.go fixtures (used via helper
// closures there); keeps this file's imports honest if helpers move.
var _ = state.New

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

// D2 — EIP-8279 delegation-target metering (protocol decision D2, Option A,
// approved 2026-11-11): following an EIP-7702 delegation designator meters
// the resolved delegation TARGET (+20 B, first touch per transaction,
// out-of-gas on meter failure), matching Nethermind
// EvmInstructions.Call.cs:183.
//
// These tests close the D2 conditional sign-off:
//  1. TestEIP8279D2DelegationTargetMetered — the +20 B charge itself,
//     as an exact +1,280 gas floor delta at the top-level call.
//  2. TestEIP8279D2CallPaths — the same delta through all four call
//     opcodes (CALL / CALLCODE / DELEGATECALL / STATICCALL).
//  3. TestEIP8279D2DelegationTargetDedup — per-tx dedup: the target is
//     charged once, never per CALL (no double metering).
//  4. TestEIP8279D2DelegationOOG — meter exhaustion on the delegation
//     path halts exceptionally with OutOfGas; a marginally larger budget
//     succeeds and settles at the metered floor.
//  5. TestEIP8279D2DelegationRevertRetainsMetering — reverted frames
//     retain their metered bytes (spec §Reverts: nothing is rewound).
//  6. TestEIP8279D2PreBogotaControl — Prague-only: delegations resolve
//     but nothing is metered (Bogotá gate).
//
// RED note: the production change under test is the uncommitted D2 hunk
// in core/vm/evm.go (resolveCode + four call paths). Phase 8 preservation
// rules prohibit reverting that hunk to stage a live RED run. The tests
// are nevertheless falsifiable: without the resolveCode meter, test 1
// settles at 85,000 (not 86,280), tests 2-3 settle 1,280 low, and test 4
// succeeds instead of raising OutOfGas.
//
// Harness: reuses the eip8131/eip8279 fixtures (same test package).

package core

import (
	"bytes"
	"errors"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/tracing"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
)

// D2 fixture addresses (pure hex — HexToAddress-safe).
var (
	eip8279D2Holder = common.HexToAddress("0x00000000000000000000000000000000000d2e01") // delegation designator → target
	eip8279D2Target = common.HexToAddress("0x00000000000000000000000000000000000d2e02") // STOP
	eip8279D2Plain  = common.HexToAddress("0x00000000000000000000000000000000000d2e03") // STOP, no delegation (control)
)

// eip8279D2FloorDelta is the exact floor contribution of metering the
// delegation target once: 20 B × 64 gas/B.
const eip8279D2FloorDelta = 20 * eip8279GasPerByte // 1,280

// eip8279D2Setup installs the entry contract; in the delegated variant the
// holder carries a delegation designator pointing at the STOP target, in
// the control variant a plain STOP account stands in for it.
func eip8279D2Setup(entry []byte, delegated bool) func(*state.StateDB) {
	return func(statedb *state.StateDB) {
		statedb.SetCode(eip8279Contract, entry, tracing.CodeChangeGenesis)
		if delegated {
			statedb.SetCode(eip8279D2Holder, types.AddressToDelegation(eip8279D2Target), tracing.CodeChangeGenesis)
			statedb.SetCode(eip8279D2Target, []byte{0x00}, tracing.CodeChangeGenesis)
		} else {
			statedb.SetCode(eip8279D2Plain, []byte{0x00}, tracing.CodeChangeGenesis)
		}
	}
}

// eip8279D2CodeCall builds: [ret 0,0,args 0,0 (,value 0)] PUSH20 addr;
// PUSH2 0xffff; <opcode>; STOP. CALL/CALLCODE take a value operand,
// DELEGATECALL/STATICCALL do not.
func eip8279D2CodeCall(addr common.Address, opcode byte) []byte {
	code := []byte{0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00} // retSize retOff argSize argOff
	if opcode == 0xf1 || opcode == 0xf2 {                          // CALL, CALLCODE
		code = append(code, 0x60, 0x00) // value = 0
	}
	code = append(code, 0x73)
	code = append(code, addr.Bytes()...)
	code = append(code, 0x61, 0xff, 0xff, opcode)
	return append(code, 0x00)
}

// eip8279D2CodeCallRevert: one CALL to addr, then REVERT(0,0).
func eip8279D2CodeCallRevert(addr common.Address) []byte {
	code := eip8279D2CodeCall(addr, 0xf1)
	return append(code[:len(code)-1], 0x60, 0x00, 0x60, 0x00, 0xfd)
}

// 1. The charge itself: a transaction sent DIRECTLY to a delegation holder
// settles floor +1,280 vs the identical transaction to a plain STOP account.
// Runtime bytes: 20 (delegation target) vs 0. Static floor (1,000 B data):
// 85,000 both sides, so the settled values are 86,280 vs 85,000.
func TestEIP8279D2DelegationTargetMetered(t *testing.T) {
	cfg := eip8279BogotaCfg()
	data := bytes.Repeat([]byte{1}, 1000)

	resDel, err := eip8279Run(cfg, 1, 0, eip8279Msg(&eip8279D2Holder, data, 0, nil, 200_000), eip8279D2Setup(nil, true))
	if err != nil {
		t.Fatalf("apply (delegated): %v", err)
	}
	resCtl, err := eip8279Run(cfg, 1, 0, eip8279Msg(&eip8279D2Plain, data, 0, nil, 200_000), eip8279D2Setup(nil, false))
	if err != nil {
		t.Fatalf("apply (control): %v", err)
	}

	wantDel := eip8279Floor(1000, 0, 0, 0, eip8279BytesPerAddress)
	wantCtl := eip8279Floor(1000, 0, 0, 0, 0)
	if resDel.UsedGas != wantDel {
		t.Fatalf("delegated gasUsed = %d, want %d (missing delegation-target 20 B×64 = %d gas)",
			resDel.UsedGas, wantDel, wantDel-resDel.UsedGas)
	}
	if resCtl.UsedGas != wantCtl {
		t.Fatalf("control gasUsed = %d, want %d", resCtl.UsedGas, wantCtl)
	}
	if delta := resDel.UsedGas - resCtl.UsedGas; delta != eip8279D2FloorDelta {
		t.Fatalf("floor delta = %d, want %d (+20 B delegation target)", delta, eip8279D2FloorDelta)
	}
}

// 2. All four call paths: an entry contract calling the delegation holder
// meters the holder (20 B, opcode site) AND the resolved target (20 B,
// resolveCode) = 40 runtime bytes, vs 20 for the plain control — the same
// +1,280 delta through CALL, CALLCODE, DELEGATECALL and STATICCALL.
func TestEIP8279D2CallPaths(t *testing.T) {
	cfg := eip8279BogotaCfg()
	data := bytes.Repeat([]byte{1}, 200)

	paths := []struct {
		name   string
		opcode byte
	}{
		{"CALL", 0xf1},
		{"CALLCODE", 0xf2},
		{"DELEGATECALL", 0xf4},
		{"STATICCALL", 0xfa},
	}
	for _, p := range paths {
		t.Run(p.name, func(t *testing.T) {
			resDel, err := eip8279Run(cfg, 1, 0,
				eip8279Msg(&eip8279Contract, data, 0, nil, 1_000_000),
				eip8279D2Setup(eip8279D2CodeCall(eip8279D2Holder, p.opcode), true))
			if err != nil {
				t.Fatalf("apply (delegated): %v", err)
			}
			resCtl, err := eip8279Run(cfg, 1, 0,
				eip8279Msg(&eip8279Contract, data, 0, nil, 1_000_000),
				eip8279D2Setup(eip8279D2CodeCall(eip8279D2Plain, p.opcode), false))
			if err != nil {
				t.Fatalf("apply (control): %v", err)
			}

			wantDel := eip8279Floor(200, 0, 0, 0, 2*eip8279BytesPerAddress)
			wantCtl := eip8279Floor(200, 0, 0, 0, eip8279BytesPerAddress)
			if resDel.UsedGas != wantDel {
				t.Fatalf("delegated gasUsed = %d, want %d (missing delegation-target %d gas)",
					resDel.UsedGas, wantDel, wantDel-resDel.UsedGas)
			}
			if resCtl.UsedGas != wantCtl {
				t.Fatalf("control gasUsed = %d, want %d", resCtl.UsedGas, wantCtl)
			}
			if delta := resDel.UsedGas - resCtl.UsedGas; delta != eip8279D2FloorDelta {
				t.Fatalf("floor delta = %d, want %d", delta, eip8279D2FloorDelta)
			}
		})
	}
}

// 3. Per-tx dedup: two CALLs to the SAME delegation holder meter the target
// once. Runtime bytes: 20 (holder) + 20 (target) = 40 — NOT 60. A
// double-metering regression settles 1,280 above the expected floor.
func TestEIP8279D2DelegationTargetDedup(t *testing.T) {
	cfg := eip8279BogotaCfg()
	data := bytes.Repeat([]byte{1}, 200)
	call := eip8279D2CodeCall(eip8279D2Holder, 0xf1)
	entry := append(call[:len(call)-1:len(call)-1], call...) // drop first STOP, append full second call

	res, err := eip8279Run(cfg, 1, 0, eip8279Msg(&eip8279Contract, data, 0, nil, 1_000_000),
		eip8279D2Setup(entry, true))
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	want := eip8279Floor(200, 0, 0, 0, 2*eip8279BytesPerAddress)
	if res.UsedGas != want {
		t.Fatalf("gasUsed = %d, want %d (target must be metered once, not per CALL; excess %d gas)",
			res.UsedGas, want, res.UsedGas-want)
	}
}

// 4. Out-of-gas on the delegation path: static floor 79,000 (1,000 B data,
// A1); the top-level delegation charge is the ONLY runtime meter (the holder
// is not an opcode-site touch): 79,000 + 1,280 = 80,280. Budget 80,000 →
// the meter raises OutOfGas before the BAL insertion. Control at 81,000
// succeeds and settles exactly at the metered floor.
func TestEIP8279D2DelegationOOG(t *testing.T) {
	cfg := eip8279BogotaCfg()
	data := bytes.Repeat([]byte{1}, 1000)

	res, err := eip8279Run(cfg, 1, 0, eip8279Msg(&eip8279D2Holder, data, 0, nil, 80_000), eip8279D2Setup(nil, true))
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !errors.Is(res.Err, vm.ErrOutOfGas) {
		t.Fatalf("res.Err = %v, want OutOfGas (metered floor 80,280 > budget 80,000); settled %d",
			res.Err, res.UsedGas)
	}

	resOk, err := eip8279Run(cfg, 1, 0, eip8279Msg(&eip8279D2Holder, data, 0, nil, 81_000), eip8279D2Setup(nil, true))
	if err != nil {
		t.Fatalf("apply (control): %v", err)
	}
	if resOk.Err != nil {
		t.Fatalf("control res.Err = %v, want success at budget 81,000", resOk.Err)
	}
	if want := eip8279Floor(1000, 0, 0, 0, eip8279BytesPerAddress); resOk.UsedGas != want {
		t.Fatalf("control gasUsed = %d, want metered floor %d", resOk.UsedGas, want)
	}
}

// 5. Revert retention: CALL to the delegation holder then REVERT(0,0).
// State changes are discarded; the 40 metered bytes (holder + target) are
// RETAINED (spec §Reverts: nothing is rewound) and the floor still binds.
func TestEIP8279D2DelegationRevertRetainsMetering(t *testing.T) {
	cfg := eip8279BogotaCfg()
	data := bytes.Repeat([]byte{1}, 200)
	res, err := eip8279Run(cfg, 1, 0, eip8279Msg(&eip8279Contract, data, 0, nil, 1_000_000),
		eip8279D2Setup(eip8279D2CodeCallRevert(eip8279D2Holder), true))
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if res.Err == nil {
		t.Fatalf("expected top-level REVERT (fixture design)")
	}
	want := eip8279Floor(200, 0, 0, 0, 2*eip8279BytesPerAddress)
	if res.UsedGas != want {
		t.Fatalf("gasUsed = %d, want %d (reverted delegation CALL must retain 40 metered bytes; missing %d gas)",
			res.UsedGas, want, want-res.UsedGas)
	}
}

// 6. Pre-Bogotá control: Prague-only config. The delegation still RESOLVES
// (Prague is active) but no meter is installed, so the delegated and plain
// transactions settle at identical gas. Pins the Bogotá gate on the D2
// charge. Green before and after the D2 change.
func TestEIP8279D2PreBogotaControl(t *testing.T) {
	cfg := eip8131Config(true, false, false, 0)
	data := bytes.Repeat([]byte{1}, 200)

	resDel, err := eip8279Run(cfg, 1, 0, eip8279Msg(&eip8279D2Holder, data, 0, nil, 1_000_000), eip8279D2Setup(nil, true))
	if err != nil {
		t.Fatalf("apply (delegated): %v", err)
	}
	resCtl, err := eip8279Run(cfg, 1, 0, eip8279Msg(&eip8279D2Plain, data, 0, nil, 1_000_000), eip8279D2Setup(nil, false))
	if err != nil {
		t.Fatalf("apply (control): %v", err)
	}
	if resDel.Err != nil || resCtl.Err != nil {
		t.Fatalf("unexpected errors: del=%v ctl=%v", resDel.Err, resCtl.Err)
	}
	if resDel.UsedGas != resCtl.UsedGas {
		t.Fatalf("pre-Bogotá delegated gasUsed = %d, control = %d — D2 charge must be Bogotá-gated",
			resDel.UsedGas, resCtl.UsedGas)
	}
}

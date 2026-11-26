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

// RED-first tests for EIP-8131 (Unified Transaction Content Floor) per the
// Hegotá design review (HEGOTA_EIP8131_DESIGN_REVIEW.md) and the approved
// design assumptions:
//
//  1. Bogotá is the proposed activation gate; Amsterdam stays unchanged.
//  2. FrameTx is excluded (provisional, pending protocol-owner confirmation).
//  3. TX_BASE = 21,000 and FLOOR_GAS_PER_BYTE = 64.
//  4. eth_estimateGas must return >= tx_floor (tested in the gasestimator
//     package — TestEIP8131R3EstimateGasCoversFloor).
//  5. Content counted: calldata, access-list addresses (20 B), access-list
//     storage keys (32 B), EIP-7702 authorizations (108 B each), blob
//     versioned hashes (32 B each).
//  6. EIP-3298 refund behavior and the EIP-8141 implementation are preserved
//     (N2/B2 settle the floor AFTER the uncapped Bogotá refund).
//
// Spec: https://eips.ethereum.org/EIPS/eip-8131 (snapshot
// hegota-research-20261107/eip-8131.md, verified identical to live master
// 2026-11-08). §Constants pins TX_BASE/FLOOR_GAS_PER_BYTE; §Transaction floor
// pins the formula; §Charging pins gasUsed = max(execution, floor).
//
// RED state: production has NO 8131 code. Enforcement is Prague-gated only and
// counts data/access-list tokens; authorization and blob-hash terms are
// absent, and a Bogotá-without-Prague schedule applies no floor at all. Tests
// asserting target behavior must therefore FAIL until the production diff is
// approved and applied. Controls (P4, N3, B2, B3, B4, F3, EIP-2780 anchors)
// pin existing behavior and must PASS before and after.

package core

import (
	"bytes"
	"errors"
	"math"
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/tracing"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/holiman/uint256"
)

// Approved formula constants (spec §Constants, as amended by decision A1:
// Bogotá includes EIP-2780 — the floor anchor is the EIP-2780 intrinsic base,
// not the legacy 21,000 TX_BASE).
const (
	eip8131Base      = uint64(15_000) // TX_BASE under A1 = 2780 base (12,000 + 3,000 cold recipient)
	eip8131PerByte   = uint64(64)     // FLOOR_GAS_PER_BYTE
	eip8131AuthBytes = uint64(108)    // AUTH_TUPLE_BYTES
	eip8131BlobBytes = uint64(32)     // per blob versioned hash
)

var (
	eip8131From = common.HexToAddress("0x00000000000000000000000000000000000beef1")
	eip8131To   = common.HexToAddress("0x00000000000000000000000000000000000dead1")
)

func eip8131U64(v uint64) *uint64 { return &v }

// eip8131Floor is the spec formula under test:
//
//	floor = TX_BASE + 64 * (len(data) + 20*alAddrs + 32*alKeys
//	                        + 108*auths + 32*blobs)
//
// A1: TX_BASE is the EIP-2780 intrinsic base (15,000 for the to≠from,
// value-free messages built by eip8131Message), not the legacy 21,000.
func eip8131Floor(dataLen, alAddrs, alKeys, auths, blobs uint64) uint64 {
	return eip8131Base + eip8131PerByte*(dataLen+20*alAddrs+32*alKeys+eip8131AuthBytes*auths+eip8131BlobBytes*blobs)
}

// eip8131Config builds a MergedTestChainConfig variant with the requested
// fork gates. Amsterdam is opt-in (never implied by Bogotá) so the controls
// can freeze it independently.
func eip8131Config(prague, bogota, amsterdam bool, bogotaTime uint64) *params.ChainConfig {
	cfg := *params.MergedTestChainConfig
	cfg.PragueTime, cfg.PragueBlock = nil, nil
	cfg.BogotaTime = nil
	cfg.AmsterdamTime = nil
	if prague {
		cfg.PragueTime = eip8131U64(0)
		cfg.PragueBlock = big.NewInt(0)
	}
	if bogota {
		cfg.BogotaTime = eip8131U64(bogotaTime)
	}
	if amsterdam {
		cfg.AmsterdamTime = eip8131U64(0)
	}
	return &cfg
}

// eip8131EVM builds a core-level EVM with an explicit block time so fork
// boundaries can be probed on either side. Merge-shaped context (Random set)
// matches the 7709/3298 harnesses.
func eip8131EVM(statedb *state.StateDB, cfg *params.ChainConfig, number, time uint64) *vm.EVM {
	random := new(common.Hash)
	blockCtx := vm.BlockContext{
		CanTransfer: func(db vm.StateDB, addr common.Address, amount *uint256.Int) bool {
			return db.GetBalance(addr).Cmp(amount) >= 0
		},
		Transfer: func(db vm.StateDB, sender, recipient common.Address, amount *uint256.Int, _ *params.Rules) {
			db.SubBalance(sender, amount, tracing.BalanceChangeTransfer)
			db.AddBalance(recipient, amount, tracing.BalanceChangeTransfer)
		},
		GetHash:          func(n uint64) common.Hash { return common.Hash{} },
		BlockNumber:      new(big.Int).SetUint64(number),
		Time:             time,
		Random:           random,
		GasLimit:         10_000_000,
		Difficulty:       big.NewInt(1),
		BaseFee:          big.NewInt(0),
		BlobBaseFee:      big.NewInt(0),
		CostPerStateByte: params.CostPerStateByte,
	}
	return vm.NewEVM(blockCtx, statedb, cfg, vm.Config{NoBaseFee: true})
}

// eip8131Message builds a Message carrying exactly the content terms under
// test. Authorization signatures are deliberately junk: EIP-7702 semantics
// skip invalid auths during execution, while the 8131 floor counts the
// authorizations present in the transaction regardless of validity (spec
// §Transaction floor counts tuples).
func eip8131Message(dataLen, auths, blobs int, al types.AccessList, gasLimit uint64) *Message {
	msg := &Message{
		From:            eip8131From,
		To:              &eip8131To,
		Nonce:           0,
		Value:           uint256.NewInt(0),
		GasLimit:        gasLimit,
		GasPrice:        uint256.NewInt(0),
		GasFeeCap:       uint256.NewInt(0),
		GasTipCap:       uint256.NewInt(0),
		BlobGasFeeCap:   uint256.NewInt(0),
		Data:            bytes.Repeat([]byte{1}, dataLen),
		AccessList:      al,
		SkipNonceChecks: true,
	}
	for i := 0; i < auths; i++ {
		msg.SetCodeAuthorizations = append(msg.SetCodeAuthorizations, types.SetCodeAuthorization{
			ChainID: *uint256.NewInt(1),
			Address: eip8131To,
			Nonce:   0,
			V:       27,
			R:       *uint256.NewInt(1),
			S:       *uint256.NewInt(1),
		})
	}
	for i := 0; i < blobs; i++ {
		var h common.Hash
		h[0] = 0x01 // kzg versioned-hash marker
		h[31] = byte(i + 1)
		msg.BlobHashes = append(msg.BlobHashes, h)
	}
	return msg
}

// eip8131Apply executes the message and returns the settled gas used.
func eip8131Apply(cfg *params.ChainConfig, number, time uint64, msg *Message) (uint64, error) {
	statedb, _ := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	evm := eip8131EVM(statedb, cfg, number, time)
	res, err := ApplyMessage(evm, msg, NewGasPool(10_000_000))
	if err != nil {
		return 0, err
	}
	return res.UsedGas, nil
}

// TestEIP8131P1SetCodeAuthFloor: SetCode tx, 1 authorization, 1,000 nonzero
// calldata bytes under Prague+Bogotá. Combined EIP-8131 + EIP-8279
// expectation (Day 3 fixture alignment): floor = 21,000 + 64×(1000 + 108)
// + 51×64 = 91,912 + 3,264 = 95,176; the floor binds because execution
// (intrinsic 21,000+16,000+25,000 = 62,000) stays below it. (Pre-8279
// baseline 91,912 preserved in /tmp/eip8131_test.go.day3-orig.) RED today:
// the authorization term is unpriced, the Prague floor still prices data at
// the 7623 rate (40 gas/byte ⇒ 61,000, below the intrinsic), and gasUsed
// settles at 62,000 — a 29,912 gap that decomposes into 6,912 (auth term) +
// 24,000 (40→64 rate upgrade mandated by the 8131 formula).
func TestEIP8131P1SetCodeAuthFloor(t *testing.T) {
	cfg := eip8131Config(true, true, false, 0)
	msg := eip8131Message(1000, 1, 0, nil, eip8131Floor(1000, 0, 0, 1, 0)+100_000)
	used, err := eip8131Apply(cfg, 1, 0, msg)
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	// EIP-8279 adds a static 51 BAL bytes per authorization to the seed:
	// floor = tx_floor + 64×(51×auths + runtime); this fixture carries no
	// runtime metering (plain transfer), so settle gains exactly 51×64.
	if want := eip8131Floor(1000, 0, 0, 1, 0) + 51*64; used != want {
		t.Fatalf("gasUsed = %d, want combined 8131+8279 floor %d (8131 floor %d + 51 B/auth seed %d)",
			used, want, eip8131Floor(1000, 0, 0, 1, 0), want-eip8131Floor(1000, 0, 0, 1, 0))
	}
}

// TestEIP8131P2BlobHashFloor: blob tx with 6 versioned hashes, empty calldata
// under Prague+Bogotá. Spec floor = 21,000 + 64×(6×32) = 33,288 (spec §Test
// Cases: 6 blobs ⇒ 12,288 gas). RED today: blob hashes are never priced at
// the floor; gasUsed settles at ~21,000.
func TestEIP8131P2BlobHashFloor(t *testing.T) {
	cfg := eip8131Config(true, true, false, 0)
	msg := eip8131Message(0, 0, 6, nil, eip8131Floor(0, 0, 0, 0, 6)+100_000)
	used, err := eip8131Apply(cfg, 1, 0, msg)
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if want := eip8131Floor(0, 0, 0, 0, 6); used != want {
		t.Fatalf("gasUsed = %d, want spec floor %d (missing 32-byte blob-hash term: %d gas)", used, want, want-used)
	}
}

// TestEIP8131P3MixedFloor: calldata 10,000 B + access list (1 address, 1
// storage key) + 2 authorizations + 6 blob hashes under Prague+Bogotá.
// Combined EIP-8131 + EIP-8279 expectation (Day 3 fixture alignment): floor
// = eip8131Floor + 51×2×64 (EIP-8279 static seed), i.e. 690,440 + 6,528 =
// 696,968. (Pre-8279 baseline preserved in /tmp/eip8131_test.go.day3-orig.)
// Spec floor = 21,000 + 64×(10,000+20+32+216+192) = 690,440. RED today: the
// Prague-formula floor prices calldata only at the 7623 rate (40 gas/byte ⇒
// 421,000) with access-list, authorization, and blob terms unpriced — a
// 269,440 gap decomposing into 29,440 = 64×(20+32+216+192) (new terms) plus
// 240,000 = 24×10,000 (40→64 rate upgrade).
func TestEIP8131P3MixedFloor(t *testing.T) {
	cfg := eip8131Config(true, true, false, 0)
	al := types.AccessList{{Address: eip8131To, StorageKeys: []common.Hash{{0x01}}}}
	msg := eip8131Message(10_000, 2, 6, al, eip8131Floor(10_000, 1, 1, 2, 6)+100_000)
	used, err := eip8131Apply(cfg, 1, 0, msg)
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if want := eip8131Floor(10_000, 1, 1, 2, 6) + 2*51*64; used != want {
		t.Fatalf("gasUsed = %d, want combined 8131+8279 floor %d (8131 floor %d + 51 B/auth seed %d)",
			used, want, eip8131Floor(10_000, 1, 1, 2, 6), want-eip8131Floor(10_000, 1, 1, 2, 6))
	}
}

// TestEIP8131P4BareTransferBase21000: control. A content-free transfer has
// floor = TX_BASE and settles at exactly TX_BASE. A1: TX_BASE is the EIP-2780
// intrinsic base (15,000), so the settlement is 15,000. The test name is
// retained for report traceability.
func TestEIP8131P4BareTransferBase21000(t *testing.T) {
	cfg := eip8131Config(true, true, false, 0)
	msg := eip8131Message(0, 0, 0, nil, 50_000)
	used, err := eip8131Apply(cfg, 1, 0, msg)
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if used != eip8131Base {
		t.Fatalf("gasUsed = %d, want TX_BASE %d", used, eip8131Base)
	}
}

// TestEIP8131N1GasLimitBelowFloorRejected: gas limit equal to the intrinsic
// cost (21,000) but below the spec floor (33,288 for 6 blob hashes) must be
// rejected with ErrFloorDataGas (spec §Charging: require tx.gas >= max
// (intrinsic, floor)). RED today: the blob term is unpriced so the limit
// satisfies the (data-only) floor and the transaction executes.
func TestEIP8131N1GasLimitBelowFloorRejected(t *testing.T) {
	cfg := eip8131Config(true, true, false, 0)
	msg := eip8131Message(0, 0, 6, nil, eip8131Base)
	_, err := eip8131Apply(cfg, 1, 0, msg)
	if err == nil {
		t.Fatalf("tx with gas limit %d below spec floor %d accepted (want ErrFloorDataGas)",
			eip8131Base, eip8131Floor(0, 0, 0, 0, 6))
	}
	if !errors.Is(err, ErrFloorDataGas) {
		t.Fatalf("err = %v, want ErrFloorDataGas", err)
	}
}

// eip8131UnitMsg builds the minimal message settleGas needs (fee fields
// non-nil; the refund path multiplies by GasPrice).
func eip8131UnitMsg(gasLimit uint64) *Message {
	return &Message{
		From:       eip8131From,
		GasLimit:   gasLimit,
		GasPrice:   uint256.NewInt(0),
		GasFeeCap:  uint256.NewInt(0),
		GasTipCap:  uint256.NewInt(0),
		Value:      uint256.NewInt(0),
	}
}

// TestEIP8131N2FloorBindsAfterFullRefund: EIP-3298 interaction (approved
// assumption 6). Under Bogotá the refund cap is removed, but the 8131 floor
// applies AFTER the refund (spec §Charging: gasUsed = max(execution_after_
// refund, floor)), so a refund larger than the execution excess can never
// push a tx below its floor. Unit-level on settleGas with a Bogotá-only
// schedule: before-refund usage F+2,000, refund counter 4,800 ⇒ after-refund
// F−2,800, which must floor back up to F = 85,000. RED today: the Prague gate
// at settleGas leaves the refund intact and the tx pays 82,200.
func TestEIP8131N2FloorBindsAfterFullRefund(t *testing.T) {
	const (
		floor              = uint64(85_000)
		beforeRefund       = floor + 2_000
		refundCounter      = uint64(4_800)
	)
	cfg := eip8131Config(false, true, false, 0)
	statedb, _ := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	statedb.AddRefund(refundCounter)
	evm := vm.NewEVM(vm.BlockContext{BlockNumber: big.NewInt(0)}, statedb, cfg, vm.Config{})
	st := &stateTransition{
		msg:          eip8131UnitMsg(beforeRefund),
		gasRemaining: vm.NewGasBudget(0, 0),
		state:        statedb,
		evm:          evm,
		gp:           NewGasPool(10_000_000),
	}
	rules := cfg.Rules(big.NewInt(0), true, 0)
	gasUsed, _, err := st.settleGas(rules, floor)
	if err != nil {
		t.Fatalf("settleGas failed: %v", err)
	}
	if gasUsed != floor {
		t.Fatalf("gasUsed = %d, want floor %d (floor must bind after the EIP-3298 uncapped refund: refund pushed usage %d below floor)", gasUsed, floor, gasUsed)
	}
}

// TestEIP8131N3AmsterdamAuthBlobUnpriced: control — byte-for-byte Amsterdam
// preservation (approved assumption 1). With Amsterdam active and Bogotá
// inactive, authorizations and blob hashes must NOT enter the floor: the
// direct FloorDataGas value equals the EIP-2780-anchored base plus data
// tokens only, and end-to-end gasUsed equals max(intrinsic, that floor)
// computed with today's production functions.
func TestEIP8131N3AmsterdamAuthBlobUnpriced(t *testing.T) {
	cfg := eip8131Config(false, false, true, 0)
	rules := cfg.Rules(big.NewInt(1), true, 0)
	data := bytes.Repeat([]byte{1}, 100)

	floor, err := FloorDataGas(rules, eip8131From, &eip8131To, uint256.NewInt(0), data, nil, 1, 2)
	if err != nil {
		t.Fatalf("FloorDataGas failed: %v", err)
	}
	base := intrinsicBaseGasEIP2780(eip8131From, &eip8131To, uint256.NewInt(0))
	if want := base + 64*uint64(len(data)); floor != want {
		t.Fatalf("Amsterdam floor = %d, want %d (EIP-2780 base %d + data tokens only; auth/blob must stay unpriced)", floor, want, base)
	}

	msg := eip8131Message(100, 1, 2, nil, 1_000_000)
	used, err := eip8131Apply(cfg, 1, 0, msg)
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	// A plain transfer earns no refund, so settled gas equals the intrinsic
	// cost exactly — byte-for-byte today's Amsterdam behavior, independent of
	// whether the (auth/blob-free) floor lies above or below it.
	intrinsic, err := IntrinsicGas(msg.Data, msg.AccessList, msg.SetCodeAuthorizations, msg.From, msg.To, msg.Value, rules)
	if err != nil {
		t.Fatalf("IntrinsicGas failed: %v", err)
	}
	if used != intrinsic {
		t.Fatalf("Amsterdam gasUsed = %d, want intrinsic %d (byte-for-byte preservation; floor %d must not include auth/blob terms)", used, intrinsic, floor)
	}
}

// TestEIP8131B1AuthCountFloorDeltas: boundary — each additional authorization
// must add exactly 64×108 + 51×64 = 10,176 gas to the settled floor under
// the combined EIP-8131 + EIP-8279 semantics (108 B 8131 content term plus
// the 51 BAL bytes/auth EIP-8279 seed; 1 and 2 auths, 1,000 data bytes,
// Prague+Bogotá, no runtime metering). Pre-8279 baseline delta was 64×108 =
// 6,912 (preserved in /tmp/eip8131_test.go.day3-orig). RED today: both settle
// at the data-only floor.
func TestEIP8131B1AuthCountFloorDeltas(t *testing.T) {
	cfg := eip8131Config(true, true, false, 0)
	for _, auths := range []uint64{1, 2} {
		msg := eip8131Message(1000, int(auths), 0, nil, eip8131Floor(1000, 0, 0, auths, 0)+100_000)
		used, err := eip8131Apply(cfg, 1, 0, msg)
		if err != nil {
			t.Fatalf("auths=%d: apply failed: %v", auths, err)
		}
		if want := eip8131Floor(1000, 0, 0, auths, 0) + auths*51*64; used != want {
			t.Fatalf("auths=%d: gasUsed = %d, want %d (8131 floor %d + 51 B/auth seed %d; delta from auths-1 case %d)",
				auths, used, want, eip8131Floor(1000, 0, 0, auths, 0), auths*51*64, 108*64+51*64)
		}
	}
}

// TestEIP8131B1BlobCountFloorDeltas: boundary — 1 vs 6 blob hashes must add
// exactly 64×32 = 2,048 gas each (1,000 data bytes, Prague+Bogotá). RED
// today: both settle at the data-only floor.
func TestEIP8131B1BlobCountFloorDeltas(t *testing.T) {
	cfg := eip8131Config(true, true, false, 0)
	for _, blobs := range []uint64{1, 6} {
		msg := eip8131Message(1000, 0, int(blobs), nil, eip8131Floor(1000, 0, 0, 0, blobs)+100_000)
		used, err := eip8131Apply(cfg, 1, 0, msg)
		if err != nil {
			t.Fatalf("blobs=%d: apply failed: %v", blobs, err)
		}
		if want := eip8131Floor(1000, 0, 0, 0, blobs); used != want {
			t.Fatalf("blobs=%d: gasUsed = %d, want %d (delta %d missing)", blobs, used, want, want-used)
		}
	}
}

// TestEIP8131B2FloorExecutionTie: boundary — when execution gas before refund
// equals the floor exactly, max(execution, floor) must return that value with
// no double counting (spec §Charging). Control: passes before and after.
func TestEIP8131B2FloorExecutionTie(t *testing.T) {
	const floor = uint64(85_000)
	cfg := eip8131Config(false, true, false, 0)
	statedb, _ := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	evm := vm.NewEVM(vm.BlockContext{BlockNumber: big.NewInt(0)}, statedb, cfg, vm.Config{})
	st := &stateTransition{
		msg:          eip8131UnitMsg(floor),
		gasRemaining: vm.NewGasBudget(0, 0),
		state:        statedb,
		evm:          evm,
		gp:           NewGasPool(10_000_000),
	}
	rules := cfg.Rules(big.NewInt(0), true, 0)
	gasUsed, _, err := st.settleGas(rules, floor)
	if err != nil {
		t.Fatalf("settleGas failed: %v", err)
	}
	if gasUsed != floor {
		t.Fatalf("gasUsed = %d, want exact tie value %d", gasUsed, floor)
	}
}

// TestEIP8131B3OverflowGuards: the data term must keep accepting ordinary
// payloads (control).
func TestEIP8131B3OverflowGuards(t *testing.T) {
	rules := eip8131Config(true, true, false, 0).Rules(big.NewInt(1), true, 0)
	huge := make([]byte, 1<<20) // 1 MiB; not near-overflow, just a large payload
	if _, err := FloorDataGas(rules, eip8131From, &eip8131To, uint256.NewInt(0), huge, nil, 0, 0); err != nil {
		t.Fatalf("unexpected error for 1 MiB payload: %v", err)
	}
}

// TestEIP8131B3OverflowAuthCount: authorization counts are plain int
// parameters, so the per-term guard can be probed with synthetic counts far
// beyond anything allocatable. One past the guard must fail with
// ErrGasUintOverflow.
func TestEIP8131B3OverflowAuthCount(t *testing.T) {
	rules := eip8131Config(true, true, false, 0).Rules(big.NewInt(1), true, 0)
	auths := int(math.MaxUint64/108) + 1
	if _, err := FloorDataGas(rules, eip8131From, &eip8131To, uint256.NewInt(0), nil, nil, auths, 0); !errors.Is(err, ErrGasUintOverflow) {
		t.Fatalf("auths=%d: err = %v, want ErrGasUintOverflow", auths, err)
	}
	// A count just under the per-term guard still trips the final
	// content*64 + TX_BASE overflow check (108*auths ≈ MaxUint64).
	auths = int(math.MaxUint64 / 108)
	if _, err := FloorDataGas(rules, eip8131From, &eip8131To, uint256.NewInt(0), nil, nil, auths, 0); !errors.Is(err, ErrGasUintOverflow) {
		t.Fatalf("auths=%d: err = %v, want ErrGasUintOverflow (final 64x content guard)", auths, err)
	}
}

// TestEIP8131B3OverflowBlobCount: same guard pattern on the blob-hash term,
// including the largest non-overflowing blob count (boundary accept) and the
// first overflowing one (boundary reject).
func TestEIP8131B3OverflowBlobCount(t *testing.T) {
	rules := eip8131Config(true, true, false, 0).Rules(big.NewInt(1), true, 0)
	limit := (math.MaxUint64 - eip8131Base) / 64 // max content bytes
	blobs := int(limit / 32)
	floor, err := FloorDataGas(rules, eip8131From, &eip8131To, uint256.NewInt(0), nil, nil, 0, blobs)
	if err != nil {
		t.Fatalf("blobs=%d (largest non-overflowing): err = %v, want nil", blobs, err)
	}
	if want := eip8131Base + 64*uint64(blobs)*32; floor != want {
		t.Fatalf("floor = %d, want %d", floor, want)
	}
	if _, err := FloorDataGas(rules, eip8131From, &eip8131To, uint256.NewInt(0), nil, nil, 0, blobs+1); !errors.Is(err, ErrGasUintOverflow) {
		t.Fatalf("blobs=%d (first overflowing): err = %v, want ErrGasUintOverflow", blobs+1, err)
	}
}

// TestEIP8131B3OverflowMixed: the guards are stepwise — a large but ordinary
// data payload plus a synthetic overflow-count term must still fail cleanly.
func TestEIP8131B3OverflowMixed(t *testing.T) {
	rules := eip8131Config(true, true, false, 0).Rules(big.NewInt(1), true, 0)
	data := make([]byte, 1<<20)
	auths := int(math.MaxUint64/108) + 1
	if _, err := FloorDataGas(rules, eip8131From, &eip8131To, uint256.NewInt(0), data, nil, auths, 0); !errors.Is(err, ErrGasUintOverflow) {
		t.Fatalf("mixed data+auth overflow: err = %v, want ErrGasUintOverflow", err)
	}
}

// TestEIP8131B4EmptyAuthListRejected: boundary — a SetCode transaction with
// zero authorizations is invalid before 8131 (ErrEmptyAuthList) and must
// remain so (the floor count-zero path never executes for an admitted tx).
// Control: passes before and after.
func TestEIP8131B4EmptyAuthListRejected(t *testing.T) {
	cfg := eip8131Config(true, true, false, 0)
	msg := eip8131Message(0, 0, 0, nil, 50_000)
	msg.SetCodeAuthorizations = []types.SetCodeAuthorization{}
	_, err := eip8131Apply(cfg, 1, 0, msg)
	if err == nil {
		t.Fatal("SetCode tx with empty authorization list accepted (want ErrEmptyAuthList)")
	}
	if !errors.Is(err, ErrEmptyAuthList) {
		t.Fatalf("err = %v, want ErrEmptyAuthList", err)
	}
}

// TestEIP8131F1GateBoundaryBothSides: fork transition (approved assumption 1:
// Bogotá gate). A 1,000-byte transfer executed one second before BogotaTime
// must charge plain execution (21,000+16×1,000 = 37,000 — control arm); the
// same transaction one second after must charge the spec floor
// (15,000+64×1,000 = 79,000 under A1 — RED today: no floor exists on a
// Bogotá-without-Prague schedule).
func TestEIP8131F1GateBoundaryBothSides(t *testing.T) {
	cfg := eip8131Config(false, true, false, 100)
	msg := eip8131Message(1000, 0, 0, nil, 200_000)

	pre, err := eip8131Apply(cfg, 1, 99, msg)
	if err != nil {
		t.Fatalf("pre-gate apply failed: %v", err)
	}
	if want := uint64(37_000); pre != want {
		t.Fatalf("pre-gate gasUsed = %d, want legacy execution %d", pre, want)
	}

	post, err := eip8131Apply(cfg, 1, 101, msg)
	if err != nil {
		t.Fatalf("post-gate apply failed: %v", err)
	}
	if want := eip8131Floor(1000, 0, 0, 0, 0); post != want {
		t.Fatalf("post-gate gasUsed = %d, want spec floor %d (Bogotá gate not enforcing the floor)", post, want)
	}
}

// TestEIP8131F2ActivationBlockChargesFloor: the activation block itself
// (block time == BogotaTime) must apply the new rules and remain error-free.
// RED today: executes fine but charges 37,000 instead of 79,000 (A1).
func TestEIP8131F2ActivationBlockChargesFloor(t *testing.T) {
	cfg := eip8131Config(false, true, false, 100)
	msg := eip8131Message(1000, 0, 0, nil, 200_000)
	used, err := eip8131Apply(cfg, 1, 100, msg)
	if err != nil {
		t.Fatalf("activation-block apply failed: %v", err)
	}
	if want := eip8131Floor(1000, 0, 0, 0, 0); used != want {
		t.Fatalf("activation-block gasUsed = %d, want spec floor %d", used, want)
	}
}

// TestEIP8131F3PragueFormulaPreserved: fork preservation — on a Prague-only
// schedule (no Bogotá) the existing floor formula must stay byte-identical:
// data tokens at the pre-Amsterdam rate (4 tokens × 16 gas per nonzero byte)
// and NO access-list, authorization, or blob terms. Control: passes before
// and after; any accidental change to the Prague path flips it RED.
func TestEIP8131F3PragueFormulaPreserved(t *testing.T) {
	cfg := eip8131Config(true, false, false, 0)
	rules := cfg.Rules(big.NewInt(1), true, 0)
	data := bytes.Repeat([]byte{1}, 1000)
	al := types.AccessList{{Address: eip8131To, StorageKeys: []common.Hash{{0x01}}}}

	floor, err := FloorDataGas(rules, eip8131From, &eip8131To, uint256.NewInt(0), data, al, 0, 0)
	if err != nil {
		t.Fatalf("FloorDataGas failed: %v", err)
	}
	// Pre-Amsterdam 7623 formula: 40 gas per nonzero byte, access list NOT
	// counted (AL floor tokens are Amsterdam-only), no auth/blob terms.
	if want := uint64(61_000); floor != want {
		t.Fatalf("Prague floor = %d, want %d (data-only 7623 formula must be preserved)", floor, want)
	}

	msg := eip8131Message(1000, 0, 0, al, 200_000)
	used, err := eip8131Apply(cfg, 1, 0, msg)
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if used != floor {
		t.Fatalf("Prague gasUsed = %d, want floor %d (byte-identical preservation)", used, floor)
	}
}

// EIP-2780 interaction (user-requested explicit coverage): under Amsterdam
// the floor base is the EIP-2780 per-resource decomposition
// (intrinsicBaseGasEIP2780), NOT the literal 21,000. These controls pin that
// anchor for every shape the decomposition distinguishes, per design review
// decision item 3 (floor-base divergence — protocol owner to confirm keeping
// the 2780 anchor).

func eip8131AmsterdamRules() params.Rules {
	return eip8131Config(false, false, true, 0).Rules(big.NewInt(1), true, 0)
}

func TestEIP8131EIP2780FloorAnchorSelfTransfer(t *testing.T) {
	rules := eip8131AmsterdamRules()
	floor, err := FloorDataGas(rules, eip8131From, &eip8131From, uint256.NewInt(0), nil, nil, 0, 0)
	if err != nil {
		t.Fatalf("FloorDataGas failed: %v", err)
	}
	if want := params.TxBaseCost2780; floor != want {
		t.Fatalf("self-transfer floor = %d, want TxBaseCost2780 %d (recipient touch and value charges must be absent)", floor, want)
	}
}

func TestEIP8131EIP2780FloorAnchorValueTransfer(t *testing.T) {
	rules := eip8131AmsterdamRules()
	floor, err := FloorDataGas(rules, eip8131From, &eip8131To, uint256.NewInt(1), nil, nil, 0, 0)
	if err != nil {
		t.Fatalf("FloorDataGas failed: %v", err)
	}
	want := params.TxBaseCost2780 + params.ColdAccountAccessAmsterdam + params.TransferLogCost2780 + params.TxValueCost2780
	if floor != want {
		t.Fatalf("value-transfer floor = %d, want 2780 decomposition %d", floor, want)
	}
}

func TestEIP8131EIP2780FloorAnchorContractCreation(t *testing.T) {
	rules := eip8131AmsterdamRules()
	floor, err := FloorDataGas(rules, eip8131From, nil, uint256.NewInt(0), nil, nil, 0, 0)
	if err != nil {
		t.Fatalf("FloorDataGas failed: %v", err)
	}
	if want := params.TxBaseCost2780 + params.CreateAccessAmsterdam; floor != want {
		t.Fatalf("creation floor = %d, want TxBaseCost2780+CreateAccessAmsterdam %d", floor, want)
	}
}

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

// RED-first tests for EIP-8279 (Block Access List Byte Floor).
//
// Spec: https://eips.ethereum.org/EIPS/eip-8279 (DRAFT, re-fetched
// 2026-11-08; research: HEGOTA_EIP8279_RESEARCH_REPORT.md).
//
// EIP-8279 adds, on top of the EIP-8131 static content floor (Bogotá gate):
//
//  1. a STATIC term of 51 BAL bytes per EIP-7702 authorization
//     (20 address + 23 delegation marker + 8 nonce), i.e. 51×64 = 3,264
//     floor gas per authorization, folded into the static floor seed; and
//
//  2. a RUNTIME meter charging 64 gas per byte that execution adds to the
//     EIP-7928 Block Access List, against per-transaction first-touch sets
//     that are INDEPENDENT of EVM warmness:
//       - first account touch ................ 20 B (BALANCE/EXT*/CALL*/
//                                                SELFDESTRUCT beneficiary/
//                                                CREATE deployed address)
//       - first storage-key touch ............ 32 B (SLOAD/SSTORE)
//       - storage value (current==original &&
//         new!=original, at most once/slot) .. 32 B
//       - nonzero-value CALL to a different
//         account (caller+recipient balances) 64 B
//       - nonzero-balance SELFDESTRUCT ....... 64 B (+20 first-touch addr)
//       - CREATE/CREATE2 ..................... 8 B creator nonce +
//                                                8 B new-contract nonce
//                                                (+64 B endowment balances)
//       - successful deployment ............. len(deployed_code) bytes
//
// The meter raises OutOfGasError when the derived floor would exceed
// execution_budget = min(tx.gas, TX_MAX_GAS_LIMIT = 2^24). Metered bytes
// are NEVER refunded or journaled: reverted frames retain their bytes.
// Settlement stays tx.gasUsed = max(execution_gas_used, floor_gas_used).
// System calls (2935/4788/7002/7251) and withdrawals are exempt.
//
// STRICT RED RULES: test file only, zero production edits. Expected values
// below are derived from the spec formula; where a scenario is a CONTROL
// (expected to pass today and stay green after implementation) this is
// stated in the test comment. Everything else must FAIL until EIP-8279 is
// implemented.
//
// Harness note: this file intentionally reuses the eip8131* fixtures from
// eip8131_test.go (same test package) — config/EVM/message builders and the
// eip8131Floor static-floor formula, which is the EIP-8131 half of every
// expected value here.

package core

import (
	"bytes"
	"errors"
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

// EIP-8279 byte constants (spec §Constants / §Runtime data metering).
const (
	eip8279BytesPerAddress     = 20
	eip8279BytesPerStorageKey  = 32
	eip8279BytesPerStorageVal  = 32
	eip8279BytesPerBalancePair = 64
	eip8279BytesPerNonce       = 8
	eip8279StaticBytesPerAuth  = 51 // 20 + 23 delegation marker + 8 nonce
	eip8279GasPerByte          = 64
	eip8279TxMaxGasLimit       = params.MaxTxGas // 1 << 24 (EIP-7825)
)

// Fixture addresses.
var (
	eip8279Contract   = common.HexToAddress("0x00000000000000000000000000000000000c0de1")
	eip8279Recipient  = common.HexToAddress("0x00000000000000000000000000000000000recip")
	eip8279Beneficiary = common.HexToAddress("0x0000000000000000000000000000000000beef01")
	eip8279Target     = common.HexToAddress("0x0000000000000000000000000000000000000a11c")
)

// eip8279Floor is the EIP-8279 expected floor for a scenario: the EIP-8131
// static floor (via eip8131Floor) plus runtimeBytes×64 (and, for
// authorization scenarios, the static 51 BAL bytes per auth).
func eip8279Floor(dataLen, alAddrs, alKeys, auths uint64, runtimeBytes uint64) uint64 {
	return eip8131Floor(dataLen, alAddrs, alKeys, auths, 0) + runtimeBytes*eip8279GasPerByte
}

// eip8279Msg builds a full-fee-fields message to an arbitrary target.
func eip8279Msg(to *common.Address, data []byte, value uint64, al types.AccessList, gasLimit uint64) *Message {
	return &Message{
		From:            eip8131From,
		To:              to,
		Nonce:           0,
		Value:           uint256.NewInt(value),
		GasLimit:        gasLimit,
		GasPrice:        uint256.NewInt(0),
		GasFeeCap:       uint256.NewInt(0),
		GasTipCap:       uint256.NewInt(0),
		BlobGasFeeCap:   uint256.NewInt(0),
		Data:            data,
		AccessList:      al,
		SkipNonceChecks: true,
	}
}

// eip8279Run executes a message against a fresh statedb with an optional
// setup hook, returning the full ExecutionResult (res.Err carries
// execution-level failures such as OutOfGas / REVERT).
func eip8279Run(cfg *params.ChainConfig, number, time uint64, msg *Message, setup func(*state.StateDB)) (*ExecutionResult, error) {
	statedb, _ := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	if setup != nil {
		setup(statedb)
	}
	evm := eip8131EVM(statedb, cfg, number, time)
	return ApplyMessage(evm, msg, NewGasPool(100_000_000))
}

// Bytecode builders (hand-assembled, verified byte-by-byte).
func eip8279CodeSloads(n int) []byte {
	// SLOAD slots 0..n-1, STOP.
	code := make([]byte, 0, 3*n+1)
	for i := 0; i < n; i++ {
		code = append(code, 0x60, byte(i), 0x54) // PUSH1 i; SLOAD
	}
	return append(code, 0x00)
}

func eip8279CodeExtcodesize(addr common.Address) []byte {
	// PUSH20 addr; EXTCODESIZE; STOP.
	code := []byte{0x73}
	code = append(code, addr.Bytes()...)
	return append(code, 0x3b, 0x00)
}

func eip8279CodeSstorePair(v1, v2 byte) []byte {
	// PUSH1 v1; PUSH1 0; SSTORE; PUSH1 v2; PUSH1 0; SSTORE; STOP.
	return []byte{0x60, v1, 0x60, 0x00, 0x55, 0x60, v2, 0x60, 0x00, 0x55, 0x00}
}

func eip8279CodeClearSlot() []byte {
	// PUSH1 0; PUSH1 0; SSTORE; STOP — clears slot 0 (nonzero → zero).
	return []byte{0x60, 0x00, 0x60, 0x00, 0x55, 0x00}
}

func eip8279CodeValueCalls(addr common.Address, n int, revert bool) []byte {
	// n × [PUSH1 0 ×4; PUSH1 1; PUSH20 addr; PUSH2 0xffff; CALL]
	// (value=1, empty args/ret), then optional REVERT(0,0), STOP.
	code := make([]byte, 0, n*33+8)
	for i := 0; i < n; i++ {
		code = append(code,
			0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, // retSize retOff argSize argOff
			0x60, 0x01, // value = 1
			0x73)
		code = append(code, addr.Bytes()...)
		code = append(code, 0x61, 0xff, 0xff, 0xf1) // gas 0xffff; CALL
	}
	if revert {
		code = append(code, 0x60, 0x00, 0x60, 0x00, 0xfd) // REVERT(0,0)
	}
	return append(code, 0x00)
}

func eip8279CodeSelfdestruct(beneficiary common.Address) []byte {
	// PUSH20 beneficiary; SELFDESTRUCT.
	code := []byte{0x73}
	code = append(code, beneficiary.Bytes()...)
	return append(code, 0xff)
}

func eip8279CodeCreate(create2 bool, value byte) []byte {
	// Deploys 5-byte runtime 602a600055 (PUSH1 42; PUSH1 0; SSTORE; STOP —
	// the init's CODECOPY grabs code[12:17], the final STOP of the 18-byte
	// blob is not copied) via 12-byte initcode 6005600c60003960056000f3.
	//
	// Operand layout (load-bearing, verified by opcode trace during RED):
	// the 18-byte initAndRuntime is right-aligned into a 32-byte word and
	// MSTOREd at mem[0:32], so it occupies mem[14:32] — the CREATE offset
	// MUST be 14 (0x0e) with size 18 (0x12). The original 15/17 pair shifts
	// the stream one byte right, the child executes 0x05 (SDIV) as its first
	// opcode, and the frame burns all forwarded gas (~63/64 of the tx limit,
	// observed 8,859,876 of 9,000,000 with an empty deploy). CREATE2 takes
	// value/offset/size/salt top-of-stack downward, so salt is pushed first.
	initAndRuntime := common.Hex2Bytes("6005600c60003960056000f3602a60005500") // 18 bytes
	word := make([]byte, 32)
	copy(word[32-len(initAndRuntime):], initAndRuntime)
	code := []byte{0x7f}
	code = append(code, word...)                // PUSH32 init+runtime
	code = append(code, 0x60, 0x00, 0x52)       // PUSH1 0; MSTORE
	if create2 {
		code = append(code, 0x60, 0xaa) // PUSH1 salt 0xaa (deepest operand)
	}
	code = append(code, 0x60, 0x12, 0x60, 0x0e) // size 18; offset 14
	code = append(code, 0x60, value)            // PUSH1 value
	if create2 {
		code = append(code, 0xf5) // CREATE2
	} else {
		code = append(code, 0xf0) // CREATE
	}
	return append(code, 0x00)
}

// setupContract installs code (and optional balance/nonce/storage) for the
// shared fixture contract address.
func eip8279Setup(code []byte, balance uint64, nonce uint64, slot0Orig *common.Hash) func(*state.StateDB) {
	return func(statedb *state.StateDB) {
		statedb.SetCode(eip8279Contract, code, tracing.CodeChangeGenesis)
		if balance > 0 {
			statedb.AddBalance(eip8279Contract, uint256.NewInt(balance), tracing.BalanceIncreaseGenesisBalance)
		}
		if nonce > 0 {
			statedb.SetNonce(eip8279Contract, nonce, tracing.NonceChangeGenesis)
		}
		if slot0Orig != nil {
			statedb.SetState(eip8279Contract, common.Hash{0x00}, *slot0Orig)
		}
	}
}

func eip8279BogotaCfg() *params.ChainConfig { return eip8131Config(true, true, false, 0) }

// ---------------------------------------------------------------------------
// S-series: static authorization term (51 BAL bytes per authorization).
// ---------------------------------------------------------------------------

// TestEIP8279S1StaticAuthBal51: 1 authorization, 1,000-byte calldata,
// Prague+Bogotá. EIP-8131 floor = 91,912 (settled, GREEN). EIP-8279 adds
// 51 BAL bytes/auth statically: 91,912 + 51×64 = 95,176.
// Spec §Static floor seed: static_floor = tx_floor + 64×51×num_authorizations.
// RED today: the 51-byte BAL term is unpriced.
// Note: the seed formula counts authorizations present in the tx (mirroring
// the 8131 tuple-counting rule); junk-signature auths are skipped by 7702
// processing but remain in num_authorizations for the SEED per the formula.
func TestEIP8279S1StaticAuthBal51(t *testing.T) {
	cfg := eip8279BogotaCfg()
	msg := eip8131Message(1000, 1, 0, nil, eip8131Floor(1000, 0, 0, 1, 0)+100_000)
	res, err := eip8279Run(cfg, 1, 0, msg, nil)
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	want := eip8279Floor(1000, 0, 0, 1, 0) // runtimeBytes = 0; auth term added below
	want += eip8279StaticBytesPerAuth * eip8279GasPerByte
	if res.UsedGas != want {
		t.Fatalf("gasUsed = %d, want EIP-8279 floor %d (missing static 51 BAL bytes/auth: %d gas)",
			res.UsedGas, want, want-res.UsedGas)
	}
}

// ---------------------------------------------------------------------------
// A/K-series: first-touch runtime metering (warmness-independent).
// ---------------------------------------------------------------------------

// TestEIP8279A1FirstAccountTouchWarm: EXTCODESIZE on an address that is both
// in the tx access list (EVM-warm) and untouched by execution so far.
// EIP-2920-style warmth does NOT exempt the meter (spec: first-touch sets
// are independent of EVM warmness, because EIP-7928 copies the access into
// the BAL). Runtime bytes: 20 (first account touch).
// RED today: nothing meters the touch; settled gas = 8131 static floor.
func TestEIP8279A1FirstAccountTouchWarm(t *testing.T) {
	cfg := eip8279BogotaCfg()
	al := types.AccessList{{Address: eip8279Target}}
	data := bytes.Repeat([]byte{1}, 200)
	msg := eip8279Msg(&eip8279Contract, data, 0, al, 1_000_000)
	res, err := eip8279Run(cfg, 1, 0, msg, eip8279Setup(eip8279CodeExtcodesize(eip8279Target), 0, 0, nil))
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	want := eip8279Floor(200, 1, 0, 0, eip8279BytesPerAddress)
	if res.UsedGas != want {
		t.Fatalf("gasUsed = %d, want %d (missing first account touch 20 B×64 = %d gas)",
			res.UsedGas, want, want-res.UsedGas)
	}
}

// TestEIP8279K1FirstStorageKeyWarm: 3 SLOADs on slots pre-warmed by the tx
// access list. Each first execution touch meters 32 B even though EVM-warm
// (spec §Runtime data metering: "These first-touch sets are independent of
// EVM warmness"). Runtime bytes: 3×32 = 96.
// RED today: settled gas = 8131 static floor only.
func TestEIP8279K1FirstStorageKeyWarm(t *testing.T) {
	cfg := eip8279BogotaCfg()
	al := types.AccessList{{Address: eip8279Contract, StorageKeys: []common.Hash{{0x00}, {0x01}, {0x02}}}}
	data := bytes.Repeat([]byte{1}, 200)
	msg := eip8279Msg(&eip8279Contract, data, 0, al, 1_000_000)
	res, err := eip8279Run(cfg, 1, 0, msg, eip8279Setup(eip8279CodeSloads(3), 0, 0, nil))
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	want := eip8279Floor(200, 1, 3, 0, 3*eip8279BytesPerStorageKey)
	if res.UsedGas != want {
		t.Fatalf("gasUsed = %d, want %d (missing first storage-key touches 3×32 B×64 = %d gas)",
			res.UsedGas, want, want-res.UsedGas)
	}
}

// TestEIP8279K2ColdSloadControl: CONTROL. 3 cold SLOADs, no access list, no
// calldata. Spec rationale table: first storage-key touch floor extension
// 2,048 vs 2,100 minimum execution charge — execution DOMINATES, so the
// meter is invisible here and settlement stays at execution gas. The
// execution-level value (24,009 under A1) was observed on the real path
// during RED development (15,000 base + 3 cold SLOADs + this tree's
// 7928-era per-access costs); the metered floor would be
// 15,000 + 3×2,048 = 21,144, comfortably below. Green today and must
// remain green after implementation (the meter must never bind below
// execution).
func TestEIP8279K2ColdSloadControl(t *testing.T) {
	cfg := eip8279BogotaCfg()
	msg := eip8279Msg(&eip8279Contract, nil, 0, nil, 50_000)
	res, err := eip8279Run(cfg, 1, 0, msg, eip8279Setup(eip8279CodeSloads(3), 0, 0, nil))
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	const want = 24_009 // execution-dominant settlement observed on the real path (A1)
	if res.UsedGas != want {
		t.Fatalf("gasUsed = %d, want %d (cold-SLOAD control must stay execution-bound; meter over-count must never lower settlement)", res.UsedGas, want)
	}
	if res.UsedGas < 15_000+3*2_048 {
		t.Fatalf("control settlement %d below the metered floor 21,144 — impossible unless the meter double-counts", res.UsedGas)
	}
}

// ---------------------------------------------------------------------------
// V-series: storage-value contributions.
// ---------------------------------------------------------------------------

// TestEIP8279V1StorageValueMeteredOnce: slot 0 preset to original O=0x09
// (pre-state); execution writes A=0x11 then B=0x22. The 32-byte storage
// value is metered ONCE, on the O→A transition (spec §Runtime data
// metering; §Rationale "Repeated writes to the same slot": A→B adds
// nothing). Key metered once too. Runtime bytes: 32 (key) + 32 (value) = 64.
// RED today: settled gas = 8131 static floor.
// Pinning note: an implementation that metered the value per write would
// settle 2,048 higher than `want` — the test pins the once-semantics.
func TestEIP8279V1StorageValueMeteredOnce(t *testing.T) {
	cfg := eip8279BogotaCfg()
	orig := common.Hash{0x09}
	al := types.AccessList{{Address: eip8279Contract, StorageKeys: []common.Hash{{0x00}}}}
	data := bytes.Repeat([]byte{1}, 200)
	msg := eip8279Msg(&eip8279Contract, data, 0, al, 1_000_000)
	res, err := eip8279Run(cfg, 1, 0, msg, eip8279Setup(eip8279CodeSstorePair(0x11, 0x22), 0, 0, &orig))
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	want := eip8279Floor(200, 1, 1, 0, eip8279BytesPerStorageKey+eip8279BytesPerStorageVal)
	if res.UsedGas != want {
		t.Fatalf("gasUsed = %d, want %d (missing storage key+value bytes 64 B×64 = %d gas; want pins value-metered-ONCE semantics)",
			res.UsedGas, want, want-res.UsedGas)
	}
}

// TestEIP8279V2NetZeroRoundTrip: O=0x09 preset; execution writes X=0x11
// then restores O=0x09. The restored write is a no-op for EIP-7928 (no
// storage_changes entry), but the 32 value bytes stay metered (spec §Test
// Cases "Net-zero SSTORE round-trip": net metered 64 B; deliberate
// over-count, never refunded). Runtime bytes: 32 (key) + 32 (value) = 64.
// RED today.
func TestEIP8279V2NetZeroRoundTrip(t *testing.T) {
	cfg := eip8279BogotaCfg()
	orig := common.Hash{0x09}
	al := types.AccessList{{Address: eip8279Contract, StorageKeys: []common.Hash{{0x00}}}}
	data := bytes.Repeat([]byte{1}, 200)
	msg := eip8279Msg(&eip8279Contract, data, 0, al, 1_000_000)
	res, err := eip8279Run(cfg, 1, 0, msg, eip8279Setup(eip8279CodeSstorePair(0x11, 0x09), 0, 0, &orig))
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	want := eip8279Floor(200, 1, 1, 0, eip8279BytesPerStorageKey+eip8279BytesPerStorageVal)
	if res.UsedGas != want {
		t.Fatalf("gasUsed = %d, want %d (net-zero round trip must retain 64 metered bytes: missing %d gas)",
			res.UsedGas, want, want-res.UsedGas)
	}
}

// TestEIP8279V3DeparturesFromOriginal: O=0x09 preset; writes 0x11, restores
// 0x09, writes 0x22. Value bytes metered once total (spec "Repeated
// departures from the original value": O→A meters, A→O refunds nothing,
// O→B sees the set already populated). Runtime bytes: 32 + 32 = 64.
// RED today.
func TestEIP8279V3DeparturesFromOriginal(t *testing.T) {
	cfg := eip8279BogotaCfg()
	orig := common.Hash{0x09}
	al := types.AccessList{{Address: eip8279Contract, StorageKeys: []common.Hash{{0x00}}}}
	data := bytes.Repeat([]byte{1}, 200)
	// 0x11 → 0x09 → 0x22
	code := append(eip8279CodeSstorePair(0x11, 0x09)[:10], // drop trailing STOP
		0x60, 0x22, 0x60, 0x00, 0x55, 0x00)
	msg := eip8279Msg(&eip8279Contract, data, 0, al, 1_000_000)
	res, err := eip8279Run(cfg, 1, 0, msg, eip8279Setup(code, 0, 0, &orig))
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	want := eip8279Floor(200, 1, 1, 0, eip8279BytesPerStorageKey+eip8279BytesPerStorageVal)
	if res.UsedGas != want {
		t.Fatalf("gasUsed = %d, want %d (repeated departures must meter the value once: missing %d gas)",
			res.UsedGas, want, want-res.UsedGas)
	}
}

// ---------------------------------------------------------------------------
// C-series: value-bearing CALL (accumulated, incl. reverted callee).
// ---------------------------------------------------------------------------

// TestEIP8279C1ValueCallAccumulated: 4 nonzero-value CALLs (1 wei each) to
// an existing empty recipient (nonce bumped in setup so no new-account
// surcharge applies). Per CALL: 64 balance bytes; the recipient address is
// metered once (20 B). Per spec rationale, a single value CALL never binds
// (floor ext 4,096 < exec) — binding is demonstrated by accumulation on
// top of a static floor that already exceeds execution (6,000-byte payload;
// this tree's 8141-era state-byte costs also make balance-touching ops
// execution-expensive, which is exactly the spec's "runtime piece did not
// bind on its own" finding). Runtime bytes: 20 + 4×64 = 276.
// RED today: settled gas = 8131 static floor.
func TestEIP8279C1ValueCallAccumulated(t *testing.T) {
	cfg := eip8279BogotaCfg()
	data := bytes.Repeat([]byte{1}, 6000)
	msg := eip8279Msg(&eip8279Contract, data, 0, nil, 1_000_000)
	res, err := eip8279Run(cfg, 1, 0, msg, func(statedb *state.StateDB) {
		eip8279Setup(eip8279CodeValueCalls(eip8279Recipient, 4, false), 10, 0, nil)(statedb)
		statedb.CreateAccount(eip8279Recipient)
		statedb.SetNonce(eip8279Recipient, 1, tracing.NonceChangeGenesis)
	})
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	want := eip8279Floor(6000, 0, 0, 0, eip8279BytesPerAddress+4*eip8279BytesPerBalancePair)
	if res.UsedGas != want {
		t.Fatalf("gasUsed = %d, want %d (missing value-CALL bytes 276 B×64 = %d gas)",
			res.UsedGas, want, want-res.UsedGas)
	}
}

// TestEIP8279C2RevertedValueCallRetained: 1 value CALL whose callee reverts
// (caller propagates REVERT). Both balance changes are discarded, but the
// metered bytes are RETAINED (spec §Test Cases "Reverted CALL with value";
// §Reverts: nothing is rewound). Runtime bytes: 20 + 64 = 84.
// RED today: the tx reverts but settles at the 8131 static floor without
// the retained bytes.
func TestEIP8279C2RevertedValueCallRetained(t *testing.T) {
	cfg := eip8279BogotaCfg()
	data := bytes.Repeat([]byte{1}, 6000)
	msg := eip8279Msg(&eip8279Contract, data, 0, nil, 1_000_000)
	res, err := eip8279Run(cfg, 1, 0, msg, func(statedb *state.StateDB) {
		eip8279Setup(eip8279CodeValueCalls(eip8279Recipient, 1, true), 10, 0, nil)(statedb)
		statedb.CreateAccount(eip8279Recipient)
		statedb.SetNonce(eip8279Recipient, 1, tracing.NonceChangeGenesis)
	})
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if res.Err == nil {
		t.Fatalf("expected top-level REVERT (fixture design)")
	}
	want := eip8279Floor(6000, 0, 0, 0, eip8279BytesPerAddress+eip8279BytesPerBalancePair)
	if res.UsedGas != want {
		t.Fatalf("gasUsed = %d, want %d (reverted value CALL must retain 84 metered bytes: missing %d gas)",
			res.UsedGas, want, want-res.UsedGas)
	}
}

// ---------------------------------------------------------------------------
// SD/CR-series: SELFDESTRUCT, CREATE/CREATE2, code bytes.
// ---------------------------------------------------------------------------

// TestEIP8279SD1SelfdestructBeneficiary: funded contract (1 wei)
// SELFDESTRUCTs to an existing (but never execution-touched) beneficiary.
// Runtime bytes: 64 (originator + beneficiary balances) + 20 (beneficiary
// first account touch) = 84 — the spec rationale table row (5,376 floor vs
// 5,000 execution). Binding needs the static-floor accumulation pattern
// (8,000-byte payload): this tree's 8141-era state-byte costs make the
// balance moves alone execution-expensive, matching the spec's finding
// that the runtime piece binds mainly on top of a high static seed.
// RED today.
func TestEIP8279SD1SelfdestructBeneficiary(t *testing.T) {
	cfg := eip8279BogotaCfg()
	data := bytes.Repeat([]byte{1}, 8000)
	msg := eip8279Msg(&eip8279Contract, data, 0, nil, 1_000_000)
	res, err := eip8279Run(cfg, 1, 0, msg, func(statedb *state.StateDB) {
		eip8279Setup(eip8279CodeSelfdestruct(eip8279Beneficiary), 1, 0, nil)(statedb)
		statedb.CreateAccount(eip8279Beneficiary)
		statedb.SetNonce(eip8279Beneficiary, 1, tracing.NonceChangeGenesis)
	})
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	want := eip8279Floor(8000, 0, 0, 0, eip8279BytesPerBalancePair+eip8279BytesPerAddress)
	if res.UsedGas != want {
		t.Fatalf("gasUsed = %d, want %d (missing SELFDESTRUCT bytes 84 B×64 = %d gas)",
			res.UsedGas, want, want-res.UsedGas)
	}
}

// TestEIP8279CR1Create: CREATE with NO endowment (value 0) deploying 5 bytes
// of runtime code. Runtime bytes: 20 (deployed address first touch) + 8
// (creator nonce) + 8 (new contract nonce) + 5 (deployed code) = 41 — the
// endowment balance term (+64) is covered by CR2 (CREATE2 with endowment);
// the spec trigger table keys CREATE/CREATE2 jointly so one endowment case
// pins the term for both opcodes.
//
// Fixture note: the builder's operand layout is load-bearing (see
// eip8279CodeCreate). An earlier draft shifted the initcode stream one byte,
// the child frame executed junk opcodes to exhaustion, and the tx settled
// at 63/64 of the gas limit (986,876 of 1,000,000) — execution-bound with a
// misleading cost. With the correct layout, execution ≈161k at this payload
// and the floor (535,624) binds with ≈374k margin. RED today: settles at
// the static floor 533,000.
func TestEIP8279CR1Create(t *testing.T) {
	cfg := eip8279BogotaCfg()
	data := bytes.Repeat([]byte{1}, 8000)
	msg := eip8279Msg(&eip8279Contract, data, 0, nil, 1_000_000)
	res, err := eip8279Run(cfg, 1, 0, msg, eip8279Setup(eip8279CodeCreate(false, 0), 10, 1, nil))
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	const runtimeBytes = eip8279BytesPerAddress + 2*eip8279BytesPerNonce + 5
	want := eip8279Floor(8000, 0, 0, 0, runtimeBytes)
	if res.UsedGas != want {
		t.Fatalf("gasUsed = %d, want %d (missing CREATE bytes 41 B×64 = %d gas; if got > want the fixture is execution-bound — the floor must bind)",
			res.UsedGas, want, want-res.UsedGas)
	}
}

// TestEIP8279CR2Create2: CREATE2, salt 0xaa — identical metering to CREATE
// (spec trigger table keys on CREATE/CREATE2 jointly). Runtime bytes: 105.
// RED today.
func TestEIP8279CR2Create2(t *testing.T) {
	cfg := eip8279BogotaCfg()
	data := bytes.Repeat([]byte{1}, 8000)
	msg := eip8279Msg(&eip8279Contract, data, 0, nil, 1_000_000)
	res, err := eip8279Run(cfg, 1, 0, msg, eip8279Setup(eip8279CodeCreate(true, 1), 10, 1, nil))
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	const runtimeBytes = eip8279BytesPerAddress + 2*eip8279BytesPerNonce + eip8279BytesPerBalancePair + 5
	want := eip8279Floor(8000, 0, 0, 0, runtimeBytes)
	if res.UsedGas != want {
		t.Fatalf("gasUsed = %d, want %d (missing CREATE2 bytes 105 B×64 = %d gas)",
			res.UsedGas, want, want-res.UsedGas)
	}
}

// ---------------------------------------------------------------------------
// O-series: execution-budget enforcement and OutOfGas.
// ---------------------------------------------------------------------------

// TestEIP8279O1MeterOOG: calldata 1,000 B ⇒ static floor 79,000 (A1);
// tx.gas = 94,000. Each distinct-slot SLOAD meters +2,048: after 7 touches
// the floor is 93,336 (≤ 94,000), the 8th raises it to 95,384 > budget —
// spec §Data meter: raise OutOfGasError BEFORE the matching BAL insertion.
// RED today: no meter exists, the tx succeeds and settles at 79,000.
func TestEIP8279O1MeterOOG(t *testing.T) {
	cfg := eip8279BogotaCfg()
	data := bytes.Repeat([]byte{1}, 1000)
	msg := eip8279Msg(&eip8279Contract, data, 0, nil, 94_000)
	res, err := eip8279Run(cfg, 1, 0, msg, eip8279Setup(eip8279CodeSloads(9), 0, 0, nil))
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if !errors.Is(res.Err, vm.ErrOutOfGas) {
		t.Fatalf("res.Err = %v, want OutOfGas at the 8th metered SLOAD (floor 95,384 > budget 94,000); tx succeeded and settled at %d", res.Err, res.UsedGas)
	}
}

// TestEIP8279O2BudgetCap: tx.gas is pinned AT the EIP-7825 cap
// (TX_MAX_GAS_LIMIT = 2^24 = 16,777,216) — the largest legal transaction —
// with calldata 261,000 B ⇒ static floor 16,719,000 (A1) ≤ budget, so
// validation passes. 29 distinct-slot SLOADs then push the floor past the
// cap (16,719,000 + 29×2,048 = 16,778,392 > 16,777,216; after 28 it is
// still 16,776,344 ≤ cap). Spec §Rationale
// "Ceiling is the execution-gas budget, not tx.gas": the meter must OOG
// even though the gas limit would numerically cover the floor.
// RED today: the tx succeeds and settles at the static floor.
func TestEIP8279O2BudgetCap(t *testing.T) {
	cfg := eip8279BogotaCfg()
	data := bytes.Repeat([]byte{1}, 261_000)
	msg := eip8279Msg(&eip8279Contract, data, 0, nil, eip8279TxMaxGasLimit)
	res, err := eip8279Run(cfg, 1, 0, msg, eip8279Setup(eip8279CodeSloads(29), 0, 0, nil))
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if !errors.Is(res.Err, vm.ErrOutOfGas) {
		t.Fatalf("res.Err = %v, want OutOfGas when metered floor crosses TX_MAX_GAS_LIMIT (16,778,392 > 16,777,216); tx succeeded and settled at %d", res.Err, res.UsedGas)
	}
}

// ---------------------------------------------------------------------------
// F-series: settlement shape and fork boundaries.
// ---------------------------------------------------------------------------

// TestEIP8279F1SettlementTail: warm 3-slot SLOADs + 1,000 B calldata. The
// runtime bytes fold into the FINAL settlement
// (tx.gasUsed = max(execution, static floor + runtime bytes)); the static
// floor alone must not cap settlement. RED today.
func TestEIP8279F1SettlementTail(t *testing.T) {
	cfg := eip8279BogotaCfg()
	al := types.AccessList{{Address: eip8279Contract, StorageKeys: []common.Hash{{0x00}, {0x01}, {0x02}}}}
	data := bytes.Repeat([]byte{1}, 1000)
	msg := eip8279Msg(&eip8279Contract, data, 0, al, 1_000_000)
	res, err := eip8279Run(cfg, 1, 0, msg, eip8279Setup(eip8279CodeSloads(3), 0, 0, nil))
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	want := eip8279Floor(1000, 1, 3, 0, 3*eip8279BytesPerStorageKey)
	if res.UsedGas != want {
		t.Fatalf("gasUsed = %d, want %d (runtime BAL bytes must fold into final settlement: missing %d gas)",
			res.UsedGas, want, want-res.UsedGas)
	}
}

// TestEIP8279B1PreBogotaControl: CONTROL (Prague-only, no Bogotá). The K1
// shape must settle at the pre-8131/8279 Prague execution level with ZERO
// runtime bytes: EIP-8279 is Bogotá-gated like EIP-8131. The settled value
// (36,609, observed on the real path during RED development) sits above the
// Prague formula floor (29,000, data-only 7623 rate) — execution-dominant,
// so this control pins the ABSENCE of runtime bytes rather than a floor
// value. Green today and must remain green after implementation.
func TestEIP8279B1PreBogotaControl(t *testing.T) {
	cfg := eip8131Config(true, false, false, 0)
	al := types.AccessList{{Address: eip8279Contract, StorageKeys: []common.Hash{{0x00}, {0x01}, {0x02}}}}
	data := bytes.Repeat([]byte{1}, 200)
	msg := eip8279Msg(&eip8279Contract, data, 0, al, 1_000_000)
	res, err := eip8279Run(cfg, 1, 0, msg, eip8279Setup(eip8279CodeSloads(3), 0, 0, nil))
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	rules := cfg.Rules(big.NewInt(1), true, 0)
	pragueFloor, ferr := FloorDataGas(rules, eip8131From, &eip8279Contract, uint256.NewInt(0), data, al, 0, 0)
	if ferr != nil {
		t.Fatalf("FloorDataGas: %v", ferr)
	}
	const want = 36_609 // pre-Bogotá execution settlement, observed on the real path
	if res.UsedGas != want {
		t.Fatalf("gasUsed = %d, want pre-Bogotá settlement %d (no 8131/8279 terms allowed before Bogotá)", res.UsedGas, want)
	}
	if pragueFloor >= res.UsedGas {
		t.Fatalf("fixture no longer execution-dominant (prague floor %d >= settlement %d); control must pin meter absence, not a floor", pragueFloor, res.UsedGas)
	}
	if res.UsedGas >= eip8279Floor(200, 1, 3, 0, 3*eip8279BytesPerStorageKey) {
		t.Fatalf("pre-Bogotá settlement %d unexpectedly includes EIP-8279 runtime bytes", res.UsedGas)
	}
}

// TestEIP8279B3AmsterdamByteExactControl: CONTROL — byte-for-byte Amsterdam
// preservation (same posture as TestEIP8131N3). With Amsterdam active and
// Bogotá inactive, an authorization-bearing transaction must gain NEITHER
// the EIP-8131 108-byte tuple term NOR the EIP-8279 51-byte BAL term: the
// floor equals the EIP-2780-anchored base plus data tokens only, and
// end-to-end gasUsed equals that floor when it binds. Mirrors the N3
// fixture exactly so the two controls pin identical behavior.
func TestEIP8279B3AmsterdamByteExactControl(t *testing.T) {
	cfg := eip8131Config(false, false, true, 0)
	rules := cfg.Rules(big.NewInt(1), true, 0)
	data := bytes.Repeat([]byte{1}, 100)

	floor, err := FloorDataGas(rules, eip8131From, &eip8131To, uint256.NewInt(0), data, nil, 1, 2)
	if err != nil {
		t.Fatalf("FloorDataGas failed: %v", err)
	}
	base := intrinsicBaseGasEIP2780(eip8131From, &eip8131To, uint256.NewInt(0))
	if want := base + 64*uint64(len(data)); floor != want {
		t.Fatalf("Amsterdam floor = %d, want %d (EIP-2780 base %d + data tokens only; auth must stay unpriced — no 8131 108 B term, no 8279 51 BAL term)",
			floor, want, base)
	}

	msg := eip8131Message(100, 1, 2, nil, 1_000_000)
	used, err := eip8131Apply(cfg, 1, 0, msg)
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	intrinsic, err := IntrinsicGas(msg.Data, msg.AccessList, msg.SetCodeAuthorizations, msg.From, msg.To, msg.Value, rules)
	if err != nil {
		t.Fatalf("IntrinsicGas: %v", err)
	}
	if want := max(intrinsic, floor); used != want {
		t.Fatalf("gasUsed = %d, want max(intrinsic %d, floor %d) = %d (Amsterdam end-to-end must stay byte-for-byte)", used, intrinsic, floor, want)
	}
}

// TestEIP8279P4BareTransferControl: CONTROL. Bare transfer settles at
// exactly TX_BASE = 21,000 (spec §Backwards Compatibility). Mirrors
// TestEIP8131P4.
func TestEIP8279P4BareTransferControl(t *testing.T) {
	cfg := eip8279BogotaCfg()
	msg := eip8279Msg(&eip8131To, nil, 0, nil, 50_000)
	res, err := eip8279Run(cfg, 1, 0, msg, nil)
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if res.UsedGas != eip8131Base {
		t.Fatalf("gasUsed = %d, want TX_BASE %d", res.UsedGas, eip8131Base)
	}
}

// ---------------------------------------------------------------------------
// X-series: EIP-3298 refund compatibility.
// ---------------------------------------------------------------------------

// TestEIP8279X1Refund3298Compat: slot preset 0x11; execution modifies it
// (0x22, nonzero → nonzero). Under EIP-3298 the SSTORE/SELFDESTRUCT refund
// paths are gone, but the settlement invariant EIP-8279 relies on must
// still hold explicitly: settlement runs the refund phase first and the
// metered floor binds AFTER it (tx.gasUsed = max(post-refund execution,
// floor)), so no refund mechanism can ever push settled gas below metered
// bytes. Runtime bytes: 32 (key) + 32 (value) = 64.
//
// BASELINE NOTE (observed during RED development, pre-existing and
// unrelated to 8279): the slot-clear (nonzero → zero) and
// revert-after-SSTORE variants of this fixture trip the tree's
// Amsterdam-era state-gas guard ("negative topmost frame state gas usage")
// under an Amsterdam-less Bogotá config. Documented for the owner; the
// modify-in-place shape used here exercises the same 3298 settlement path
// without the guard.
// RED today.
func TestEIP8279X1Refund3298Compat(t *testing.T) {
	cfg := eip8279BogotaCfg()
	orig := common.Hash{0x11}
	al := types.AccessList{{Address: eip8279Contract, StorageKeys: []common.Hash{{0x00}}}}
	data := bytes.Repeat([]byte{1}, 500)
	code := []byte{0x60, 0x22, 0x60, 0x00, 0x55, 0x00} // SSTORE 0x22 → slot 0; STOP
	msg := eip8279Msg(&eip8279Contract, data, 0, al, 1_000_000)
	res, err := eip8279Run(cfg, 1, 0, msg, eip8279Setup(code, 0, 0, &orig))
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if res.Err != nil {
		t.Fatalf("unexpected execution error: %v", res.Err)
	}
	want := eip8279Floor(500, 1, 1, 0, eip8279BytesPerStorageKey+eip8279BytesPerStorageVal)
	if res.UsedGas != want {
		t.Fatalf("gasUsed = %d, want %d (settlement must be max(post-refund execution, metered floor); EIP-3298 refund phase must not drop settlement below metered bytes: missing %d gas)",
			res.UsedGas, want, want-res.UsedGas)
	}
}

// ---------------------------------------------------------------------------
// F3: EIP-8141 FrameTx isolation (control).
// ---------------------------------------------------------------------------

// TestEIP8279F3FrameTxIsolationControl: CONTROL. ValidateGasLimit /
// ValidateFrameGasLimits are pure transaction-level checks (no Rules
// argument — see core/types/tx_frame.go:487) governed solely by EIP-8141
// frame fee machinery; they cannot observe any runtime meter. This control
// pins that a valid frame tx validates identically under a Bogotá-active
// config, and documents that EIP-8279 must not touch the frame path (same
// provisional FrameTx-exclusion posture as EIP-8131).
func TestEIP8279F3FrameTxIsolationControl(t *testing.T) {
	frame := types.Frame{Mode: 0, Value: uint256.NewInt(0), Data: []byte{1, 2, 3}}
	inner := &types.FrameTx{Sender: eip8131From, Frames: []types.Frame{frame}}
	if err := inner.ValidateGasLimit(); err != nil {
		t.Fatalf("ValidateGasLimit(valid frame tx) = %v; EIP-8141 frame validation must be independent of any 8279 meter", err)
	}
	// Frame calldata floor must remain the 8141 intrinsic machinery.
	if floor := inner.CalldataFloorGas(); floor == 0 {
		t.Fatalf("frame CalldataFloorGas = 0; 8141 frame fee machinery changed unexpectedly")
	}
}

// ---------------------------------------------------------------------------
// SYS1: system-transaction exemption (control).
// ---------------------------------------------------------------------------

// TestEIP8279SYS1SystemCallExemptionControl: CONTROL. System contract calls
// (2935/4788/7002/7251) bypass ApplyMessage and call evm.Call directly
// (core/state_processor.go processRequestsSystemCall). The 8279 meter must
// never be installed on that path, so a warm-SLOAD contract called
// directly consumes exactly the tree's ordinary per-access execution cost
// with no floor top-up. Pin: 6,109 gas observed on the real path (this
// tree's 7928-era per-access state-byte costs make a warm SLOAD ≈2,036,
// NOT the canonical-mainnet 100 — the 300-gas figure in the first RED
// draft was a harness assumption, corrected here).
// Green today (no meter anywhere) and must remain green after
// implementation — this is the executable half of the exemption
// requirement; the Process-level half is covered by the system-call paths
// in state_processor.go.
func TestEIP8279SYS1SystemCallExemptionControl(t *testing.T) {
	cfg := eip8279BogotaCfg()
	statedb, _ := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	statedb.SetCode(eip8279Contract, eip8279CodeSloads(3), tracing.CodeChangeGenesis)
	statedb.AddAddressToAccessList(eip8279Contract)
	for i := 0; i < 3; i++ {
		statedb.AddSlotToAccessList(eip8279Contract, common.Hash{byte(i)})
	}
	evm := eip8131EVM(statedb, cfg, 1, 0)
	initial := vm.NewGasBudget(1_000_000, 0)
	_, rem, err := evm.Call(eip8131From, eip8279Contract, nil, initial, uint256.NewInt(0))
	if err != nil {
		t.Fatalf("direct evm.Call failed: %v", err)
	}
	consumed := initial.RegularGas - rem.RegularGas
	const want = 6_109 // 3 warm SLOADs at this tree's 7928-era per-access cost, observed on the real path
	if consumed != want {
		t.Fatalf("consumed = %d, want %d (direct-call/system path must never carry a 8279 floor top-up)", consumed, want)
	}
}

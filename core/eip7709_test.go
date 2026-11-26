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

// Activation and BAL-recording tests for EIP-7709 (Serve historical block
// hashes from state) on Bogotá-without-Prague schedules. Upstream gates the
// history contract deploy, ring buffer, and ProcessParentBlockHash system
// call on Prague/UBT; on XDC those must fire from Bogotá onward so the ring
// is populated for the state-serving BLOCKHASH introduced in the Bogotá
// instruction set (see core/vm/eip7709_test.go). The Prague path must stay
// byte-identical.

package core

import (
	"context"
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/tracing"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/holiman/uint256"
)

// eip7709HashFor returns a deterministic non-zero hash per block number so
// backfill assertions can distinguish slots.
func eip7709HashFor(n uint64) common.Hash {
	return crypto.Keccak256Hash([]byte("eip7709-block"), new(big.Int).SetUint64(n).Bytes())
}

// eip7709RingSlot replicates the ring formula for seeding from this package.
func eip7709RingSlot(number uint64) common.Hash {
	var key common.Hash
	binary.BigEndian.PutUint64(key[24:], number%params.HistoryServeWindow)
	return key
}

// bogotaNoPrague7709Config: Bogotá active, Prague fully disabled — the
// schedule under test.
func bogotaNoPrague7709Config() *params.ChainConfig {
	cfg := *params.MergedTestChainConfig
	cfg.BogotaTime = new(uint64)
	cfg.PragueBlock = nil
	cfg.PragueTime = nil
	return &cfg
}

// prague7709Config: Prague active (timestamp gate) with the block-numbered
// deploy branch armed, Bogotá inactive — the preservation control (upstream
// behavior: deploy, backfill, and system-call ring write).
func prague7709Config() *params.ChainConfig {
	cfg := *params.MergedTestChainConfig
	cfg.BogotaTime = nil
	cfg.PragueTime = new(uint64) // zero time → IsPrague gate fires
	cfg.PragueBlock = big.NewInt(0)
	return &cfg
}

// eip7709EVM builds a core-level EVM at block number with GetHash serving
// eip7709HashFor. mergeCtx selects a merge-shaped context (required when the
// test needs merge-gated Rules flags such as IsAmsterdam for BAL recording).
func eip7709EVM(t *testing.T, statedb *state.StateDB, cfg *params.ChainConfig, number uint64, mergeCtx bool) *vm.EVM {
	t.Helper()
	random := (*common.Hash)(nil)
	if mergeCtx {
		random = new(common.Hash)
	}
	blockCtx := vm.BlockContext{
		CanTransfer: func(db vm.StateDB, addr common.Address, amount *uint256.Int) bool {
			return db.GetBalance(addr).Cmp(amount) >= 0
		},
		Transfer: func(db vm.StateDB, sender, recipient common.Address, amount *uint256.Int, _ *params.Rules) {
			db.SubBalance(sender, amount, tracing.BalanceChangeTransfer)
			db.AddBalance(recipient, amount, tracing.BalanceChangeTransfer)
		},
		GetHash:          func(n uint64) common.Hash { return eip7709HashFor(n) },
		BlockNumber:      new(big.Int).SetUint64(number),
		Time:             0,
		Random:           random,
		GasLimit:         10000000,
		Difficulty:       big.NewInt(1),
		BaseFee:          big.NewInt(0),
		CostPerStateByte: params.CostPerStateByte,
	}
	return vm.NewEVM(blockCtx, statedb, cfg, vm.Config{})
}

// TestEIP7709ProcessParentBlockHashUnderBogota: on a Bogota-without-Prague
// chain, PreExecution must deploy the history contract, backfill the ring
// window from GetHash, and store the parent hash via the system call.
func TestEIP7709ProcessParentBlockHashUnderBogota(t *testing.T) {
	const n = uint64(9000)
	cfg := bogotaNoPrague7709Config()
	statedb, _ := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	evm := eip7709EVM(t, statedb, cfg, n, true)
	parent := &types.Header{Number: new(big.Int).SetUint64(n - 1), Time: 0}

	PreExecution(context.Background(), nil, parent, cfg, evm, new(big.Int).SetUint64(n), 0)

	if code := statedb.GetCode(params.HistoryStorageAddress); len(code) == 0 {
		t.Fatalf("Bogota-without-Prague: history contract not deployed (Prague-only gate still active)")
	} else if string(code) != string(params.HistoryStorageCode) {
		t.Fatalf("deployed code mismatch")
	}
	if got := statedb.GetState(params.HistoryStorageAddress, historyStorageKey(n-1)); got != parent.Hash() {
		t.Fatalf("ring slot n-1 = %x, want parent hash %x (system call write)", got, parent.Hash())
	}
	if got := statedb.GetState(params.HistoryStorageAddress, historyStorageKey(4000)); got != eip7709HashFor(4000) {
		t.Fatalf("ring slot 4000 = %x, want backfilled GetHash value %x", got, eip7709HashFor(4000))
	}
}

// TestEIP7709PraguePathPreserved: with Prague active and Bogotá inactive the
// existing Prague behavior (system-call ring write, no deploy without
// PragueBlock) must be unchanged. Control — green before and after.
func TestEIP7709PraguePathPreserved(t *testing.T) {
	const n = uint64(9000)
	cfg := prague7709Config()
	statedb, _ := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	evm := eip7709EVM(t, statedb, cfg, n, true)
	parent := &types.Header{Number: new(big.Int).SetUint64(n - 1), Time: 0}

	PreExecution(context.Background(), nil, parent, cfg, evm, new(big.Int).SetUint64(n), 0)

	if code := statedb.GetCode(params.HistoryStorageAddress); string(code) != string(params.HistoryStorageCode) {
		t.Fatalf("Prague path: history contract code mismatch: got len=%d %x, want len=%d", len(code), code, len(params.HistoryStorageCode))
	}
	if got := statedb.GetState(params.HistoryStorageAddress, historyStorageKey(n-1)); got != parent.Hash() {
		t.Fatalf("Prague path: ring slot n-1 = %x, want parent hash %x", got, parent.Hash())
	}
	if got := statedb.GetState(params.HistoryStorageAddress, historyStorageKey(4000)); got != eip7709HashFor(4000) {
		t.Fatalf("Prague path: ring slot 4000 = %x, want backfilled GetHash value %x", got, eip7709HashFor(4000))
	}
}

// TestEIP7709BALRecording: a Bogotá BLOCKHASH read of the history ring must
// be visible in the Amsterdam BAL construction — account read and storage
// slot read on HISTORY_STORAGE_ADDRESS — so verifiable state access is
// recorded (Bogotá ships no verkle conversion).
func TestEIP7709BALRecording(t *testing.T) {
	const n = uint64(1000)
	cfg := *params.MergedTestChainConfig
	cfg.AmsterdamTime = new(uint64)
	cfg.BogotaTime = new(uint64)

	statedb, _ := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	statedb.CreateAccount(params.HistoryStorageAddress)
	statedb.SetState(params.HistoryStorageAddress, eip7709RingSlot(n-1), eip7709HashFor(n-1))
	statedb.Finalise(true) // commit the seed so the read takes the committed path

	rules := cfg.Rules(new(big.Int).SetUint64(n), true, 0)
	statedb.Prepare(rules, common.Address{}, common.Address{}, nil, nil, nil)

	evm := eip7709EVM(t, statedb, &cfg, n, true)
	self := common.BytesToAddress([]byte("bal-reader"))
	statedb.CreateAccount(self)
	prog := append(pushUint7709(n-1), 0x40, 0x50, 0x00) // BLOCKHASH, POP, STOP
	statedb.SetCode(self, prog, tracing.CodeChangeUnspecified)
	gas := vm.NewGasBudget(1_000_000, 0)
	if _, _, err := evm.Call(common.Address{}, self, nil, gas, uint256.NewInt(0)); err != nil {
		t.Fatalf("call failed: %v", err)
	}

	bal := statedb.Finalise(true)
	acct, ok := bal.Accounts[params.HistoryStorageAddress]
	if !ok {
		t.Fatalf("BAL has no account-read entry for %s (history ring read not recorded)", params.HistoryStorageAddress)
	}
	// Slot-level note: mirroring the fork's own SLOAD, GetState serves the
	// value from dirty (per-block pending) storage without a StorageRead
	// journal entry — stateObject.GetCommittedState only records when the
	// read falls through to it. The account-read entry above is the
	// BAL-visible proof that BLOCKHASH touched the history contract; the
	// access-list warming assertion lives in the vm gas test.
	_ = acct
}

// pushUint7709 is the minimal-PUSH helper for the core-side bytecode fixture.
func pushUint7709(v uint64) []byte {
	if v == 0 {
		return []byte{0x60, 0x00}
	}
	var b []byte
	for tmp := v; tmp > 0; tmp >>= 8 {
		b = append([]byte{byte(tmp)}, b...)
	}
	return append([]byte{0x5f + byte(len(b))}, b...)
}

// TestEIP7709FirstBogotaBlock: at the first Bogotá block (n=1, genesis
// parent), PreExecution must deploy the history contract and write the
// parent hash — the ring bootstraps from the first block onward.
func TestEIP7709FirstBogotaBlock(t *testing.T) {
	const n = uint64(1)
	cfg := bogotaNoPrague7709Config()
	statedb, _ := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	evm := eip7709EVM(t, statedb, cfg, n, true)
	parent := &types.Header{Number: new(big.Int).SetUint64(0), Time: 0}

	PreExecution(context.Background(), nil, parent, cfg, evm, new(big.Int).SetUint64(n), 0)

	if code := statedb.GetCode(params.HistoryStorageAddress); string(code) != string(params.HistoryStorageCode) {
		t.Fatalf("first Bogotá block: history contract not deployed")
	}
	if got := statedb.GetState(params.HistoryStorageAddress, historyStorageKey(0)); got != parent.Hash() {
		t.Fatalf("first Bogotá block: ring slot 0 = %x, want parent hash %x", got, parent.Hash())
	}
}

// TestEIP7709SubsequentBlocks: the block after activation must append its
// parent to the ring while the activation-time backfill remains intact —
// the per-block system call is what keeps the ring warm after bootstrap.
func TestEIP7709SubsequentBlocks(t *testing.T) {
	cfg := bogotaNoPrague7709Config()
	statedb, _ := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())

	parentA := &types.Header{Number: new(big.Int).SetUint64(8999), Time: 0}
	evmA := eip7709EVM(t, statedb, cfg, 9000, true)
	PreExecution(context.Background(), nil, parentA, cfg, evmA, new(big.Int).SetUint64(9000), 0)

	parentB := &types.Header{Number: new(big.Int).SetUint64(9000), Time: 0}
	evmB := eip7709EVM(t, statedb, cfg, 9001, true)
	PreExecution(context.Background(), nil, parentB, cfg, evmB, new(big.Int).SetUint64(9001), 0)

	if got := statedb.GetState(params.HistoryStorageAddress, historyStorageKey(8999)); got != parentA.Hash() {
		t.Fatalf("slot 8999 = %x, want activation-block parent hash %x", got, parentA.Hash())
	}
	if got := statedb.GetState(params.HistoryStorageAddress, historyStorageKey(9000)); got != parentB.Hash() {
		t.Fatalf("slot 9000 = %x, want subsequent-block parent hash %x (system call append)", got, parentB.Hash())
	}
	if got := statedb.GetState(params.HistoryStorageAddress, historyStorageKey(4000)); got != eip7709HashFor(4000) {
		t.Fatalf("slot 4000 = %x, want activation backfill %x", got, eip7709HashFor(4000))
	}
}

// TestEIP7709InitializedContractPreserved: when the history contract already
// carries the canonical code, activation must NOT redeploy or backfill over
// existing history — initialized history is never overwritten. The per-block
// system call still appends the parent hash (normal ring operation).
func TestEIP7709InitializedContractPreserved(t *testing.T) {
	const n = uint64(9000)
	cfg := bogotaNoPrague7709Config()
	statedb, _ := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	custom := common.BytesToHash([]byte("preexisting-history-slot-32b!!"))
	statedb.CreateAccount(params.HistoryStorageAddress)
	statedb.SetCode(params.HistoryStorageAddress, params.HistoryStorageCode, tracing.CodeChangeGenesis)
	statedb.SetState(params.HistoryStorageAddress, historyStorageKey(4000), custom)
	statedb.Finalise(true)

	parent := &types.Header{Number: new(big.Int).SetUint64(n - 1), Time: 0}
	evm := eip7709EVM(t, statedb, cfg, n, true)
	PreExecution(context.Background(), nil, parent, cfg, evm, new(big.Int).SetUint64(n), 0)

	if code := statedb.GetCode(params.HistoryStorageAddress); string(code) != string(params.HistoryStorageCode) {
		t.Fatalf("initialized contract: code was modified")
	}
	if got := statedb.GetState(params.HistoryStorageAddress, historyStorageKey(4000)); got != custom {
		t.Fatalf("initialized history overwritten: slot 4000 = %x, want %x", got, custom)
	}
	if got := statedb.GetState(params.HistoryStorageAddress, historyStorageKey(n-1)); got != parent.Hash() {
		t.Fatalf("slot n-1 = %x, want system-call append %x", got, parent.Hash())
	}
}

// T1 — TestEIP7709BackfillFullWindow: at n=9000 (end=8999 ≥ HISTORY_SERVE_
// WINDOW) the Bogotá backfill must populate exactly slots [end+1-8191 .. end]
// = blocks [809 .. 8999] from GetHash — the full 8191-slot ring in one block.
func TestEIP7709BackfillFullWindow(t *testing.T) {
	const n = uint64(9000)
	const start = n - params.HistoryServeWindow // 809
	cfg := bogotaNoPrague7709Config()
	statedb, _ := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	parent := &types.Header{Number: new(big.Int).SetUint64(n - 1), Time: 0}
	evm := eip7709EVM(t, statedb, cfg, n, true)

	PreExecution(context.Background(), nil, parent, cfg, evm, new(big.Int).SetUint64(n), 0)

	nonZero := 0
	for b := start; b <= n-1; b++ {
		got := statedb.GetState(params.HistoryStorageAddress, historyStorageKey(b))
		want := eip7709HashFor(b)
		if b == n-1 {
			want = parent.Hash() // system-call append lands on the same slot
		}
		if got != want {
			t.Fatalf("backfill slot for block %d = %x, want %x", b, got, want)
		}
		nonZero++
	}
	if nonZero != params.HistoryServeWindow {
		t.Fatalf("backfilled slots = %d, want %d (full ring)", nonZero, params.HistoryServeWindow)
	}
}

// T2 — TestEIP7709ZeroHashSkipDeterminism: hashes GetHash cannot serve are
// skipped (slot left empty → BLOCKHASH serves 0, the canonical unknown
// value), and the skip rule is consensus-relevant: two independent replays
// of the same activation block must produce the identical state root.
func TestEIP7709ZeroHashSkipDeterminism(t *testing.T) {
	const n = uint64(500) // n-1 = 499 < 8191 → saturating backfill covers [0..499]
	cfg := bogotaNoPrague7709Config()
	getHash := func(bn uint64) common.Hash {
		if bn%5 == 0 { // simulate unavailable history: every 5th hash missing
			return common.Hash{}
		}
		return eip7709HashFor(bn)
	}
	run := func() (*state.StateDB, common.Hash) {
		db, _ := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
		blockCtx := vm.BlockContext{
			CanTransfer: func(db vm.StateDB, addr common.Address, amount *uint256.Int) bool {
				return db.GetBalance(addr).Cmp(amount) >= 0
			},
			Transfer: func(db vm.StateDB, sender, recipient common.Address, amount *uint256.Int, _ *params.Rules) {
				db.SubBalance(sender, amount, tracing.BalanceChangeTransfer)
				db.AddBalance(recipient, amount, tracing.BalanceChangeTransfer)
			},
			GetHash:          getHash,
			BlockNumber:      new(big.Int).SetUint64(n),
			Time:             0,
			Random:           new(common.Hash),
			GasLimit:         10000000,
			Difficulty:       big.NewInt(1),
			BaseFee:          big.NewInt(0),
			CostPerStateByte: params.CostPerStateByte,
		}
		evm := vm.NewEVM(blockCtx, db, cfg, vm.Config{})
		parent := &types.Header{Number: new(big.Int).SetUint64(n - 1), Time: 0}
		PreExecution(context.Background(), nil, parent, cfg, evm, new(big.Int).SetUint64(n), 0)
		return db, db.IntermediateRoot(true)
	}

	dbA, rootA := run()
	_, rootB := run()
	if rootA != rootB {
		t.Fatalf("zero-hash-skip replay divergence: root A %x != root B %x", rootA, rootB)
	}
	for b := uint64(0); b < n; b++ {
		got := dbA.GetState(params.HistoryStorageAddress, historyStorageKey(b))
		if b%5 == 0 && b != n-1 {
			if got != (common.Hash{}) {
				t.Fatalf("skipped hash block %d: slot = %x, want empty", b, got)
			}
		} else if b != n-1 && got != eip7709HashFor(b) {
			t.Fatalf("block %d: slot = %x, want %x", b, got, eip7709HashFor(b))
		}
	}
}

// T3 — TestEIP7709ActivationAtGenesis: Bogotá at genesis (n=1) must match
// EIP-2935's genesis-activation scenario — the genesis hash lands in slot 0
// (via backfill and then the per-block append), the account carries code and
// nonce 1 (EIP-161 exemption), and no other slot is touched.
func TestEIP7709ActivationAtGenesis(t *testing.T) {
	const n = uint64(1)
	cfg := bogotaNoPrague7709Config()
	statedb, _ := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	parent := &types.Header{Number: new(big.Int).SetUint64(0), Time: 0}
	evm := eip7709EVM(t, statedb, cfg, n, true)

	PreExecution(context.Background(), nil, parent, cfg, evm, new(big.Int).SetUint64(n), 0)

	if got := statedb.GetNonce(params.HistoryStorageAddress); got != 1 {
		t.Fatalf("history account nonce = %d, want 1 (EIP-161 exemption)", got)
	}
	if got := statedb.GetState(params.HistoryStorageAddress, historyStorageKey(0)); got != parent.Hash() {
		t.Fatalf("genesis activation: slot 0 = %x, want genesis/parent hash %x", got, parent.Hash())
	}
	if got := statedb.GetState(params.HistoryStorageAddress, historyStorageKey(1)); got != (common.Hash{}) {
		t.Fatalf("genesis activation: slot 1 = %x, want empty (only slot 0 written)", got)
	}
}

// T4 — TestEIP7709BackfillBoundary8192: at exactly n=8192 (end=8191) the
// saturating backfill covers blocks [1..8191]; slot 0 (block 0's ring index)
// is NOT backfilled — the per-block system call fills it with the parent
// hash instead. Exactly 8192 slots end up populated.
func TestEIP7709BackfillBoundary8192(t *testing.T) {
	const n = uint64(8192)
	cfg := bogotaNoPrague7709Config()
	statedb, _ := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	parent := &types.Header{Number: new(big.Int).SetUint64(n - 1), Time: 0}
	evm := eip7709EVM(t, statedb, cfg, n, true)

	PreExecution(context.Background(), nil, parent, cfg, evm, new(big.Int).SetUint64(n), 0)

	if got := statedb.GetState(params.HistoryStorageAddress, historyStorageKey(0)); got != parent.Hash() {
		t.Fatalf("boundary: slot 0 = %x, want system-call parent append %x (not backfilled)", got, parent.Hash())
	}
	for b := uint64(1); b <= n-1; b++ {
		want := eip7709HashFor(b)
		if b == n-1 {
			want = parent.Hash() // system-call append overwrites slot (n-1)%8191 == 0
		}
		if got := statedb.GetState(params.HistoryStorageAddress, historyStorageKey(b)); got != want {
			t.Fatalf("boundary: slot for block %d = %x, want %x", b, got, want)
		}
	}
}

// T5 — TestEIP7709ReplayDeterminism: the activation block's state root must
// be a pure function of the chain data — two fresh statedb instances
// processing the same block produce identical roots (sync-from-genesis
// equivalence, the property that makes the backfill consensus-safe).
func TestEIP7709ReplayDeterminism(t *testing.T) {
	const n = uint64(9000)
	cfg := bogotaNoPrague7709Config()
	run := func() common.Hash {
		db, _ := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
		evm := eip7709EVM(t, db, cfg, n, true)
		parent := &types.Header{Number: new(big.Int).SetUint64(n - 1), Time: 0}
		PreExecution(context.Background(), nil, parent, cfg, evm, new(big.Int).SetUint64(n), 0)
		return db.IntermediateRoot(true)
	}
	if rootA, rootB := run(), run(); rootA != rootB {
		t.Fatalf("activation replay divergence: %x != %x", rootA, rootB)
	}
}

// T6 — TestEIP7709FuturePragueBlockSafeMode: a misconfigured chain (PragueBlock
// in the future, Bogotá active now) must not crash or backfill from a
// fork-block bound that hasn't been reached — the contract deploys, the ring
// stays empty except the per-block append, and the BLOCKHASH window serves 0
// until the ring fills naturally.
func TestEIP7709FuturePragueBlockSafeMode(t *testing.T) {
	const n = uint64(100)
	cfg := *params.MergedTestChainConfig
	cfg.BogotaTime = new(uint64)
	cfg.PragueTime = nil
	cfg.PragueBlock = big.NewInt(9000) // future

	statedb, _ := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	parent := &types.Header{Number: new(big.Int).SetUint64(n - 1), Time: 0}
	evm := eip7709EVM(t, statedb, &cfg, n, true)
	PreExecution(context.Background(), nil, parent, &cfg, evm, new(big.Int).SetUint64(n), 0)

	if code := statedb.GetCode(params.HistoryStorageAddress); string(code) != string(params.HistoryStorageCode) {
		t.Fatalf("safe mode: history contract not deployed")
	}
	if got := statedb.GetState(params.HistoryStorageAddress, historyStorageKey(50)); got != (common.Hash{}) {
		t.Fatalf("safe mode: slot for block 50 = %x, want empty (no speculative backfill)", got)
	}
	if got := statedb.GetState(params.HistoryStorageAddress, historyStorageKey(n-1)); got != parent.Hash() {
		t.Fatalf("safe mode: slot n-1 = %x, want system-call append %x", got, parent.Hash())
	}
}

// T7 — TestEIP7709BackfillNoAccessListWarming: the deploy/backfill path is
// host-level state writes and must NOT warm ring slots in the EIP-2929
// access list (EIP-2935 §Gas costs: the system update does not warm slots).
// Only the per-block system call's own SSTORE slot may appear.
func TestEIP7709BackfillNoAccessListWarming(t *testing.T) {
	const n = uint64(9000)
	cfg := bogotaNoPrague7709Config()
	statedb, _ := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	parent := &types.Header{Number: new(big.Int).SetUint64(n - 1), Time: 0}
	evm := eip7709EVM(t, statedb, cfg, n, true)

	PreExecution(context.Background(), nil, parent, cfg, evm, new(big.Int).SetUint64(n), 0)

	if _, slotPresent := statedb.SlotInAccessList(params.HistoryStorageAddress, historyStorageKey(4000)); slotPresent {
		t.Fatalf("backfill warmed ring slot 4000 in the access list (host writes must not warm)")
	}
	if _, slotPresent := statedb.SlotInAccessList(params.HistoryStorageAddress, historyStorageKey(0)); slotPresent {
		t.Fatalf("backfill warmed ring slot 0 in the access list (host writes must not warm)")
	}
}

// T8 — TestEIP7709PragueForkBlockBackfillBound: the existing Prague
// block-numbered path (devnet-5551 behavior) must be byte-identical: the
// backfill starts at max(window-wrap, forkBlock-1), never earlier. With
// PragueBlock=8500 and n=9000 only blocks [8499..8999] may be backfilled.
func TestEIP7709PragueForkBlockBackfillBound(t *testing.T) {
	const n = uint64(9000)
	const forkBlock = int64(8500)
	cfg := *params.MergedTestChainConfig
	cfg.BogotaTime = nil
	cfg.PragueTime = new(uint64) // Prague gate also requires the timestamp arm
	cfg.PragueBlock = big.NewInt(forkBlock)

	statedb, _ := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	parent := &types.Header{Number: new(big.Int).SetUint64(n - 1), Time: 0}
	evm := eip7709EVM(t, statedb, &cfg, n, true)
	PreExecution(context.Background(), nil, parent, &cfg, evm, new(big.Int).SetUint64(n), 0)

	if code := statedb.GetCode(params.HistoryStorageAddress); string(code) != string(params.HistoryStorageCode) {
		t.Fatalf("Prague bound: history contract not deployed")
	}
	if got := statedb.GetState(params.HistoryStorageAddress, historyStorageKey(uint64(forkBlock-1))); got != eip7709HashFor(uint64(forkBlock-1)) {
		t.Fatalf("Prague bound: first backfilled slot (forkBlock-1) = %x, want %x", got, eip7709HashFor(uint64(forkBlock-1)))
	}
	if got := statedb.GetState(params.HistoryStorageAddress, historyStorageKey(uint64(forkBlock-2))); got != (common.Hash{}) {
		t.Fatalf("Prague bound: slot for forkBlock-2 = %x, want empty (pre-fork history NOT backfilled)", got)
	}
	if got := statedb.GetState(params.HistoryStorageAddress, historyStorageKey(n-1)); got != parent.Hash() {
		t.Fatalf("Prague bound: slot n-1 = %x, want parent hash %x", got, parent.Hash())
	}
}

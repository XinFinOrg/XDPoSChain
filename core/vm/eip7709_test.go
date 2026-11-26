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

// BLOCKHASH tests for EIP-7709 (Serve historical block hashes from state),
// activated in the Bogotá instruction set. Under Bogotá, BLOCKHASH must serve
// from the EIP-2935 history storage ring (params.HistoryStorageAddress,
// HISTORY_SERVE_WINDOW = 8191 slots, key = big-endian uint64 of n % 8191 in
// bytes [24:32]) instead of the memory GetHash function, with SLOAD semantics:
// EIP-8038 cold (3000) / warm (100) gas for the arg % 8191 slot, access-list
// warming, and state-access BAL recording. Window: parent (n-1) down to
// n-256 inclusive; arg == n, arg > n, and uint64-overflow args return zero.
//
// Spec: https://eips.ethereum.org/EIPS/eip-7709 (full snapshot fetched
// 2026-11-07: hegota-research-20261107/eip-7709.md). The history contract
// deploy, ring buffer, and ProcessParentBlockHash system call are additionally
// gated to Bogotá chains (Prague-gated upstream; core/eip7709_test.go pins
// the Bogota-without-Prague activation).

package vm

import (
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/tracing"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/holiman/uint256"
)

var eip7709Self = common.BytesToAddress([]byte("blockhash-self"))

// ringSlot replicates core.historyStorageKey (unexported there) so the vm
// tests can seed and inspect the EIP-2935 ring independently; the core test
// asserts agreement against the production helper.
func ringSlot(number uint64) common.Hash {
	var key common.Hash
	binary.BigEndian.PutUint64(key[24:], number%params.HistoryServeWindow)
	return key
}

// pushUint encodes a PUSHn of v (minimal length; PUSH1 0 for zero).
func pushUint(v uint64) []byte {
	if v == 0 {
		return []byte{0x60, 0x00}
	}
	var b []byte
	for tmp := v; tmp > 0; tmp >>= 8 {
		b = append([]byte{byte(tmp)}, b...)
	}
	return append([]byte{0x5f + byte(len(b))}, b...)
}

// blockhashProg returns BLOCKHASH(arg), MSTORE(0), RETURN(32) — the served
// hash as the call's returndata.
func blockhashProg(arg uint64) []byte {
	p := pushUint(arg)
	p = append(p, 0x40)                   // BLOCKHASH
	p = append(p, 0x60, 0x00, 0x52)       // PUSH1 0, MSTORE
	p = append(p, 0x60, 0x20, 0x60, 0x00) // PUSH1 32, PUSH1 0
	p = append(p, 0xf3)                   // RETURN
	return p
}

// bogota7709Config is Bogotá-active (which inherits the Amsterdam table via
// newBogotaInstructionSet); Prague is irrelevant at the vm level.
func bogota7709Config() *params.ChainConfig {
	cfg := *params.MergedTestChainConfig
	cfg.BogotaTime = new(uint64)
	return &cfg
}

// preBogota7709Config is the control config: Bogotá inactive, so BLOCKHASH
// must stay memory-served with GasExtStep.
func preBogota7709Config() *params.ChainConfig {
	cfg := *params.MergedTestChainConfig
	cfg.BogotaTime = nil
	return &cfg
}

// eip7709EVM builds an EVM at block number with the given GetHash function.
// Rules.IsBogota is NOT merge-gated (5920 milestone), so the context keeps
// the XDPoS non-merge shape.
func eip7709EVM(statedb StateDB, cfg *params.ChainConfig, number uint64, getHash func(uint64) common.Hash) *EVM {
	ctx := BlockContext{
		CanTransfer: func(db StateDB, addr common.Address, amount *uint256.Int) bool {
			return db.GetBalance(addr).Cmp(amount) >= 0
		},
		Transfer: func(db StateDB, sender, recipient common.Address, amount *uint256.Int, _ *params.Rules) {
			db.SubBalance(sender, amount, tracing.BalanceChangeTransfer)
			db.AddBalance(recipient, amount, tracing.BalanceChangeTransfer)
		},
		GetHash:          getHash,
		BlockNumber:      new(big.Int).SetUint64(number),
		Time:             0,
		Random:           nil,
		GasLimit:         10000000,
		Difficulty:       big.NewInt(1),
		BaseFee:          big.NewInt(0),
		CostPerStateByte: params.CostPerStateByte,
	}
	return NewEVM(ctx, statedb, cfg, Config{})
}

// runBlockhash deploys code at eip7709Self with committed setup state and
// executes it, returning the returndata and the regular gas consumed.
func runBlockhash(t *testing.T, cfg *params.ChainConfig, number uint64, getHash func(uint64) common.Hash, code []byte, setup func(*state.StateDB)) (ret []byte, gasUsed uint64, statedb *state.StateDB) {
	t.Helper()
	statedb, _ = state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	statedb.CreateAccount(eip7709Self)
	statedb.SetCode(eip7709Self, code, tracing.CodeChangeUnspecified)
	if setup != nil {
		setup(statedb)
	}
	statedb.Finalise(true)
	gas := NewGasBudget(1_000_000, 0)
	ret, result, err := eip7709EVM(statedb, cfg, number, getHash).Call(common.Address{}, eip7709Self, nil, gas, uint256.NewInt(0))
	if err != nil {
		t.Fatalf("call failed: %v", err)
	}
	assertBudgetSane(t, gas, result)
	return ret, 1_000_000 - result.RegularGas, statedb
}

var (
	eip7709RingHash = common.BytesToHash([]byte("ring-block-hash-value-32bytes!"))
	eip7709Sentinel = common.BytesToHash([]byte("memory-served-sentinel-32bytes!"))
)

func zeroHash(uint64) common.Hash { return common.Hash{} }

// TestEIP7709ServesFromRing: under Bogotá an in-window BLOCKHASH must return
// the ring value even when GetHash returns something different (here zero).
func TestEIP7709ServesFromRing(t *testing.T) {
	const n = uint64(1000)
	ret, _, _ := runBlockhash(t, bogota7709Config(), n, zeroHash, blockhashProg(n-1), func(db *state.StateDB) {
		db.CreateAccount(params.HistoryStorageAddress)
		db.SetCode(params.HistoryStorageAddress, params.HistoryStorageCode, tracing.CodeChangeGenesis)
		db.SetState(params.HistoryStorageAddress, ringSlot(n-1), eip7709RingHash)
	})
	if common.BytesToHash(ret) != eip7709RingHash {
		t.Fatalf("BLOCKHASH(n-1) = %x, want ring value %x (must be state-served, not GetHash)", ret, eip7709RingHash)
	}
}

// TestEIP7709WindowBoundaries: serve parent..n-256 from the ring; zero for
// arg == n, arg > n, below-window (n-257), and overflow args — even where
// the ring slot holds a value.
func TestEIP7709WindowBoundaries(t *testing.T) {
	const n = uint64(5000)
	sentinel := func(uint64) common.Hash { return eip7709Sentinel }
	cases := []struct {
		name string
		arg  uint64
		want common.Hash
	}{
		{"parent", n - 1, eip7709RingHash},
		{"window-bottom", n - 256, eip7709RingHash},
		{"below-window", n - 257, common.Hash{}},
		{"self", n, common.Hash{}},
		{"future", n + 1, common.Hash{}},
		{"overflow", ^uint64(0), common.Hash{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ret, _, _ := runBlockhash(t, bogota7709Config(), n, sentinel, blockhashProg(tc.arg), func(db *state.StateDB) {
				db.CreateAccount(params.HistoryStorageAddress)
				db.SetCode(params.HistoryStorageAddress, params.HistoryStorageCode, tracing.CodeChangeGenesis)
				db.SetState(params.HistoryStorageAddress, ringSlot(tc.arg), eip7709RingHash)
				db.SetState(params.HistoryStorageAddress, ringSlot(n-1), eip7709RingHash)
				db.SetState(params.HistoryStorageAddress, ringSlot(n-256), eip7709RingHash)
			})
			if common.BytesToHash(ret) != tc.want {
				t.Fatalf("BLOCKHASH(%d) = %x, want %x", tc.arg, ret, tc.want)
			}
		})
	}
}

// TestEIP7709RingWraparound: slots are n % 8191, so block 8999 and block 808
// share slot 808; the later write must win for both args.
func TestEIP7709RingWraparound(t *testing.T) {
	const n = uint64(9000)
	stale := common.BytesToHash([]byte("stale-hash-from-block-808-32b!"))
	fresh := common.BytesToHash([]byte("fresh-hash-from-block-8999-32b"))
	if ringSlot(808) != ringSlot(8999) {
		t.Fatalf("fixture broken: ringSlot(808) != ringSlot(8999)")
	}
	ret, _, _ := runBlockhash(t, bogota7709Config(), n, zeroHash, blockhashProg(n-1), func(db *state.StateDB) {
		db.CreateAccount(params.HistoryStorageAddress)
		db.SetCode(params.HistoryStorageAddress, params.HistoryStorageCode, tracing.CodeChangeGenesis)
		db.SetState(params.HistoryStorageAddress, ringSlot(808), stale)
		db.SetState(params.HistoryStorageAddress, ringSlot(n-1), fresh) // overwrite slot 808
	})
	if common.BytesToHash(ret) != fresh {
		t.Fatalf("BLOCKHASH(8999) = %x, want overwritten value %x", ret, fresh)
	}
}

// TestEIP7709SloadGasAndWarming: the ring read must charge the original
// GasExtStep base PLUS the additional EIP-8038 SLOAD cost — cold 3000 on
// first touch (with access-list warming), warm 100 on the second read. Per
// the pinned EIP-7709 spec: "charge the additional (cold or warm) storage
// costs"; "the entire semantics and effects of the SLOAD operation" apply.
func TestEIP7709SloadGasAndWarming(t *testing.T) {
	const n = uint64(1000)
	prog := append(pushUint(n-1), 0x40, 0x50) // BLOCKHASH, POP
	prog = append(prog, pushUint(n-1)...)
	prog = append(prog, 0x40, 0x50, 0x00) // BLOCKHASH, POP, STOP
	_, gas, statedb := runBlockhash(t, bogota7709Config(), n, zeroHash, prog, func(db *state.StateDB) {
		db.CreateAccount(params.HistoryStorageAddress)
		db.SetCode(params.HistoryStorageAddress, params.HistoryStorageCode, tracing.CodeChangeGenesis)
		db.SetState(params.HistoryStorageAddress, ringSlot(n-1), eip7709RingHash)
	})
	want := uint64(2*3) + 2*GasExtStep + 2*2 + params.ColdStorageAccessAmsterdam + params.WarmStorageReadCostEIP2929
	if gas != want {
		t.Fatalf("gas consumed = %d, want %d (2×PUSH + 2×base 20 + 2×POP + cold %d + warm %d)", gas, want, params.ColdStorageAccessAmsterdam, params.WarmStorageReadCostEIP2929)
	}
	if _, slotPresent := statedb.SlotInAccessList(params.HistoryStorageAddress, ringSlot(n-1)); !slotPresent {
		t.Fatalf("ring slot for n-1 not warmed into the access list")
	}
}

// TestEIP7709GasOutOfWindow: out-of-window args (n-257, arg == n) keep the
// exact legacy price (PUSH + GasExtStep, no storage cost) and must NOT warm
// or touch the access list — the base cost is preserved, never double
// charged. Control — green before and after; guards the no-double-charge
// requirement.
func TestEIP7709GasOutOfWindow(t *testing.T) {
	const n = uint64(1000)
	prog := append(pushUint(n-257), 0x40, 0x50) // BLOCKHASH(n-257), POP
	prog = append(prog, pushUint(n)...)
	prog = append(prog, 0x40, 0x50, 0x00) // BLOCKHASH(n), POP, STOP
	_, gas, statedb := runBlockhash(t, bogota7709Config(), n, zeroHash, prog, func(db *state.StateDB) {
		db.CreateAccount(params.HistoryStorageAddress)
		db.SetCode(params.HistoryStorageAddress, params.HistoryStorageCode, tracing.CodeChangeGenesis)
		db.SetState(params.HistoryStorageAddress, ringSlot(n-257), eip7709RingHash)
	})
	want := uint64(2*3) + 2*GasExtStep + 2*2 // 2×(PUSH + base 20 + POP), no storage cost
	if gas != want {
		t.Fatalf("out-of-window gas = %d, want %d (2×PUSH + 2×base 20 + 2×POP, no storage cost)", gas, want)
	}
	if addrPresent, slotPresent := statedb.SlotInAccessList(params.HistoryStorageAddress, ringSlot(n-257)); addrPresent || slotPresent {
		t.Fatalf("out-of-window read touched the access list (addr=%v slot=%v)", addrPresent, slotPresent)
	}
}

// TestEIP7709OverflowArg: a uint256 arg that does not fit uint64 must return
// 0 (spec: "arg > current_block_number or overflow → 0") without truncating
// to fit, and charge no storage cost.
func TestEIP7709OverflowArg(t *testing.T) {
	const n = uint64(1000)
	overflow := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1)) // 2^256-1
	prog := append(pushBig(overflow), 0x40, 0x50, 0x00)                               // BLOCKHASH, POP, STOP
	ret, gas, statedb := runBlockhash(t, bogota7709Config(), n, func(uint64) common.Hash { return eip7709Sentinel }, prog, func(db *state.StateDB) {
		db.CreateAccount(params.HistoryStorageAddress)
		db.SetCode(params.HistoryStorageAddress, params.HistoryStorageCode, tracing.CodeChangeGenesis)
		db.SetState(params.HistoryStorageAddress, ringSlot(^uint64(0)), eip7709RingHash)
	})
	_ = ret
	if want := uint64(3) + GasExtStep + 2; gas != want { // PUSH32 + base 20 + POP
		t.Fatalf("overflow-arg gas = %d, want %d (PUSH32 + base 20 + POP, no storage cost)", gas, want)
	}
	if addrPresent, slotPresent := statedb.SlotInAccessList(params.HistoryStorageAddress, ringSlot(^uint64(0))); addrPresent || slotPresent {
		t.Fatalf("overflow-arg read touched the access list (addr=%v slot=%v)", addrPresent, slotPresent)
	}
	// Result check via RETURN-style prog: must be zero, not the truncated GetHash.
	ret, _, _ = runBlockhash(t, bogota7709Config(), n, func(uint64) common.Hash { return eip7709Sentinel },
		append(pushBig(overflow), 0x40, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3), func(db *state.StateDB) {
			db.SetState(params.HistoryStorageAddress, ringSlot(^uint64(0)), eip7709RingHash)
		})
	if common.BytesToHash(ret) != (common.Hash{}) {
		t.Fatalf("BLOCKHASH(2^256-1) = %x, want 0 (no uint64 truncation)", ret)
	}
}

// pushBig encodes a PUSHn of a big.Int (≤32 bytes).
func pushBig(v *big.Int) []byte {
	b := v.Bytes()
	if len(b) == 0 {
		return []byte{0x60, 0x00}
	}
	if len(b) > 32 {
		panic("pushBig: too large")
	}
	return append([]byte{0x5f + byte(len(b))}, b...)
}

// TestEIP7709SmallChainWindow: with n < 256 the spec window is (arg+256) < n
// → every existing ancestor is servable; n-256 must not underflow. Overflow-
// safe boundary test.
func TestEIP7709SmallChainWindow(t *testing.T) {
	const n = uint64(10)
	seed := common.BytesToHash([]byte("genesis-era-blockhash-32bytes!"))
	ret, _, _ := runBlockhash(t, bogota7709Config(), n, zeroHash, blockhashProg(0), func(db *state.StateDB) {
		db.CreateAccount(params.HistoryStorageAddress)
		db.SetCode(params.HistoryStorageAddress, params.HistoryStorageCode, tracing.CodeChangeGenesis)
		db.SetState(params.HistoryStorageAddress, ringSlot(0), seed)
	})
	if common.BytesToHash(ret) != seed {
		t.Fatalf("BLOCKHASH(0) at n=10 = %x, want %x (small-chain window underflowed)", ret, seed)
	}
}

// TestEIP7709IncompleteHistory: a canonical-code contract with a partially
// filled ring serves the present slots and returns 0 for missing ones —
// never panics, never falls back to GetHash.
func TestEIP7709IncompleteHistory(t *testing.T) {
	const n = uint64(1000)
	present := common.BytesToHash([]byte("present-slot-hash-32bytes!!"))
	ret, _, _ := runBlockhash(t, bogota7709Config(), n, zeroHash, blockhashProg(n-2), func(db *state.StateDB) {
		db.CreateAccount(params.HistoryStorageAddress)
		db.SetCode(params.HistoryStorageAddress, params.HistoryStorageCode, tracing.CodeChangeGenesis)
		db.SetState(params.HistoryStorageAddress, ringSlot(n-2), present) // only this slot exists
	})
	if common.BytesToHash(ret) != present {
		t.Fatalf("incomplete ring: BLOCKHASH(n-2) = %x, want present slot %x", ret, present)
	}
	ret, _, _ = runBlockhash(t, bogota7709Config(), n, func(uint64) common.Hash { return eip7709Sentinel }, blockhashProg(n-1), func(db *state.StateDB) {
		db.CreateAccount(params.HistoryStorageAddress)
		db.SetCode(params.HistoryStorageAddress, params.HistoryStorageCode, tracing.CodeChangeGenesis)
		db.SetState(params.HistoryStorageAddress, ringSlot(n-2), present)
	})
	if common.BytesToHash(ret) != (common.Hash{}) {
		t.Fatalf("incomplete ring: BLOCKHASH(n-1) = %x, want 0 (missing slot, no GetHash fallback)", ret)
	}
}

// TestEIP7709FrameTxInherits: the FrameTx instruction set extends the Bogotá
// set, so FrameTx-active chains must serve BLOCKHASH from the ring too.
func TestEIP7709FrameTxInherits(t *testing.T) {
	const n = uint64(1000)
	cfg := *params.MergedTestChainConfig
	cfg.BogotaTime = new(uint64)
	cfg.FrameTxTime = new(uint64)
	ret, _, _ := runBlockhash(t, &cfg, n, zeroHash, blockhashProg(n-1), func(db *state.StateDB) {
		db.CreateAccount(params.HistoryStorageAddress)
		db.SetCode(params.HistoryStorageAddress, params.HistoryStorageCode, tracing.CodeChangeGenesis)
		db.SetState(params.HistoryStorageAddress, ringSlot(n-1), eip7709RingHash)
	})
	if common.BytesToHash(ret) != eip7709RingHash {
		t.Fatalf("FrameTx chain: BLOCKHASH(n-1) = %x, want ring value %x (FrameTx set must inherit Bogotá's 7709)", ret, eip7709RingHash)
	}
}

// TestEIP7709PreBogotaUnchanged: with Bogotá inactive, BLOCKHASH must stay
// memory-served from GetHash at GasExtStep per read. Control — green before
// and after the fix.
func TestEIP7709PreBogotaUnchanged(t *testing.T) {
	const n = uint64(1000)
	// Result: memory-served from GetHash even though the ring slot is seeded.
	ret, _, _ := runBlockhash(t, preBogota7709Config(), n, func(uint64) common.Hash { return eip7709Sentinel }, blockhashProg(n-1), func(db *state.StateDB) {
		db.CreateAccount(params.HistoryStorageAddress)
		db.SetCode(params.HistoryStorageAddress, params.HistoryStorageCode, tracing.CodeChangeGenesis)
		db.SetState(params.HistoryStorageAddress, ringSlot(n-1), eip7709RingHash)
	})
	if common.BytesToHash(ret) != eip7709Sentinel {
		t.Fatalf("pre-Bogotá BLOCKHASH(n-1) = %x, want GetHash sentinel %x (memory-served)", ret, eip7709Sentinel)
	}
	// Gas: PUSH + GasExtStep per read (POP-style prog, no MSTORE tail).
	popProg := append(pushUint(n-1), 0x40, 0x50, 0x00) // BLOCKHASH, POP, STOP
	_, gas, _ := runBlockhash(t, preBogota7709Config(), n, func(uint64) common.Hash { return eip7709Sentinel }, popProg, nil)
	if want := uint64(3) + GasExtStep + 2; gas != want { // PUSH + BLOCKHASH + POP(GasQuickStep)
		t.Fatalf("pre-Bogotá gas = %d, want %d (PUSH + GasExtStep + POP)", gas, want)
	}
}

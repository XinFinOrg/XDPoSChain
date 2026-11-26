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

// Opcode-level tests for EIP-5920 (PAY opcode, 0xfc), activated in the Bogotá
// instruction set. Tests use the raw 0xfc byte and Bogotá rules; pre-activation
// the slot is opUndefined and the execution tests fail (RED) until enable5920
// lands.
//
// Spec: https://eips.ethereum.org/EIPS/eip-5920 (snapshot in the EIP-8141
// evidence tree, hegota-research-20261107/eip-5920-spec-snapshot.md).

package vm

import (
	"bytes"
	"errors"
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/tracing"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/holiman/uint256"
)

const opPAYByte = byte(0xfc)

// bogota5920Config is Bogotá-active, Amsterdam-inactive, exactly as an XDC
// chain would schedule it (the table chain extends Amsterdam, but the config
// gate itself must not require Amsterdam or the merge).
func bogota5920Config() *params.ChainConfig {
	cfg := *params.MergedTestChainConfig
	cfg.BogotaTime = new(uint64)
	return &cfg
}

// bogota5920EVM builds an EVM with a non-merge context (Random nil, i.e.
// isMerge=false, the XDPoS header shape). Bogotá must still be selectable:
// this exercises the NOT-merge-gated Rules.IsBogota predicate directly.
func bogota5920EVM(statedb StateDB) *EVM {
	ctx := BlockContext{
		CanTransfer: func(db StateDB, addr common.Address, amount *uint256.Int) bool {
			return db.GetBalance(addr).Cmp(amount) >= 0
		},
		Transfer: func(db StateDB, sender, recipient common.Address, amount *uint256.Int, _ *params.Rules) {
			db.SubBalance(sender, amount, tracing.BalanceChangeTransfer)
			db.AddBalance(recipient, amount, tracing.BalanceChangeTransfer)
		},
		BlockNumber:      big.NewInt(0),
		Random:           nil,
		CostPerStateByte: params.CostPerStateByte,
	}
	return NewEVM(ctx, statedb, bogota5920Config(), Config{})
}

var paySelf = common.BytesToAddress([]byte("self"))

// mkPayCode assembles PUSH1 val; PUSH20 addr; PAY; STOP.
func mkPayCode(val byte, addr common.Address) []byte {
	code := []byte{0x60, val, 0x73}
	code = append(code, addr.Bytes()...)
	code = append(code, opPAYByte, 0x00)
	return code
}

// runPay deploys code at "self" (funded via setup), executes it with a Call
// under Bogotá rules, and returns the returndata, remaining gas budget and db.
func runPay(t *testing.T, code []byte, setup func(*state.StateDB, common.Address)) ([]byte, GasBudget, *state.StateDB, error) {
	t.Helper()
	statedb, _ := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	statedb.CreateAccount(paySelf)
	statedb.SetCode(paySelf, code, tracing.CodeChangeUnspecified)
	if setup != nil {
		setup(statedb, paySelf)
	}
	statedb.Finalise(true)
	gas := NewGasBudget(1_000_000, 0)
	ret, result, err := bogota5920EVM(statedb).Call(common.Address{}, paySelf, nil, gas, uint256.NewInt(0))
	assertBudgetSane(t, gas, result)
	return ret, result, statedb, err
}

// fundAndWarm funds self and makes other a non-empty, optionally warm account.
func fundAndWarm(db *state.StateDB, self common.Address, other common.Address, warm bool) {
	db.AddBalance(self, uint256.NewInt(1_000_000), tracing.BalanceIncreaseGenesisBalance)
	db.SetNonce(other, 1, tracing.NonceChangeUnspecified)
	if warm {
		db.AddAddressToAccessList(other)
	}
}

// TestEIP5920GasMatrix pins the spec gas table row by row. Each row is
// {warm?, exists?, val} with the exact expected total regular gas, where the
// code is PUSH1 val + PUSH20 addr + PAY + STOP:
//
//	2 pushes = 6 gas, STOP = 0, PAY constant (warm) = 100,
//	cold delta = 2500, value transfer = 9000, new account = 25000.
func TestEIP5920GasMatrix(t *testing.T) {
	const push = uint64(6)
	warm := params.WarmStorageReadCostEIP2929 // 100
	cold := params.ColdAccountAccessCostEIP2929 - params.WarmStorageReadCostEIP2929
	value := params.CallValueTransferGas // 9000
	create := params.CallNewAccountGas   // 25000

	other := common.BytesToAddress([]byte("other-acct"))
	cases := []struct {
		name     string
		warm     bool
		exists   bool
		val      byte
		wantGas  uint64
		wantMove uint64 // wei expected to arrive at `other`
	}{
		{"warm-existing-zeroval", true, true, 0, push + warm, 0},
		{"warm-existing-value", true, true, 5, push + warm + value, 5},
		{"cold-existing-zeroval", false, true, 0, push + warm + cold, 0},
		{"cold-existing-value", false, true, 5, push + warm + cold + value, 5},
		{"warm-newaccount-value", true, false, 5, push + warm + value + create, 5},
		{"cold-newaccount-value", false, false, 5, push + warm + cold + value + create, 5},
		{"cold-newaccount-zeroval", false, false, 0, push + warm + cold, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, result, statedb, err := runPay(t, mkPayCode(c.val, other), func(db *state.StateDB, self common.Address) {
				db.AddBalance(self, uint256.NewInt(1_000_000), tracing.BalanceIncreaseGenesisBalance)
				if c.exists {
					db.SetNonce(other, 1, tracing.NonceChangeUnspecified)
				}
				if c.warm {
					db.AddAddressToAccessList(other)
				}
			})
			if err != nil {
				t.Fatalf("execution failed: %v", err)
			}
			if used := result.UsedRegularGas; used != c.wantGas {
				t.Fatalf("gas used = %d, want %d", used, c.wantGas)
			}
			if bal := statedb.GetBalance(other); bal.Uint64() != c.wantMove {
				t.Fatalf("recipient balance = %d, want %d", bal.Uint64(), c.wantMove)
			}
			if bal := statedb.GetBalance(paySelf); bal.Uint64() != 1_000_000-c.wantMove {
				t.Fatalf("sender balance = %d, want %d", bal.Uint64(), 1_000_000-c.wantMove)
			}
		})
	}
}

// TestEIP5920StackOrder verifies addr is the TOP stack operand (popped
// before val), mirroring CALL's operand order per the spec.
func TestEIP5920StackOrder(t *testing.T) {
	other := common.BytesToAddress([]byte("stack-ordr"))
	_, _, statedb, err := runPay(t, mkPayCode(7, other), func(db *state.StateDB, self common.Address) {
		fundAndWarm(db, self, other, true)
	})
	if err != nil {
		t.Fatalf("execution failed: %v", err)
	}
	if bal := statedb.GetBalance(other); bal.Uint64() != 7 {
		t.Fatalf("recipient balance = %d, want 7 (addr must be the top operand)", bal.Uint64())
	}
}

// TestEIP5920StaticHalt verifies PAY in a static frame halts exceptionally
// and transfers nothing.
func TestEIP5920StaticHalt(t *testing.T) {
	other := common.BytesToAddress([]byte("static-x"))
	statedb, _ := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	statedb.CreateAccount(paySelf)
	statedb.SetCode(paySelf, mkPayCode(5, other), tracing.CodeChangeUnspecified)
	statedb.AddBalance(paySelf, uint256.NewInt(1_000_000), tracing.BalanceIncreaseGenesisBalance)
	statedb.SetNonce(other, 1, tracing.NonceChangeUnspecified)
	statedb.Finalise(true)
	_, _, err := bogota5920EVM(statedb).StaticCall(common.Address{}, paySelf, nil, NewGasBudget(100_000, 0))
	if !errors.Is(err, ErrWriteProtection) {
		t.Fatalf("err = %v, want ErrWriteProtection", err)
	}
	if bal := statedb.GetBalance(other); !bal.IsZero() {
		t.Fatalf("static PAY transferred %d wei, want 0", bal.Uint64())
	}
}

// TestEIP5920AddressRange verifies an address with any high 12 bytes set
// halts exceptionally (spec: exceptional halt, not truncation).
func TestEIP5920AddressRange(t *testing.T) {
	bad := make([]byte, 32)
	bad[0] = 0x01 // most-significant byte set: any of the high 12 bytes non-zero
	bad[19] = 0xaa // low 20 bytes arbitrary
	code := append([]byte{0x60, 0x05, 0x7f}, bad...) // PUSH1 5; PUSH32 bad; PAY
	code = append(code, opPAYByte, 0x00)
	_, _, statedb, err := runPay(t, code, func(db *state.StateDB, self common.Address) {
		db.AddBalance(self, uint256.NewInt(1_000_000), tracing.BalanceIncreaseGenesisBalance)
	})
	if err == nil {
		t.Fatal("expected exceptional halt for high-12-byte address")
	}
	if !errors.Is(err, ErrPayInvalidAddress) {
		t.Fatalf("err = %v, want ErrPayInvalidAddress", err)
	}
	if bal := statedb.GetBalance(common.BytesToAddress(bad[12:])); !bal.IsZero() {
		t.Fatalf("out-of-range PAY transferred %d wei, want 0", bal.Uint64())
	}
}

// TestEIP5920InsufficientBalance verifies a failed transfer pushes 0, moves
// nothing, and does NOT revert the frame (execution succeeds).
func TestEIP5920InsufficientBalance(t *testing.T) {
	other := common.BytesToAddress([]byte("poor-recv"))
	// Code: PUSH1 100; PUSH20 other; PAY; PUSH1 0; MSTORE; PUSH1 32; PUSH1 0; RETURN
	// (mkPayCode's trailing STOP is stripped: code after STOP would be
	// unreachable, and RETURN wants offset 0 / size 32 so ret[31] is the
	// MSTORE'd PAY result byte.)
	code := mkPayCode(100, other)[:3+20+1] // PUSH1 val; PUSH20 addr; PAY — no STOP
	code = append(code, []byte{0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3}...)
	ret, _, statedb, err := runPay(t, code, func(db *state.StateDB, self common.Address) {
		db.AddBalance(self, uint256.NewInt(10), tracing.BalanceIncreaseGenesisBalance)
		db.SetNonce(other, 1, tracing.NonceChangeUnspecified)
		db.AddAddressToAccessList(other)
	})
	if err != nil {
		t.Fatalf("execution must succeed with 0 push on insufficient balance, got %v", err)
	}
	if len(ret) != 32 {
		t.Fatalf("ret length = %d, want 32", len(ret))
	}
	if ret[31] != 0 {
		t.Fatalf("PAY failure push = %v, want 0", ret[31])
	}
	if bal := statedb.GetBalance(other); !bal.IsZero() {
		t.Fatalf("recipient balance = %d, want 0", bal.Uint64())
	}
	if bal := statedb.GetBalance(paySelf); bal.Uint64() != 10 {
		t.Fatalf("sender balance = %d, want 10", bal.Uint64())
	}
}

// TestEIP5920SuccessPush verifies a successful PAY pushes 1, observed via
// RETURN of the MSTORE'd result byte.
func TestEIP5920SuccessPush(t *testing.T) {
	other := common.BytesToAddress([]byte("success-"))
	code := mkPayCode(5, other)[:3+20+1] // strip trailing STOP; see InsufficientBalance
	code = append(code, []byte{0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3}...)
	ret, _, statedb, err := runPay(t, code, func(db *state.StateDB, self common.Address) {
		db.AddBalance(self, uint256.NewInt(1_000), tracing.BalanceIncreaseGenesisBalance)
		db.SetNonce(other, 1, tracing.NonceChangeUnspecified)
		db.AddAddressToAccessList(other)
	})
	if err != nil {
		t.Fatalf("execution failed: %v", err)
	}
	if len(ret) != 32 {
		t.Fatalf("ret length = %d, want 32", len(ret))
	}
	if ret[31] != 1 {
		t.Fatalf("PAY success push = %v, want 1", ret[31])
	}
	if bal := statedb.GetBalance(other); bal.Uint64() != 5 {
		t.Fatalf("recipient balance = %d, want 5", bal.Uint64())
	}
}

// TestEIP5920MarksWarm verifies the first PAY warms addr, so a second PAY in
// the same frame pays no cold-access delta.
func TestEIP5920MarksWarm(t *testing.T) {
	other := common.BytesToAddress([]byte("warm-rec"))
	code := []byte{0x60, 0x01, 0x73}
	code = append(code, other.Bytes()...)
	code = append(code, opPAYByte) // PUSH1 1; PUSH20 other; PAY
	code = append(code, 0x60, 0x02, 0x73)
	code = append(code, other.Bytes()...)
	code = append(code, opPAYByte, 0x00) // PUSH1 2; PUSH20 other; PAY; STOP
	const push = uint64(6)
	want := 2*push + params.WarmStorageReadCostEIP2929 + params.ColdAccountAccessCostEIP2929 - params.WarmStorageReadCostEIP2929 + params.CallValueTransferGas + params.CallNewAccountGas + params.WarmStorageReadCostEIP2929 + params.CallValueTransferGas
	_, result, statedb, err := runPay(t, code, func(db *state.StateDB, self common.Address) {
		db.AddBalance(self, uint256.NewInt(1_000_000), tracing.BalanceIncreaseGenesisBalance)
	})
	if err != nil {
		t.Fatalf("execution failed: %v", err)
	}
	if used := result.UsedRegularGas; used != want {
		t.Fatalf("gas used = %d, want %d (second PAY must be warm: no cold delta)", used, want)
	}
	if bal := statedb.GetBalance(other); bal.Uint64() != 3 {
		t.Fatalf("recipient balance = %d, want 3", bal.Uint64())
	}
}

// TestEIP5920SelfPay verifies PAY to the calling contract itself succeeds
// with net zero balance change.
func TestEIP5920SelfPay(t *testing.T) {
	_, _, statedb, err := runPay(t, mkPayCode(5, paySelf), func(db *state.StateDB, self common.Address) {
		db.AddBalance(self, uint256.NewInt(1_000_000), tracing.BalanceIncreaseGenesisBalance)
		db.AddAddressToAccessList(self)
	})
	if err != nil {
		t.Fatalf("execution failed: %v", err)
	}
	if bal := statedb.GetBalance(paySelf); bal.Uint64() != 1_000_000 {
		t.Fatalf("self-pay changed balance to %d, want 1_000_000", bal.Uint64())
	}
}

// TestEIP5920PreForkUndefined verifies 0xfc stays opUndefined before Bogotá
// (Amsterdam table) and is a real operation in the Bogotá table.
func TestEIP5920PreForkUndefined(t *testing.T) {
	pre := newAmsterdamInstructionSet()
	if !pre[0xfc].undefined {
		t.Fatal("0xfc must be opUndefined pre-Bogotá")
	}
	post := newBogotaInstructionSet()
	if post[0xfc].undefined || post[0xfc].execute == nil {
		t.Fatal("0xfc must be a defined operation in the Bogotá set")
	}
}

// TestEIP5920RulesNotMergeGated pins the XDPoS activation fix: Rules.IsBogota
// must be true with isMerge=false (XDPoS headers never have zero difficulty),
// and remain true with isMerge=true (control — must pass either way).
func TestEIP5920RulesNotMergeGated(t *testing.T) {
	cfg := bogota5920Config()
	if !cfg.Rules(big.NewInt(0), false, 0).IsBogota {
		t.Fatal("Rules.IsBogota is merge-gated: false with isMerge=false (XDPoS shape)")
	}
	if !cfg.Rules(big.NewInt(0), true, 0).IsBogota {
		t.Fatal("Rules.IsBogota false with isMerge=true (control case)")
	}
	// Default presets must stay inactive (nil BogotaTime).
	if params.MainnetChainConfig.Rules(big.NewInt(0), true, 0).IsBogota {
		t.Fatal("mainnet preset must not report IsBogota without BogotaTime")
	}
}

// logCapture wraps a StateDB and records AddLog calls.
type logCapture struct {
	StateDB
	logs []*types.Log
}

func (lc *logCapture) AddLog(l *types.Log) {
	lc.logs = append(lc.logs, l)
	lc.StateDB.AddLog(l)
}

// TestEIP5920AmsterdamTransferLog verifies that with Amsterdam active, a
// non-zero PAY to a different address emits exactly one EIP-7708-style
// EthTransferLog, mirroring the SELFDESTRUCT convention.
func TestEIP5920AmsterdamTransferLog(t *testing.T) {
	other := common.BytesToAddress([]byte("log-recv"))
	cfg := *params.MergedTestChainConfig
	cfg.AmsterdamTime = new(uint64)
	cfg.BogotaTime = new(uint64)

	raw, _ := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	statedb := &logCapture{StateDB: raw}
	statedb.CreateAccount(paySelf)
	statedb.SetCode(paySelf, mkPayCode(5, other), tracing.CodeChangeUnspecified)
	statedb.AddBalance(paySelf, uint256.NewInt(1_000_000), tracing.BalanceIncreaseGenesisBalance)
	statedb.SetNonce(other, 1, tracing.NonceChangeUnspecified)
	statedb.AddAddressToAccessList(other)
	statedb.Finalise(true)

	ctx := BlockContext{
		CanTransfer: func(db StateDB, addr common.Address, amount *uint256.Int) bool {
			return db.GetBalance(addr).Cmp(amount) >= 0
		},
		Transfer: func(db StateDB, sender, recipient common.Address, amount *uint256.Int, _ *params.Rules) {
			db.SubBalance(sender, amount, tracing.BalanceChangeTransfer)
			db.AddBalance(recipient, amount, tracing.BalanceChangeTransfer)
		},
		BlockNumber:      big.NewInt(0),
		Random:           &common.Hash{}, // isMerge=true -> IsAmsterdam active
		CostPerStateByte: params.CostPerStateByte,
	}
	evm := NewEVM(ctx, statedb, &cfg, Config{})
	if _, _, err := evm.Call(common.Address{}, paySelf, nil, NewGasBudget(1_000_000, 0), uint256.NewInt(0)); err != nil {
		t.Fatalf("execution failed: %v", err)
	}
	if len(statedb.logs) != 1 {
		t.Fatalf("log count = %d, want 1", len(statedb.logs))
	}
	log := statedb.logs[0]
	// Canonical EIP-7708 convention (mirrored by types.EthTransferLog and the
	// Amsterdam SELFDESTRUCT path): the emitter is the system address
	// 0xffff…fffe, NOT the transferring contract.
	if log.Address != params.SystemAddress {
		t.Fatalf("log emitter = %x, want system address %x", log.Address, params.SystemAddress)
	}
	// EthTransferLog topics: [keccak("Transfer(address,address,uint256)"), from, to]
	if len(log.Topics) != 3 {
		t.Fatalf("topic count = %d, want 3", len(log.Topics))
	}
	if log.Topics[1] != common.BytesToHash(paySelf.Bytes()) {
		t.Fatalf("topic[1] = %x, want from=%x", log.Topics[1], paySelf)
	}
	if log.Topics[2] != common.BytesToHash(other.Bytes()) {
		t.Fatalf("topic[2] = %x, want to=%x", log.Topics[2], other)
	}
	if !bytes.Equal(log.Data, common.BigToHash(big.NewInt(5)).Bytes()) {
		t.Fatalf("unexpected transfer log data: %x", log.Data)
	}
}

// TestEIP5920TxLevelEffects verifies balance moves survive frame semantics:
// after a successful Call, statedb balances reflect the PAY.
func TestEIP5920TxLevelEffects(t *testing.T) {
	other := common.BytesToAddress([]byte("tx-level"))
	_, _, statedb, err := runPay(t, mkPayCode(5, other), func(db *state.StateDB, self common.Address) {
		fundAndWarm(db, self, other, true)
	})
	if err != nil {
		t.Fatalf("execution failed: %v", err)
	}
	if bal := statedb.GetBalance(other); bal.Uint64() != 5 {
		t.Fatalf("post-call recipient balance = %d, want 5", bal.Uint64())
	}
}

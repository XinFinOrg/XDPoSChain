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

package state

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/tracing"
	"github.com/XinFinOrg/XDPoSChain/core/types"
)

var (
	eip8246Addr  = common.HexToAddress("0x8246824682468246824682468246824682468246")
	eip8246Slot  = common.HexToHash("0x05")
	eip8246Value = common.HexToHash("0x2a")
	// eip8246Code is the probe initcode shared with core/eip8246_test.go:
	// PUSH1 0x2a; PUSH1 0x05; SSTORE; ADDRESS; SELFDESTRUCT.
	eip8246Code = []byte{0x60, 0x2a, 0x60, 0x05, 0x55, 0x30, 0xff}
)

// newContractInTx returns a session in which addr has been deployed by the
// current transaction, the way evm.create sets it up before running the
// initcode: the account exists, is flagged as a new contract, has nonce 1, and
// carries the given code and storage.
func newContractInTx(t *testing.T, balance *big.Int) (*StateDB, Database) {
	t.Helper()

	db := NewDatabaseForTesting()
	sd, err := New(types.EmptyRootHash, db)
	if err != nil {
		t.Fatalf("failed to create statedb: %v", err)
	}
	sd.CreateAccount(eip8246Addr)
	sd.CreateContract(eip8246Addr)
	sd.SetNonce(eip8246Addr, 1, tracing.NonceChangeNewContract)
	sd.SetCode(eip8246Addr, eip8246Code)
	sd.SetState(eip8246Addr, eip8246Slot, eip8246Value)
	if balance.Sign() != 0 {
		sd.AddBalance(eip8246Addr, balance, tracing.BalanceChangeUnspecified)
	}
	return sd, db
}

// commitAndReopen commits the given session and opens a fresh one over the new root.
func commitAndReopen(t *testing.T, sd *StateDB, db Database) *StateDB {
	t.Helper()

	root, err := sd.Commit(0, true)
	if err != nil {
		t.Fatalf("failed to commit state: %v", err)
	}
	if err := db.TrieDB().Commit(root, false); err != nil {
		t.Fatalf("failed to commit trie: %v", err)
	}
	fresh, err := New(root, db)
	if err != nil {
		t.Fatalf("failed to reopen statedb: %v", err)
	}
	return fresh
}

// TestEIP8246SelfDestructPreservesBalance verifies that, on Amsterdam, a
// contract created and self-destructed to itself in the same transaction keeps
// its balance while its nonce, code and storage are cleared at finalisation.
func TestEIP8246SelfDestructPreservesBalance(t *testing.T) {
	balance := big.NewInt(1234)
	sd, db := newContractInTx(t, balance)

	prev, destructed := sd.SelfDestruct6780(eip8246Addr, true)
	if !destructed {
		t.Fatalf("new contract was not marked for destruction")
	}
	if prev.Cmp(balance) != 0 {
		t.Errorf("prior balance = %v, want %v", prev, balance)
	}
	// EIP-8246 item 1: the balance is not burnt at the instruction level.
	if got := sd.GetBalance(eip8246Addr); got.Cmp(balance) != 0 {
		t.Errorf("balance after self-destruct = %v, want %v", got, balance)
	}
	sd.Finalise(true)

	assertBalanceOnlyAccount(t, sd, balance)
	assertBalanceOnlyAccount(t, commitAndReopen(t, sd, db), balance)
}

// TestEIP8246SelfDestructZeroBalanceDeleted verifies that a preserved account
// whose balance is zero is still removed by EIP-161 at finalisation.
func TestEIP8246SelfDestructZeroBalanceDeleted(t *testing.T) {
	sd, db := newContractInTx(t, new(big.Int))

	if _, destructed := sd.SelfDestruct6780(eip8246Addr, true); !destructed {
		t.Fatalf("new contract was not marked for destruction")
	}
	sd.Finalise(true)

	if sd.Exist(eip8246Addr) {
		t.Errorf("zero-balance destructed account still exists")
	}
	if root := commitAndReopen(t, sd, db); root.Exist(eip8246Addr) {
		t.Errorf("zero-balance destructed account survived the commit")
	}
}

// TestEIP8246SelfDestructKeepsLateFunds verifies EIP-8246 item 2: ether sent to
// a destructed account later in the same transaction is preserved instead of
// burnt at finalisation.
func TestEIP8246SelfDestructKeepsLateFunds(t *testing.T) {
	balance := big.NewInt(1234)
	sd, db := newContractInTx(t, balance)

	sd.SelfDestruct6780(eip8246Addr, true)
	sd.AddBalance(eip8246Addr, big.NewInt(7), tracing.BalanceChangeUnspecified)
	sd.Finalise(true)

	want := new(big.Int).Add(balance, big.NewInt(7))
	assertBalanceOnlyAccount(t, sd, want)
	assertBalanceOnlyAccount(t, commitAndReopen(t, sd, db), want)
}

// TestEIP8246SelfDestructToOtherKeepsLateFunds covers the other EIP-8246
// finalisation shape: the contract sends its balance to a beneficiary and is
// removed, then receives ether before finalisation, which must survive as the
// balance of the balance-only account instead of being burnt.
func TestEIP8246SelfDestructToOtherKeepsLateFunds(t *testing.T) {
	balance := big.NewInt(1234)
	beneficiary := common.HexToAddress("0xbeef")
	sd, db := newContractInTx(t, balance)

	sd.SubBalance(eip8246Addr, balance, tracing.BalanceDecreaseSelfdestruct)
	sd.AddBalance(beneficiary, balance, tracing.BalanceIncreaseSelfdestruct)
	sd.SelfDestruct6780(eip8246Addr, true)
	sd.AddBalance(eip8246Addr, big.NewInt(7), tracing.BalanceChangeUnspecified)
	sd.Finalise(true)

	if got := sd.GetBalance(beneficiary); got.Cmp(balance) != 0 {
		t.Errorf("beneficiary balance = %v, want %v", got, balance)
	}
	assertBalanceOnlyAccount(t, sd, big.NewInt(7))
	assertBalanceOnlyAccount(t, commitAndReopen(t, sd, db), big.NewInt(7))
}

// TestEIP8246SelfDestructReverted verifies that reverting a preserved
// self-destruct restores the account, including its balance and flags.
func TestEIP8246SelfDestructReverted(t *testing.T) {
	balance := big.NewInt(1234)
	sd, _ := newContractInTx(t, balance)

	snapshot := sd.Snapshot()
	sd.SelfDestruct6780(eip8246Addr, true)
	if !sd.HasSelfDestructed(eip8246Addr) {
		t.Fatalf("account not marked as destructed before the revert")
	}
	sd.RevertToSnapshot(snapshot)

	if sd.HasSelfDestructed(eip8246Addr) {
		t.Errorf("account still marked as destructed after the revert")
	}
	sd.Finalise(true)
	if sd.GetBalance(eip8246Addr).Cmp(balance) != 0 {
		t.Errorf("balance after revert and finalise = %v, want %v", sd.GetBalance(eip8246Addr), balance)
	}
	if sd.GetNonce(eip8246Addr) != 1 {
		t.Errorf("nonce after revert and finalise = %d, want 1", sd.GetNonce(eip8246Addr))
	}
	if len(sd.GetCode(eip8246Addr)) == 0 {
		t.Errorf("code after revert and finalise is empty")
	}
	if got := sd.GetState(eip8246Addr, eip8246Slot); got != eip8246Value {
		t.Errorf("storage after revert and finalise = %x, want %x", got, eip8246Value)
	}
}

// TestSelfDestructBurnsWithoutEIP8246 pins the pre-Amsterdam behaviour: the
// balance is burnt at the instruction and any ether arriving before finalisation
// is burnt there.
func TestSelfDestructBurnsWithoutEIP8246(t *testing.T) {
	sd, db := newContractInTx(t, big.NewInt(1234))

	sd.SelfDestruct6780(eip8246Addr, false)
	if got := sd.GetBalance(eip8246Addr); got.Sign() != 0 {
		t.Errorf("balance after pre-Amsterdam self-destruct = %v, want 0", got)
	}
	sd.AddBalance(eip8246Addr, big.NewInt(7), tracing.BalanceChangeUnspecified)
	sd.Finalise(true)

	if sd.Exist(eip8246Addr) {
		t.Errorf("destructed account still exists")
	}
	if fresh := commitAndReopen(t, sd, db); fresh.Exist(eip8246Addr) {
		t.Errorf("destructed account survived the commit")
	}
}

// TestEIP8246PreservesBalanceOfPreexistingAccount verifies the finalisation
// path for an account that existed before the block and is deployed to and
// destroyed within one transaction. Its original storage has to be wiped while
// the balance survives.
//
// The shape itself is not reachable through the EVM: evm.create rejects an
// address whose storage root is non-empty with ErrContractAddressCollision, so
// a block-start account carrying storage can never be deployed to. It is kept
// to pin the storage-wiping bookkeeping; the reachable prefunded shape, and the
// block diff it leaves behind, is covered by
// TestEIP8246PreservedAccountKeepsBlockOrigin.
//
// Unlike upstream go-ethereum #35219, which rebuilds the account from its origin
// and therefore keeps the origin's code and storage root, this tree rebuilds it
// from nil and clears both. The difference is confined to this unreachable
// shape.
func TestEIP8246PreservesBalanceOfPreexistingAccount(t *testing.T) {
	db := NewDatabaseForTesting()

	// Seed the account and commit it, so the object has a non-nil origin.
	sd, err := New(types.EmptyRootHash, db)
	if err != nil {
		t.Fatalf("failed to create statedb: %v", err)
	}
	sd.AddBalance(eip8246Addr, big.NewInt(1234), tracing.BalanceChangeUnspecified)
	sd.SetCode(eip8246Addr, eip8246Code)
	sd.SetState(eip8246Addr, eip8246Slot, eip8246Value)
	root, err := sd.Commit(0, false)
	if err != nil {
		t.Fatalf("failed to commit state: %v", err)
	}
	if err := db.TrieDB().Commit(root, false); err != nil {
		t.Fatalf("failed to commit trie: %v", err)
	}

	sd, err = New(root, db)
	if err != nil {
		t.Fatalf("failed to reopen statedb: %v", err)
	}
	sd.CreateContract(eip8246Addr) // deployed to in this transaction
	sd.SelfDestruct6780(eip8246Addr, true)
	sd.Finalise(true)

	assertBalanceOnlyAccount(t, sd, big.NewInt(1234))
	assertBalanceOnlyAccount(t, commitAndReopen(t, sd, db), big.NewInt(1234))
}

// TestEIP8246PreservedAccountKeepsBlockOrigin verifies that the reborn
// balance-only account keeps the origin of the account it replaced: the
// block-level diff has to record the account as existing at block start,
// otherwise a consumer reading the diff before the commit sees a nil origin.
// The shape is the reachable one - a prefunded, codeless account is not reset
// by evm.create (CreateAccount is only called when the address does not exist)
// and is marked as a new contract instead, which makes it destructible.
func TestEIP8246PreservedAccountKeepsBlockOrigin(t *testing.T) {
	db := NewDatabaseForTesting()

	// Seed a balance-only account, the way a plain transfer would.
	balance := big.NewInt(1234)
	sd, err := New(types.EmptyRootHash, db)
	if err != nil {
		t.Fatalf("failed to create statedb: %v", err)
	}
	sd.AddBalance(eip8246Addr, balance, tracing.BalanceChangeUnspecified)
	root, err := sd.Commit(0, false)
	if err != nil {
		t.Fatalf("failed to commit state: %v", err)
	}
	if err := db.TrieDB().Commit(root, false); err != nil {
		t.Fatalf("failed to commit trie: %v", err)
	}
	sd, err = New(root, db)
	if err != nil {
		t.Fatalf("failed to reopen statedb: %v", err)
	}
	seeded := sd.getStateObject(eip8246Addr)
	if seeded == nil || seeded.origin == nil {
		t.Fatalf("seeded account has no origin")
	}
	wantOrigin := types.SlimAccountRLP(*seeded.origin)

	// Mirror evm.create: reuse the existing object, mark it as a contract of
	// this transaction, then let it self-destruct to itself.
	sd.CreateContract(eip8246Addr)
	sd.SelfDestruct6780(eip8246Addr, true)
	sd.Finalise(true)
	sd.IntermediateRoot(true)

	got, ok := sd.accountsOrigin[eip8246Addr]
	if !ok {
		t.Errorf("block diff does not track the preserved account")
	} else if !bytes.Equal(got, wantOrigin) {
		t.Errorf("block diff origin = %x, want %x", got, wantOrigin)
	}
	assertBalanceOnlyAccount(t, sd, balance)
	assertBalanceOnlyAccount(t, commitAndReopen(t, sd, db), balance)
}

// TestEIP8246HookedFinaliseSkipsBurn verifies that a tracer is not told about a
// burn that EIP-8246 removed.
func TestEIP8246HookedFinaliseSkipsBurn(t *testing.T) {
	sd, _ := newContractInTx(t, big.NewInt(1234))

	var (
		decreases int
		burns     int
	)
	hooked := NewHookedState(sd, &tracing.Hooks{
		OnBalanceChange: func(addr common.Address, prev, new *big.Int, reason tracing.BalanceChangeReason) {
			switch reason {
			case tracing.BalanceDecreaseSelfdestruct:
				decreases++
			case tracing.BalanceDecreaseSelfdestructBurn:
				burns++
			}
		},
	})
	hooked.SelfDestruct6780(eip8246Addr, true)
	hooked.AddBalance(eip8246Addr, big.NewInt(7), tracing.BalanceChangeUnspecified)
	hooked.Finalise(true)

	if decreases != 0 || burns != 0 {
		t.Errorf("preserved self-destruct reported %d decreases and %d burns, want none", decreases, burns)
	}
	if got := sd.GetBalance(eip8246Addr); got.Cmp(big.NewInt(1241)) != 0 {
		t.Errorf("balance after hooked finalise = %v, want 1241", got)
	}
}

// TestSelfDestructHookedBurnWithoutEIP8246 pins the pre-Amsterdam hooks: the
// destruct reports the balance decrease, and ether arriving afterwards is
// reported as burnt at finalisation.
func TestSelfDestructHookedBurnWithoutEIP8246(t *testing.T) {
	sd, _ := newContractInTx(t, big.NewInt(1234))

	var (
		decreases int
		burns     int
		burned    = new(big.Int)
	)
	hooked := NewHookedState(sd, &tracing.Hooks{
		OnBalanceChange: func(addr common.Address, prev, new *big.Int, reason tracing.BalanceChangeReason) {
			switch reason {
			case tracing.BalanceDecreaseSelfdestruct:
				decreases++
			case tracing.BalanceDecreaseSelfdestructBurn:
				burns++
				burned.Add(burned, prev)
			}
		},
	})
	hooked.SelfDestruct6780(eip8246Addr, false)
	hooked.AddBalance(eip8246Addr, big.NewInt(7), tracing.BalanceChangeUnspecified)
	hooked.Finalise(true)

	if decreases != 1 {
		t.Errorf("destruct reported %d decreases, want 1", decreases)
	}
	if burns != 1 || burned.Cmp(big.NewInt(7)) != 0 {
		t.Errorf("finalise reported %d burns (total %v), want 1 burn of 7", burns, burned)
	}
}

// assertBalanceOnlyAccount checks that addr holds exactly want and carries no
// nonce, code or storage, as EIP-8246 requires of a preserved account.
func assertBalanceOnlyAccount(t *testing.T, sd *StateDB, want *big.Int) {
	t.Helper()

	if !sd.Exist(eip8246Addr) {
		t.Fatalf("balance-only account does not exist")
	}
	if got := sd.GetBalance(eip8246Addr); got.Cmp(want) != 0 {
		t.Errorf("balance = %v, want %v", got, want)
	}
	if got := sd.GetNonce(eip8246Addr); got != 0 {
		t.Errorf("nonce = %d, want 0", got)
	}
	if code := sd.GetCode(eip8246Addr); len(code) != 0 {
		t.Errorf("code = %x, want empty", code)
	}
	if got := sd.GetState(eip8246Addr, eip8246Slot); got != (common.Hash{}) {
		t.Errorf("storage = %x, want empty", got)
	}
	if got := sd.GetStorageRoot(eip8246Addr); got != types.EmptyRootHash {
		t.Errorf("storage root = %x, want %x", got, types.EmptyRootHash)
	}
	if got := sd.GetCodeHash(eip8246Addr); got != types.EmptyCodeHash {
		t.Errorf("code hash = %x, want %x", got, types.EmptyCodeHash)
	}
	if sd.HasSelfDestructed(eip8246Addr) {
		t.Errorf("preserved account is still marked as destructed")
	}
}

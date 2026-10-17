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
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/tracing"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/ethdb"
)

// newDeleteAddressState returns an address holding balance 1234 and some
// code, committed to db under root, together with a statedb session opened
// over that root.
func newDeleteAddressState(t *testing.T) (addr common.Address, root common.Hash, sd *StateDB, db ethdb.Database) {
	t.Helper()

	addr = common.BytesToAddress([]byte("deleteaddress"))
	db = rawdb.NewMemoryDatabase()

	sdb, err := New(types.EmptyRootHash, NewDatabase(db))
	if err != nil {
		t.Fatalf("failed to create statedb: %v", err)
	}
	sdb.AddBalance(addr, big.NewInt(1234), tracing.BalanceChangeUnspecified)
	sdb.SetCode(addr, []byte{0x60, 0x00})
	root, err = sdb.Commit(0, false)
	if err != nil {
		t.Fatalf("failed to commit state: %v", err)
	}
	if err := sdb.Database().TrieDB().Commit(root, false); err != nil {
		t.Fatalf("failed to commit trie: %v", err)
	}
	sd, err = New(root, NewDatabase(db))
	if err != nil {
		t.Fatalf("failed to reopen statedb: %v", err)
	}
	return addr, root, sd, db
}

// DeleteAddress must be visible to the rest of the session: reads after the
// removal report the account as absent, and a statedb rebuilt from the
// resulting root agrees with the in-session view. Regression test for the
// session cache not being invalidated (#2611).
func TestDeleteAddressVisibleInSameSession(t *testing.T) {
	addr, root0, sd, db := newDeleteAddressState(t)

	// Pre-removal sanity: the account is readable.
	if got := sd.GetBalance(addr); got == nil || got.Int64() != 1234 {
		t.Fatalf("pre-removal balance: have %v, want 1234", got)
	}
	if len(sd.GetCode(addr)) == 0 {
		t.Fatalf("pre-removal code: empty, want the committed code")
	}

	sd.DeleteAddress(addr)

	if got := sd.GetBalance(addr); got == nil || got.Sign() != 0 {
		t.Errorf("balance after DeleteAddress: have %v, want 0", got)
	}
	if sd.Exist(addr) {
		t.Errorf("account still exists after DeleteAddress")
	}
	if code := sd.GetCode(addr); len(code) != 0 {
		t.Errorf("code after DeleteAddress: have %x, want empty", code)
	}
	if hash := sd.GetCodeHash(addr); hash != (common.Hash{}) {
		t.Errorf("code hash after DeleteAddress: have %x, want zero", hash)
	}

	root1, err := sd.Commit(0, false)
	if err != nil {
		t.Fatalf("failed to commit state: %v", err)
	}
	if root1 == root0 {
		t.Fatalf("state root unchanged after DeleteAddress: %x", root1)
	}
	if err := sd.Database().TrieDB().Commit(root1, false); err != nil {
		t.Fatalf("failed to commit trie: %v", err)
	}
	// A statedb constructed fresh from the resulting root must not see the
	// account either, i.e. the in-session view matches the final state.
	fresh, err := New(root1, NewDatabase(db))
	if err != nil {
		t.Fatalf("failed to open statedb over new root: %v", err)
	}
	if fresh.Exist(addr) {
		t.Errorf("account exists in a fresh session over the post-deletion root")
	}
	if got := fresh.GetBalance(addr); got == nil || got.Sign() != 0 {
		t.Errorf("balance in a fresh session over the post-deletion root: have %v, want 0", got)
	}
}

// DeleteAddress on an account that does not exist must be a no-op.
func TestDeleteAddressNonExistent(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	sd, err := New(types.EmptyRootHash, NewDatabase(db))
	if err != nil {
		t.Fatalf("failed to create statedb: %v", err)
	}
	addr := common.BytesToAddress([]byte("absent"))

	sd.DeleteAddress(addr)

	if sd.Exist(addr) {
		t.Errorf("account exists after DeleteAddress of a non-existent address")
	}
	if root := sd.IntermediateRoot(false); root != types.EmptyRootHash {
		t.Errorf("state root changed after DeleteAddress of a non-existent address: have %x, want %x", root, types.EmptyRootHash)
	}
}

// Deleting an account whose update was finalised but not applied yet must not
// leave a stale update mutation behind. The Byzantium transaction path
// finalises the state without applying the mutations, so a pending update
// would otherwise be applied against an object that no longer exists and
// panic in updateStateObject. DeleteAddress must record a deletion mutation
// instead, the same invariant the self-destruct finalisation path keeps.
func TestDeleteAddressReplacesPendingUpdate(t *testing.T) {
	addr, _, sd, db := newDeleteAddressState(t)

	// Modify the account and finalise it without applying the mutation,
	// the way finaliseTxState does per transaction on Byzantium blocks.
	sd.AddBalance(addr, big.NewInt(1), tracing.BalanceChangeUnspecified)
	sd.Finalise(true)

	sd.DeleteAddress(addr)

	root1, err := sd.Commit(0, false)
	if err != nil {
		t.Fatalf("failed to commit state: %v", err)
	}
	if err := sd.Database().TrieDB().Commit(root1, false); err != nil {
		t.Fatalf("failed to commit trie: %v", err)
	}
	fresh, err := New(root1, NewDatabase(db))
	if err != nil {
		t.Fatalf("failed to open statedb over new root: %v", err)
	}
	if fresh.Exist(addr) {
		t.Errorf("account exists in a fresh session over the post-deletion root")
	}
}

// Removing an account must not make it unreadable if it is recreated later
// in the same session; the removal is a destruct-and-maybe-resurrect
// transition, exactly like the self-destruct path.
func TestDeleteAddressThenRecreateSameSession(t *testing.T) {
	addr, _, sd, db := newDeleteAddressState(t)

	sd.DeleteAddress(addr)
	if sd.Exist(addr) {
		t.Fatalf("account still exists after DeleteAddress")
	}

	sd.AddBalance(addr, big.NewInt(7), tracing.BalanceChangeUnspecified)

	if got := sd.GetBalance(addr); got == nil || got.Int64() != 7 {
		t.Errorf("balance after recreating the account: have %v, want 7", got)
	}
	if !sd.Exist(addr) {
		t.Errorf("recreated account does not exist")
	}
	root1, err := sd.Commit(0, false)
	if err != nil {
		t.Fatalf("failed to commit state: %v", err)
	}
	if err := sd.Database().TrieDB().Commit(root1, false); err != nil {
		t.Fatalf("failed to commit trie: %v", err)
	}
	fresh, err := New(root1, NewDatabase(db))
	if err != nil {
		t.Fatalf("failed to open statedb over new root: %v", err)
	}
	if got := fresh.GetBalance(addr); got == nil || got.Int64() != 7 {
		t.Errorf("balance in a fresh session over the post-recreate root: have %v, want 7", got)
	}
}

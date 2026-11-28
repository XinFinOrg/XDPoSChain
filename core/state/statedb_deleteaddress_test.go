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
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/tracing"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/ethdb"
	"github.com/XinFinOrg/XDPoSChain/trie/trienode"
)

// newDeleteAddressState commits an address holding balance, code and one
// storage slot, and returns a session opened over that root.
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
	sdb.SetState(addr, common.HexToHash("0x01"), common.HexToHash("0x42"))
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

// TestDeleteAddressVisibleInSameSession pins that reads after the removal
// report the account as absent, matching a session rebuilt from the new root.
func TestDeleteAddressVisibleInSameSession(t *testing.T) {
	addr, root0, sd, db := newDeleteAddressState(t)

	// Pre-removal sanity: the account is readable.
	if got := sd.GetBalance(addr); got.Int64() != 1234 {
		t.Fatalf("pre-removal balance: have %v, want 1234", got)
	}
	if len(sd.GetCode(addr)) == 0 {
		t.Fatalf("pre-removal code: empty, want the committed code")
	}

	sd.DeleteAddress(addr)

	if got := sd.GetBalance(addr); got.Sign() != 0 {
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
	if slot := sd.GetState(addr, common.HexToHash("0x01")); slot != (common.Hash{}) {
		t.Errorf("storage slot after DeleteAddress: have %x, want empty", slot)
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
	// A fresh session over the new root must agree with the in-session view.
	fresh, err := New(root1, NewDatabase(db))
	if err != nil {
		t.Fatalf("failed to open statedb over new root: %v", err)
	}
	if fresh.Exist(addr) {
		t.Errorf("account exists in a fresh session over the post-deletion root")
	}
	if got := fresh.GetBalance(addr); got.Sign() != 0 {
		t.Errorf("balance in a fresh session over the post-deletion root: have %v, want 0", got)
	}
	if slot := fresh.GetState(addr, common.HexToHash("0x01")); slot != (common.Hash{}) {
		t.Errorf("storage slot in a fresh session over the post-deletion root: have %x, want empty", slot)
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

// TestDeleteAddressReplacesPendingUpdate pins that the deletion replaces a
// pending update mutation; otherwise Commit would update a missing object.
func TestDeleteAddressReplacesPendingUpdate(t *testing.T) {
	addr, _, sd, db := newDeleteAddressState(t)

	// Finalise without applying the mutation, as finaliseTxState does per Byzantium transaction.
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

// TestDeleteAddressRevertRestoresAccount pins the journalling of the removal:
// reverting to a snapshot taken before the call brings the account back instead
// of leaving the journal revert to read a missing object.
func TestDeleteAddressRevertRestoresAccount(t *testing.T) {
	addr, root0, sd, _ := newDeleteAddressState(t)

	snap := sd.Snapshot()
	sd.AddBalance(addr, big.NewInt(5), tracing.BalanceChangeUnspecified)
	sd.DeleteAddress(addr)
	if sd.Exist(addr) {
		t.Fatalf("account still exists after DeleteAddress")
	}

	sd.RevertToSnapshot(snap)

	if got := sd.GetBalance(addr); got.Int64() != 1234 {
		t.Errorf("balance after the revert: have %v, want 1234", got)
	}
	if !sd.Exist(addr) {
		t.Fatalf("account not restored by the revert")
	}
	if code := sd.GetCode(addr); len(code) != 2 {
		t.Errorf("code after the revert: have %x, want the committed code", code)
	}
	if got := sd.GetState(addr, common.HexToHash("0x01")); got != common.HexToHash("0x42") {
		t.Errorf("storage after the revert: have %x, want 0x42", got)
	}
	root1, err := sd.Commit(0, false)
	if err != nil {
		t.Fatalf("failed to commit state: %v", err)
	}
	if root1 != root0 {
		t.Errorf("state root after the revert: have %x, want %x", root1, root0)
	}
}

// TestDeleteAddressThenRecreateSameSession pins destruct-and-resurrect in one
// session, like the self-destruct path.
func TestDeleteAddressThenRecreateSameSession(t *testing.T) {
	addr, _, sd, db := newDeleteAddressState(t)

	sd.DeleteAddress(addr)
	if sd.Exist(addr) {
		t.Fatalf("account still exists after DeleteAddress")
	}

	sd.AddBalance(addr, big.NewInt(7), tracing.BalanceChangeUnspecified)

	if got := sd.GetBalance(addr); got.Int64() != 7 {
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
	if got := fresh.GetBalance(addr); got.Int64() != 7 {
		t.Errorf("balance in a fresh session over the post-recreate root: have %v, want 7", got)
	}
}

// TestDeleteAddressTracksDestruction pins that the destruct marker feeds
// handleDestruction: the original account and storage are recorded as deleted.
func TestDeleteAddressTracksDestruction(t *testing.T) {
	addr, _, sd, _ := newDeleteAddressState(t)

	sd.DeleteAddress(addr)
	if _, ok := sd.stateObjectsDestruct[addr]; !ok {
		t.Fatalf("account not marked destructed")
	}
	nodes := trienode.NewMergedNodeSet()
	if _, err := sd.handleDestruction(nodes); err != nil {
		t.Fatalf("handleDestruction: %v", err)
	}
	if sd.accountsOrigin[addr] == nil {
		t.Errorf("original account not recorded as a deletion")
	}
	deleted := 0
	for _, set := range nodes.Sets {
		_, n := set.Size()
		deleted += n
	}
	if deleted == 0 {
		t.Errorf("original storage not recorded as deleted")
	}
}

// TestDeleteAddressRevertAfterCreate pins the revert of a deletion when the
// account was created and removed after the snapshot: the creation is rolled
// back too, so the revert must not leave an update mutation without an object.
func TestDeleteAddressRevertAfterCreate(t *testing.T) {
	_, root0, sd, _ := newDeleteAddressState(t)
	addr := common.BytesToAddress([]byte("created-and-deleted"))

	snap := sd.Snapshot()
	sd.AddBalance(addr, big.NewInt(5), tracing.BalanceChangeUnspecified)
	sd.DeleteAddress(addr)
	sd.RevertToSnapshot(snap)

	// The creation never crossed a transaction boundary, so neither origin map
	// held an entry at capture time. Reverting must restore that absence rather
	// than resurrect the keys with an explicit nil, which updateStateObject
	// would take as already recorded.
	if _, ok := sd.accountsOrigin[addr]; ok {
		t.Errorf("accountsOrigin resurrected as an explicit nil after the revert")
	}
	if _, ok := sd.storagesOrigin[addr]; ok {
		t.Errorf("storagesOrigin resurrected as an explicit nil after the revert")
	}

	if sd.Exist(addr) {
		t.Fatalf("account still exists after reverting its creation")
	}
	if root := sd.IntermediateRoot(false); root != root0 {
		t.Fatalf("state root after the revert: have %x, want %x", root, root0)
	}
}

// TestDeleteAddressRevertKeepsDestructMarker pins that a marker recorded before
// the snapshot survives the revert: dropping it would leave handleDestruction
// without the original account of a same-block resurrect.
func TestDeleteAddressRevertKeepsDestructMarker(t *testing.T) {
	addr, _, sd, _ := newDeleteAddressState(t)

	sd.SelfDestruct(addr)
	sd.IntermediateRoot(false)

	sd.AddBalance(addr, big.NewInt(1), tracing.BalanceChangeUnspecified)
	snap := sd.Snapshot()
	sd.DeleteAddress(addr)
	sd.RevertToSnapshot(snap)

	if _, ok := sd.stateObjectsDestruct[addr]; !ok {
		t.Fatalf("destruct marker lost after the revert")
	}
	// The resurrected object has no origin of its own, so only the restored
	// marker can make handleDestruction record the original account.
	sd.IntermediateRoot(false)
	nodes := trienode.NewMergedNodeSet()
	if _, err := sd.handleDestruction(nodes); err != nil {
		t.Fatalf("handleDestruction: %v", err)
	}
	if sd.accountsOrigin[addr] == nil {
		t.Fatalf("original account not recorded after the revert")
	}
}

// TestDeleteAddressRevertKeepsDestructedBalance pins that the burn a destruct
// has cleared so far survives a DeleteAddress that is reverted again: without
// it the account stays marked destructed but finalisation reports no burn.
func TestDeleteAddressRevertKeepsDestructedBalance(t *testing.T) {
	burned, balanceHook := burnRecorder()
	s, _ := New(types.EmptyRootHash, NewDatabaseForTesting())
	hooked := NewHookedState(s, &tracing.Hooks{OnBalanceChange: balanceHook})
	addr := common.Address{0xaa}

	hooked.AddBalance(addr, big.NewInt(100), tracing.BalanceChangeUnspecified)
	hooked.CreateContract(addr)
	hooked.SelfDestruct(addr)

	snap := hooked.Snapshot()
	hooked.DeleteAddress(addr)
	hooked.RevertToSnapshot(snap)
	hooked.Finalise(true)

	if burned.Cmp(big.NewInt(100)) != 0 {
		t.Fatalf("burn after the DeleteAddress revert = %v, want 100", burned)
	}
}

// TestDeleteAddressRevertRestoresOrigins pins that the block-scoped origin caches
// cleared by the removal are restored, so the commit keeps the original values.
func TestDeleteAddressRevertRestoresOrigins(t *testing.T) {
	addr, _, sd, _ := newDeleteAddressState(t)

	sd.SetState(addr, common.HexToHash("0x02"), common.HexToHash("0x77"))
	sd.IntermediateRoot(false)
	if sd.storagesOrigin[addr] == nil {
		t.Fatalf("fixture: storagesOrigin not populated by the first transaction")
	}
	if sd.accountsOrigin[addr] == nil {
		t.Fatalf("fixture: accountsOrigin not populated by the first transaction")
	}
	wantStoragesOrigin := copyStorageMap(sd.storagesOrigin[addr])
	wantAccountsOrigin := common.CopyBytes(sd.accountsOrigin[addr])

	snap := sd.Snapshot()
	sd.AddBalance(addr, big.NewInt(1), tracing.BalanceChangeUnspecified)
	sd.DeleteAddress(addr)
	if _, ok := sd.accountsOrigin[addr]; ok {
		t.Fatal("accountsOrigin still populated after the removal")
	}
	if _, ok := sd.storagesOrigin[addr]; ok {
		t.Fatal("storagesOrigin still populated after the removal")
	}
	sd.RevertToSnapshot(snap)

	gotStoragesOrigin := sd.storagesOrigin[addr]
	if gotStoragesOrigin == nil {
		t.Fatalf("storagesOrigin lost after the revert")
	}
	if len(gotStoragesOrigin) != len(wantStoragesOrigin) {
		t.Errorf("storagesOrigin after the revert: have %d slots, want %d", len(gotStoragesOrigin), len(wantStoragesOrigin))
	}
	for key, want := range wantStoragesOrigin {
		if got := gotStoragesOrigin[key]; !bytes.Equal(got, want) {
			t.Errorf("storagesOrigin slot %x after the revert: have %x, want %x", key, got, want)
		}
	}
	if got := sd.accountsOrigin[addr]; !bytes.Equal(got, wantAccountsOrigin) {
		t.Errorf("accountsOrigin after the revert: have %x, want %x", got, wantAccountsOrigin)
	}
}

// TestDeleteAddressRevertKeepsUncommittedStorageNodes pins that reverting the
// removal keeps the storage trie the object held at the snapshot point.
// IntermediateRoot folds a storage write into the trie and advances data.Root
// without persisting the new nodes, so an object restored without the handle
// names a trie the database does not have: uncached reads come back zero, and the
// commit reports the expected root while leaving the storage out. Neither shows
// up in a root comparison, and the written slot itself is served from
// originStorage, so both reads below are needed.
func TestDeleteAddressRevertKeepsUncommittedStorageNodes(t *testing.T) {
	addr, _, sd, db := newDeleteAddressState(t)
	updated := common.HexToHash("0x02")
	committed := common.HexToHash("0x01")
	untouched := common.HexToHash("0x09")

	sd.SetState(addr, updated, common.HexToHash("0x77"))
	sd.IntermediateRoot(false)

	snap := sd.Snapshot()
	sd.DeleteAddress(addr)
	sd.RevertToSnapshot(snap)

	// The uncached slot is the only read that has to resolve through the trie.
	if got := sd.GetState(addr, untouched); got != (common.Hash{}) {
		t.Errorf("uncached slot after the revert: have %x, want empty", got)
	}
	if err := sd.Error(); err != nil {
		t.Fatalf("failed to read storage after the revert: %v", err)
	}
	if got := sd.GetState(addr, updated); got != common.HexToHash("0x77") {
		t.Errorf("written slot after the revert: have %x, want 0x77", got)
	}

	root, err := sd.Commit(1, false)
	if err != nil {
		t.Fatalf("failed to commit the reverted state: %v", err)
	}
	if err := sd.Database().TrieDB().Commit(root, false); err != nil {
		t.Fatalf("failed to commit the reverted trie: %v", err)
	}
	// Reopening drops the live trie, so this is the only place where storage
	// nodes missing from the database become visible.
	fresh, err := New(root, NewDatabase(db))
	if err != nil {
		t.Fatalf("failed to open statedb over the reverted root: %v", err)
	}
	if got := fresh.GetState(addr, updated); got != common.HexToHash("0x77") {
		t.Errorf("written slot after reopening the reverted root: have %x, want 0x77", got)
	}
	if got := fresh.GetState(addr, committed); got != common.HexToHash("0x42") {
		t.Errorf("committed slot after reopening the reverted root: have %x, want 0x42", got)
	}
	if err := fresh.Error(); err != nil {
		t.Fatalf("failed to read storage after reopening the reverted root: %v", err)
	}
}

// TestDeleteAddressCopyRevert pins that the journal entry survives StateDB.Copy
// with an independent storage trie and still restores the account. The fixture
// hashes a storage write without persisting it, so the copy has to carry its own
// trie: without one the restored object reads zeros and commits a root with no
// storage behind it.
func TestDeleteAddressCopyRevert(t *testing.T) {
	addr, _, sd, db := newDeleteAddressState(t)
	updated := common.HexToHash("0x02")
	committed := common.HexToHash("0x01")
	untouched := common.HexToHash("0x09")

	sd.SetState(addr, updated, common.HexToHash("0x77"))
	sd.IntermediateRoot(false)

	// The control commits the snapshot point in its own database, so the reverted
	// root can be compared without seeding the nodes this test is about.
	_, _, ctl, _ := newDeleteAddressState(t)
	ctl.SetState(addr, updated, common.HexToHash("0x77"))
	ctl.IntermediateRoot(false)
	wantRoot, err := ctl.Commit(0, false)
	if err != nil {
		t.Fatalf("failed to commit the control state: %v", err)
	}

	snap := sd.Snapshot()
	sd.DeleteAddress(addr)
	cp := sd.Copy()
	cp.RevertToSnapshot(snap)

	if got := cp.GetBalance(addr); got.Int64() != 1234 {
		t.Fatalf("balance after the revert on a copy: have %v, want 1234", got)
	}
	if got := cp.GetState(addr, untouched); got != (common.Hash{}) {
		t.Errorf("uncached slot after the revert on a copy: have %x, want empty", got)
	}
	if err := cp.Error(); err != nil {
		t.Fatalf("failed to read storage after the revert on a copy: %v", err)
	}
	if got := cp.GetState(addr, updated); got != common.HexToHash("0x77") {
		t.Errorf("written slot after the revert on a copy: have %x, want 0x77", got)
	}
	if got := cp.GetState(addr, committed); got != common.HexToHash("0x42") {
		t.Errorf("committed slot after the revert on a copy: have %x, want 0x42", got)
	}

	root, err := cp.Commit(0, false)
	if err != nil {
		t.Fatalf("failed to commit the copied state: %v", err)
	}
	if root != wantRoot {
		t.Errorf("state root after the revert on a copy: have %x, want %x", root, wantRoot)
	}
	if err := cp.Database().TrieDB().Commit(root, false); err != nil {
		t.Fatalf("failed to commit the copied trie: %v", err)
	}
	fresh, err := New(root, NewDatabase(db))
	if err != nil {
		t.Fatalf("failed to open statedb over the reverted root: %v", err)
	}
	if got := fresh.GetState(addr, updated); got != common.HexToHash("0x77") {
		t.Errorf("written slot after reopening the reverted root: have %x, want 0x77", got)
	}
	if got := fresh.GetState(addr, committed); got != common.HexToHash("0x42") {
		t.Errorf("committed slot after reopening the reverted root: have %x, want 0x42", got)
	}
	if err := fresh.Error(); err != nil {
		t.Fatalf("failed to read storage after reopening the reverted root: %v", err)
	}
}

// TestDeleteAddressRevertRestoresPendingMutationAndDiffs pins the three revert
// branches the other revert cases leave uncovered: the pending update mutation,
// the s.accounts diff cache and the s.storages diff cache. The fixture commits one
// transaction to fill the two caches, then finalises a second one without applying
// it, so the snapshot point carries all three at once. Losing the mutation drops
// the balance that transaction wrote; losing a cache entry drops the block-scoped
// diff the commit reports, which is what the control state root compares against.
func TestDeleteAddressRevertRestoresPendingMutationAndDiffs(t *testing.T) {
	addr, _, sd, _ := newDeleteAddressState(t)
	addrHash := crypto.Keccak256Hash(addr[:])

	// A committed transaction fills both diff caches.
	sd.SetState(addr, common.HexToHash("0x02"), common.HexToHash("0x77"))
	sd.AddBalance(addr, big.NewInt(1), tracing.BalanceChangeUnspecified)
	sd.IntermediateRoot(false)
	if sd.accounts[addrHash] == nil || sd.storages[addrHash] == nil {
		t.Fatalf("fixture: the committed transaction did not fill the diff caches")
	}
	wantAccount := sd.accounts[addrHash]
	wantStorage := sd.storages[addrHash]

	// A finalised but unapplied transaction leaves a pending update mutation.
	sd.AddBalance(addr, big.NewInt(3), tracing.BalanceChangeUnspecified)
	sd.Finalise(false)
	pending, ok := sd.mutations[addr]
	if !ok || pending.isDelete() || pending.applied {
		t.Fatalf("fixture: no pending update mutation before the snapshot")
	}

	// The control commits the snapshot point itself, so the reverted state can be
	// compared against the root the snapshot is supposed to stand for.
	_, _, ctl, _ := newDeleteAddressState(t)
	ctl.SetState(addr, common.HexToHash("0x02"), common.HexToHash("0x77"))
	ctl.AddBalance(addr, big.NewInt(1), tracing.BalanceChangeUnspecified)
	ctl.IntermediateRoot(false)
	ctl.AddBalance(addr, big.NewInt(3), tracing.BalanceChangeUnspecified)
	ctl.Finalise(false)
	wantRoot, err := ctl.Commit(0, false)
	if err != nil {
		t.Fatalf("failed to commit the control state: %v", err)
	}

	snap := sd.Snapshot()
	sd.AddBalance(addr, big.NewInt(2), tracing.BalanceChangeUnspecified)
	sd.SetState(addr, common.HexToHash("0x02"), common.HexToHash("0x99"))
	sd.DeleteAddress(addr)
	sd.RevertToSnapshot(snap)

	got, ok := sd.mutations[addr]
	if !ok {
		t.Errorf("pending update mutation lost after the revert")
	} else if got.isDelete() {
		t.Errorf("pending update mutation restored as a deletion after the revert")
	} else if got.applied {
		t.Errorf("pending update mutation restored as already applied after the revert")
	}
	if !bytes.Equal(sd.accounts[addrHash], wantAccount) {
		t.Errorf("account diff cache after the revert: have %x, want %x", sd.accounts[addrHash], wantAccount)
	}
	gotStorage := sd.storages[addrHash]
	if len(gotStorage) != len(wantStorage) {
		t.Errorf("storage diff cache after the revert: have %d slots, want %d", len(gotStorage), len(wantStorage))
	}
	for key, want := range wantStorage {
		if !bytes.Equal(gotStorage[key], want) {
			t.Errorf("storage diff cache slot %x after the revert: have %x, want %x", key, gotStorage[key], want)
		}
	}
	root, err := sd.Commit(0, false)
	if err != nil {
		t.Fatalf("failed to commit the reverted state: %v", err)
	}
	if root != wantRoot {
		t.Errorf("state root after the revert: have %x, want %x", root, wantRoot)
	}
}

// TestDeleteAddressHookSkipsAbsentAccount pins the tracer boundary of the
// removal: a no-op removal reports nothing, while an existing zero-balance
// account is still reported. ApplyTIPSigningHardFork calls DeleteAddress
// unconditionally at the activation block, so networks without the legacy
// account must not surface a 0 -> 0 destruct event.
func TestDeleteAddressHookSkipsAbsentAccount(t *testing.T) {
	sd, err := New(types.EmptyRootHash, NewDatabase(rawdb.NewMemoryDatabase()))
	if err != nil {
		t.Fatalf("failed to create statedb: %v", err)
	}
	var (
		changes int
		prev    *big.Int
		next    *big.Int
		reason  tracing.BalanceChangeReason
	)
	hooked := NewHookedState(sd, &tracing.Hooks{
		OnBalanceChange: func(addr common.Address, prevIn, nextIn *big.Int, reasonIn tracing.BalanceChangeReason) {
			changes++
			prev, next, reason = prevIn, nextIn, reasonIn
		},
	})
	absent := common.BytesToAddress([]byte("absent"))
	hooked.DeleteAddress(absent)
	if changes != 0 {
		t.Fatalf("balance changes reported for an absent account: have %d, want 0", changes)
	}
	if sd.Exist(absent) {
		t.Fatalf("absent account exists after DeleteAddress")
	}

	// An existing account is still reported, even with a zero balance: the
	// guard is existence, not a non-zero balance.
	zero := common.BytesToAddress([]byte("zero-balance"))
	hooked.SetCode(zero, []byte{0x60, 0x00})
	hooked.DeleteAddress(zero)
	if changes != 1 {
		t.Fatalf("balance changes reported for an existing zero-balance account: have %d, want 1", changes)
	}
	if prev == nil || prev.Sign() != 0 || next == nil || next.Sign() != 0 {
		t.Errorf("reported change: have %v -> %v, want 0 -> 0", prev, next)
	}
	if reason != tracing.BalanceDecreaseSelfdestruct {
		t.Errorf("reported reason: have %v, want %v", reason, tracing.BalanceDecreaseSelfdestruct)
	}
}

// TestDeleteAddressSecondRemovalKeepsOriginalDestructOrigin pins that a second
// removal keeps the destruct origin recorded by the first one. The account can
// be resurrected in the same block and removed again; the recreated object has
// no origin of its own, so overwriting the marker would make handleDestruction
// skip the original account and its storage at commit.
func TestDeleteAddressSecondRemovalKeepsOriginalDestructOrigin(t *testing.T) {
	addr, _, sd, _ := newDeleteAddressState(t)

	obj := sd.getStateObject(addr)
	if obj == nil {
		t.Fatalf("fixture: account missing from the committed state")
	}
	wantOrigin := types.SlimAccountRLP(*obj.origin)

	sd.DeleteAddress(addr)
	sd.AddBalance(addr, big.NewInt(7), tracing.BalanceChangeUnspecified)
	sd.DeleteAddress(addr)

	if sd.Exist(addr) {
		t.Fatalf("account still exists after the second DeleteAddress")
	}
	origin := sd.stateObjectsDestruct[addr]
	if origin == nil {
		t.Fatalf("destruct marker lost the original account after the second removal")
	}
	if got := types.SlimAccountRLP(*origin); !bytes.Equal(got, wantOrigin) {
		t.Errorf("destruct marker after the second removal: have %x, want the original %x", got, wantOrigin)
	}

	nodes := trienode.NewMergedNodeSet()
	if _, err := sd.handleDestruction(nodes); err != nil {
		t.Fatalf("handleDestruction: %v", err)
	}
	if got := sd.accountsOrigin[addr]; !bytes.Equal(got, wantOrigin) {
		t.Errorf("recorded account origin after the second removal: have %x, want %x", got, wantOrigin)
	}
	deleted := 0
	for _, set := range nodes.Sets {
		_, n := set.Size()
		deleted += n
	}
	if deleted == 0 {
		t.Errorf("original storage not recorded as deleted after the second removal")
	}
}

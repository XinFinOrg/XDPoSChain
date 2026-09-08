// Copyright 2025 The XDPoSChain Authors
// This file is part of the XDPoSChain library.
//
// The XDPoSChain library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The XDPoSChain library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the XDPoSChain library. If not, see <http://www.gnu.org/licenses/>.

package core

import (
	"encoding/binary"
	"math/big"
	"path/filepath"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/ethdb"
	"github.com/XinFinOrg/XDPoSChain/ethdb/leveldb"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// newFreezerChainDB opens a real leveldb+freezer backed database for tests that
// need to exercise the ancient store (the in-memory rawdb has no freezer).
func newFreezerChainDB(t *testing.T) ethdb.Database {
	t.Helper()
	dir := t.TempDir()
	kv, err := leveldb.New(filepath.Join(dir, "chaindata"), 0, 0, "", false)
	if err != nil {
		t.Fatalf("open leveldb: %v", err)
	}
	db, err := rawdb.NewDatabaseWithFreezer(kv, filepath.Join(dir, "ancient"), "", false)
	if err != nil {
		kv.Close()
		t.Fatalf("open freezer-backed db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// TestInsertReceiptChainWritesAncients exercises the fast-sync direct-to-ancient
// path in InsertReceiptChain. Blocks below the supplied ancientLimit must land in
// the freezer (not the key-value store) while the remainder stay live, and
// everything must read back identically either way.
//
// No header is inserted up front: InsertReceiptChain is the sole writer of
// fast-synced data, so it has to store the headers itself, and exactly once.
func TestInsertReceiptChainWritesAncients(t *testing.T) {
	var (
		key, _  = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		address = crypto.PubkeyToAddress(key.PublicKey)
		funds   = big.NewInt(1000000000000000)
		gspec   = &Genesis{
			Config: params.TestChainConfig,
			Alloc:  types.GenesisAlloc{address: {Balance: funds}},
		}
	)
	const (
		numBlocks    = 64
		ancientLimit = 40
	)
	_, blocks, receipts := GenerateChainWithGenesis(gspec, ethash.NewFaker(), numBlocks, nil)

	db := newFreezerChainDB(t)
	chain, err := NewBlockChain(db, nil, gspec, ethash.NewFaker(), vm.Config{})
	if err != nil {
		t.Fatalf("new blockchain: %v", err)
	}
	defer chain.Stop()

	if n, err := chain.InsertReceiptChain(blocks, receipts, ancientLimit, 0); err != nil {
		t.Fatalf("failed to insert receipt %d: %v", n, err)
	}
	// The head header marker has to follow the content, nothing else moves it.
	if head := chain.CurrentHeader(); head.Number.Uint64() != numBlocks {
		t.Fatalf("head header: got %d, want %d", head.Number.Uint64(), numBlocks)
	}

	// Blocks [0, ancientLimit) plus the genesis must now live in the freezer.
	frozen, err := db.Ancients()
	if err != nil {
		t.Fatalf("Ancients: %v", err)
	}
	if frozen != ancientLimit {
		t.Fatalf("ancient item count: got %d, want %d", frozen, ancientLimit)
	}
	// Genesis must have been written first, otherwise the freezer would have a
	// hole at index 0 and every subsequent lookup would be off by one.
	if blob, err := db.Ancient(rawdb.ChainFreezerHashTable, 0); err != nil {
		t.Fatalf("genesis hash missing from ancients: %v", err)
	} else if got := common.BytesToHash(blob); got != chain.Genesis().Hash() {
		t.Fatalf("ancient genesis hash: got %x, want %x", got, chain.Genesis().Hash())
	}

	// Every block must read back correctly regardless of which side it landed on.
	for i, block := range blocks {
		num, hash := block.NumberU64(), block.Hash()

		if got := chain.GetBlockByNumber(num); got == nil || got.Hash() != hash {
			t.Fatalf("block %d not readable after ancient insert", num)
		}
		gotReceipts := chain.GetReceiptsByHash(hash)
		if len(gotReceipts) != len(receipts[i]) {
			t.Fatalf("block %d: receipt count %d, want %d", num, len(gotReceipts), len(receipts[i]))
		}
		// Transaction lookups must keep working for ancient blocks too.
		for _, tx := range block.Transactions() {
			if found := rawdb.ReadTxLookupEntry(db, tx.Hash()); found == nil {
				t.Fatalf("block %d: tx %x lost its lookup entry", num, tx.Hash())
			} else if *found != num {
				t.Fatalf("block %d: tx %x maps to block %d", num, tx.Hash(), *found)
			}
		}
		// Below the limit the body must be served by the freezer, not leveldb.
		inAncient := num < ancientLimit
		if _, err := db.Ancient(rawdb.ChainFreezerBodiesTable, num); (err == nil) != inAncient {
			t.Fatalf("block %d: ancient body presence %v, want %v", num, err == nil, inAncient)
		}
		// Frozen blocks must hold no second copy of the header or the canonical
		// marker on the key-value store: the freezer serves both, and the header
		// sync phase no longer writes them. A copy here would be a permanent
		// leak, since the background freezer never revisits this range.
		if has, err := db.Has(kvHeaderKey(num, hash)); err != nil {
			t.Fatalf("block %d: header lookup: %v", num, err)
		} else if has == inAncient {
			t.Fatalf("block %d: key-value header presence %v, want %v", num, has, !inAncient)
		}
		if has, err := db.Has(kvCanonicalHashKey(num)); err != nil {
			t.Fatalf("block %d: canonical marker lookup: %v", num, err)
		} else if has == inAncient {
			t.Fatalf("block %d: key-value canonical marker presence %v, want %v", num, has, !inAncient)
		}
		// What the freezer does not hold has to be on the key-value store for
		// every block, frozen or not.
		if rawdb.ReadHeaderNumber(db, hash) == nil {
			t.Fatalf("block %d: hash->number mapping missing", num)
		}
		if td := rawdb.ReadTd(db, hash, num); td == nil {
			t.Fatalf("block %d: total difficulty missing", num)
		} else if want := chain.GetTd(hash, num); td.Cmp(want) != 0 {
			t.Fatalf("block %d: total difficulty %v, want %v", num, td, want)
		}
	}
}

// kvHeaderKey and kvCanonicalHashKey rebuild the raw rawdb schema keys, so tests
// can probe the key-value store directly without the ancient-store fallback that
// every rawdb accessor performs.
func kvHeaderKey(number uint64, hash common.Hash) []byte {
	key := append([]byte("h"), encodeBlockNumber(number)...)
	return append(key, hash.Bytes()...)
}

func kvCanonicalHashKey(number uint64) []byte {
	key := append([]byte("h"), encodeBlockNumber(number)...)
	return append(key, 'n')
}

func encodeBlockNumber(number uint64) []byte {
	enc := make([]byte, 8)
	binary.BigEndian.PutUint64(enc, number)
	return enc
}

// TestInsertReceiptChainValidatesHeaders checks that InsertReceiptChain rejects a
// chain whose headers do not check out. It is the only place downloaded fast-sync
// headers are verified now, so a bad chain must not reach the database at all.
func TestInsertReceiptChainValidatesHeaders(t *testing.T) {
	var (
		key, _  = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		address = crypto.PubkeyToAddress(key.PublicKey)
		funds   = big.NewInt(1000000000000000)
		gspec   = &Genesis{
			Config: params.TestChainConfig,
			Alloc:  types.GenesisAlloc{address: {Balance: funds}},
		}
	)
	_, blocks, receipts := GenerateChainWithGenesis(gspec, ethash.NewFaker(), 16, nil)

	db := newFreezerChainDB(t)
	// A faker that fails verification, so the headers are rejected on their own
	// merits rather than because the chain is malformed.
	chain, err := NewBlockChain(db, nil, gspec, ethash.NewFakeFailer(blocks[8].NumberU64()), vm.Config{})
	if err != nil {
		t.Fatalf("new blockchain: %v", err)
	}
	defer chain.Stop()

	if _, err := chain.InsertReceiptChain(blocks, receipts, 8, 0); err == nil {
		t.Fatal("inserted a receipt chain with an invalid header")
	}
	// Nothing may have been written, neither live nor frozen.
	if frozen, _ := db.Ancients(); frozen != 0 {
		t.Errorf("invalid chain froze %d items", frozen)
	}
	for _, block := range blocks {
		if has, err := db.Has(kvHeaderKey(block.NumberU64(), block.Hash())); err != nil {
			t.Fatalf("header lookup: %v", err)
		} else if has {
			t.Errorf("block %d: header written despite failed verification", block.NumberU64())
		}
	}
	if head := chain.CurrentHeader(); head.Number.Uint64() != 0 {
		t.Errorf("head header advanced to %d on a rejected chain", head.Number.Uint64())
	}
}

// TestInsertReceiptChainZeroLimitStaysLive verifies that ancientLimit==0 keeps
// the previous behaviour exactly: nothing is written to the freezer.
func TestInsertReceiptChainZeroLimitStaysLive(t *testing.T) {
	var (
		key, _  = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		address = crypto.PubkeyToAddress(key.PublicKey)
		funds   = big.NewInt(1000000000000000)
		gspec   = &Genesis{
			Config: params.TestChainConfig,
			Alloc:  types.GenesisAlloc{address: {Balance: funds}},
		}
	)
	_, blocks, receipts := GenerateChainWithGenesis(gspec, ethash.NewFaker(), 16, nil)

	db := newFreezerChainDB(t)
	chain, err := NewBlockChain(db, nil, gspec, ethash.NewFaker(), vm.Config{})
	if err != nil {
		t.Fatalf("new blockchain: %v", err)
	}
	defer chain.Stop()

	if n, err := chain.InsertReceiptChain(blocks, receipts, 0, 0); err != nil {
		t.Fatalf("failed to insert receipt %d: %v", n, err)
	}
	if frozen, _ := db.Ancients(); frozen != 0 {
		t.Fatalf("ancientLimit 0 still froze %d items", frozen)
	}
	for _, block := range blocks {
		num, hash := block.NumberU64(), block.Hash()

		if got := chain.GetBlockByNumber(num); got == nil || got.Hash() != hash {
			t.Fatalf("block %d not readable", num)
		}
		// Everything stays live here, so the key-value store holds the header
		// and the canonical marker for the whole chain.
		if has, err := db.Has(kvHeaderKey(num, hash)); err != nil {
			t.Fatalf("block %d: header lookup: %v", num, err)
		} else if !has {
			t.Fatalf("block %d: live header missing", num)
		}
		if rawdb.ReadTd(db, hash, num) == nil {
			t.Fatalf("block %d: total difficulty missing", num)
		}
	}
}

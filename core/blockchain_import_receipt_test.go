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

package core

import (
	"errors"
	"math/big"
	"sync/atomic"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/ethdb"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// TestInsertReceiptChainReportsInterruption covers the interruption check of a receipt
// batch. The blocks before the one that stopped the batch may already have been flushed
// to disk, so reporting a nil error would claim the whole batch had been written - the
// very thing an interrupted insertion must not claim. The sentinel is local, so the
// downloader reports it as errLocalInsertFailure: it neither drops the peer that served
// the batch nor presents the failure as a cancellation somebody requested.
func TestInsertReceiptChainReportsInterruption(t *testing.T) {
	chain, blocks := newInsertChainTester(t, nil, 5, 5)
	receipts := make([]types.Receipts, len(blocks))

	chain.InterruptInsert(true)
	defer chain.InterruptInsert(false)

	n, err := chain.InsertReceiptChain(blocks, receipts)
	if !errors.Is(err, ErrInsertionInterrupted) {
		t.Fatalf("unexpected error: have %v want %v", err, ErrInsertionInterrupted)
	}
	if want := 0; n != want {
		t.Fatalf("unexpected failing index: have %d want %d", n, want)
	}
}

// errRefusedWrite is what the batch below reports, standing for a local write the database
// refused (a full disk, a read-only mount, an I/O error).
var errRefusedWrite = errors.New("the database refused the write")

// refusingBatchDB hands out batches that can be told to fail their write, so that the failure
// path of a receipt import can be driven without a real disk failing.
type refusingBatchDB struct {
	ethdb.Database
	refuse atomic.Bool
}

func (db *refusingBatchDB) NewBatch() ethdb.Batch {
	return &refusingBatch{Batch: db.Database.NewBatch(), refuse: &db.refuse}
}

type refusingBatch struct {
	ethdb.Batch
	refuse *atomic.Bool
}

func (b *refusingBatch) Write() error {
	if b.refuse.Load() {
		return errRefusedWrite
	}
	return b.Batch.Write()
}

// TestInsertReceiptChainReportsARefusedWrite covers a write the database refuses while a receipt
// batch is being flushed. It says nothing about the peer that served the receipts, so it is
// reported as the local condition it is - the one the downloader answers by cancelling the
// content processing instead of dropping the peer that supplied valid data.
func TestInsertReceiptChainReportsARefusedWrite(t *testing.T) {
	var (
		key, _  = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		address = crypto.PubkeyToAddress(key.PublicKey)
		gspec   = &Genesis{
			Alloc:   types.GenesisAlloc{address: {Balance: big.NewInt(1000000000000000)}},
			BaseFee: big.NewInt(params.InitialBaseFee),
			Config:  params.TestChainConfig,
		}
	)
	db := &refusingBatchDB{Database: rawdb.NewMemoryDatabase()}
	_, blocks, _ := GenerateChainWithGenesis(gspec, ethash.NewFaker(), 5, nil)
	chain, err := NewBlockChain(db, nil, gspec, ethash.NewFaker(), vm.Config{})
	if err != nil {
		t.Fatalf("failed to create chain: %v", err)
	}
	defer chain.Stop()

	// Headers only: a receipt import completes a header chain, and a block that is already there
	// would be skipped instead of written.
	headers := make([]*types.Header, len(blocks))
	for i, block := range blocks {
		headers[i] = block.Header()
	}
	if n, err := chain.InsertHeaderChain(headers, 1); err != nil {
		t.Fatalf("header %d: failed to insert headers: %v", n, err)
	}
	receipts := make([]types.Receipts, len(blocks))

	db.refuse.Store(true)
	defer db.refuse.Store(false)

	n, err := chain.InsertReceiptChain(blocks, receipts)
	if !errors.Is(err, errRefusedWrite) {
		t.Fatalf("index %d: the refused write must be reported with its cause, have %v", n, err)
	}
	if !errors.Is(err, ErrLocalInsertCondition) {
		t.Fatalf("index %d: a refused write must be reported as a local condition, have %v", n, err)
	}
	if !IsLocalInsertError(err) {
		t.Fatalf("a refused write must not be blamed on the peer: %v", err)
	}
}

// interruptingDB hands out batches that report their progress to the test, so that an import
// can be interrupted in the middle of its own work instead of before it starts: the index an
// interruption reports only has something to leave out once a batch has reached the database
// and the next one already holds writes.
type interruptingDB struct {
	ethdb.Database
	onWrite func()
	onPut   func()
}

func (db *interruptingDB) NewBatch() ethdb.Batch {
	return &interruptingBatch{Batch: db.Database.NewBatch(), db: db}
}

type interruptingBatch struct {
	ethdb.Batch
	db *interruptingDB
}

func (b *interruptingBatch) Put(key, value []byte) error {
	if err := b.Batch.Put(key, value); err != nil {
		return err
	}
	if b.db.onPut != nil {
		b.db.onPut()
	}
	return nil
}

func (b *interruptingBatch) Write() error {
	if err := b.Batch.Write(); err != nil {
		return err
	}
	if b.db.onWrite != nil {
		b.db.onWrite()
	}
	return nil
}

// TestInsertReceiptChainReportsOnlyWhatReachedDisk covers the index an interrupted receipt
// import reports. Blocks reach the database only when a batch has grown past
// ethdb.IdealBatchSize, so an interruption can land while every block walked since the last
// flush - the one the loop is on included - is still only in the batch. Reporting the loop
// cursor would count those as written, which is exactly the claim the index exists to avoid,
// and it is the half written batch the earlier interruption check would otherwise report as a
// complete one. The interruption is raised one block after the first batch has been written,
// and the index is checked against the database rather than against an index the test
// computes: everything below it has to be on disk, and the block at it has to be missing.
func TestInsertReceiptChainReportsOnlyWhatReachedDisk(t *testing.T) {
	var (
		key, _  = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		address = crypto.PubkeyToAddress(key.PublicKey)
		gspec   = &Genesis{
			Alloc:   types.GenesisAlloc{address: {Balance: big.NewInt(1000000000000000000)}},
			BaseFee: big.NewInt(params.InitialBaseFee),
			Config:  params.TestChainConfig,
		}
		signer = types.LatestSigner(gspec.Config)
		// One body of this size per block, so that a batch of them crosses
		// ethdb.IdealBatchSize a few blocks in and the import flushes while it still has
		// blocks to walk.
		payload = make([]byte, 4096)
	)
	db := &interruptingDB{Database: rawdb.NewMemoryDatabase()}
	_, blocks, receipts := GenerateChainWithGenesis(gspec, ethash.NewFaker(), 40, func(i int, block *BlockGen) {
		tx, err := types.SignTx(types.NewTransaction(block.TxNonce(address), common.Address{0x00}, big.NewInt(1), 100000, block.header.BaseFee, payload), signer, key)
		if err != nil {
			t.Fatalf("block %d: failed to sign the transaction: %v", i, err)
		}
		block.AddTx(tx)
	})
	chain, err := NewBlockChain(db, nil, gspec, ethash.NewFaker(), vm.Config{})
	if err != nil {
		t.Fatalf("failed to create chain: %v", err)
	}
	defer chain.Stop()

	// Headers only: a receipt import completes a header chain, and a block that is already
	// there would be skipped instead of written.
	headers := make([]*types.Header, len(blocks))
	for i, block := range blocks {
		headers[i] = block.Header()
	}
	if n, err := chain.InsertHeaderChain(headers, 1); err != nil {
		t.Fatalf("header %d: failed to insert headers: %v", n, err)
	}
	// Interrupt the import three queued writes after the first batch has been written, which
	// is one block later: the batch then holds blocks the reported index must leave out.
	var puts, putsAtFirstWrite int
	db.onWrite = func() {
		if putsAtFirstWrite == 0 {
			putsAtFirstWrite = puts
		}
	}
	db.onPut = func() {
		puts++
		if putsAtFirstWrite > 0 && puts == putsAtFirstWrite+3 {
			chain.InterruptInsert(true)
		}
	}
	defer chain.InterruptInsert(false)

	n, err := chain.InsertReceiptChain(blocks, receipts)
	if !errors.Is(err, ErrInsertionInterrupted) {
		// Either no batch was flushed on the way - raise the number of blocks or the payload
		// - or the interruption was never raised: both leave this check with nothing to
		// verify, so it fails instead of passing vacuously.
		t.Fatalf("the import has to flush a batch and then be interrupted: have index %d err %v", n, err)
	}
	for i := 0; i < n; i++ {
		if !rawdb.HasBody(chain.db, blocks[i].Hash(), blocks[i].NumberU64()) {
			t.Fatalf("index %d counts block %d as written, but its body is not in the database", n, i)
		}
	}
	if n < len(blocks) && rawdb.HasBody(chain.db, blocks[n].Hash(), blocks[n].NumberU64()) {
		t.Fatalf("index %d leaves out block %d, but its body is in the database", n, n)
	}
}

// TestInsertReceiptChainReportsTheStoredPrefix covers the index an interrupted receipt
// import reports for a batch that starts with blocks already on disk: those blocks are part
// of what the database holds, so they are part of the prefix the index describes. Counting
// only what this very loop wrote would report the start of the batch and claim that blocks
// written long ago still had to be written - the opposite of the overcount the index exists
// to avoid, but wrong in the same way.
func TestInsertReceiptChainReportsTheStoredPrefix(t *testing.T) {
	var (
		key, _  = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		address = crypto.PubkeyToAddress(key.PublicKey)
		gspec   = &Genesis{
			Alloc:   types.GenesisAlloc{address: {Balance: big.NewInt(1000000000000000000)}},
			BaseFee: big.NewInt(params.InitialBaseFee),
			Config:  params.TestChainConfig,
		}
		signer = types.LatestSigner(gspec.Config)
		// Small enough that six of these never cross ethdb.IdealBatchSize: the import below
		// must be interrupted before it has written anything of its own.
		payload = make([]byte, 512)
	)
	db := &interruptingDB{Database: rawdb.NewMemoryDatabase()}
	_, blocks, receipts := GenerateChainWithGenesis(gspec, ethash.NewFaker(), 6, func(i int, block *BlockGen) {
		tx, err := types.SignTx(types.NewTransaction(block.TxNonce(address), common.Address{0x00}, big.NewInt(1), 100000, block.header.BaseFee, payload), signer, key)
		if err != nil {
			t.Fatalf("block %d: failed to sign the transaction: %v", i, err)
		}
		block.AddTx(tx)
	})
	chain, err := NewBlockChain(db, nil, gspec, ethash.NewFaker(), vm.Config{})
	if err != nil {
		t.Fatalf("failed to create chain: %v", err)
	}
	defer chain.Stop()

	// Headers only: a receipt import completes a header chain, and a block that is already
	// there would be skipped instead of written.
	headers := make([]*types.Header, len(blocks))
	for i, block := range blocks {
		headers[i] = block.Header()
	}
	if n, err := chain.InsertHeaderChain(headers, 1); err != nil {
		t.Fatalf("header %d: failed to insert headers: %v", n, err)
	}
	// The stored prefix: three blocks this node completed with an import of its own.
	stored := 3
	if n, err := chain.InsertReceiptChain(blocks[:stored], receipts[:stored]); err != nil {
		t.Fatalf("stored prefix: failed to import the receipts: index %d err %v", n, err)
	}
	// Interrupt on the first write the second import queues, so that what it reports has to
	// be the blocks it skipped rather than anything it put into its own batch: nothing in
	// that batch ever reached the database.
	db.onPut = func() {
		chain.InterruptInsert(true)
	}
	defer chain.InterruptInsert(false)

	n, err := chain.InsertReceiptChain(blocks, receipts)
	if !errors.Is(err, ErrInsertionInterrupted) {
		t.Fatalf("the import has to be interrupted before it writes: index %d err %v", n, err)
	}
	// Checked against the database rather than against a count the test computed: every
	// block below the reported index has a body, and the block at it has none.
	if want := stored; n != want {
		t.Fatalf("unexpected failing index: have %d want %d - the stored prefix is part of what the database holds",
			n, want)
	}
	for i := 0; i < n; i++ {
		if !rawdb.HasBody(chain.db, blocks[i].Hash(), blocks[i].NumberU64()) {
			t.Fatalf("index %d counts block %d as written, but its body is not in the database", n, i)
		}
	}
	if n < len(blocks) && rawdb.HasBody(chain.db, blocks[n].Hash(), blocks[n].NumberU64()) {
		t.Fatalf("index %d leaves out block %d, but its body is in the database", n, n)
	}
}

// Copyright 2026 The XDPoSChain Authors
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

package rawdb

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/big"
	"path/filepath"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/ethdb"
	"github.com/XinFinOrg/XDPoSChain/ethdb/leveldb"
	"github.com/XinFinOrg/XDPoSChain/ethdb/memorydb"
	"github.com/XinFinOrg/XDPoSChain/metrics"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// prunerTestChainLength is long enough for the freezer to hold blocks once the
// immutability threshold is at its floor, which is also the retention floor.
const prunerTestChainLength = params.MinFullImmutabilityThreshold + 3000

// writePrunableChain is writeTestChain with incompressible bodies and receipts,
// so that a small XDC_FREEZER_TABLE_SIZE spreads the block data group over
// several data files.
func writePrunableChain(t *testing.T, db ethdb.Database, count uint64) []*types.Header {
	t.Helper()

	headers := make([]*types.Header, 0, count)
	var parent common.Hash
	for i := uint64(0); i < count; i++ {
		var seed [8]byte
		binary.BigEndian.PutUint64(seed[:], i)
		payload := bytes.Repeat(crypto.Keccak256(seed[:]), 6)

		header := &types.Header{
			Number:     new(big.Int).SetUint64(i),
			ParentHash: parent,
			Difficulty: big.NewInt(1),
		}
		hash := header.Hash()
		parent = hash

		WriteHeader(db, header)
		WriteCanonicalHash(db, hash, i)
		WriteBody(db, hash, i, &types.Body{Uncles: []*types.Header{{Number: big.NewInt(0), Extra: payload}}})
		WriteReceipts(db, hash, i, types.Receipts{{Status: types.ReceiptStatusSuccessful, Logs: []*types.Log{{Data: payload}}}})
		WriteTd(db, hash, i, new(big.Int).SetUint64(i+1))
		headers = append(headers, header)
	}
	last := headers[len(headers)-1]
	WriteHeadBlockHash(db, last.Hash())
	WriteHeadHeaderHash(db, last.Hash())
	return headers
}

// openPrunerTestDB opens the freezer-backed database in dir, with the
// immutability threshold at its floor and small ancient data files.
func openPrunerTestDB(t *testing.T, dir string) ethdb.Database {
	t.Helper()
	kv, err := leveldb.New(filepath.Join(dir, "chaindata"), 0, 0, "", false)
	if err != nil {
		t.Fatalf("open leveldb: %v", err)
	}
	db, err := NewDatabaseWithFreezer(kv, filepath.Join(dir, "ancient"), "", false)
	if err != nil {
		kv.Close()
		t.Fatalf("open freezer-backed db: %v", err)
	}
	return db
}

func setupPrunerTest(t *testing.T) {
	t.Helper()
	old := params.FullImmutabilityThreshold
	t.Cleanup(func() { params.FullImmutabilityThreshold = old })
	params.FullImmutabilityThreshold = params.MinFullImmutabilityThreshold
	t.Setenv(freezerTableSizeEnv, "65536")
}

// countDataFiles returns the number of data files of a chain freezer table.
func countDataFiles(t *testing.T, dir, table string) int {
	t.Helper()
	ext := ".cdat"
	if chainFreezerTableConfigs[table].noSnappy {
		ext = ".rdat"
	}
	files, err := filepath.Glob(filepath.Join(dir, "ancient", ChainFreezerName, table+".*"+ext))
	if err != nil {
		t.Fatal(err)
	}
	return len(files)
}

func freeze(t *testing.T, db ethdb.Database) {
	t.Helper()
	if err := db.(*freezerdb).Freeze(); err != nil {
		t.Fatalf("freeze: %v", err)
	}
}

// TestTailFileBoundary checks that the boundary is the first item of the newest
// data file, and that truncating the tail to it deletes every older file while
// all items from the boundary on stay readable.
func TestTailFileBoundary(t *testing.T) {
	rm, wm, sg := metrics.NewMeter(), metrics.NewMeter(), metrics.NewGauge()
	dir := t.TempDir()
	f, err := newTable(dir, "boundary", rm, wm, sg, 40, freezerTableConfig{noSnappy: true}, false)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	// A table with a single data file has nothing to delete.
	writeChunks(t, f, 2, 20)
	if boundary, err := f.tailFileBoundary(); err != nil || boundary != 0 {
		t.Fatalf("single file boundary: got %d (err %v), want 0", boundary, err)
	}
	// 10 items of 20 bytes, two per 40 byte file: five files, the newest one
	// holding items 8 and 9.
	batch := f.newBatch()
	for i := uint64(2); i < 10; i++ {
		if err := batch.AppendRaw(i, getChunk(20, int(i))); err != nil {
			t.Fatal(err)
		}
	}
	if err := batch.commit(); err != nil {
		t.Fatal(err)
	}
	if files, _ := filepath.Glob(filepath.Join(dir, "boundary.*.rdat")); len(files) != 5 {
		t.Fatalf("data files: got %d, want 5", len(files))
	}
	// A hidden tail inside an old file does not move the boundary.
	if err := f.truncateTail(3); err != nil {
		t.Fatal(err)
	}
	boundary, err := f.tailFileBoundary()
	if err != nil || boundary != 8 {
		t.Fatalf("boundary: got %d (err %v), want 8", boundary, err)
	}
	if err := f.truncateTail(boundary); err != nil {
		t.Fatal(err)
	}
	if files, _ := filepath.Glob(filepath.Join(dir, "boundary.*.rdat")); len(files) != 1 {
		t.Fatalf("data files after truncation: got %d, want 1", len(files))
	}
	checkRetrieve(t, f, map[uint64][]byte{8: getChunk(20, 8), 9: getChunk(20, 9)})
	checkRetrieveError(t, f, map[uint64]error{7: errOutOfBounds})

	// The boundary is stable once only the newest file is left.
	if boundary, err := f.tailFileBoundary(); err != nil || boundary != 8 {
		t.Fatalf("boundary after truncation: got %d (err %v), want 8", boundary, err)
	}
}

// TestBlockDataGroupTailIndependent checks that pruning the block data group
// leaves the headers and hashes untouched, and that the tail survives a reopen.
func TestBlockDataGroupTailIndependent(t *testing.T) {
	dir := t.TempDir()
	open := func() *Freezer {
		f, err := NewFreezer(dir, "", false, 2048, chainFreezerTableConfigs)
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	f := open()
	_, err := f.ModifyAncients(func(op ethdb.AncientWriteOp) error {
		for i := uint64(0); i < 4000; i++ {
			for table := range chainFreezerTableConfigs {
				if err := op.AppendRaw(table, i, getChunk(32, int(i))); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.TruncateTail(ChainFreezerBlockDataGroup, 3000); err != nil {
		t.Fatal(err)
	}
	check := func(f *Freezer) {
		t.Helper()
		if tail, _ := f.Tail(ChainFreezerBlockDataGroup); tail != 3000 {
			t.Fatalf("block data tail: got %d, want 3000", tail)
		}
		if tail, _ := f.Tail(""); tail != 0 {
			t.Fatalf("non-prunable tail: got %d, want 0", tail)
		}
		for _, table := range []string{ChainFreezerHeaderTable, ChainFreezerHashTable} {
			if _, err := f.Ancient(table, 0); err != nil {
				t.Fatalf("%s 0 not readable: %v", table, err)
			}
		}
		for _, table := range []string{ChainFreezerBodiesTable, ChainFreezerReceiptTable} {
			if _, err := f.Ancient(table, 2999); !errors.Is(err, errOutOfBounds) {
				t.Fatalf("%s 2999: got err %v, want %v", table, err, errOutOfBounds)
			}
			if _, err := f.Ancient(table, 3000); err != nil {
				t.Fatalf("%s 3000 not readable: %v", table, err)
			}
		}
	}
	check(f)
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	f = open()
	defer f.Close()
	check(f)
}

// TestMinimalPrunerKeepsNewestFile runs the pruner on a freezer whose block
// data spans many data files: only the newest data file of the group's tables
// may survive, the header chain must stay complete, and the pruned tail must be
// reported by the readers and survive a reopen.
func TestMinimalPrunerKeepsNewestFile(t *testing.T) {
	setupPrunerTest(t)
	dir := t.TempDir()
	db := openPrunerTestDB(t, dir)
	t.Cleanup(func() { db.Close() })
	headers := writePrunableChain(t, db, prunerTestChainLength)
	WriteHistoryMode(db, HistoryModeMinimal)

	// The first cycle freezes, there is nothing to prune before it.
	freeze(t, db)
	frozen, _ := db.Ancients()
	if frozen != prunerTestChainLength-params.MinFullImmutabilityThreshold {
		t.Fatalf("frozen: got %d, want %d", frozen, prunerTestChainLength-params.MinFullImmutabilityThreshold)
	}
	if tail, _ := db.Tail(ChainFreezerBlockDataGroup); tail != 0 {
		t.Fatalf("tail before pruning: got %d, want 0", tail)
	}
	headerFiles := countDataFiles(t, dir, ChainFreezerHeaderTable)
	hashFiles := countDataFiles(t, dir, ChainFreezerHashTable)
	for _, table := range []string{ChainFreezerBodiesTable, ChainFreezerReceiptTable} {
		if n := countDataFiles(t, dir, table); n < 3 {
			t.Fatalf("%s spans %d data files before pruning, want at least 3", table, n)
		}
	}
	// The next cycle prunes.
	freeze(t, db)
	tail, _ := db.Tail(ChainFreezerBlockDataGroup)
	if tail == 0 || tail >= frozen {
		t.Fatalf("tail after pruning: got %d, want within (0, %d)", tail, frozen)
	}
	checkPrunedFiles(t, db, tail)
	if n := countDataFiles(t, dir, ChainFreezerHeaderTable); n != headerFiles {
		t.Fatalf("header data files: got %d, want %d", n, headerFiles)
	}
	if n := countDataFiles(t, dir, ChainFreezerHashTable); n != hashFiles {
		t.Fatalf("hash data files: got %d, want %d", n, hashFiles)
	}
	checkPrunedReads(t, db, headers, tail)

	// Pruning is idempotent and the tail survives a reopen.
	freeze(t, db)
	if again, _ := db.Tail(ChainFreezerBlockDataGroup); again != tail {
		t.Fatalf("tail moved without new data: got %d, want %d", again, tail)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db = openPrunerTestDB(t, dir)
	if reopened, _ := db.Tail(ChainFreezerBlockDataGroup); reopened != tail {
		t.Fatalf("tail after reopen: got %d, want %d", reopened, tail)
	}
	checkPrunedReads(t, db, headers, tail)
}

// checkPrunedFiles asserts that pruning to tail deleted whole data files only,
// and all of them: no table of the block data group keeps a data file that lies
// wholly below the tail, and the table whose boundary set the tail is down to
// its newest data file.
func checkPrunedFiles(t *testing.T, db ethdb.Database, tail uint64) {
	t.Helper()
	freezer := db.(*freezerdb).chainFreezer.ancients.(*Freezer)
	freezer.writeLock.RLock()
	defer freezer.writeLock.RUnlock()

	var newestOnly bool
	for _, name := range []string{ChainFreezerBodiesTable, ChainFreezerReceiptTable} {
		table := freezer.tables[name]
		indices, err := table.getIndices(tail, 1)
		if err != nil {
			t.Fatalf("%s: index of tail %d: %v", name, tail, err)
		}
		if table.tailId != indices[1].filenum {
			t.Fatalf("%s: oldest data file %d, but the tail %d is in file %d", name, table.tailId, tail, indices[1].filenum)
		}
		newestOnly = newestOnly || table.tailId == table.headId
	}
	if !newestOnly {
		t.Fatal("no block data table is down to its newest data file")
	}
}

// checkPrunedReads asserts that block data below the tail reads as missing,
// while headers stay readable everywhere and block data from the tail on is
// intact.
func checkPrunedReads(t *testing.T, db ethdb.Database, headers []*types.Header, tail uint64) {
	t.Helper()
	for _, n := range []uint64{1, tail - 1} {
		hash := headers[n].Hash()
		if ReadBody(db, hash, n) != nil || ReadRawReceipts(db, hash, n) != nil {
			t.Fatalf("block %d below tail %d still has block data", n, tail)
		}
		if HasBody(db, hash, n) || HasReceipts(db, hash, n) {
			t.Fatalf("block %d below tail %d still reports block data", n, tail)
		}
		if !IsBlockDataPruned(db, n) {
			t.Fatalf("block %d below tail %d not reported as pruned", n, tail)
		}
		if h := ReadHeader(db, hash, n); h == nil || h.Hash() != hash {
			t.Fatalf("header %d below tail missing", n)
		}
		if ReadCanonicalHash(db, n) != hash {
			t.Fatalf("canonical hash %d below tail missing", n)
		}
		if ReadTd(db, hash, n) == nil {
			t.Fatalf("total difficulty %d below tail missing", n)
		}
	}
	// The freezer keeps a key-value copy of the genesis block, which must keep
	// serving it once the ancient copy is pruned.
	if ReadBody(db, headers[0].Hash(), 0) == nil || !HasBody(db, headers[0].Hash(), 0) {
		t.Fatal("genesis body lost to pruning")
	}
	if ReadRawReceipts(db, headers[0].Hash(), 0) == nil || !HasReceipts(db, headers[0].Hash(), 0) {
		t.Fatal("genesis receipts lost to pruning")
	}
	for _, n := range []uint64{tail, uint64(len(headers)) - 1} {
		hash := headers[n].Hash()
		if ReadBody(db, hash, n) == nil || ReadRawReceipts(db, hash, n) == nil {
			t.Fatalf("block %d at or above tail %d lost its block data", n, tail)
		}
		if !HasBody(db, hash, n) || !HasReceipts(db, hash, n) {
			t.Fatalf("block %d at or above tail %d does not report its block data", n, tail)
		}
		if IsBlockDataPruned(db, n) {
			t.Fatalf("block %d at or above tail %d reported as pruned", n, tail)
		}
	}
}

// TestMinimalPrunerRetentionFloor checks that the retention floor binds even
// when the data file boundary would allow pruning further: the newest
// minimalRetention blocks below the head keep their block data.
func TestMinimalPrunerRetentionFloor(t *testing.T) {
	setupPrunerTest(t)
	dir := t.TempDir()
	db := openPrunerTestDB(t, dir)
	defer db.Close()
	headers := writePrunableChain(t, db, prunerTestChainLength)
	WriteHistoryMode(db, HistoryModeMinimal)
	freeze(t, db)

	// Pull the head back so that the floor lands far below the newest data file.
	const floor = 50
	head := headers[minimalRetention+floor]
	WriteHeadBlockHash(db, head.Hash())
	WriteHeadFastBlockHash(db, head.Hash())
	freeze(t, db)

	if tail, _ := db.Tail(ChainFreezerBlockDataGroup); tail != floor {
		t.Fatalf("tail: got %d, want the retention floor %d", tail, floor)
	}
	checkPrunedReads(t, db, headers, floor)
}

// TestMinimalPrunerFullMode checks that a database in full mode is never pruned.
func TestMinimalPrunerFullMode(t *testing.T) {
	setupPrunerTest(t)
	db := openPrunerTestDB(t, t.TempDir())
	defer db.Close()
	writePrunableChain(t, db, prunerTestChainLength)
	freeze(t, db)
	freeze(t, db)
	if tail, _ := db.Tail(ChainFreezerBlockDataGroup); tail != 0 {
		t.Fatalf("full mode pruned to %d", tail)
	}
}

// TestMinimalPrunerMemoryFreezer checks that an in-memory freezer, which has no
// data files, is pruned down to the retention floor.
func TestMinimalPrunerMemoryFreezer(t *testing.T) {
	setupPrunerTest(t)
	db, err := Open(memorydb.New(), OpenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	headers := writePrunableChain(t, db, prunerTestChainLength)
	WriteHistoryMode(db, HistoryModeMinimal)
	freeze(t, db)
	freeze(t, db)

	want := prunerTestChainLength - 1 - minimalRetention
	if tail, _ := db.Tail(ChainFreezerBlockDataGroup); tail != uint64(want) {
		t.Fatalf("tail: got %d, want %d", tail, want)
	}
	checkPrunedReads(t, db, headers, uint64(want))
}

func TestPruneTarget(t *testing.T) {
	for _, tc := range []struct {
		head, boundary, want uint64
	}{
		{head: 0, boundary: 100, want: 0},
		{head: minimalRetention - 1, boundary: 100, want: 0},
		{head: minimalRetention, boundary: 100, want: 0},
		{head: minimalRetention + 50, boundary: 100, want: 50},
		{head: minimalRetention + 500, boundary: 100, want: 100},
	} {
		if got := pruneTarget(tc.head, tc.boundary); got != tc.want {
			t.Errorf("pruneTarget(%d, %d): got %d, want %d", tc.head, tc.boundary, got, tc.want)
		}
	}
}

// TestReadPruneHead checks that the retention floor follows the fast block
// during a fast sync, when the head block is still genesis.
func TestReadPruneHead(t *testing.T) {
	db := NewMemoryDatabase()
	headers := writeTestChain(t, db, 20)
	WriteHeadBlockHash(db, headers[0].Hash())
	if head := readPruneHead(db); head != 0 {
		t.Fatalf("head without fast block: got %d, want 0", head)
	}
	WriteHeadFastBlockHash(db, headers[15].Hash())
	if head := readPruneHead(db); head != 15 {
		t.Fatalf("head during fast sync: got %d, want 15", head)
	}
	WriteHeadBlockHash(db, headers[19].Hash())
	if head := readPruneHead(db); head != 19 {
		t.Fatalf("head after fast sync: got %d, want 19", head)
	}
}

func TestHistoryModeRoundTrip(t *testing.T) {
	db := NewMemoryDatabase()
	if mode := ReadHistoryMode(db); mode != HistoryModeFull {
		t.Fatalf("default mode: got %v, want full", mode)
	}
	WriteHistoryMode(db, HistoryModeMinimal)
	if mode := ReadHistoryMode(db); mode != HistoryModeMinimal {
		t.Fatalf("stored mode: got %v, want minimal", mode)
	}
	var mode HistoryMode
	if err := mode.UnmarshalText([]byte("archive")); err == nil {
		t.Fatal("unknown history mode accepted")
	}
	if _, err := HistoryMode(7).MarshalText(); err == nil {
		t.Fatal("invalid history mode marshalled")
	}
}

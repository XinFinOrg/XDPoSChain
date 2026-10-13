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

package rawdb

import (
	"bytes"
	"math/big"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/ethdb"
	"github.com/XinFinOrg/XDPoSChain/ethdb/leveldb"
	"github.com/XinFinOrg/XDPoSChain/log"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// writeTestChain writes a synthetic canonical chain of `count` blocks (0..count-1)
// into the key-value side of db, including the head markers the freezer needs.
func writeTestChain(t *testing.T, db ethdb.Database, count uint64) []*types.Header {
	t.Helper()

	headers := make([]*types.Header, 0, count)
	var parent common.Hash
	for i := uint64(0); i < count; i++ {
		header := &types.Header{
			Number:     new(big.Int).SetUint64(i),
			ParentHash: parent,
			Difficulty: big.NewInt(1),
			Extra:      []byte("xdpos-freezer-test"),
		}
		hash := header.Hash()
		parent = hash

		WriteHeader(db, header)
		WriteCanonicalHash(db, hash, i)
		WriteBody(db, hash, i, &types.Body{})
		WriteReceipts(db, hash, i, types.Receipts{})
		WriteTd(db, hash, i, new(big.Int).SetUint64(i+1))
		headers = append(headers, header)
	}
	last := headers[len(headers)-1]
	WriteHeadBlockHash(db, last.Hash())
	WriteHeadHeaderHash(db, last.Hash())
	return headers
}

func newFreezerBackedDB(t *testing.T) (ethdb.Database, string) {
	t.Helper()
	dir := t.TempDir()
	ancient := filepath.Join(dir, "ancient")
	kv, err := leveldb.New(filepath.Join(dir, "chaindata"), 0, 0, "", false)
	if err != nil {
		t.Fatalf("open leveldb: %v", err)
	}
	db, err := NewDatabaseWithFreezer(kv, ancient, "", false)
	if err != nil {
		kv.Close()
		t.Fatalf("open freezer-backed db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db, ancient
}

// TestChainFreezerMovesDataToAncients is the end-to-end Phase 1 check: with a
// lowered immutability threshold, a freeze cycle must relocate everything below
// HEAD-threshold out of the key-value store and into the ancient store, and the
// data must still read back identically afterwards.
func TestChainFreezerMovesDataToAncients(t *testing.T) {
	defer func(v uint64) { params.FullImmutabilityThreshold = v }(params.FullImmutabilityThreshold)
	params.FullImmutabilityThreshold = 10

	db, _ := newFreezerBackedDB(t)
	const count = 40
	headers := writeTestChain(t, db, count)

	if frozen, _ := db.Ancients(); frozen != 0 {
		t.Fatalf("expected empty ancient store, got %d items", frozen)
	}
	if err := db.(*freezerdb).Freeze(); err != nil {
		t.Fatalf("freeze: %v", err)
	}

	// HEAD is block 39, threshold 10, so blocks 0..29 must be frozen.
	wantFrozen := uint64(count - params.FullImmutabilityThreshold)
	frozen, err := db.Ancients()
	if err != nil {
		t.Fatalf("Ancients: %v", err)
	}
	if frozen != wantFrozen {
		t.Fatalf("frozen count: got %d, want %d", frozen, wantFrozen)
	}

	// Every frozen block must still read back correctly, and must now be served
	// by the ancient store rather than leveldb.
	// Block 0 is deliberately retained in the key-value store by the freezer, so
	// the "no longer in leveldb" assertion starts at block 1.
	for i := uint64(0); i < frozen; i++ {
		want := headers[i]
		if got := ReadCanonicalHash(db, i); got != want.Hash() {
			t.Fatalf("canonical hash %d: got %x, want %x", i, got, want.Hash())
		}
		if got := ReadHeader(db, want.Hash(), i); got == nil || got.Hash() != want.Hash() {
			t.Fatalf("header %d not readable after freezing", i)
		}
		if blob, err := db.Ancient(ChainFreezerHeaderTable, i); err != nil || len(blob) == 0 {
			t.Fatalf("header %d not present in ancient store: %v", i, err)
		}
		// The key-value copy must be gone: that is the whole point of freezing.
		if i != 0 {
			if has, _ := db.Has(headerKey(i, want.Hash())); has {
				t.Fatalf("header %d still present in key-value store after freezing", i)
			}
		}
	}
	// Blocks at and above the threshold must remain in the key-value store.
	for i := frozen; i < count; i++ {
		if has, _ := db.Has(headerKey(i, headers[i].Hash())); !has {
			t.Fatalf("header %d should still be in the key-value store", i)
		}
	}
}

// TestTotalDifficultyNeverFrozen locks in this fork's deliberate deviation from
// upstream go-ethereum: there is no "diffs" ancient table, TD lives only in the
// key-value store, and it survives freezing. See claude/plan 3.4.
func TestTotalDifficultyNeverFrozen(t *testing.T) {
	defer func(v uint64) { params.FullImmutabilityThreshold = v }(params.FullImmutabilityThreshold)
	params.FullImmutabilityThreshold = 10

	db, _ := newFreezerBackedDB(t)
	const count = 40
	headers := writeTestChain(t, db, count)

	if err := db.(*freezerdb).Freeze(); err != nil {
		t.Fatalf("freeze: %v", err)
	}
	frozen, _ := db.Ancients()
	if frozen == 0 {
		t.Fatal("nothing was frozen, test is vacuous")
	}
	// There must be no total-difficulty ancient table at all.
	if _, err := db.AncientSize("diffs"); err == nil {
		t.Fatal("a \"diffs\" ancient table exists; TD must never be frozen in this fork")
	}
	// TD must still be readable for every frozen block, straight from leveldb.
	for i := uint64(0); i < frozen; i++ {
		td := ReadTd(db, headers[i].Hash(), i)
		if td == nil {
			t.Fatalf("total difficulty for frozen block %d is missing", i)
		}
		if td.Uint64() != i+1 {
			t.Fatalf("total difficulty %d: got %d, want %d", i, td.Uint64(), i+1)
		}
	}
}

// TestFreezerGenesisMismatchRejected verifies the consistency guard that stops a
// node from pairing a freezer with a key-value store from a different chain.
func TestFreezerGenesisMismatchRejected(t *testing.T) {
	defer func(v uint64) { params.FullImmutabilityThreshold = v }(params.FullImmutabilityThreshold)
	params.FullImmutabilityThreshold = 10

	dir := t.TempDir()
	ancient := filepath.Join(dir, "ancient")

	// First run: build a small frozen chain.
	kv, err := leveldb.New(filepath.Join(dir, "chaindata"), 0, 0, "", false)
	if err != nil {
		t.Fatalf("open leveldb: %v", err)
	}
	db, err := NewDatabaseWithFreezer(kv, ancient, "", false)
	if err != nil {
		t.Fatalf("open freezer-backed db: %v", err)
	}
	writeTestChain(t, db, 40)
	if err := db.(*freezerdb).Freeze(); err != nil {
		t.Fatalf("freeze: %v", err)
	}
	if frozen, _ := db.Ancients(); frozen == 0 {
		t.Fatal("nothing was frozen, test is vacuous")
	}
	db.Close()

	// Second run: pair that same ancient store with a fresh key-value store
	// carrying a different genesis. This must be refused.
	kv2, err := leveldb.New(filepath.Join(dir, "chaindata2"), 0, 0, "", false)
	if err != nil {
		t.Fatalf("open second leveldb: %v", err)
	}
	defer kv2.Close()
	WriteCanonicalHash(kv2, common.HexToHash("0xdeadbeef"), 0)

	if _, err := NewDatabaseWithFreezer(kv2, ancient, "", false); err == nil {
		t.Fatal("expected genesis mismatch to be rejected, but the database opened")
	}
}

// TestInspectDatabaseAncients checks that `XDC db inspect` reports per-table
// item counts for the chain freezer, and still works on a database without one.
func TestInspectDatabaseAncients(t *testing.T) {
	defer func(v uint64) { params.FullImmutabilityThreshold = v }(params.FullImmutabilityThreshold)
	params.FullImmutabilityThreshold = 10

	db, _ := newFreezerBackedDB(t)
	writeTestChain(t, db, 40)
	if err := db.(*freezerdb).Freeze(); err != nil {
		t.Fatalf("freeze: %v", err)
	}
	infos, err := inspectFreezers(db)
	if err != nil {
		t.Fatalf("inspectFreezers: %v", err)
	}
	if len(infos) != 1 || infos[0].name != ChainFreezerName {
		t.Fatalf("unexpected freezers: %+v", infos)
	}
	if infos[0].head != 29 {
		t.Fatalf("freezer head: got %d, want 29", infos[0].head)
	}
	if len(infos[0].tables) != len(chainFreezerTableConfigs) {
		t.Fatalf("table count: got %d, want %d", len(infos[0].tables), len(chainFreezerTableConfigs))
	}
	for _, table := range infos[0].tables {
		if table.count != 30 {
			t.Errorf("table %s: got %d items, want 30", table.name, table.count)
		}
		if table.size == 0 {
			t.Errorf("table %s: zero size", table.name)
		}
	}
	if err := InspectDatabase(db, nil, nil); err != nil {
		t.Fatalf("InspectDatabase with freezer: %v", err)
	}
	if err := InspectDatabase(NewMemoryDatabase(), nil, nil); err != nil {
		t.Fatalf("InspectDatabase without freezer: %v", err)
	}
}

// TestChainFreezerTableSizeOverride checks the parsing and bounds of the
// XDC_FREEZER_TABLE_SIZE development override.
func TestChainFreezerTableSizeOverride(t *testing.T) {
	tests := []struct {
		value   string
		want    uint32
		wantErr bool
	}{
		{value: "", want: freezerTableSize},
		{value: "65536", want: 65536},
		{value: "4294967295", want: 4294967295},
		{value: "65535", wantErr: true},
		{value: "4294967296", wantErr: true},
		{value: "-1", wantErr: true},
		{value: "2GiB", wantErr: true},
	}
	for _, tt := range tests {
		t.Setenv(freezerTableSizeEnv, tt.value)
		got, err := chainFreezerTableSize()
		if tt.wantErr {
			if err == nil {
				t.Errorf("%q: expected an error, got size %d", tt.value, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: unexpected error: %v", tt.value, err)
		} else if got != tt.want {
			t.Errorf("%q: got %d, want %d", tt.value, got, tt.want)
		}
	}
	// An invalid override must stop the database from opening at all.
	t.Setenv(freezerTableSizeEnv, "1024")
	dir := t.TempDir()
	kv, err := leveldb.New(filepath.Join(dir, "chaindata"), 0, 0, "", false)
	if err != nil {
		t.Fatalf("open leveldb: %v", err)
	}
	defer kv.Close()
	if _, err := NewDatabaseWithFreezer(kv, filepath.Join(dir, "ancient"), "", false); err == nil {
		t.Fatal("expected an invalid table size to be rejected")
	}
}

// TestChainFreezerTableSizeRollover checks that a small XDC_FREEZER_TABLE_SIZE
// makes the chain freezer spread its tables over several data files, which is
// what the minimal history mode tests rely on, and that the data still reads
// back after reopening.
func TestChainFreezerTableSizeRollover(t *testing.T) {
	defer func(v uint64) { params.FullImmutabilityThreshold = v }(params.FullImmutabilityThreshold)
	params.FullImmutabilityThreshold = 10
	t.Setenv(freezerTableSizeEnv, "65536")

	dir := t.TempDir()
	open := func() ethdb.Database {
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
	db := open()
	headers := writeTestChain(t, db, 3000)
	if err := db.(*freezerdb).Freeze(); err != nil {
		t.Fatalf("freeze: %v", err)
	}
	db.Close()

	files, err := filepath.Glob(filepath.Join(dir, "ancient", ChainFreezerName, ChainFreezerHeaderTable+".*.cdat"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) < 3 {
		t.Fatalf("expected the header table to span at least 3 data files, got %d", len(files))
	}

	db = open()
	defer db.Close()
	frozen, err := db.Ancients()
	if err != nil {
		t.Fatalf("Ancients: %v", err)
	}
	if frozen != 2990 {
		t.Fatalf("frozen count: got %d, want 2990", frozen)
	}
	for i := uint64(0); i < frozen; i++ {
		want := headers[i]
		if got := ReadHeader(db, want.Hash(), i); got == nil || got.Hash() != want.Hash() {
			t.Fatalf("header %d not readable after reopening", i)
		}
	}
}

// syncBuffer is a bytes.Buffer safe for the freezer goroutine to log into.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestChainFreezerBacklogReporting checks that a backlog spanning several
// freeze batches is reported at info level and through the backlog gauge, and
// that the end of the backlog is announced.
func TestChainFreezerBacklogReporting(t *testing.T) {
	defer func(v uint64) { params.FullImmutabilityThreshold = v }(params.FullImmutabilityThreshold)
	params.FullImmutabilityThreshold = 10
	defer func(v uint64) { freezerBatchLimit = v }(freezerBatchLimit)
	freezerBatchLimit = 10

	logs := new(syncBuffer)
	defer log.SetDefault(log.Root())
	log.SetDefault(log.NewLogger(log.NewTerminalHandlerWithLevel(logs, log.LevelInfo, false)))

	db, _ := newFreezerBackedDB(t)
	// HEAD is block 39 and the threshold 10, so blocks 0..29 are due: three
	// batches of ten.
	writeTestChain(t, db, 40)
	freezerBacklogGauge.Update(-1)
	if err := db.(*freezerdb).Freeze(); err != nil {
		t.Fatalf("freeze: %v", err)
	}
	if frozen, _ := db.Ancients(); frozen != 30 {
		t.Fatalf("frozen count: got %d, want 30", frozen)
	}
	if backlog := freezerBacklogGauge.Snapshot().Value(); backlog != 0 {
		t.Fatalf("backlog gauge after catching up: got %d, want 0", backlog)
	}
	output := logs.String()
	for _, want := range []string{
		"Freezing chain backlog into the ancient store frozen=10 remaining=20",
		"Chain freezer caught up with the backlog frozen=30",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("missing log line %q in:\n%s", want, output)
		}
	}
	// The second batch falls inside the progress interval and stays quiet.
	if n := strings.Count(output, "Freezing chain backlog"); n != 1 {
		t.Errorf("got %d progress reports, want 1:\n%s", n, output)
	}

	// A freeze cycle with nothing to do neither reports nor raises the gauge.
	freezerBacklogGauge.Update(-1)
	if err := db.(*freezerdb).Freeze(); err != nil {
		t.Fatalf("freeze: %v", err)
	}
	if backlog := freezerBacklogGauge.Snapshot().Value(); backlog != 0 {
		t.Fatalf("backlog gauge when idle: got %d, want 0", backlog)
	}
	if n := strings.Count(logs.String(), "Freezing chain backlog"); n != 1 {
		t.Errorf("idle freeze cycle reported progress")
	}
}

func TestFreezerBacklog(t *testing.T) {
	for _, tt := range []struct{ frozen, threshold, want uint64 }{
		{0, 0, 1},
		{0, 29, 30},
		{10, 29, 20},
		{30, 29, 0},
		{31, 29, 0},
	} {
		if got := freezerBacklog(tt.frozen, tt.threshold); got != tt.want {
			t.Errorf("freezerBacklog(%d, %d) = %d, want %d", tt.frozen, tt.threshold, got, tt.want)
		}
	}
}

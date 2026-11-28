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

package fetcher

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/types"
)

// TestImportedBlockSignatureSkippedParksWithBackoff pins the entry-less skip
// path: the fresh entry must carry the skip backoff, or the ticker retries the
// hook on its next tick instead of after parkedSkipBackoff.
func TestImportedBlockSignatureSkippedParksWithBackoff(t *testing.T) {
	tester := newTesterWithGate(func() bool { return true })
	defer tester.fetcher.Stop()

	block := newParkedTestBlock(0x50)
	tester.lock.Lock()
	tester.blocks[block.Hash()] = block
	tester.lock.Unlock()
	adoptCanonical(t, tester, block)

	var calls atomic.Int32
	tester.fetcher.signHook = func(*types.Block) error {
		calls.Add(1)
		return ErrSignatureSkipped
	}
	tester.fetcher.insertBlock = func(*types.Block) error { return nil }
	proposed := make(chan struct{}, 1)
	tester.fetcher.handleProposedBlock = func(*types.Header) error {
		proposed <- struct{}{}
		return nil
	}
	tester.fetcher.insert("test", block)
	select {
	case <-proposed:
	case <-time.After(5 * time.Second):
		t.Fatalf("delivery of the skipped block never finished")
	}

	if got := calls.Load(); got != 1 {
		t.Fatalf("hook calls after the delivery = %d, want 1", got)
	}
	tester.fetcher.parkedMu.Lock()
	parked, ok := tester.fetcher.parked[block.Hash()]
	var retryAfter time.Time
	if ok {
		retryAfter = parked.retryAfter
	}
	tester.fetcher.parkedMu.Unlock()
	if !ok {
		t.Fatalf("the skipped block was not parked")
	}
	if retryAfter.IsZero() {
		t.Fatalf("the fresh entry carries no skip backoff")
	}
	if wait := time.Until(retryAfter); wait < parkedSkipBackoff/2 {
		t.Fatalf("entry retried in %v, want about %v", wait, parkedSkipBackoff)
	}
	if n := signingCount(tester.fetcher); n != 0 {
		t.Fatalf("in-flight markers after the park = %d, want 0", n)
	}
	if n := pendingCount(tester.fetcher); n != 0 {
		t.Fatalf("reservations after the park = %d, want 0", n)
	}
	time.Sleep(300 * time.Millisecond)
	if got := calls.Load(); got != 1 {
		t.Fatalf("hook calls within the backoff = %d, want 1", got)
	}
}

// TestParkedSignatureSkippedAdmissionReleasesHeldClaimWhenFull pins that the
// held claim marker of an entry-less skip is released when the admission is
// refused, instead of blocking every later attempt for the hash.
func TestParkedSignatureSkippedAdmissionReleasesHeldClaimWhenFull(t *testing.T) {
	tester := newTester()
	defer tester.fetcher.Stop()
	tester.fetcher.signHook = func(*types.Block) error { return nil }

	full := blockParkedFullMeter.Snapshot().Count()
	block := newParkedTestBlock(0x57)
	tester.fetcher.parkedMu.Lock()
	for i := 0; i < maxParkedSignatures; i++ {
		hash := common.BytesToHash([]byte{0x0b, byte(i)})
		tester.fetcher.parked[hash] = &parkedBlock{block: newParkedTestBlock(byte(i)), deadline: time.Now().Add(time.Minute), stored: true}
	}
	// The claim marker the delivery path takes with no entry behind it.
	tester.fetcher.signing[block.Hash()] = struct{}{}
	tester.fetcher.parkedMu.Unlock()

	tester.fetcher.parkForSignatureSkipped(block, true)

	tester.fetcher.parkedMu.Lock()
	defer tester.fetcher.parkedMu.Unlock()
	if _, ok := tester.fetcher.signing[block.Hash()]; ok {
		t.Fatalf("a refused skipped admission leaked its claim marker")
	}
	if _, ok := tester.fetcher.pending[block.Hash()]; ok {
		t.Fatalf("a refused skipped admission leaked its booking")
	}
	if n := len(tester.fetcher.parked); n != maxParkedSignatures {
		t.Fatalf("parked count = %d, want %d", n, maxParkedSignatures)
	}
	if n := blockParkedFullMeter.Snapshot().Count() - full; n != 1 {
		t.Fatalf("full meter moved by %d, want 1", n)
	}
}

// TestParkedSignatureReclaimBindsStoredGateWhenBothClose pins that a reclaim
// for a stored admission frees a stored entry when both budgets are closed: a
// non-stored entry cannot reopen the stored subset, so it must keep its slot.
func TestParkedSignatureReclaimBindsStoredGateWhenBothClose(t *testing.T) {
	tester := newTester()
	defer tester.fetcher.Stop()
	tester.fetcher.signHook = func(*types.Block) error { return nil }

	var (
		storedSkipped    = common.BytesToHash([]byte{0x05, 0x01})
		notStoredSkipped = common.BytesToHash([]byte{0x05, 0x02})
	)
	reclaimed := blockParkedReclaimedMeter.Snapshot().Count()
	tester.fetcher.parkedMu.Lock()
	for i := 0; i < maxParkedStored-1; i++ {
		hash := common.BytesToHash([]byte{0x06, byte(i)})
		tester.fetcher.parked[hash] = &parkedBlock{block: newParkedTestBlock(byte(i)), deadline: time.Now().Add(time.Minute), stored: true}
	}
	// The stored skipped entry has the later deadline; the non-stored one would
	// be picked first by a gate-blind reclaim.
	tester.fetcher.parked[storedSkipped] = &parkedBlock{block: newParkedTestBlock(0x52), deadline: time.Now().Add(50 * time.Second), stored: true, retryAfter: time.Now().Add(time.Minute)}
	for i := 0; i < maxParkedSignatures-maxParkedStored-1; i++ {
		hash := common.BytesToHash([]byte{0x07, byte(i)})
		tester.fetcher.parked[hash] = &parkedBlock{block: newParkedTestBlock(byte(i)), deadline: time.Now().Add(time.Minute)}
	}
	tester.fetcher.parked[notStoredSkipped] = &parkedBlock{block: newParkedTestBlock(0x53), deadline: time.Now().Add(30 * time.Second), retryAfter: time.Now().Add(time.Minute)}
	tester.fetcher.parkedMu.Unlock()

	tester.fetcher.parkForSignatureStored(newParkedTestBlock(0x54), true)

	tester.fetcher.parkedMu.Lock()
	defer tester.fetcher.parkedMu.Unlock()
	if _, ok := tester.fetcher.parked[storedSkipped]; ok {
		t.Fatalf("the stored skipped entry was not reclaimed for a stored admission")
	}
	if _, ok := tester.fetcher.parked[notStoredSkipped]; !ok {
		t.Fatalf("a non-stored entry was reclaimed while the stored subset bound the admission")
	}
	if n := len(tester.fetcher.parked); n != maxParkedSignatures {
		t.Fatalf("parked count = %d, want %d", n, maxParkedSignatures)
	}
	if n := blockParkedReclaimedMeter.Snapshot().Count() - reclaimed; n != 1 {
		t.Fatalf("reclaimed meter moved by %d, want 1", n)
	}
}

// TestParkedSignatureBothClosedRefusesStoredWithoutGate pins that a stored
// admission in a both-closed set answers before the signer gate when no stored
// entry can be reclaimed: a non-stored one cannot reopen the stored subset.
func TestParkedSignatureBothClosedRefusesStoredWithoutGate(t *testing.T) {
	var gateCalls atomic.Int32
	tester := newTesterWithGate(func() bool {
		gateCalls.Add(1)
		return true
	})
	defer tester.fetcher.Stop()
	tester.fetcher.signHook = func(*types.Block) error { return nil }

	full := blockParkedFullMeter.Snapshot().Count()
	notStoredSkipped := common.BytesToHash([]byte{0x08, 0x01})
	tester.fetcher.parkedMu.Lock()
	for i := 0; i < maxParkedStored; i++ {
		hash := common.BytesToHash([]byte{0x09, byte(i)})
		tester.fetcher.parked[hash] = &parkedBlock{block: newParkedTestBlock(byte(i)), deadline: time.Now().Add(time.Minute), stored: true}
	}
	for i := 0; i < maxParkedSignatures-maxParkedStored-1; i++ {
		hash := common.BytesToHash([]byte{0x0a, byte(i)})
		tester.fetcher.parked[hash] = &parkedBlock{block: newParkedTestBlock(byte(i)), deadline: time.Now().Add(time.Minute)}
	}
	tester.fetcher.parked[notStoredSkipped] = &parkedBlock{block: newParkedTestBlock(0x55), deadline: time.Now().Add(time.Minute), retryAfter: time.Now().Add(time.Minute)}
	tester.fetcher.parkedMu.Unlock()

	block := newParkedTestBlock(0x56)
	tester.fetcher.parkForSignatureStored(block, true)

	tester.fetcher.parkedMu.Lock()
	defer tester.fetcher.parkedMu.Unlock()
	if _, ok := tester.fetcher.parked[block.Hash()]; ok {
		t.Fatalf("a stored block was parked while both budgets were closed")
	}
	if _, ok := tester.fetcher.parked[notStoredSkipped]; !ok {
		t.Fatalf("a non-stored entry was reclaimed although it cannot reopen the stored subset")
	}
	if n := len(tester.fetcher.parked); n != maxParkedSignatures {
		t.Fatalf("parked count = %d, want %d", n, maxParkedSignatures)
	}
	if n := gateCalls.Load(); n != 0 {
		t.Fatalf("signer gate calls = %d for a refused admission, want 0", n)
	}
	if n := blockParkedFullMeter.Snapshot().Count() - full; n != 1 {
		t.Fatalf("full meter moved by %d, want 1", n)
	}
}

// TestParkedSignatureReclaimSkipsDueEntry pins which skipped entry a full set may
// reclaim: one still in its backoff is a dead slot, while one past its backoff is
// due for the scan's retry and must keep the slot.
func TestParkedSignatureReclaimSkipsDueEntry(t *testing.T) {
	for _, tt := range []struct {
		name    string
		backoff time.Duration
		reclaim bool
	}{
		{"still in backoff", time.Minute, true},
		{"past its backoff", -time.Minute, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tester := newTester()
			defer tester.fetcher.Stop()
			tester.fetcher.signHook = func(*types.Block) error { return nil }

			skipped := common.BytesToHash([]byte{0x0c, 0x01})
			tester.fetcher.parkedMu.Lock()
			for i := 0; i < maxParkedSignatures-1; i++ {
				hash := common.BytesToHash([]byte{0x0d, byte(i)})
				tester.fetcher.parked[hash] = &parkedBlock{block: newParkedTestBlock(byte(i)), deadline: time.Now().Add(time.Minute)}
			}
			// The skipped entry has the earliest deadline, so it is the pick whenever it is eligible.
			tester.fetcher.parked[skipped] = &parkedBlock{block: newParkedTestBlock(0x5e), deadline: time.Now().Add(30 * time.Second), retryAfter: time.Now().Add(tt.backoff)}
			tester.fetcher.parkedMu.Unlock()

			full := blockParkedFullMeter.Snapshot().Count()
			reclaimed := blockParkedReclaimedMeter.Snapshot().Count()
			block := newParkedTestBlock(0x5f)
			tester.fetcher.parkForSignatureStored(block, false)

			tester.fetcher.parkedMu.Lock()
			_, kept := tester.fetcher.parked[skipped]
			_, parked := tester.fetcher.parked[block.Hash()]
			n := len(tester.fetcher.parked)
			tester.fetcher.parkedMu.Unlock()

			if kept != !tt.reclaim {
				t.Fatalf("skipped entry kept = %v, want %v", kept, !tt.reclaim)
			}
			if parked != tt.reclaim {
				t.Fatalf("fresh block parked = %v, want %v", parked, tt.reclaim)
			}
			if n != maxParkedSignatures {
				t.Fatalf("parked count = %d, want %d", n, maxParkedSignatures)
			}
			var wantReclaimed, wantFull int64
			if tt.reclaim {
				wantReclaimed = 1
			} else {
				wantFull = 1
			}
			if got := blockParkedReclaimedMeter.Snapshot().Count() - reclaimed; got != wantReclaimed {
				t.Fatalf("reclaimed meter moved by %d, want %d", got, wantReclaimed)
			}
			if got := blockParkedFullMeter.Snapshot().Count() - full; got != wantFull {
				t.Fatalf("full meter moved by %d, want %d", got, wantFull)
			}
		})
	}
}

// TestParkedSignatureReclaimKeepsUnimportedShareWhenTotalBinds pins the budget a
// reclaim draws from: with the total set full but the stored subset open, a stored
// admission may only drop a stored entry, so an entry waiting on a block the
// downloader is still importing keeps its slot.
func TestParkedSignatureReclaimKeepsUnimportedShareWhenTotalBinds(t *testing.T) {
	for _, tt := range []struct {
		name       string
		storedSkip int
		wantParked bool
	}{
		{"no stored skipped entry", 0, false},
		{"a stored skipped entry", 1, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tester := newTester()
			defer tester.fetcher.Stop()
			tester.fetcher.signHook = func(*types.Block) error { return nil }

			unimportedSkipped := common.BytesToHash([]byte{0x0a, 0x01})
			storedSkipped := common.BytesToHash([]byte{0x0a, 0x02})
			tester.fetcher.parkedMu.Lock()
			for i := 0; i < 40-tt.storedSkip; i++ {
				hash := common.BytesToHash([]byte{0x0b, byte(i)})
				tester.fetcher.parked[hash] = &parkedBlock{block: newParkedTestBlock(byte(i)), deadline: time.Now().Add(time.Minute), stored: true}
			}
			for i := 0; i < tt.storedSkip; i++ {
				// The stored skipped entry has the earliest deadline, so an
				// undirected reclaim would take it anyway.
				tester.fetcher.parked[storedSkipped] = &parkedBlock{block: newParkedTestBlock(0x8a), deadline: time.Now().Add(20 * time.Second), stored: true, retryAfter: time.Now().Add(time.Minute)}
			}
			for i := 0; i < 23; i++ {
				hash := common.BytesToHash([]byte{0x0c, byte(i)})
				tester.fetcher.parked[hash] = &parkedBlock{block: newParkedTestBlock(byte(0x40 + i)), deadline: time.Now().Add(time.Minute)}
			}
			// The unimported skipped entry must keep its slot either way.
			tester.fetcher.parked[unimportedSkipped] = &parkedBlock{block: newParkedTestBlock(0x8b), deadline: time.Now().Add(30 * time.Second), retryAfter: time.Now().Add(time.Minute)}
			tester.fetcher.parkedMu.Unlock()

			full := blockParkedFullMeter.Snapshot().Count()
			reclaimed := blockParkedReclaimedMeter.Snapshot().Count()
			block := newParkedTestBlock(0x8c)
			tester.fetcher.parkForSignatureStored(block, true)

			tester.fetcher.parkedMu.Lock()
			_, parked := tester.fetcher.parked[block.Hash()]
			_, unimportedKept := tester.fetcher.parked[unimportedSkipped]
			n := len(tester.fetcher.parked)
			tester.fetcher.parkedMu.Unlock()

			if parked != tt.wantParked {
				t.Fatalf("fresh stored block parked = %v, want %v", parked, tt.wantParked)
			}
			if !unimportedKept {
				t.Fatalf("an unimported skipped entry lost its slot to a stored admission")
			}
			if n != maxParkedSignatures {
				t.Fatalf("parked count = %d, want %d", n, maxParkedSignatures)
			}
			var wantReclaimed, wantFull int64
			if tt.wantParked {
				wantReclaimed = 1
			} else {
				wantFull = 1
			}
			if got := blockParkedReclaimedMeter.Snapshot().Count() - reclaimed; got != wantReclaimed {
				t.Fatalf("reclaimed meter moved by %d, want %d", got, wantReclaimed)
			}
			if got := blockParkedFullMeter.Snapshot().Count() - full; got != wantFull {
				t.Fatalf("full meter moved by %d, want %d", got, wantFull)
			}
		})
	}
}

// TestParkedSignatureRefusedClaimKeepsUnimportedShare pins the refused-claim
// re-park to the stored budget: with the total set full but the stored subset
// open, the claim may only reclaim a stored skipped entry.
func TestParkedSignatureRefusedClaimKeepsUnimportedShare(t *testing.T) {
	for _, tt := range []struct {
		name       string
		storedSkip int
		wantParked bool
	}{
		{"no stored skipped entry", 0, false},
		{"a stored skipped entry", 1, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tester := newTester()
			defer tester.fetcher.Stop()
			tester.fetcher.signHook = func(*types.Block) error { return nil }

			unimportedSkipped := common.BytesToHash([]byte{0x0f, 0x01})
			storedSkipped := common.BytesToHash([]byte{0x0f, 0x02})
			block := newParkedTestBlock(0x9c)
			tester.fetcher.parkedMu.Lock()
			for i := 0; i < 40-tt.storedSkip; i++ {
				hash := common.BytesToHash([]byte{0x10, byte(i)})
				tester.fetcher.parked[hash] = &parkedBlock{block: newParkedTestBlock(byte(i)), deadline: time.Now().Add(time.Minute), stored: true}
			}
			for i := 0; i < tt.storedSkip; i++ {
				tester.fetcher.parked[storedSkipped] = &parkedBlock{block: newParkedTestBlock(0x9a), deadline: time.Now().Add(20 * time.Second), stored: true, retryAfter: time.Now().Add(time.Minute)}
			}
			for i := 0; i < 23; i++ {
				hash := common.BytesToHash([]byte{0x11, byte(i)})
				tester.fetcher.parked[hash] = &parkedBlock{block: newParkedTestBlock(byte(0x40 + i)), deadline: time.Now().Add(time.Minute)}
			}
			tester.fetcher.parked[unimportedSkipped] = &parkedBlock{block: newParkedTestBlock(0x9b), deadline: time.Now().Add(30 * time.Second), retryAfter: time.Now().Add(time.Minute)}
			// The delivery path takes the claim marker before it settles the claim.
			tester.fetcher.signing[block.Hash()] = struct{}{}
			tester.fetcher.parkedMu.Unlock()

			full := blockParkedFullMeter.Snapshot().Count()
			reclaimed := blockParkedReclaimedMeter.Snapshot().Count()
			tester.fetcher.settleRefusedClaim(block, false)

			tester.fetcher.parkedMu.Lock()
			_, parked := tester.fetcher.parked[block.Hash()]
			_, unimportedKept := tester.fetcher.parked[unimportedSkipped]
			_, storedKept := tester.fetcher.parked[storedSkipped]
			n := len(tester.fetcher.parked)
			markers := len(tester.fetcher.signing)
			bookings := len(tester.fetcher.pending)
			tester.fetcher.parkedMu.Unlock()

			if parked != tt.wantParked {
				t.Fatalf("refused claim parked = %v, want %v", parked, tt.wantParked)
			}
			if !unimportedKept {
				t.Fatalf("an unimported skipped entry lost its slot to a refused claim")
			}
			if tt.wantParked && storedKept {
				t.Fatalf("the stored skipped entry was not reclaimed for a refused claim")
			}
			if n != maxParkedSignatures {
				t.Fatalf("parked count = %d, want %d", n, maxParkedSignatures)
			}
			if markers != 0 || bookings != 0 {
				t.Fatalf("markers = %d, bookings = %d after settling the claim, want 0 and 0", markers, bookings)
			}
			var wantReclaimed, wantFull int64
			if tt.wantParked {
				wantReclaimed = 1
			} else {
				wantFull = 1
			}
			if got := blockParkedReclaimedMeter.Snapshot().Count() - reclaimed; got != wantReclaimed {
				t.Fatalf("reclaimed meter moved by %d, want %d", got, wantReclaimed)
			}
			if got := blockParkedFullMeter.Snapshot().Count() - full; got != wantFull {
				t.Fatalf("full meter moved by %d, want %d", got, wantFull)
			}
		})
	}
}

// TestParkedSignatureUnimportedAdmissionReclaimsStoredSkipped pins that an
// unimported admission may drop a stored skipped entry: freeing a stored slot
// only widens the reserve, so the pick is not restricted to its own bucket.
func TestParkedSignatureUnimportedAdmissionReclaimsStoredSkipped(t *testing.T) {
	tester := newTester()
	defer tester.fetcher.Stop()
	tester.fetcher.signHook = func(*types.Block) error { return nil }

	storedSkipped := common.BytesToHash([]byte{0x12, 0x01})
	block := newParkedTestBlock(0x9e)
	tester.fetcher.parkedMu.Lock()
	for i := 0; i < 47; i++ {
		hash := common.BytesToHash([]byte{0x13, byte(i)})
		tester.fetcher.parked[hash] = &parkedBlock{block: newParkedTestBlock(byte(i)), deadline: time.Now().Add(time.Minute), stored: true}
	}
	tester.fetcher.parked[storedSkipped] = &parkedBlock{block: newParkedTestBlock(0x9d), deadline: time.Now().Add(20 * time.Second), stored: true, retryAfter: time.Now().Add(time.Minute)}
	for i := 0; i < 16; i++ {
		hash := common.BytesToHash([]byte{0x14, byte(i)})
		tester.fetcher.parked[hash] = &parkedBlock{block: newParkedTestBlock(byte(0x40 + i)), deadline: time.Now().Add(time.Minute)}
	}
	tester.fetcher.parkedMu.Unlock()

	full := blockParkedFullMeter.Snapshot().Count()
	reclaimed := blockParkedReclaimedMeter.Snapshot().Count()
	tester.fetcher.parkForSignatureStored(block, false)

	tester.fetcher.parkedMu.Lock()
	_, parked := tester.fetcher.parked[block.Hash()]
	_, storedKept := tester.fetcher.parked[storedSkipped]
	n := len(tester.fetcher.parked)
	tester.fetcher.parkedMu.Unlock()

	if !parked {
		t.Fatalf("an unimported admission did not reclaim a stored skipped entry")
	}
	if storedKept {
		t.Fatalf("the stored skipped entry kept its slot")
	}
	if n != maxParkedSignatures {
		t.Fatalf("parked count = %d, want %d", n, maxParkedSignatures)
	}
	if got := blockParkedReclaimedMeter.Snapshot().Count() - reclaimed; got != 1 {
		t.Fatalf("reclaimed meter moved by %d, want 1", got)
	}
	if got := blockParkedFullMeter.Snapshot().Count() - full; got != 0 {
		t.Fatalf("full meter moved by %d, want 0", got)
	}
}

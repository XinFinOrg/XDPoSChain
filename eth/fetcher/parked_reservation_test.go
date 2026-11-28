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
	"testing"
	"time"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/types"
)

// TestParkedSignatureReservedAdmissionSurvivesStoredFlip pins that a slot booked
// before the signer gate becomes an entry after it, even when the scan flipped an
// entry to stored while the gate ran: the stored cap is an admission gate, not a
// post-gate one.
func TestParkedSignatureReservedAdmissionSurvivesStoredFlip(t *testing.T) {
	tester := newTester()
	defer tester.fetcher.Stop()
	tester.fetcher.signHook = func(*types.Block) error { return nil }

	flip := common.BytesToHash([]byte{0x20, 0x01})
	tester.fetcher.parkedMu.Lock()
	for i := 0; i < maxParkedStored-1; i++ {
		hash := common.BytesToHash([]byte{0x21, byte(i)})
		tester.fetcher.parked[hash] = &parkedBlock{block: newParkedTestBlock(byte(i)), deadline: time.Now().Add(time.Minute), stored: true}
	}
	for i := 0; i < maxParkedSignatures-maxParkedStored-1; i++ {
		hash := common.BytesToHash([]byte{0x22, byte(i)})
		tester.fetcher.parked[hash] = &parkedBlock{block: newParkedTestBlock(byte(0x80 + i)), deadline: time.Now().Add(time.Minute)}
	}
	tester.fetcher.parked[flip] = &parkedBlock{block: newParkedTestBlock(0x7f), deadline: time.Now().Add(time.Minute)}
	tester.fetcher.parkedMu.Unlock()

	reclaimed := blockParkedReclaimedMeter.Snapshot().Count()
	var storedInGate int
	tester.fetcher.SetSignerGate(func() bool {
		// The scan flips an entry to stored while the gate runs.
		tester.fetcher.parkedMu.Lock()
		tester.fetcher.parked[flip].stored = true
		storedInGate = tester.fetcher.parkedStoredLocked()
		tester.fetcher.parkedMu.Unlock()
		return true
	})

	block := newParkedTestBlock(0x77)
	tester.fetcher.parkForSignatureStored(block, true)

	if storedInGate != maxParkedStored {
		t.Fatalf("stored entries while the gate ran = %d, want %d", storedInGate, maxParkedStored)
	}
	tester.fetcher.parkedMu.Lock()
	_, parked := tester.fetcher.parked[block.Hash()]
	n := len(tester.fetcher.parked)
	stored := tester.fetcher.parkedStoredLocked()
	tester.fetcher.parkedMu.Unlock()

	if !parked {
		t.Fatalf("the block admitted before the gate was not parked after it")
	}
	if n != maxParkedSignatures {
		t.Fatalf("parked count = %d after the gated admission, want %d", n, maxParkedSignatures)
	}
	if stored != maxParkedStored+1 {
		t.Fatalf("stored entries = %d after the flip and the reservation, want %d", stored, maxParkedStored+1)
	}
	if got := blockParkedReclaimedMeter.Snapshot().Count() - reclaimed; got != 0 {
		t.Fatalf("reclaimed meter moved by %d for a reserved admission, want 0", got)
	}
}

// TestParkedSignatureReclaimRefusesWhenOneRemovalCannotReopen pins the reclaim
// guard: an entry is only dropped when one removal takes the admission, so a set
// already past the stored cap keeps its skipped retries and refuses the block.
func TestParkedSignatureReclaimRefusesWhenOneRemovalCannotReopen(t *testing.T) {
	for _, tt := range []struct {
		name    string
		stored  int
		skipped int
	}{
		{"one skipped retry", maxParkedStored + 1, 1},
		{"two skipped retries", maxParkedStored + 2, 2},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tester := newTester()
			defer tester.fetcher.Stop()
			tester.fetcher.signHook = func(*types.Block) error { return nil }

			skipped := make([]common.Hash, 0, tt.skipped)
			tester.fetcher.parkedMu.Lock()
			for i := 0; i < tt.stored-tt.skipped; i++ {
				hash := common.BytesToHash([]byte{0x30, byte(i)})
				tester.fetcher.parked[hash] = &parkedBlock{block: newParkedTestBlock(byte(i)), deadline: time.Now().Add(time.Minute), stored: true}
			}
			for i := 0; i < tt.skipped; i++ {
				hash := common.BytesToHash([]byte{0x31, byte(i)})
				skipped = append(skipped, hash)
				// The skipped entries have the earliest deadlines, so a blind reclaim picks them first.
				tester.fetcher.parked[hash] = &parkedBlock{block: newParkedTestBlock(byte(0x90 + i)), deadline: time.Now().Add(30 * time.Second), stored: true, retryAfter: time.Now().Add(time.Minute)}
			}
			tester.fetcher.parkedMu.Unlock()

			full := blockParkedFullMeter.Snapshot().Count()
			reclaimed := blockParkedReclaimedMeter.Snapshot().Count()
			block := newParkedTestBlock(0x78)
			tester.fetcher.parkForSignatureStored(block, true)

			tester.fetcher.parkedMu.Lock()
			_, parked := tester.fetcher.parked[block.Hash()]
			kept := 0
			for _, hash := range skipped {
				if _, ok := tester.fetcher.parked[hash]; ok {
					kept++
				}
			}
			n := len(tester.fetcher.parked)
			stored := tester.fetcher.parkedStoredLocked()
			tester.fetcher.parkedMu.Unlock()

			if parked {
				t.Fatalf("a stored admission was parked although one reclaim cannot reopen the stored gate")
			}
			if kept != tt.skipped {
				t.Fatalf("skipped entries kept = %d, want %d", kept, tt.skipped)
			}
			if n != tt.stored {
				t.Fatalf("parked count = %d after the refused admission, want %d", n, tt.stored)
			}
			if stored != tt.stored {
				t.Fatalf("stored entries = %d after the refused admission, want %d", stored, tt.stored)
			}
			if got := blockParkedReclaimedMeter.Snapshot().Count() - reclaimed; got != 0 {
				t.Fatalf("reclaimed meter moved by %d for a refused admission, want 0", got)
			}
			if got := blockParkedFullMeter.Snapshot().Count() - full; got != 1 {
				t.Fatalf("full meter moved by %d for a refused admission, want 1", got)
			}
		})
	}
}

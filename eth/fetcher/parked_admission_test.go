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

func newStoredPressureTester(t *testing.T) (*fetcherTester, common.Hash) {
	t.Helper()
	tester := newIdleTester()
	t.Cleanup(tester.fetcher.Stop)
	tester.fetcher.signHook = func(*types.Block) error { return nil }
	tester.fetcher.parkedWaiter = true
	victim := common.BytesToHash([]byte{0x81, 0x01})
	tester.fetcher.parkedMu.Lock()
	for i := 0; i < maxParkedStored-1; i++ {
		hash := common.BytesToHash([]byte{0x82, byte(i)})
		tester.fetcher.parked[hash] = &parkedBlock{block: newParkedTestBlock(byte(i)), deadline: time.Now().Add(time.Minute), stored: true}
	}
	tester.fetcher.parked[victim] = &parkedBlock{block: newParkedTestBlock(0xfd), deadline: time.Now().Add(30 * time.Second), stored: true, retryAfter: time.Now().Add(time.Minute)}
	tester.fetcher.parkedMu.Unlock()
	return tester, victim
}

func newAdmissionOrderTester(t *testing.T, victimStored bool) (*fetcherTester, common.Hash) {
	t.Helper()
	tester := newIdleTester()
	t.Cleanup(tester.fetcher.Stop)
	tester.fetcher.signHook = func(*types.Block) error { return nil }
	tester.fetcher.parkedWaiter = true
	victim := common.BytesToHash([]byte{0x83, 0x01})
	tester.fetcher.parkedMu.Lock()
	for i := 0; i < maxParkedSignatures-2; i++ {
		hash := common.BytesToHash([]byte{0x84, byte(i)})
		tester.fetcher.parked[hash] = &parkedBlock{block: newParkedTestBlock(byte(i)), deadline: time.Now().Add(time.Minute)}
	}
	tester.fetcher.parked[victim] = &parkedBlock{block: newParkedTestBlock(0xfc), deadline: time.Now().Add(30 * time.Second), stored: victimStored, retryAfter: time.Now().Add(time.Minute)}
	tester.fetcher.parkedMu.Unlock()
	return tester, victim
}

func assertUnreclaimableVictim(t *testing.T, f *BlockFetcher, victim common.Hash, block *types.Block, reclaimed, full int64) {
	t.Helper()
	f.parkedMu.Lock()
	defer f.parkedMu.Unlock()
	if _, ok := f.parked[victim]; !ok {
		t.Fatal("the skipped victim was dropped although it stopped being reclaimable during the gate")
	}
	if _, ok := f.parked[block.Hash()]; ok {
		t.Fatal("a fresh block was parked although its victim was not reclaimed")
	}
	if n := f.parkedStoredLocked(); n != maxParkedStored {
		t.Fatalf("stored entries = %d, want %d", n, maxParkedStored)
	}
	if n := len(f.pending); n != 0 {
		t.Fatalf("reservations left after admission = %d, want 0", n)
	}
	if got := blockParkedReclaimedMeter.Snapshot().Count() - reclaimed; got != 0 {
		t.Fatalf("reclaimed meter moved by %d for a victim that stayed in the set, want 0", got)
	}
	if got := blockParkedFullMeter.Snapshot().Count() - full; got != 1 {
		t.Fatalf("full meter moved by %d for an admission without freed capacity, want 1", got)
	}
}

func TestParkedSignatureStoredAdmissionKeepsUnreclaimableVictim(t *testing.T) {
	tester, victim := newStoredPressureTester(t)
	tester.fetcher.SetSignerGate(func() bool {
		tester.fetcher.parkedMu.Lock()
		tester.fetcher.parked[victim].claimed = true
		tester.fetcher.parkedMu.Unlock()
		return true
	})
	block := newParkedTestBlock(0xfe)
	reclaimed := blockParkedReclaimedMeter.Snapshot().Count()
	full := blockParkedFullMeter.Snapshot().Count()
	tester.fetcher.parkForSignatureStored(block, true)
	assertUnreclaimableVictim(t, tester.fetcher, victim, block, reclaimed, full)
}

func TestSettleRefusedClaimStoredAdmissionKeepsUnreclaimableVictim(t *testing.T) {
	tester, victim := newStoredPressureTester(t)
	tester.fetcher.SetSignerGate(func() bool {
		tester.fetcher.parkedMu.Lock()
		tester.fetcher.parked[victim].retryAfter = time.Now().Add(-time.Second)
		tester.fetcher.parkedMu.Unlock()
		return true
	})
	block := newParkedTestBlock(0xfe)
	reclaimed := blockParkedReclaimedMeter.Snapshot().Count()
	full := blockParkedFullMeter.Snapshot().Count()
	tester.fetcher.settleRefusedClaim(block, false)
	assertUnreclaimableVictim(t, tester.fetcher, victim, block, reclaimed, full)
}

func TestParkedSignatureAdmitsStoredBlockAfterReclaim(t *testing.T) {
	tester, victim := newStoredPressureTester(t)
	tester.fetcher.SetSignerGate(func() bool { return true })
	block := newParkedTestBlock(0xfe)
	reclaimed := blockParkedReclaimedMeter.Snapshot().Count()
	tester.fetcher.parkForSignatureStored(block, true)
	f := tester.fetcher
	f.parkedMu.Lock()
	defer f.parkedMu.Unlock()
	if _, ok := f.parked[victim]; ok {
		t.Fatal("the reclaimed victim stayed in the set")
	}
	if _, ok := f.parked[block.Hash()]; !ok {
		t.Fatal("the admitted stored block was not parked after its victim was reclaimed")
	}
	if n := f.parkedStoredLocked(); n != maxParkedStored {
		t.Fatalf("stored entries = %d after a reclaim, want %d", n, maxParkedStored)
	}
	if got := blockParkedReclaimedMeter.Snapshot().Count() - reclaimed; got != 1 {
		t.Fatalf("reclaimed meter moved by %d, want 1", got)
	}
}

func TestOrdinaryReservationSurvivesReclaimBackedGate(t *testing.T) {
	for _, tt := range []struct {
		name         string
		settleB      bool
		victimStored bool
	}{
		{"park path", false, false},
		{"settle path", true, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tester, victim := newAdmissionOrderTester(t, tt.victimStored)
			f := tester.fetcher
			enteredA, enteredB := make(chan struct{}), make(chan struct{})
			releaseA, releaseB := make(chan struct{}), make(chan struct{})
			doneA, doneB := make(chan struct{}), make(chan struct{})
			var calls atomic.Int32
			f.SetSignerGate(func() bool {
				switch calls.Add(1) {
				case 1:
					close(enteredA)
					<-releaseA
				case 2:
					close(enteredB)
					<-releaseB
				}
				return true
			})
			blockA, blockB := newParkedTestBlock(0xfa), newParkedTestBlock(0xfb)
			go func() { f.parkForSignatureStored(blockA, false); close(doneA) }()
			<-enteredA
			go func() {
				if tt.settleB {
					f.settleRefusedClaim(blockB, false)
				} else {
					f.parkForSignatureStored(blockB, false)
				}
				close(doneB)
			}()
			<-enteredB
			close(releaseA)
			<-doneA
			close(releaseB)
			<-doneB
			f.parkedMu.Lock()
			defer f.parkedMu.Unlock()
			_, aParked := f.parked[blockA.Hash()]
			_, bParked := f.parked[blockB.Hash()]
			_, victimKept := f.parked[victim]
			if !aParked || !bParked || victimKept || len(f.parked) != maxParkedSignatures || len(f.pending) != 0 {
				t.Fatalf("A=%v B=%v victim=%v total=%d pending=%d", aParked, bParked, victimKept, len(f.parked), len(f.pending))
			}
		})
	}
}

func TestOnlyOneGateCanReserveAVictim(t *testing.T) {
	tester, victim := newAdmissionOrderTester(t, false)
	f := tester.fetcher
	f.parkedMu.Lock()
	extra := common.BytesToHash([]byte{0x85, 0x01})
	f.parked[extra] = &parkedBlock{block: newParkedTestBlock(0xf7), deadline: time.Now().Add(time.Minute)}
	f.parkedMu.Unlock()

	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	f.SetSignerGate(func() bool {
		if calls.Add(1) == 1 {
			close(entered)
			<-release
		}
		return true
	})
	blockA, blockB := newParkedTestBlock(0xf8), newParkedTestBlock(0xf9)
	go func() { f.parkForSignatureStored(blockA, false); close(done) }()
	<-entered
	f.parkForSignatureStored(blockB, false)
	f.parkedMu.Lock()
	pendingDuring := len(f.pending)
	_, bParkedDuring := f.parked[blockB.Hash()]
	_, victimKeptDuring := f.parked[victim]
	f.parkedMu.Unlock()
	if pendingDuring != 1 || bParkedDuring || !victimKeptDuring {
		t.Fatalf("pending=%d B=%v victim=%v", pendingDuring, bParkedDuring, victimKeptDuring)
	}
	close(release)
	<-done
	f.parkedMu.Lock()
	defer f.parkedMu.Unlock()
	_, aParked := f.parked[blockA.Hash()]
	_, bParked := f.parked[blockB.Hash()]
	_, victimKept := f.parked[victim]
	if !aParked || bParked || victimKept || len(f.parked) != maxParkedSignatures || len(f.pending) != 0 {
		t.Fatalf("A=%v B=%v victim=%v total=%d pending=%d", aParked, bParked, victimKept, len(f.parked), len(f.pending))
	}
}

func TestTwoStoredReclaimsKeepTheStoredCap(t *testing.T) {
	tester := newIdleTester()
	t.Cleanup(tester.fetcher.Stop)
	f := tester.fetcher
	f.signHook = func(*types.Block) error { return nil }
	f.parkedWaiter = true
	victimA := common.BytesToHash([]byte{0x95, 0x01})
	victimB := common.BytesToHash([]byte{0x95, 0x02})
	f.parkedMu.Lock()
	for i := 0; i < maxParkedStored-2; i++ {
		hash := common.BytesToHash([]byte{0x96, byte(i)})
		f.parked[hash] = &parkedBlock{block: newParkedTestBlock(byte(i)), deadline: time.Now().Add(time.Minute), stored: true}
	}
	for i, victim := range []common.Hash{victimA, victimB} {
		f.parked[victim] = &parkedBlock{block: newParkedTestBlock(byte(0xfc + i)), deadline: time.Now().Add(30 * time.Second), stored: true, retryAfter: time.Now().Add(time.Minute)}
	}
	f.parkedMu.Unlock()

	enteredA, enteredB := make(chan struct{}), make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	f.SetSignerGate(func() bool {
		switch calls.Add(1) {
		case 1:
			close(enteredA)
			<-release
		case 2:
			close(enteredB)
			<-release
		}
		return true
	})
	blockA, blockB := newParkedTestBlock(0xfa), newParkedTestBlock(0xfb)
	doneA, doneB := make(chan struct{}), make(chan struct{})
	go func() { f.parkForSignatureStored(blockA, true); close(doneA) }()
	<-enteredA
	go func() { f.parkForSignatureStored(blockB, true); close(doneB) }()
	select {
	case <-enteredB:
	case <-time.After(time.Second):
		close(release)
		<-doneA
		<-doneB
		t.Fatal("the second stored reclaim never reached the signer gate")
	}
	close(release)
	<-doneA
	<-doneB
	f.parkedMu.Lock()
	defer f.parkedMu.Unlock()
	_, aParked := f.parked[blockA.Hash()]
	_, bParked := f.parked[blockB.Hash()]
	_, victimAKept := f.parked[victimA]
	_, victimBKept := f.parked[victimB]
	if !aParked || !bParked || victimAKept || victimBKept {
		t.Fatalf("A=%v B=%v victimA=%v victimB=%v", aParked, bParked, victimAKept, victimBKept)
	}
	if n := f.parkedStoredLocked(); n != maxParkedStored {
		t.Fatalf("stored entries = %d, want %d", n, maxParkedStored)
	}
	if n := len(f.parked); n != maxParkedStored {
		t.Fatalf("parked entries = %d, want %d", n, maxParkedStored)
	}
	if n := len(f.pending); n != 0 {
		t.Fatalf("reservations left after admission = %d, want 0", n)
	}
}

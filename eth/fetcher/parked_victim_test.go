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

func newVictimGateTester(t *testing.T, mutate func(*BlockFetcher, common.Hash)) (*fetcherTester, common.Hash) {
	t.Helper()
	tester := newIdleTester()
	t.Cleanup(tester.fetcher.Stop)
	tester.fetcher.signHook = func(*types.Block) error { return nil }
	victim := common.BytesToHash([]byte{0x51, 0x01})
	tester.fetcher.parkedMu.Lock()
	for i := 0; i < maxParkedSignatures-1; i++ {
		hash := common.BytesToHash([]byte{0x50, byte(i)})
		tester.fetcher.parked[hash] = &parkedBlock{
			block:    newParkedTestBlock(byte(i)),
			deadline: time.Now().Add(time.Minute),
			stored:   i < maxParkedStored-1,
		}
	}
	tester.fetcher.parked[victim] = &parkedBlock{
		block:      newParkedTestBlock(0x91),
		deadline:   time.Now().Add(time.Minute),
		retryAfter: time.Now().Add(time.Minute),
	}
	tester.fetcher.parkedMu.Unlock()
	tester.fetcher.SetSignerGate(func() bool {
		tester.fetcher.parkedMu.Lock()
		mutate(tester.fetcher, victim)
		tester.fetcher.parkedMu.Unlock()
		return true
	})
	return tester, victim
}

func assertVictimKept(t *testing.T, tester *fetcherTester, victim common.Hash, block *types.Block, reclaimed int64) {
	t.Helper()
	tester.fetcher.parkedMu.Lock()
	defer tester.fetcher.parkedMu.Unlock()
	if _, ok := tester.fetcher.parked[victim]; !ok {
		t.Fatalf("the skipped victim was dropped although it stopped being reclaimable during the gate")
	}
	if _, ok := tester.fetcher.parked[block.Hash()]; ok {
		t.Fatalf("a fresh block was parked although its victim was not reclaimed")
	}
	if got := blockParkedReclaimedMeter.Snapshot().Count() - reclaimed; got != 0 {
		t.Fatalf("reclaimed meter moved by %d for a victim that stayed in the set, want 0", got)
	}
	if n := len(tester.fetcher.pending); n != 0 {
		t.Fatalf("reservations left after admission = %d, want 0", n)
	}
}

func TestParkedSignatureReclaimKeepsVictimClaimedDuringGate(t *testing.T) {
	tester, victim := newVictimGateTester(t, func(f *BlockFetcher, hash common.Hash) {
		f.parked[hash].claimed = true
	})
	block := newParkedTestBlock(0xa1)
	reclaimed := blockParkedReclaimedMeter.Snapshot().Count()
	tester.fetcher.parkForSignatureStored(block, false)
	assertVictimKept(t, tester, victim, block, reclaimed)
}

func TestParkedSignatureReclaimKeepsVictimPastBackoffDuringGate(t *testing.T) {
	tester, victim := newVictimGateTester(t, func(f *BlockFetcher, hash common.Hash) {
		f.parked[hash].retryAfter = time.Now().Add(-time.Second)
	})
	block := newParkedTestBlock(0xa2)
	reclaimed := blockParkedReclaimedMeter.Snapshot().Count()
	tester.fetcher.parkForSignatureStored(block, false)
	assertVictimKept(t, tester, victim, block, reclaimed)
}

func TestParkedSignatureReclaimKeepsReplacedVictimDuringGate(t *testing.T) {
	tester, victim := newVictimGateTester(t, func(f *BlockFetcher, hash common.Hash) {
		delete(f.parked, hash)
		f.parked[hash] = &parkedBlock{block: newParkedTestBlock(0x92), deadline: time.Now().Add(time.Minute), retryAfter: time.Now().Add(time.Minute)}
	})
	block := newParkedTestBlock(0xa3)
	reclaimed := blockParkedReclaimedMeter.Snapshot().Count()
	tester.fetcher.parkForSignatureStored(block, false)
	assertVictimKept(t, tester, victim, block, reclaimed)
}

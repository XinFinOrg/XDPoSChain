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

func newRefusalSet(ready bool) (*fetcherTester, map[common.Hash]bool) {
	tester := newIdleTester()
	tester.fetcher.SetSignerGate(func() bool { return ready })
	tester.fetcher.signHook = func(*types.Block) error { return nil }
	before := make(map[common.Hash]bool)
	deadline := time.Now().Add(time.Minute)
	tester.fetcher.parkedMu.Lock()
	for i := 0; i < maxParkedSignatures; i++ {
		hash := common.BytesToHash([]byte{0x01, byte(i)})
		tester.fetcher.parked[hash] = &parkedBlock{
			block:      newParkedTestBlock(0x60),
			deadline:   deadline,
			stored:     i < maxParkedStored-1,
			retryAfter: time.Now().Add(time.Minute),
		}
		before[hash] = true
	}
	tester.fetcher.parkedMu.Unlock()
	return tester, before
}

func refusalLost(tester *fetcherTester, before map[common.Hash]bool) int {
	lost := 0
	for h := range before {
		if _, ok := tester.fetcher.parked[h]; !ok {
			lost++
		}
	}
	return lost
}

func TestParkedSignatureRefusedAdmissionKeepsSkippedEntry(t *testing.T) {
	tester, before := newRefusalSet(false)
	defer tester.fetcher.Stop()
	block := newParkedTestBlock(0x61)
	reclaimed := blockParkedReclaimedMeter.Snapshot().Count()
	tester.fetcher.parkForSignatureStored(block, false)
	tester.fetcher.parkedMu.Lock()
	defer tester.fetcher.parkedMu.Unlock()
	if lost := refusalLost(tester, before); lost != 0 {
		t.Fatalf("lost %d skipped entries to a refused admission, want 0", lost)
	}
	if _, ok := tester.fetcher.parked[block.Hash()]; ok {
		t.Fatalf("the refused block was parked")
	}
	if n := len(tester.fetcher.parked); n != maxParkedSignatures {
		t.Fatalf("parked count = %d after a refusal, want %d", n, maxParkedSignatures)
	}
	if n := len(tester.fetcher.pending) + len(tester.fetcher.signing); n != 0 {
		t.Fatalf("reservations and markers left after a refusal = %d, want 0", n)
	}
	if got := blockParkedReclaimedMeter.Snapshot().Count() - reclaimed; got != 0 {
		t.Fatalf("reclaimed meter moved by %d for a refused admission, want 0", got)
	}
}

func TestSettleRefusedClaimRefusalKeepsSkippedEntry(t *testing.T) {
	tester, before := newRefusalSet(false)
	defer tester.fetcher.Stop()
	block := newParkedTestBlock(0x61)
	reclaimed := blockParkedReclaimedMeter.Snapshot().Count()
	tester.fetcher.settleRefusedClaim(block, false)
	tester.fetcher.parkedMu.Lock()
	defer tester.fetcher.parkedMu.Unlock()
	if lost := refusalLost(tester, before); lost != 0 {
		t.Fatalf("lost %d skipped entries to a refused claim, want 0", lost)
	}
	if _, ok := tester.fetcher.parked[block.Hash()]; ok {
		t.Fatalf("the refused claim was parked")
	}
	if n := len(tester.fetcher.parked); n != maxParkedSignatures {
		t.Fatalf("parked count = %d after a refusal, want %d", n, maxParkedSignatures)
	}
	if got := blockParkedReclaimedMeter.Snapshot().Count() - reclaimed; got != 0 {
		t.Fatalf("reclaimed meter moved by %d for a refused claim, want 0", got)
	}
}

func TestParkedSignatureAdmissionReclaimsOnlyAfterBooking(t *testing.T) {
	tester, before := newRefusalSet(true)
	defer tester.fetcher.Stop()
	block := newParkedTestBlock(0x61)
	reclaimed := blockParkedReclaimedMeter.Snapshot().Count()
	tester.fetcher.parkForSignatureStored(block, false)
	tester.fetcher.parkedMu.Lock()
	defer tester.fetcher.parkedMu.Unlock()
	if lost := refusalLost(tester, before); lost != 1 {
		t.Fatalf("lost %d skipped entries to an admitted block, want 1", lost)
	}
	if _, ok := tester.fetcher.parked[block.Hash()]; !ok {
		t.Fatalf("the admitted block was not parked")
	}
	if n := len(tester.fetcher.parked); n != maxParkedSignatures {
		t.Fatalf("parked count = %d after admission, want %d", n, maxParkedSignatures)
	}
	if got := blockParkedReclaimedMeter.Snapshot().Count() - reclaimed; got != 1 {
		t.Fatalf("reclaimed meter moved by %d for an admitted block, want 1", got)
	}
}

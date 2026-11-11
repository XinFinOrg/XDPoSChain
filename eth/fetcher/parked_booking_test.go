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

	"github.com/XinFinOrg/XDPoSChain/core/types"
)

// TestForgetHashKeepsSignerGateBooking pins that forgetting an announced hash
// does not cancel a slot booked across the signer gate: a fetch timer can forget
// the hash while the gate runs, and the block must still be parked.
func TestForgetHashKeepsSignerGateBooking(t *testing.T) {
	// forgetHash runs on the loop goroutine in production; drive it on a fetcher
	// whose loop never started, or the announce maps race with it.
	tester := newIdleTester()
	defer tester.fetcher.Stop()
	tester.fetcher.signHook = func(*types.Block) error { return nil }

	block := newParkedTestBlock(0x42)
	var booked int
	tester.fetcher.SetSignerGate(func() bool {
		tester.fetcher.announced[block.Hash()] = []*blockAnnounce{{origin: "test"}}
		tester.fetcher.announces["test"] = 1
		tester.fetcher.forgetHash(block.Hash())

		tester.fetcher.parkedMu.Lock()
		booked = len(tester.fetcher.pending)
		tester.fetcher.parkedMu.Unlock()
		return true
	})
	tester.fetcher.parkForSignatureStored(block, true)

	if booked != 1 {
		t.Fatalf("bookings while the gate ran = %d, want 1", booked)
	}
	if n := parkedCount(tester.fetcher); n != 1 {
		t.Fatalf("parked count = %d after its hash was forgotten during the gate, want 1", n)
	}
	if n := pendingCount(tester.fetcher); n != 0 {
		t.Fatalf("reservations left after parking = %d, want 0", n)
	}
	if n := signingCount(tester.fetcher); n != 0 {
		t.Fatalf("in-flight markers left after parking = %d, want 0", n)
	}
}

// TestForgetBlockKeepsSignerGateBooking pins the same on the queue side: a
// complete timer can forget a queued hash while the gate runs, and the block must
// still be parked.
func TestForgetBlockKeepsSignerGateBooking(t *testing.T) {
	// forgetBlock runs on the loop goroutine in production, so drive it on a
	// fetcher whose loop never started, for the same reason as the hash test.
	tester := newIdleTester()
	defer tester.fetcher.Stop()
	tester.fetcher.signHook = func(*types.Block) error { return nil }

	block := newParkedTestBlock(0x43)
	var booked int
	tester.fetcher.SetSignerGate(func() bool {
		tester.fetcher.queued[block.Hash()] = &blockInject{origin: "test", block: block}
		tester.fetcher.queues["test"] = 1
		tester.fetcher.forgetBlock(block.Hash())

		tester.fetcher.parkedMu.Lock()
		booked = len(tester.fetcher.pending)
		tester.fetcher.parkedMu.Unlock()
		return true
	})
	tester.fetcher.parkForSignatureStored(block, false)

	if booked != 1 {
		t.Fatalf("bookings while the gate ran = %d, want 1", booked)
	}
	if n := parkedCount(tester.fetcher); n != 1 {
		t.Fatalf("parked count = %d after its queued hash was forgotten during the gate, want 1", n)
	}
	if n := pendingCount(tester.fetcher); n != 0 {
		t.Fatalf("reservations left after parking = %d, want 0", n)
	}
	if n := signingCount(tester.fetcher); n != 0 {
		t.Fatalf("in-flight markers left after parking = %d, want 0", n)
	}
}

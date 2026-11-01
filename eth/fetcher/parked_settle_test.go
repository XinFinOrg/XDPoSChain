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

// TestSettleRefusedClaimReleasesBookingOnStopDuringGate pins the quit check in
// settleRefusedClaim: a stop that lands while the gate runs must release the
// claim marker and the reserved slot instead of parking the block.
func TestSettleRefusedClaimReleasesBookingOnStopDuringGate(t *testing.T) {
	tester := newTester()
	tester.fetcher.signHook = func(*types.Block) error { return nil }

	block := newParkedTestBlock(0x60)
	tester.fetcher.parkedMu.Lock()
	tester.fetcher.signing[block.Hash()] = struct{}{}
	tester.fetcher.parkedMu.Unlock()

	tester.fetcher.SetSignerGate(func() bool {
		tester.fetcher.Stop()
		return true
	})
	tester.fetcher.settleRefusedClaim(block, false)

	if n := parkedCount(tester.fetcher); n != 0 {
		t.Fatalf("parked %d entries for a claim stopped during the gate, want 0", n)
	}
	if n := pendingCount(tester.fetcher); n != 0 {
		t.Fatalf("reservations left after a stop during the gate = %d, want 0", n)
	}
	if n := signingCount(tester.fetcher); n != 0 {
		t.Fatalf("in-flight markers left after a stop during the gate = %d, want 0", n)
	}
}

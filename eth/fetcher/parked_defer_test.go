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

	"github.com/XinFinOrg/XDPoSChain/core/types"
)

// TestDeferParkedReleasesMarkerWhenEntryIsGone pins that a skip settled after
// the scan dropped its entry still releases the in-flight marker: the scan keeps
// the marker of a claimed entry it evicts at the deadline, and the owner settling
// a skipped signature is what takes it down.
func TestDeferParkedReleasesMarkerWhenEntryIsGone(t *testing.T) {
	tester := newTester()
	defer tester.fetcher.Stop()
	tester.fetcher.signHook = func(*types.Block) error { return nil }

	block := newParkedTestBlock(0x62)
	tester.fetcher.parkedMu.Lock()
	tester.fetcher.parked[block.Hash()] = &parkedBlock{block: block, deadline: time.Now().Add(-time.Second), claimed: true}
	tester.fetcher.signing[block.Hash()] = struct{}{}
	tester.fetcher.parkedMu.Unlock()

	// The scan drops the claimed entry at its deadline and keeps the marker for the owner.
	tester.fetcher.scanParkedSignatures()

	tester.fetcher.deferParked(block.Hash())

	if n := signingCount(tester.fetcher); n != 0 {
		t.Fatalf("in-flight markers left after a skip settled without its entry = %d, want 0", n)
	}
}

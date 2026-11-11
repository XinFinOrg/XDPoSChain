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
)

func TestDeliveryClaimRespectsSkipBackoff(t *testing.T) {
	tester := newTester()
	defer tester.fetcher.Stop()
	block := newParkedTestBlock(0x62)
	hash := block.Hash()
	tester.fetcher.parkedMu.Lock()
	tester.fetcher.parked[hash] = &parkedBlock{
		block:      block,
		deadline:   time.Now().Add(time.Minute),
		retryAfter: time.Now().Add(parkedSkipBackoff),
		stored:     true,
	}
	tester.fetcher.parkedMu.Unlock()
	if ok, took := tester.fetcher.claimParkedSignature(hash); ok || took {
		t.Fatalf("claim during backoff = (%v, %v), want (false, false)", ok, took)
	}
	tester.fetcher.parkedMu.Lock()
	parked := tester.fetcher.parked[hash]
	claimed := parked.claimed
	_, marked := tester.fetcher.signing[hash]
	parked.retryAfter = time.Now().Add(-time.Second)
	tester.fetcher.parkedMu.Unlock()
	if claimed || marked {
		t.Fatalf("a refused claim still took the entry: claimed=%v marked=%v", claimed, marked)
	}
	if ok, took := tester.fetcher.claimParkedSignature(hash); !ok || !took {
		t.Fatalf("claim after backoff = (%v, %v), want (true, true)", ok, took)
	}
}

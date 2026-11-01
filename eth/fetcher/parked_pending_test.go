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

func TestParkedSignaturePendingStoredFlag(t *testing.T) {
	for _, tt := range []struct {
		name       string
		stored     bool
		wantStored bool
	}{
		{"unimported admission", false, false},
		{"stored admission", true, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tester := newTester()
			defer tester.fetcher.Stop()
			tester.fetcher.signHook = func(*types.Block) error { return nil }

			block := newParkedTestBlock(0xc1)
			var (
				booked        bool
				value         bool
				storedPending int
			)
			tester.fetcher.SetSignerGate(func() bool {
				tester.fetcher.parkedMu.Lock()
				value, booked = tester.fetcher.pending[block.Hash()]
				storedPending = tester.fetcher.pendingStoredLocked()
				tester.fetcher.parkedMu.Unlock()
				return true
			})
			tester.fetcher.parkForSignatureStored(block, tt.stored)

			if !booked {
				t.Fatalf("no booking visible to the signer gate")
			}
			if value != tt.wantStored {
				t.Fatalf("booking stored flag = %v, want %v", value, tt.wantStored)
			}
			want := 0
			if tt.wantStored {
				want = 1
			}
			if storedPending != want {
				t.Fatalf("pendingStoredLocked() = %d, want %d", storedPending, want)
			}
		})
	}
}

func TestParkedSignatureRefusedClaimBooksStoredPending(t *testing.T) {
	tester := newTester()
	defer tester.fetcher.Stop()
	tester.fetcher.signHook = func(*types.Block) error { return nil }

	block := newParkedTestBlock(0xc2)
	tester.fetcher.parkedMu.Lock()
	tester.fetcher.signing[block.Hash()] = struct{}{}
	tester.fetcher.parkedMu.Unlock()

	var (
		booked        bool
		value         bool
		storedPending int
	)
	tester.fetcher.SetSignerGate(func() bool {
		tester.fetcher.parkedMu.Lock()
		value, booked = tester.fetcher.pending[block.Hash()]
		storedPending = tester.fetcher.pendingStoredLocked()
		tester.fetcher.parkedMu.Unlock()
		return true
	})
	tester.fetcher.settleRefusedClaim(block, false)

	if !booked {
		t.Fatalf("no booking visible to the signer gate")
	}
	if !value {
		t.Fatalf("refused claim booked as unimported, want stored")
	}
	if storedPending != 1 {
		t.Fatalf("pendingStoredLocked() = %d, want 1", storedPending)
	}
}

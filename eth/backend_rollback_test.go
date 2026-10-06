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

package eth

import (
	"math"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
)

// TestResolveRollbackTarget covers the arithmetic that turns a --set-head request
// into an absolute target block number.
func TestResolveRollbackTarget(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		request    int64
		headNumber uint64
		want       uint64
		wantErr    bool
	}{
		{name: "absolute block number", request: 1000, headNumber: 5000, want: 1000},
		{name: "absolute one", request: 1, headNumber: 5000, want: 1},
		{name: "absolute max int64", request: math.MaxInt64, headNumber: 5000, want: math.MaxInt64},
		{name: "offset of one block", request: -1, headNumber: 5000, want: 4999},
		{name: "offset smaller than head", request: -1000, headNumber: 5000, want: 4000},
		{name: "offset equal to head rewinds to genesis", request: -5000, headNumber: 5000, want: 0},
		{name: "largest representable offset", request: math.MinInt64 + 1, headNumber: 5000, wantErr: true},
		{name: "offset below genesis", request: -5001, headNumber: 5000, wantErr: true},
		{name: "offset on a height zero chain", request: -1, headNumber: 0, wantErr: true},
		{name: "zero is rejected", request: 0, headNumber: 5000, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := resolveRollbackTarget(tt.request, tt.headNumber)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("resolveRollbackTarget(%d, %d) = %d, want an error", tt.request, tt.headNumber, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveRollbackTarget(%d, %d) failed: %v", tt.request, tt.headNumber, err)
			}
			if got != tt.want {
				t.Fatalf("resolveRollbackTarget(%d, %d) = %d, want %d", tt.request, tt.headNumber, got, tt.want)
			}
		})
	}
}

// TestResolveRollbackTargetCountsFromTheRecordedHead pins the reason the request
// is resolved before the chain is opened: startup repair may lower the head on
// its own, and the offset must still count from the head the operator saw. With
// the recorded head at 5000 and a repair that already rewound the chain to 4998,
// "--set-head=-1000" has to mean 4000 (not 3998), and the target must stay below
// the repaired head so that SetHead actually rewinds instead of doing nothing.
func TestResolveRollbackTargetCountsFromTheRecordedHead(t *testing.T) {
	t.Parallel()

	const (
		recordedHead = uint64(5000)
		repairedHead = uint64(4998)
		request      = int64(-1000)
	)
	target, err := resolveRollbackTarget(request, recordedHead)
	if err != nil {
		t.Fatalf("resolveRollbackTarget(%d, %d) failed: %v", request, recordedHead, err)
	}
	if target != 4000 {
		t.Fatalf("target resolved to %d, want 4000", target)
	}
	if target > repairedHead {
		t.Fatalf("target %d is above the repaired head %d, SetHead would do nothing", target, repairedHead)
	}
}

// TestRollbackHeadNumber covers reading the head height off disk, including a
// datadir that carries no head block number yet.
func TestRollbackHeadNumber(t *testing.T) {
	t.Parallel()

	t.Run("recorded head", func(t *testing.T) {
		t.Parallel()

		db := rawdb.NewMemoryDatabase()
		head := common.Hash{0x01}
		rawdb.WriteHeaderNumber(db, head, 1799)
		rawdb.WriteHeadBlockHash(db, head)

		got, recorded := rollbackHeadNumber(db)
		if !recorded {
			t.Fatalf("rollbackHeadNumber reported no recorded head, want the written one")
		}
		if got != 1799 {
			t.Fatalf("rollbackHeadNumber = %d, want 1799", got)
		}
	})

	t.Run("no recorded head", func(t *testing.T) {
		t.Parallel()

		got, recorded := rollbackHeadNumber(rawdb.NewMemoryDatabase())
		if recorded {
			t.Fatalf("rollbackHeadNumber reported a recorded head on an empty datadir")
		}
		if got != 0 {
			t.Fatalf("rollbackHeadNumber = %d, want 0 on an empty datadir", got)
		}
	})
}

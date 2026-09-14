// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package core

import (
	"errors"
	"fmt"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/consensus"
)

// TestClassifyInsertErr pins the whole classification table. The insertion paths read flags
// from this one table, so a sentinel added for any of them has to be added here, and moving one
// between classes is a deliberate edit to this test rather than a silent drift.
func TestClassifyInsertErr(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want insertErrClass
	}{
		{
			name: "interrupted import",
			err:  ErrInsertionInterrupted,
			want: insertErrClass{retryable: true, local: true},
		},
		{
			name: "stopped chain",
			err:  ErrChainStopped,
			want: insertErrClass{retryable: true, local: true},
		},
		{
			// Local but not retryable: every condition it carries is read the same way on the
			// next attempt, so keeping the block parked would re-verify it on every
			// futureBlocksLoop tick.
			name: "local insert condition",
			err:  ErrLocalInsertCondition,
			want: insertErrClass{local: true},
		},
		{
			// The one local condition that heals: the clock catches up, and the block that
			// could not be queued is queued then.
			name: "block ahead of the local clock",
			err:  ErrLocalInsertAheadOfClock,
			want: insertErrClass{retryable: true, local: true},
		},
		{
			// Local but not retryable: a refused reorg is refused again on every retry, so the
			// parked block has to be evicted rather than re-verified.
			name: "refused reorg",
			err:  ErrLocalInsertRefused,
			want: insertErrClass{local: true},
		},
		{
			name: "known block",
			err:  ErrKnownBlock,
			want: insertErrClass{local: true},
		},
		{
			name: "pruned ancestor",
			err:  consensus.ErrPrunedAncestor,
			want: insertErrClass{local: true},
		},
		{
			// Retryable but not local: a block dated ahead of this node's clock is parked,
			// while a peer serving it is not at fault. See IsLocalInsertError.
			name: "future block",
			err:  consensus.ErrFutureBlock,
			want: insertErrClass{retryable: true},
		},
		{
			name: "unknown ancestor",
			err:  consensus.ErrUnknownAncestor,
			want: insertErrClass{badBlock: true},
		},
		{
			name: "unrecognised error",
			err:  errors.New("derived state root mismatch"),
			want: insertErrClass{badBlock: true},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyInsertErr(tt.err); got != tt.want {
				t.Errorf("classifyInsertErr(%v) = %+v, want %+v", tt.err, got, tt.want)
			}
		})
	}
}

// TestClassifyInsertErrUnwraps pins that the table keeps matching through the wrapping the
// insertion paths do: writeKnownBlock reports a refused reorg as "%w: %v", insertSideChain
// reports a block dated ahead of the local clock as "%w: %w", and the downloader wraps
// whatever InsertChain returned into errInvalidChain before anyone looks at it again.
func TestClassifyInsertErrUnwraps(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want insertErrClass
	}{
		{
			// What writeKnownBlock returns for a reorg this node refuses. Retrying cannot help,
			// so procFutureBlocks has to evict the block rather than re-run the refusal every
			// tick.
			name: "refused reorg",
			err:  fmt.Errorf("download: %w", fmt.Errorf("%w: %v", ErrLocalInsertRefused, errors.New("stop reorg, blockchain is under forking attack"))),
			want: insertErrClass{local: true},
		},
		{
			// What insertSideChain returns for a block dated ahead of the local clock, which
			// heals once the clock catches up.
			name: "clock skew",
			err:  fmt.Errorf("download: %w", fmt.Errorf("%w: %w", ErrLocalInsertAheadOfClock, consensus.ErrFutureBlock)),
			want: insertErrClass{retryable: true, local: true},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyInsertErr(tt.err); got != tt.want {
				t.Errorf("classifyInsertErr(%v) = %+v, want %+v", tt.err, got, tt.want)
			}
			if !IsLocalInsertError(tt.err) {
				t.Error("IsLocalInsertError must keep matching through wrapping")
			}
		})
	}
}

// TestIsLocalInsertErrorIsTheLocalFlag pins that the exported predicate is the table's local
// flag and not a second list that could disagree with it. The sentinels are taken from
// insertErrClasses, so one added to the table is covered without editing this test, and the two
// errors the table does not carry are the default answer's to keep non-local.
func TestIsLocalInsertErrorIsTheLocalFlag(t *testing.T) {
	sentinels := []error{consensus.ErrUnknownAncestor, errors.New("boom")}
	for _, entry := range insertErrClasses {
		sentinels = append(sentinels, entry.err)
	}
	for _, err := range sentinels {
		if got, want := IsLocalInsertError(err), classifyInsertErr(err).local; got != want {
			t.Errorf("IsLocalInsertError(%v) = %v, want the local flag %v", err, got, want)
		}
	}
}

// TestDescribeLocalInsertFailure pins the reason each local sentinel reports, and that a failure
// the blocks are to blame for stays with the caller. The file importers take their message from
// here, so a sentinel whose reason is missing would be reported as "invalid block <n>".
//
// The reason is deliberately not a claim about a retry: ErrLocalInsertCondition and
// ErrLocalInsertAheadOfClock differ in classifyInsertErr, and both only say that this very input
// cannot be imported now.
func TestDescribeLocalInsertFailure(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"refused reorg", ErrLocalInsertRefused, "cannot be imported"},
		{"local condition", ErrLocalInsertCondition, "cannot be imported"},
		{"ahead of the local clock", ErrLocalInsertAheadOfClock, "cannot be imported"},
		{"known block", ErrKnownBlock, "already imported"},
		{"pruned ancestor", consensus.ErrPrunedAncestor, "ancestor state is pruned"},
		{"interrupted import", ErrInsertionInterrupted, "interrupted during import"},
		{"stopped chain", ErrChainStopped, "interrupted during import"},
		// Not "interrupted during import": an inconsistent local chain is not a state a file or
		// a retry can get past.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reason, ok := DescribeLocalInsertFailure(tt.err)
			if !ok {
				t.Fatalf("DescribeLocalInsertFailure(%v) must report a local failure", tt.err)
			}
			if reason != tt.want {
				t.Errorf("DescribeLocalInsertFailure(%v) = %q, want %q", tt.err, reason, tt.want)
			}
		})
	}
	// A future block is retryable but not local, and an unknown ancestor is the peer's: the
	// caller words both itself.
	for _, err := range []error{
		consensus.ErrFutureBlock,
		consensus.ErrUnknownAncestor,
		errors.New("derived state root mismatch"),
		nil,
	} {
		if reason, ok := DescribeLocalInsertFailure(err); ok {
			t.Errorf("DescribeLocalInsertFailure(%v) = %q, want it left to the caller", err, reason)
		}
	}
}

// TestDescribeLocalInsertFailurePrefersTheNamedEntry pins the one case that tells the two
// questions of the table apart: the class comes from the first entry the error matches, the
// wording from the first matching entry that carries one. An error matching an unnamed local
// sentinel first and a named one after it is the only shape that can separate them, and a
// single scan answering both questions from its first hit would silently change the wording.
func TestDescribeLocalInsertFailurePrefersTheNamedEntry(t *testing.T) {
	// ErrInsertionInterrupted comes first in the table and carries no wording of its own;
	// ErrKnownBlock comes after it and is named.
	err := fmt.Errorf("%w: %w", ErrInsertionInterrupted, ErrKnownBlock)

	// The class stays the first matching entry's, so the block may stay parked.
	if got, want := classifyInsertErr(err), (insertErrClass{retryable: true, local: true}); got != want {
		t.Errorf("classifyInsertErr(%v) = %+v, want the class of the first matching entry %+v", err, got, want)
	}
	reason, ok := DescribeLocalInsertFailure(err)
	if !ok {
		t.Fatalf("DescribeLocalInsertFailure(%v) must report a local failure", err)
	}
	if want := "already imported"; reason != want {
		t.Errorf("DescribeLocalInsertFailure(%v) = %q, want the named entry's wording %q", err, reason, want)
	}
}

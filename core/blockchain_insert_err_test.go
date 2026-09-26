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

// TestClassifyInsertErr pins the whole classification table. The insertion paths used to
// carry an errors.Is list each; they now read flags from this one table, so a sentinel added
// for any of them has to be added here, and moving a sentinel between classes has to be a
// deliberate edit to this test rather than a silent drift between call sites.
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
			// Local but not retryable: every condition it carries - a segment with nothing
			// stored, a receipt write this node refused, a stored block with no total
			// difficulty record - is read the same way on the next attempt, so keeping the
			// block parked would re-verify it on every futureBlocksLoop tick and forever.
			name: "local insert condition",
			err:  ErrLocalInsertCondition,
			want: insertErrClass{local: true},
		},
		{
			// The one local condition that heals: the clock catches up, and the block that
			// could not be queued is queued then. It is why the retryable flag is not the
			// same column as the local one.
			name: "block ahead of the local clock",
			err:  ErrLocalInsertAheadOfClock,
			want: insertErrClass{retryable: true, local: true},
		},
		{
			// Local but not retryable: a refused reorg is refused again on every retry, so
			// the parked block has to be evicted rather than re-verified forever.
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
			// What reorg reports when it reads a record of the chain and does not find it.
			// The production path that raises it cannot be built in a unit test - reorg
			// only reads what is already on disk - so the table is what pins the class,
			// and it pins the two flags that matter: the peer that served the batch must
			// not be blamed for it, and a retry cannot repair it either.
			name: "old chain inconsistent",
			err:  errInvalidOldChain,
			want: insertErrClass{local: true},
		},
		{
			name: "new chain inconsistent",
			err:  errInvalidNewChain,
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
// insertion paths do: writeKnownBlock reports a refused reorg as "%w: %v"
// (ErrLocalInsertRefused, err), insertSideChain reports a block dated ahead of the local
// clock as "%w: %w" (ErrLocalInsertCondition, consensus.ErrFutureBlock), and the downloader
// wraps whatever InsertChain returned into errInvalidChain before anyone looks at it again.
func TestClassifyInsertErrUnwraps(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want insertErrClass
	}{
		{
			// What writeKnownBlock returns for a reorg this node refuses. Retrying cannot
			// help, so procFutureBlocks has to evict the block: keeping it parked would
			// re-run the refused reorg on every futureBlocksLoop tick.
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
// flag and not a second list that can disagree with it. It covers every sentinel and one
// unrecognised error, so a sentinel added to either side without the other fails here.
func TestIsLocalInsertErrorIsTheLocalFlag(t *testing.T) {
	for _, err := range []error{
		ErrInsertionInterrupted,
		ErrChainStopped,
		ErrLocalInsertCondition,
		ErrLocalInsertAheadOfClock,
		ErrLocalInsertRefused,
		ErrKnownBlock,
		consensus.ErrPrunedAncestor,
		errInvalidOldChain,
		errInvalidNewChain,
		consensus.ErrFutureBlock,
		consensus.ErrUnknownAncestor,
		errors.New("boom"),
	} {
		if got, want := IsLocalInsertError(err), classifyInsertErr(err).local; got != want {
			t.Errorf("IsLocalInsertError(%v) = %v, want the local flag %v", err, got, want)
		}
	}
}

// TestDescribeLocalInsertFailure pins the reason each local sentinel reports, and that a failure
// the blocks are to blame for stays with the caller. The file importers take their message from
// here, so a sentinel whose reason is missing would be reported as "invalid block <n>" - the
// reading the classification exists to avoid.
//
// The reason is deliberately not a claim about a retry: ErrLocalInsertCondition and
// ErrLocalInsertAheadOfClock differ in classifyInsertErr - a record this node is missing is
// missing again on the next tick, while a clock that cannot place a block yet catches up - and
// both only say that this very input cannot be imported now.
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
		// Not "interrupted during import": an inconsistent local chain is not a state the
		// file or a retry can get past, and the reason has to say so.
		{"old chain inconsistent", errInvalidOldChain, "the local chain is inconsistent"},
		{"new chain inconsistent", errInvalidNewChain, "the local chain is inconsistent"},
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

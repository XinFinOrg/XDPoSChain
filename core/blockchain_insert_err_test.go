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
			name: "local insert condition",
			err:  ErrLocalInsertCondition,
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
			err:  fmt.Errorf("download: %w", fmt.Errorf("%w: %w", ErrLocalInsertCondition, consensus.ErrFutureBlock)),
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
		ErrLocalInsertRefused,
		ErrKnownBlock,
		consensus.ErrPrunedAncestor,
		consensus.ErrFutureBlock,
		consensus.ErrUnknownAncestor,
		errors.New("boom"),
	} {
		if got, want := IsLocalInsertError(err), classifyInsertErr(err).local; got != want {
			t.Errorf("IsLocalInsertError(%v) = %v, want the local flag %v", err, got, want)
		}
	}
}

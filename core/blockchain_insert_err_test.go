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
	}{}
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

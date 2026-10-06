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

package downloader

import (
	"errors"
	"fmt"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/core"
)

// TestBackoffOnError pins the verdict the syncer asks for before it records a failed sync cycle
// against the peer that served it: the cycles this node ends itself, and the local conditions of the
// chain, must not be charged to the peer, while a failure the peer can be held to still is.
//
// The exhaustive walk over the sentinels the chain calls local is core's test's job, so this
// exercises one representative sentinel and one wrapped shape rather than copying that list here.
func TestBackoffOnError(t *testing.T) {
	tester := newTester()
	defer tester.terminate()

	// Cycles the downloader ends without blaming the peer: this node asked for the cancel, either
	// half of it, or another download was already running. Synchronise returns all of them without
	// blaming the peer, and nil is no failure at all.
	for _, err := range []error{nil, errBusy, errCanceled, errCancelStateFetch, errCancelContentProcessing} {
		if tester.downloader.BackoffOnError(err) {
			t.Errorf("BackoffOnError(%v) = true, want false: this node ended the cycle", err)
		}
	}
	// A local condition of the chain is not the peer's doing either, in the shape it reaches the
	// syncer: the downloader wraps the cause, and the wrap has to keep matching.
	local := []error{
		core.ErrInsertionInterrupted,
		fmt.Errorf("%w: %w", errLocalInsertFailure, core.ErrInsertionInterrupted),
	}
	for _, err := range local {
		if tester.downloader.BackoffOnError(err) {
			t.Errorf("BackoffOnError(%v) = true, want false: the failure is this node's", err)
		}
	}
	// A batch that cannot be linked to our chain is the peer's to answer for, as is anything the
	// classification does not recognise.
	remote := []error{
		consensus.ErrUnknownAncestor,
		fmt.Errorf("download: %w", consensus.ErrUnknownAncestor),
		errors.New("unclassified failure"),
	}
	for _, err := range remote {
		if !tester.downloader.BackoffOnError(err) {
			t.Errorf("BackoffOnError(%v) = false, want true: the failure is the peer's", err)
		}
	}
}

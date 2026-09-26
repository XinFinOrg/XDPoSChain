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

// TestIsLocalInsertError pins the classification the downloader relies on to keep its peer:
// only failures that say nothing about the blocks are local, everything else must stay a
// consensus failure so that the peer serving an invalid batch is still dropped.
func TestIsLocalInsertError(t *testing.T) {
	tests := []struct {
		err  error
		want bool
	}{
		{ErrInsertionInterrupted, true},
		{ErrChainStopped, true},
		{fmt.Errorf("insertion aborted: %w", ErrChainStopped), true},
		{ErrLocalInsertCondition, true},
		{fmt.Errorf("a block ahead of our clock: %w", ErrLocalInsertCondition), true},
		// The reorg refusal writeKnownBlock reports. Local like the condition above, but
		// unlike it not retryable, which the downloader does not have to care about.
		{ErrLocalInsertRefused, true},
		{fmt.Errorf("adopting a known block: %w", ErrLocalInsertRefused), true},
		{fmt.Errorf("%w: stop reorg, blockchain is under forking attack", ErrLocalInsertRefused), true},
		// A batch that stops on a block this node already stores with its state is local
		// too: the peer served the range it was asked for.
		{ErrKnownBlock, true},
		// An import that needs an ancestor whose state this node no longer holds
		// describes what this node has on disk, not the blocks it was served.
		{consensus.ErrPrunedAncestor, true},
		{fmt.Errorf("sidechain import: %w", consensus.ErrPrunedAncestor), true},
		{nil, false},
		{errors.New("blockchain is stopped"), false},
		// A batch that cannot be linked to our chain is something the peer can be held
		// accountable for, so this one deliberately stays a consensus failure.
		{consensus.ErrUnknownAncestor, false},
		{errors.New("transaction root hash mismatch"), false},
	}
	for _, tt := range tests {
		if have := IsLocalInsertError(tt.err); have != tt.want {
			t.Errorf("IsLocalInsertError(%v): have %v want %v", tt.err, have, tt.want)
		}
	}
}

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

package rawdb

import (
	"bytes"
	"testing"
)

func TestXdposV2HighestVotedRound(t *testing.T) {
	db := NewMemoryDatabase()
	if got := ReadXdposV2HighestVotedRound(db); got != 0 {
		t.Fatalf("empty database: have %d, want 0", got)
	}
	for _, round := range []uint64{6, 7, 1 << 40} {
		if err := WriteXdposV2HighestVotedRound(db, round); err != nil {
			t.Fatalf("write %d: %v", round, err)
		}
		if got := ReadXdposV2HighestVotedRound(db); got != round {
			t.Fatalf("have %d, want %d", got, round)
		}
	}
	// A malformed value reads as never voted rather than as a garbage round.
	if err := db.Put(xdposV2HighestVotedRoundKey, []byte{1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	if got := ReadXdposV2HighestVotedRound(db); got != 0 {
		t.Fatalf("malformed value: have %d, want 0", got)
	}
	// The key must stay outside the snapshot prefixes.
	if bytes.HasPrefix(xdposV2HighestVotedRoundKey, xdposV1Prefix) || bytes.HasPrefix(xdposV2HighestVotedRoundKey, xdposV2Prefix) {
		t.Fatalf("key %q shares a snapshot prefix", xdposV2HighestVotedRoundKey)
	}
}

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
	"errors"
	"strings"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/ethdb"
	"github.com/XinFinOrg/XDPoSChain/log"
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

// TestReadXdposV2HighestVotedRoundLogsBadRead checks that a voted round that
// exists but cannot be read, or is malformed, is reported instead of silently
// read as never voted, while a missing round stays silent.
func TestReadXdposV2HighestVotedRoundLogsBadRead(t *testing.T) {
	var logBuf bytes.Buffer
	prevLog := log.Root()
	log.SetDefault(log.NewLogger(log.NewTerminalHandlerWithLevel(&logBuf, log.LevelWarn, false)))
	defer log.SetDefault(prevLog)

	malformed := NewMemoryDatabase()
	if err := malformed.Put(xdposV2HighestVotedRoundKey, []byte{1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name   string
		db     ethdb.KeyValueReader
		report bool
	}{
		{"missing", NewMemoryDatabase(), false},
		{"missing, get fails", &errorReader{getErr: errors.New("not found")}, false},
		{"malformed", malformed, true},
		{"has fails", &errorReader{hasErr: errors.New("io error")}, true},
		{"get fails", &errorReader{hasResult: true, getErr: errors.New("io error")}, true},
	} {
		logBuf.Reset()
		if got := ReadXdposV2HighestVotedRound(c.db); got != 0 {
			t.Errorf("%s: have round %d, want 0", c.name, got)
		}
		reported := strings.Contains(logBuf.String(), "highest voted round")
		if reported != c.report {
			t.Errorf("%s: reported %v, want %v; log: %q", c.name, reported, c.report, logBuf.String())
		}
	}
}

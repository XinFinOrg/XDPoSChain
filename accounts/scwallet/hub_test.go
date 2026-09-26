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

package scwallet

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/accounts"
	"github.com/XinFinOrg/XDPoSChain/common"
)

// testPairings builds n distinguishable pairings.
func testPairings(n int) map[string]smartcardPairing {
	pairings := make(map[string]smartcardPairing, n)
	for i := 0; i < n; i++ {
		pubkey := make([]byte, 33)
		pubkey[0] = 0x02
		pubkey[32] = byte(i + 1)

		addr := common.BytesToAddress(bytes.Repeat([]byte{byte(i + 1)}, common.AddressLength))
		pairings[string(pubkey)] = smartcardPairing{
			PublicKey:    pubkey,
			PairingIndex: uint8(i),
			PairingKey:   bytes.Repeat([]byte{byte(i + 1)}, 32),
			Accounts: map[common.Address]accounts.DerivationPath{
				addr: {44, 60, 0, 0, uint32(i)},
			},
		}
	}
	return pairings
}

// TestWritePairingsTruncates checks that rewriting the pairing file after entries
// were removed does not leave stale bytes behind. Without O_TRUNC the tail of the
// previous, longer content survives, the file stops being valid JSON and
// readPairings fails, which loses every pairing and forces the user to pair the
// card again.
func TestWritePairingsTruncates(t *testing.T) {
	hub := &Hub{datadir: t.TempDir()}
	path := filepath.Join(hub.datadir, "smartcards.json")

	// Write a longer file first, so a shorter rewrite has something to leave behind.
	hub.pairings = testPairings(4)
	if err := hub.writePairings(); err != nil {
		t.Fatalf("first write failed: %v", err)
	}
	long, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read the pairing file: %v", err)
	}
	hub.pairings = testPairings(1)
	if err := hub.writePairings(); err != nil {
		t.Fatalf("second write failed: %v", err)
	}
	short, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read the pairing file: %v", err)
	}
	var pairings []smartcardPairing
	if err := json.Unmarshal(short, &pairings); err != nil {
		t.Fatalf("pairing file is not valid JSON after the rewrite: %v", err)
	}
	if len(pairings) != 1 {
		t.Fatalf("pairing count mismatch: have %d, want 1", len(pairings))
	}
	// Sanity check: the rewrite really was shorter, otherwise this test could not
	// detect a missing truncation in the first place.
	if len(short) >= len(long) {
		t.Fatalf("test setup is broken: the rewritten file did not shrink, have %d bytes, previous %d", len(short), len(long))
	}
	// readPairings must accept what writePairings produced.
	reloaded := &Hub{datadir: hub.datadir}
	if err := reloaded.readPairings(); err != nil {
		t.Fatalf("failed to read the pairings back: %v", err)
	}
	if len(reloaded.pairings) != 1 {
		t.Fatalf("reloaded pairing count mismatch: have %d, want 1", len(reloaded.pairings))
	}
}

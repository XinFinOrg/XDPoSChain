// Copyright 2025 The XDC Authors
// This file is part of the XDC library.
//
// The XDC library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The XDC library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the XDC library. If not, see <http://www.gnu.org/licenses/>.

package downloader

import (
	"math/big"
	"testing"
)

// Tests that a missing local TD for the chain head neither crashes the
// stalling-peer checks nor blocks synchronisation. GetTd returns nil when the
// TD is absent from the database (legacy XDPoS chaindata predating the TD
// index). The checks fall back to a height comparison, so a peer whose head
// height is not ahead of ours simply completes the cycle without progress.
func TestMissingLocalTd100Full(t *testing.T)  { testMissingLocalTd(t, xdc100, FullSync) }
func TestMissingLocalTd100Fast(t *testing.T)  { testMissingLocalTd(t, xdc100, FastSync) }
func TestMissingLocalTd164Full(t *testing.T)  { testMissingLocalTd(t, xdc164, FullSync) }
func TestMissingLocalTd164Fast(t *testing.T)  { testMissingLocalTd(t, xdc164, FastSync) }
func TestMissingLocalTd164Light(t *testing.T) { testMissingLocalTd(t, xdc164, LightSync) }
func TestMissingLocalTd165Full(t *testing.T)  { testMissingLocalTd(t, xdc165, FullSync) }
func TestMissingLocalTd165Fast(t *testing.T)  { testMissingLocalTd(t, xdc165, FastSync) }
func TestMissingLocalTd165Light(t *testing.T) { testMissingLocalTd(t, xdc165, LightSync) }

func testMissingLocalTd(t *testing.T, protocol int, mode SyncMode) {
	t.Parallel()

	tester := newTester()
	defer tester.terminate()

	// Drop the TD of the genesis head, simulating chaindata without a TD entry
	// for the header the stalling-peer checks resolve to. The peer chain must
	// stay genesis-only: the harness derives TDs from the parent header on
	// insertion, so any delivered header would make InsertHeaderChain panic on
	// the missing parent TD.
	delete(tester.ownChainTd, tester.genesis.Hash())

	chain := testChainBase.shorten(1)
	tester.newPeer("peer", protocol, chain)
	// The promised TD is set far above the local head, but the promised height
	// (genesis) is not ahead of ours, so the height fallback must not flag the
	// peer as stalling. Sync twice: the second cycle repeats the missing-TD
	// path and must not change the outcome.
	for i := 0; i < 2; i++ {
		if err := tester.sync("peer", big.NewInt(1000000), mode); err != nil {
			t.Fatalf("Synchronisation error mismatch (cycle %d): have %v, want nil", i, err)
		}
	}
}

// Tests that the deliveredTd fallback of the fast/light-sync stalling check is
// exercised: the local genesis TD is missing, so every header the peer delivers
// is stored without a TD entry and the terminator check must fall back to the
// promised height. A healthy peer delivering its full chain must not be flagged
// as stalling, and the local head must still carry no TD entry afterwards.
func TestMissingDeliveredTd100Fast(t *testing.T)  { testMissingDeliveredTd(t, xdc100, FastSync) }
func TestMissingDeliveredTd164Fast(t *testing.T)  { testMissingDeliveredTd(t, xdc164, FastSync) }
func TestMissingDeliveredTd164Light(t *testing.T) { testMissingDeliveredTd(t, xdc164, LightSync) }
func TestMissingDeliveredTd165Fast(t *testing.T)  { testMissingDeliveredTd(t, xdc165, FastSync) }
func TestMissingDeliveredTd165Light(t *testing.T) { testMissingDeliveredTd(t, xdc165, LightSync) }

func testMissingDeliveredTd(t *testing.T, protocol int, mode SyncMode) {
	t.Parallel()

	tester := newTester()
	defer tester.terminate()

	// Drop the TD of the genesis head. The harness mirrors production and
	// stores delivered headers without a TD entry when the parent TD is
	// missing, so the deliveredTd == nil branch of the stalling check runs
	// for every header the peer delivers.
	delete(tester.ownChainTd, tester.genesis.Hash())

	chain := testChainBase.shorten(100)
	tester.newPeer("peer", protocol, chain)
	if err := tester.sync("peer", nil, mode); err != nil {
		t.Fatalf("Synchronisation error mismatch: have %v, want nil", err)
	}
	// The peer delivered its full chain, so the local head must be at the
	// promised height and still carry no TD entry.
	head := chain.headBlock()
	if current := tester.CurrentHeader(); current.Hash() != head.Hash() {
		t.Fatalf("Head hash mismatch: have %x, want %x", current.Hash(), head.Hash())
	}
	if td := tester.GetTd(head.Hash(), head.NumberU64()); td != nil {
		t.Fatalf("Head TD mismatch: have %v, want nil", td)
	}
}

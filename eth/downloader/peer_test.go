// Copyright 2020 The go-ethereum Authors
// This file is part of go-ethereum.
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with go-ethereum. If not, see <http://www.gnu.org/licenses/>.

package downloader

import (
	"fmt"
	"sort"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/log"
)

// TestIdlePeersProtocolVersions verifies that peers running every supported
// protocol version (xdc100, xdc164, xdc165, xdc166) are eligible for concurrent
// downloads. A regression here silently disables skeleton filling and body,
// receipt and state fetches, stalling any node that falls behind.
func TestIdlePeersProtocolVersions(t *testing.T) {
	ps := newPeerSet()
	for i, version := range []uint{xdc100, xdc164, xdc165, xdc166} {
		id := fmt.Sprintf("peer-%d", i)
		if err := ps.Register(newPeerConnection(id, version, nil, log.New("id", id))); err != nil {
			t.Fatalf("failed to register version %d peer: %v", version, err)
		}
	}
	tests := []struct {
		name  string
		peers func() ([]*peerConnection, int)
		total int
	}{
		{"HeaderIdlePeers", ps.HeaderIdlePeers, 4},
		{"BodyIdlePeers", ps.BodyIdlePeers, 4},
		{"ReceiptIdlePeers", ps.ReceiptIdlePeers, 4},
		{"NodeDataIdlePeers", ps.NodeDataIdlePeers, 4},
	}
	for _, tt := range tests {
		idle, total := tt.peers()
		if len(idle) != tt.total || total != tt.total {
			t.Errorf("%s: got %d idle / %d total, want %d / %d", tt.name, len(idle), total, tt.total, tt.total)
		}
	}
}

func TestPeerThroughputSorting(t *testing.T) {
	a := &peerConnection{
		id:               "a",
		headerThroughput: 1.25,
	}
	b := &peerConnection{
		id:               "b",
		headerThroughput: 1.21,
	}
	c := &peerConnection{
		id:               "c",
		headerThroughput: 1.23,
	}

	peers := []*peerConnection{a, b, c}
	tps := []float64{a.headerThroughput,
		b.headerThroughput, c.headerThroughput}
	sortPeers := &peerThroughputSort{peers, tps}
	sort.Sort(sortPeers)
	if got, exp := sortPeers.p[0].id, "a"; got != exp {
		t.Errorf("sort fail, got %v exp %v", got, exp)
	}
	if got, exp := sortPeers.p[1].id, "c"; got != exp {
		t.Errorf("sort fail, got %v exp %v", got, exp)
	}
	if got, exp := sortPeers.p[2].id, "b"; got != exp {
		t.Errorf("sort fail, got %v exp %v", got, exp)
	}
}

// TestShortPeerID verifies the log helper keeps short ids, such as the ones the
// tests use, intact and trims a long peer id to the 16 characters the sync logs
// keep.
func TestShortPeerID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		id   string
		want string
	}{
		{"empty id", "", ""},
		{"short id", "peer", "peer"},
		{"fifteen characters", "0123456789abcde", "0123456789abcde"},
		{"sixteen characters", "0123456789abcdef", "0123456789abcdef"},
		{"sixty-four character node id", "e5a1f9b4c7d0a2e64c3b8f19d0a7e2c5b6f419d0a7e2c5b6f419d0a7e2c5b6f4", "e5a1f9b4c7d0a2e6"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := shortPeerID(tt.id); got != tt.want {
				t.Errorf("shortPeerID(%q) = %q, want %q", tt.id, got, tt.want)
			}
		})
	}
}

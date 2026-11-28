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
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
)

// oversizedNodeDataPeer wraps a regular tester peer and pads every NodeData
// response with junk blobs that were never requested, so the response carries
// more items than the request asked for.
type oversizedNodeDataPeer struct {
	Peer                     // Delegates every other request to the honest peer
	tester   *downloadTester // Used to look up the honest state data
	id       string          // Peer id under which responses are delivered
	requests atomic.Int32    // Number of NodeData requests served
	padded   atomic.Int32    // Number of junk blobs injected in total
}

func (p *oversizedNodeDataPeer) RequestNodeData(hashes []common.Hash) error {
	p.requests.Add(1)

	p.tester.lock.RLock()
	results := make([][]byte, 0, 2*len(hashes))
	for _, hash := range hashes {
		if data, err := p.tester.peerDb.Get(hash.Bytes()); err == nil {
			results = append(results, data)
		}
	}
	p.tester.lock.RUnlock()

	// Append as many junk blobs as hashes requested: the response now holds
	// up to twice the number of items asked for.
	for i := range hashes {
		results = append(results, []byte(fmt.Sprintf("xdc-16 junk node %d-%d", p.requests.Load(), i)))
		p.padded.Add(1)
	}
	go p.tester.downloader.DeliverNodeData(p.id, results)
	return nil
}

// TestOversizedNodeDataResponseDropsPeer is a regression test for XDC-16: a
// NodeData response that carries more items than requested must be rejected
// before any of it is hashed, and the peer that sent it must be dropped.
func TestOversizedNodeDataResponseDropsPeer100(t *testing.T) {
	testOversizedNodeDataResponseDropsPeer(t, xdc100)
}
func TestOversizedNodeDataResponseDropsPeer164(t *testing.T) {
	testOversizedNodeDataResponseDropsPeer(t, xdc164)
}
func TestOversizedNodeDataResponseDropsPeer165(t *testing.T) {
	testOversizedNodeDataResponseDropsPeer(t, xdc165)
}
func TestOversizedNodeDataResponseDropsPeer166(t *testing.T) {
	testOversizedNodeDataResponseDropsPeer(t, xdc166)
}

func testOversizedNodeDataResponseDropsPeer(t *testing.T, protocol uint) {
	t.Parallel()

	tester := newTester()
	defer tester.terminate()

	chain := testChainBase.shorten(blockCacheMaxItems - 15)
	if err := tester.newPeer("attacker", protocol, chain); err != nil {
		t.Fatalf("failed to register peer: %v", err)
	}
	conn := tester.downloader.peers.Peer("attacker")
	if conn == nil {
		t.Fatal("attacker peer not registered with the downloader")
	}
	attacker := &oversizedNodeDataPeer{Peer: conn.peer, tester: tester, id: "attacker"}
	conn.peer = attacker

	// The sync outcome itself is not asserted: once the fix is in place the
	// attacker is the master peer, so the sync is expected to abort.
	_ = tester.sync("attacker", nil, FastSync)

	if attacker.requests.Load() == 0 {
		t.Fatal("precondition failed: fast sync issued no NodeData requests")
	}
	tester.downloader.syncStatsLock.RLock()
	unexpected := tester.downloader.syncStatsState.unexpected
	tester.downloader.syncStatsLock.RUnlock()

	if unexpected != 0 {
		t.Errorf("over-sized response was processed: %d unrequested blobs hashed (of %d injected)", unexpected, attacker.padded.Load())
	}
	if tester.downloader.peers.Peer("attacker") != nil {
		t.Errorf("peer sending over-sized NodeData responses was not dropped (%d requests served)", attacker.requests.Load())
	}
}

// Copyright 2015 The go-ethereum Authors
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

package eth

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/XinFinOrg/XDPoSChain/eth/downloader"
	"github.com/XinFinOrg/XDPoSChain/p2p"
	"github.com/XinFinOrg/XDPoSChain/p2p/discover"
)

// Tests that fast sync gets disabled as soon as a real block is successfully
// imported into the blockchain.
func TestFastSyncDisabling(t *testing.T) {
	// Create a pristine protocol manager, check that fast sync is left enabled
	pmEmpty, _ := newTestProtocolManagerMust(t, downloader.FastSync, 0, nil, nil)
	defer pmEmpty.Stop()
	if atomic.LoadUint32(&pmEmpty.snapSync) == 0 {
		t.Fatalf("snap sync disabled on pristine blockchain")
	}
	// Create a full protocol manager, check that snap sync gets disabled
	pmFull, _ := newTestProtocolManagerMust(t, downloader.FastSync, 1024, nil, nil)
	defer pmFull.Stop()
	if atomic.LoadUint32(&pmFull.snapSync) == 1 {
		t.Fatalf("snap sync not disabled on non-empty blockchain")
	}
	// Sync up the two peers
	io1, io2 := p2p.MsgPipe()

	go pmFull.handle(pmFull.newPeer(63, p2p.NewPeer(discover.NodeID{}, "empty", nil), io2))
	go pmEmpty.handle(pmEmpty.newPeer(63, p2p.NewPeer(discover.NodeID{}, "full", nil), io1))

	deadline := time.After(15 * time.Second)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		if atomic.LoadUint32(&pmEmpty.snapSync) == 0 {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("snap sync not disabled after successful synchronisation")
		case <-ticker.C:
			pmEmpty.synchronise(pmEmpty.peers.BestPeer())
		}
	}
}

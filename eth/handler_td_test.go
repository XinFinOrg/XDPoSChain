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

package eth

import (
	"crypto/rand"
	"math/big"
	"sync/atomic"
	"testing"
	"time"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/eth/downloader"
	"github.com/XinFinOrg/XDPoSChain/eth/ethconfig"
	"github.com/XinFinOrg/XDPoSChain/event"
	"github.com/XinFinOrg/XDPoSChain/p2p"
	"github.com/XinFinOrg/XDPoSChain/p2p/enode"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// TestBroadcastBlockMissingParentTd verifies that propagating a block whose
// parent TD is missing (legacy chaindata) no longer panics: the block is sent
// with a zero TD, which is the wire representation of an unknown value.
func TestBroadcastBlockMissingParentTd(t *testing.T) {
	var (
		evmux   = new(event.TypeMux)
		pow     = ethash.NewFaker()
		db      = rawdb.NewMemoryDatabase()
		config  = params.TestChainConfig.Clone()
		gspec   = &core.Genesis{Config: config}
		genesis = gspec.MustCommit(db)
	)
	blockchain, err := core.NewBlockChain(db, nil, gspec, pow, vm.Config{})
	if err != nil {
		t.Fatalf("failed to create new blockchain: %v", err)
	}
	chain, _ := core.GenerateChain(gspec.Config, genesis, ethash.NewFaker(), db, 1, nil)

	// Drop the genesis TD (the parent of chain[0]) and reopen the chain with a
	// fresh TD cache so the deletion becomes visible.
	blockchain.Stop()
	rawdb.DeleteTd(db, genesis.Hash(), genesis.NumberU64())

	blockchain, err = core.NewBlockChain(db, nil, gspec, pow, vm.Config{})
	if err != nil {
		t.Fatalf("failed to reopen blockchain: %v", err)
	}
	pm, err := NewProtocolManager(config, downloader.FullSync, ethconfig.Defaults.NetworkId, evmux, &testTxPool{pool: make(map[common.Hash]*types.Transaction)}, pow, blockchain, db)
	if err != nil {
		t.Fatalf("failed to start test protocol manager: %v", err)
	}
	pm.Start(1000)
	defer pm.Stop()

	// Register a pipe peer so the propagation path actually encodes and sends
	// the block with its TD on the wire.
	app, net := p2p.MsgPipe()
	defer app.Close()
	var id enode.ID
	rand.Read(id[:])
	peer := pm.newPeer(xdc164, p2p.NewPeer(id, "test", nil), net, pm.txpool.Get)
	// Mimic a completed handshake: the syncer goroutine reads Head() of every
	// registered peer on its periodic tick and panics on a nil TD.
	peer.td = new(big.Int)
	peer.head = chain[0].ParentHash()
	pm.peers.Register(peer)

	// Must not panic on the nil parent TD; the block is sent to the pipe peer
	// with a zero TD, which is the wire representation of an unknown value.
	// MsgPipe is synchronous and WriteMsg only returns once the receiver has
	// consumed the payload, so read and decode concurrently with the write.
	type result struct {
		code   uint64
		packet newBlockData
		err    error
	}
	resCh := make(chan result, 1)
	go func() {
		msg, err := app.ReadMsg()
		if err != nil {
			resCh <- result{err: err}
			return
		}
		var packet newBlockData
		if err := msg.Decode(&packet); err != nil {
			resCh <- result{err: err}
			return
		}
		resCh <- result{code: msg.Code, packet: packet}
	}()
	pm.BroadcastBlock(chain[0], true /*propagate*/)

	res := <-resCh
	if res.err != nil {
		t.Fatalf("failed to read broadcast: %v", res.err)
	}
	if res.code != NewBlockMsg {
		t.Fatalf("message code mismatch: have %d, want %d", res.code, NewBlockMsg)
	}
	if res.packet.Block == nil || res.packet.Block.Hash() != chain[0].Hash() {
		t.Fatalf("broadcast block mismatch: have %v, want %x", res.packet.Block, chain[0].Hash())
	}
	if res.packet.TD == nil || res.packet.TD.Sign() != 0 {
		t.Fatalf("broadcast TD mismatch: have %v, want 0", res.packet.TD)
	}
}

// TestNewBlockZeroTdTriggersSync verifies that a NewBlock announcement carrying
// the zero TD wire sentinel (a legacy peer without a TD index) schedules a
// sync probe on a healthy local node and advances the peer's advertised head
// by the announced block's height. The peer advertises block 10 at handshake
// time; the announcement of block 12 (whose parent is block 11) must move the
// tracked head to block 11 so the probe syncs through it. A subsequent stale
// announcement must not regress the head.
func TestNewBlockZeroTdTriggersSync(t *testing.T) {
	for _, protocol := range []int{xdc100, xdc164, xdc165} {
		t.Run(protocolTestName(protocol), func(t *testing.T) {
			var (
				evmux   = new(event.TypeMux)
				engine  = ethash.NewFaker()
				db      = rawdb.NewMemoryDatabase()
				gspec   = &core.Genesis{Config: params.TestChainConfig}
				genesis = gspec.MustCommit(db)
			)
			blockchain, err := core.NewBlockChain(db, nil, gspec, engine, vm.Config{})
			if err != nil {
				t.Fatalf("failed to create new blockchain: %v", err)
			}
			// Insert nine blocks: next (block 10) is the peer's advertised
			// head, target (block 11) is where the announcement must advance
			// it, and announced (block 12) has target as its parent.
			chain, _ := core.GenerateChain(gspec.Config, genesis, ethash.NewFaker(), db, 13, nil)
			if _, err := blockchain.InsertChain(chain[:9]); err != nil {
				t.Fatalf("failed to seed chain: %v", err)
			}
			next := chain[9]
			target := chain[10]
			announced := chain[11]

			pm, err := NewProtocolManager(gspec.Config, downloader.FullSync, ethconfig.Defaults.NetworkId, evmux, newTestTxPool(), engine, blockchain, db)
			if err != nil {
				t.Fatalf("failed to create protocol manager: %v", err)
			}
			pm.Start(1000)
			defer pm.Stop()

			peer, _ := newTestPeer("peer", protocol, pm, false)
			defer peer.app.Close()
			testHandshake(t, pm, peer, protocol)

			// The legacy peer advertises the unimported block 10 as its head
			// with the zero TD sentinel.
			peer.peer.SetHead(next.Hash(), new(big.Int))

			// Announce block 12 (parent block 11). The zero TD carries no
			// head claim, so the receiver must advance the advertised head by
			// height: from block 10 to block 11.
			if err := p2p.Send(peer.app, NewBlockMsg, &newBlockData{Block: announced, TD: new(big.Int)}); err != nil {
				t.Fatalf("failed to send new block announcement: %v", err)
			}
			testServeChain(pm, peer.app, chain, target, false)

			// The announced block's parent advances the tracked head.
			deadline := time.After(5 * time.Second)
			for {
				if hash, _ := peer.peer.Head(); hash == target.Hash() {
					break
				}
				select {
				case <-deadline:
					hash, _ := peer.peer.Head()
					t.Fatalf("zero-TD announcement did not advance the peer head: have %x, want %x", hash, target.Hash())
				default:
					time.Sleep(time.Millisecond)
				}
			}

			// The probe targets block 11 and must import through it: only a
			// sync cycle can import block 10, so a completed cycle proves the
			// announcement triggered the probe. The fetcher may additionally
			// import block 12 afterwards, so require at least block 11.
			probeDeadline := time.After(5 * time.Second)
			for atomic.LoadUint32(&pm.acceptTxs) != 1 {
				select {
				case <-probeDeadline:
					t.Fatalf("sync probe did not complete a sync cycle: acceptTxs=%d, want 1", atomic.LoadUint32(&pm.acceptTxs))
				default:
					time.Sleep(time.Millisecond)
				}
			}
			if got := pm.blockchain.CurrentBlock(); got.Number.Uint64() < target.NumberU64() {
				t.Fatalf("head number mismatch after announcement: have %d, want >= %d", got.Number.Uint64(), target.NumberU64())
			}

			// Regression: a stale announcement below the tracked height must
			// not regress the advertised head. Wait long enough for the
			// handler to process the message; the head would regress
			// immediately if the height guard were missing.
			stale := chain[4] // block 5, parent block 4
			if err := p2p.Send(peer.app, NewBlockMsg, &newBlockData{Block: stale, TD: new(big.Int)}); err != nil {
				t.Fatalf("failed to send stale announcement: %v", err)
			}
			time.Sleep(200 * time.Millisecond)
			if hash, _ := peer.peer.Head(); hash != target.Hash() {
				t.Fatalf("stale announcement regressed the peer head: have %x, want %x", hash, target.Hash())
			}
		})
	}
}

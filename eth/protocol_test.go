// Copyright 2014 The go-ethereum Authors
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
	"fmt"
	"math/big"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/eth/downloader"
	ethproto "github.com/XinFinOrg/XDPoSChain/eth/protocols/eth"
	"github.com/XinFinOrg/XDPoSChain/event"
	"github.com/XinFinOrg/XDPoSChain/internal/testshort"
	"github.com/XinFinOrg/XDPoSChain/p2p"
	"github.com/XinFinOrg/XDPoSChain/p2p/enode"
	"github.com/XinFinOrg/XDPoSChain/params"
)

func init() {
	// log.SetDefault(log.NewLogger(log.NewTerminalHandlerWithLevel(os.Stderr, log.LevelTrace, false)))
}

var testAccount, _ = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")

func TestForkIDSplit(t *testing.T) {
	var (
		engine = ethash.NewFaker()

		configNoFork = &params.ChainConfig{
			ChainID:        big.NewInt(1234),
			HomesteadBlock: big.NewInt(1),
			Ethash:         new(params.EthashConfig),
		}
		configProFork = &params.ChainConfig{
			ChainID:        big.NewInt(1234),
			HomesteadBlock: big.NewInt(1),
			EIP150Block:    big.NewInt(2),
			EIP155Block:    big.NewInt(2),
			EIP158Block:    big.NewInt(2),
			ByzantiumBlock: big.NewInt(3),
			Ethash:         new(params.EthashConfig),
		}
		dbNoFork  = rawdb.NewMemoryDatabase()
		dbProFork = rawdb.NewMemoryDatabase()

		gspecNoFork  = &core.Genesis{Config: configNoFork}
		gspecProFork = &core.Genesis{Config: configProFork}

		genesisNoFork  = gspecNoFork.MustCommit(dbNoFork)
		genesisProFork = gspecProFork.MustCommit(dbProFork)

		chainNoFork, _  = core.NewBlockChain(dbNoFork, nil, gspecNoFork, engine, vm.Config{})
		chainProFork, _ = core.NewBlockChain(dbProFork, nil, gspecProFork, engine, vm.Config{})

		blocksNoFork, _  = core.GenerateChain(configNoFork, genesisNoFork, engine, dbNoFork, 2, nil)
		blocksProFork, _ = core.GenerateChain(configProFork, genesisProFork, engine, dbProFork, 2, nil)

		ethNoFork, _ = newHandler(&handlerConfig{
			Database:    dbNoFork,
			Chain:       chainNoFork,
			TxPool:      &testTxPool{pool: make(map[common.Hash]*types.Transaction)},
			Network:     1,
			Sync:        downloader.FullSync,
			EventMux:    new(event.TypeMux),
			ChainConfig: configNoFork,
			Engine:      engine,
		})
		ethProFork, _ = newHandler(&handlerConfig{
			Database:    dbProFork,
			Chain:       chainProFork,
			TxPool:      &testTxPool{pool: make(map[common.Hash]*types.Transaction)},
			Network:     1,
			Sync:        downloader.FullSync,
			EventMux:    new(event.TypeMux),
			ChainConfig: configProFork,
			Engine:      engine,
		})
	)
	ethNoFork.Start(1000)
	ethProFork.Start(1000)
	defer ethNoFork.Stop()
	defer ethProFork.Stop()
	defer chainNoFork.Stop()
	defer chainProFork.Stop()

	// Both nodes should allow the other to connect (same genesis, next fork is the same)
	p2pNoFork, p2pProFork := p2p.MsgPipe()
	peerNoFork := newTestRawPeer(ethproto.XDC164, enode.ID{1}, p2pNoFork, nil)
	peerProFork := newTestRawPeer(ethproto.XDC164, enode.ID{2}, p2pProFork, nil)
	defer peerNoFork.Close()
	defer peerProFork.Close()

	errc := make(chan error, 2)
	go func() { errc <- ethNoFork.handle(peerProFork, testHandler(ethNoFork)) }()
	go func() { errc <- ethProFork.handle(peerNoFork, testHandler(ethProFork)) }()

	select {
	case err := <-errc:
		t.Fatalf("frontier nofork <-> profork failed: %v", err)
	case <-time.After(250 * time.Millisecond):
		p2pNoFork.Close()
		p2pProFork.Close()
	}
	// Wait for both handle goroutines to fully return so their removePeer defers
	// finish before the next phase reuses the same enode IDs. Otherwise a stale
	// removePeer could disconnect the peer registered under the same ID next.
	<-errc
	<-errc

	// Progress into Homestead. Fork's match, so we don't care what the future holds
	chainNoFork.InsertChain(blocksNoFork[:1])
	chainProFork.InsertChain(blocksProFork[:1])

	p2pNoFork, p2pProFork = p2p.MsgPipe()
	peerNoFork = newTestRawPeer(ethproto.XDC164, enode.ID{1}, p2pNoFork, nil)
	peerProFork = newTestRawPeer(ethproto.XDC164, enode.ID{1}, p2pProFork, nil)
	defer peerNoFork.Close()
	defer peerProFork.Close()

	errc = make(chan error, 2)
	go func() { errc <- ethNoFork.handle(peerProFork, testHandler(ethNoFork)) }()
	go func() { errc <- ethProFork.handle(peerNoFork, testHandler(ethProFork)) }()

	select {
	case err := <-errc:
		t.Fatalf("homestead nofork <-> profork failed: %v", err)
	case <-time.After(250 * time.Millisecond):
		p2pNoFork.Close()
		p2pProFork.Close()
	}
	// Wait for both handle goroutines to fully return so their removePeer defers
	// finish before the next phase reuses the same enode IDs.
	<-errc
	<-errc

	// Progress into Spurious. Forks mismatch, signalling differing chains, reject
	chainNoFork.InsertChain(blocksNoFork[1:2])
	chainProFork.InsertChain(blocksProFork[1:2])

	p2pNoFork, p2pProFork = p2p.MsgPipe()
	peerNoFork = newTestRawPeer(ethproto.XDC164, enode.ID{1}, p2pNoFork, nil)
	peerProFork = newTestRawPeer(ethproto.XDC164, enode.ID{1}, p2pProFork, nil)
	defer peerNoFork.Close()
	defer peerProFork.Close()

	errc = make(chan error, 2)
	go func() { errc <- ethNoFork.handle(peerProFork, testHandler(ethNoFork)) }()
	go func() { errc <- ethProFork.handle(peerNoFork, testHandler(ethProFork)) }()

	// On a fork split the fork filter is asymmetric: at least one side rejects
	// the peer during the handshake, but the other side may pass the handshake
	// and block in the message loop. A rejecting peer returns before its
	// removePeer defer is installed, so it neither tears down the pipe nor stops
	// the broadcasters NewPeer started; the deferred Close above covers them.
	// Wait for the first (rejecting) result, then close the pipes to unblock the
	// peer that may still be waiting, and drain the second result.
	var rejected bool
	timeout := time.NewTimer(2 * time.Second)
	defer timeout.Stop()

	for received := 0; received < 2; received++ {
		select {
		case err := <-errc:
			if err != nil {
				rejected = true
			}
			// Tear down the pipes so the peer still blocked in the message
			// loop unblocks and its handle goroutine returns.
			p2pNoFork.Close()
			p2pProFork.Close()
		case <-timeout.C:
			t.Fatalf("split peers not rejected")
		}
	}

	if !rejected {
		t.Fatalf("fork ID rejection didn't happen")
	}
}

// This test checks that received transactions are added to the local pool.
func TestRecvTransactions100(t *testing.T) { testRecvTransactions(t, int(ethproto.XDC100)) }
func TestRecvTransactions164(t *testing.T) { testRecvTransactions(t, int(ethproto.XDC164)) }
func TestRecvTransactions165(t *testing.T) { testRecvTransactions(t, int(ethproto.XDC165)) }

func testRecvTransactions(t *testing.T, protocol int) {
	txAdded := make(chan []*types.Transaction)
	pm, _ := newTestHandlerMust(t, downloader.FullSync, 0, nil, txAdded)
	pm.acceptTxs = 1 // mark synced to accept transactions
	p, _ := newTestPeer("peer", protocol, pm, true)
	defer pm.Stop()
	defer p.close()

	tx := newTestTransaction(testAccount, 0, 0)
	if err := p2p.Send(p.app, ethproto.TransactionMsg, []interface{}{tx}); err != nil {
		t.Fatalf("send error: %v", err)
	}
	select {
	case added := <-txAdded:
		if len(added) != 1 {
			t.Errorf("wrong number of added transactions: got %d, want 1", len(added))
		} else if added[0].Hash() != tx.Hash() {
			t.Errorf("added wrong tx hash: got %v, want %v", added[0].Hash(), tx.Hash())
		}
	case <-time.After(2 * time.Second):
		t.Errorf("no NewTxsEvent received within 2 seconds")
	}
}

// This test checks that pending transactions are sent.
func TestSendTransactions100(t *testing.T) { testSendTransactions(t, int(ethproto.XDC100)) }
func TestSendTransactions164(t *testing.T) { testSendTransactions(t, int(ethproto.XDC164)) }
func TestSendTransactions165(t *testing.T) { testSendTransactions(t, int(ethproto.XDC165)) }

func testSendTransactions(t *testing.T, protocol int) {
	pm, _ := newTestHandlerMust(t, downloader.FullSync, 0, nil, nil)
	defer pm.Stop()

	// Fill the pool with big transactions (use a subscription to wait until all
	// the transactions are announced to avoid spurious events causing extra
	// broadcasts).
	const txsize = ethproto.TxsyncPackSize / 10
	alltxs := make([]*types.Transaction, 100)
	for nonce := range alltxs {
		tx := newTestTransaction(testAccount, uint64(nonce), txsize)
		alltxs[nonce] = tx
	}
	pm.txpool.Add(alltxs, false)
	time.Sleep(100 * time.Millisecond) // Wait until new tx even gets out of the system (lame)

	// Connect several peers. They should all receive the pending transactions.
	var wg sync.WaitGroup
	checktxs := func(p *testPeer) {
		defer p.close()
		seen := make(map[common.Hash]bool)
		for _, tx := range alltxs {
			seen[tx.Hash()] = false
		}
		for n := 0; n < len(alltxs) && !t.Failed(); {
			var forAllHashes func(callback func(hash common.Hash))
			switch protocol {
			case ethproto.XDC100:
				fallthrough
			case ethproto.XDC164:
				msg, err := p.app.ReadMsg()
				if err != nil {
					t.Errorf("%v: read error: %v", p.Peer, err)
					continue
				} else if msg.Code != ethproto.TransactionMsg {
					t.Errorf("%v: got code %d, want TxMsg", p.Peer, msg.Code)
					continue
				}
				var txs []*types.Transaction
				if err := msg.Decode(&txs); err != nil {
					t.Errorf("%v: %v", p.Peer, err)
					continue
				}
				forAllHashes = func(callback func(hash common.Hash)) {
					for _, tx := range txs {
						callback(tx.Hash())
					}
				}
			case ethproto.XDC165:
				msg, err := p.app.ReadMsg()
				if err != nil {
					t.Errorf("%v: read error: %v", p.Peer, err)
					continue
				} else if msg.Code != ethproto.NewPooledTransactionHashesMsg {
					t.Errorf("%v: got code %d, want ethproto.NewPooledTransactionHashesMsg", p.Peer, msg.Code)
					continue
				}
				var hashes []common.Hash
				if err := msg.Decode(&hashes); err != nil {
					t.Errorf("%v: %v", p.Peer, err)
					continue
				}
				forAllHashes = func(callback func(hash common.Hash)) {
					for _, h := range hashes {
						callback(h)
					}
				}
			}
			forAllHashes(func(hash common.Hash) {
				seentx, want := seen[hash]
				if seentx {
					t.Errorf("%v: got tx more than once: %x", p.Peer, hash)
				}
				if !want {
					t.Errorf("%v: got unexpected tx: %x", p.Peer, hash)
				}
				seen[hash] = true
				n++
			})
		}
	}
	for i := 0; i < 3; i++ {
		wg.Go(func() {
			p, _ := newTestPeer(fmt.Sprintf("peer #%d", i), protocol, pm, true)
			checktxs(p)
		})
	}
	wg.Wait()
}

func TestTransactionPropagation(t *testing.T) { testSyncTransaction(t, true) }
func TestTransactionAnnouncement(t *testing.T) {
	testshort.Skip(t)
	testSyncTransaction(t, false)
}

func testSyncTransaction(t *testing.T, propagation bool) {
	// Create a handler for transaction fetcher and sender
	pmFetcher, _ := newTestHandlerMust(t, downloader.FastSync, 0, nil, nil)
	defer pmFetcher.Stop()
	pmSender, _ := newTestHandlerMust(t, downloader.FastSync, 1024, nil, nil)
	pmSender.broadcastTxAnnouncesOnly = !propagation
	defer pmSender.Stop()

	// Sync up the two peers
	io1, io2 := p2p.MsgPipe()

	go pmSender.handle(newTestRawPeer(ethproto.XDC165, enode.ID{}, io2, pmSender.txpool.Get), testHandler(pmSender))
	go pmFetcher.handle(newTestRawPeer(ethproto.XDC165, enode.ID{}, io1, pmFetcher.txpool.Get), testHandler(pmFetcher))

	time.Sleep(250 * time.Millisecond)
	pmFetcher.synchronise(pmFetcher.peers.BestPeer())
	atomic.StoreUint32(&pmFetcher.acceptTxs, 1)

	newTxs := make(chan core.NewTxsEvent, 1024)
	sub := pmFetcher.txpool.SubscribeTransactions(newTxs, false)
	defer sub.Unsubscribe()

	// Fill the pool with new transactions
	alltxs := make([]*types.Transaction, 1024)
	for nonce := range alltxs {
		alltxs[nonce] = newTestTransaction(testAccount, uint64(nonce), 0)
	}
	pmSender.txpool.Add(alltxs, false)

	var got int
	timeout := time.After(time.Second)
loop:
	for {
		select {
		case ev := <-newTxs:
			got += len(ev.Txs)
			if got == 1024 {
				break loop
			}
		case <-timeout:
			t.Fatal("Failed to retrieve all transaction")
		}
	}
}

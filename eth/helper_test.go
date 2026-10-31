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

// This file contains some shares testing functionality, common to  multiple
// different files and modules being tested.

package eth

import (
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"math/big"
	"sort"
	"sync"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/forkid"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/txpool"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/eth/downloader"
	"github.com/XinFinOrg/XDPoSChain/eth/ethconfig"
	ethproto "github.com/XinFinOrg/XDPoSChain/eth/protocols/eth"
	"github.com/XinFinOrg/XDPoSChain/ethdb"
	"github.com/XinFinOrg/XDPoSChain/event"
	"github.com/XinFinOrg/XDPoSChain/p2p"
	"github.com/XinFinOrg/XDPoSChain/p2p/enode"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/holiman/uint256"
)

var (
	testBankKey, _ = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	testBank       = crypto.PubkeyToAddress(testBankKey.PublicKey)
)

// newTestHandler creates a new handler for testing purposes,
// with the given number of blocks already known, and potential notification
// channels for different events.
func newTestHandler(mode downloader.SyncMode, blocks int, generator func(int, *core.BlockGen), newtx chan<- []*types.Transaction) (*handler, ethdb.Database, error) {
	var (
		evmux  = new(event.TypeMux)
		engine = ethash.NewFaker()
		db     = rawdb.NewMemoryDatabase()
		gspec  = &core.Genesis{
			Alloc:  types.GenesisAlloc{testBank: {Balance: new(big.Int).SetUint64(10000000000000000000)}},
			Config: params.TestChainConfig,
		}
		genesis       = gspec.MustCommit(db)
		blockchain, _ = core.NewBlockChain(db, nil, gspec, engine, vm.Config{})
	)
	chain, _ := core.GenerateChain(gspec.Config, genesis, ethash.NewFaker(), db, blocks, generator)
	if _, err := blockchain.InsertChain(chain); err != nil {
		panic(err)
	}

	txpool := newTestTxPool()
	txpool.added = newtx
	pm, err := newHandler(&handlerConfig{
		Database:    db,
		Chain:       blockchain,
		TxPool:      &testTxPool{added: newtx, pool: make(map[common.Hash]*types.Transaction)},
		Network:     ethconfig.Defaults.NetworkId,
		Sync:        mode,
		EventMux:    evmux,
		ChainConfig: gspec.Config,
		Engine:      engine,
	})
	if err != nil {
		return nil, nil, err
	}
	pm.Start(1000)
	return pm, db, nil
}

// newTestHandlerMust creates a new handler for testing purposes,
// with the given number of blocks already known, and potential notification
// channels for different events. In case of an error, the constructor force-
// fails the test.
func newTestHandlerMust(t *testing.T, mode downloader.SyncMode, blocks int, generator func(int, *core.BlockGen), newtx chan<- []*types.Transaction) (*handler, ethdb.Database) {
	pm, db, err := newTestHandler(mode, blocks, generator, newtx)
	if err != nil {
		t.Fatalf("Failed to create handler: %v", err)
	}
	return pm, db
}

// testTxPool is a fake, helper transaction pool for testing purposes
type testTxPool struct {
	txFeed event.Feed
	pool   map[common.Hash]*types.Transaction // Hash map of collected transactions
	added  chan<- []*types.Transaction        // Notification channel for new transactions

	lock sync.RWMutex // Protects the transaction pool
}

// Has returns an indicator whether txpool has a transaction
// cached with the given hash.
func (p *testTxPool) Has(hash common.Hash) bool {
	p.lock.Lock()
	defer p.lock.Unlock()

	return p.pool[hash] != nil
}

// Get retrieves the transaction from local txpool with given
// tx hash.
func (p *testTxPool) Get(hash common.Hash) *types.Transaction {
	p.lock.Lock()
	defer p.lock.Unlock()

	return p.pool[hash]
}

// newTestTxPool creates a mock transaction pool.
func newTestTxPool() *testTxPool {
	return &testTxPool{
		pool: make(map[common.Hash]*types.Transaction),
	}
}

// Add appends a batch of transactions to the pool, and notifies any
// listeners if the addition channel is non nil
func (p *testTxPool) Add(txs []*types.Transaction, sync bool) []error {
	p.lock.Lock()
	defer p.lock.Unlock()

	for _, tx := range txs {
		p.pool[tx.Hash()] = tx
	}
	if p.added != nil {
		p.added <- txs
	}
	p.txFeed.Send(core.NewTxsEvent{Txs: txs})
	return make([]error, len(txs))
}

// Pending returns all the transactions known to the pool
func (p *testTxPool) Pending(filter txpool.PendingFilter) map[common.Address][]*txpool.LazyTransaction {
	p.lock.RLock()
	defer p.lock.RUnlock()

	batches := make(map[common.Address][]*types.Transaction)
	for _, tx := range p.pool {
		from, _ := types.Sender(types.HomesteadSigner{}, tx)
		batches[from] = append(batches[from], tx)
	}
	for _, batch := range batches {
		sort.Sort(types.TxByNonce(batch))
	}
	pending := make(map[common.Address][]*txpool.LazyTransaction)
	for addr, batch := range batches {
		for _, tx := range batch {
			pending[addr] = append(pending[addr], &txpool.LazyTransaction{
				Hash:      tx.Hash(),
				Tx:        tx,
				Time:      tx.Time(),
				GasFeeCap: uint256.MustFromBig(tx.GasFeeCap()),
				GasTipCap: uint256.MustFromBig(tx.GasTipCap()),
			})
		}
	}
	return pending
}

// SubscribeTransactions should return an event subscription of NewTxsEvent and
// send events to the given channel.
func (p *testTxPool) SubscribeTransactions(ch chan<- core.NewTxsEvent, reorgs bool) event.Subscription {
	return p.txFeed.Subscribe(ch)
}

// SubscribeNewTxsEvent should return an event subscription of NewTxsEvent and
// send events to the given channel.
func (p *testTxPool) SubscribeNewTxsEvent(ch chan<- core.NewTxsEvent) event.Subscription {
	return p.SubscribeTransactions(ch, false)
}

// newTestTransaction create a new dummy transaction.
func newTestTransaction(from *ecdsa.PrivateKey, nonce uint64, datasize int) *types.Transaction {
	tx := types.NewTransaction(nonce, common.Address{}, big.NewInt(0), 100000, big.NewInt(0), make([]byte, datasize))
	tx, _ = types.SignTx(tx, types.HomesteadSigner{}, from)
	return tx
}

// testPeer is a simulated peer to allow testing direct network calls.
type testPeer struct {
	net p2p.MsgReadWriter // Network layer reader/writer to simulate remote messaging
	app *p2p.MsgPipeRW    // Application layer reader/writer to simulate the local side
	*peer
}

// newTestNodePeer creates a node-layer peer wrapping a wire peer over a fresh
// message pipe. Both the peer and its pipe are closed when the test ends; the
// tests that need a serving loop use newTestPeer instead.
func newTestNodePeer(t *testing.T, version int, name string, getPooledTx func(common.Hash) *types.Transaction) *peer {
	t.Helper()

	app, net := p2p.MsgPipe()
	// Cleanups run last-in-first-out, so the peer stops its broadcast
	// goroutines before the pipe they write to is closed.
	t.Cleanup(func() { app.Close() })

	var id enode.ID
	rand.Read(id[:])

	p := &peer{
		Peer: ethproto.NewPeer(uint(version), p2p.NewPeer(id, name, nil), net, getPooledTx),
	}
	t.Cleanup(p.Close)
	return p
}

// testHandler is the inbound message loop a handler hands to the wire
// layer for a peer.
func testHandler(pm *handler) ethproto.Handler {
	return func(p *ethproto.Peer) error { return ethproto.Handle(ethHandler{pm}, p) }
}

// newTestRawPeer creates a node-layer peer over an existing message pipe, without
// registering it at a handler.
func newTestRawPeer(version uint, id enode.ID, rw p2p.MsgReadWriter, getPooledTx func(common.Hash) *types.Transaction) *peer {
	return &peer{
		Peer: ethproto.NewPeer(version, p2p.NewPeer(id, "", nil), rw, getPooledTx),
	}
}

// newTestPeer creates a new peer registered at the given handler.
func newTestPeer(name string, version int, pm *handler, shake bool) (*testPeer, <-chan error) {
	// Create a message pipe to communicate through
	app, net := p2p.MsgPipe()

	// Generate a random id and create the peer
	var id enode.ID
	rand.Read(id[:])

	peer := &peer{
		Peer: ethproto.NewPeer(uint(version), p2p.NewPeer(id, name, nil), net, pm.txpool.Get),
	}

	// Start the peer on a new thread
	errc := make(chan error, 1)
	go func() {
		select {
		case pm.newPeerCh <- peer:
			errc <- pm.handle(peer, testHandler(pm))
		case <-pm.quitSync:
			errc <- p2p.DiscQuitting
		}
	}()
	tp := &testPeer{app: app, net: net, peer: peer}
	// Execute any implicitly requested handshakes and return
	if shake {
		var (
			genesis = pm.chain.Genesis()
			head    = pm.chain.CurrentHeader()
			td      = pm.chain.GetTd(head.Hash(), head.Number.Uint64())
		)
		tp.handshake(nil, td, head.Hash(), genesis.Hash(), forkid.NewID(pm.chain.Config(), genesis, head.Number.Uint64()), forkid.NewFilter(pm.chain))
	}
	return tp, errc
}

// handshake simulates a trivial handshake that expects the same state from the
// remote side as we are simulating locally.
func (p *testPeer) handshake(t *testing.T, td *big.Int, head common.Hash, genesis common.Hash, forkID forkid.ID, forkFilter forkid.Filter) {
	var msg interface{}
	switch p.Version() {
	case ethproto.XDC165, ethproto.XDC164, ethproto.XDC166:
		msg = &ethproto.StatusPacket{
			ProtocolVersion: uint32(p.Version()),
			NetworkID:       ethconfig.Defaults.NetworkId,
			TD:              td,
			Head:            head,
			Genesis:         genesis,
			ForkID:          forkID,
		}
	case ethproto.XDC100:
		msg = &ethproto.StatusPacket100{
			ProtocolVersion: uint32(p.Version()),
			NetworkId:       ethconfig.Defaults.NetworkId,
			TD:              td,
			CurrentBlock:    head,
			GenesisBlock:    genesis,
		}
	default:
		panic(fmt.Sprintf("unsupported eth protocol version: %d", p.Version()))
	}
	if err := p2p.ExpectMsg(p.app, ethproto.StatusMsg, msg); err != nil {
		t.Fatalf("status recv: %v", err)
	}
	if err := p2p.Send(p.app, ethproto.StatusMsg, msg); err != nil {
		t.Fatalf("status send: %v", err)
	}
}

// close stops the peer's broadcast goroutines and terminates the local side of
// the message pipe, notifying the remote protocol manager of termination.
func (p *testPeer) close() {
	p.Close()
	p.app.Close()
}

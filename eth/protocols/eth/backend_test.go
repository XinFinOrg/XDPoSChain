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

// This file contains the shared test scaffolding of the wire layer: a fake
// backend to drive the package without a node, and a peer wired through an
// in-memory message pipe.

package eth

import (
	"crypto/ecdsa"
	"crypto/rand"
	"math/big"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/ethdb"
	"github.com/XinFinOrg/XDPoSChain/event"
	"github.com/XinFinOrg/XDPoSChain/p2p"
	"github.com/XinFinOrg/XDPoSChain/p2p/enode"
	"github.com/XinFinOrg/XDPoSChain/params"
)

var (
	testBankKey, _ = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	testBank       = crypto.PubkeyToAddress(testBankKey.PublicKey)
)

// testNetworkID is the network id both handshake sides in these tests agree on.
const testNetworkID = 50

// testBackend is a fake Backend: it serves data from a real in-memory chain and
// transaction pool, while the reactions to inbound packets are supplied by the
// test that needs them.
type testBackend struct {
	chain    *core.BlockChain
	db       ethdb.Database
	txpool   *testTxPool
	handler  func(peer *Peer, packet Packet, size uint32) error
	accepted atomic.Bool
}

// Chain implements Backend.
func (b *testBackend) Chain() *core.BlockChain { return b.chain }

// TxPool implements Backend.
func (b *testBackend) TxPool() TxPool { return b.txpool }

// AcceptTxs implements Backend.
func (b *testBackend) AcceptTxs() bool { return b.accepted.Load() }

// RunPeer implements Backend; there is no node bookkeeping to do, so the handler
// is just run.
func (b *testBackend) RunPeer(peer *Peer, handler Handler) error { return handler(peer) }

// Handle implements Backend.
func (b *testBackend) Handle(peer *Peer, packet Packet, size uint32) error {
	if b.handler != nil {
		return b.handler(peer, packet, size)
	}
	return nil
}

// NodeInfo implements Backend.
func (b *testBackend) NodeInfo() interface{} { return nil }

// PeerInfo implements Backend.
func (b *testBackend) PeerInfo(id enode.ID) interface{} { return nil }

// newTestBackend creates a fake backend with the given number of blocks already
// imported into its chain.
func newTestBackend(t *testing.T, blocks int, generator func(int, *core.BlockGen)) *testBackend {
	t.Helper()

	var (
		engine = ethash.NewFaker()
		db     = rawdb.NewMemoryDatabase()
		gspec  = &core.Genesis{
			Alloc:  types.GenesisAlloc{testBank: {Balance: new(big.Int).SetUint64(10000000000000000000)}},
			Config: params.TestChainConfig,
		}
		genesis       = gspec.MustCommit(db)
		blockchain, _ = core.NewBlockChain(db, nil, gspec, engine, vm.Config{})
	)
	chain, _ := core.GenerateChain(gspec.Config, genesis, engine, db, blocks, generator)
	if _, err := blockchain.InsertChain(chain); err != nil {
		t.Fatalf("failed to insert test chain: %v", err)
	}
	t.Cleanup(func() { blockchain.Stop() })

	return &testBackend{
		chain:  blockchain,
		db:     db,
		txpool: newTestTxPool(),
	}
}

// testTxPool is a fake, helper transaction pool for testing purposes.
type testTxPool struct {
	txFeed event.Feed
	pool   map[common.Hash]*types.Transaction // Hash map of collected transactions

	lock sync.RWMutex // Protects the transaction pool
}

// Has returns an indicator whether txpool has a transaction cached with the given hash.
func (p *testTxPool) Has(hash common.Hash) bool {
	p.lock.RLock()
	defer p.lock.RUnlock()

	return p.pool[hash] != nil
}

// Get retrieves the transaction from local txpool with given tx hash.
func (p *testTxPool) Get(hash common.Hash) *types.Transaction {
	p.lock.RLock()
	defer p.lock.RUnlock()

	return p.pool[hash]
}

// Add appends a batch of transactions to the pool, and notifies any listeners.
func (p *testTxPool) Add(txs []*types.Transaction, sync bool) []error {
	p.lock.Lock()
	defer p.lock.Unlock()

	for _, tx := range txs {
		p.pool[tx.Hash()] = tx
	}
	p.txFeed.Send(core.NewTxsEvent{Txs: txs})
	return make([]error, len(txs))
}

// newTestTxPool creates a mock transaction pool.
func newTestTxPool() *testTxPool {
	return &testTxPool{
		pool: make(map[common.Hash]*types.Transaction),
	}
}

// testPeer is a simulated remote peer, talking to a wire peer over an in-memory
// message pipe.
type testPeer struct {
	app  *p2p.MsgPipeRW // Remote side of the pipe, used by the test
	net  *p2p.MsgPipeRW // Local side of the pipe, handed to the wire peer
	Peer *Peer
	errc chan error
}

// newTestPeer creates a new wire peer connected to the given backend and starts
// serving it. The peer is closed when the test ends.
func newTestPeer(t *testing.T, name string, version uint, backend *testBackend) *testPeer {
	t.Helper()

	app, net := p2p.MsgPipe()

	var id enode.ID
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatalf("failed to generate random peer id: %v", err)
	}
	peer := NewPeer(version, p2p.NewPeer(id, name, nil), net, backend.txpool.Get)
	tp := &testPeer{app: app, net: net, Peer: peer, errc: make(chan error, 1)}

	go func() {
		tp.errc <- Handle(backend, peer)
	}()
	t.Cleanup(tp.close)
	return tp
}

// close stops the peer's broadcast goroutines and terminates the local side of
// the pipe, notifying the message loop.
func (p *testPeer) close() {
	p.Peer.Close()
	p.app.Close()
}

// newTestTransaction creates a new dummy transaction.
func newTestTransaction(from *ecdsa.PrivateKey, nonce uint64, datasize int) *types.Transaction {
	tx := types.NewTransaction(nonce, common.Address{}, big.NewInt(0), 100000, big.NewInt(0), make([]byte, datasize))
	tx, _ = types.SignTx(tx, types.HomesteadSigner{}, from)
	return tx
}

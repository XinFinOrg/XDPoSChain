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
	"fmt"
	"math/big"
	"math/rand"
	"sync"
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
	ethproto "github.com/XinFinOrg/XDPoSChain/eth/protocols/eth"
	"github.com/XinFinOrg/XDPoSChain/event"
	"github.com/XinFinOrg/XDPoSChain/p2p"
	"github.com/XinFinOrg/XDPoSChain/p2p/enode"
	"github.com/XinFinOrg/XDPoSChain/params"
)

func TestBroadcastBlock(t *testing.T) {
	var tests = []struct {
		totalPeers        int
		broadcastExpected int
	}{
		{1, 1},
		{2, 2},
		{3, 3},
		{4, 4},
		{5, 5},
		{9, 9},
		{12, 12},
		{16, 16},
		{26, 26},
		{100, 100},
	}
	for _, test := range tests {
		testBroadcastBlock(t, test.totalPeers, test.broadcastExpected)
	}
}

func testBroadcastBlock(t *testing.T, totalPeers, broadcastExpected int) {
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
	pm, err := newHandler(&handlerConfig{
		Database: db,
		Chain:    blockchain,
		TxPool:   &testTxPool{pool: make(map[common.Hash]*types.Transaction)},
		Network:  ethconfig.Defaults.NetworkId,
		Sync:     downloader.FullSync,
		EventMux: evmux,
		Config:   config,
		Engine:   pow,
	})
	if err != nil {
		t.Fatalf("failed to start test handler: %v", err)
	}
	pm.Start(1000)
	defer pm.Stop()
	var peers []*testPeer
	for i := range totalPeers {
		peer, _ := newTestPeer(fmt.Sprintf("peer %d", i), int(ethproto.XDC100), pm, true)
		defer peer.Close()
		peers = append(peers, peer)
	}
	// Peers are registered asynchronously once the handshake completes on the
	// handler side, wait for the peer set to catch up before broadcasting.
	for deadline := time.Now().Add(10 * time.Second); pm.peers.Len() < totalPeers; {
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for peer registration: have %d, want %d", pm.peers.Len(), totalPeers)
		}
		time.Sleep(10 * time.Millisecond)
	}
	chain, _ := core.GenerateChain(gspec.Config, genesis, ethash.NewFaker(), db, 1, func(i int, gen *core.BlockGen) {})
	expectedTD := new(big.Int).Add(chain[0].Difficulty(), pm.chain.GetTd(chain[0].ParentHash(), chain[0].NumberU64()-1))

	errCh := make(chan error, totalPeers)
	doneCh := make(chan struct{}, totalPeers)
	for _, peer := range peers {
		go func(p *testPeer) {
			deadline := time.After(2 * time.Second)
			for {
				select {
				case <-deadline:
					errCh <- fmt.Errorf("timeout waiting for ethproto.NewBlockMsg")
					return
				default:
				}

				msg, err := p.app.ReadMsg()
				if err != nil {
					errCh <- err
					return
				}
				if msg.Code != ethproto.NewBlockMsg {
					_ = msg.Discard()
					continue
				}

				var got ethproto.NewBlockPacket
				if err := msg.Decode(&got); err != nil {
					errCh <- err
					return
				}
				if got.Block == nil {
					errCh <- fmt.Errorf("unexpected nil block in ethproto.NewBlockMsg")
					return
				}
				if got.Block.Hash() != chain[0].Hash() {
					errCh <- fmt.Errorf("unexpected block hash: have %v, want %v", got.Block.Hash(), chain[0].Hash())
					return
				}
				if got.TD == nil || got.TD.Cmp(expectedTD) != 0 {
					errCh <- fmt.Errorf("unexpected td: have %v, want %v", got.TD, expectedTD)
					return
				}
				doneCh <- struct{}{}
				return
			}
		}(peer)
	}
	pm.BroadcastBlock(chain[0], true /*propagate*/)
	timeout := time.After(2 * time.Second)
	var receivedCount int
outer:
	for {
		select {
		case err = <-errCh:
			break outer
		case <-doneCh:
			receivedCount++
			if receivedCount == totalPeers {
				break outer
			}
		case <-timeout:
			break outer
		}
	}
	for _, peer := range peers {
		peer.app.Close()
	}
	if err != nil {
		t.Errorf("error matching block by peer: %v", err)
	}
	if receivedCount != broadcastExpected {
		t.Errorf("block broadcast to %d peers, expected %d", receivedCount, broadcastExpected)
	}
}

// Tests that a propagated malformed block (uncles or transactions don't match
// with the hashes in the header) gets discarded and not broadcast forward.
func TestBroadcastMalformedBlock164(t *testing.T) {
	testBroadcastMalformedBlock(t, int(ethproto.XDC164))
}
func TestBroadcastMalformedBlock165(t *testing.T) {
	testBroadcastMalformedBlock(t, int(ethproto.XDC165))
}

func testBroadcastMalformedBlock(t *testing.T, protocol int) {
	t.Parallel()

	// Create a live node to test propagation with
	var (
		engine  = ethash.NewFaker()
		db      = rawdb.NewMemoryDatabase()
		config  = params.TestChainConfig.Clone()
		gspec   = &core.Genesis{Config: config}
		genesis = gspec.MustCommit(db)
	)
	blockchain, err := core.NewBlockChain(db, nil, gspec, engine, vm.Config{})
	if err != nil {
		t.Fatalf("failed to create new blockchain: %v", err)
	}
	pm, err := newHandler(&handlerConfig{
		Database: db,
		Chain:    blockchain,
		TxPool:   new(testTxPool),
		Network:  ethconfig.Defaults.NetworkId,
		Sync:     downloader.FullSync,
		EventMux: new(event.TypeMux),
		Config:   config,
		Engine:   engine,
	})
	if err != nil {
		t.Fatalf("failed to start test handler: %v", err)
	}
	pm.Start(2)
	defer pm.Stop()

	// Create two peers, one to send the malformed block with and one to check
	// propagation
	source, _ := newTestPeer("source", protocol, pm, true)
	defer source.close()

	sink, _ := newTestPeer("sink", protocol, pm, true)
	defer sink.close()

	// Create various combinations of malformed blocks
	chain, _ := core.GenerateChain(gspec.Config, genesis, ethash.NewFaker(), db, 1, func(i int, gen *core.BlockGen) {})

	malformedUncles := chain[0].Header()
	malformedUncles.UncleHash[0]++
	malformedTransactions := chain[0].Header()
	malformedTransactions.TxHash[0]++
	malformedEverything := chain[0].Header()
	malformedEverything.UncleHash[0]++
	malformedEverything.TxHash[0]++

	// Keep listening and notify only if block propagation messages arrive.
	notify := make(chan uint64, 1)
	go func() {
		for {
			msg, err := sink.app.ReadMsg()
			if err != nil {
				return
			}
			if msg.Code == ethproto.NewBlockMsg || msg.Code == ethproto.NewBlockHashesMsg {
				select {
				case notify <- msg.Code:
				default:
				}
			}
		}
	}()
	// Try to broadcast all malformations and ensure they all get discarded
	for _, header := range []*types.Header{malformedUncles, malformedTransactions, malformedEverything} {
		block := types.NewBlockWithHeader(header).WithBody(types.Body{Transactions: chain[0].Transactions(), Uncles: chain[0].Uncles()})
		if err := p2p.Send(source.app, ethproto.NewBlockMsg, []any{block, big.NewInt(131136)}); err != nil {
			t.Fatalf("failed to broadcast block: %v", err)
		}
		select {
		case code := <-notify:
			t.Fatalf("malformed block forwarded, msg code=%#x", code)
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// Tests that a propagated block is still queued into the block fetcher by the
// node layer: the fetcher imports it, so the local chain advances onto it.
func TestPropagatedBlockQueuedIntoFetcher(t *testing.T) {
	pm, db := newTestHandlerMust(t, downloader.FullSync, 8, nil, nil)
	defer pm.Stop()

	tp, _ := newTestPeer("propagate", int(ethproto.XDC165), pm, true)
	defer tp.close()

	// Build a block on top of our head that we do not have ourselves yet.
	head := pm.chain.CurrentBlock()
	chain, _ := core.GenerateChain(pm.chain.Config(), pm.chain.GetBlockByHash(head.Hash()), ethash.NewFaker(), db, 1, nil)
	block := chain[0]

	if err := p2p.Send(tp.app, ethproto.NewBlockMsg, []any{block, big.NewInt(131136)}); err != nil {
		t.Fatalf("failed to send ethproto.NewBlockMsg: %v", err)
	}
	deadline := time.After(5 * time.Second)
	for pm.chain.CurrentBlock().Number.Cmp(head.Number) <= 0 {
		select {
		case <-deadline:
			t.Fatalf("propagated block was not queued into the fetcher, head still at %d", pm.chain.CurrentBlock().Number.Uint64())
		case <-time.After(10 * time.Millisecond):
		}
	}
	if got := pm.chain.CurrentBlock().Hash(); got != block.Hash() {
		t.Errorf("chain advanced to the wrong block: have %v, want %v", got, block.Hash())
	}
}

// Tests that post eth protocol handshake, DAO fork-enabled clients also execute
// a DAO "challenge" verifying each others' DAO fork headers to ensure they're on
// compatible chains.
func TestDAOChallengeNoVsNo(t *testing.T) { testDAOChallenge(t, false, false, false) }

// TestDAOChallengeNoVsPro tests dao challenge no vs pro.
func TestDAOChallengeNoVsPro(t *testing.T) { testDAOChallenge(t, false, true, false) }

// TestDAOChallengeProVsNo tests dao challenge pro vs no.
func TestDAOChallengeProVsNo(t *testing.T) { testDAOChallenge(t, true, false, false) }

// TestDAOChallengeProVsPro tests dao challenge pro vs pro.
func TestDAOChallengeProVsPro(t *testing.T) { testDAOChallenge(t, true, true, false) }

// TestDAOChallengeNoVsTimeout tests dao challenge no vs timeout.
func TestDAOChallengeNoVsTimeout(t *testing.T) { testDAOChallenge(t, false, false, true) }

// TestDAOChallengeProVsTimeout tests dao challenge pro vs timeout.
func TestDAOChallengeProVsTimeout(t *testing.T) { testDAOChallenge(t, true, true, true) }

func testDAOChallenge(t *testing.T, localForked, remoteForked bool, timeout bool) {
	// Reduce the DAO handshake challenge timeout
	if timeout {
		defer func(old time.Duration) { syncChallengeTimeout = old }(syncChallengeTimeout)
		syncChallengeTimeout = 500 * time.Millisecond
	}
	// Create a DAO aware handler
	var (
		evmux = new(event.TypeMux)
		pow   = ethash.NewFaker()
		db    = rawdb.NewMemoryDatabase()
		gspec = &core.Genesis{
			Config: daoChallengeChainConfig(localForked),
		}
		blockchain, _ = core.NewBlockChain(db, nil, gspec, pow, vm.Config{})
	)
	pm, err := newHandler(&handlerConfig{
		Database: db,
		Chain:    blockchain,
		TxPool:   &testTxPool{pool: make(map[common.Hash]*types.Transaction)},
		Network:  ethconfig.Defaults.NetworkId,
		Sync:     downloader.FullSync,
		EventMux: evmux,
		Config:   gspec.Config,
		Engine:   pow,
	})
	if err != nil {
		t.Fatalf("failed to start test handler: %v", err)
	}
	pm.Start(1000)
	defer pm.Stop()

	// Connect a new peer and check that we receive the DAO challenge
	peer, _ := newTestPeer("peer", int(ethproto.XDC100), pm, true)
	defer peer.Close()

	challenge := &ethproto.GetBlockHeadersPacket{
		Origin:  ethproto.HashOrNumber{Number: gspec.Config.DAOForkBlock.Uint64()},
		Amount:  1,
		Skip:    0,
		Reverse: false,
	}
	if err := p2p.ExpectMsg(peer.app, ethproto.GetBlockHeadersMsg, challenge); err != nil {
		t.Fatalf("challenge mismatch: %v", err)
	}
	// Create a block to reply to the challenge if no timeout is simulated
	if !timeout {
		_, blocks, _ := core.GenerateChainWithGenesis(gspec, ethash.NewFaker(), 1, func(i int, block *core.BlockGen) {
			if remoteForked {
				block.SetExtra(params.DAOForkBlockExtra)
			} else {
				// Override the auto-injected DAO extra-data from GenerateChain when
				// the local config supports the fork but the remote peer should not.
				block.SetExtra([]byte{})
			}
		})
		if err := p2p.Send(peer.app, ethproto.BlockHeadersMsg, []*types.Header{blocks[0].Header()}); err != nil {
			t.Fatalf("failed to answer challenge: %v", err)
		}
		time.Sleep(100 * time.Millisecond) // Sleep to avoid the verification racing with the drops
	} else {
		// Otherwise wait until the test timeout passes
		time.Sleep(syncChallengeTimeout + 500*time.Millisecond)
	}
	// Verify that depending on fork side, the remote peer is maintained or dropped
	if localForked == remoteForked && !timeout {
		if peers := pm.peers.Len(); peers != 1 {
			t.Fatalf("peer count mismatch: have %d, want %d", peers, 1)
		}
	} else {
		if peers := pm.peers.Len(); peers != 0 {
			t.Fatalf("peer count mismatch: have %d, want %d", peers, 0)
		}
	}
}

// daoChallengeChainConfig builds a chain config that activates the DAO fork
// challenge while pushing later forks into the future.
func daoChallengeChainConfig(daoForkSupport bool) *params.ChainConfig {
	config := params.TestChainConfig.Clone()
	futureForkBlock := big.NewInt(1_000_000_000)

	config.ChainID = big.NewInt(1337)
	config.DAOForkBlock = big.NewInt(1)
	config.DAOForkSupport = daoForkSupport
	config.EIP150Block = new(big.Int).Set(futureForkBlock)
	config.EIP155Block = new(big.Int).Set(futureForkBlock)
	config.EIP158Block = new(big.Int).Set(futureForkBlock)
	config.ByzantiumBlock = new(big.Int).Set(futureForkBlock)
	config.ConstantinopleBlock = new(big.Int).Set(futureForkBlock)
	config.PetersburgBlock = new(big.Int).Set(futureForkBlock)
	config.IstanbulBlock = new(big.Int).Set(futureForkBlock)
	config.TIPSigningBlock = new(big.Int).Set(futureForkBlock)
	config.TIPRandomizeBlock = new(big.Int).Set(futureForkBlock)
	config.TIPIncreaseMasternodesBlock = new(big.Int).Set(futureForkBlock)
	config.DenylistBlock = new(big.Int).Set(futureForkBlock)
	config.TIPNoHalvingMNRewardBlock = new(big.Int).Set(futureForkBlock)
	config.TIPXDCXBlock = new(big.Int).Set(futureForkBlock)
	config.TIPXDCXLendingBlock = new(big.Int).Set(futureForkBlock)
	config.TIPXDCXCancellationFeeBlock = new(big.Int).Set(futureForkBlock)
	config.TIPTRC21FeeBlock = new(big.Int).Set(futureForkBlock)
	config.Gas50xBlock = new(big.Int).Set(futureForkBlock)
	config.BerlinBlock = new(big.Int).Set(futureForkBlock)
	config.LondonBlock = new(big.Int).Set(futureForkBlock)
	config.MergeBlock = new(big.Int).Set(futureForkBlock)
	config.ShanghaiBlock = new(big.Int).Set(futureForkBlock)
	config.TIPXDCXMinerDisableBlock = new(big.Int).Set(futureForkBlock)
	config.TIPXDCXReceiverDisableBlock = new(big.Int).Set(futureForkBlock)
	config.EIP1559Block = new(big.Int).Set(futureForkBlock)
	config.CancunBlock = new(big.Int).Set(futureForkBlock)
	config.PragueBlock = new(big.Int).Set(futureForkBlock)
	config.OsakaBlock = new(big.Int).Set(futureForkBlock)
	config.AmsterdamBlock = new(big.Int).Set(futureForkBlock)
	config.DynamicGasLimitBlock = new(big.Int).Set(futureForkBlock)
	config.TIPUpgradeRewardBlock = new(big.Int).Set(futureForkBlock)
	config.TIPUpgradePenaltyBlock = new(big.Int).Set(futureForkBlock)
	config.TIPEpochHalvingBlock = new(big.Int).Set(futureForkBlock)

	return config
}

// waitForPeerRegistration blocks until the peer with the given id has been
// registered by the handler's handle goroutine.
func waitForPeerRegistration(t *testing.T, pm *handler, id string) {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for pm.peers.Peer(id) == nil {
		select {
		case <-deadline:
			t.Fatalf("test peer %s was not registered in time", id)
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// TestHandlerRemovePeerIdempotent verifies that removing an already
// removed peer is a silent no-op.
func TestHandlerRemovePeerIdempotent(t *testing.T) {
	pm, _ := newTestHandlerMust(t, downloader.FullSync, 0, nil, nil)
	defer pm.Stop()

	// Register a peer through the normal protocol handshake path.
	tp, errc := newTestPeer("test-peer", int(ethproto.XDC165), pm, true)
	// Ensure broadcaster goroutines stop if the test exits before removePeer
	// reaches peerSet.Unregister.
	defer tp.peer.Close()
	defer tp.close()
	defer tp.app.Close()
	defer func() {
		select {
		case <-errc:
		default:
		}
	}()
	waitForPeerRegistration(t, pm, tp.ID())

	if pm.peers.Len() != 1 {
		t.Fatalf("peer set size mismatch: got %d want 1", pm.peers.Len())
	}
	// The first removal performs the full unregister sequence.
	pm.removePeer(tp.ID())
	if pm.peers.Peer(tp.ID()) != nil {
		t.Fatal("peer still registered after first removePeer")
	}
	if pm.peers.Len() != 0 {
		t.Fatalf("peer set size mismatch after removal: got %d want 0", pm.peers.Len())
	}
	// A duplicate removal must be a silent no-op. Note it is short-circuited by
	// the peer == nil lookup above, so markRemoved's atomic branch is covered
	// by TestPeerMarkRemovedOnce and TestHandlerRemovePeerConcurrent.
	pm.removePeer(tp.ID())
	if pm.peers.Len() != 0 {
		t.Fatalf("peer set size mismatch after second removePeer: got %d want 0", pm.peers.Len())
	}
}

// TestHandlerRemovePeerConcurrent verifies that concurrent removePeer
// calls for the same peer remove it exactly once, without panicking or racing
// on the removal flag.
func TestHandlerRemovePeerConcurrent(t *testing.T) {
	pm, _ := newTestHandlerMust(t, downloader.FullSync, 0, nil, nil)
	defer pm.Stop()

	// Register a peer through the normal protocol handshake path.
	tp, errc := newTestPeer("test-peer", int(ethproto.XDC165), pm, true)
	// Stop the broadcast goroutines NewPeer started. This test drives pm.handle
	// directly instead of going through MakeProtocols.Run, so the production
	// defer peer.Close() never runs and the test has to close the peer itself.
	defer tp.peer.Close()
	defer tp.close()
	defer tp.app.Close()
	defer func() {
		select {
		case <-errc:
		default:
		}
	}()
	waitForPeerRegistration(t, pm, tp.ID())

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pm.removePeer(tp.ID())
		}()
	}
	wg.Wait()

	if pm.peers.Peer(tp.ID()) != nil {
		t.Fatal("peer still registered after concurrent removePeer calls")
	}
	if pm.peers.Len() != 0 {
		t.Fatalf("peer set size mismatch after concurrent removal: got %d want 0", pm.peers.Len())
	}
	// The downloader must not retain a stale entry that blocks re-registration.
	// Poll briefly in case handle() is still undoing its registration.
	deadline := time.After(2 * time.Second)
	for {
		if err := pm.downloader.RegisterPeer(tp.ID(), tp.Version(), tp); err == nil {
			break
		}
		select {
		case <-deadline:
			t.Fatal("stale downloader entry blocks re-registration")
		case <-time.After(10 * time.Millisecond):
		}
	}
	// Undo the test's own registration.
	pm.downloader.UnregisterPeer(tp.ID())
}

// TestRegisterDownloaderPeerUndoesRacedRemoval reproduces the window in handle()
// between pm.peers.Register and the downloader registration, where a BFT
// broadcaster can remove the peer. Without the recheck in
// registerDownloaderPeer, the downloader would keep a stale entry that blocks
// a reconnect of the same node id.
func TestRegisterDownloaderPeerUndoesRacedRemoval(t *testing.T) {
	pm, _ := newTestHandlerMust(t, downloader.FullSync, 0, nil, nil)
	defer pm.Stop()

	// Register the peer in pm.peers only — the state handle() is in mid-window.
	app, net := p2p.MsgPipe()
	defer app.Close()
	var id enode.ID
	rand.Read(id[:])
	p := &peer{
		Peer: ethproto.NewPeer(ethproto.XDC165, p2p.NewPeer(id, "race-peer", nil), net, pm.txpool.Get),
	}
	// NewPeer has already started the peer's broadcast goroutines; close the
	// term channel so they terminate when the test ends.
	defer p.Close()
	if err := pm.peers.Register(p); err != nil {
		t.Fatalf("failed to register test peer: %v", err)
	}
	if pm.peers.Len() != 1 {
		t.Fatalf("peer set size mismatch: got %d want 1", pm.peers.Len())
	}
	// A BFT broadcaster's failing send removes the peer inside the window.
	pm.removePeer(p.ID())
	if pm.peers.Peer(p.ID()) != nil {
		t.Fatal("peer still present after removePeer")
	}
	// The recheck must undo the registration and abort the handshake.
	if err := pm.registerDownloaderPeer(p); err != p2p.DiscUselessPeer {
		t.Fatalf("registerDownloaderPeer should abort with DiscUselessPeer a handshake whose removal was already claimed, got: %v", err)
	}
	// A reconnect of the same node id must not be blocked by a stale entry.
	if err := pm.downloader.RegisterPeer(p.ID(), p.Version(), p); err != nil {
		t.Fatalf("reconnect blocked by stale downloader entry: %v", err)
	}
	pm.downloader.UnregisterPeer(p.ID())
}

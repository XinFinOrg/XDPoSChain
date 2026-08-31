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
	"github.com/XinFinOrg/XDPoSChain/rlp"
)

// TestSynchroniseMissingLocalTd verifies that a node whose head has no TD entry
// (legacy chaindata) neither panics in the sync threshold comparison nor runs
// pointless sync probes. A peer whose known head is not strictly above the
// local head is skipped via the height fallback, and a peer advertising one
// block ahead completes a full sync cycle that sets acceptTxs.
func TestSynchroniseMissingLocalTd(t *testing.T) {
	for _, protocol := range []int{xdc100, xdc164, xdc165} {
		t.Run(func() string {
			switch protocol {
			case xdc100:
				return "protocol100"
			case xdc164:
				return "protocol164"
			default:
				return "protocol165"
			}
		}(), func(t *testing.T) {
			var (
				evmux  = new(event.TypeMux)
				engine = ethash.NewFaker()
				db     = rawdb.NewMemoryDatabase()
				gspec  = &core.Genesis{
					Alloc:  types.GenesisAlloc{testBank: {Balance: new(big.Int).SetUint64(10000000000000000000)}},
					Config: params.TestChainConfig,
				}
				genesis = gspec.MustCommit(db)
			)
			blockchain, _ := core.NewBlockChain(db, nil, gspec, engine, vm.Config{})
			chain, _ := core.GenerateChain(gspec.Config, genesis, ethash.NewFaker(), db, 11, nil)
			if _, err := blockchain.InsertChain(chain[:10]); err != nil {
				t.Fatalf("failed to seed chain: %v", err)
			}
			next := chain[10]
			// Drop the head's TD entry to simulate legacy chaindata and reopen
			// the chain with a fresh TD cache so the deletion is visible.
			head := blockchain.CurrentBlock()
			blockchain.Stop()
			rawdb.DeleteTd(db, head.Hash(), head.Number.Uint64())

			blockchain, err := core.NewBlockChain(db, nil, gspec, engine, vm.Config{})
			if err != nil {
				t.Fatalf("failed to reopen chain: %v", err)
			}
			pm, err := NewProtocolManager(gspec.Config, downloader.FullSync, ethconfig.Defaults.NetworkId, evmux, newTestTxPool(), engine, blockchain, db)
			if err != nil {
				t.Fatalf("failed to create protocol manager: %v", err)
			}
			pm.Start(1000)
			defer pm.Stop()

			app, net := p2p.MsgPipe()
			defer app.Close()
			var id enode.ID
			rand.Read(id[:])
			fakePeer := pm.newPeer(protocol, p2p.NewPeer(id, "test", nil), net, pm.txpool.Get)
			fakePeer.td = big.NewInt(1000000)
			fakePeer.head = head.Hash()

			// The old pTd.Cmp(nil) comparison panicked here. With the local TD
			// missing, the height fallback now short-circuits first: the fake
			// peer's head is known and not above ours, so synchronise returns
			// before touching either TD and no cycle is started.
			pm.synchronise(fakePeer)
			if atomic.LoadUint32(&pm.acceptTxs) != 0 {
				t.Fatalf("synchronise with a non-ahead peer must not complete a sync cycle: acceptTxs=%d, want 0", atomic.LoadUint32(&pm.acceptTxs))
			}

			// Positive path: a fully handshaken peer advertising one block ahead
			// of the legacy local head. The missing local TD makes the threshold
			// unverifiable, so the downloader must run a complete sync cycle:
			// the height fallback must not flag the delivering peer as stalling
			// and acceptTxs must be set once the cycle completes.
			peer, _ := newTestPeer("peer", protocol, pm, false)
			defer peer.app.Close()

			// The local head TD is nil, so complete the handshake manually by
			// echoing the remote status back, letting handle() register the peer.
			msg, err := peer.app.ReadMsg()
			if err != nil {
				t.Fatalf("failed to read handshake: %v", err)
			}
			if msg.Code != StatusMsg {
				t.Fatalf("handshake message code mismatch: have %d, want %d", msg.Code, StatusMsg)
			}
			switch protocol {
			case xdc100:
				var status statusData100
				if err := msg.Decode(&status); err != nil {
					t.Fatalf("failed to decode status: %v", err)
				}
				if err := p2p.Send(peer.app, StatusMsg, &status); err != nil {
					t.Fatalf("failed to send status: %v", err)
				}
			case xdc164, xdc165:
				var status statusData
				if err := msg.Decode(&status); err != nil {
					t.Fatalf("failed to decode status: %v", err)
				}
				if err := p2p.Send(peer.app, StatusMsg, &status); err != nil {
					t.Fatalf("failed to send status: %v", err)
				}
			}

			// Serve the local chain plus the advertised next block to the
			// downloader: single-header requests get the matching header
			// (local or the next one), everything beyond is answered empty,
			// terminating the header phase. Body requests for the next block
			// are answered so the full sync import can finish.
			go func() {
				for {
					msg, err := peer.app.ReadMsg()
					if err != nil {
						return
					}
					switch msg.Code {
					case GetBlockBodiesMsg:
						var hashes []common.Hash
						if err := msg.Decode(&hashes); err != nil {
							return
						}
						bodies := make([]*blockBody, len(hashes))
						for i, hash := range hashes {
							if hash == next.Hash() {
								bodies[i] = &blockBody{Transactions: next.Transactions(), Uncles: next.Uncles()}
							}
						}
						if err := p2p.Send(peer.app, BlockBodiesMsg, bodies); err != nil {
							return
						}
					case GetBlockHeadersMsg:
						var req getBlockHeadersData
						if err := msg.Decode(&req); err != nil {
							return
						}
						var headers []*types.Header
						if req.Origin.Hash != (common.Hash{}) {
							if header := pm.blockchain.GetHeaderByHash(req.Origin.Hash); header != nil {
								headers = []*types.Header{header}
							} else if req.Origin.Hash == next.Hash() {
								headers = []*types.Header{next.Header()}
							}
						} else {
							for i, number := 0, req.Origin.Number; i < int(req.Amount); i++ {
								var header *types.Header
								if number == next.NumberU64() {
									header = next.Header()
								} else {
									header = pm.blockchain.GetHeaderByNumber(number)
								}
								if header == nil {
									break
								}
								headers = append(headers, header)
								number += req.Skip + 1
							}
						}
						if err := p2p.Send(peer.app, BlockHeadersMsg, headers); err != nil {
							return
						}
					default:
						msg.Discard()
					}
				}
			}()
			// Wait for the handshake goroutine to finish registering the peer.
			deadline := time.After(5 * time.Second)
			for pm.peers.Len() == 0 {
				select {
				case <-deadline:
					t.Fatalf("peer never registered")
				default:
					time.Sleep(time.Millisecond)
				}
			}
			// The handshake advertised the local head: it is known and not
			// above ours, so the height-based short-circuit must skip the
			// cycle entirely without probing the peer.
			pm.synchronise(peer.peer)
			if atomic.LoadUint32(&pm.acceptTxs) != 0 {
				t.Fatalf("synchronise with a same-height peer must not complete a sync cycle: acceptTxs=%d, want 0", atomic.LoadUint32(&pm.acceptTxs))
			}
			// Advertise the peer one block ahead of the local head so the
			// short-circuit lets the sync cycle through.
			peer.peer.SetHead(next.Hash(), new(big.Int).SetUint64(next.NumberU64()))
			pm.synchronise(peer.peer)
			if atomic.LoadUint32(&pm.acceptTxs) != 1 {
				t.Fatalf("synchronise did not complete the sync cycle: acceptTxs=%d, want 1", atomic.LoadUint32(&pm.acceptTxs))
			}
			if head := pm.blockchain.CurrentBlock(); head.Hash() != next.Hash() {
				t.Fatalf("head hash mismatch after sync: have %x, want %x", head.Hash(), next.Hash())
			}
		})
	}
}

// protocolTestName maps a protocol version to a human-readable subtest name.
func protocolTestName(protocol int) string {
	switch protocol {
	case xdc100:
		return "protocol100"
	case xdc164:
		return "protocol164"
	default:
		return "protocol165"
	}
}

// testHandshake completes the status handshake for a newTestPeer created with
// shake=false by echoing the remote status back, then waits until handle()
// registers the peer in the protocol manager.
func testHandshake(t *testing.T, pm *ProtocolManager, peer *testPeer, protocol int) {
	t.Helper()
	msg, err := peer.app.ReadMsg()
	if err != nil {
		t.Fatalf("failed to read handshake: %v", err)
	}
	if msg.Code != StatusMsg {
		t.Fatalf("handshake message code mismatch: have %d, want %d", msg.Code, StatusMsg)
	}
	switch protocol {
	case xdc100:
		var status statusData100
		if err := msg.Decode(&status); err != nil {
			t.Fatalf("failed to decode status: %v", err)
		}
		if err := p2p.Send(peer.app, StatusMsg, &status); err != nil {
			t.Fatalf("failed to send status: %v", err)
		}
	case xdc164, xdc165:
		var status statusData
		if err := msg.Decode(&status); err != nil {
			t.Fatalf("failed to decode status: %v", err)
		}
		if err := p2p.Send(peer.app, StatusMsg, &status); err != nil {
			t.Fatalf("failed to send status: %v", err)
		}
	}
	deadline := time.After(5 * time.Second)
	for pm.peers.Len() == 0 {
		select {
		case <-deadline:
			t.Fatalf("peer never registered")
		default:
			time.Sleep(time.Millisecond)
		}
	}
}

// testServeChain answers header, body, receipt and node-data requests on app
// for a generated chain whose blocks carry no transactions. The responder only
// serves blocks up to next, the head the simulated peer advertises; requests
// beyond it are answered empty so the header phase terminates. All generated
// blocks have empty transaction lists, so their receipts are empty and their
// state roots equal the genesis root.
func testServeChain(pm *ProtocolManager, app *p2p.MsgPipeRW, chain []*types.Block, next *types.Block, serveReceipts bool) {
	headNum := next.NumberU64()
	byHash := make(map[common.Hash]*types.Block, headNum+1)
	for _, block := range chain {
		if block.NumberU64() > headNum {
			break
		}
		byHash[block.Hash()] = block
	}
	byHash[next.Hash()] = next
	go func() {
		for {
			msg, err := app.ReadMsg()
			if err != nil {
				return
			}
			switch msg.Code {
			case GetBlockBodiesMsg:
				var hashes []common.Hash
				if err := msg.Decode(&hashes); err != nil {
					return
				}
				bodies := make([]*blockBody, len(hashes))
				for i, hash := range hashes {
					if block := byHash[hash]; block != nil {
						bodies[i] = &blockBody{Transactions: block.Transactions(), Uncles: block.Uncles()}
					}
				}
				if err := p2p.Send(app, BlockBodiesMsg, bodies); err != nil {
					return
				}
			case GetBlockHeadersMsg:
				var req getBlockHeadersData
				if err := msg.Decode(&req); err != nil {
					return
				}
				var headers []*types.Header
				if req.Origin.Hash != (common.Hash{}) {
					if block := byHash[req.Origin.Hash]; block != nil {
						headers = []*types.Header{block.Header()}
					} else if header := pm.blockchain.GetHeaderByHash(req.Origin.Hash); header != nil {
						headers = []*types.Header{header}
					}
				} else {
					for i, number := 0, req.Origin.Number; i < int(req.Amount); i++ {
						var header *types.Header
						if number >= 1 && number <= headNum {
							header = chain[number-1].Header()
						} else {
							header = pm.blockchain.GetHeaderByNumber(number)
						}
						if header == nil {
							break
						}
						headers = append(headers, header)
						number += req.Skip + 1
					}
				}
				if err := p2p.Send(app, BlockHeadersMsg, headers); err != nil {
					return
				}
			case GetReceiptsMsg:
				if !serveReceipts {
					msg.Discard()
					break
				}
				var hashes []common.Hash
				if err := msg.Decode(&hashes); err != nil {
					return
				}
				receipts := make([]rlp.RawValue, 0, len(hashes))
				for _, hash := range hashes {
					if _, ok := byHash[hash]; ok {
						// Generated blocks carry no transactions.
						encoded, err := rlp.EncodeToBytes(types.Receipts{})
						if err != nil {
							return
						}
						receipts = append(receipts, encoded)
						continue
					}
					results := pm.blockchain.GetReceiptsByHash(hash)
					if results == nil {
						if header := pm.blockchain.GetHeaderByHash(hash); header == nil || header.ReceiptHash != types.EmptyRootHash {
							continue
						}
					}
					encoded, err := rlp.EncodeToBytes(results)
					if err != nil {
						return
					}
					receipts = append(receipts, encoded)
				}
				if err := p2p.Send(app, ReceiptsMsg, receipts); err != nil {
					return
				}
			case GetNodeDataMsg:
				// The generated chain has no transactions, so every state root
				// equals the genesis root, which is fully present locally. The
				// state sync normally issues no requests; serve defensively in
				// case it does.
				msgStream := rlp.NewStream(msg.Payload, uint64(msg.Size))
				if _, err := msgStream.List(); err != nil {
					return
				}
				var (
					hash common.Hash
					data [][]byte
				)
				for {
					if err := msgStream.Decode(&hash); err == rlp.EOL {
						break
					} else if err != nil {
						return
					}
					if entry, _ := pm.blockchain.TrieNode(hash); len(entry) > 0 {
						data = append(data, entry)
					} else if entry, _ = pm.blockchain.ContractCodeWithPrefix(hash); len(entry) > 0 {
						data = append(data, entry)
					}
				}
				if err := p2p.Send(app, NodeDataMsg, data); err != nil {
					return
				}
			default:
				msg.Discard()
			}
		}
	}()
}

// TestSynchroniseZeroPeerTd verifies that a peer advertising the zero TD wire
// sentinel (a legacy node without a TD index) is not treated as having a real
// total difficulty. A healthy local node must skip such a peer when its known
// head is not strictly above ours, and must otherwise complete a full sync
// cycle with it.
func TestSynchroniseZeroPeerTd(t *testing.T) {
	for _, protocol := range []int{xdc100, xdc164, xdc165} {
		t.Run(protocolTestName(protocol), func(t *testing.T) {
			var (
				evmux  = new(event.TypeMux)
				engine = ethash.NewFaker()
				db     = rawdb.NewMemoryDatabase()
				gspec  = &core.Genesis{
					Alloc:  types.GenesisAlloc{testBank: {Balance: new(big.Int).SetUint64(10000000000000000000)}},
					Config: params.TestChainConfig,
				}
				genesis = gspec.MustCommit(db)
			)
			blockchain, _ := core.NewBlockChain(db, nil, gspec, engine, vm.Config{})
			chain, _ := core.GenerateChain(gspec.Config, genesis, ethash.NewFaker(), db, 11, nil)
			if _, err := blockchain.InsertChain(chain[:10]); err != nil {
				t.Fatalf("failed to seed chain: %v", err)
			}
			next := chain[10]
			head := blockchain.CurrentBlock()

			pm, err := NewProtocolManager(gspec.Config, downloader.FullSync, ethconfig.Defaults.NetworkId, evmux, newTestTxPool(), engine, blockchain, db)
			if err != nil {
				t.Fatalf("failed to create protocol manager: %v", err)
			}
			pm.Start(1000)
			defer pm.Stop()

			// Skip path: a zero-TD peer whose head is known and not strictly
			// above ours is skipped via the height fallback even though the
			// local TD exists.
			app, net := p2p.MsgPipe()
			defer app.Close()
			var id enode.ID
			rand.Read(id[:])
			fakePeer := pm.newPeer(protocol, p2p.NewPeer(id, "test", nil), net, pm.txpool.Get)
			fakePeer.td = new(big.Int) // zero TD wire sentinel of a legacy peer
			fakePeer.head = head.Hash()
			pm.synchronise(fakePeer)
			if atomic.LoadUint32(&pm.acceptTxs) != 0 {
				t.Fatalf("synchronise with a non-ahead zero-TD peer must not complete a sync cycle: acceptTxs=%d, want 0", atomic.LoadUint32(&pm.acceptTxs))
			}

			// Positive path: a fully handshaken peer advertising one block
			// ahead with the zero TD sentinel. The peer TD is unverifiable,
			// so the downloader must run a complete sync cycle and acceptTxs
			// must be set once it completes.
			peer, _ := newTestPeer("peer", protocol, pm, false)
			defer peer.app.Close()
			testHandshake(t, pm, peer, protocol)
			testServeChain(pm, peer.app, chain, next, false)

			peer.peer.SetHead(next.Hash(), new(big.Int))
			pm.synchronise(peer.peer)
			if atomic.LoadUint32(&pm.acceptTxs) != 1 {
				t.Fatalf("synchronise did not complete the sync cycle: acceptTxs=%d, want 1", atomic.LoadUint32(&pm.acceptTxs))
			}
			if got := pm.blockchain.CurrentBlock(); got.Hash() != next.Hash() {
				t.Fatalf("head hash mismatch after sync: have %x, want %x", got.Hash(), next.Hash())
			}
		})
	}
}

// TestSynchroniseZeroPeerTdFastSync verifies the fast sync guard against the
// zero TD wire sentinel: a healthy node running fast sync must not reject a
// zero-TD peer merely because the local snap TD exists. The peer serves the
// entire generated chain from genesis and the sync cycle must complete.
func TestSynchroniseZeroPeerTdFastSync(t *testing.T) {
	for _, protocol := range []int{xdc100, xdc164, xdc165} {
		t.Run(protocolTestName(protocol), func(t *testing.T) {
			var (
				evmux  = new(event.TypeMux)
				engine = ethash.NewFaker()
				db     = rawdb.NewMemoryDatabase()
				gspec  = &core.Genesis{
					Alloc:  types.GenesisAlloc{testBank: {Balance: new(big.Int).SetUint64(10000000000000000000)}},
					Config: params.TestChainConfig,
				}
				genesis = gspec.MustCommit(db)
			)
			// Fast sync is only enabled on an empty blockchain, so the local
			// chain stays at genesis and the peer serves the entire chain.
			blockchain, _ := core.NewBlockChain(db, nil, gspec, engine, vm.Config{})
			chain, _ := core.GenerateChain(gspec.Config, genesis, ethash.NewFaker(), db, 11, nil)
			next := chain[10]

			pm, err := NewProtocolManager(gspec.Config, downloader.FastSync, ethconfig.Defaults.NetworkId, evmux, newTestTxPool(), engine, blockchain, db)
			if err != nil {
				t.Fatalf("failed to create protocol manager: %v", err)
			}
			if atomic.LoadUint32(&pm.snapSync) != 1 {
				t.Fatalf("snap sync not enabled on pristine blockchain")
			}
			pm.Start(1000)
			defer pm.Stop()

			peer, _ := newTestPeer("peer", protocol, pm, false)
			defer peer.app.Close()
			testHandshake(t, pm, peer, protocol)
			testServeChain(pm, peer.app, chain, next, true)

			// Advertise the peer one block ahead with the zero TD sentinel.
			// Neither the head TD threshold nor the snap TD guard may reject
			// the unverifiable peer.
			peer.peer.SetHead(next.Hash(), new(big.Int))
			pm.synchronise(peer.peer)
			if atomic.LoadUint32(&pm.acceptTxs) != 1 {
				t.Fatalf("synchronise did not complete the sync cycle: acceptTxs=%d, want 1", atomic.LoadUint32(&pm.acceptTxs))
			}
			if got := pm.blockchain.CurrentBlock(); got.Hash() != next.Hash() {
				t.Fatalf("head hash mismatch after sync: have %x, want %x", got.Hash(), next.Hash())
			}
			if atomic.LoadUint32(&pm.snapSync) != 0 {
				t.Fatalf("snap sync not disabled after sync cycle")
			}
		})
	}
}

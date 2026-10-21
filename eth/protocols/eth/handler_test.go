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
	"math/big"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/eth/downloader"
	"github.com/XinFinOrg/XDPoSChain/p2p"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// Tests that block headers can be retrieved from a remote chain based on user queries.
func TestGetBlockHeaders100(t *testing.T) { testGetBlockHeaders(t, XDC100) }
func TestGetBlockHeaders164(t *testing.T) { testGetBlockHeaders(t, XDC164) }
func TestGetBlockHeaders165(t *testing.T) { testGetBlockHeaders(t, XDC165) }

func testGetBlockHeaders(t *testing.T, protocol uint) {
	backend := newTestBackend(t, downloader.MaxHashFetch+15, nil)
	peer := newTestPeer(t, "peer", protocol, backend)
	chain := backend.chain

	// Create a "random" unknown hash for testing
	var unknown common.Hash
	for i := range unknown {
		unknown[i] = byte(i)
	}
	// Create a batch of tests for various scenarios
	limit := uint64(downloader.MaxHeaderFetch)
	tests := []struct {
		query  *GetBlockHeadersPacket // The query to execute for header retrieval
		expect []common.Hash          // The hashes of the block whose headers are expected
	}{
		// A single random block should be retrievable by hash and number too
		{
			&GetBlockHeadersPacket{Origin: HashOrNumber{Hash: chain.GetBlockByNumber(limit / 2).Hash()}, Amount: 1},
			[]common.Hash{chain.GetBlockByNumber(limit / 2).Hash()},
		}, {
			&GetBlockHeadersPacket{Origin: HashOrNumber{Number: limit / 2}, Amount: 1},
			[]common.Hash{chain.GetBlockByNumber(limit / 2).Hash()},
		},
		// Multiple headers should be retrievable in both directions
		{
			&GetBlockHeadersPacket{Origin: HashOrNumber{Number: limit / 2}, Amount: 3},
			[]common.Hash{
				chain.GetBlockByNumber(limit / 2).Hash(),
				chain.GetBlockByNumber(limit/2 + 1).Hash(),
				chain.GetBlockByNumber(limit/2 + 2).Hash(),
			},
		}, {
			&GetBlockHeadersPacket{Origin: HashOrNumber{Number: limit / 2}, Amount: 3, Reverse: true},
			[]common.Hash{
				chain.GetBlockByNumber(limit / 2).Hash(),
				chain.GetBlockByNumber(limit/2 - 1).Hash(),
				chain.GetBlockByNumber(limit/2 - 2).Hash(),
			},
		},
		// Multiple headers with skip lists should be retrievable
		{
			&GetBlockHeadersPacket{Origin: HashOrNumber{Number: limit / 2}, Skip: 3, Amount: 3},
			[]common.Hash{
				chain.GetBlockByNumber(limit / 2).Hash(),
				chain.GetBlockByNumber(limit/2 + 4).Hash(),
				chain.GetBlockByNumber(limit/2 + 8).Hash(),
			},
		}, {
			&GetBlockHeadersPacket{Origin: HashOrNumber{Number: limit / 2}, Skip: 3, Amount: 3, Reverse: true},
			[]common.Hash{
				chain.GetBlockByNumber(limit / 2).Hash(),
				chain.GetBlockByNumber(limit/2 - 4).Hash(),
				chain.GetBlockByNumber(limit/2 - 8).Hash(),
			},
		},
		// The chain endpoints should be retrievable
		{
			&GetBlockHeadersPacket{Origin: HashOrNumber{Number: 0}, Amount: 1},
			[]common.Hash{chain.GetBlockByNumber(0).Hash()},
		}, {
			&GetBlockHeadersPacket{Origin: HashOrNumber{Number: chain.CurrentBlock().Number.Uint64()}, Amount: 1},
			[]common.Hash{chain.CurrentBlock().Hash()},
		},
		// Ensure protocol limits are honored
		{
			&GetBlockHeadersPacket{Origin: HashOrNumber{Number: chain.CurrentBlock().Number.Uint64() - 1}, Amount: limit + 10, Reverse: true},
			headerHashRange(chain, chain.CurrentBlock().Number.Uint64()-1, limit),
		},
		// Check that requesting more than available is handled gracefully
		{
			&GetBlockHeadersPacket{Origin: HashOrNumber{Number: chain.CurrentBlock().Number.Uint64() - 4}, Skip: 3, Amount: 3},
			[]common.Hash{
				chain.GetBlockByNumber(chain.CurrentBlock().Number.Uint64() - 4).Hash(),
				chain.GetBlockByNumber(chain.CurrentBlock().Number.Uint64()).Hash(),
			},
		}, {
			&GetBlockHeadersPacket{Origin: HashOrNumber{Number: 4}, Skip: 3, Amount: 3, Reverse: true},
			[]common.Hash{
				chain.GetBlockByNumber(4).Hash(),
				chain.GetBlockByNumber(0).Hash(),
			},
		},
		// Check that requesting more than available is handled gracefully, even if mid skip
		{
			&GetBlockHeadersPacket{Origin: HashOrNumber{Number: chain.CurrentBlock().Number.Uint64() - 4}, Skip: 2, Amount: 3},
			[]common.Hash{
				chain.GetBlockByNumber(chain.CurrentBlock().Number.Uint64() - 4).Hash(),
				chain.GetBlockByNumber(chain.CurrentBlock().Number.Uint64() - 1).Hash(),
			},
		}, {
			&GetBlockHeadersPacket{Origin: HashOrNumber{Number: 4}, Skip: 2, Amount: 3, Reverse: true},
			[]common.Hash{
				chain.GetBlockByNumber(4).Hash(),
				chain.GetBlockByNumber(1).Hash(),
			},
		},
		// Check a corner case where requesting more can iterate past the endpoints
		{
			&GetBlockHeadersPacket{Origin: HashOrNumber{Number: 2}, Amount: 5, Reverse: true},
			[]common.Hash{
				chain.GetBlockByNumber(2).Hash(),
				chain.GetBlockByNumber(1).Hash(),
				chain.GetBlockByNumber(0).Hash(),
			},
		},
		// Check a corner case where skipping overflow loops back into the chain start
		{
			&GetBlockHeadersPacket{Origin: HashOrNumber{Hash: chain.GetBlockByNumber(3).Hash()}, Amount: 2, Reverse: false, Skip: ^uint64(0) - 1},
			[]common.Hash{
				chain.GetBlockByNumber(3).Hash(),
			},
		},
		// Check a corner case where skipping overflow loops back to the same header
		{
			&GetBlockHeadersPacket{Origin: HashOrNumber{Hash: chain.GetBlockByNumber(1).Hash()}, Amount: 2, Reverse: false, Skip: ^uint64(0)},
			[]common.Hash{
				chain.GetBlockByNumber(1).Hash(),
			},
		},
		// Check that non existing headers aren't returned
		{
			&GetBlockHeadersPacket{Origin: HashOrNumber{Hash: unknown}, Amount: 1},
			[]common.Hash{},
		}, {
			&GetBlockHeadersPacket{Origin: HashOrNumber{Number: chain.CurrentBlock().Number.Uint64() + 1}, Amount: 1},
			[]common.Hash{},
		},
	}
	// Run each of the tests and verify the results against the chain
	for i, tt := range tests {
		// Collect the headers to expect in the response
		headers := []*types.Header{}
		for _, hash := range tt.expect {
			headers = append(headers, chain.GetBlockByHash(hash).Header())
		}
		// Send the hash request and verify the response
		p2p.Send(peer.app, GetBlockHeadersMsg, tt.query)
		if err := p2p.ExpectMsg(peer.app, BlockHeadersMsg, headers); err != nil {
			t.Errorf("test %d: headers mismatch: %v", i, err)
		}
		// If the test used number origins, repeat with hashes as the too
		if tt.query.Origin.Hash == (common.Hash{}) {
			if origin := chain.GetBlockByNumber(tt.query.Origin.Number); origin != nil {
				tt.query.Origin.Hash, tt.query.Origin.Number = origin.Hash(), 0

				p2p.Send(peer.app, GetBlockHeadersMsg, tt.query)
				if err := p2p.ExpectMsg(peer.app, BlockHeadersMsg, headers); err != nil {
					t.Errorf("test %d: headers mismatch: %v", i, err)
				}
			}
		}
	}
}

// headerHashRange returns the hashes of the canonical headers at top, top-1, ...,
// down towards genesis, at most count of them. Tests state the expected reply of
// a descending query with it instead of asking the chain for the same slice the
// serving code builds.
func headerHashRange(chain *core.BlockChain, top, count uint64) []common.Hash {
	hashes := make([]common.Hash, 0, count)
	for i := uint64(0); i < count && i <= top; i++ {
		hashes = append(hashes, chain.GetHeaderByNumber(top-i).Hash())
	}
	return hashes
}

// Tests that block contents can be retrieved from a remote chain based on their hashes.
func TestGetBlockBodies100(t *testing.T) { testGetBlockBodies(t, XDC100) }
func TestGetBlockBodies164(t *testing.T) { testGetBlockBodies(t, XDC164) }
func TestGetBlockBodies165(t *testing.T) { testGetBlockBodies(t, XDC165) }

func testGetBlockBodies(t *testing.T, protocol uint) {
	backend := newTestBackend(t, downloader.MaxBlockFetch+15, nil)
	peer := newTestPeer(t, "peer", protocol, backend)
	chain := backend.chain

	// Create a batch of tests for various scenarios
	limit := downloader.MaxBlockFetch
	tests := []struct {
		random    int           // Number of blocks to fetch randomly from the chain
		explicit  []common.Hash // Explicitly requested blocks
		available []bool        // Availability of explicitly requested blocks
		expected  int           // Total number of existing blocks to expect
	}{
		{1, nil, nil, 1},             // A single random block should be retrievable
		{10, nil, nil, 10},           // Multiple random blocks should be retrievable
		{limit, nil, nil, limit},     // The maximum possible blocks should be retrievable
		{limit + 1, nil, nil, limit}, // No more than the possible block count should be returned
		{0, []common.Hash{chain.Genesis().Hash()}, []bool{true}, 1},      // The genesis block should be retrievable
		{0, []common.Hash{chain.CurrentBlock().Hash()}, []bool{true}, 1}, // The chains head block should be retrievable
		{0, []common.Hash{{}}, []bool{false}, 0},                         // A non existent block should not be returned

		// Existing and non-existing blocks interleaved should not cause problems
		{0, []common.Hash{
			{},
			chain.GetBlockByNumber(1).Hash(),
			{},
			chain.GetBlockByNumber(10).Hash(),
			{},
			chain.GetBlockByNumber(100).Hash(),
			{},
		}, []bool{false, true, false, true, false, true, false}, 3},
	}
	// Run each of the tests and verify the results against the chain
	for i, tt := range tests {
		// Collect the hashes to request, and the response to expect
		hashes, seen := []common.Hash{}, make(map[int64]bool)
		bodies := []*BlockBody{}

		for j := 0; j < tt.random; j++ {
			for {
				num := rand.Int63n(int64(chain.CurrentBlock().Number.Uint64()))
				if !seen[num] {
					seen[num] = true

					block := chain.GetBlockByNumber(uint64(num))
					hashes = append(hashes, block.Hash())
					if len(bodies) < tt.expected {
						bodies = append(bodies, &BlockBody{Transactions: block.Transactions(), Uncles: block.Uncles()})
					}
					break
				}
			}
		}
		for j, hash := range tt.explicit {
			hashes = append(hashes, hash)
			if tt.available[j] && len(bodies) < tt.expected {
				block := chain.GetBlockByHash(hash)
				bodies = append(bodies, &BlockBody{Transactions: block.Transactions(), Uncles: block.Uncles()})
			}
		}
		// Send the hash request and verify the response
		p2p.Send(peer.app, GetBlockBodiesMsg, hashes)
		if err := p2p.ExpectMsg(peer.app, BlockBodiesMsg, bodies); err != nil {
			t.Errorf("test %d: bodies mismatch: %v", i, err)
		}
	}
}

// Tests that the node state database can be retrieved based on hashes.
func TestGetNodeData100(t *testing.T) { testGetNodeData(t, XDC100) }
func TestGetNodeData164(t *testing.T) { testGetNodeData(t, XDC164) }
func TestGetNodeData165(t *testing.T) { testGetNodeData(t, XDC165) }

func testGetNodeData(t *testing.T, protocol uint) {
	// Define three accounts to simulate transactions with
	acc1Key, _ := crypto.HexToECDSA("8a1f9a8f95be41cd7ccb6168179afb4504aefe388d1e14474d32c45c72ce7b7a")
	acc2Key, _ := crypto.HexToECDSA("49a7b37aa6f6645917e7b807e9d1c00d4fa71f18343b0d4122a4d2df64dd6fee")
	acc1Addr := crypto.PubkeyToAddress(acc1Key.PublicKey)
	acc2Addr := crypto.PubkeyToAddress(acc2Key.PublicKey)

	signer := types.HomesteadSigner{}
	// Create a chain generator with some simple transactions (blatantly stolen from @fjl/chain_markets_test)
	generator := func(i int, block *core.BlockGen) {
		fee := block.BaseFee()
		if fee == nil {
			fee = big.NewInt(params.InitialBaseFee)
		}
		switch i {
		case 0:
			// In block 1, the test bank sends account #1 some ether.
			tx, _ := types.SignTx(types.NewTransaction(block.TxNonce(testBank), acc1Addr, new(big.Int).SetUint64(1_000_000_000_000_000_000), params.TxGas, fee, nil), signer, testBankKey)
			block.AddTx(tx)
		case 1:
			// In block 2, the test bank sends some more ether to account #1.
			// acc1Addr passes it on to account #2.
			tx1, _ := types.SignTx(types.NewTransaction(block.TxNonce(testBank), acc1Addr, new(big.Int).SetUint64(1_000_000_000_000_000_000), params.TxGas, fee, nil), signer, testBankKey)
			tx2, _ := types.SignTx(types.NewTransaction(block.TxNonce(acc1Addr), acc2Addr, new(big.Int).SetUint64(1_000_000_000_000_000_000), params.TxGas, fee, nil), signer, acc1Key)
			block.AddTx(tx1)
			block.AddTx(tx2)
		case 2:
			// Block 3 is empty but was mined by account #2.
			block.SetCoinbase(acc2Addr)
			block.SetExtra([]byte("yeehaw"))
		case 3:
			// Block 4 includes blocks 2 and 3 as uncle headers (with modified extra data).
			b2 := block.PrevBlock(1).Header()
			b2.Extra = []byte("foo")
			block.AddUncle(b2)
			b3 := block.PrevBlock(2).Header()
			b3.Extra = []byte("foo")
			block.AddUncle(b3)
		}
	}
	// Assemble the test environment
	backend := newTestBackend(t, 4, generator)
	peer := newTestPeer(t, "peer", protocol, backend)
	db := backend.db

	// Fetch for now the entire chain db
	hashes := []common.Hash{}
	it := db.NewIterator(nil, nil)
	for it.Next() {
		key := it.Key()
		if len(key) == len(common.Hash{}) {
			hashes = append(hashes, common.BytesToHash(key))
		}
	}
	p2p.Send(peer.app, GetNodeDataMsg, hashes)
	msg, err := peer.app.ReadMsg()
	if err != nil {
		t.Fatalf("failed to read node data response: %v", err)
	}
	if msg.Code != NodeDataMsg {
		t.Fatalf("response packet code mismatch: have %x, want %x", msg.Code, NodeDataMsg)
	}
	var data [][]byte
	if err := msg.Decode(&data); err != nil {
		t.Fatalf("failed to decode response node data: %v", err)
	}
	// Verify that all hashes correspond to the requested data, and reconstruct a state tree
	for i, want := range hashes {
		if hash := crypto.Keccak256Hash(data[i]); hash != want {
			t.Errorf("data hash mismatch: have %x, want %x", hash, want)
		}
	}
	statedb := rawdb.NewMemoryDatabase()
	for i := 0; i < len(data); i++ {
		statedb.Put(hashes[i].Bytes(), data[i])
	}
	accounts := []common.Address{testBank, acc1Addr, acc2Addr}
	for i := uint64(0); i <= backend.chain.CurrentBlock().Number.Uint64(); i++ {
		trie, _ := state.New(backend.chain.GetBlockByNumber(i).Root(), state.NewDatabase(statedb))

		for j, acc := range accounts {
			state, _ := backend.chain.State()
			bw := state.GetBalance(acc)
			bh := trie.GetBalance(acc)

			if (bw != nil && bh == nil) || (bw == nil && bh != nil) {
				t.Errorf("test %d, account %d: balance mismatch: have %v, want %v", i, j, bh, bw)
			}
			if bw != nil && bh != nil && bw.Cmp(bw) != 0 {
				t.Errorf("test %d, account %d: balance mismatch: have %v, want %v", i, j, bh, bw)
			}
		}
	}
}

// Tests that the transaction receipts can be retrieved based on hashes.
func TestGetReceipt100(t *testing.T) { testGetReceipt(t, XDC100) }
func TestGetReceipt164(t *testing.T) { testGetReceipt(t, XDC164) }
func TestGetReceipt165(t *testing.T) { testGetReceipt(t, XDC165) }

func testGetReceipt(t *testing.T, protocol uint) {
	// Define three accounts to simulate transactions with
	acc1Key, _ := crypto.HexToECDSA("8a1f9a8f95be41cd7ccb6168179afb4504aefe388d1e14474d32c45c72ce7b7a")
	acc2Key, _ := crypto.HexToECDSA("49a7b37aa6f6645917e7b807e9d1c00d4fa71f18343b0d4122a4d2df64dd6fee")
	acc1Addr := crypto.PubkeyToAddress(acc1Key.PublicKey)
	acc2Addr := crypto.PubkeyToAddress(acc2Key.PublicKey)

	signer := types.HomesteadSigner{}
	// Create a chain generator with some simple transactions (blatantly stolen from @fjl/chain_markets_test)
	generator := func(i int, block *core.BlockGen) {
		fee := block.BaseFee()
		if fee == nil {
			fee = big.NewInt(params.InitialBaseFee)
		}
		switch i {
		case 0:
			// In block 1, the test bank sends account #1 some ether.
			tx, _ := types.SignTx(types.NewTransaction(block.TxNonce(testBank), acc1Addr, new(big.Int).SetUint64(1_000_000_000_000_000_000), params.TxGas, fee, nil), signer, testBankKey)
			block.AddTx(tx)
		case 1:
			// In block 2, the test bank sends some more ether to account #1.
			// acc1Addr passes it on to account #2.
			tx1, _ := types.SignTx(types.NewTransaction(block.TxNonce(testBank), acc1Addr, new(big.Int).SetUint64(1_000_000_000_000_000_000), params.TxGas, fee, nil), signer, testBankKey)
			tx2, _ := types.SignTx(types.NewTransaction(block.TxNonce(acc1Addr), acc2Addr, new(big.Int).SetUint64(1_000_000_000_000_000_000), params.TxGas, fee, nil), signer, acc1Key)
			block.AddTx(tx1)
			block.AddTx(tx2)
		case 2:
			// Block 3 is empty but was mined by account #2.
			block.SetCoinbase(acc2Addr)
			block.SetExtra([]byte("yeehaw"))
		case 3:
			// Block 4 includes blocks 2 and 3 as uncle headers (with modified extra data).
			b2 := block.PrevBlock(1).Header()
			b2.Extra = []byte("foo")
			block.AddUncle(b2)
			b3 := block.PrevBlock(2).Header()
			b3.Extra = []byte("foo")
			block.AddUncle(b3)
		}
	}
	// Assemble the test environment
	backend := newTestBackend(t, 4, generator)
	peer := newTestPeer(t, "peer", protocol, backend)

	// Collect the hashes to request, and the response to expect
	hashes, receipts := []common.Hash{}, []types.Receipts{}
	for i := uint64(0); i <= backend.chain.CurrentBlock().Number.Uint64(); i++ {
		block := backend.chain.GetBlockByNumber(i)

		hashes = append(hashes, block.Hash())
		receipts = append(receipts, backend.chain.GetReceiptsByHash(block.Hash()))
	}
	// Send the hash request and verify the response
	p2p.Send(peer.app, GetReceiptsMsg, hashes)
	if err := p2p.ExpectMsg(peer.app, ReceiptsMsg, receipts); err != nil {
		t.Errorf("receipts mismatch: %v", err)
	}
}

// Tests that a malformed payload is rejected through the decode-error path
// instead of crashing the peer.
func TestMalformedPayload(t *testing.T) {
	backend := newTestBackend(t, 1, nil)
	peer := newTestPeer(t, "peer", XDC165, backend)

	// A header query is a struct, so an integer payload cannot decode into it.
	go p2p.Send(peer.app, GetBlockHeadersMsg, uint64(1))

	select {
	case err := <-peer.errc:
		if err == nil {
			t.Fatal("malformed payload was accepted")
		}
		if want := errCode(ErrDecode).String(); !strings.Contains(err.Error(), want) {
			t.Errorf("wrong error: got %v, want a %q error", err, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("malformed payload was not rejected within 2 seconds")
	}
}

// Tests that a message larger than the protocol cap is rejected without being
// decoded.
func TestOversizeMessage(t *testing.T) {
	backend := newTestBackend(t, 1, nil)
	peer := newTestPeer(t, "peer", XDC165, backend)

	// The payload is larger than the protocol cap, so it is never read by the
	// serving side; send it from a goroutine and let the pipe teardown release it.
	go p2p.Send(peer.app, NodeDataMsg, make([]byte, protocolMaxMsgSize+1))

	select {
	case err := <-peer.errc:
		if err == nil {
			t.Fatal("oversize message was accepted")
		}
		if !strings.Contains(err.Error(), errCode(ErrMsgTooLarge).String()) {
			t.Errorf("wrong error: got %v, want a %q error", err, errCode(ErrMsgTooLarge).String())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("oversize message was not rejected within 2 seconds")
	}
}

// Tests that the XDC-specific packets are decoded and handed to the backend
// instead of being dropped.
func TestXDCPacketsReachBackend(t *testing.T) {
	backend := newTestBackend(t, 1, nil)

	type handled struct {
		name string
		size uint32
	}
	received := make(chan handled, 5)
	backend.handler = func(peer *Peer, packet Packet, size uint32) error {
		received <- handled{name: packet.Name(), size: size}
		return nil
	}
	peer := newTestPeer(t, "peer", XDC165, backend)

	vote := &types.Vote{ProposedBlockInfo: &types.BlockInfo{Hash: common.Hash{0x01}, Round: 1, Number: big.NewInt(2)}, Signature: types.Signature{0x01}}
	timeout := &types.Timeout{Round: 2, Signature: types.Signature{0x02}}
	syncInfo := &types.SyncInfo{
		HighestQuorumCert:  &types.QuorumCert{ProposedBlockInfo: &types.BlockInfo{Hash: common.Hash{0x02}, Round: 1, Number: big.NewInt(2)}, Signatures: []types.Signature{{0x03}}},
		HighestTimeoutCert: &types.TimeoutCert{Round: 3, Signatures: []types.Signature{{0x04}}},
	}
	orderTx := types.NewOrderTransaction(1, big.NewInt(1), big.NewInt(1), common.Address{}, common.Address{}, common.Address{}, common.Address{}, "status", "side", "type", common.Hash{}, 1)
	lendingTx := types.NewLendingTransaction(1, big.NewInt(1), 1, 1, common.Address{}, common.Address{}, common.Address{}, common.Address{}, false, "status", "side", "type", common.Hash{}, 1, 1, "")

	backend.accepted.Store(true)
	sends := []struct {
		name string
		code uint64
		data interface{}
	}{
		{"OrderTransactions", OrderTxMsg, types.OrderTransactions{orderTx}},
		{"LendingTransactions", LendingTxMsg, types.LendingTransactions{lendingTx}},
		{"Vote", VoteMsg, vote},
		{"Timeout", TimeoutMsg, timeout},
		{"SyncInfo", SyncInfoMsg, syncInfo},
	}
	for _, send := range sends {
		sentErr := make(chan error, 1)
		go func() {
			// Only a failed send is news here: the serving loop tears the pipe
			// down when it rejects a packet. A nil error says nothing about
			// delivery, and reporting it would race the received channel below.
			if err := p2p.Send(peer.app, send.code, send.data); err != nil {
				sentErr <- err
			}
		}()

		select {
		case err := <-sentErr:
			t.Fatalf("packet %q was rejected instead of being handed to the backend: %v", send.name, err)
		case got := <-received:
			if got.name != send.name {
				t.Errorf("packet name mismatch: have %q, want %q", got.name, send.name)
			}
			if got.size == 0 {
				t.Errorf("packet %q: reported wire size is zero", got.name)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("packet %q was not handed to the backend within 2 seconds", send.name)
		}
	}
}

// Tests that inbound transaction traffic is ignored while the node is not
// synchronised, and only then handed to the backend.
func TestTransactionGate(t *testing.T) {
	backend := newTestBackend(t, 1, nil)

	received := make(chan Packet, 1)
	backend.handler = func(peer *Peer, packet Packet, size uint32) error {
		received <- packet
		return nil
	}
	peer := newTestPeer(t, "peer", XDC165, backend)

	tx := newTestTransaction(testBankKey, 0, 0)

	// Not synchronised: the transaction must be dropped silently.
	go p2p.Send(peer.app, TransactionMsg, []*types.Transaction{tx})
	select {
	case packet := <-received:
		t.Fatalf("transaction handed to the backend while not synchronised: %v", packet)
	case <-time.After(100 * time.Millisecond):
	}

	// Synchronised: the same transaction must now reach the backend.
	backend.accepted.Store(true)
	go p2p.Send(peer.app, TransactionMsg, []*types.Transaction{tx})
	select {
	case packet := <-received:
		txs, ok := packet.(*TransactionsPacket)
		if !ok {
			t.Fatalf("packet type mismatch: have %T, want *TransactionsPacket", packet)
		}
		if len(*txs) != 1 || (*txs)[0].Hash() != tx.Hash() {
			t.Fatalf("transaction mismatch: have %v, want %v", (*txs)[0].Hash(), tx.Hash())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("transaction was not handed to the backend within 2 seconds")
	}
}

// Tests that transactions are served from the pool on request.
func TestGetPooledTransactions(t *testing.T) {
	backend := newTestBackend(t, 1, nil)
	tx := newTestTransaction(testBankKey, 0, 0)
	backend.txpool.Add([]*types.Transaction{tx}, false)

	peer := newTestPeer(t, "peer", XDC165, backend)

	p2p.Send(peer.app, GetPooledTransactionsMsg, []common.Hash{tx.Hash(), {0x02}})
	msg, err := peer.app.ReadMsg()
	if err != nil {
		t.Fatalf("failed to read transactions response: %v", err)
	}
	if msg.Code != PooledTransactionsMsg {
		t.Fatalf("response packet code mismatch: have %x, want %x", msg.Code, PooledTransactionsMsg)
	}
	var sent []*types.Transaction
	if err := msg.Decode(&sent); err != nil {
		t.Fatalf("failed to decode transactions response: %v", err)
	}
	if len(sent) != 1 || sent[0].Hash() != tx.Hash() {
		t.Fatalf("transaction response mismatch: have %v, want %v", sent, []*types.Transaction{tx})
	}
}

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
	"crypto/rand"
	"math/big"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/p2p"
	"github.com/XinFinOrg/XDPoSChain/p2p/enode"
	"github.com/XinFinOrg/XDPoSChain/rlp"
)

// TestPeerSends checks that each request and response packet the wire layer can
// send arrives as the matching message on the other end of the pipe.
func TestPeerSends(t *testing.T) {
	app, net := p2p.MsgPipe()
	defer app.Close()

	backend := newTestBackend(t, 1, nil)
	tx := newTestTransaction(testBankKey, 0, 0)

	var id enode.ID
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatalf("failed to generate random peer id: %v", err)
	}
	peer := NewPeer(XDC165, p2p.NewPeer(id, "peer", nil), net, func(common.Hash) *types.Transaction { return tx })
	defer peer.Close()

	var (
		hash     = common.Hash{0x01}
		block    = backend.chain.GetBlockByNumber(backend.chain.CurrentBlock().Number.Uint64())
		header   = block.Header()
		vote     = types.Vote{ProposedBlockInfo: &types.BlockInfo{Hash: hash, Round: 1, Number: big.NewInt(2)}, Signature: types.Signature{0x01}, GapNumber: 3}
		timeout  = types.Timeout{Round: 2, Signature: types.Signature{0x02}, GapNumber: 3}
		syncInfo = types.SyncInfo{HighestQuorumCert: &types.QuorumCert{ProposedBlockInfo: &types.BlockInfo{Hash: hash, Round: 1, Number: big.NewInt(2)}, Signatures: []types.Signature{{0x03}}}}
	)

	tests := []struct {
		name string
		send func() error
		code uint64
		want interface{}
	}{
		{
			name: "BlockHeaders",
			send: func() error { return peer.SendBlockHeaders([]*types.Header{header}) },
			code: BlockHeadersMsg,
			want: []*types.Header{header},
		},
		{
			name: "BlockBodies",
			send: func() error {
				return peer.SendBlockBodies([]*BlockBody{{Transactions: block.Transactions(), Uncles: block.Uncles()}})
			},
			code: BlockBodiesMsg,
			want: BlockBodiesPacket{{Transactions: block.Transactions(), Uncles: block.Uncles()}},
		},
		{
			name: "NodeData",
			send: func() error { return peer.SendNodeData([][]byte{{0x01, 0x02}}) },
			code: NodeDataMsg,
			want: [][]byte{{0x01, 0x02}},
		},
		{
			name: "Receipts",
			send: func() error {
				encoded, err := rlp.EncodeToBytes(backend.chain.GetReceiptsByHash(block.Hash()))
				if err != nil {
					return err
				}
				return peer.SendReceiptsRLP([]rlp.RawValue{encoded})
			},
			code: ReceiptsMsg,
			want: []rlp.RawValue{mustEncode(t, backend.chain.GetReceiptsByHash(block.Hash()))},
		},
		{
			name: "NewBlockHashes",
			send: func() error { return peer.SendNewBlockHashes([]common.Hash{hash}, []uint64{1}) },
			code: NewBlockHashesMsg,
			want: NewBlockHashesPacket{{Hash: hash, Number: 1}},
		},
		{
			name: "NewBlock",
			send: func() error { return peer.SendNewBlock(block, big.NewInt(131)) },
			code: NewBlockMsg,
			want: []interface{}{block, big.NewInt(131)},
		},
		{
			name: "Transactions",
			send: func() error { return peer.SendTransactions64(types.Transactions{tx}) },
			code: TransactionMsg,
			want: []*types.Transaction{tx},
		},
		{
			name: "PooledTransactionHashes",
			send: func() error { return peer.sendPooledTransactionHashes([]common.Hash{hash}) },
			code: NewPooledTransactionHashesMsg,
			want: []common.Hash{hash},
		},
		{
			name: "PooledTransactions",
			send: func() error {
				return peer.SendPooledTransactionsRLP([]common.Hash{hash}, []rlp.RawValue{mustEncode(t, tx)})
			},
			code: PooledTransactionsMsg,
			want: []rlp.RawValue{mustEncode(t, tx)},
		},
		{
			name: "OrderTransactions",
			send: func() error {
				return peer.SendOrderTransactions(types.OrderTransactions{types.NewOrderTransaction(1, big.NewInt(1), big.NewInt(1), common.Address{}, common.Address{}, common.Address{}, common.Address{}, "status", "side", "type", hash, 1)})
			},
			code: OrderTxMsg,
			want: types.OrderTransactions{types.NewOrderTransaction(1, big.NewInt(1), big.NewInt(1), common.Address{}, common.Address{}, common.Address{}, common.Address{}, "status", "side", "type", hash, 1)},
		},
		{
			name: "LendingTransactions",
			send: func() error {
				return peer.SendLendingTransactions(types.LendingTransactions{types.NewLendingTransaction(1, big.NewInt(1), 1, 1, common.Address{}, common.Address{}, common.Address{}, common.Address{}, false, "status", "side", "type", hash, 1, 1, "")})
			},
			code: LendingTxMsg,
			want: types.LendingTransactions{types.NewLendingTransaction(1, big.NewInt(1), 1, 1, common.Address{}, common.Address{}, common.Address{}, common.Address{}, false, "status", "side", "type", hash, 1, 1, "")},
		},
		{
			name: "Vote",
			send: func() error { return peer.SendVote(&vote) },
			code: VoteMsg,
			want: &vote,
		},
		{
			name: "Timeout",
			send: func() error { return peer.SendTimeout(&timeout) },
			code: TimeoutMsg,
			want: &timeout,
		},
		{
			name: "SyncInfo",
			send: func() error { return peer.SendSyncInfo(&syncInfo) },
			code: SyncInfoMsg,
			want: &syncInfo,
		},
		{
			name: "RequestHeadersByHash",
			send: func() error { return peer.RequestHeadersByHash(hash, 3, 1, true) },
			code: GetBlockHeadersMsg,
			want: &GetBlockHeadersPacket{Origin: HashOrNumber{Hash: hash}, Amount: 3, Skip: 1, Reverse: true},
		},
		{
			name: "RequestHeadersByNumber",
			send: func() error { return peer.RequestHeadersByNumber(314, 3, 1, false) },
			code: GetBlockHeadersMsg,
			want: &GetBlockHeadersPacket{Origin: HashOrNumber{Number: 314}, Amount: 3, Skip: 1},
		},
		{
			name: "RequestBodies",
			send: func() error { return peer.RequestBodies([]common.Hash{hash}) },
			code: GetBlockBodiesMsg,
			want: []common.Hash{hash},
		},
		{
			name: "RequestNodeData",
			send: func() error { return peer.RequestNodeData([]common.Hash{hash}) },
			code: GetNodeDataMsg,
			want: []common.Hash{hash},
		},
		{
			name: "RequestReceipts",
			send: func() error { return peer.RequestReceipts([]common.Hash{hash}) },
			code: GetReceiptsMsg,
			want: []common.Hash{hash},
		},
		{
			name: "RequestTxs",
			send: func() error { return peer.RequestTxs([]common.Hash{hash}) },
			code: GetPooledTransactionsMsg,
			want: []common.Hash{hash},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sent := make(chan error, 1)
			go func() { sent <- tt.send() }()

			if err := p2p.ExpectMsg(app, tt.code, tt.want); err != nil {
				t.Fatalf("unexpected message: %v", err)
			}
			if err := <-sent; err != nil {
				t.Fatalf("send failed: %v", err)
			}
		})
	}
}

// TestPeerMarkBookkeeping checks that announcing a hash marks it as known, which
// is the criterion the node layer uses to skip a peer on the next broadcast.
func TestPeerMarkBookkeeping(t *testing.T) {
	var id enode.ID
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatalf("failed to generate random peer id: %v", err)
	}
	hash := common.Hash{0x01}
	tx := newTestTransaction(testBankKey, 0, 0)
	vote := types.Vote{ProposedBlockInfo: &types.BlockInfo{Hash: hash, Round: 1, Number: big.NewInt(2)}}
	timeout := types.Timeout{Round: 1}
	syncInfo := types.SyncInfo{HighestTimeoutCert: &types.TimeoutCert{Round: 1}}

	app, net := p2p.MsgPipe()
	defer app.Close()

	// Mark through each of the entry points and check the known set the node layer
	// reads back.
	peer := NewPeer(XDC165, p2p.NewPeer(id, "peer", nil), net, func(common.Hash) *types.Transaction { return tx })
	defer peer.Close()

	peer.MarkBlock(hash)
	if !peer.KnownBlock(hash) {
		t.Error("marked block not reported as known")
	}
	peer.MarkTransaction(tx.Hash())
	if !peer.KnownTransaction(tx.Hash()) {
		t.Error("marked transaction not reported as known")
	}
	peer.MarkOrderTransaction(hash)
	if !peer.KnownOrderTransaction(hash) {
		t.Error("marked order transaction not reported as known")
	}
	peer.MarkLendingTransaction(hash)
	if !peer.KnownLendingTransaction(hash) {
		t.Error("marked lending transaction not reported as known")
	}
	peer.MarkVote(vote.Hash())
	if !peer.KnownVote(vote.Hash()) {
		t.Error("marked vote not reported as known")
	}
	peer.MarkTimeout(timeout.Hash())
	if !peer.KnownTimeout(timeout.Hash()) {
		t.Error("marked timeout not reported as known")
	}
	peer.MarkSyncInfo(syncInfo.Hash())
	if !peer.KnownSyncInfo(syncInfo.Hash()) {
		t.Error("marked sync info not reported as known")
	}
}

// TestPeerCloseIsIdempotent verifies that Close can be called repeatedly and from
// concurrent goroutines without panicking on a double close of term.
func TestPeerCloseIsIdempotent(t *testing.T) {
	app, net := p2p.MsgPipe()
	defer app.Close()

	var id enode.ID
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatalf("failed to generate random peer id: %v", err)
	}
	peer := NewPeer(XDC100, p2p.NewPeer(id, "close", nil), net, func(common.Hash) *types.Transaction { return nil })

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Go(peer.Close)
	}
	peer.Close()
	wg.Wait()

	// All concurrent calls returned without panic, so idempotency holds. As a
	// final sanity check, the first call must have closed term; the default
	// case fails fast if Close ever stops closing it.
	select {
	case <-peer.term:
	default:
		t.Fatal("Close did not terminate the peer")
	}
}

// waitBroadcasters blocks until the peer's broadcast goroutines have exited, or
// fails the test if they are still running after the grace period.
func waitBroadcasters(t *testing.T, wg *sync.WaitGroup) {
	t.Helper()
	const gracePeriod = 2 * time.Second

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(gracePeriod):
		t.Fatalf("waitBroadcasters: broadcast goroutines still running after %v, want them to terminate", gracePeriod)
	}
}

// TestCloseTerminatesBroadcasters ensures that Close stops the peer's broadcast
// goroutines, which only exit via the termination channel (or a send error).
func TestCloseTerminatesBroadcasters(t *testing.T) {
	app, net := p2p.MsgPipe()
	defer app.Close()

	var id enode.ID
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatalf("failed to generate random peer id: %v", err)
	}
	// Use XDC165 so the transaction announcer is started too; the wait below then
	// covers all three broadcast goroutines.
	peer := NewPeer(XDC165, p2p.NewPeer(id, "close", nil), net, func(common.Hash) *types.Transaction { return nil })

	peer.Close()
	waitBroadcasters(t, &peer.broadcastWg)
}

// countingMsgWriter wraps a p2p.MsgReadWriter and counts every write attempt,
// allowing tests to assert that a peer stops sending after a network error.
type countingMsgWriter struct {
	p2p.MsgReadWriter
	writes atomic.Int32
}

func (c *countingMsgWriter) WriteMsg(msg p2p.Msg) error {
	c.writes.Add(1)
	return c.MsgReadWriter.WriteMsg(msg)
}

// newBroadcastTestPeer assembles a peer whose network connection is already
// broken, so the first send from any broadcast loop fails. The returned
// terminate function closes the peer exactly once and is safe to call from
// anywhere, including t.Cleanup and the test body itself.
func newBroadcastTestPeer(t *testing.T, name string) (*Peer, *types.Transaction, *countingMsgWriter, func()) {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}
	tx, err := types.SignTx(types.NewTransaction(0, common.Address{}, big.NewInt(1), 100000, big.NewInt(1), nil), types.HomesteadSigner{}, key)
	if err != nil {
		t.Fatalf("failed to sign test transaction: %v", err)
	}
	app, net := p2p.MsgPipe()
	var id enode.ID
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatalf("failed to generate random peer id: %v", err)
	}
	counter := &countingMsgWriter{MsgReadWriter: net}
	peer := NewPeer(XDC100, p2p.NewPeer(id, name, nil), counter, func(common.Hash) *types.Transaction { return tx })
	terminate := peer.Close
	t.Cleanup(terminate)
	app.Close()
	return peer, tx, counter, terminate
}

// runDrainCheck performs repeated asynchronous sends through send and fails the
// test if any of them blocks, which would indicate that the peer's broadcast
// loop stopped draining its queue after a send error. On a blocked send it
// terminates the peer first, so the stuck sender unblocks via the termination
// channel and cannot leak after the test has aborted.
func runDrainCheck(t *testing.T, what string, send, terminate func()) {
	t.Helper()
	for i := 0; i < 50; i++ {
		sent := make(chan struct{})
		go func() {
			defer close(sent)
			send()
		}()
		select {
		case <-sent:
		case <-time.After(5 * time.Second):
			terminate()
			// The blocked sender unblocks via the termination channel; join it
			// before failing so the failure path cannot leak the goroutine.
			<-sent
			t.Fatalf("%s blocked on attempt %d: the peer stopped draining after a send error", what, i)
		}
	}
}

// waitForWrites waits until the wrapped connection has seen its first write
// attempt and reports the total number of attempts observed so far. The
// broadcast loops launch at most one sender at a time and never start a new one
// after a failure, so once the count reaches one it must never grow again. The
// test fails if no write attempt is observed before the deadline.
func waitForWrites(t *testing.T, counter *countingMsgWriter) int32 {
	t.Helper()
	const deadline = 5 * time.Second

	timeout := time.NewTimer(deadline)
	defer timeout.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for counter.writes.Load() == 0 {
		select {
		case <-timeout.C:
			t.Fatalf("waitForWrites: no write attempt observed within %v, want 1", deadline)
		case <-ticker.C:
		}
	}
	return counter.writes.Load()
}

// TestBroadcastTransactionsKeepsDrainingAfterSendFailure reproduces the mainnet
// freeze: the broadcaster used to return on the first send error, leaving the
// transaction queue without a reader, so every later AsyncSendTransactions
// blocked forever and took txBroadcastLoop, and through it the transaction pool,
// down with it.
func TestBroadcastTransactionsKeepsDrainingAfterSendFailure(t *testing.T) {
	peer, tx, counter, terminate := newBroadcastTestPeer(t, "broadcaster")

	runDrainCheck(t, "AsyncSendTransactions", func() { peer.AsyncSendTransactions([]common.Hash{tx.Hash()}) }, terminate)

	// The connection is broken, so the very first broadcast fails. After that the
	// broadcaster must only drain its queue and never attempt another write.
	if got := waitForWrites(t, counter); got != 1 {
		t.Fatalf("write attempts after failed send: got %d, want 1", got)
	}
	// Extra batches still have to drain without blocking or resending.
	runDrainCheck(t, "AsyncSendTransactions after failure", func() { peer.AsyncSendTransactions([]common.Hash{tx.Hash()}) }, terminate)
	if got := counter.writes.Load(); got != 1 {
		t.Fatalf("write attempts after further drain: got %d, want 1", got)
	}
}

// TestAnnounceTransactionsKeepsDrainingAfterSendFailure is the announce-side
// counterpart: the announcer has to keep servicing its queue until the peer is
// closed, otherwise AsyncSendPooledTransactionHashes blocks forever.
func TestAnnounceTransactionsKeepsDrainingAfterSendFailure(t *testing.T) {
	app, net := p2p.MsgPipe()
	var id enode.ID
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatalf("failed to generate random peer id: %v", err)
	}
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}
	tx, err := types.SignTx(types.NewTransaction(0, common.Address{}, big.NewInt(1), 100000, big.NewInt(1), nil), types.HomesteadSigner{}, key)
	if err != nil {
		t.Fatalf("failed to sign test transaction: %v", err)
	}
	counter := &countingMsgWriter{MsgReadWriter: net}
	// The announcer only runs for xdc/165, so this peer must be created on that
	// version.
	peer := NewPeer(XDC165, p2p.NewPeer(id, "announcer", nil), counter, func(common.Hash) *types.Transaction { return tx })
	terminate := peer.Close
	t.Cleanup(terminate)
	app.Close()

	runDrainCheck(t, "AsyncSendPooledTransactionHashes", func() { peer.AsyncSendPooledTransactionHashes([]common.Hash{tx.Hash()}) }, terminate)

	// The connection is broken, so the very first announcement fails. After that
	// the announcer must only drain its queue and never attempt another write.
	if got := waitForWrites(t, counter); got != 1 {
		t.Fatalf("write attempts after failed send: got %d, want 1", got)
	}
	// Extra batches still have to drain without blocking or resending.
	runDrainCheck(t, "AsyncSendPooledTransactionHashes after failure", func() { peer.AsyncSendPooledTransactionHashes([]common.Hash{tx.Hash()}) }, terminate)
	if got := counter.writes.Load(); got != 1 {
		t.Fatalf("write attempts after further drain: got %d, want 1", got)
	}
}

// mustEncode RLP-encodes the given value or fails the test.
func mustEncode(t *testing.T, v interface{}) []byte {
	t.Helper()

	encoded, err := rlp.EncodeToBytes(v)
	if err != nil {
		t.Fatalf("failed to encode payload: %v", err)
	}
	return encoded
}

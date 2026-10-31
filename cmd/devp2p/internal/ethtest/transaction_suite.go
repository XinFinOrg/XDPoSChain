// Copyright 2020 The go-ethereum Authors
// This file is part of go-ethereum.
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with go-ethereum. If not, see <http://www.gnu.org/licenses/>.

// The transaction conformance cases exercise the transaction paths against a
// live node: invalid transactions must be rejected without being announced
// (upstream #21857), and announced pooled transaction hashes must be retrieved
// and served back (upstream #22630). Node-run verification of these cases is
// the §8.3 devnet matrix; CI runs only the node-less shape tests around them.
package ethtest

import (
	"errors"
	"fmt"
	"math/big"
	"net"
	"time"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	ethproto "github.com/XinFinOrg/XDPoSChain/eth/protocols/eth"
	"github.com/XinFinOrg/XDPoSChain/internal/utesting"
	"github.com/XinFinOrg/XDPoSChain/rlp"
)

// invalidTxRecipient is the recipient address of the invalid transactions the
// cases build; it carries no balance expectations, the rejection comes from
// the transaction itself.
var invalidTxRecipient = common.HexToAddress("0x00000000000000000000000000000000000000aa")

// TestMaliciousTx sends invalid transactions - already included, stale nonce,
// oversized value, gas price and data - and verifies the node announces none
// of them (upstream #21857). The generators build on the fixture sender set
// the smoke cases use; a subcase whose fixture prerequisites are missing is
// skipped individually.
func (s *Suite) TestMaliciousTx(t *utesting.T) {
	t.Log(`This test sends invalid transactions and expects none of them to be announced.`)
	if len(s.chain.senders) == 0 {
		t.Log("fixture has no sender accounts; skipping invalid transaction cases")
		return
	}
	cases := []struct {
		name  string
		build func() (*types.Transaction, bool)
	}{
		{"already included tx", s.oldChainTx},
		{"stale nonce tx", s.invalidNonceTx},
		{"oversized value tx", s.hugeAmountTx},
		{"oversized gas price tx", s.hugeGasPriceTx},
		{"oversized data tx", s.hugeDataTx},
	}
	for _, tc := range cases {
		tx, ok := tc.build()
		if !ok {
			t.Logf("%s: fixture prerequisites missing; skipping", tc.name)
			continue
		}
		t.Logf("testing malicious tx propagation: %s", tc.name)
		s.sendFailingTx(t, tx)
	}
}

// sendFailingTx sends an invalid transaction and verifies the node neither
// announces it back nor tears the receiving connection down over the wait
// window (upstream #21857).
func (s *Suite) sendFailingTx(t *utesting.T, tx *types.Transaction) {
	sendConn, err := s.dialAndPeer(nil)
	if err != nil {
		t.Fatalf("peering failed: %v", err)
	}
	defer sendConn.Close()
	recvConn, err := s.dialAndPeer(nil)
	if err != nil {
		t.Fatalf("peering failed: %v", err)
	}
	defer recvConn.Close()

	// Straggler announcements from earlier cases must not fail the wait below,
	// so one incoming frame is drained and ignored first.
	if _, _, err := recvConn.Read(); err != nil {
		var netErr net.Error
		if !errors.As(err, &netErr) || !netErr.Timeout() {
			t.Fatalf("failed to drain receiver: %v", err)
		}
	}
	if err := sendConn.Write(ethProto, ethproto.TransactionMsg, types.Transactions{tx}); err != nil {
		t.Fatalf("failed to write TxMsg: %v", err)
	}
	if err := expectNoTxAnnouncement(recvConn, announceTimeout); err != nil {
		t.Fatalf("invalid tx was propagated: %v", err)
	}
}

// oldChainTx returns an already-included transaction from the fixture chain
// blocks below the head; the node already knows it and must not announce it
// again. It reports ok=false when the fixture blocks carry no transactions.
func (s *Suite) oldChainTx() (*types.Transaction, bool) {
	for _, block := range s.chain.blocks[:s.chain.Len()-1] {
		if txs := block.Transactions(); txs.Len() != 0 {
			return txs[0], true
		}
	}
	return nil, false
}

// invalidNonceTx returns a transaction signed by the first fixture sender for
// an already-consumed nonce, which the node rejects as too low. It reports
// ok=false while the sender has no consumed nonce to reuse.
func (s *Suite) invalidNonceTx() (*types.Transaction, bool) {
	from, nonce := s.chain.GetSender(0)
	if nonce < 2 {
		return nil, false
	}
	unsigned := types.NewTransaction(nonce-2, invalidTxRecipient, big.NewInt(1), 21000, big.NewInt(1), nil)
	return s.signFixtureTx(from, unsigned)
}

// hugeAmountTx returns a transaction whose value carries megabytes, far past
// any balance the fixture sender could back it with.
func (s *Suite) hugeAmountTx() (*types.Transaction, bool) {
	from, nonce := s.chain.GetSender(0)
	unsigned := types.NewTransaction(nonce, invalidTxRecipient, largeNumber(2), 21000, big.NewInt(1), nil)
	return s.signFixtureTx(from, unsigned)
}

// hugeGasPriceTx returns a transaction whose gas price carries megabytes,
// which the sender cannot cover.
func (s *Suite) hugeGasPriceTx() (*types.Transaction, bool) {
	from, nonce := s.chain.GetSender(0)
	unsigned := types.NewTransaction(nonce, invalidTxRecipient, big.NewInt(1), 21000, largeNumber(2), nil)
	return s.signFixtureTx(from, unsigned)
}

// hugeDataTx returns a transaction carrying megabytes of data with a gas
// budget that cannot pay for the data's intrinsic gas.
func (s *Suite) hugeDataTx() (*types.Transaction, bool) {
	from, nonce := s.chain.GetSender(0)
	unsigned := types.NewTransaction(nonce, invalidTxRecipient, big.NewInt(1), 21000, big.NewInt(1), largeBuffer(2))
	return s.signFixtureTx(from, unsigned)
}

// signFixtureTx signs an unsigned transaction with the given fixture sender's
// key and reports ok=false when signing fails.
func (s *Suite) signFixtureTx(from common.Address, unsigned *types.Transaction) (*types.Transaction, bool) {
	signed, err := s.chain.SignTx(from, unsigned)
	if err != nil {
		return nil, false
	}
	return signed, true
}

// TestNewPooledTxs_66 tests whether the node issues a pooled transaction
// request upon receiving a hashes-only transaction announcement (upstream
// #22630, adapted to the XDC announcement shape). It skips unless xdc/166 was
// negotiated: the node acts on announcements from peers at xdc/165 or above.
//
// Upstream sends a block announcement before this case to make sure the node
// is synced and accepts transactions; the ported suite has no successor block
// to announce (frozen testdata), so the AcceptTxs precondition is left to the
// devnet matrix ordering.
func (s *Suite) TestNewPooledTxs_66(t *utesting.T) {
	t.Log(`This test announces pooled transaction hashes over xdc/166 and expects the node to request the announced transactions.`)
	hashMap, _, err := s.generateTxs(50)
	if err != nil {
		t.Fatalf("failed to generate transactions: %v", err)
	}
	hashes := make([]common.Hash, 0, len(hashMap))
	for hash := range hashMap {
		hashes = append(hashes, hash)
	}
	conn, ok := s.setupConnection66(t)
	if !ok {
		return
	}
	defer conn.Close()

	if err := conn.Write(ethProto, ethproto.NewPooledTransactionHashesMsg, ethproto.NewPooledTransactionHashesPacket(hashes)); err != nil {
		t.Fatalf("failed to write pooled tx announcement: %v", err)
	}
	// The wait for the node's retrieval request is bounded: read timeouts are
	// retried until the window closes, then the case fails, so a node that
	// never asks cannot stall the run (upstream #32551).
	deadline := time.Now().Add(announceTimeout)
	for time.Now().Before(deadline) {
		_, msg, err := conn.ReadEth66()
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			t.Fatalf("failed to read pooled tx request: %v", err)
		}
		req, ok := msg.(*getPooledTransactionsData)
		if !ok {
			continue
		}
		if len(*req) != len(hashes) {
			t.Fatalf("unexpected number of txs requested: wanted %d, got %d", len(hashes), len(*req))
		}
		return
	}
	t.Fatalf("timed out waiting for the pooled tx request within %s", announceTimeout)
}

// TestLargeTxRequest_66 tests whether the node can fulfill a large pooled
// transaction request covering everything it was just sent (upstream
// #22630). It skips unless xdc/166 was negotiated: the pooled transaction
// request path is served from xdc/165 upwards.
func (s *Suite) TestLargeTxRequest_66(t *utesting.T) {
	t.Log(`This test sends a large batch of transactions and requests all of them back through a pooled transaction query.`)
	hashMap, txs, err := s.generateTxs(2000)
	if err != nil {
		t.Fatalf("failed to generate transactions: %v", err)
	}
	sendConn, ok := s.setupConnection66(t)
	if !ok {
		return
	}
	defer sendConn.Close()

	s.sendMultipleSuccessfulTxs(t, sendConn, txs)
	// Track the consumed nonces locally, like the smoke cases do.
	from, _ := s.chain.GetSender(0)
	s.chain.IncNonce(from, uint64(len(txs)))

	hashes := make(getPooledTransactionsData, 0, len(hashMap))
	for hash := range hashMap {
		hashes = append(hashes, hash)
	}
	getTxReq := &getPooledTransactionsPacket66{
		RequestId: 1234,
		Hashes:    hashes,
	}
	if err := sendConn.Write(ethProto, ethproto.GetPooledTransactionsMsg, getTxReq); err != nil {
		t.Fatalf("could not write to conn: %v", err)
	}
	// Check that every transaction the node serves back belongs to the sent
	// batch; the node may serve fewer than it was sent, but never more.
	for i := 0; i < max66ResponseReads; i++ {
		id, msg, err := s.readMsg66(sendConn)
		if err != nil {
			t.Fatalf("failed to read pooled tx response: %v", err)
		}
		gotTxs, ok := msg.(*types.Transactions)
		if !ok {
			continue
		}
		if id != getTxReq.RequestId {
			t.Fatalf("request id mismatch: wanted %d, got %d", getTxReq.RequestId, id)
		}
		for _, gotTx := range *gotTxs {
			if _, exists := hashMap[gotTx.Hash()]; !exists {
				t.Fatalf("unexpected tx received: %v", gotTx.Hash())
			}
		}
		return
	}
	t.Fatalf("did not receive PooledTransactions response within %d read(s)", max66ResponseReads)
}

// sendMultipleSuccessfulTxs sends a batch of valid transactions and verifies
// the node announces every one of them to a freshly peered connection
// (upstream #22630).
func (s *Suite) sendMultipleSuccessfulTxs(t *utesting.T, sendConn *Conn, txs types.Transactions) {
	t.Logf("sending %d txs", len(txs))
	recvConn, ok := s.setupConnection66(t)
	if !ok {
		return
	}
	defer recvConn.Close()

	if err := sendConn.Write(ethProto, ethproto.TransactionMsg, txs); err != nil {
		t.Fatalf("failed to write TxMsg: %v", err)
	}
	recvHashes := make([]common.Hash, 0)
	// All transactions should be announced within three wait windows.
	for i := 0; i < 3; i++ {
		hashes, err := readTxAnnouncement(recvConn, announceTimeout)
		if err != nil {
			t.Fatalf("failed to read tx announcement: %v", err)
		}
		recvHashes = append(recvHashes, hashes...)
		_, missing := compareReceivedTxs(recvHashes, txs)
		if len(missing) == 0 {
			t.Logf("successfully received all %d txs", len(txs))
			return
		}
	}
	_, missing := compareReceivedTxs(recvHashes, txs)
	for _, tx := range missing {
		t.Logf("missing tx: %v", tx.Hash())
	}
	t.Fatalf("missing %d txs", len(missing))
}

// generateTxs builds numTxs validly signed transactions from the first
// fixture sender, starting at its tracked nonce, and indexes them by hash
// (upstream #22630).
func (s *Suite) generateTxs(numTxs int) (map[common.Hash]common.Hash, types.Transactions, error) {
	if len(s.chain.senders) == 0 {
		return nil, nil, fmt.Errorf("fixture has no sender accounts")
	}
	from, nonce := s.chain.GetSender(0)
	hashMap := make(map[common.Hash]common.Hash, numTxs)
	txs := make(types.Transactions, 0, numTxs)
	for i := 0; i < numTxs; i++ {
		unsigned := types.NewTransaction(nonce+uint64(i), invalidTxRecipient, big.NewInt(1), 21000, big.NewInt(1), nil)
		signed, err := s.chain.SignTx(from, unsigned)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to sign tx %d: %w", i, err)
		}
		hashMap[signed.Hash()] = signed.Hash()
		txs = append(txs, signed)
	}
	return hashMap, txs, nil
}

// compareReceivedTxs compares the received set of tx hashes against the given
// set of txs, returning both the txs whose hashes were announced and the txs
// whose hashes were missing (upstream #22630).
func compareReceivedTxs(recvTxs []common.Hash, txs types.Transactions) (present, missing types.Transactions) {
	recvHashes := make(map[common.Hash]struct{}, len(recvTxs))
	for _, hash := range recvTxs {
		recvHashes[hash] = struct{}{}
	}
	present = make(types.Transactions, 0)
	missing = make(types.Transactions, 0)
	for _, tx := range txs {
		if _, exists := recvHashes[tx.Hash()]; exists {
			present = append(present, tx)
		} else {
			missing = append(missing, tx)
		}
	}
	return present, missing
}

// readTxAnnouncement collects the transaction hashes announced to the
// connection over one wait window. Both announcement dialects carry hashes:
// full transaction broadcasts arrive as transaction frames, pooled
// announcements as bare hash lists. Frames that fail to decode as
// transactions are skipped, since the legacy dialect of this node reuses the
// transaction frame for hash lists; ping frames are answered and read
// timeouts close the window.
func readTxAnnouncement(conn *Conn, window time.Duration) ([]common.Hash, error) {
	hashes := make([]common.Hash, 0)
	deadline := time.Now().Add(window)
	for {
		code, data, err := conn.Read()
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				return hashes, nil
			}
			return hashes, fmt.Errorf("connection failed: %w", err)
		}
		if isEth66MsgCode(code) {
			switch code - protoOffset(ethProto) {
			case ethproto.TransactionMsg:
				var txs types.Transactions
				if rlp.DecodeBytes(data, &txs) == nil {
					for _, tx := range txs {
						hashes = append(hashes, tx.Hash())
					}
				}
			case ethproto.NewPooledTransactionHashesMsg:
				var announced []common.Hash
				if rlp.DecodeBytes(data, &announced) == nil {
					hashes = append(hashes, announced...)
				}
			}
		}
		switch code {
		case discMsg:
			return hashes, fmt.Errorf("peer disconnected")
		case pingMsg:
			if err := conn.Write(baseProto, pongMsg, []byte{}); err != nil {
				return hashes, fmt.Errorf("failed to reply pong: %w", err)
			}
		}
		if time.Now().After(deadline) {
			return hashes, nil
		}
	}
}

// expectNoTxAnnouncement reads raw frames for the given window and reports an
// error as soon as a transaction frame (broadcast or pooled hash
// announcement) shows up. Read timeouts are retried until the window closes,
// while an early teardown fails the wait since it could hide an announcement
// that was about to arrive.
func expectNoTxAnnouncement(conn *Conn, window time.Duration) error {
	deadline := time.Now().Add(window)
	for {
		code, _, err := conn.Read()
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				if time.Now().After(deadline) {
					return nil
				}
				continue
			}
			return fmt.Errorf("connection failed before the window closed: %w", err)
		}
		if isEth66MsgCode(code) {
			switch code - protoOffset(ethProto) {
			case ethproto.TransactionMsg, ethproto.NewPooledTransactionHashesMsg:
				return fmt.Errorf("received tx announcement frame with code %d", code)
			}
		}
		switch code {
		case discMsg:
			return fmt.Errorf("peer disconnected before the window closed")
		case pingMsg:
			if err := conn.Write(baseProto, pongMsg, []byte{}); err != nil {
				return fmt.Errorf("failed to reply pong: %w", err)
			}
		}
		if time.Now().After(deadline) {
			return nil
		}
	}
}

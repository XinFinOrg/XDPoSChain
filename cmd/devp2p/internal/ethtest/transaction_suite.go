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

package ethtest

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"time"

	"github.com/XinFinOrg/XDPoSChain/crypto"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	ethproto "github.com/XinFinOrg/XDPoSChain/eth/protocols/eth"
	"github.com/XinFinOrg/XDPoSChain/internal/utesting"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/XinFinOrg/XDPoSChain/rlp"
)

// Carries no balance expectations; the rejection comes from the transaction
// itself
var invalidTxRecipient = common.HexToAddress("0x00000000000000000000000000000000000000aa")

// TestMaliciousTx anchors on rejections the pool actually enforces (#21857).
// The upstream huge-value and huge-gas-price forms do not hold on XDC: the pool
// accepts them and defers balance and price sanity to execution
func (s *Suite) TestMaliciousTx(t *utesting.T) {
	t.Log(`This test sends invalid transactions and expects none of them to be announced.`)
	var (
		sign       func(tx *types.Transaction) (*types.Transaction, error)
		nonceStart uint64
		live       bool
	)
	if mk, ok := matrixSender(); ok {
		signer := types.LatestSignerForChainID(s.chain.config.ChainID)
		sign = func(tx *types.Transaction) (*types.Transaction, error) {
			return types.SignTx(tx, signer, mk)
		}
		nonceStart = matrixNonce()
		live = true
	} else {
		if len(s.chain.senders) == 0 {
			t.Log("fixture has no sender accounts; skipping invalid transaction cases")
			return
		}
		from, nonce := s.chain.GetSender(0)
		sign = func(tx *types.Transaction) (*types.Transaction, error) {
			return s.chain.SignTx(from, tx)
		}
		nonceStart = nonce
	}
	build := func(name string, mutate func(tx *types.Transaction) *types.Transaction) (*types.Transaction, bool) {
		unsigned := types.NewTransaction(nonceStart, invalidTxRecipient, big.NewInt(1), 100000, big.NewInt(1), nil)
		unsigned = mutate(unsigned)
		signed, err := sign(unsigned)
		if err != nil {
			t.Logf("%s: signing failed (%v); skipping", name, err)
			return nil, false
		}
		return signed, true
	}
	cases := []struct {
		name  string
		build func() (*types.Transaction, bool)
	}{
		{"underpriced tx (below the pool minimum)", func() (*types.Transaction, bool) {
			return build("underpriced tx", func(tx *types.Transaction) *types.Transaction {
				return types.NewTransaction(tx.Nonce(), invalidTxRecipient, big.NewInt(1), 100000, big.NewInt(1), nil)
			})
		}},
		{"intrinsic gas too low", func() (*types.Transaction, bool) {
			return build("intrinsic gas tx", func(tx *types.Transaction) *types.Transaction {
				return types.NewTransaction(tx.Nonce(), invalidTxRecipient, big.NewInt(1), 21000, big.NewInt(1), make([]byte, 400))
			})
		}},
		{"reused nonce tx", func() (*types.Transaction, bool) {
			if !live || nonceStart == 0 {
				return nil, false
			}
			return build("reused nonce tx", func(tx *types.Transaction) *types.Transaction {
				return types.NewTransaction(tx.Nonce(), invalidTxRecipient, big.NewInt(1), 100000, big.NewInt(1), []byte("reused"))
			})
		}},
	}
	for _, tc := range cases {
		tx, ok := tc.build()
		if !ok {
			t.Logf("%s: prerequisites missing; skipping", tc.name)
			continue
		}
		t.Logf("testing malicious tx propagation: %s", tc.name)
		s.sendFailingTx(t, tx)
	}
}

func (s *Suite) sendFailingTx(t *utesting.T, tx *types.Transaction) {
	sendConn, ok := s.setupConnectionXdc166(t)
	if !ok {
		return
	}
	defer sendConn.Close()
	recvConn, ok := s.setupConnectionXdc166(t)
	if !ok {
		return
	}
	defer recvConn.Close()

	// Straggler announcements from earlier cases must not fail the wait below
	if _, _, err := recvConn.Read(); err != nil {
		var netErr net.Error
		if !errors.As(err, &netErr) || !netErr.Timeout() {
			t.Fatalf("failed to drain receiver: %v", err)
		}
	}
	// From xdc/165 on there is no full-broadcast TxMsg: announce the hash and
	// serve the body on request, which must be rejected without a reply and
	// without the connection going down
	hash := tx.Hash()
	if err := sendConn.Write(ethProto, ethproto.NewPooledTransactionHashesMsg, ethproto.NewPooledTransactionHashesPacket([]common.Hash{hash})); err != nil {
		t.Fatalf("failed to write pooled tx announcement: %v", err)
	}
	deadline := time.Now().Add(announceTimeout)
	for time.Now().Before(deadline) {
		code, data, err := sendConn.Read()
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			t.Fatalf("failed to read pooled tx request: %v", err)
		}
		if !isXdc166MsgCode(code) || code-protoOffset(ethProto) != ethproto.GetPooledTransactionsMsg {
			continue
		}
		var req getPooledTransactionsPacket166
		if err := rlp.DecodeBytes(data, &req); err != nil {
			t.Fatalf("failed to decode pooled tx request: %v", err)
		}
		if err := sendConn.Write(ethProto, ethproto.PooledTransactionsMsg, &pooledTransactionsPacket166{
			RequestId: req.RequestId,
			Txs:       types.Transactions{tx},
		}); err != nil {
			t.Fatalf("failed to write pooled tx body: %v", err)
		}
		break
	}
	if err := expectNoTxAnnouncement(recvConn, announceTimeout, tx.Hash()); err != nil {
		t.Fatalf("invalid tx was propagated: %v", err)
	}
}

func (s *Suite) oldChainTx() (*types.Transaction, bool) {
	for _, block := range s.chain.blocks[:s.chain.Len()-1] {
		if txs := block.Transactions(); txs.Len() != 0 {
			return txs[0], true
		}
	}
	return nil, false
}

func (s *Suite) invalidNonceTx() (*types.Transaction, bool) {
	from, nonce := s.chain.GetSender(0)
	if nonce < 2 {
		return nil, false
	}
	unsigned := types.NewTransaction(nonce-2, invalidTxRecipient, big.NewInt(1), 21000, big.NewInt(1), nil)
	return s.signFixtureTx(from, unsigned)
}

// 2^250 wei is far past the total supply while staying tiny on the wire; a
// megabyte-scale value field would trip the message-size cap instead of the
// balance check
func (s *Suite) hugeAmountTx() (*types.Transaction, bool) {
	from, nonce := s.chain.GetSender(0)
	value := new(big.Int).Lsh(big.NewInt(1), 250)
	unsigned := types.NewTransaction(nonce, invalidTxRecipient, value, 21000, big.NewInt(1), nil)
	return s.signFixtureTx(from, unsigned)
}

func (s *Suite) hugeGasPriceTx() (*types.Transaction, bool) {
	from, nonce := s.chain.GetSender(0)
	unsigned := types.NewTransaction(nonce, invalidTxRecipient, big.NewInt(1), 21000, new(big.Int).Lsh(big.NewInt(1), 250), nil)
	return s.signFixtureTx(from, unsigned)
}

func (s *Suite) hugeDataTx() (*types.Transaction, bool) {
	from, nonce := s.chain.GetSender(0)
	unsigned := types.NewTransaction(nonce, invalidTxRecipient, big.NewInt(1), 21000, big.NewInt(1), largeBuffer(2))
	return s.signFixtureTx(from, unsigned)
}

func (s *Suite) signFixtureTx(from common.Address, unsigned *types.Transaction) (*types.Transaction, bool) {
	signed, err := s.chain.SignTx(from, unsigned)
	if err != nil {
		return nil, false
	}
	return signed, true
}

// Skips unless xdc/166 was negotiated, since the node acts on announcements
// from xdc/165 on. Upstream announces a block first to establish AcceptTxs;
// the frozen fixture has no successor block, so that precondition is left to
// the devnet matrix ordering (#22630)
func (s *Suite) TestNewPooledTxs_Xdc166(t *utesting.T) {
	t.Log(`This test announces pooled transaction hashes over xdc/166 and expects the node to request the announced transactions.`)
	hashMap, _, err := s.generateTxs(50)
	if err != nil {
		t.Fatalf("failed to generate transactions: %v", err)
	}
	hashes := make([]common.Hash, 0, len(hashMap))
	for hash := range hashMap {
		hashes = append(hashes, hash)
	}
	conn, ok := s.setupConnectionXdc166(t)
	if !ok {
		return
	}
	defer conn.Close()

	if err := conn.Write(ethProto, ethproto.NewPooledTransactionHashesMsg, ethproto.NewPooledTransactionHashesPacket(hashes)); err != nil {
		t.Fatalf("failed to write pooled tx announcement: %v", err)
	}
	// Read timeouts are retried until the window closes, so a node that never
	// asks cannot stall the run (#32551)
	deadline := time.Now().Add(announceTimeout)
	for time.Now().Before(deadline) {
		_, msg, err := conn.ReadXdc166()
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

// Reads the matrix sender nonce from MATRIX_SENDER_NONCE; the runner queries
// the chain because the nonce moves as earlier batches are mined
func matrixNonce() uint64 {
	var n uint64
	if v := os.Getenv("MATRIX_SENDER_NONCE"); v != "" {
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil {
			return n
		}
	}
	return 0
}

// Returns the funded sender override for live devnet runs (MATRIX_SENDER_KEY);
// the devnet genesis funds the matrix validator accounts, not the fixture
// senders
func matrixSender() (*ecdsa.PrivateKey, bool) {
	raw := os.Getenv("MATRIX_SENDER_KEY")
	if raw == "" {
		return nil, false
	}
	key, err := crypto.HexToECDSA(strings.TrimPrefix(raw, "0x"))
	if err != nil {
		return nil, false
	}
	return key, true
}

// Skips unless xdc/166 was negotiated; the pooled request path is served from
// xdc/165 upwards (#22630)
func (s *Suite) TestLargeTxRequest_Xdc166(t *utesting.T) {
	t.Log(`This test sends a large batch of transactions and requests all of them back through a pooled transaction query.`)
	numTxs := 2000
	var hashMap map[common.Hash]common.Hash
	var txs types.Transactions
	matrixMode := false
	if key, ok := matrixSender(); ok {
		// The legacypool account queue caps one sender at 64 non-executable
		// txs, so the live batch stays under it; the fixture world keeps the
		// upstream 2000-tx calibration
		matrixMode = true
		numTxs = 48
		nonceStart := matrixNonce()
		sender := crypto.PubkeyToAddress(key.PublicKey)
		hashMap = make(map[common.Hash]common.Hash, numTxs)
		txs = make(types.Transactions, 0, numTxs)
		signer := types.LatestSignerForChainID(s.chain.config.ChainID)
		floor := s.chainGasPriceFloor()
		for i := 0; i < numTxs; i++ {
			salt := fmt.Sprintf("matrix-salt-%d-%d", time.Now().UnixNano(), i)
			unsigned := types.NewTransaction(nonceStart+uint64(i), invalidTxRecipient, big.NewInt(1), 100000, floor, []byte(salt))
			signed, err := types.SignTx(unsigned, signer, key)
			if err != nil {
				t.Fatalf("failed to sign matrix tx %d: %v", i, err)
			}
			hashMap[signed.Hash()] = signed.Hash()
			txs = append(txs, signed)
		}
		_ = sender
	} else {
		var err error
		hashMap, txs, err = s.generateTxsFrom(1, numTxs)
		if err != nil {
			t.Fatalf("failed to generate transactions: %v", err)
		}
	}
	sendConn, ok := s.setupConnectionXdc166(t)
	if !ok {
		return
	}
	defer sendConn.Close()
	queryConn := sendConn

	if matrixMode {
		// The announcement-broadcast half cannot run here: the validators mine
		// every 2 seconds and mine the batch away before a second receiver sees
		// the window. The query phase is the case's actual assert
		hashes := make(getPooledTransactionsData, 0, len(hashMap))
		for hash := range hashMap {
			hashes = append(hashes, hash)
		}
		if err := sendConn.Write(ethProto, ethproto.NewPooledTransactionHashesMsg, ethproto.NewPooledTransactionHashesPacket(hashes)); err != nil {
			t.Fatalf("failed to write pooled tx announcement: %v", err)
		}
		byHash := make(map[common.Hash]*types.Transaction, len(txs))
		for _, tx := range txs {
			byHash[tx.Hash()] = tx
		}
		deadline := time.Now().Add(announceTimeout)
		served := false
		for time.Now().Before(deadline) && !served {
			code, data, err := sendConn.Read()
			if err != nil {
				var netErr net.Error
				if errors.As(err, &netErr) && netErr.Timeout() {
					continue
				}
				t.Fatalf("failed to read pooled tx request: %v", err)
			}
			if !isXdc166MsgCode(code) || code-protoOffset(ethProto) != ethproto.GetPooledTransactionsMsg {
				continue
			}
			var req getPooledTransactionsPacket166
			if err := rlp.DecodeBytes(data, &req); err != nil {
				t.Fatalf("failed to decode pooled tx request: %v", err)
			}
			serve := make(types.Transactions, 0, len(req.Hashes))
			for _, hash := range req.Hashes {
				if tx, ok := byHash[hash]; ok {
					serve = append(serve, tx)
				}
			}
			if err := sendConn.Write(ethProto, ethproto.PooledTransactionsMsg, &pooledTransactionsPacket166{
				RequestId: req.RequestId,
				Txs:       serve,
			}); err != nil {
				t.Fatalf("failed to write pooled tx bodies: %v", err)
			}
			served = true
		}
	} else {
		s.sendMultipleSuccessfulTxs(t, sendConn, txs)
		from, _ := s.chain.GetSender(1)
		s.chain.IncNonce(from, uint64(len(txs)))
		// The delivery windows only read recvConn, so the node's block and BFT
		// broadcasts pile up on sendConn; query over a fresh connection like
		// upstream, where they cannot consume the response wait
		queryConn, ok = s.setupConnectionXdc166(t)
		if !ok {
			return
		}
		defer queryConn.Close()
	}

	hashes := make(getPooledTransactionsData, 0, len(hashMap))
	for hash := range hashMap {
		hashes = append(hashes, hash)
	}
	getTxReq := &getPooledTransactionsPacket166{
		RequestId: 1234,
		Hashes:    hashes,
	}
	if err := queryConn.Write(ethProto, ethproto.GetPooledTransactionsMsg, getTxReq); err != nil {
		t.Fatalf("could not write to conn: %v", err)
	}
	deadline := time.Now().Add(announceTimeout)
	gotTxs, err := waitPooledTransactionsXdc166(func() (uint64, interface{}, error) {
		return s.readMsgXdc166Until(queryConn, deadline)
	}, getTxReq.RequestId, deadline)
	if err != nil {
		t.Fatalf("failed to read pooled tx response: %v", err)
	}
	// The node may serve fewer than it was sent, but never one that was not
	// part of the batch
	for _, gotTx := range gotTxs {
		if _, exists := hashMap[gotTx.Hash()]; !exists {
			t.Fatalf("unexpected tx received: %v", gotTx.Hash())
		}
	}
}

var errPooledTxDeadline = errors.New("did not receive PooledTransactions response before the deadline")

// waitPooledTransactionsXdc166 reads until the PooledTransactions response
// carrying wantID arrives, skipping unrelated frames (block, BFT and full
// transaction broadcasts) and giving up at the deadline; upstream waits for
// the target message code for the same reason
func waitPooledTransactionsXdc166(readMsg func() (uint64, interface{}, error), wantID uint64, deadline time.Time) (types.Transactions, error) {
	for {
		if !time.Now().Before(deadline) {
			return nil, errPooledTxDeadline
		}
		id, msg, err := readMsg()
		if err != nil {
			return nil, fmt.Errorf("failed to read pooled tx response: %w", err)
		}
		// A read clamped to the deadline may still deliver a frame after it
		if !time.Now().Before(deadline) {
			return nil, errPooledTxDeadline
		}
		// Only a PooledTransactions payload carries the request id; a full
		// TransactionMsg broadcast decodes to types.Transactions with a zero id
		// and must be skipped rather than fail the id check
		txs, ok := msg.(*pooledTransactionsResponse)
		if !ok {
			continue
		}
		if id != wantID {
			return nil, fmt.Errorf("request id mismatch: wanted %d, got %d", wantID, id)
		}
		return types.Transactions(*txs), nil
	}
}

// A single message cannot advance the pending nonce, so each frame stays
// within the LimitThresholdNonceInQueue admission window
const txDeliveryWindow = common.LimitThresholdNonceInQueue + 1

func txDeliveryFrames(txs types.Transactions) ([]types.Transactions, error) {
	for i := 1; i < len(txs); i++ {
		if txs[i].Nonce() != txs[i-1].Nonce()+1 {
			return nil, fmt.Errorf("tx %d breaks nonce continuity: %d after %d", i, txs[i].Nonce(), txs[i-1].Nonce())
		}
	}
	frames := make([]types.Transactions, 0, (len(txs)+txDeliveryWindow-1)/txDeliveryWindow)
	for start := 0; start < len(txs); start += txDeliveryWindow {
		frames = append(frames, txs[start:min(start+txDeliveryWindow, len(txs))])
	}
	return frames, nil
}

func writeTxFrames(conn *Conn, frames []types.Transactions) error {
	want := 0
	for _, frame := range frames {
		want += len(frame)
	}
	sent := 0
	for _, frame := range frames {
		if err := conn.Write(ethProto, ethproto.TransactionMsg, frame); err != nil {
			return fmt.Errorf("failed to send txs %d-%d: %w", sent, sent+len(frame), err)
		}
		sent += len(frame)
	}
	if sent != want {
		return fmt.Errorf("sent %d of %d txs", sent, want)
	}
	return nil
}

func sendTxFrames(conn *Conn, txs types.Transactions) error {
	frames, err := txDeliveryFrames(txs)
	if err != nil {
		return err
	}
	return writeTxFrames(conn, frames)
}

const (
	maxTxDeliveryAttempts = 3
	txDeliveryReadWindows = 3
)

// Pool promotion runs after Add returns, so a frame is rejected unless the
// previous one already advanced the pending nonce; deliver one window at a time
// and wait for that window to be observed before sending the next
func deliverTxFrames(txs types.Transactions, writeFrames func([]types.Transactions) error, readAnnouncement func(map[common.Hash]struct{}) ([]common.Hash, error)) error {
	frames, err := txDeliveryFrames(txs)
	if err != nil {
		return err
	}
	seen := make(map[common.Hash]struct{}, len(txs))
	recvHashes := make([]common.Hash, 0, len(txs))
	for i, frame := range frames {
		want := make(map[common.Hash]struct{}, len(frame))
		for _, tx := range frame {
			want[tx.Hash()] = struct{}{}
		}
		accepted := false
		for attempt := 0; attempt < maxTxDeliveryAttempts && !accepted; attempt++ {
			if err := writeFrames([]types.Transactions{frame}); err != nil {
				return err
			}
			for range txDeliveryReadWindows {
				hashes, err := readAnnouncement(want)
				if err != nil {
					return err
				}
				for _, hash := range hashes {
					if _, ok := seen[hash]; !ok {
						seen[hash] = struct{}{}
						recvHashes = append(recvHashes, hash)
					}
				}
				if hashesCover(recvHashes, want) {
					accepted = true
					break
				}
			}
		}
		if !accepted {
			return fmt.Errorf("frame %d (nonces %d-%d) not accepted after %d attempts", i, frame[0].Nonce(), frame[len(frame)-1].Nonce(), maxTxDeliveryAttempts)
		}
	}
	// Every window was observed, but keep the whole-batch assertion so a broken
	// accumulator cannot pass silently
	return checkTxCoverage(recvHashes, txs)
}

// hashesCover reports whether have contains every hash in want; an empty want
// never counts as covered, so readers without a target keep collecting until
// their own deadline
func hashesCover(have []common.Hash, want map[common.Hash]struct{}) bool {
	if len(want) == 0 {
		return false
	}
	present := make(map[common.Hash]struct{}, len(have))
	for _, hash := range have {
		present[hash] = struct{}{}
	}
	for hash := range want {
		if _, ok := present[hash]; !ok {
			return false
		}
	}
	return true
}

func checkTxCoverage(recv []common.Hash, txs types.Transactions) error {
	present, missing := compareReceivedTxs(recv, txs)
	if len(present) != len(txs) {
		return fmt.Errorf("received %d of %d txs, first missing %v", len(present), len(txs), missing[0].Hash())
	}
	return nil
}

func (s *Suite) sendMultipleSuccessfulTxs(t *utesting.T, sendConn *Conn, txs types.Transactions) {
	t.Logf("sending %d txs", len(txs))
	// The receiver must be connected before the batch: validators mine every
	// 2 seconds and mine it away before a late receiver sees the broadcast
	recvConn, ok := s.setupConnectionXdc166(t)
	if !ok {
		return
	}
	defer recvConn.Close()
	err := deliverTxFrames(txs,
		func(frames []types.Transactions) error {
			return writeTxFrames(sendConn, frames)
		},
		func(want map[common.Hash]struct{}) ([]common.Hash, error) {
			return readTxAnnouncementUntil(recvConn, announceTimeout, want)
		},
	)
	if err != nil {
		t.Fatalf("failed to deliver transactions: %v", err)
	}
	t.Logf("successfully received all %d txs", len(txs))
}

func (s *Suite) chainGasPriceFloor() *big.Int {
	pending := new(big.Int).Add(s.chain.Head().Number(), common.Big1)
	return params.GetMinGasPrice(pending, s.chain.config)
}

func (s *Suite) generateTxs(numTxs int) (map[common.Hash]common.Hash, types.Transactions, error) {
	return s.generateTxsFrom(0, numTxs)
}

func (s *Suite) generateTxsFrom(senderIdx, numTxs int) (map[common.Hash]common.Hash, types.Transactions, error) {
	if senderIdx < 0 || senderIdx >= len(s.chain.senders) {
		return nil, nil, fmt.Errorf("fixture has %d sender accounts, cannot use sender index %d", len(s.chain.senders), senderIdx)
	}
	from, nonce := s.chain.GetSender(senderIdx)
	floor := s.chainGasPriceFloor()
	hashMap := make(map[common.Hash]common.Hash, numTxs)
	txs := make(types.Transactions, 0, numTxs)
	for i := 0; i < numTxs; i++ {
		unsigned := types.NewTransaction(nonce+uint64(i), invalidTxRecipient, big.NewInt(1), 21000, floor, nil)
		signed, err := s.chain.SignTx(from, unsigned)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to sign tx %d: %w", i, err)
		}
		if signed.GasPriceIntCmp(floor) < 0 {
			return nil, nil, fmt.Errorf("tx %d priced below the chain floor %v", i, floor)
		}
		hashMap[signed.Hash()] = signed.Hash()
		txs = append(txs, signed)
	}
	return hashMap, txs, nil
}

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

// The legacy dialect of this node reuses the transaction frame for hash lists,
// so undecodable transaction frames are skipped; ping frames are answered and
// read timeouts close the window
func readTxAnnouncement(conn *Conn, window time.Duration) ([]common.Hash, error) {
	return readTxAnnouncementUntil(conn, window, nil)
}

// readTxAnnouncementUntil stops as soon as every wanted hash has arrived, so
// per-window delivery does not wait out the read timeout for each frame
func readTxAnnouncementUntil(conn *Conn, window time.Duration, want map[common.Hash]struct{}) ([]common.Hash, error) {
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
		if isXdc166MsgCode(code) {
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
			case ethproto.NewBlockMsg:
				var packet ethproto.NewBlockPacket
				if rlp.DecodeBytes(data, &packet) == nil && packet.Block != nil {
					for _, tx := range packet.Block.Transactions() {
						hashes = append(hashes, tx.Hash())
					}
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
		if hashesCover(hashes, want) {
			return hashes, nil
		}
		if time.Now().After(deadline) {
			return hashes, nil
		}
	}
}

// An early teardown fails the wait since it could hide an announcement that was
// about to arrive
func expectNoTxAnnouncement(conn *Conn, window time.Duration, watched ...common.Hash) error {
	watchedSet := make(map[common.Hash]bool, len(watched))
	for _, h := range watched {
		watchedSet[h] = true
	}
	deadline := time.Now().Add(window)
	for {
		code, data, err := conn.Read()
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
		if isXdc166MsgCode(code) {
			switch code - protoOffset(ethProto) {
			case ethproto.NewPooledTransactionHashesMsg:
				// Live networks relay unrelated transactions; only the watched
				// hash counts as propagation
				var announced []common.Hash
				if rlp.DecodeBytes(data, &announced) == nil {
					for _, h := range announced {
						if watchedSet[h] {
							return fmt.Errorf("invalid tx %s was propagated", h)
						}
					}
				}
			case ethproto.TransactionMsg:
				var txs types.Transactions
				if rlp.DecodeBytes(data, &txs) == nil {
					for _, tx := range txs {
						if watchedSet[tx.Hash()] {
							return fmt.Errorf("invalid tx %s was propagated", tx.Hash())
						}
					}
				}
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

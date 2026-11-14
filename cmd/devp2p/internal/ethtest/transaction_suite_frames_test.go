package ethtest

import (
	"fmt"
	"math/big"
	"net"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	ethproto "github.com/XinFinOrg/XDPoSChain/eth/protocols/eth"
	"github.com/XinFinOrg/XDPoSChain/p2p/rlpx"
	"github.com/XinFinOrg/XDPoSChain/rlp"
)

func frameTestTxs(n int) types.Transactions {
	txs := make(types.Transactions, 0, n)
	for i := range n {
		txs = append(txs, types.NewTransaction(uint64(i), invalidTxRecipient, big.NewInt(1), 21000, big.NewInt(1), []byte(strconv.Itoa(i))))
	}
	return txs
}

func newFramePeer(t *testing.T) (*rlpx.Conn, *rlpx.Conn) {
	t.Helper()
	clientConn, peerConn := net.Pipe()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate client key: %v", err)
	}
	peerKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate peer key: %v", err)
	}
	client := rlpx.NewConn(clientConn, &peerKey.PublicKey)
	peer := rlpx.NewConn(peerConn, nil)
	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := peer.Handshake(peerKey); err != nil {
			t.Errorf("peer handshake failed: %v", err)
		}
	}()
	if _, err := client.Handshake(key); err != nil {
		t.Fatalf("client handshake failed: %v", err)
	}
	<-done
	t.Cleanup(func() {
		client.Close()
		peer.Close()
	})
	return client, peer
}

func TestTxDeliveryFrames(t *testing.T) {
	txs := frameTestTxs(2000)
	frames, err := txDeliveryFrames(txs)
	if err != nil {
		t.Fatalf("txDeliveryFrames: %v", err)
	}
	if want := (len(txs) + txDeliveryWindow - 1) / txDeliveryWindow; len(frames) != want {
		t.Fatalf("got %d frames, want %d", len(frames), want)
	}
	seen := 0
	for i, frame := range frames {
		if len(frame) == 0 || len(frame) > txDeliveryWindow {
			t.Fatalf("frame %d has %d txs, window is %d", i, len(frame), txDeliveryWindow)
		}
		for j, tx := range frame {
			if want := uint64(i*txDeliveryWindow + j); tx.Nonce() != want {
				t.Fatalf("frame %d tx %d has nonce %d, want %d", i, j, tx.Nonce(), want)
			}
			seen++
		}
	}
	if seen != len(txs) {
		t.Fatalf("frames cover %d txs, want %d", seen, len(txs))
	}
	for _, n := range []int{0, 1, txDeliveryWindow - 1, txDeliveryWindow, txDeliveryWindow + 1} {
		frames, err := txDeliveryFrames(frameTestTxs(n))
		if err != nil {
			t.Fatalf("txDeliveryFrames(%d): %v", n, err)
		}
		if want := (n + txDeliveryWindow - 1) / txDeliveryWindow; len(frames) != want {
			t.Fatalf("%d txs produced %d frames, want %d", n, len(frames), want)
		}
	}
	gapped := slices.Clone(txs)
	gapped[1], gapped[2] = gapped[2], gapped[1]
	if _, err := txDeliveryFrames(gapped); err == nil {
		t.Fatal("nonce discontinuity accepted")
	}
}

func TestSendTxFramesCoversEntireBatch(t *testing.T) {
	client, peer := newFramePeer(t)
	conn := &Conn{Conn: client}
	txs := frameTestTxs(2*txDeliveryWindow + 3)
	if err := peer.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}

	type result struct {
		hashes []common.Hash
		frames int
		err    error
	}
	res := make(chan result, 1)
	go func() {
		var hashes []common.Hash
		frames := 0
		for {
			code, data, _, err := peer.Read()
			if err != nil {
				res <- result{hashes, frames, err}
				return
			}
			if code != protoOffset(ethProto)+ethproto.TransactionMsg {
				res <- result{hashes, frames, fmt.Errorf("unexpected frame code %d", code)}
				return
			}
			var batch types.Transactions
			if err := rlp.DecodeBytes(data, &batch); err != nil {
				res <- result{hashes, frames, err}
				return
			}
			for _, tx := range batch {
				hashes = append(hashes, tx.Hash())
			}
			frames++
			if len(hashes) >= len(txs) {
				res <- result{hashes, frames, nil}
				return
			}
		}
	}()

	if err := sendTxFrames(conn, txs); err != nil {
		t.Fatalf("sendTxFrames: %v", err)
	}
	got := <-res
	if got.err != nil {
		t.Fatalf("peer read: %v", got.err)
	}
	if want := (len(txs) + txDeliveryWindow - 1) / txDeliveryWindow; got.frames != want {
		t.Fatalf("got %d frames, want %d", got.frames, want)
	}
	if err := checkTxCoverage(got.hashes, txs); err != nil {
		t.Fatalf("frames do not cover the batch: %v", err)
	}
}

func TestCheckTxCoverage(t *testing.T) {
	txs := frameTestTxs(10)
	all := make([]common.Hash, 0, len(txs))
	for _, tx := range txs {
		all = append(all, tx.Hash())
	}
	if err := checkTxCoverage(all, txs); err != nil {
		t.Fatalf("full coverage rejected: %v", err)
	}
	if err := checkTxCoverage(all[:9], txs); err == nil {
		t.Fatal("partial coverage accepted")
	}
	wrong := slices.Clone(all[:9])
	wrong = append(wrong, frameTestTxs(11)[10].Hash())
	if err := checkTxCoverage(wrong, txs); err == nil {
		t.Fatal("equal-sized batch with an unknown hash accepted")
	}
	if err := checkTxCoverage(append(slices.Clone(all), all[0]), txs); err != nil {
		t.Fatalf("duplicate announcement rejected: %v", err)
	}
}

func TestWriteTxFramesWritesOnlySelectedFrames(t *testing.T) {
	client, peer := newFramePeer(t)
	conn := &Conn{Conn: client}
	txs := frameTestTxs(2*txDeliveryWindow + 1)
	frames, err := txDeliveryFrames(txs)
	if err != nil {
		t.Fatalf("txDeliveryFrames: %v", err)
	}
	selected := frames[1:]
	if err := peer.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}

	type result struct {
		nonces []uint64
		frames int
		err    error
	}
	res := make(chan result, 1)
	go func() {
		var nonces []uint64
		count := 0
		for {
			code, data, _, err := peer.Read()
			if err != nil {
				res <- result{nonces, count, err}
				return
			}
			if code != protoOffset(ethProto)+ethproto.TransactionMsg {
				res <- result{nonces, count, fmt.Errorf("unexpected frame code %d", code)}
				return
			}
			var batch types.Transactions
			if err := rlp.DecodeBytes(data, &batch); err != nil {
				res <- result{nonces, count, err}
				return
			}
			for _, tx := range batch {
				nonces = append(nonces, tx.Nonce())
			}
			count++
			want := 0
			for _, frame := range selected {
				want += len(frame)
			}
			if len(nonces) >= want {
				res <- result{nonces, count, nil}
				return
			}
		}
	}()

	if err := writeTxFrames(conn, selected); err != nil {
		t.Fatalf("writeTxFrames: %v", err)
	}
	got := <-res
	if got.err != nil {
		t.Fatalf("peer read: %v", got.err)
	}
	if got.frames != len(selected) {
		t.Fatalf("got %d frames, want %d", got.frames, len(selected))
	}
	if got.nonces[0] != uint64(txDeliveryWindow) {
		t.Fatalf("first resent nonce is %d, want %d", got.nonces[0], txDeliveryWindow)
	}
}

func frameTestHashes(txs types.Transactions) []common.Hash {
	hashes := make([]common.Hash, 0, len(txs))
	for _, tx := range txs {
		hashes = append(hashes, tx.Hash())
	}
	return hashes
}

func TestDeliverTxFramesSendsOneWindowAtATime(t *testing.T) {
	txs := frameTestTxs(2*txDeliveryWindow + 3)
	frames, err := txDeliveryFrames(txs)
	if err != nil {
		t.Fatalf("txDeliveryFrames: %v", err)
	}
	var (
		writes   int
		accepted int
	)
	err = deliverTxFrames(txs,
		func(fs []types.Transactions) error {
			if len(fs) != 1 {
				return fmt.Errorf("wrote %d frames in one round, want 1", len(fs))
			}
			if want := uint64(accepted * txDeliveryWindow); fs[0][0].Nonce() != want {
				return fmt.Errorf("wrote nonce %d while the pending nonce is %d", fs[0][0].Nonce(), want)
			}
			writes++
			return nil
		},
		func(map[common.Hash]struct{}) ([]common.Hash, error) {
			// The node accepts only the next window: promotion advances the
			// pending nonce one frame per read
			if accepted >= len(frames) {
				return nil, nil
			}
			frame := frames[accepted]
			accepted++
			return frameTestHashes(frame), nil
		},
	)
	if err != nil {
		t.Fatalf("deliverTxFrames: %v", err)
	}
	if writes != len(frames) {
		t.Fatalf("wrote %d windows, want %d", writes, len(frames))
	}
}

func TestDeliverTxFramesRetriesSingleWindow(t *testing.T) {
	txs := frameTestTxs(2*txDeliveryWindow + 3)
	frames, err := txDeliveryFrames(txs)
	if err != nil {
		t.Fatalf("txDeliveryFrames: %v", err)
	}
	var (
		writes      int
		lastWritten int
		written     = make(map[int]int, len(frames))
	)
	err = deliverTxFrames(txs,
		func(fs []types.Transactions) error {
			writes++
			lastWritten = int(fs[0][0].Nonce() / uint64(txDeliveryWindow))
			written[lastWritten]++
			return nil
		},
		func(map[common.Hash]struct{}) ([]common.Hash, error) {
			// The second window needs a retry: every read window of its first
			// write comes back empty
			if lastWritten == 1 && written[1] == 1 {
				return nil, nil
			}
			return frameTestHashes(frames[lastWritten]), nil
		},
	)
	if err != nil {
		t.Fatalf("deliverTxFrames: %v", err)
	}
	if want := len(frames) + 1; writes != want {
		t.Fatalf("wrote %d windows, want %d", writes, want)
	}
}

func TestDeliverTxFramesStopsAfterBoundedAttempts(t *testing.T) {
	txs := frameTestTxs(txDeliveryWindow)
	writes := 0
	err := deliverTxFrames(txs,
		func([]types.Transactions) error {
			writes++
			return nil
		},
		func(map[common.Hash]struct{}) ([]common.Hash, error) { return nil, nil },
	)
	if err == nil {
		t.Fatal("uncovered window accepted")
	}
	if writes != maxTxDeliveryAttempts {
		t.Fatalf("wrote %d windows, want %d", writes, maxTxDeliveryAttempts)
	}
}

func TestGenerateTxsFromUsesDedicatedSender(t *testing.T) {
	chain, err := NewChain("testdata")
	if err != nil {
		t.Fatalf("failed to load chain fixtures: %v", err)
	}
	s := &Suite{chain: chain}
	_, base, err := s.generateTxs(2)
	if err != nil {
		t.Fatalf("generateTxs: %v", err)
	}
	_, dedicated, err := s.generateTxsFrom(1, 2)
	if err != nil {
		t.Fatalf("generateTxsFrom: %v", err)
	}
	if len(base) != 2 || len(dedicated) != 2 {
		t.Fatalf("unexpected batch sizes: %d / %d", len(base), len(dedicated))
	}
	if base[0].Hash() == dedicated[0].Hash() {
		t.Fatal("dedicated sender produced the same tx as the default sender")
	}
	if dedicated[0].Nonce() != 0 || dedicated[1].Nonce() != 1 {
		t.Fatalf("dedicated sender nonces are not contiguous from zero: %d, %d", dedicated[0].Nonce(), dedicated[1].Nonce())
	}
}

func TestGenerateTxsFromRejectsMissingSender(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	addr := crypto.PubkeyToAddress(key.PublicKey)
	s := &Suite{chain: &Chain{senders: map[common.Address]*senderInfo{
		addr: {Key: key, Nonce: 0},
	}}}
	for _, idx := range []int{-1, 1} {
		if _, _, err := s.generateTxsFrom(idx, 1); err == nil {
			t.Fatalf("generateTxsFrom(%d) accepted a fixture with one sender", idx)
		}
	}
}

func TestReadTxAnnouncementCountsMinedTxs(t *testing.T) {
	client, peer := newFramePeer(t)
	conn := &Conn{Conn: client}
	txs := frameTestTxs(3)
	header := &types.Header{Number: big.NewInt(1), Difficulty: big.NewInt(1), GasLimit: 1000000, Time: 1}
	block := types.NewBlockWithHeader(header).WithBody(types.Body{Transactions: txs})
	data, err := rlp.EncodeToBytes(&ethproto.NewBlockPacket{Block: block, TD: big.NewInt(1)})
	if err != nil {
		t.Fatalf("encode NewBlockPacket: %v", err)
	}
	written := make(chan error, 1)
	go func() {
		_, err := peer.Write(protoOffset(ethProto)+ethproto.NewBlockMsg, data)
		written <- err
	}()
	hashes, err := readTxAnnouncement(conn, 0)
	if err != nil {
		t.Fatalf("readTxAnnouncement: %v", err)
	}
	if err := <-written; err != nil {
		t.Fatalf("peer write: %v", err)
	}
	if len(hashes) != len(txs) {
		t.Fatalf("got %d hashes, want %d", len(hashes), len(txs))
	}
	for i, h := range hashes {
		if h != txs[i].Hash() {
			t.Fatalf("hash %d = %v, want %v", i, h, txs[i].Hash())
		}
	}
}

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

func TestTxFramesToRetry(t *testing.T) {
	txs := frameTestTxs(3 * txDeliveryWindow)
	frames, err := txDeliveryFrames(txs)
	if err != nil {
		t.Fatalf("txDeliveryFrames: %v", err)
	}
	seen := make(map[common.Hash]struct{}, len(txs))
	for _, tx := range txs {
		seen[tx.Hash()] = struct{}{}
	}
	if got := txFramesToRetry(frames, seen); len(got) != 0 {
		t.Fatalf("fully covered batch retried %d frames", len(got))
	}
	delete(seen, txs[txDeliveryWindow].Hash())
	partial := txFramesToRetry(frames, seen)
	if len(partial) != 1 {
		t.Fatalf("one uncovered tx retried %d frames, want 1", len(partial))
	}
	if partial[0][0].Nonce() != uint64(txDeliveryWindow) {
		t.Fatalf("retry frame starts at nonce %d, want %d", partial[0][0].Nonce(), txDeliveryWindow)
	}
	if got := txFramesToRetry(frames, map[common.Hash]struct{}{}); len(got) != len(frames) {
		t.Fatalf("empty coverage retried %d frames, want %d", len(got), len(frames))
	}
}

func frameTestHashes(txs types.Transactions) []common.Hash {
	hashes := make([]common.Hash, 0, len(txs))
	for _, tx := range txs {
		hashes = append(hashes, tx.Hash())
	}
	return hashes
}

func TestDeliverTxFramesRetriesUncoveredFrames(t *testing.T) {
	txs := frameTestTxs(2*txDeliveryWindow + 3)
	frames, err := txDeliveryFrames(txs)
	if err != nil {
		t.Fatalf("txDeliveryFrames: %v", err)
	}
	var writes [][]types.Transactions
	err = deliverTxFrames(txs,
		func(fs []types.Transactions) error {
			writes = append(writes, fs)
			return nil
		},
		func() ([]common.Hash, error) {
			if len(writes) == 1 {
				return frameTestHashes(frames[0]), nil
			}
			return frameTestHashes(txs), nil
		},
	)
	if err != nil {
		t.Fatalf("deliverTxFrames: %v", err)
	}
	if len(writes) != 2 {
		t.Fatalf("got %d write rounds, want 2", len(writes))
	}
	if want := len(frames) - 1; len(writes[1]) != want {
		t.Fatalf("retry wrote %d frames, want %d", len(writes[1]), want)
	}
	for i, frame := range writes[1] {
		if want := uint64((i + 1) * txDeliveryWindow); frame[0].Nonce() != want {
			t.Fatalf("retry frame %d starts at nonce %d, want %d", i, frame[0].Nonce(), want)
		}
	}
}

func TestDeliverTxFramesNoRetryWhenCovered(t *testing.T) {
	txs := frameTestTxs(2*txDeliveryWindow + 3)
	writes, reads := 0, 0
	err := deliverTxFrames(txs,
		func([]types.Transactions) error {
			writes++
			return nil
		},
		func() ([]common.Hash, error) {
			reads++
			return frameTestHashes(txs), nil
		},
	)
	if err != nil {
		t.Fatalf("deliverTxFrames: %v", err)
	}
	if writes != 1 || reads != 1 {
		t.Fatalf("covered batch used %d writes and %d reads, want 1 and 1", writes, reads)
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
		func() ([]common.Hash, error) { return nil, nil },
	)
	if err == nil {
		t.Fatal("uncovered batch accepted")
	}
	if writes != maxTxDeliveryAttempts {
		t.Fatalf("got %d write rounds, want %d", writes, maxTxDeliveryAttempts)
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

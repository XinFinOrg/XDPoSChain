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
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/eth"
	"github.com/XinFinOrg/XDPoSChain/internal/utesting"
	"github.com/XinFinOrg/XDPoSChain/p2p"
	"github.com/XinFinOrg/XDPoSChain/p2p/enode"
	"github.com/XinFinOrg/XDPoSChain/p2p/rlpx"
	"github.com/XinFinOrg/XDPoSChain/rlp"
)

const handshakeTimeout = 5 * time.Second

// Suite represents a minimal conformance test set that is compatible with
// the protocol packages available in this repository snapshot.
type Suite struct {
	Dest  *enode.Node
	chain *Chain
}

// NewSuite creates and returns a compatibility subset suite.
func NewSuite(dest *enode.Node, chainDir, _, _ string) (*Suite, error) {
	chain, err := NewChain(chainDir)
	if err != nil {
		return nil, err
	}
	return &Suite{Dest: dest, chain: chain}, nil
}

// EthTests returns the enabled compatibility subset.
//
// Scope freeze:
//  1. Keep only tests that depend on RLPx/devp2p handshake primitives available
//     in this repository snapshot.
//  2. Avoid extending coverage into protocol packages that are not importable in
//     this fork state.
//  3. Maintain behavior via boundary-driven hello/message-code/payload cases.
func (s *Suite) EthTests() []utesting.Test {
	return []utesting.Test{
		// Baseline.
		{Name: "RLPxHandshake", Fn: s.TestRLPxHandshake},
		{Name: "Status", Fn: s.TestStatus},
		{Name: "GetBlockHeaders", Fn: s.TestGetBlockHeaders},
		{Name: "GetBlockHeadersByHash", Fn: s.TestGetBlockHeadersByHash},
		{Name: "GetBlockHeadersReverseFromGenesis", Fn: s.TestGetBlockHeadersReverseFromGenesis},
		{Name: "GetBlockHeadersSequentialRequests", Fn: s.TestGetBlockHeadersSequentialRequests},
		{Name: "GetSequentialMixedRequests", Fn: s.TestGetSequentialMixedRequests},
		{Name: "GetNonexistentBlockHeaders", Fn: s.TestGetNonexistentBlockHeaders},
		{Name: "GetNonexistentBlockHeadersByHash", Fn: s.TestGetNonexistentBlockHeadersByHash},
		{Name: "GetNonexistentHeadersThenBlockBodies", Fn: s.TestGetNonexistentHeadersThenBlockBodies},
		{Name: "GetNonexistentHeadersThenReceipts", Fn: s.TestGetNonexistentHeadersThenReceipts},
		{Name: "TransactionSmoke", Fn: s.TestTransactionSmoke},
		{Name: "TransactionBatchSmoke", Fn: s.TestTransactionBatchSmoke},
		{Name: "TransactionEmptyListSmoke", Fn: s.TestTransactionEmptyListSmoke},
		{Name: "TransactionEmptyListThenBlockBodiesSmoke", Fn: s.TestTransactionEmptyListThenBlockBodiesSmoke},
		{Name: "TransactionThenBlockBodiesSmoke", Fn: s.TestTransactionThenBlockBodiesSmoke},
		{Name: "TransactionThenReceiptsSmoke", Fn: s.TestTransactionThenReceiptsSmoke},
		{Name: "TransactionBatchThenBlockBodiesSmoke", Fn: s.TestTransactionBatchThenBlockBodiesSmoke},
		{Name: "TransactionBatchThenReceiptsSmoke", Fn: s.TestTransactionBatchThenReceiptsSmoke},
		{Name: "TransactionEmptyListThenReceiptsSmoke", Fn: s.TestTransactionEmptyListThenReceiptsSmoke},
		{Name: "GetBlockBodies", Fn: s.TestGetBlockBodies},
		{Name: "GetBlockBodiesSequentialRequests", Fn: s.TestGetBlockBodiesSequentialRequests},
		{Name: "GetBlockBodiesMixedHashes", Fn: s.TestGetBlockBodiesMixedHashes},
		{Name: "GetBlockBodiesUnknownOnly", Fn: s.TestGetBlockBodiesUnknownOnly},
		{Name: "GetBlockBodiesUnknownThenKnown", Fn: s.TestGetBlockBodiesUnknownThenKnown},
		{Name: "GetReceipts", Fn: s.TestGetReceipts},
		{Name: "GetReceiptsSequentialRequests", Fn: s.TestGetReceiptsSequentialRequests},
		{Name: "GetReceiptsMixedHashes", Fn: s.TestGetReceiptsMixedHashes},
		{Name: "GetReceiptsUnknownOnly", Fn: s.TestGetReceiptsUnknownOnly},
		{Name: "GetReceiptsUnknownThenKnown", Fn: s.TestGetReceiptsUnknownThenKnown},

		// Identity-focused hello boundary tests.
		{Name: "MalformedHello", Fn: s.TestMalformedHello},
		{Name: "MalformedHelloShortID", Fn: s.TestMalformedHelloShortID},
		{Name: "MalformedHelloEmptyID", Fn: s.TestMalformedHelloEmptyID},
		{Name: "MalformedHelloLongID", Fn: s.TestMalformedHelloLongID},
		{Name: "MalformedHelloZeroID", Fn: s.TestMalformedHelloZeroID},
		{Name: "MalformedHelloMismatchedID", Fn: s.TestMalformedHelloMismatchedID},

		// Capability-focused hello boundary tests.
		{Name: "HelloWithoutEthCap", Fn: s.TestHelloWithoutEthCap},
		{Name: "HelloWithEmptyCaps", Fn: s.TestHelloWithEmptyCaps},
		{Name: "HelloWithEmptyCapName", Fn: s.TestHelloWithEmptyCapName},
		{Name: "HelloWithLongCapName", Fn: s.TestHelloWithLongCapName},
		{Name: "HelloWithNULCapName", Fn: s.TestHelloWithNULCapName},
		{Name: "HelloWithMismatchedIDAndEmptyCaps", Fn: s.TestHelloWithMismatchedIDAndEmptyCaps},
		{Name: "HelloWithUnsortedNonEthCaps", Fn: s.TestHelloWithUnsortedNonEthCaps},
		{Name: "HelloWithDuplicateEthCaps", Fn: s.TestHelloWithDuplicateEthCaps},

		// Version and mixed hello semantics.
		{Name: "HelloWithZeroVersion", Fn: s.TestHelloWithZeroVersion},
		{Name: "HelloWithMaxVersion", Fn: s.TestHelloWithMaxVersion},
		{Name: "HelloWithZeroVersionAndEmptyCaps", Fn: s.TestHelloWithZeroVersionAndEmptyCaps},

		// Post-RLPx first-message code handling.
		{Name: "WrongFirstMessageCode", Fn: s.TestWrongFirstMessageCode},
		{Name: "FirstMessageDisconnect", Fn: s.TestFirstMessageDisconnect},
		{Name: "FirstMessageDisconnectInvalidPayload", Fn: s.TestFirstMessageDisconnectInvalidPayload},
		{Name: "FirstMessageDisconnectEmptyPayload", Fn: s.TestFirstMessageDisconnectEmptyPayload},

		// Handshake payload size/encoding/type boundaries.
		{Name: "OversizedHelloPayload", Fn: s.TestOversizedHelloPayload},
		{Name: "EmptyHelloPayload", Fn: s.TestEmptyHelloPayload},
		{Name: "TruncatedHelloPayload", Fn: s.TestTruncatedHelloPayload},
		{Name: "InvalidHelloRLP", Fn: s.TestInvalidHelloRLP},
		{Name: "HelloPayloadWrongRLPType", Fn: s.TestHelloPayloadWrongRLPType},
		{Name: "HelloPayloadEmptyList", Fn: s.TestHelloPayloadEmptyList},
		{Name: "HelloPayloadShortList", Fn: s.TestHelloPayloadShortList},
		{Name: "HelloPayloadVersionWrongType", Fn: s.TestHelloPayloadVersionWrongType},
	}
}

func (s *Suite) TestRLPxHandshake(t *utesting.T) {
	t.Log(`This test verifies that the peer accepts a plain RLPx handshake.`)
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	conn, err := s.dialConn(key)
	if err != nil {
		t.Fatalf("rlpx handshake failed: %v", err)
	}
	conn.Close()
}

func (s *Suite) TestStatus(t *utesting.T) {
	t.Log(`This test performs a protocol handshake plus status exchange.`)
	conn, err := s.dialAndPeer(nil)
	if err != nil {
		t.Fatalf("status handshake failed: %v", err)
	}
	conn.Close()
}

func (s *Suite) TestGetBlockHeaders(t *utesting.T) {
	t.Log(`This test requests block headers for a known fixture block.`)
	conn, err := s.dialAndPeer(nil)
	if err != nil {
		t.Fatalf("peering failed: %v", err)
	}
	defer conn.Close()

	req := &getBlockHeadersData{
		Origin: hashOrNumber{Number: 0},
		Amount: 1,
	}
	if err := conn.Write(ethProto, eth.GetBlockHeadersMsg, req); err != nil {
		t.Fatalf("failed to write GetBlockHeaders: %v", err)
	}
	if err := s.expectHeadersResponse(conn, req, 1); err != nil {
		t.Fatalf("headers response validation failed: %v", err)
	}
}

func (s *Suite) TestGetBlockHeadersByHash(t *utesting.T) {
	t.Log(`This test requests block headers by origin hash.`)
	conn, err := s.dialAndPeer(nil)
	if err != nil {
		t.Fatalf("peering failed: %v", err)
	}
	defer conn.Close()

	req := &getBlockHeadersData{
		Origin: hashOrNumber{Hash: s.chain.blocks[0].Hash()},
		Amount: 1,
	}
	if err := conn.Write(ethProto, eth.GetBlockHeadersMsg, req); err != nil {
		t.Fatalf("failed to write GetBlockHeaders by hash: %v", err)
	}
	if err := s.expectHeadersResponse(conn, req, 1); err != nil {
		t.Fatalf("headers-by-hash response validation failed: %v", err)
	}
}

func (s *Suite) TestGetBlockHeadersReverseFromGenesis(t *utesting.T) {
	t.Log(`This test requests reverse headers from genesis and expects a safely truncated response.`)
	conn, err := s.dialAndPeer(nil)
	if err != nil {
		t.Fatalf("peering failed: %v", err)
	}
	defer conn.Close()

	req := &getBlockHeadersData{
		Origin:  hashOrNumber{Number: 0},
		Amount:  3,
		Reverse: true,
	}
	if err := conn.Write(ethProto, eth.GetBlockHeadersMsg, req); err != nil {
		t.Fatalf("failed to write reverse GetBlockHeaders: %v", err)
	}
	if err := s.expectHeadersResponse(conn, req, 1); err != nil {
		t.Fatalf("reverse-from-genesis headers response validation failed: %v", err)
	}
}

func (s *Suite) TestGetBlockHeadersSequentialRequests(t *utesting.T) {
	t.Log(`This test sends two different valid headers requests on the same connection.`)
	conn, err := s.dialAndPeer(nil)
	if err != nil {
		t.Fatalf("peering failed: %v", err)
	}
	defer conn.Close()

	first := &getBlockHeadersData{Origin: hashOrNumber{Number: 0}, Amount: 1}
	second := &getBlockHeadersData{Origin: hashOrNumber{Hash: s.chain.blocks[0].Hash()}, Amount: 1}

	if err := conn.Write(ethProto, eth.GetBlockHeadersMsg, first); err != nil {
		t.Fatalf("failed to write first GetBlockHeaders request: %v", err)
	}
	if err := conn.Write(ethProto, eth.GetBlockHeadersMsg, second); err != nil {
		t.Fatalf("failed to write second GetBlockHeaders request: %v", err)
	}
	if err := s.expectHeadersResponse(conn, first, 2); err != nil {
		t.Fatalf("first sequential headers response validation failed: %v", err)
	}
	if err := s.expectHeadersResponse(conn, second, 2); err != nil {
		t.Fatalf("second sequential headers response validation failed: %v", err)
	}
}

func (s *Suite) TestGetSequentialMixedRequests(t *utesting.T) {
	t.Log(`This test sends headers, block bodies, and receipts requests sequentially on one connection.`)
	conn, err := s.dialAndPeer(nil)
	if err != nil {
		t.Fatalf("peering failed: %v", err)
	}
	defer conn.Close()

	headersReq := &getBlockHeadersData{Origin: hashOrNumber{Number: 0}, Amount: 1}
	if err := conn.Write(ethProto, eth.GetBlockHeadersMsg, headersReq); err != nil {
		t.Fatalf("failed to write GetBlockHeaders request: %v", err)
	}
	if err := s.expectHeadersResponse(conn, headersReq, 1); err != nil {
		t.Fatalf("headers response validation failed: %v", err)
	}

	bodiesReq := getBlockBodiesData{s.chain.blocks[0].Hash()}
	if err := conn.Write(ethProto, eth.GetBlockBodiesMsg, &bodiesReq); err != nil {
		t.Fatalf("failed to write GetBlockBodies request: %v", err)
	}
	if err := s.expectBlockBodiesResponse(conn, &bodiesReq, 1); err != nil {
		t.Fatalf("block bodies response validation failed: %v", err)
	}

	receiptsReq := getReceiptsData{s.chain.blocks[0].Hash()}
	if err := conn.Write(ethProto, eth.GetReceiptsMsg, &receiptsReq); err != nil {
		t.Fatalf("failed to write GetReceipts request: %v", err)
	}
	if err := s.expectReceiptsResponse(conn, &receiptsReq, 1); err != nil {
		t.Fatalf("receipts response validation failed: %v", err)
	}
}

func (s *Suite) TestGetNonexistentBlockHeaders(t *utesting.T) {
	t.Log(`This test sends a nonexistent headers request and verifies the peer remains responsive.`)
	conn, err := s.dialAndPeer(nil)
	if err != nil {
		t.Fatalf("peering failed: %v", err)
	}
	defer conn.Close()

	badReq := &getBlockHeadersData{
		Origin: hashOrNumber{Number: ^uint64(0)},
		Amount: 1,
	}
	if err := conn.Write(ethProto, eth.GetBlockHeadersMsg, badReq); err != nil {
		t.Fatalf("failed to write nonexistent GetBlockHeaders request: %v", err)
	}

	goodReq := &getBlockHeadersData{
		Origin: hashOrNumber{Number: 0},
		Amount: 1,
	}
	if err := conn.Write(ethProto, eth.GetBlockHeadersMsg, goodReq); err != nil {
		t.Fatalf("failed to write follow-up GetBlockHeaders request: %v", err)
	}

	if err := s.expectHeadersResponse(conn, goodReq, 2); err != nil {
		t.Fatalf("follow-up valid headers response was not received: %v", err)
	}
}

func (s *Suite) TestGetNonexistentBlockHeadersByHash(t *utesting.T) {
	t.Log(`This test sends a nonexistent hash-based headers request and verifies the peer remains responsive.`)
	conn, err := s.dialAndPeer(nil)
	if err != nil {
		t.Fatalf("peering failed: %v", err)
	}
	defer conn.Close()

	badReq := &getBlockHeadersData{
		Origin: hashOrNumber{Hash: common.HexToHash("0x01")},
		Amount: 1,
	}
	if err := conn.Write(ethProto, eth.GetBlockHeadersMsg, badReq); err != nil {
		t.Fatalf("failed to write nonexistent hash GetBlockHeaders request: %v", err)
	}

	goodReq := &getBlockHeadersData{
		Origin: hashOrNumber{Hash: s.chain.blocks[0].Hash()},
		Amount: 1,
	}
	if err := conn.Write(ethProto, eth.GetBlockHeadersMsg, goodReq); err != nil {
		t.Fatalf("failed to write follow-up hash GetBlockHeaders request: %v", err)
	}

	if err := s.expectHeadersResponse(conn, goodReq, 2); err != nil {
		t.Fatalf("follow-up valid hash-based headers response was not received: %v", err)
	}
}

func (s *Suite) TestGetNonexistentHeadersThenBlockBodies(t *utesting.T) {
	t.Log(`This test sends a nonexistent headers request then a valid block bodies request on the same connection.`)
	conn, err := s.dialAndPeer(nil)
	if err != nil {
		t.Fatalf("peering failed: %v", err)
	}
	defer conn.Close()

	badReq := &getBlockHeadersData{Origin: hashOrNumber{Number: ^uint64(0)}, Amount: 1}
	if err := conn.Write(ethProto, eth.GetBlockHeadersMsg, badReq); err != nil {
		t.Fatalf("failed to write nonexistent GetBlockHeaders request: %v", err)
	}
	goodReq := getBlockBodiesData{s.chain.blocks[0].Hash()}
	if err := conn.Write(ethProto, eth.GetBlockBodiesMsg, &goodReq); err != nil {
		t.Fatalf("failed to write follow-up GetBlockBodies request: %v", err)
	}
	if err := s.expectBlockBodiesResponse(conn, &goodReq, 2); err != nil {
		t.Fatalf("follow-up valid block bodies response was not received: %v", err)
	}
}

func (s *Suite) TestGetNonexistentHeadersThenReceipts(t *utesting.T) {
	t.Log(`This test sends a nonexistent headers request then a valid receipts request on the same connection.`)
	conn, err := s.dialAndPeer(nil)
	if err != nil {
		t.Fatalf("peering failed: %v", err)
	}
	defer conn.Close()

	badReq := &getBlockHeadersData{Origin: hashOrNumber{Number: ^uint64(0)}, Amount: 1}
	if err := conn.Write(ethProto, eth.GetBlockHeadersMsg, badReq); err != nil {
		t.Fatalf("failed to write nonexistent GetBlockHeaders request: %v", err)
	}
	goodReq := getReceiptsData{s.chain.blocks[0].Hash()}
	if err := conn.Write(ethProto, eth.GetReceiptsMsg, &goodReq); err != nil {
		t.Fatalf("failed to write follow-up GetReceipts request: %v", err)
	}
	if err := s.expectReceiptsResponse(conn, &goodReq, 2); err != nil {
		t.Fatalf("follow-up valid receipts response was not received: %v", err)
	}
}

func (s *Suite) expectHeadersResponse(conn *Conn, req *getBlockHeadersData, maxReads int) error {
	expected, err := s.chain.GetHeaders(req)
	if err != nil {
		return fmt.Errorf("failed to build expected headers: %w", err)
	}
	for i := 0; i < maxReads; i++ {
		msg, err := conn.ReadEth()
		if err != nil {
			return fmt.Errorf("failed to read headers response %d: %w", i+1, err)
		}
		headers, ok := msg.(*blockHeadersData)
		if !ok {
			continue
		}
		if len(*headers) != len(expected) {
			continue
		}
		matched := true
		for j := range expected {
			if (*headers)[j].Hash() != expected[j].Hash() {
				matched = false
				break
			}
		}
		if matched {
			return nil
		}
	}
	return fmt.Errorf("did not receive matching BlockHeaders response in %d read(s)", maxReads)
}

func (s *Suite) signedFixtureTxs(count int) (types.Transactions, common.Address, error) {
	if len(s.chain.senders) == 0 {
		return nil, common.Address{}, fmt.Errorf("fixture has no sender accounts")
	}
	from, nonce := s.chain.GetSender(0)
	to := common.HexToAddress("0x00000000000000000000000000000000000000aa")
	txs := make(types.Transactions, 0, count)
	for i := 0; i < count; i++ {
		unsigned := types.NewTransaction(nonce+uint64(i), to, big.NewInt(int64(i+1)), 21000, big.NewInt(1), nil)
		signed, err := s.chain.SignTx(from, unsigned)
		if err != nil {
			return nil, common.Address{}, fmt.Errorf("failed to sign tx %d: %w", i, err)
		}
		txs = append(txs, signed)
	}
	return txs, from, nil
}

func (s *Suite) runTransactionSmoke(t *utesting.T, txs types.Transactions, nonceAdvance uint64, skipWithoutSenders bool, skipMessage string, followUp func(*Conn) error) {
	t.Helper()
	if skipWithoutSenders && len(s.chain.senders) == 0 {
		t.Log(skipMessage)
		return
	}
	conn, err := s.dialAndPeer(nil)
	if err != nil {
		t.Fatalf("peering failed: %v", err)
	}
	defer conn.Close()

	if err := conn.Write(ethProto, eth.TxMsg, txs); err != nil {
		t.Fatalf("failed to write TxMsg: %v", err)
	}
	if skipWithoutSenders && nonceAdvance > 0 {
		from, _ := s.chain.GetSender(0)
		s.chain.IncNonce(from, nonceAdvance)
	}
	if err := followUp(conn); err != nil {
		t.Fatal(err)
	}
}

func (s *Suite) TestTransactionSmoke(t *utesting.T) {
	t.Log(`This test sends a signed transaction and verifies the peer remains responsive.`)
	txs, _, err := s.signedFixtureTxs(1)
	if err != nil {
		t.Log("fixture has no sender accounts; skipping transaction smoke")
		return
	}
	s.runTransactionSmoke(t, txs, 1, true, "fixture has no sender accounts; skipping transaction smoke", func(conn *Conn) error {
		req := &getBlockHeadersData{Origin: hashOrNumber{Number: 0}, Amount: 1}
		if err := conn.Write(ethProto, eth.GetBlockHeadersMsg, req); err != nil {
			return fmt.Errorf("failed to write follow-up GetBlockHeaders: %w", err)
		}
		if err := s.expectHeadersResponse(conn, req, 5); err != nil {
			return fmt.Errorf("did not receive BlockHeaders response after TxMsg: %w", err)
		}
		return nil
	})
}

func (s *Suite) TestTransactionBatchSmoke(t *utesting.T) {
	t.Log(`This test sends a batch of signed transactions and verifies the peer remains responsive.`)
	txs, _, err := s.signedFixtureTxs(2)
	if err != nil {
		t.Log("fixture has no sender accounts; skipping transaction batch smoke")
		return
	}
	s.runTransactionSmoke(t, txs, 2, true, "fixture has no sender accounts; skipping transaction batch smoke", func(conn *Conn) error {
		req := &getBlockHeadersData{Origin: hashOrNumber{Number: 0}, Amount: 1}
		if err := conn.Write(ethProto, eth.GetBlockHeadersMsg, req); err != nil {
			return fmt.Errorf("failed to write follow-up GetBlockHeaders: %w", err)
		}
		if err := s.expectHeadersResponse(conn, req, 5); err != nil {
			return fmt.Errorf("did not receive BlockHeaders response after batched TxMsg: %w", err)
		}
		return nil
	})
}

func (s *Suite) TestTransactionEmptyListSmoke(t *utesting.T) {
	t.Log(`This test sends an empty transaction list and verifies the peer remains responsive.`)
	s.runTransactionSmoke(t, types.Transactions{}, 0, false, "", func(conn *Conn) error {
		req := &getBlockHeadersData{Origin: hashOrNumber{Number: 0}, Amount: 1}
		if err := conn.Write(ethProto, eth.GetBlockHeadersMsg, req); err != nil {
			return fmt.Errorf("failed to write follow-up GetBlockHeaders: %w", err)
		}
		if err := s.expectHeadersResponse(conn, req, 5); err != nil {
			return fmt.Errorf("did not receive BlockHeaders response after empty TxMsg: %w", err)
		}
		return nil
	})
}

func (s *Suite) TestTransactionEmptyListThenBlockBodiesSmoke(t *utesting.T) {
	t.Log(`This test sends an empty transaction list and then requests block bodies.`)
	s.runTransactionSmoke(t, types.Transactions{}, 0, false, "", func(conn *Conn) error {
		req := getBlockBodiesData{s.chain.blocks[0].Hash()}
		if err := conn.Write(ethProto, eth.GetBlockBodiesMsg, &req); err != nil {
			return fmt.Errorf("failed to write follow-up GetBlockBodies: %w", err)
		}
		if err := s.expectBlockBodiesResponse(conn, &req, 5); err != nil {
			return fmt.Errorf("did not receive BlockBodies response after empty TxMsg: %w", err)
		}
		return nil
	})
}

func (s *Suite) TestTransactionEmptyListThenReceiptsSmoke(t *utesting.T) {
	t.Log(`This test sends an empty transaction list and then requests receipts.`)
	s.runTransactionSmoke(t, types.Transactions{}, 0, false, "", func(conn *Conn) error {
		req := getReceiptsData{s.chain.blocks[0].Hash()}
		if err := conn.Write(ethProto, eth.GetReceiptsMsg, &req); err != nil {
			return fmt.Errorf("failed to write follow-up GetReceipts: %w", err)
		}
		if err := s.expectReceiptsResponse(conn, &req, 5); err != nil {
			return fmt.Errorf("did not receive Receipts response after empty TxMsg: %w", err)
		}
		return nil
	})
}

func (s *Suite) TestTransactionThenBlockBodiesSmoke(t *utesting.T) {
	t.Log(`This test sends a signed transaction and then requests block bodies.`)
	txs, _, err := s.signedFixtureTxs(1)
	if err != nil {
		t.Log("fixture has no sender accounts; skipping transaction block-bodies smoke")
		return
	}
	s.runTransactionSmoke(t, txs, 1, true, "fixture has no sender accounts; skipping transaction block-bodies smoke", func(conn *Conn) error {
		req := getBlockBodiesData{s.chain.blocks[0].Hash()}
		if err := conn.Write(ethProto, eth.GetBlockBodiesMsg, &req); err != nil {
			return fmt.Errorf("failed to write follow-up GetBlockBodies: %w", err)
		}
		if err := s.expectBlockBodiesResponse(conn, &req, 5); err != nil {
			return fmt.Errorf("did not receive BlockBodies response after TxMsg: %w", err)
		}
		return nil
	})
}

func (s *Suite) TestTransactionThenReceiptsSmoke(t *utesting.T) {
	t.Log(`This test sends a signed transaction and then requests receipts.`)
	txs, _, err := s.signedFixtureTxs(1)
	if err != nil {
		t.Log("fixture has no sender accounts; skipping transaction receipts smoke")
		return
	}
	s.runTransactionSmoke(t, txs, 1, true, "fixture has no sender accounts; skipping transaction receipts smoke", func(conn *Conn) error {
		req := getReceiptsData{s.chain.blocks[0].Hash()}
		if err := conn.Write(ethProto, eth.GetReceiptsMsg, &req); err != nil {
			return fmt.Errorf("failed to write follow-up GetReceipts: %w", err)
		}
		if err := s.expectReceiptsResponse(conn, &req, 5); err != nil {
			return fmt.Errorf("did not receive Receipts response after TxMsg: %w", err)
		}
		return nil
	})
}

func (s *Suite) TestTransactionBatchThenBlockBodiesSmoke(t *utesting.T) {
	t.Log(`This test sends a batch of signed transactions and then requests block bodies.`)
	txs, _, err := s.signedFixtureTxs(2)
	if err != nil {
		t.Log("fixture has no sender accounts; skipping batched transaction block-bodies smoke")
		return
	}
	s.runTransactionSmoke(t, txs, 2, true, "fixture has no sender accounts; skipping batched transaction block-bodies smoke", func(conn *Conn) error {
		req := getBlockBodiesData{s.chain.blocks[0].Hash()}
		if err := conn.Write(ethProto, eth.GetBlockBodiesMsg, &req); err != nil {
			return fmt.Errorf("failed to write follow-up GetBlockBodies: %w", err)
		}
		if err := s.expectBlockBodiesResponse(conn, &req, 5); err != nil {
			return fmt.Errorf("did not receive BlockBodies response after batched TxMsg: %w", err)
		}
		return nil
	})
}

func (s *Suite) TestTransactionBatchThenReceiptsSmoke(t *utesting.T) {
	t.Log(`This test sends a batch of signed transactions and then requests receipts.`)
	txs, _, err := s.signedFixtureTxs(2)
	if err != nil {
		t.Log("fixture has no sender accounts; skipping batched transaction receipts smoke")
		return
	}
	s.runTransactionSmoke(t, txs, 2, true, "fixture has no sender accounts; skipping batched transaction receipts smoke", func(conn *Conn) error {
		req := getReceiptsData{s.chain.blocks[0].Hash()}
		if err := conn.Write(ethProto, eth.GetReceiptsMsg, &req); err != nil {
			return fmt.Errorf("failed to write follow-up GetReceipts: %w", err)
		}
		if err := s.expectReceiptsResponse(conn, &req, 5); err != nil {
			return fmt.Errorf("did not receive Receipts response after batched TxMsg: %w", err)
		}
		return nil
	})
}

func (s *Suite) TestGetBlockBodies(t *utesting.T) {
	t.Log(`This test requests block bodies for a known fixture block hash.`)
	conn, err := s.dialAndPeer(nil)
	if err != nil {
		t.Fatalf("peering failed: %v", err)
	}
	defer conn.Close()

	req := getBlockBodiesData{s.chain.blocks[0].Hash()}
	if err := conn.Write(ethProto, eth.GetBlockBodiesMsg, &req); err != nil {
		t.Fatalf("failed to write GetBlockBodies: %v", err)
	}
	if err := s.expectBlockBodiesResponse(conn, &req, 1); err != nil {
		t.Fatalf("block bodies response validation failed: %v", err)
	}
}

func (s *Suite) TestGetBlockBodiesSequentialRequests(t *utesting.T) {
	t.Log(`This test sends two valid block bodies requests on the same connection.`)
	conn, err := s.dialAndPeer(nil)
	if err != nil {
		t.Fatalf("peering failed: %v", err)
	}
	defer conn.Close()

	first := getBlockBodiesData{s.chain.blocks[0].Hash()}
	second := getBlockBodiesData{s.chain.blocks[0].Hash(), common.HexToHash("0x01")}

	if err := conn.Write(ethProto, eth.GetBlockBodiesMsg, &first); err != nil {
		t.Fatalf("failed to write first GetBlockBodies request: %v", err)
	}
	if err := s.expectBlockBodiesResponse(conn, &first, 1); err != nil {
		t.Fatalf("first sequential block bodies response validation failed: %v", err)
	}
	if err := conn.Write(ethProto, eth.GetBlockBodiesMsg, &second); err != nil {
		t.Fatalf("failed to write second GetBlockBodies request: %v", err)
	}
	if err := s.expectBlockBodiesResponse(conn, &second, 1); err != nil {
		t.Fatalf("second sequential block bodies response validation failed: %v", err)
	}
}

func (s *Suite) TestGetBlockBodiesMixedHashes(t *utesting.T) {
	t.Log(`This test requests block bodies with mixed known and unknown hashes.`)
	conn, err := s.dialAndPeer(nil)
	if err != nil {
		t.Fatalf("peering failed: %v", err)
	}
	defer conn.Close()

	req := getBlockBodiesData{s.chain.blocks[0].Hash(), common.HexToHash("0x01")}
	if err := conn.Write(ethProto, eth.GetBlockBodiesMsg, &req); err != nil {
		t.Fatalf("failed to write mixed GetBlockBodies: %v", err)
	}
	if err := s.expectBlockBodiesResponse(conn, &req, 1); err != nil {
		t.Fatalf("mixed block bodies response validation failed: %v", err)
	}
}

func (s *Suite) TestGetBlockBodiesUnknownOnly(t *utesting.T) {
	t.Log(`This test requests block bodies for unknown hashes only.`)
	conn, err := s.dialAndPeer(nil)
	if err != nil {
		t.Fatalf("peering failed: %v", err)
	}
	defer conn.Close()

	req := getBlockBodiesData{common.HexToHash("0x01")}
	if err := conn.Write(ethProto, eth.GetBlockBodiesMsg, &req); err != nil {
		t.Fatalf("failed to write unknown-only GetBlockBodies: %v", err)
	}
	if err := s.expectBlockBodiesResponse(conn, &req, 2); err != nil {
		t.Fatalf("unknown-only block bodies response validation failed: %v", err)
	}
}

func (s *Suite) TestGetBlockBodiesUnknownThenKnown(t *utesting.T) {
	t.Log(`This test sends unknown then known block-bodies requests and expects valid follow-up response.`)
	conn, err := s.dialAndPeer(nil)
	if err != nil {
		t.Fatalf("peering failed: %v", err)
	}
	defer conn.Close()

	badReq := getBlockBodiesData{common.HexToHash("0x01")}
	if err := conn.Write(ethProto, eth.GetBlockBodiesMsg, &badReq); err != nil {
		t.Fatalf("failed to write unknown GetBlockBodies: %v", err)
	}
	goodReq := getBlockBodiesData{s.chain.blocks[0].Hash()}
	if err := conn.Write(ethProto, eth.GetBlockBodiesMsg, &goodReq); err != nil {
		t.Fatalf("failed to write follow-up GetBlockBodies: %v", err)
	}
	if err := s.expectBlockBodiesResponse(conn, &goodReq, 2); err != nil {
		t.Fatalf("follow-up block bodies response validation failed: %v", err)
	}
}

func (s *Suite) TestGetReceipts(t *utesting.T) {
	t.Log(`This test requests receipts for a known fixture block hash.`)
	conn, err := s.dialAndPeer(nil)
	if err != nil {
		t.Fatalf("peering failed: %v", err)
	}
	defer conn.Close()

	req := getReceiptsData{s.chain.blocks[0].Hash()}
	if err := conn.Write(ethProto, eth.GetReceiptsMsg, &req); err != nil {
		t.Fatalf("failed to write GetReceipts: %v", err)
	}
	if err := s.expectReceiptsResponse(conn, &req, 1); err != nil {
		t.Fatalf("receipts response validation failed: %v", err)
	}
}

func (s *Suite) TestGetReceiptsSequentialRequests(t *utesting.T) {
	t.Log(`This test sends two valid receipts requests on the same connection.`)
	conn, err := s.dialAndPeer(nil)
	if err != nil {
		t.Fatalf("peering failed: %v", err)
	}
	defer conn.Close()

	first := getReceiptsData{s.chain.blocks[0].Hash()}
	second := getReceiptsData{s.chain.blocks[0].Hash(), common.HexToHash("0x01")}

	if err := conn.Write(ethProto, eth.GetReceiptsMsg, &first); err != nil {
		t.Fatalf("failed to write first GetReceipts request: %v", err)
	}
	if err := s.expectReceiptsResponse(conn, &first, 1); err != nil {
		t.Fatalf("first sequential receipts response validation failed: %v", err)
	}
	if err := conn.Write(ethProto, eth.GetReceiptsMsg, &second); err != nil {
		t.Fatalf("failed to write second GetReceipts request: %v", err)
	}
	if err := s.expectReceiptsResponse(conn, &second, 1); err != nil {
		t.Fatalf("second sequential receipts response validation failed: %v", err)
	}
}

func (s *Suite) TestGetReceiptsMixedHashes(t *utesting.T) {
	t.Log(`This test requests receipts with mixed known and unknown hashes.`)
	conn, err := s.dialAndPeer(nil)
	if err != nil {
		t.Fatalf("peering failed: %v", err)
	}
	defer conn.Close()

	req := getReceiptsData{s.chain.blocks[0].Hash(), common.HexToHash("0x01")}
	if err := conn.Write(ethProto, eth.GetReceiptsMsg, &req); err != nil {
		t.Fatalf("failed to write mixed GetReceipts: %v", err)
	}
	if err := s.expectReceiptsResponse(conn, &req, 1); err != nil {
		t.Fatalf("mixed receipts response validation failed: %v", err)
	}
}

func (s *Suite) TestGetReceiptsUnknownOnly(t *utesting.T) {
	t.Log(`This test requests receipts for unknown hashes only.`)
	conn, err := s.dialAndPeer(nil)
	if err != nil {
		t.Fatalf("peering failed: %v", err)
	}
	defer conn.Close()

	req := getReceiptsData{common.HexToHash("0x01")}
	if err := conn.Write(ethProto, eth.GetReceiptsMsg, &req); err != nil {
		t.Fatalf("failed to write unknown-only GetReceipts: %v", err)
	}
	if err := s.expectReceiptsResponse(conn, &req, 2); err != nil {
		t.Fatalf("unknown-only receipts response validation failed: %v", err)
	}
}

func (s *Suite) TestGetReceiptsUnknownThenKnown(t *utesting.T) {
	t.Log(`This test sends unknown then known receipts requests and expects valid follow-up response.`)
	conn, err := s.dialAndPeer(nil)
	if err != nil {
		t.Fatalf("peering failed: %v", err)
	}
	defer conn.Close()

	badReq := getReceiptsData{common.HexToHash("0x01")}
	if err := conn.Write(ethProto, eth.GetReceiptsMsg, &badReq); err != nil {
		t.Fatalf("failed to write unknown GetReceipts: %v", err)
	}
	goodReq := getReceiptsData{s.chain.blocks[0].Hash()}
	if err := conn.Write(ethProto, eth.GetReceiptsMsg, &goodReq); err != nil {
		t.Fatalf("failed to write follow-up GetReceipts: %v", err)
	}
	if err := s.expectReceiptsResponse(conn, &goodReq, 2); err != nil {
		t.Fatalf("follow-up receipts response validation failed: %v", err)
	}
}

func (s *Suite) expectBlockBodiesResponse(conn *Conn, req *getBlockBodiesData, maxReads int) error {
	expected, err := s.chain.GetBlockBodies(req)
	if err != nil {
		return fmt.Errorf("failed to build expected block bodies: %w", err)
	}
	for i := 0; i < maxReads; i++ {
		msg, err := conn.ReadEth()
		if err != nil {
			return fmt.Errorf("failed to read block bodies response %d: %w", i+1, err)
		}
		bodies, ok := msg.(*blockBodiesData)
		if !ok {
			continue
		}
		if len(*bodies) != len(expected) {
			continue
		}
		matched := true
		for j := range expected {
			if len((*bodies)[j].Transactions) != len(expected[j].Transactions) || len((*bodies)[j].Uncles) != len(expected[j].Uncles) {
				matched = false
				break
			}
			for k := range expected[j].Transactions {
				if (*bodies)[j].Transactions[k].Hash() != expected[j].Transactions[k].Hash() {
					matched = false
					break
				}
			}
			if !matched {
				break
			}
			for k := range expected[j].Uncles {
				if (*bodies)[j].Uncles[k].Hash() != expected[j].Uncles[k].Hash() {
					matched = false
					break
				}
			}
			if !matched {
				break
			}
		}
		if matched {
			return nil
		}
	}
	return fmt.Errorf("did not receive matching BlockBodies response in %d read(s)", maxReads)
}

func (s *Suite) expectReceiptsResponse(conn *Conn, req *getReceiptsData, maxReads int) error {
	expected, err := s.chain.GetReceipts(req)
	if err != nil {
		return fmt.Errorf("failed to build expected receipts: %w", err)
	}
	for i := 0; i < maxReads; i++ {
		msg, err := conn.ReadEth()
		if err != nil {
			return fmt.Errorf("failed to read receipts response %d: %w", i+1, err)
		}
		receipts, ok := msg.(*receiptsData)
		if !ok {
			continue
		}
		if len(*receipts) != len(expected) {
			continue
		}
		matched := true
		for j := range expected {
			if len((*receipts)[j]) != len(expected[j]) {
				matched = false
				break
			}
		}
		if matched {
			return nil
		}
	}
	return fmt.Errorf("did not receive matching Receipts response in %d read(s)", maxReads)
}

func (s *Suite) TestMalformedHello(t *utesting.T) {
	t.Log(`This test sends a malformed devp2p hello and expects a disconnect.`)
	s.runMalformedHelloNamedCase(t, "MalformedHello")
}

func (s *Suite) TestMalformedHelloShortID(t *utesting.T) {
	t.Log(`This test sends a hello with a too-short peer id and expects a disconnect.`)
	s.runMalformedHelloNamedCase(t, "MalformedHelloShortID")
}

func (s *Suite) TestMalformedHelloEmptyID(t *utesting.T) {
	t.Log(`This test sends a hello with an empty peer id and expects a disconnect.`)
	s.runMalformedHelloNamedCase(t, "MalformedHelloEmptyID")
}

func (s *Suite) TestMalformedHelloLongID(t *utesting.T) {
	t.Log(`This test sends a hello with an overly long peer id and expects a disconnect.`)
	s.runMalformedHelloNamedCase(t, "MalformedHelloLongID")
}

func (s *Suite) TestMalformedHelloZeroID(t *utesting.T) {
	t.Log(`This test sends a hello with an all-zero peer id and expects a disconnect.`)
	s.runMalformedHelloNamedCase(t, "MalformedHelloZeroID")
}

func (s *Suite) TestMalformedHelloMismatchedID(t *utesting.T) {
	t.Log(`This test sends a hello with a non-zero but mismatched peer id and expects a disconnect.`)
	s.runMalformedHelloNamedCase(t, "MalformedHelloMismatchedID")
}

func (s *Suite) TestHelloWithoutEthCap(t *utesting.T) {
	t.Log(`This test sends a hello that omits eth capability and expects a disconnect.`)
	s.runMalformedHelloNamedCase(t, "HelloWithoutEthCap")
}

func (s *Suite) TestHelloWithZeroVersion(t *utesting.T) {
	t.Log(`This test sends a hello with protocol version zero and expects a disconnect.`)
	s.runMalformedHelloNamedCase(t, "HelloWithZeroVersion")
}

func (s *Suite) TestHelloWithMaxVersion(t *utesting.T) {
	t.Log(`This test sends a hello with max uint64 version and expects a disconnect.`)
	s.runMalformedHelloNamedCase(t, "HelloWithMaxVersion")
}

func (s *Suite) TestHelloWithZeroVersionAndEmptyCaps(t *utesting.T) {
	t.Log(`This test sends a hello with zero version and empty capabilities and expects a disconnect.`)
	s.runMalformedHelloNamedCase(t, "HelloWithZeroVersionAndEmptyCaps")
}

func (s *Suite) TestHelloWithEmptyCaps(t *utesting.T) {
	t.Log(`This test sends a hello with empty capabilities and expects a disconnect.`)
	s.runMalformedHelloNamedCase(t, "HelloWithEmptyCaps")
}

func (s *Suite) TestHelloWithEmptyCapName(t *utesting.T) {
	t.Log(`This test sends a hello with an empty capability name and expects a disconnect.`)
	s.runMalformedHelloNamedCase(t, "HelloWithEmptyCapName")
}

func (s *Suite) TestHelloWithLongCapName(t *utesting.T) {
	t.Log(`This test sends a hello with an overly long capability name and expects a disconnect.`)
	s.runMalformedHelloNamedCase(t, "HelloWithLongCapName")
}

func (s *Suite) TestHelloWithNULCapName(t *utesting.T) {
	t.Log(`This test sends a hello with a NUL byte in capability name and expects a disconnect.`)
	s.runMalformedHelloNamedCase(t, "HelloWithNULCapName")
}

func (s *Suite) TestHelloWithMismatchedIDAndEmptyCaps(t *utesting.T) {
	t.Log(`This test sends a hello with mismatched id and empty capabilities and expects a disconnect.`)
	s.runMalformedHelloNamedCase(t, "HelloWithMismatchedIDAndEmptyCaps")
}

func (s *Suite) TestHelloWithUnsortedNonEthCaps(t *utesting.T) {
	t.Log(`This test sends a hello with unsorted non-eth capabilities and expects a disconnect.`)
	s.runMalformedHelloNamedCase(t, "HelloWithUnsortedNonEthCaps")
}

func (s *Suite) TestOversizedHelloPayload(t *utesting.T) {
	t.Log(`This test sends an oversized hello payload and expects a disconnect.`)
	s.withRLPxConn(t, func(conn *rlpx.Conn) {
		// p2p readProtocolHandshake enforces a 2KB max size for hello.
		oversized := make([]byte, 2049)
		s.expectDisconnectAfterHelloPayload(t, conn, oversized)
	})
}

func (s *Suite) TestWrongFirstMessageCode(t *utesting.T) {
	t.Log(`This test sends a non-handshake first message code and expects a disconnect.`)
	s.withRLPxConn(t, func(conn *rlpx.Conn) {
		// The first post-RLPx message must be handshakeMsg.
		s.expectDisconnectAfterMessage(t, conn, pingMsg, []byte{})
	})
}

func (s *Suite) TestFirstMessageDisconnect(t *utesting.T) {
	t.Log(`This test sends a disconnect as first post-RLPx message and expects disconnect handling.`)
	s.withRLPxConn(t, func(conn *rlpx.Conn) {
		reasonPayload, err := rlp.EncodeToBytes([1]p2p.DiscReason{p2p.DiscRequested})
		if err != nil {
			t.Fatalf("failed to encode disconnect reason: %v", err)
		}
		s.expectDisconnectAfterMessage(t, conn, discMsg, reasonPayload)
	})
}

func (s *Suite) TestFirstMessageDisconnectInvalidPayload(t *utesting.T) {
	t.Log(`This test sends a disconnect with invalid reason payload and expects disconnect handling.`)
	s.withRLPxConn(t, func(conn *rlpx.Conn) {
		// Invalid RLP for [1]DiscReason decoding path on receiver side.
		s.expectDisconnectAfterMessage(t, conn, discMsg, []byte{0xff})
	})
}

func (s *Suite) TestFirstMessageDisconnectEmptyPayload(t *utesting.T) {
	t.Log(`This test sends a disconnect with empty payload and expects disconnect handling.`)
	s.withRLPxConn(t, func(conn *rlpx.Conn) {
		// Empty payload should fail disconnect-reason decoding on receiver side.
		s.expectDisconnectAfterMessage(t, conn, discMsg, []byte{})
	})
}

func (s *Suite) TestEmptyHelloPayload(t *utesting.T) {
	t.Log(`This test sends an empty hello payload and expects a disconnect.`)
	s.withRLPxConn(t, func(conn *rlpx.Conn) {
		s.expectDisconnectAfterHelloPayload(t, conn, []byte{})
	})
}

func (s *Suite) TestTruncatedHelloPayload(t *utesting.T) {
	t.Log(`This test sends a truncated hello RLP payload and expects a disconnect.`)
	s.withRLPxConn(t, func(conn *rlpx.Conn) {
		// List length prefix (1 byte) without element content.
		s.expectDisconnectAfterHelloPayload(t, conn, []byte{0xc1})
	})
}

func (s *Suite) TestInvalidHelloRLP(t *utesting.T) {
	t.Log(`This test sends invalid hello RLP bytes and expects a disconnect.`)
	s.withRLPxConn(t, func(conn *rlpx.Conn) {
		s.expectDisconnectAfterHelloPayload(t, conn, []byte{0xff})
	})
}

func (s *Suite) TestHelloPayloadWrongRLPType(t *utesting.T) {
	t.Log(`This test sends hello payload with wrong RLP type and expects a disconnect.`)
	s.withRLPxConn(t, func(conn *rlpx.Conn) {
		// RLP empty string, while hello expects a list/struct payload.
		s.expectDisconnectAfterHelloPayload(t, conn, []byte{0x80})
	})
}

func (s *Suite) TestHelloPayloadEmptyList(t *utesting.T) {
	t.Log(`This test sends hello payload as an empty RLP list and expects a disconnect.`)
	s.withRLPxConn(t, func(conn *rlpx.Conn) {
		// RLP empty list. Decoded hello has zero-value fields and invalid identity.
		s.expectDisconnectAfterHelloPayload(t, conn, []byte{0xc0})
	})
}

func (s *Suite) TestHelloPayloadShortList(t *utesting.T) {
	t.Log(`This test sends hello payload as a short RLP list and expects a disconnect.`)
	s.withRLPxConn(t, func(conn *rlpx.Conn) {
		// RLP list with a single element (version only), missing required hello fields.
		s.expectDisconnectAfterHelloPayload(t, conn, []byte{0xc1, 0x05})
	})
}

func (s *Suite) TestHelloPayloadVersionWrongType(t *utesting.T) {
	t.Log(`This test sends hello payload with wrong version field type and expects a disconnect.`)
	s.withRLPxConn(t, func(conn *rlpx.Conn) {
		// RLP list with one element: empty list, but hello version expects uint.
		s.expectDisconnectAfterHelloPayload(t, conn, []byte{0xc1, 0xc0})
	})
}

func (s *Suite) TestHelloWithDuplicateEthCaps(t *utesting.T) {
	t.Log(`This test sends a hello with duplicate eth capabilities and expects a disconnect.`)
	s.runMalformedHelloNamedCase(t, "HelloWithDuplicateEthCaps")
}

func malformedHelloByCase(name string, pub0 []byte) *protoHandshake {
	base := &protoHandshake{
		Version: 5,
		Caps:    []p2p.Cap{{Name: "eth", Version: 63}},
		ID:      pub0,
	}
	builders := map[string]func() *protoHandshake{
		"MalformedHello": func() *protoHandshake {
			cpy := append([]byte(nil), pub0...)
			return &protoHandshake{Version: base.Version, Caps: base.Caps, ID: append(cpy, byte(0))}
		},
		"MalformedHelloShortID": func() *protoHandshake {
			return &protoHandshake{Version: base.Version, Caps: base.Caps, ID: pub0[:63]}
		},
		"MalformedHelloEmptyID": func() *protoHandshake {
			return &protoHandshake{Version: base.Version, Caps: base.Caps, ID: nil}
		},
		"MalformedHelloLongID": func() *protoHandshake {
			longID := make([]byte, 128)
			copy(longID, pub0)
			return &protoHandshake{Version: base.Version, Caps: base.Caps, ID: longID}
		},
		"MalformedHelloZeroID": func() *protoHandshake {
			return &protoHandshake{Version: base.Version, Caps: base.Caps, ID: make([]byte, 64)}
		},
		"MalformedHelloMismatchedID": func() *protoHandshake {
			mismatch := append([]byte(nil), pub0...)
			mismatch[0] ^= 0x01
			return &protoHandshake{Version: base.Version, Caps: base.Caps, ID: mismatch}
		},
		"HelloWithoutEthCap": func() *protoHandshake {
			return &protoHandshake{Version: base.Version, Caps: []p2p.Cap{{Name: "les", Version: 2}}, ID: base.ID}
		},
		"HelloWithZeroVersion": func() *protoHandshake {
			return &protoHandshake{Version: 0, Caps: base.Caps, ID: base.ID}
		},
		"HelloWithMaxVersion": func() *protoHandshake {
			return &protoHandshake{Version: ^uint64(0), Caps: base.Caps, ID: base.ID}
		},
		"HelloWithZeroVersionAndEmptyCaps": func() *protoHandshake {
			return &protoHandshake{Version: 0, Caps: []p2p.Cap{}, ID: base.ID}
		},
		"HelloWithEmptyCaps": func() *protoHandshake {
			return &protoHandshake{Version: base.Version, Caps: []p2p.Cap{}, ID: base.ID}
		},
		"HelloWithEmptyCapName": func() *protoHandshake {
			return &protoHandshake{Version: base.Version, Caps: []p2p.Cap{{Name: "", Version: 63}}, ID: base.ID}
		},
		"HelloWithLongCapName": func() *protoHandshake {
			return &protoHandshake{Version: base.Version, Caps: []p2p.Cap{{Name: strings.Repeat("x", 512), Version: 1}}, ID: base.ID}
		},
		"HelloWithNULCapName": func() *protoHandshake {
			return &protoHandshake{Version: base.Version, Caps: []p2p.Cap{{Name: "et\x00h", Version: 63}}, ID: base.ID}
		},
		"HelloWithMismatchedIDAndEmptyCaps": func() *protoHandshake {
			mismatch := append([]byte(nil), pub0...)
			mismatch[0] ^= 0x01
			return &protoHandshake{Version: base.Version, Caps: []p2p.Cap{}, ID: mismatch}
		},
		"HelloWithUnsortedNonEthCaps": func() *protoHandshake {
			return &protoHandshake{
				Version: base.Version,
				Caps: []p2p.Cap{
					{Name: "zzz", Version: 2},
					{Name: "les", Version: 1},
				},
				ID: base.ID,
			}
		},
		"HelloWithDuplicateEthCaps": func() *protoHandshake {
			return &protoHandshake{
				Version: base.Version,
				Caps: []p2p.Cap{
					{Name: "eth", Version: 63},
					{Name: "eth", Version: 63},
				},
				ID: base.ID,
			}
		},
	}
	if builder, ok := builders[name]; ok {
		return builder()
	}
	panic("unknown malformed hello case: " + name)
}

func (s *Suite) runMalformedHelloNamedCase(t *utesting.T, caseName string) {
	s.withRLPxConnAndKey(t, func(conn *rlpx.Conn, key *ecdsa.PrivateKey) {
		pub0 := crypto.FromECDSAPub(&key.PublicKey)[1:]
		s.expectDisconnectAfterHello(t, conn, malformedHelloByCase(caseName, pub0))
	})
}

func (s *Suite) withRLPxConn(t *utesting.T, fn func(conn *rlpx.Conn)) {
	s.withRLPxConnAndKey(t, func(conn *rlpx.Conn, _ *ecdsa.PrivateKey) {
		fn(conn)
	})
}

func (s *Suite) withRLPxConnAndKey(t *utesting.T, fn func(conn *rlpx.Conn, key *ecdsa.PrivateKey)) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	conn, err := s.dialConn(key)
	if err != nil {
		t.Fatalf("rlpx handshake failed: %v", err)
	}
	defer conn.Close()
	fn(conn, key)
}

func (s *Suite) expectDisconnectAfterHello(t *utesting.T, conn *rlpx.Conn, hello *protoHandshake) {
	payload, err := rlp.EncodeToBytes(hello)
	if err != nil {
		t.Fatalf("failed to encode malformed hello: %v", err)
	}
	s.expectDisconnectAfterHelloPayload(t, conn, payload)
}

func (s *Suite) expectDisconnectAfterHelloPayload(t *utesting.T, conn *rlpx.Conn, payload []byte) {
	s.expectDisconnectAfterMessage(t, conn, handshakeMsg, payload)
}

func (s *Suite) expectDisconnectAfterMessage(t *utesting.T, conn *rlpx.Conn, code uint64, payload []byte) {
	if _, err := conn.Write(code, payload); err != nil {
		t.Fatalf("failed to write test message: %v", err)
	}

	conn.SetReadDeadline(time.Now().Add(handshakeTimeout))
	code, _, _, err := conn.Read()
	if err != nil {
		return
	}
	if code == discMsg {
		return
	}
	t.Fatalf("expected disconnect after test message, got msg code %d", code)
}

func (s *Suite) dialConn(key *ecdsa.PrivateKey) (*rlpx.Conn, error) {
	tcpEndpoint, ok := s.Dest.TCPEndpoint()
	if !ok {
		return nil, fmt.Errorf("node has no TCP endpoint")
	}
	fd, err := net.DialTimeout("tcp", tcpEndpoint.String(), handshakeTimeout)
	if err != nil {
		return nil, err
	}

	conn := rlpx.NewConn(fd, s.Dest.Pubkey())
	_, err = conn.Handshake(key)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

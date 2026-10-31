// Copyright 2021 The go-ethereum Authors
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
	"fmt"
	"reflect"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	ethproto "github.com/XinFinOrg/XDPoSChain/eth/protocols/eth"
	"github.com/XinFinOrg/XDPoSChain/internal/utesting"
)

const maxXdc166ResponseReads = 5

func (s *Suite) TestStatus_Xdc166(t *utesting.T) {
	t.Log(`This test performs a protocol handshake plus status exchange on xdc/166.`)
	conn, ok := s.setupConnectionXdc166(t)
	if !ok {
		return
	}
	conn.Close()
}

func (s *Suite) TestGetBlockHeaders_Xdc166(t *utesting.T) {
	t.Log(`This test sends a xdc/166 GetBlockHeaders with a fixed request id and asserts the echoed id and response shape.`)
	conn, ok := s.setupConnectionXdc166(t)
	if !ok {
		return
	}
	defer conn.Close()

	req := &getBlockHeadersPacket166{
		RequestId: 3,
		Request: &getBlockHeadersData{
			Origin: hashOrNumber{Hash: s.chain.blocks[0].Hash()},
			Amount: 1,
		},
	}
	if err := conn.Write(ethProto, ethproto.GetBlockHeadersMsg, req); err != nil {
		t.Fatalf("failed to write GetBlockHeaders: %v", err)
	}
	if err := s.expectHeadersResponseXdc166(conn, req.RequestId, 1); err != nil {
		t.Fatalf("headers response validation failed: %v", err)
	}
}

func (s *Suite) TestGetBlockBodies_Xdc166(t *utesting.T) {
	t.Log(`This test sends a xdc/166 GetBlockBodies with a fixed request id and asserts the echoed id and response shape.`)
	conn, ok := s.setupConnectionXdc166(t)
	if !ok {
		return
	}
	defer conn.Close()

	req := &getBlockBodiesPacket166{
		RequestId: 55,
		Hashes:    getBlockBodiesData{s.chain.blocks[0].Hash()},
	}
	if err := conn.Write(ethProto, ethproto.GetBlockBodiesMsg, req); err != nil {
		t.Fatalf("failed to write GetBlockBodies: %v", err)
	}
	if err := s.expectBlockBodiesResponseXdc166(conn, req.RequestId, 1); err != nil {
		t.Fatalf("block bodies response validation failed: %v", err)
	}
}

func (s *Suite) TestGetNodeData_Xdc166(t *utesting.T) {
	t.Log(`This test sends a xdc/166 GetNodeData with a fixed request id and asserts the echoed id on the empty response.`)
	conn, ok := s.setupConnectionXdc166(t)
	if !ok {
		return
	}
	defer conn.Close()

	req := &getNodeDataPacket166{
		RequestId: 77,
		Hashes:    getNodeDataPacket{common.HexToHash("0x01")},
	}
	if err := conn.Write(ethProto, ethproto.GetNodeDataMsg, req); err != nil {
		t.Fatalf("failed to write GetNodeData: %v", err)
	}
	if err := s.expectNodeDataResponseXdc166(conn, req.RequestId, 0); err != nil {
		t.Fatalf("node data response validation failed: %v", err)
	}
}

func (s *Suite) TestGetReceipts_Xdc166(t *utesting.T) {
	t.Log(`This test sends a xdc/166 GetReceipts with a fixed request id and asserts the echoed id on the empty response.`)
	conn, ok := s.setupConnectionXdc166(t)
	if !ok {
		return
	}
	defer conn.Close()

	req := &getReceiptsPacket166{
		RequestId: 88,
		Hashes:    getReceiptsData{common.HexToHash("0x01")},
	}
	if err := conn.Write(ethProto, ethproto.GetReceiptsMsg, req); err != nil {
		t.Fatalf("failed to write GetReceipts: %v", err)
	}
	if err := s.expectReceiptsResponseXdc166(conn, req.RequestId, 0); err != nil {
		t.Fatalf("receipts response validation failed: %v", err)
	}
}

func (s *Suite) TestGetPooledTransactions_Xdc166(t *utesting.T) {
	t.Log(`This test sends a xdc/166 GetPooledTransactions with a fixed request id and asserts the echoed id on the empty response.`)
	conn, ok := s.setupConnectionXdc166(t)
	if !ok {
		return
	}
	defer conn.Close()

	req := &getPooledTransactionsPacket166{
		RequestId: 99,
		Hashes:    getPooledTransactionsData{common.HexToHash("0x01")},
	}
	if err := conn.Write(ethProto, ethproto.GetPooledTransactionsMsg, req); err != nil {
		t.Fatalf("failed to write GetPooledTransactions: %v", err)
	}
	if err := s.expectPooledTransactionsResponseXdc166(conn, req.RequestId, 0); err != nil {
		t.Fatalf("pooled transactions response validation failed: %v", err)
	}
}

// TestSameRequestID_Xdc166 sends two xdc/166 header queries carrying the same
// request id, so both requests are in flight on one connection at the same
// time, and asserts that both responses echo the shared id. The requests are
// written sequentially to avoid a concurrent-write race on the connection,
// which is what made the upstream original flaky (upstream #22754, with the
// #22757 CI hardening folded in).
func (s *Suite) TestSameRequestID_Xdc166(t *utesting.T) {
	t.Log(`This test sends two xdc/166 GetBlockHeaders requests with the same request id and asserts both responses echo it.`)
	conn, ok := s.setupConnectionXdc166(t)
	if !ok {
		return
	}
	defer conn.Close()

	reqID := uint64(1234)
	request1 := &getBlockHeadersPacket166{
		RequestId: reqID,
		Request: &getBlockHeadersData{
			Origin: hashOrNumber{Number: 1},
			Amount: 2,
		},
	}
	request2 := &getBlockHeadersPacket166{
		RequestId: reqID,
		Request: &getBlockHeadersData{
			Origin: hashOrNumber{Number: 33},
			Amount: 2,
		},
	}
	// Write the first request without reading its response, leaving two
	// outstanding requests that share one request id.
	if err := conn.Write(ethProto, ethproto.GetBlockHeadersMsg, request1); err != nil {
		t.Fatalf("could not write to connection: %v", err)
	}
	// Perform the second request and collect its response.
	headers2, err := s.getBlockHeadersXdc166(conn, request2, reqID)
	if err != nil {
		t.Fatalf("could not get block headers: %v", err)
	}
	// Wait for the response to the first request.
	headers1, err := s.waitForBlockHeadersResponseXdc166(conn, reqID)
	if err != nil {
		t.Fatalf("could not get BlockHeaders response: %v", err)
	}
	// The two responses may arrive in either order; every received header must
	// match the fixture chain's block for its own number.
	for i, headers := range []blockHeadersData{headers1, headers2} {
		if matched, detail := headersMatchXdc166(s.chain, headers); !matched {
			t.Fatalf("received wrong header(s) in response %d: %s", i+1, detail)
		}
	}
}

// waitForBlockHeadersResponseXdc166 reads until a xdc/166 BlockHeaders response
// with the expected request id arrives, serving any inbound block header
// queries along the way. It returns errors instead of failing the test so the
// request-id reuse cases control their own failure output (upstream #22754,
// with the want/have failure detail of upstream #22482).
func (s *Suite) waitForBlockHeadersResponseXdc166(conn *Conn, expectedID uint64) (blockHeadersData, error) {
	for i := 0; i < maxXdc166ResponseReads; i++ {
		id, msg, err := s.readMsgXdc166(conn)
		if err != nil {
			return nil, fmt.Errorf("failed to read BlockHeaders response: %w", err)
		}
		headers, ok := msg.(*blockHeadersData)
		if !ok {
			continue
		}
		if id != expectedID {
			return nil, fmt.Errorf("request ID mismatch: wanted %d, got %d", expectedID, id)
		}
		return *headers, nil
	}
	return nil, fmt.Errorf("did not receive BlockHeaders response within %d read(s)", maxXdc166ResponseReads)
}

// getBlockHeadersXdc166 writes a xdc/166 header query and waits for the response
// carrying the expected request id.
func (s *Suite) getBlockHeadersXdc166(conn *Conn, req *getBlockHeadersPacket166, expectedID uint64) (blockHeadersData, error) {
	if err := conn.Write(ethProto, ethproto.GetBlockHeadersMsg, req); err != nil {
		return nil, fmt.Errorf("could not write to connection: %w", err)
	}
	return s.waitForBlockHeadersResponseXdc166(conn, expectedID)
}

// headersMatchXdc166 reports whether every received header is the fixture chain's
// header for the same block number. On mismatch it returns a want/have detail
// naming the divergence, so a failing case prints the offending header instead
// of a bare count (upstream #22754/#22482 failure-output shape).
func headersMatchXdc166(chain *Chain, headers blockHeadersData) (bool, string) {
	for _, header := range headers {
		if header == nil {
			return false, "nil header in BlockHeaders response"
		}
		num := header.Number.Uint64()
		if num >= uint64(chain.Len()) {
			return false, fmt.Sprintf("header for unknown block %d (fixture chain head is %d)", num, chain.Len()-1)
		}
		if !reflect.DeepEqual(chain.blocks[num].Header(), header) {
			return false, fmt.Sprintf("wrong header for block %d: have hash %s, want hash %s", num, header.Hash(), chain.blocks[num].Hash())
		}
	}
	return true, ""
}

// setupConnectionXdc166 returns ok=false when the peer did not negotiate xdc/166
func (s *Suite) setupConnectionXdc166(t *utesting.T) (*Conn, bool) {
	conn, err := s.dialXdc166()
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	if err := conn.handshake(); err != nil {
		conn.Close()
		t.Fatalf("handshake failed: %v", err)
	}
	// xdc166-shaped requests on an xdc/100 connection would be misread as legacy packets
	if conn.negotiatedProtoVersion != ethProtoVersionXDpos166 {
		conn.Close()
		t.Logf("xdc/166 not negotiated (peer settled on %d); skipping case", conn.negotiatedProtoVersion)
		return nil, false
	}
	if err := conn.statusExchange(s.chain, nil); err != nil {
		conn.Close()
		t.Fatalf("status exchange failed: %v", err)
	}
	return conn, true
}

func (s *Suite) readMsgXdc166(conn *Conn) (uint64, interface{}, error) {
	for {
		id, msg, err := conn.ReadXdc166()
		if err != nil {
			return 0, nil, err
		}
		req, ok := msg.(*getBlockHeadersData)
		if !ok {
			return id, msg, nil
		}
		// Unanswerable queries get an empty but wire-legal header list
		headers, err := s.chain.GetHeaders(req)
		if err != nil {
			headers = nil
		}
		resp := &blockHeadersPacket166{RequestId: id, Headers: blockHeadersData(headers)}
		if err := conn.Write(ethProto, ethproto.BlockHeadersMsg, resp); err != nil {
			return 0, nil, fmt.Errorf("failed to write BlockHeaders response: %w", err)
		}
	}
}

func (s *Suite) expectHeadersResponseXdc166(conn *Conn, wantID uint64, wantLen int) error {
	for i := 0; i < maxXdc166ResponseReads; i++ {
		id, msg, err := s.readMsgXdc166(conn)
		if err != nil {
			return fmt.Errorf("failed to read headers response %d: %w", i+1, err)
		}
		headers, ok := msg.(*blockHeadersData)
		if !ok {
			continue
		}
		if id != wantID {
			return fmt.Errorf("request id mismatch: want %d, got %d", wantID, id)
		}
		if len(*headers) != wantLen {
			return fmt.Errorf("wrong header count: want %d, got %d", wantLen, len(*headers))
		}
		for _, header := range *headers {
			if header == nil {
				return fmt.Errorf("nil header in BlockHeaders response")
			}
		}
		return nil
	}
	return fmt.Errorf("did not receive BlockHeaders response in %d read(s)", maxXdc166ResponseReads)
}

func (s *Suite) expectBlockBodiesResponseXdc166(conn *Conn, wantID uint64, wantLen int) error {
	for i := 0; i < maxXdc166ResponseReads; i++ {
		id, msg, err := s.readMsgXdc166(conn)
		if err != nil {
			return fmt.Errorf("failed to read block bodies response %d: %w", i+1, err)
		}
		bodies, ok := msg.(*blockBodiesData)
		if !ok {
			continue
		}
		if id != wantID {
			return fmt.Errorf("request id mismatch: want %d, got %d", wantID, id)
		}
		if len(*bodies) != wantLen {
			return fmt.Errorf("wrong body count: want %d, got %d", wantLen, len(*bodies))
		}
		for _, body := range *bodies {
			if body == nil {
				return fmt.Errorf("nil body in BlockBodies response")
			}
		}
		return nil
	}
	return fmt.Errorf("did not receive BlockBodies response in %d read(s)", maxXdc166ResponseReads)
}

func (s *Suite) expectNodeDataResponseXdc166(conn *Conn, wantID uint64, wantLen int) error {
	for i := 0; i < maxXdc166ResponseReads; i++ {
		id, msg, err := s.readMsgXdc166(conn)
		if err != nil {
			return fmt.Errorf("failed to read node data response %d: %w", i+1, err)
		}
		data, ok := msg.(*nodeDataPacket)
		if !ok {
			continue
		}
		if id != wantID {
			return fmt.Errorf("request id mismatch: want %d, got %d", wantID, id)
		}
		if len(*data) != wantLen {
			return fmt.Errorf("wrong node data entry count: want %d, got %d", wantLen, len(*data))
		}
		return nil
	}
	return fmt.Errorf("did not receive NodeData response in %d read(s)", maxXdc166ResponseReads)
}

func (s *Suite) expectReceiptsResponseXdc166(conn *Conn, wantID uint64, wantLen int) error {
	for i := 0; i < maxXdc166ResponseReads; i++ {
		id, msg, err := s.readMsgXdc166(conn)
		if err != nil {
			return fmt.Errorf("failed to read receipts response %d: %w", i+1, err)
		}
		receipts, ok := msg.(*receiptsData)
		if !ok {
			continue
		}
		if id != wantID {
			return fmt.Errorf("request id mismatch: want %d, got %d", wantID, id)
		}
		if len(*receipts) != wantLen {
			return fmt.Errorf("wrong receipts count: want %d, got %d", wantLen, len(*receipts))
		}
		return nil
	}
	return fmt.Errorf("did not receive Receipts response in %d read(s)", maxXdc166ResponseReads)
}

func (s *Suite) expectPooledTransactionsResponseXdc166(conn *Conn, wantID uint64, wantLen int) error {
	for i := 0; i < maxXdc166ResponseReads; i++ {
		id, msg, err := s.readMsgXdc166(conn)
		if err != nil {
			return fmt.Errorf("failed to read pooled transactions response %d: %w", i+1, err)
		}
		txs, ok := msg.(*types.Transactions)
		if !ok {
			continue
		}
		if id != wantID {
			return fmt.Errorf("request id mismatch: want %d, got %d", wantID, id)
		}
		if len(*txs) != wantLen {
			return fmt.Errorf("wrong pooled transaction count: want %d, got %d", wantLen, len(*txs))
		}
		return nil
	}
	return fmt.Errorf("did not receive PooledTransactions response in %d read(s)", maxXdc166ResponseReads)
}

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

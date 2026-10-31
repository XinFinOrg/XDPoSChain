package ethtest

import (
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	ethproto "github.com/XinFinOrg/XDPoSChain/eth/protocols/eth"
	"github.com/XinFinOrg/XDPoSChain/rlp"
)

func TestEth66RequestPacketsMatchWireDialect(t *testing.T) {
	hash := common.HexToHash("0x1234")

	b, err := rlp.EncodeToBytes(&getBlockHeadersPacket66{
		RequestId: 3,
		Request: &getBlockHeadersData{
			Origin: hashOrNumber{Hash: hash},
			Amount: 2,
			Skip:   1,
		},
	})
	if err != nil {
		t.Fatalf("failed to encode GetBlockHeaders66 packet: %v", err)
	}
	var wireHeadersReq ethproto.GetBlockHeadersPacket66
	if err := rlp.DecodeBytes(b, &wireHeadersReq); err != nil {
		t.Fatalf("node wire layer rejected GetBlockHeaders66 packet: %v", err)
	}
	if wireHeadersReq.RequestId != 3 || wireHeadersReq.GetBlockHeadersPacket == nil ||
		wireHeadersReq.Origin.Hash != hash || wireHeadersReq.Amount != 2 || wireHeadersReq.Skip != 1 {
		t.Fatalf("GetBlockHeaders66 packet mismatch: have %+v", wireHeadersReq)
	}

	b, err = rlp.EncodeToBytes(&getBlockBodiesPacket66{
		RequestId: 55,
		Hashes:    getBlockBodiesData{hash},
	})
	if err != nil {
		t.Fatalf("failed to encode GetBlockBodies66 packet: %v", err)
	}
	var wireBodiesReq ethproto.GetBlockBodiesPacket66
	if err := rlp.DecodeBytes(b, &wireBodiesReq); err != nil {
		t.Fatalf("node wire layer rejected GetBlockBodies66 packet: %v", err)
	}
	if wireBodiesReq.RequestId != 55 || len(wireBodiesReq.GetBlockBodiesPacket) != 1 || wireBodiesReq.GetBlockBodiesPacket[0] != hash {
		t.Fatalf("GetBlockBodies66 packet mismatch: have %+v", wireBodiesReq)
	}

	b, err = rlp.EncodeToBytes(&getNodeDataPacket66{
		RequestId: 77,
		Hashes:    getNodeDataPacket{hash},
	})
	if err != nil {
		t.Fatalf("failed to encode GetNodeData66 packet: %v", err)
	}
	var wireNodeDataReq ethproto.GetNodeDataPacket66
	if err := rlp.DecodeBytes(b, &wireNodeDataReq); err != nil {
		t.Fatalf("node wire layer rejected GetNodeData66 packet: %v", err)
	}
	if wireNodeDataReq.RequestId != 77 || len(wireNodeDataReq.GetNodeDataPacket) != 1 || wireNodeDataReq.GetNodeDataPacket[0] != hash {
		t.Fatalf("GetNodeData66 packet mismatch: have %+v", wireNodeDataReq)
	}

	b, err = rlp.EncodeToBytes(&getReceiptsPacket66{
		RequestId: 88,
		Hashes:    getReceiptsData{hash},
	})
	if err != nil {
		t.Fatalf("failed to encode GetReceipts66 packet: %v", err)
	}
	var wireReceiptsReq ethproto.GetReceiptsPacket66
	if err := rlp.DecodeBytes(b, &wireReceiptsReq); err != nil {
		t.Fatalf("node wire layer rejected GetReceipts66 packet: %v", err)
	}
	if wireReceiptsReq.RequestId != 88 || len(wireReceiptsReq.GetReceiptsPacket) != 1 || wireReceiptsReq.GetReceiptsPacket[0] != hash {
		t.Fatalf("GetReceipts66 packet mismatch: have %+v", wireReceiptsReq)
	}

	b, err = rlp.EncodeToBytes(&getPooledTransactionsPacket66{
		RequestId: 99,
		Hashes:    getPooledTransactionsData{hash},
	})
	if err != nil {
		t.Fatalf("failed to encode GetPooledTransactions66 packet: %v", err)
	}
	var wirePooledReq ethproto.GetPooledTransactionsPacket66
	if err := rlp.DecodeBytes(b, &wirePooledReq); err != nil {
		t.Fatalf("node wire layer rejected GetPooledTransactions66 packet: %v", err)
	}
	if wirePooledReq.RequestId != 99 || len(wirePooledReq.GetPooledTransactionsPacket) != 1 || wirePooledReq.GetPooledTransactionsPacket[0] != hash {
		t.Fatalf("GetPooledTransactions66 packet mismatch: have %+v", wirePooledReq)
	}
}

func TestEth66ResponsesDecodeWireDialect(t *testing.T) {
	headers := ethproto.BlockHeadersPacket{{Number: big.NewInt(1)}}
	b, err := rlp.EncodeToBytes(&ethproto.BlockHeadersPacket66{RequestId: 7, BlockHeadersPacket: headers})
	if err != nil {
		t.Fatalf("failed to encode BlockHeaders66 packet: %v", err)
	}
	id, msg, err := decodeEthPayload66(ethproto.BlockHeadersMsg, b)
	if err != nil {
		t.Fatalf("failed to decode BlockHeaders66 payload: %v", err)
	}
	gotHeaders, ok := msg.(*blockHeadersData)
	if !ok {
		t.Fatalf("wrong BlockHeaders payload type: %T", msg)
	}
	if id != 7 || len(*gotHeaders) != 1 || (*gotHeaders)[0].Number.Uint64() != 1 {
		t.Fatalf("BlockHeaders66 payload mismatch: id %d, have %+v", id, *gotHeaders)
	}

	rawBody, err := rlp.EncodeToBytes(&blockBody{Transactions: types.Transactions{}, Uncles: []*types.Header{}})
	if err != nil {
		t.Fatalf("failed to encode block body: %v", err)
	}
	b, err = rlp.EncodeToBytes(&ethproto.BlockBodiesRLPPacket66{
		RequestId:            8,
		BlockBodiesRLPPacket: ethproto.BlockBodiesRLPPacket{rawBody},
	})
	if err != nil {
		t.Fatalf("failed to encode BlockBodies66 packet: %v", err)
	}
	id, msg, err = decodeEthPayload66(ethproto.BlockBodiesMsg, b)
	if err != nil {
		t.Fatalf("failed to decode BlockBodies66 payload: %v", err)
	}
	gotBodies, ok := msg.(*blockBodiesData)
	if !ok {
		t.Fatalf("wrong BlockBodies payload type: %T", msg)
	}
	if id != 8 || len(*gotBodies) != 1 || len((*gotBodies)[0].Transactions) != 0 || len((*gotBodies)[0].Uncles) != 0 {
		t.Fatalf("BlockBodies66 payload mismatch: id %d, have %+v", id, *gotBodies)
	}

	b, err = rlp.EncodeToBytes(&ethproto.NodeDataPacket66{
		RequestId:      0,
		NodeDataPacket: ethproto.NodeDataPacket{{0xaa, 0xbb}},
	})
	if err != nil {
		t.Fatalf("failed to encode NodeData66 packet: %v", err)
	}
	id, msg, err = decodeEthPayload66(ethproto.NodeDataMsg, b)
	if err != nil {
		t.Fatalf("failed to decode NodeData66 payload: %v", err)
	}
	gotNodeData, ok := msg.(*nodeDataPacket)
	if !ok {
		t.Fatalf("wrong NodeData payload type: %T", msg)
	}
	if id != 0 || len(*gotNodeData) != 1 || len((*gotNodeData)[0]) != 2 {
		t.Fatalf("NodeData66 payload mismatch: id %d, have %+v", id, *gotNodeData)
	}

	rawReceipts, err := rlp.EncodeToBytes(types.Receipts{})
	if err != nil {
		t.Fatalf("failed to encode receipts: %v", err)
	}
	b, err = rlp.EncodeToBytes(&ethproto.ReceiptsRLPPacket66{
		RequestId:         10,
		ReceiptsRLPPacket: ethproto.ReceiptsRLPPacket{rawReceipts},
	})
	if err != nil {
		t.Fatalf("failed to encode Receipts66 packet: %v", err)
	}
	id, msg, err = decodeEthPayload66(ethproto.ReceiptsMsg, b)
	if err != nil {
		t.Fatalf("failed to decode Receipts66 payload: %v", err)
	}
	gotReceipts, ok := msg.(*receiptsData)
	if !ok {
		t.Fatalf("wrong Receipts payload type: %T", msg)
	}
	if id != 10 || len(*gotReceipts) != 1 || len((*gotReceipts)[0]) != 0 {
		t.Fatalf("Receipts66 payload mismatch: id %d, have %+v", id, *gotReceipts)
	}

	tx := types.NewTransaction(1, common.HexToAddress("0xaa"), big.NewInt(1), 21000, big.NewInt(1), nil)
	rawTx, err := rlp.EncodeToBytes(tx)
	if err != nil {
		t.Fatalf("failed to encode transaction: %v", err)
	}
	b, err = rlp.EncodeToBytes(&ethproto.PooledTransactionsRLPPacket66{
		RequestId:                   11,
		PooledTransactionsRLPPacket: ethproto.PooledTransactionsRLPPacket{rawTx},
	})
	if err != nil {
		t.Fatalf("failed to encode PooledTransactions66 packet: %v", err)
	}
	id, msg, err = decodeEthPayload66(ethproto.PooledTransactionsMsg, b)
	if err != nil {
		t.Fatalf("failed to decode PooledTransactions66 payload: %v", err)
	}
	gotTxs, ok := msg.(*types.Transactions)
	if !ok {
		t.Fatalf("wrong PooledTransactions payload type: %T", msg)
	}
	if id != 11 || len(*gotTxs) != 1 || (*gotTxs)[0].Hash() != tx.Hash() {
		t.Fatalf("PooledTransactions66 payload mismatch: id %d, have %+v", id, *gotTxs)
	}
}

func TestEth66DecodeRejectsLegacyShape(t *testing.T) {
	headers := blockHeadersData{{Number: big.NewInt(1)}}
	b, err := rlp.EncodeToBytes(&headers)
	if err != nil {
		t.Fatalf("failed to encode legacy headers payload: %v", err)
	}
	if _, _, err := decodeEthPayload66(ethproto.BlockHeadersMsg, b); err == nil {
		t.Fatal("expected legacy-shaped BlockHeaders payload to fail 66 decode")
	}
}

package ethtest

import (
	"fmt"
	"io"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/rlp"
)

type getBlockHeadersData struct {
	Origin  hashOrNumber
	Amount  uint64
	Skip    uint64
	Reverse bool
}

type blockHeadersData []*types.Header

type getBlockBodiesData []common.Hash

type blockBody struct {
	Transactions []*types.Transaction
	Uncles       []*types.Header
}

type blockBodiesData []*blockBody

type getReceiptsData []common.Hash

type receiptsData []types.Receipts

type getNodeDataPacket []common.Hash

type nodeDataPacket [][]byte

type getPooledTransactionsData []common.Hash

// Payload fields must stay exported; rlp drops embedded unexported fields

type getBlockHeadersPacket66 struct {
	RequestId uint64
	Request   *getBlockHeadersData
}

type blockHeadersPacket66 struct {
	RequestId uint64
	Headers   blockHeadersData
}

type getBlockBodiesPacket66 struct {
	RequestId uint64
	Hashes    getBlockBodiesData
}

type blockBodiesPacket66 struct {
	RequestId uint64
	Bodies    blockBodiesData
}

type getNodeDataPacket66 struct {
	RequestId uint64
	Hashes    getNodeDataPacket
}

type nodeDataPacket66 struct {
	RequestId uint64
	Data      nodeDataPacket
}

type getReceiptsPacket66 struct {
	RequestId uint64
	Hashes    getReceiptsData
}

type receiptsPacket66 struct {
	RequestId uint64
	Receipts  receiptsData
}

type getPooledTransactionsPacket66 struct {
	RequestId uint64
	Hashes    getPooledTransactionsData
}

type pooledTransactionsPacket66 struct {
	RequestId uint64
	Txs       types.Transactions
}

// hashOrNumber is a union for specifying header request origin.
type hashOrNumber struct {
	Hash   common.Hash
	Number uint64
}

// EncodeRLP encodes either hash or number (but never both) for origin.
func (hn *hashOrNumber) EncodeRLP(w io.Writer) error {
	if hn.Hash == (common.Hash{}) {
		return rlp.Encode(w, hn.Number)
	}
	if hn.Number != 0 {
		return fmt.Errorf("both origin hash (%x) and number (%d) provided", hn.Hash, hn.Number)
	}
	return rlp.Encode(w, hn.Hash)
}

// DecodeRLP decodes origin into either hash or number depending on RLP item size.
func (hn *hashOrNumber) DecodeRLP(s *rlp.Stream) error {
	_, size, _ := s.Kind()
	origin, err := s.Raw()
	if err != nil {
		return err
	}
	switch {
	case size == 32:
		return rlp.DecodeBytes(origin, &hn.Hash)
	case size <= 8:
		return rlp.DecodeBytes(origin, &hn.Number)
	default:
		return fmt.Errorf("invalid input size %d for origin", size)
	}
}

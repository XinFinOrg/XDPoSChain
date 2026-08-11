package ethtest

import (
	"fmt"
	"io"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/rlp"
)

// getBlockHeadersData represents a block header query payload for eth protocol.
type getBlockHeadersData struct {
	Origin  hashOrNumber
	Amount  uint64
	Skip    uint64
	Reverse bool
}

// blockHeadersData represents a list of block header payloads.
type blockHeadersData []*types.Header

// getBlockBodiesData represents a block body query payload for eth protocol.
type getBlockBodiesData []common.Hash

// blockBody represents a block body payload in response.
type blockBody struct {
	Transactions []*types.Transaction
	Uncles       []*types.Header
}

// blockBodiesData represents a list of block body payloads.
type blockBodiesData []*blockBody

// getReceiptsData represents a receipts query payload for eth protocol.
type getReceiptsData []common.Hash

// receiptsData represents a receipts response list aligned to requested blocks.
type receiptsData []types.Receipts

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

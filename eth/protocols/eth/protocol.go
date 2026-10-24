// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package eth

import (
	"fmt"
	"io"
	"math/big"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/forkid"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/rlp"
)

// Constants to match up protocol versions and messages
const (
	XDC100 = 100
	XDC164 = 164 // eth64
	XDC165 = 165 // eth65
)

// ProtocolName is the official short name of the protocol used during capability
// negotiation.
//
// Upstream go-ethereum made the name, version and length tables private in the
// commit that introduced this package. They stay exported here as a seam for a
// later alignment pass. Nothing outside this package consumes ProtocolName
// today: the devp2p test client deliberately keeps its own copy of the wire
// facts (see cmd/devp2p/internal/ethtest/protocol.go), so a change here does
// not reach it.
const ProtocolName = "eth"

// ProtocolVersions are the supported versions of the eth protocol (first is primary).
//
// The order is part of the wire contract: the first entry is the version the
// node prefers during capability negotiation.
var ProtocolVersions = []uint{XDC165, XDC164, XDC100}

// ProtocolLengths are the number of implemented messages corresponding to the
// different protocol versions.
//
// These are message-code space bounds, not message counts: the bound covers the
// XDC BFT codes (0xe0-0xe2) and the pooled transaction codes (0xe3-0xe5).
var ProtocolLengths = map[uint]uint64{XDC165: 230, XDC164: 227, XDC100: 227}

const protocolMaxMsgSize = 10 * 1024 * 1024 // Maximum cap on the size of a protocol message

// eth protocol message codes
//
// The XDC layout deliberately diverges from upstream: OrderTxMsg and LendingTxMsg
// occupy 0x08 and 0x09 (upstream puts the pooled transaction trio there), and the
// transaction broadcast message keeps its pre-split name TransactionMsg. Both are
// recorded here for a later alignment pass; changing either would be a wire change.
const (
	StatusMsg          = 0x00
	NewBlockHashesMsg  = 0x01
	TransactionMsg     = 0x02
	GetBlockHeadersMsg = 0x03
	BlockHeadersMsg    = 0x04
	GetBlockBodiesMsg  = 0x05
	BlockBodiesMsg     = 0x06
	NewBlockMsg        = 0x07
	OrderTxMsg         = 0x08
	LendingTxMsg       = 0x09
	GetNodeDataMsg     = 0x0d
	NodeDataMsg        = 0x0e
	GetReceiptsMsg     = 0x0f
	ReceiptsMsg        = 0x10

	// Protocol message codes introduced in xdc/100
	VoteMsg     = 0xe0
	TimeoutMsg  = 0xe1
	SyncInfoMsg = 0xe2

	// Protocol message codes introduced in xdc/165
	NewPooledTransactionHashesMsg = 0xe3
	GetPooledTransactionsMsg      = 0xe4
	PooledTransactionsMsg         = 0xe5
)

type errCode int

const (
	ErrMsgTooLarge = iota
	ErrDecode
	ErrInvalidMsgCode
	ErrProtocolVersionMismatch
	ErrNetworkIDMismatch
	ErrGenesisMismatch
	ErrForkIDRejected
	ErrNoStatusMsg
	ErrExtraStatusMsg
)

func (e errCode) String() string {
	return errorToString[int(e)]
}

// XXX change once legacy code is out
var errorToString = map[int]string{
	ErrMsgTooLarge:             "Message too long",
	ErrDecode:                  "Invalid message",
	ErrInvalidMsgCode:          "Invalid message code",
	ErrProtocolVersionMismatch: "Protocol version mismatch",
	ErrNetworkIDMismatch:       "Network ID mismatch",
	ErrGenesisMismatch:         "Genesis mismatch",
	ErrForkIDRejected:          "Fork ID rejected",
	ErrNoStatusMsg:             "No status message",
	ErrExtraStatusMsg:          "Extra status message",
}

// Packet represents a p2p message in the `eth` protocol.
type Packet interface {
	Name() string // Name returns a string corresponding to the message type.
	Kind() byte   // Kind returns the message type.
}

// StatusPacket is the network packet for the status message for eth/64, xdc/164
// and later.
type StatusPacket struct {
	ProtocolVersion uint32
	NetworkID       uint64
	TD              *big.Int
	Head            common.Hash
	Genesis         common.Hash
	ForkID          forkid.ID
}

// Name implements Packet.
func (p *StatusPacket) Name() string { return "Status" }

// Kind implements Packet.
func (p *StatusPacket) Kind() byte { return StatusMsg }

// StatusPacket100 is the network packet for the status message for xdc/100. It
// has no upstream counterpart: the older XDC version predates the forkid field.
type StatusPacket100 struct {
	ProtocolVersion uint32
	NetworkId       uint64
	TD              *big.Int
	CurrentBlock    common.Hash
	GenesisBlock    common.Hash
}

// Name implements Packet.
func (p *StatusPacket100) Name() string { return "Status" }

// Kind implements Packet.
func (p *StatusPacket100) Kind() byte { return StatusMsg }

// NewBlockHashesPacket is the network packet for the block announcements.
type NewBlockHashesPacket []struct {
	Hash   common.Hash // Hash of one particular block being announced
	Number uint64      // Number of one particular block being announced
}

// Name implements Packet.
func (p *NewBlockHashesPacket) Name() string { return "NewBlockHashes" }

// Kind implements Packet.
func (p *NewBlockHashesPacket) Kind() byte { return NewBlockHashesMsg }

// TransactionsPacket is the network packet for broadcasting new transactions.
type TransactionsPacket []*types.Transaction

// Name implements Packet.
func (p *TransactionsPacket) Name() string { return "Transaction" }

// Kind implements Packet.
func (p *TransactionsPacket) Kind() byte { return TransactionMsg }

// sanityCheck verifies that the packet carries no nil transaction, as a peer
// sending one must be dropped instead of crashing the transaction handling.
func (p TransactionsPacket) sanityCheck() error {
	for i, tx := range p {
		if tx == nil {
			return fmt.Errorf("transaction %d is nil", i)
		}
	}
	return nil
}

// GetBlockHeadersPacket represents a block header query.
type GetBlockHeadersPacket struct {
	Origin  HashOrNumber // Block from which to retrieve headers
	Amount  uint64       // Maximum number of headers to retrieve
	Skip    uint64       // Blocks to skip between consecutive headers
	Reverse bool         // Query direction (false = rising towards latest, true = falling towards genesis)
}

// Name implements Packet.
func (p *GetBlockHeadersPacket) Name() string { return "GetBlockHeaders" }

// Kind implements Packet.
func (p *GetBlockHeadersPacket) Kind() byte { return GetBlockHeadersMsg }

// HashOrNumber is a combined field for specifying an origin block.
type HashOrNumber struct {
	Hash   common.Hash // Block hash from which to retrieve headers (excludes Number)
	Number uint64      // Block hash from which to retrieve headers (excludes Hash)
}

// EncodeRLP is a specialized encoder for HashOrNumber to encode only one of the
// two contained union fields.
func (hn *HashOrNumber) EncodeRLP(w io.Writer) error {
	if hn.Hash == (common.Hash{}) {
		return rlp.Encode(w, hn.Number)
	}
	if hn.Number != 0 {
		return fmt.Errorf("both origin hash (%x) and number (%d) provided", hn.Hash, hn.Number)
	}
	return rlp.Encode(w, hn.Hash)
}

// DecodeRLP is a specialized decoder for HashOrNumber to decode the contents
// into either a block hash or a block number.
func (hn *HashOrNumber) DecodeRLP(s *rlp.Stream) error {
	_, size, _ := s.Kind()
	origin, err := s.Raw()
	if err == nil {
		switch {
		case size == 32:
			err = rlp.DecodeBytes(origin, &hn.Hash)
		case size <= 8:
			err = rlp.DecodeBytes(origin, &hn.Number)
		default:
			err = fmt.Errorf("invalid input size %d for origin", size)
		}
	}
	return err
}

// BlockHeadersPacket is the network packet for the block headers response, and
// for the batch of headers arriving to one of our previous requests.
type BlockHeadersPacket []*types.Header

// Name implements Packet.
func (p *BlockHeadersPacket) Name() string { return "BlockHeaders" }

// Kind implements Packet.
func (p *BlockHeadersPacket) Kind() byte { return BlockHeadersMsg }

// NewBlockPacket is the network packet for the block propagation message.
type NewBlockPacket struct {
	Block *types.Block
	TD    *big.Int
}

// Name implements Packet.
func (p *NewBlockPacket) Name() string { return "NewBlock" }

// Kind implements Packet.
func (p *NewBlockPacket) Kind() byte { return NewBlockMsg }

// sanityCheck verifies that the values are reasonable, as a DoS protection.
func (p *NewBlockPacket) sanityCheck() error {
	if err := p.Block.SanityCheck(); err != nil {
		return err
	}
	// TD is 34 bits at mainnet block 105048538
	// TD is 32 bits at testnet block 84385810.
	// If it becomes 100 million times larger, it will still fit within 100 bits.
	if tdlen := p.TD.BitLen(); tdlen > 100 {
		return fmt.Errorf("too large block TD: bitlen %d", tdlen)
	}
	return nil
}

// GetBlockBodiesPacket represents a block body query.
type GetBlockBodiesPacket []common.Hash

// Name implements Packet.
func (p *GetBlockBodiesPacket) Name() string { return "GetBlockBodies" }

// Kind implements Packet.
func (p *GetBlockBodiesPacket) Kind() byte { return GetBlockBodiesMsg }

// BlockBody represents the data content of a single block.
type BlockBody struct {
	Transactions []*types.Transaction // Transactions contained within a block
	Uncles       []*types.Header      // Uncles contained within a block
}

// BlockBodiesPacket is the network packet for block content distribution.
type BlockBodiesPacket []*BlockBody

// Name implements Packet.
func (p *BlockBodiesPacket) Name() string { return "BlockBodies" }

// Kind implements Packet.
func (p *BlockBodiesPacket) Kind() byte { return BlockBodiesMsg }

// sanityCheck verifies that the uncle headers are reasonable, as a DoS protection.
func (p BlockBodiesPacket) sanityCheck() error {
	for bodyIndex, body := range p {
		if body == nil {
			return fmt.Errorf("nil block body at index %d", bodyIndex)
		}
		if err := types.SanityCheckHeaders(body.Uncles); err != nil {
			return err
		}
	}
	return nil
}

// GetNodeDataPacket represents a trie node data query.
type GetNodeDataPacket []common.Hash

// Name implements Packet.
func (p *GetNodeDataPacket) Name() string { return "GetNodeData" }

// Kind implements Packet.
func (p *GetNodeDataPacket) Kind() byte { return GetNodeDataMsg }

// NodeDataPacket is the network packet for the state data response.
type NodeDataPacket [][]byte

// Name implements Packet.
func (p *NodeDataPacket) Name() string { return "NodeData" }

// Kind implements Packet.
func (p *NodeDataPacket) Kind() byte { return NodeDataMsg }

// GetReceiptsPacket represents a block receipts query.
type GetReceiptsPacket []common.Hash

// Name implements Packet.
func (p *GetReceiptsPacket) Name() string { return "GetReceipts" }

// Kind implements Packet.
func (p *GetReceiptsPacket) Kind() byte { return GetReceiptsMsg }

// ReceiptsPacket is the network packet for the receipts response, decoded as one
// receipt list per requested block.
type ReceiptsPacket [][]*types.Receipt

// Name implements Packet.
func (p *ReceiptsPacket) Name() string { return "Receipts" }

// Kind implements Packet.
func (p *ReceiptsPacket) Kind() byte { return ReceiptsMsg }

// NewPooledTransactionHashesPacket is the network packet for the transaction
// announcement.
type NewPooledTransactionHashesPacket []common.Hash

// Name implements Packet.
func (p *NewPooledTransactionHashesPacket) Name() string { return "NewPooledTransactionHashes" }

// Kind implements Packet.
func (p *NewPooledTransactionHashesPacket) Kind() byte { return NewPooledTransactionHashesMsg }

// GetPooledTransactionsPacket is the network packet for the transaction query.
type GetPooledTransactionsPacket []common.Hash

// Name implements Packet.
func (p *GetPooledTransactionsPacket) Name() string { return "GetPooledTransactions" }

// Kind implements Packet.
func (p *GetPooledTransactionsPacket) Kind() byte { return GetPooledTransactionsMsg }

// PooledTransactionsPacket is the network packet for the transaction response.
//
// Responses are sent from already encoded transactions (see
// SendPooledTransactionsRLP), but the inbound side decodes the full transactions,
// which is what the node layer acts on.
type PooledTransactionsPacket []*types.Transaction

// Name implements Packet.
func (p *PooledTransactionsPacket) Name() string { return "PooledTransactions" }

// Kind implements Packet.
func (p *PooledTransactionsPacket) Kind() byte { return PooledTransactionsMsg }

// sanityCheck verifies that the packet carries no nil transaction, as a peer
// sending one must be dropped instead of crashing the transaction handling.
func (p PooledTransactionsPacket) sanityCheck() error {
	for i, tx := range p {
		if tx == nil {
			return fmt.Errorf("transaction %d is nil", i)
		}
	}
	return nil
}

// OrderTransactionsPacket is the network packet for the order transaction
// propagation and response messages.
type OrderTransactionsPacket []*types.OrderTransaction

// Name implements Packet.
func (p *OrderTransactionsPacket) Name() string { return "OrderTransactions" }

// Kind implements Packet.
func (p *OrderTransactionsPacket) Kind() byte { return OrderTxMsg }

// sanityCheck verifies that the packet carries no nil transaction, as a peer
// sending one must be dropped instead of crashing the transaction handling.
func (p OrderTransactionsPacket) sanityCheck() error {
	for i, tx := range p {
		if tx == nil {
			return fmt.Errorf("transaction %d is nil", i)
		}
	}
	return nil
}

// LendingTransactionsPacket is the network packet for the lending transaction
// propagation and response messages.
type LendingTransactionsPacket []*types.LendingTransaction

// Name implements Packet.
func (p *LendingTransactionsPacket) Name() string { return "LendingTransactions" }

// Kind implements Packet.
func (p *LendingTransactionsPacket) Kind() byte { return LendingTxMsg }

// sanityCheck verifies that the packet carries no nil transaction, as a peer
// sending one must be dropped instead of crashing the transaction handling.
func (p LendingTransactionsPacket) sanityCheck() error {
	for i, tx := range p {
		if tx == nil {
			return fmt.Errorf("transaction %d is nil", i)
		}
	}
	return nil
}

// VotePacket is the network packet for the BFT vote message.
type VotePacket types.Vote

// Name implements Packet.
func (p *VotePacket) Name() string { return "Vote" }

// Kind implements Packet.
func (p *VotePacket) Kind() byte { return VoteMsg }

// TimeoutPacket is the network packet for the BFT timeout message.
type TimeoutPacket types.Timeout

// Name implements Packet.
func (p *TimeoutPacket) Name() string { return "Timeout" }

// Kind implements Packet.
func (p *TimeoutPacket) Kind() byte { return TimeoutMsg }

// SyncInfoPacket is the network packet for the BFT sync info message.
type SyncInfoPacket types.SyncInfo

// Name implements Packet.
func (p *SyncInfoPacket) Name() string { return "SyncInfo" }

// Kind implements Packet.
func (p *SyncInfoPacket) Kind() byte { return SyncInfoMsg }

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
	"bytes"
	"math/big"
	"reflect"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/forkid"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/XinFinOrg/XDPoSChain/rlp"
)

// TestProtocolRegistration locks the capability-level wire invariants at the
// p2p.Protocol registration seam: the capability name, the version numbers and
// their order, and the message-code space bound of each version.
func TestProtocolRegistration(t *testing.T) {
	backend := newTestBackend(t, 0, nil)
	protos := MakeProtocols(backend)

	want := []struct {
		version uint
		length  uint64
	}{
		{XDC166, 230},
		{XDC165, 230},
		{XDC164, 227},
		{XDC100, 227},
	}
	if len(protos) != len(want) {
		t.Fatalf("protocol count mismatch: have %d, want %d", len(protos), len(want))
	}
	for i, proto := range protos {
		if proto.Name != "eth" {
			t.Errorf("protocol %d: name mismatch: have %q, want %q", i, proto.Name, "eth")
		}
		if proto.Version != want[i].version {
			t.Errorf("protocol %d: version mismatch: have %d, want %d", i, proto.Version, want[i].version)
		}
		if proto.Length != want[i].length {
			t.Errorf("protocol %d: length mismatch: have %d, want %d", i, proto.Length, want[i].length)
		}
		// The ENR attributes are set from inside the protocol construction, so
		// the node layer never has to touch them.
		if len(proto.Attributes) != 1 {
			t.Fatalf("protocol %d: attribute count mismatch: have %d, want 1", i, len(proto.Attributes))
		}
		if key := proto.Attributes[0].ENRKey(); key != "eth" {
			t.Errorf("protocol %d: ENR key mismatch: have %q, want %q", i, key, "eth")
		}
	}
	// The exported tables are the same facts the registration uses.
	if !reflect.DeepEqual(ProtocolVersions, []uint{XDC166, XDC165, XDC164, XDC100}) {
		t.Errorf("protocol versions mismatch: have %v", ProtocolVersions)
	}
	for _, version := range ProtocolVersions {
		if ProtocolLengths[version] == 0 {
			t.Errorf("protocol %d has no length declared", version)
		}
	}
}

// TestPacketRoundTrips checks that every packet the capability sends survives an
// encode/decode cycle unchanged, and declares the message code it travels under.
func TestPacketRoundTrips(t *testing.T) {
	// Build a chain with one transaction-carrying block, so receipts and bodies
	// are real payloads rather than empty ones.
	backend := newTestBackend(t, 1, func(i int, block *core.BlockGen) {
		fee := block.BaseFee()
		if fee == nil {
			fee = big.NewInt(params.InitialBaseFee)
		}
		tx, _ := types.SignTx(types.NewTransaction(block.TxNonce(testBank), common.Address{}, big.NewInt(1), params.TxGas, fee, nil), types.HomesteadSigner{}, testBankKey)
		block.AddTx(tx)
	})
	block := backend.chain.GetBlockByNumber(1)
	header := block.Header()
	receipts := backend.chain.GetReceiptsByHash(block.Hash())
	orderTx := types.NewOrderTransaction(1, big.NewInt(1), big.NewInt(1), common.Address{}, common.Address{}, common.Address{}, common.Address{}, "status", "side", "type", common.Hash{}, 1)
	lendingTx := types.NewLendingTransaction(1, big.NewInt(1), 1, 1, common.Address{}, common.Address{}, common.Address{}, common.Address{}, false, "status", "side", "type", common.Hash{}, 1, 1, "")
	vote := types.Vote{
		ProposedBlockInfo: &types.BlockInfo{Hash: common.Hash{0x01}, Round: 2, Number: big.NewInt(3)},
		Signature:         types.Signature{0x04},
		GapNumber:         5,
	}
	timeout := types.Timeout{Round: 2, Signature: types.Signature{0x03}, GapNumber: 4}
	syncInfo := types.SyncInfo{
		HighestQuorumCert:  &types.QuorumCert{ProposedBlockInfo: &types.BlockInfo{Hash: common.Hash{0x02}, Round: 1, Number: big.NewInt(2)}, Signatures: []types.Signature{{0x05}}},
		HighestTimeoutCert: &types.TimeoutCert{Round: 3, Signatures: []types.Signature{{0x06}}},
	}
	var (
		hash       = common.Hash{0x07}
		headers    = BlockHeadersPacket{header}
		blockBodys = BlockBodiesPacket{{Transactions: block.Transactions(), Uncles: block.Uncles()}}
	)

	tests := []struct {
		packet Packet
		decode func() Packet
	}{
		{
			&StatusPacket{ProtocolVersion: XDC164, NetworkID: 50, TD: big.NewInt(131), Head: hash, Genesis: hash, ForkID: forkid.ID{Hash: [4]byte{1, 2, 3, 4}, Next: 5}},
			func() Packet { return new(StatusPacket) },
		},
		{
			&StatusPacket100{ProtocolVersion: XDC100, NetworkId: 50, TD: big.NewInt(131), CurrentBlock: hash, GenesisBlock: hash},
			func() Packet { return new(StatusPacket100) },
		},
		{
			&NewBlockHashesPacket{{Hash: hash, Number: 314}},
			func() Packet { return new(NewBlockHashesPacket) },
		},
		{
			&TransactionsPacket{block.Transactions()[0]},
			func() Packet { return new(TransactionsPacket) },
		},
		{
			&GetBlockHeadersPacket{Origin: HashOrNumber{Number: 314}, Amount: 3, Skip: 1, Reverse: true},
			func() Packet { return new(GetBlockHeadersPacket) },
		},
		{
			&GetBlockHeadersPacket{Origin: HashOrNumber{Hash: hash}, Amount: 3, Skip: 1},
			func() Packet { return new(GetBlockHeadersPacket) },
		},
		{
			&headers,
			func() Packet { return new(BlockHeadersPacket) },
		},
		{
			&NewBlockPacket{Block: block, TD: big.NewInt(131)},
			func() Packet { return new(NewBlockPacket) },
		},
		{
			&GetBlockBodiesPacket{hash},
			func() Packet { return new(GetBlockBodiesPacket) },
		},
		{
			&blockBodys,
			func() Packet { return new(BlockBodiesPacket) },
		},
		{
			&GetNodeDataPacket{hash},
			func() Packet { return new(GetNodeDataPacket) },
		},
		{
			&NodeDataPacket{{0x01, 0x02, 0x03}},
			func() Packet { return new(NodeDataPacket) },
		},
		{
			&GetReceiptsPacket{hash},
			func() Packet { return new(GetReceiptsPacket) },
		},
		{
			&ReceiptsPacket{receipts},
			func() Packet { return new(ReceiptsPacket) },
		},
		{
			&NewPooledTransactionHashesPacket{hash},
			func() Packet { return new(NewPooledTransactionHashesPacket) },
		},
		{
			&GetPooledTransactionsPacket{hash},
			func() Packet { return new(GetPooledTransactionsPacket) },
		},
		{
			&PooledTransactionsPacket{block.Transactions()[0]},
			func() Packet { return new(PooledTransactionsPacket) },
		},
		{
			&OrderTransactionsPacket{orderTx},
			func() Packet { return new(OrderTransactionsPacket) },
		},
		{
			&LendingTransactionsPacket{lendingTx},
			func() Packet { return new(LendingTransactionsPacket) },
		},
		{
			(*VotePacket)(&vote),
			func() Packet { return new(VotePacket) },
		},
		{
			(*TimeoutPacket)(&timeout),
			func() Packet { return new(TimeoutPacket) },
		},
		{
			(*SyncInfoPacket)(&syncInfo),
			func() Packet { return new(SyncInfoPacket) },
		},
	}
	for i, tt := range tests {
		enc, err := rlp.EncodeToBytes(tt.packet)
		if err != nil {
			t.Errorf("test %d (%s): failed to encode: %v", i, tt.packet.Name(), err)
			continue
		}
		dec := tt.decode()
		if err := rlp.DecodeBytes(enc, dec); err != nil {
			t.Errorf("test %d (%s): failed to decode: %v", i, tt.packet.Name(), err)
			continue
		}
		reenc, err := rlp.EncodeToBytes(dec)
		if err != nil {
			t.Errorf("test %d (%s): failed to re-encode: %v", i, tt.packet.Name(), err)
			continue
		}
		if !bytes.Equal(enc, reenc) {
			t.Errorf("test %d (%s): round trip mismatch:\nhave %x\nwant %x", i, tt.packet.Name(), reenc, enc)
		}
		if name := dec.Name(); name != tt.packet.Name() {
			t.Errorf("test %d: name mismatch: have %q, want %q", i, name, tt.packet.Name())
		}
		if kind := dec.Kind(); kind != tt.packet.Kind() {
			t.Errorf("test %d: kind mismatch: have %#x, want %#x", i, kind, tt.packet.Kind())
		}
	}
}

// TestMessageCodes locks the code values themselves: they are part of the wire
// contract and are shared with peers running any other build.
func TestMessageCodes(t *testing.T) {
	codes := map[string]struct {
		have uint64
		want uint64
	}{
		"StatusMsg":                     {StatusMsg, 0x00},
		"NewBlockHashesMsg":             {NewBlockHashesMsg, 0x01},
		"TransactionMsg":                {TransactionMsg, 0x02},
		"GetBlockHeadersMsg":            {GetBlockHeadersMsg, 0x03},
		"BlockHeadersMsg":               {BlockHeadersMsg, 0x04},
		"GetBlockBodiesMsg":             {GetBlockBodiesMsg, 0x05},
		"BlockBodiesMsg":                {BlockBodiesMsg, 0x06},
		"NewBlockMsg":                   {NewBlockMsg, 0x07},
		"OrderTxMsg":                    {OrderTxMsg, 0x08},
		"LendingTxMsg":                  {LendingTxMsg, 0x09},
		"GetNodeDataMsg":                {GetNodeDataMsg, 0x0d},
		"NodeDataMsg":                   {NodeDataMsg, 0x0e},
		"GetReceiptsMsg":                {GetReceiptsMsg, 0x0f},
		"ReceiptsMsg":                   {ReceiptsMsg, 0x10},
		"VoteMsg":                       {VoteMsg, 0xe0},
		"TimeoutMsg":                    {TimeoutMsg, 0xe1},
		"SyncInfoMsg":                   {SyncInfoMsg, 0xe2},
		"NewPooledTransactionHashesMsg": {NewPooledTransactionHashesMsg, 0xe3},
		"GetPooledTransactionsMsg":      {GetPooledTransactionsMsg, 0xe4},
		"PooledTransactionsMsg":         {PooledTransactionsMsg, 0xe5},
	}
	for name, code := range codes {
		if code.have != code.want {
			t.Errorf("%s value mismatch: have %#x, want %#x", name, code.have, code.want)
		}
	}
}

// TestBlockBodiesDataSanityCheckUncleExtraSize checks the DoS bound on uncle
// headers travelling inside a block bodies response.
func TestBlockBodiesDataSanityCheckUncleExtraSize(t *testing.T) {
	request := BlockBodiesPacket{{
		Uncles: []*types.Header{{
			Extra: bytes.Repeat([]byte{0x01}, 20*1024+1),
		}},
	}}

	if err := request.sanityCheck(); err == nil {
		t.Fatal("expected oversized uncle extra data to fail sanity check")
	}
}

// TestBlockHeadersDataSanityCheckExtraSize checks the DoS bound on header extra
// data travelling inside a headers response.
func TestBlockHeadersDataSanityCheckExtraSize(t *testing.T) {
	headers := []*types.Header{{
		Extra: bytes.Repeat([]byte{0x01}, 20*1024+1),
	}}

	if err := types.SanityCheckHeaders(headers); err == nil {
		t.Fatal("expected oversized header extra data to fail sanity check")
	}
}

// TestEth66EmptyMessages tests encoding of empty XDC166 messages: every request
// and reply packet carrying a request id encodes the id first, followed by the
// (empty) payload, so all of them collapse to the same byte sequence.
func TestEth66EmptyMessages(t *testing.T) {
	// All empty messages encode to the same format
	want := common.FromHex("c4820457c0")

	for i, msg := range []interface{}{
		// Headers
		GetBlockHeadersPacket66{1111, nil},
		BlockHeadersPacket66{1111, nil},
		// Bodies
		GetBlockBodiesPacket66{1111, nil},
		BlockBodiesPacket66{1111, nil},
		BlockBodiesRLPPacket66{1111, nil},
		// Node data
		GetNodeDataPacket66{1111, nil},
		NodeDataPacket66{1111, nil},
		// Receipts
		GetReceiptsPacket66{1111, nil},
		ReceiptsPacket66{1111, nil},
		ReceiptsRLPPacket66{1111, nil},
		// Transactions
		GetPooledTransactionsPacket66{1111, nil},
		PooledTransactionsPacket66{1111, nil},
		PooledTransactionsRLPPacket66{1111, nil},

		// Headers
		BlockHeadersPacket66{1111, BlockHeadersPacket([]*types.Header{})},
		// Bodies
		GetBlockBodiesPacket66{1111, GetBlockBodiesPacket([]common.Hash{})},
		BlockBodiesPacket66{1111, BlockBodiesPacket([]*BlockBody{})},
		BlockBodiesRLPPacket66{1111, BlockBodiesRLPPacket([]rlp.RawValue{})},
		// Node data
		GetNodeDataPacket66{1111, GetNodeDataPacket([]common.Hash{})},
		NodeDataPacket66{1111, NodeDataPacket([][]byte{})},
		// Receipts
		GetReceiptsPacket66{1111, GetReceiptsPacket([]common.Hash{})},
		ReceiptsPacket66{1111, ReceiptsPacket([][]*types.Receipt{})},
		// Transactions
		GetPooledTransactionsPacket66{1111, GetPooledTransactionsPacket([]common.Hash{})},
		PooledTransactionsPacket66{1111, PooledTransactionsPacket([]*types.Transaction{})},
		PooledTransactionsRLPPacket66{1111, PooledTransactionsRLPPacket([]rlp.RawValue{})},
	} {
		if have, _ := rlp.EncodeToBytes(msg); !bytes.Equal(have, want) {
			t.Errorf("test %d, type %T, have\n\t%x\nwant\n\t%x", i, msg, have, want)
		}
	}
}

// TestEth66Messages tests the encoding of all redefined XDC166 messages.
func TestEth66Messages(t *testing.T) {
	// Some basic structs used during testing
	var (
		header       *types.Header
		blockBody    *BlockBody
		blockBodyRlp rlp.RawValue
		txs          []*types.Transaction
		txRlps       []rlp.RawValue
		hashes       []common.Hash
		receipts     []*types.Receipt
		receiptsRlp  rlp.RawValue

		err error
	)
	header = &types.Header{
		Difficulty: big.NewInt(2222),
		Number:     big.NewInt(3333),
		GasLimit:   4444,
		GasUsed:    5555,
		Time:       6666,
		Extra:      []byte{0x77, 0x88},
	}
	// Init the transactions, taken from a different test
	{
		for _, hexrlp := range []string{
			"f867088504a817c8088302e2489435353535353535353535353535353535353535358202008025a064b1702d9298fee62dfeccc57d322a463ad55ca201256d01f62b45b2e1c21c12a064b1702d9298fee62dfeccc57d322a463ad55ca201256d01f62b45b2e1c21c10",
			"f867098504a817c809830334509435353535353535353535353535353535353535358202d98025a052f8f61201b2b11a78d6e866abc9c3db2ae8631fa656bfe5cb53668255367afba052f8f61201b2b11a78d6e866abc9c3db2ae8631fa656bfe5cb53668255367afb",
		} {
			var tx *types.Transaction
			rlpdata := common.FromHex(hexrlp)
			if err := rlp.DecodeBytes(rlpdata, &tx); err != nil {
				t.Fatal(err)
			}
			txs = append(txs, tx)
			txRlps = append(txRlps, rlpdata)
		}
	}
	// init the block body data, both object and rlp form
	blockBody = &BlockBody{
		Transactions: txs,
		Uncles:       []*types.Header{header},
	}
	blockBodyRlp, err = rlp.EncodeToBytes(blockBody)
	if err != nil {
		t.Fatal(err)
	}

	hashes = []common.Hash{
		common.HexToHash("deadc0de"),
		common.HexToHash("feedbeef"),
	}
	byteSlices := [][]byte{
		common.FromHex("deadc0de"),
		common.FromHex("feedbeef"),
	}
	// init the receipts
	{
		receipts = []*types.Receipt{
			{
				Status:            types.ReceiptStatusFailed,
				CumulativeGasUsed: 1,
				Logs: []*types.Log{
					{
						Address: common.BytesToAddress([]byte{0x11}),
						Topics:  []common.Hash{common.HexToHash("dead"), common.HexToHash("beef")},
						Data:    []byte{0x01, 0x00, 0xff},
					},
				},
				TxHash:          hashes[0],
				ContractAddress: common.BytesToAddress([]byte{0x01, 0x11, 0x11}),
				GasUsed:         111111,
			},
		}
		rlpData, err := rlp.EncodeToBytes(receipts)
		if err != nil {
			t.Fatal(err)
		}
		receiptsRlp = rlpData
	}

	for i, tc := range []struct {
		message interface{}
		want    []byte
	}{
		{
			GetBlockHeadersPacket66{1111, &GetBlockHeadersPacket{HashOrNumber{hashes[0], 0}, 5, 5, false}},
			common.FromHex("e8820457e4a000000000000000000000000000000000000000000000000000000000deadc0de050580"),
		},
		{
			GetBlockHeadersPacket66{1111, &GetBlockHeadersPacket{HashOrNumber{common.Hash{}, 9999}, 5, 5, false}},
			common.FromHex("ca820457c682270f050580"),
		},
		{
			// The want bytes diverge from upstream eth/66: the XDC types.Header
			// carries three extra fields (Validators, Validator, Penalties).
			BlockHeadersPacket66{1111, BlockHeadersPacket{header}},
			common.FromHex("f90205820457f901fff901fca00000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000000940000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000000b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008208ae820d0582115c8215b3821a0a827788a00000000000000000000000000000000000000000000000000000000000000000880000000000000000808080"),
		},
		{
			GetBlockBodiesPacket66{1111, GetBlockBodiesPacket(hashes)},
			common.FromHex("f847820457f842a000000000000000000000000000000000000000000000000000000000deadc0dea000000000000000000000000000000000000000000000000000000000feedbeef"),
		},
		{ // Same header divergence from upstream as above.
			BlockBodiesPacket66{1111, BlockBodiesPacket([]*BlockBody{blockBody})},
			common.FromHex("f902df820457f902d9f902d6f8d2f867088504a817c8088302e2489435353535353535353535353535353535353535358202008025a064b1702d9298fee62dfeccc57d322a463ad55ca201256d01f62b45b2e1c21c12a064b1702d9298fee62dfeccc57d322a463ad55ca201256d01f62b45b2e1c21c10f867098504a817c809830334509435353535353535353535353535353535353535358202d98025a052f8f61201b2b11a78d6e866abc9c3db2ae8631fa656bfe5cb53668255367afba052f8f61201b2b11a78d6e866abc9c3db2ae8631fa656bfe5cb53668255367afbf901fff901fca00000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000000940000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000000b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008208ae820d0582115c8215b3821a0a827788a00000000000000000000000000000000000000000000000000000000000000000880000000000000000808080"),
		},
		{ // Identical to non-rlp-shortcut version
			BlockBodiesRLPPacket66{1111, BlockBodiesRLPPacket([]rlp.RawValue{blockBodyRlp})},
			common.FromHex("f902df820457f902d9f902d6f8d2f867088504a817c8088302e2489435353535353535353535353535353535353535358202008025a064b1702d9298fee62dfeccc57d322a463ad55ca201256d01f62b45b2e1c21c12a064b1702d9298fee62dfeccc57d322a463ad55ca201256d01f62b45b2e1c21c10f867098504a817c809830334509435353535353535353535353535353535353535358202d98025a052f8f61201b2b11a78d6e866abc9c3db2ae8631fa656bfe5cb53668255367afba052f8f61201b2b11a78d6e866abc9c3db2ae8631fa656bfe5cb53668255367afbf901fff901fca00000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000000940000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000000b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008208ae820d0582115c8215b3821a0a827788a00000000000000000000000000000000000000000000000000000000000000000880000000000000000808080"),
		},
		{
			GetNodeDataPacket66{1111, GetNodeDataPacket(hashes)},
			common.FromHex("f847820457f842a000000000000000000000000000000000000000000000000000000000deadc0dea000000000000000000000000000000000000000000000000000000000feedbeef"),
		},
		{
			NodeDataPacket66{1111, NodeDataPacket(byteSlices)},
			common.FromHex("ce820457ca84deadc0de84feedbeef"),
		},
		{
			GetReceiptsPacket66{1111, GetReceiptsPacket(hashes)},
			common.FromHex("f847820457f842a000000000000000000000000000000000000000000000000000000000deadc0dea000000000000000000000000000000000000000000000000000000000feedbeef"),
		},
		{
			ReceiptsPacket66{1111, ReceiptsPacket([][]*types.Receipt{receipts})},
			common.FromHex("f90172820457f9016cf90169f901668001b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f85ff85d940000000000000000000000000000000000000011f842a0000000000000000000000000000000000000000000000000000000000000deada0000000000000000000000000000000000000000000000000000000000000beef830100ff"),
		},
		{
			ReceiptsRLPPacket66{1111, ReceiptsRLPPacket([]rlp.RawValue{receiptsRlp})},
			common.FromHex("f90172820457f9016cf90169f901668001b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f85ff85d940000000000000000000000000000000000000011f842a0000000000000000000000000000000000000000000000000000000000000deada0000000000000000000000000000000000000000000000000000000000000beef830100ff"),
		},
		{
			GetPooledTransactionsPacket66{1111, GetPooledTransactionsPacket(hashes)},
			common.FromHex("f847820457f842a000000000000000000000000000000000000000000000000000000000deadc0dea000000000000000000000000000000000000000000000000000000000feedbeef"),
		},
		{
			PooledTransactionsPacket66{1111, PooledTransactionsPacket(txs)},
			common.FromHex("f8d7820457f8d2f867088504a817c8088302e2489435353535353535353535353535353535353535358202008025a064b1702d9298fee62dfeccc57d322a463ad55ca201256d01f62b45b2e1c21c12a064b1702d9298fee62dfeccc57d322a463ad55ca201256d01f62b45b2e1c21c10f867098504a817c809830334509435353535353535353535353535353535353535358202d98025a052f8f61201b2b11a78d6e866abc9c3db2ae8631fa656bfe5cb53668255367afba052f8f61201b2b11a78d6e866abc9c3db2ae8631fa656bfe5cb53668255367afb"),
		},
		{
			PooledTransactionsRLPPacket66{1111, PooledTransactionsRLPPacket(txRlps)},
			common.FromHex("f8d7820457f8d2f867088504a817c8088302e2489435353535353535353535353535353535353535358202008025a064b1702d9298fee62dfeccc57d322a463ad55ca201256d01f62b45b2e1c21c12a064b1702d9298fee62dfeccc57d322a463ad55ca201256d01f62b45b2e1c21c10f867098504a817c809830334509435353535353535353535353535353535353535358202d98025a052f8f61201b2b11a78d6e866abc9c3db2ae8631fa656bfe5cb53668255367afba052f8f61201b2b11a78d6e866abc9c3db2ae8631fa656bfe5cb53668255367afb"),
		},
	} {
		if have, _ := rlp.EncodeToBytes(tc.message); !bytes.Equal(have, tc.want) {
			t.Errorf("test %d, type %T, have\n\t%x\nwant\n\t%x", i, tc.message, have, tc.want)
		}
	}
}

// Tests that the custom union field encoder and decoder works correctly.
func TestGetBlockHeadersDataEncodeDecode(t *testing.T) {
	// Create a "random" hash for testing
	var hash common.Hash
	for i := range hash {
		hash[i] = byte(i)
	}
	// Assemble some table driven tests
	tests := []struct {
		packet *GetBlockHeadersPacket
		fail   bool
	}{
		// Providing the origin as either a hash or a number should both work
		{fail: false, packet: &GetBlockHeadersPacket{Origin: HashOrNumber{Number: 314}}},
		{fail: false, packet: &GetBlockHeadersPacket{Origin: HashOrNumber{Hash: hash}}},

		// Providing arbitrary query field should also work
		{fail: false, packet: &GetBlockHeadersPacket{Origin: HashOrNumber{Number: 314}, Amount: 314, Skip: 1, Reverse: true}},
		{fail: false, packet: &GetBlockHeadersPacket{Origin: HashOrNumber{Hash: hash}, Amount: 314, Skip: 1, Reverse: true}},

		// Providing both the origin hash and origin number must fail
		{fail: true, packet: &GetBlockHeadersPacket{Origin: HashOrNumber{Hash: hash, Number: 314}}},
	}
	// Iterate over each of the tests and try to encode and then decode
	for i, tt := range tests {
		bytes, err := rlp.EncodeToBytes(tt.packet)
		if err != nil && !tt.fail {
			t.Fatalf("test %d: failed to encode packet: %v", i, err)
		} else if err == nil && tt.fail {
			t.Fatalf("test %d: encode should have failed", i)
		}
		if !tt.fail {
			packet := new(GetBlockHeadersPacket)
			if err := rlp.DecodeBytes(bytes, packet); err != nil {
				t.Fatalf("test %d: failed to decode packet: %v", i, err)
			}
			if packet.Origin.Hash != tt.packet.Origin.Hash || packet.Origin.Number != tt.packet.Origin.Number || packet.Amount != tt.packet.Amount ||
				packet.Skip != tt.packet.Skip || packet.Reverse != tt.packet.Reverse {
				t.Fatalf("test %d: encode decode mismatch: have %+v, want %+v", i, packet, tt.packet)
			}
		}
	}
}

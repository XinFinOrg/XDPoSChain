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
	if !reflect.DeepEqual(ProtocolVersions, []uint{XDC165, XDC164, XDC100}) {
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

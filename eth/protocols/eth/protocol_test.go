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
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/rlp"
)

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

	if err := request.SanityCheck(); err == nil {
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

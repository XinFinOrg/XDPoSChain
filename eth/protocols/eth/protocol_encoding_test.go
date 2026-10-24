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
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/forkid"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/rlp"
)

// preSplitEncodings holds the RLP bytes the pre-split code produced for the
// payloads built in TestPacketEncodingsMatchPreSplit. They were generated on
// 2026-10-22 in a detached worktree of baf6d167e9 (the branch point) by
// encoding the pre-split types (statusData, statusData100, newBlockHashesData,
// getBlockHeadersData, newBlockData, blockBodiesData) and the raw slices that
// later became named packet types.
var preSplitEncodings = map[string]string{
	"status164":       "f84e81a4328183a00700000000000000000000000000000000000000000000000000000000000000a00800000000000000000000000000000000000000000000000000000000000000c6840102030405",
	"status100":       "f84664328183a00700000000000000000000000000000000000000000000000000000000000000a00800000000000000000000000000000000000000000000000000000000000000",
	"newblockhashes":  "e5e4a0070000000000000000000000000000000000000000000000000000000000000082013a",
	"getheaders-num":  "c682013a030101",
	"getheaders-hash": "e4a00700000000000000000000000000000000000000000000000000000000000000030180",
	"newblock":        "f90226f90221f901fca00000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000000940000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000000b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008302000001837a1200825208845f5e100001a00000000000000000000000000000000000000000000000000000000000000000880000000000000000808080e0df01018252089400000000000000000000000000000000000000000180808080c08183",
	"blockbodies":     "e3e2e0df01018252089400000000000000000000000000000000000000000180808080c0",
	"nodedata":        "c483010203",
	"transactions":    "e0df01018252089400000000000000000000000000000000000000000180808080",
	"order":           "f88ff88d010101940000000000000000000000000000000000000000940000000000000000000000000000000000000000940000000000000000000000000000000000000000940000000000000000000000000000000000000000867374617475738473696465847479706501808080a00000000000000000000000000000000000000000000000000000000000000000",
	"lending":         "f893f89101010194000000000000000000000000000000000000000094000000000000000000000000000000000000000094000000000000000000000000000000000000000080940000000000000000000000000000000000000000018673746174757384736964658474797065010180808080a00000000000000000000000000000000000000000000000000000000000000000",
	"vote":            "e6e3a0010000000000000000000000000000000000000000000000000000000000000002030405",
	"timeout":         "c3020304",
	"syncinfo":        "ede7e3a002000000000000000000000000000000000000000000000000000000000000000102c10580c403c10680",
}

// TestPacketEncodingsMatchPreSplit pins the encoding of the packets the split
// moved or reshaped to the bytes the pre-split code produced for the same
// payload. TestPacketRoundTrips only proves that a packet type is
// self-consistent (encode, decode, re-encode); this table is what makes "the
// move changed no byte" falsifiable - a reordered field or a reshaped payload
// fails here immediately.
func TestPacketEncodingsMatchPreSplit(t *testing.T) {
	hash := common.Hash{0x07}
	td := big.NewInt(131)

	header := &types.Header{Number: big.NewInt(1), Difficulty: big.NewInt(131072), GasLimit: 8000000, GasUsed: 21000, Time: 1600000000, Extra: []byte{0x01}}
	tx := types.NewTransaction(1, common.Address{}, big.NewInt(1), 21000, big.NewInt(1), nil)
	block := types.NewBlockWithHeader(header).WithBody(types.Body{Transactions: []*types.Transaction{tx}})

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
	packets := map[string]Packet{
		"status164":       &StatusPacket{ProtocolVersion: XDC164, NetworkID: 50, TD: td, Head: hash, Genesis: common.Hash{0x08}, ForkID: forkid.ID{Hash: [4]byte{1, 2, 3, 4}, Next: 5}},
		"status100":       &StatusPacket100{ProtocolVersion: XDC100, NetworkId: 50, TD: td, CurrentBlock: hash, GenesisBlock: common.Hash{0x08}},
		"newblockhashes":  &NewBlockHashesPacket{{Hash: hash, Number: 314}},
		"getheaders-num":  &GetBlockHeadersPacket{Origin: HashOrNumber{Number: 314}, Amount: 3, Skip: 1, Reverse: true},
		"getheaders-hash": &GetBlockHeadersPacket{Origin: HashOrNumber{Hash: hash}, Amount: 3, Skip: 1},
		"newblock":        &NewBlockPacket{Block: block, TD: td},
		"blockbodies":     &BlockBodiesPacket{{Transactions: []*types.Transaction{tx}}},
		"nodedata":        &NodeDataPacket{{0x01, 0x02, 0x03}},
		"transactions":    &TransactionsPacket{tx},
		"order":           &OrderTransactionsPacket{orderTx},
		"lending":         &LendingTransactionsPacket{lendingTx},
		"vote":            (*VotePacket)(&vote),
		"timeout":         (*TimeoutPacket)(&timeout),
		"syncinfo":        (*SyncInfoPacket)(&syncInfo),
	}
	for name, want := range preSplitEncodings {
		packet, ok := packets[name]
		if !ok {
			t.Fatalf("%s: golden encoding without a packet", name)
		}
		enc, err := rlp.EncodeToBytes(packet)
		if err != nil {
			t.Errorf("%s: failed to encode: %v", name, err)
			continue
		}
		if have := hex.EncodeToString(enc); have != want {
			t.Errorf("%s: wire encoding changed since the split:\nhave %s\nwant %s", name, have, want)
		}
	}
}

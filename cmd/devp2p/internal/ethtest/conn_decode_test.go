package ethtest

import (
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/eth"
	"github.com/XinFinOrg/XDPoSChain/rlp"
)

func TestDecodeEthPayloadGetBlockHeaders(t *testing.T) {
	p := &getBlockHeadersData{Origin: hashOrNumber{Number: 0}, Amount: 1}
	b, err := rlp.EncodeToBytes(p)
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}
	msg, err := decodeEthPayload(eth.GetBlockHeadersMsg, b)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	decoded, ok := msg.(*getBlockHeadersData)
	if !ok {
		t.Fatalf("wrong decoded type: %T", msg)
	}
	if decoded.Amount != p.Amount || decoded.Origin.Number != p.Origin.Number {
		t.Fatalf("decoded payload mismatch: have %+v want %+v", decoded, p)
	}
}

func TestDecodeEthPayloadGetReceipts(t *testing.T) {
	p := &getReceiptsData{common.HexToHash("0x01")}
	b, err := rlp.EncodeToBytes(p)
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}
	msg, err := decodeEthPayload(eth.GetReceiptsMsg, b)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	decoded, ok := msg.(*getReceiptsData)
	if !ok {
		t.Fatalf("wrong decoded type: %T", msg)
	}
	if len(*decoded) != len(*p) || (*decoded)[0] != (*p)[0] {
		t.Fatalf("decoded payload mismatch: have %v want %v", *decoded, *p)
	}
}

func TestDecodeEthPayloadNewBlockHashesMsg(t *testing.T) {
	raw := rlp.RawValue{0xc0}
	msg, err := decodeEthPayload(eth.NewBlockHashesMsg, raw)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	decoded, ok := msg.(*rlp.RawValue)
	if !ok {
		t.Fatalf("wrong decoded type: %T", msg)
	}
	if len(*decoded) != len(raw) || (*decoded)[0] != raw[0] {
		t.Fatalf("decoded new block hashes payload mismatch: have %x want %x", *decoded, raw)
	}
}

func TestDecodeEthPayloadNewBlockMsg(t *testing.T) {
	raw := rlp.RawValue{0xc0}
	msg, err := decodeEthPayload(eth.NewBlockMsg, raw)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	decoded, ok := msg.(*rlp.RawValue)
	if !ok {
		t.Fatalf("wrong decoded type: %T", msg)
	}
	if len(*decoded) != len(raw) || (*decoded)[0] != raw[0] {
		t.Fatalf("decoded new block payload mismatch: have %x want %x", *decoded, raw)
	}
}

func TestDecodeEthPayloadNodeDataMsgs(t *testing.T) {
	raw := rlp.RawValue{0xc0}
	for _, code := range []uint64{eth.GetNodeDataMsg, eth.NodeDataMsg} {
		msg, err := decodeEthPayload(code, raw)
		if err != nil {
			t.Fatalf("decode failed for code %d: %v", code, err)
		}
		decoded, ok := msg.(*rlp.RawValue)
		if !ok {
			t.Fatalf("wrong decoded type for code %d: %T", code, msg)
		}
		if len(*decoded) != len(raw) || (*decoded)[0] != raw[0] {
			t.Fatalf("decoded node data payload mismatch for code %d: have %x want %x", code, *decoded, raw)
		}
	}
}

func TestDecodeEthPayloadTxMsg(t *testing.T) {
	to := common.HexToAddress("0x00000000000000000000000000000000000000aa")
	tx := types.NewTransaction(0, to, big.NewInt(1), 21000, big.NewInt(1), nil)
	p := types.Transactions{tx}
	b, err := rlp.EncodeToBytes(&p)
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}
	msg, err := decodeEthPayload(eth.TxMsg, b)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	decoded, ok := msg.(*types.Transactions)
	if !ok {
		t.Fatalf("wrong decoded type: %T", msg)
	}
	if len(*decoded) != 1 {
		t.Fatalf("wrong tx count: have %d want 1", len(*decoded))
	}
	if (*decoded)[0].Hash() != tx.Hash() {
		t.Fatalf("decoded tx hash mismatch: have %x want %x", (*decoded)[0].Hash(), tx.Hash())
	}
}

func TestDecodeEthPayloadOrderTxMsg(t *testing.T) {
	p := []rlp.RawValue{}
	b, err := rlp.EncodeToBytes(&p)
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}
	msg, err := decodeEthPayload(eth.OrderTxMsg, b)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	decoded, ok := msg.(*[]rlp.RawValue)
	if !ok {
		t.Fatalf("wrong decoded type: %T", msg)
	}
	if len(*decoded) != 0 {
		t.Fatalf("wrong order tx list length: have %d want 0", len(*decoded))
	}
}

func TestDecodeEthPayloadLendingTxMsg(t *testing.T) {
	p := []rlp.RawValue{}
	b, err := rlp.EncodeToBytes(&p)
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}
	msg, err := decodeEthPayload(eth.LendingTxMsg, b)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	decoded, ok := msg.(*[]rlp.RawValue)
	if !ok {
		t.Fatalf("wrong decoded type: %T", msg)
	}
	if len(*decoded) != 0 {
		t.Fatalf("wrong lending tx list length: have %d want 0", len(*decoded))
	}
}

func TestDecodeEthPayloadVoteMsg(t *testing.T) {
	raw := rlp.RawValue{0xc0}
	msg, err := decodeEthPayload(eth.VoteMsg, raw)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	decoded, ok := msg.(*rlp.RawValue)
	if !ok {
		t.Fatalf("wrong decoded type: %T", msg)
	}
	if len(*decoded) != len(raw) || (*decoded)[0] != raw[0] {
		t.Fatalf("decoded vote payload mismatch: have %x want %x", *decoded, raw)
	}
}

func TestDecodeEthPayloadTimeoutMsg(t *testing.T) {
	raw := rlp.RawValue{0xc0}
	msg, err := decodeEthPayload(eth.TimeoutMsg, raw)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	decoded, ok := msg.(*rlp.RawValue)
	if !ok {
		t.Fatalf("wrong decoded type: %T", msg)
	}
	if len(*decoded) != len(raw) || (*decoded)[0] != raw[0] {
		t.Fatalf("decoded timeout payload mismatch: have %x want %x", *decoded, raw)
	}
}

func TestDecodeEthPayloadSyncInfoMsg(t *testing.T) {
	raw := rlp.RawValue{0xc0}
	msg, err := decodeEthPayload(eth.SyncInfoMsg, raw)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	decoded, ok := msg.(*rlp.RawValue)
	if !ok {
		t.Fatalf("wrong decoded type: %T", msg)
	}
	if len(*decoded) != len(raw) || (*decoded)[0] != raw[0] {
		t.Fatalf("decoded sync info payload mismatch: have %x want %x", *decoded, raw)
	}
}

func TestDecodeEthPayloadUnknownCode(t *testing.T) {
	_, err := decodeEthPayload(0xff, []byte{0xc0})
	if err == nil {
		t.Fatal("expected error for unknown eth message code")
	}
}

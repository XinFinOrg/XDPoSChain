package ethtest

import (
	"testing"

	ethproto "github.com/XinFinOrg/XDPoSChain/eth/protocols/eth"
	"github.com/XinFinOrg/XDPoSChain/rlp"
)

var xdcRelayFrameCodes = []uint64{
	ethproto.VoteMsg,
	ethproto.TimeoutMsg,
	ethproto.SyncInfoMsg,
	ethproto.NewPooledTransactionHashesMsg,
	ethproto.GetPooledTransactionsMsg,
	ethproto.PooledTransactionsMsg,
}

func TestReadEthSkipsXdcRelayFrames(t *testing.T) {
	client, peer, _, _, _ := newScriptedPeer(t)
	conn := &Conn{Conn: client}

	written := make(chan error, 1)
	go func() {
		for _, code := range xdcRelayFrameCodes {
			if _, err := peer.Write(protoOffset(ethProto)+code, []byte{0x80}); err != nil {
				written <- err
				return
			}
		}
		_, err := peer.Write(protoOffset(ethProto)+ethproto.NewBlockHashesMsg, []byte{0xc0})
		written <- err
	}()

	msg, err := conn.ReadEth()
	if err != nil {
		t.Fatalf("ReadEth failed: %v", err)
	}
	decoded, ok := msg.(*rlp.RawValue)
	if !ok {
		t.Fatalf("got %T, want *rlp.RawValue", msg)
	}
	if len(*decoded) != 1 || (*decoded)[0] != 0xc0 {
		t.Fatalf("ReadEth returned a relayed frame instead of the eth message: %x", *decoded)
	}
	if err := <-written; err != nil {
		t.Fatalf("peer write failed: %v", err)
	}
}

func TestStatusExchangeSkipsXdcRelayFrames(t *testing.T) {
	chain, err := NewChain("testdata")
	if err != nil {
		t.Fatalf("failed to load chain fixtures: %v", err)
	}
	client, peer, _, _, _ := newScriptedPeer(t)
	conn := &Conn{Conn: client, negotiatedProtoVersion: ethProtoVersionXDpos2}

	status, err := rlp.EncodeToBytes(makeStatusPacket(chain, ethProtoVersionXDpos2))
	if err != nil {
		t.Fatalf("failed to encode status packet: %v", err)
	}

	written := make(chan error, 1)
	go func() {
		for _, code := range xdcRelayFrameCodes {
			if _, err := peer.Write(protoOffset(ethProto)+code, []byte{0xc0}); err != nil {
				written <- err
				return
			}
		}
		_, err := peer.Write(protoOffset(ethProto)+statusMsgCode, status)
		written <- err
	}()

	if err := conn.statusExchange(chain, nil); err != nil {
		t.Fatalf("statusExchange failed: %v", err)
	}
	if err := <-written; err != nil {
		t.Fatalf("peer write failed: %v", err)
	}
}

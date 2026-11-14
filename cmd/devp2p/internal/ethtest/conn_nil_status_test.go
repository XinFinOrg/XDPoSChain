package ethtest

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"net"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/p2p"
	"github.com/XinFinOrg/XDPoSChain/p2p/rlpx"
	"github.com/XinFinOrg/XDPoSChain/rlp"
)

// The wrappers must keep the status argument untyped so a nil stays untyped
var (
	_ func(*Suite, interface{}) (*Conn, error) = (*Suite).dialAndPeer
	_ func(*Conn, *Chain, interface{}) error   = (*Conn).peer
)

func newStatusExchangePeer(t *testing.T) (*rlpx.Conn, *rlpx.Conn, *ecdsa.PrivateKey) {
	t.Helper()
	clientConn, peerConn := net.Pipe()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate client key: %v", err)
	}
	peerKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate peer key: %v", err)
	}
	client := rlpx.NewConn(clientConn, &peerKey.PublicKey)
	peer := rlpx.NewConn(peerConn, nil)
	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := peer.Handshake(peerKey); err != nil {
			t.Errorf("peer handshake failed: %v", err)
		}
	}()
	if _, err := client.Handshake(key); err != nil {
		t.Fatalf("client handshake failed: %v", err)
	}
	<-done
	t.Cleanup(func() {
		client.Close()
		peer.Close()
	})
	return client, peer, key
}

func TestStatusExchangeSendsValidPacketForNilStatus(t *testing.T) {
	chain, err := NewChain("testdata")
	if err != nil {
		t.Fatalf("failed to load chain fixtures: %v", err)
	}
	client, peer, _ := newStatusExchangePeer(t)
	conn := &Conn{Conn: client, negotiatedProtoVersion: ethProtoVersionXDpos2}
	incoming, err := rlp.EncodeToBytes(makeStatusPacket(chain, ethProtoVersionXDpos2))
	if err != nil {
		t.Fatalf("failed to encode peer status: %v", err)
	}
	statusCode := protoOffset(ethProto) + statusMsgCode

	type result struct {
		code uint64
		data []byte
		err  error
	}
	res := make(chan result, 1)
	go func() {
		if _, err := peer.Write(statusCode, incoming); err != nil {
			res <- result{err: err}
			return
		}
		code, data, _, err := peer.Read()
		res <- result{code: code, data: data, err: err}
	}()

	if err := conn.statusExchange(chain, nil); err != nil {
		t.Fatalf("statusExchange failed: %v", err)
	}
	got := <-res
	if got.err != nil {
		t.Fatalf("peer read: %v", got.err)
	}
	if got.code != statusCode {
		t.Fatalf("got status code %d, want %d", got.code, statusCode)
	}
	var packet statusPacket
	if err := rlp.DecodeBytes(got.data, &packet); err != nil {
		t.Fatalf("outgoing status is not a decodable packet: %v", err)
	}
	if packet.ProtocolVersion != uint32(ethProtoVersionXDpos2) {
		t.Fatalf("protocol version %d, want %d", packet.ProtocolVersion, ethProtoVersionXDpos2)
	}
	if packet.GenesisBlock != chain.blocks[0].Hash() {
		t.Fatalf("genesis %#x, want %#x", packet.GenesisBlock, chain.blocks[0].Hash())
	}
	if packet.CurrentBlock != chain.Head().Hash() {
		t.Fatalf("head %#x, want %#x", packet.CurrentBlock, chain.Head().Hash())
	}
}

func TestStatusExchangeKeepsExplicitStatus(t *testing.T) {
	chain, err := NewChain("testdata")
	if err != nil {
		t.Fatalf("failed to load chain fixtures: %v", err)
	}
	client, peer, _ := newStatusExchangePeer(t)
	conn := &Conn{Conn: client, negotiatedProtoVersion: ethProtoVersionXDpos2}
	incoming, err := rlp.EncodeToBytes(makeStatusPacket(chain, ethProtoVersionXDpos2))
	if err != nil {
		t.Fatalf("failed to encode peer status: %v", err)
	}
	explicit := &statusPacket{
		ProtocolVersion: uint32(ethProtoVersionXDpos164),
		NetworkId:       7,
		TD:              big.NewInt(9001),
		CurrentBlock:    common.HexToHash("0x1234"),
		GenesisBlock:    common.HexToHash("0x5678"),
	}
	statusCode := protoOffset(ethProto) + statusMsgCode

	res := make(chan []byte, 1)
	errCh := make(chan error, 1)
	go func() {
		if _, err := peer.Write(statusCode, incoming); err != nil {
			errCh <- err
			return
		}
		code, data, _, err := peer.Read()
		if err != nil {
			errCh <- err
			return
		}
		if code != statusCode {
			errCh <- fmt.Errorf("got status code %d, want %d", code, statusCode)
			return
		}
		res <- data
	}()

	if err := conn.statusExchange(chain, explicit); err != nil {
		t.Fatalf("statusExchange failed: %v", err)
	}
	select {
	case err := <-errCh:
		t.Fatalf("scripted peer: %v", err)
	case data := <-res:
		var packet statusPacket
		if err := rlp.DecodeBytes(data, &packet); err != nil {
			t.Fatalf("outgoing status is not a decodable packet: %v", err)
		}
		if packet.ProtocolVersion != explicit.ProtocolVersion || packet.NetworkId != explicit.NetworkId ||
			packet.TD.Cmp(explicit.TD) != 0 || packet.CurrentBlock != explicit.CurrentBlock ||
			packet.GenesisBlock != explicit.GenesisBlock {
			t.Fatalf("explicit status was replaced: %+v", packet)
		}
	}
}

func TestPeerWithNilStatusSendsValidPacket(t *testing.T) {
	chain, err := NewChain("testdata")
	if err != nil {
		t.Fatalf("failed to load chain fixtures: %v", err)
	}
	client, peer, key := newStatusExchangePeer(t)
	conn := &Conn{
		Conn:                   client,
		ourKey:                 key,
		ourHighestProtoVersion: ethProtoVersionXDpos2,
		caps:                   []p2p.Cap{{Name: "eth", Version: ethProtoVersionXDpos2}},
	}
	hello, err := rlp.EncodeToBytes(&protoHandshake{
		Version: 4,
		Caps:    []p2p.Cap{{Name: "eth", Version: ethProtoVersionXDpos2}},
		ID:      make([]byte, 64),
	})
	if err != nil {
		t.Fatalf("failed to encode peer hello: %v", err)
	}
	incoming, err := rlp.EncodeToBytes(makeStatusPacket(chain, ethProtoVersionXDpos2))
	if err != nil {
		t.Fatalf("failed to encode peer status: %v", err)
	}
	statusCode := protoOffset(ethProto) + statusMsgCode

	type result struct {
		data []byte
		err  error
	}
	res := make(chan result, 1)
	go func() {
		if err := conn.peer(chain, nil); err != nil {
			res <- result{err: err}
			return
		}
		res <- result{}
	}()
	peerResult := make(chan result, 1)
	go func() {
		if _, _, _, err := peer.Read(); err != nil {
			peerResult <- result{err: err}
			return
		}
		if _, err := peer.Write(handshakeMsg, hello); err != nil {
			peerResult <- result{err: err}
			return
		}
		if _, err := peer.Write(statusCode, incoming); err != nil {
			peerResult <- result{err: err}
			return
		}
		code, data, _, err := peer.Read()
		if err != nil {
			peerResult <- result{err: err}
			return
		}
		if code != statusCode {
			peerResult <- result{err: fmt.Errorf("got status code %d, want %d", code, statusCode)}
			return
		}
		peerResult <- result{data: data}
	}()

	if got := <-res; got.err != nil {
		t.Fatalf("peer failed: %v", got.err)
	}
	got := <-peerResult
	if got.err != nil {
		t.Fatalf("scripted peer: %v", got.err)
	}
	var packet statusPacket
	if err := rlp.DecodeBytes(got.data, &packet); err != nil {
		t.Fatalf("outgoing status is not a decodable packet: %v", err)
	}
	if packet.GenesisBlock != chain.blocks[0].Hash() {
		t.Fatalf("genesis %#x, want %#x", packet.GenesisBlock, chain.blocks[0].Hash())
	}
	if packet.CurrentBlock != chain.Head().Hash() {
		t.Fatalf("head %#x, want %#x", packet.CurrentBlock, chain.Head().Hash())
	}
}

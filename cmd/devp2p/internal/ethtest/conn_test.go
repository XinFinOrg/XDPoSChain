package ethtest

import (
	"testing"

	"github.com/XinFinOrg/XDPoSChain/eth"
	"github.com/XinFinOrg/XDPoSChain/p2p"
)

func TestConnNegotiatesHighestSharedEthVersion(t *testing.T) {
	c := &Conn{ourHighestProtoVersion: ethProtoVersionXDpos2}
	remoteCaps := []p2p.Cap{
		{Name: "eth", Version: ethProtoVersion63},
		{Name: "eth", Version: ethProtoVersionXDpos2},
	}

	c.negotiateEthProtocol(remoteCaps)

	if c.negotiatedProtoVersion != ethProtoVersionXDpos2 {
		t.Fatalf("wrong negotiated protocol version: have %d want %d", c.negotiatedProtoVersion, ethProtoVersionXDpos2)
	}
}

func TestConnNegotiatesZeroWhenNoSharedEthVersion(t *testing.T) {
	c := &Conn{ourHighestProtoVersion: ethProtoVersion63}
	remoteCaps := []p2p.Cap{{Name: "eth", Version: 70}}

	c.negotiateEthProtocol(remoteCaps)

	if c.negotiatedProtoVersion != 0 {
		t.Fatalf("expected no negotiated protocol version, have %d", c.negotiatedProtoVersion)
	}
}

func TestMakeStatusPacketFromChain(t *testing.T) {
	chain, err := NewChain("testdata")
	if err != nil {
		t.Fatalf("failed to load chain fixtures: %v", err)
	}

	status := makeStatusPacket(chain, ethProtoVersion63)

	if status.ProtocolVersion != uint32(ethProtoVersion63) {
		t.Fatalf("wrong protocol version: have %d want %d", status.ProtocolVersion, ethProtoVersion63)
	}
	if status.GenesisBlock != chain.blocks[0].Hash() {
		t.Fatalf("wrong genesis hash in status: have %x want %x", status.GenesisBlock, chain.blocks[0].Hash())
	}
	if status.CurrentBlock != chain.Head().Hash() {
		t.Fatalf("wrong current block hash in status: have %x want %x", status.CurrentBlock, chain.Head().Hash())
	}
	if status.NetworkId != chain.config.ChainID.Uint64() {
		t.Fatalf("wrong network id in status: have %d want %d", status.NetworkId, chain.config.ChainID.Uint64())
	}
	if status.TD == nil {
		t.Fatal("status TD must not be nil")
	}
}

func TestStatusMsgCodeMatchesEthProtocol(t *testing.T) {
	if statusMsgCode != eth.StatusMsg {
		t.Fatalf("status msg code drift: have %d want %d", statusMsgCode, eth.StatusMsg)
	}
}

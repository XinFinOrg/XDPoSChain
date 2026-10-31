package ethtest

import (
	"testing"

	"github.com/XinFinOrg/XDPoSChain/core/forkid"
	ethproto "github.com/XinFinOrg/XDPoSChain/eth/protocols/eth"
	"github.com/XinFinOrg/XDPoSChain/p2p"
)

func TestConnNegotiatesHighestSharedEthVersion(t *testing.T) {
	c := &Conn{ourHighestProtoVersion: ethProtoVersionXDpos2}
	remoteCaps := []p2p.Cap{
		{Name: "eth", Version: 170}, // above ours, must be skipped
		{Name: "eth", Version: ethProtoVersionXDpos2},
	}

	c.negotiateEthProtocol(remoteCaps)

	if c.negotiatedProtoVersion != ethProtoVersionXDpos2 {
		t.Fatalf("wrong negotiated protocol version: have %d want %d", c.negotiatedProtoVersion, ethProtoVersionXDpos2)
	}
}

func TestConnNegotiatesZeroWhenNoSharedEthVersion(t *testing.T) {
	c := &Conn{ourHighestProtoVersion: ethProtoVersionXDpos2}
	remoteCaps := []p2p.Cap{{Name: "eth", Version: 170}}

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

	status := makeStatusPacket(chain, ethProtoVersionXDpos2)
	legacy, ok := status.(*statusPacket)
	if !ok {
		t.Fatalf("xdc/100 status must keep the five-field shape, got %T", status)
	}

	if legacy.ProtocolVersion != uint32(ethProtoVersionXDpos2) {
		t.Fatalf("wrong protocol version: have %d want %d", legacy.ProtocolVersion, ethProtoVersionXDpos2)
	}
	if legacy.GenesisBlock != chain.blocks[0].Hash() {
		t.Fatalf("wrong genesis hash in status: have %x want %x", legacy.GenesisBlock, chain.blocks[0].Hash())
	}
	if legacy.CurrentBlock != chain.Head().Hash() {
		t.Fatalf("wrong current block hash in status: have %x want %x", legacy.CurrentBlock, chain.Head().Hash())
	}
	if legacy.NetworkId != chain.config.ChainID.Uint64() {
		t.Fatalf("wrong network id in status: have %d want %d", legacy.NetworkId, chain.config.ChainID.Uint64())
	}
	if legacy.TD == nil {
		t.Fatal("status TD must not be nil")
	}
}

func TestMakeStatusPacketCarriesForkIDFrom164(t *testing.T) {
	chain, err := NewChain("testdata")
	if err != nil {
		t.Fatalf("failed to load chain fixtures: %v", err)
	}

	for _, version := range []uint{ethProtoVersionXDpos164, ethProtoVersionXDpos166} {
		status := makeStatusPacket(chain, version)
		forked, ok := status.(*statusPacketFork)
		if !ok {
			t.Fatalf("xdc/%d status must carry the fork-id shape, got %T", version, status)
		}
		if forked.ProtocolVersion != uint32(version) {
			t.Fatalf("wrong protocol version: have %d want %d", forked.ProtocolVersion, version)
		}
		want := forkid.NewID(chain.config, chain.blocks[0], chain.Head().NumberU64())
		if forked.ForkID != want {
			t.Fatalf("wrong fork id: have %+v want %+v", forked.ForkID, want)
		}
		if forked.GenesisBlock != chain.blocks[0].Hash() {
			t.Fatalf("wrong genesis hash in status: have %x want %x", forked.GenesisBlock, chain.blocks[0].Hash())
		}
	}

	// xdc/100 must stay fork-id free.
	if _, ok := makeStatusPacket(chain, ethProtoVersionXDpos2).(*statusPacketFork); ok {
		t.Fatal("xdc/100 status must not carry the fork id")
	}
}

func TestStatusMsgCodeMatchesEthProtocol(t *testing.T) {
	if statusMsgCode != ethproto.StatusMsg {
		t.Fatalf("status msg code drift: have %d want %d", statusMsgCode, ethproto.StatusMsg)
	}
}

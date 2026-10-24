package eth

import (
	"testing"
	"time"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	ethproto "github.com/XinFinOrg/XDPoSChain/eth/protocols/eth"
	"github.com/XinFinOrg/XDPoSChain/p2p"
	"github.com/XinFinOrg/XDPoSChain/p2p/enode"
)

func TestPeerSetRegisterRejectsDuplicateID(t *testing.T) {
	peers := newPeerSet()
	first := &peer{Peer: ethproto.NewPeer(ethproto.XDC165, p2p.NewPeer(enode.ID{1}, "dup", nil), new(nilReadWriter), nil)}
	second := &peer{Peer: ethproto.NewPeer(ethproto.XDC165, p2p.NewPeer(enode.ID{1}, "dup", nil), new(nilReadWriter), nil)}
	defer first.Close()
	defer second.Close()

	if err := peers.Register(first); err != nil {
		t.Fatalf("first register failed: %v", err)
	}
	if err := peers.Register(second); err != errAlreadyRegistered {
		t.Fatalf("second register error mismatch: got %v want %v", err, errAlreadyRegistered)
	}
	if peers.Len() != 1 {
		t.Fatalf("peer set size mismatch: got %d want 1", peers.Len())
	}
	if got := peers.Peer(first.ID()); got != first {
		t.Fatalf("registered peer replaced: got %p want %p", got, first)
	}
}

// TestPeerSetUnregisterClosesPeer ensures that Unregister closes the peer, so
// the broadcast loops behind it wind down when the peer is removed. The loops
// only exit via the termination channel (or a send error), so without this they
// leak and retain the peer for the lifetime of the process. A closed peer also
// stops accepting asynchronous sends instead of blocking the caller forever,
// which is what this asserts.
func TestPeerSetUnregisterClosesPeer(t *testing.T) {
	peers := newPeerSet()

	// Use XDC165 so the peer also runs the transaction announcer.
	p := &peer{
		Peer: ethproto.NewPeer(ethproto.XDC165, p2p.NewPeer(enode.ID{1}, "unregister", nil), new(nilReadWriter), func(common.Hash) *types.Transaction { return nil }),
	}
	if err := peers.Register(p); err != nil {
		t.Fatalf("first register failed: %v", err)
	}
	if err := peers.Unregister(p.ID()); err != nil {
		t.Fatalf("unregister failed: %v", err)
	}
	// The peer is closed, so an asynchronous send returns instead of blocking on
	// a queue nobody drains any more.
	done := make(chan struct{})
	go func() {
		p.AsyncSendTransactions([]common.Hash{{0x01}})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("async send blocked after the peer was unregistered")
	}
	// A second unregister must fail cleanly and must not close the peer again.
	if err := peers.Unregister(p.ID()); err != errNotRegistered {
		t.Fatalf("second unregister error mismatch: got %v want %v", err, errNotRegistered)
	}
}

// TestPeerSetUnregisterTwice documents that unregistering an already-removed
// peer reports errNotRegistered. A bare &peer{} would panic here: Unregister
// closes the peer, so the peer must wrap a wire peer.
func TestPeerSetUnregisterTwice(t *testing.T) {
	peers := newPeerSet()

	p := &peer{
		Peer: ethproto.NewPeer(ethproto.XDC100, p2p.NewPeer(enode.ID{1}, "twice", nil), new(nilReadWriter), func(common.Hash) *types.Transaction { return nil }),
	}
	if err := peers.Register(p); err != nil {
		t.Fatalf("register failed: %v", err)
	}
	if err := peers.Unregister(p.ID()); err != nil {
		t.Fatalf("first unregister failed: %v", err)
	}
	if err := peers.Unregister(p.ID()); err != errNotRegistered {
		t.Fatalf("second unregister error mismatch: got %v want %v", err, errNotRegistered)
	}
}

// nilReadWriter is a p2p.MsgReadWriter whose reads and writes fail, standing in
// for a connection the tests never use.
type nilReadWriter struct{}

func (nilReadWriter) ReadMsg() (p2p.Msg, error) { return p2p.Msg{}, errNotRegistered }
func (nilReadWriter) WriteMsg(p2p.Msg) error    { return errNotRegistered }

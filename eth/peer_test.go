package eth

import (
	"fmt"
	"io"
	"sync"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/p2p"
	"github.com/XinFinOrg/XDPoSChain/p2p/discover"
)

type stubMsgReadWriter struct{}

func (*stubMsgReadWriter) ReadMsg() (p2p.Msg, error) {
	return p2p.Msg{}, io.EOF
}

func (*stubMsgReadWriter) WriteMsg(p2p.Msg) error {
	return nil
}

func TestPeerSetUnregisterPairKeepsPrimaryAndClearsPairWriter(t *testing.T) {
	ps := newPeerSet()
	var id discover.NodeID
	id[0] = 1

	primaryRW := &stubMsgReadWriter{}
	pairRW := &stubMsgReadWriter{}

	primary := newPeer(eth63, p2p.NewPeer(id, "primary", nil), primaryRW)
	pair := newPeer(eth63, p2p.NewPeer(id, "pair", nil), pairRW)

	if err := ps.Register(primary); err != nil {
		t.Fatalf("register primary: %v", err)
	}
	if err := ps.Register(pair); err != p2p.ErrAddPairPeer {
		t.Fatalf("register pair: got %v want %v", err, p2p.ErrAddPairPeer)
	}
	if primary.pairRW() != pair.rw {
		t.Fatal("primary did not record pair writer")
	}
	if pair.PairPeer() != primary.Peer {
		t.Fatal("pair peer did not record primary peer")
	}

	if err := ps.UnregisterPeer(pair); err != nil {
		t.Fatalf("unregister pair: %v", err)
	}
	if got := ps.Peer(primary.id); got != primary {
		t.Fatal("primary peer was removed while unregistering pair")
	}
	if primary.pairRW() != nil {
		t.Fatal("primary peer still references pair writer after unregister")
	}
	if primary.PairPeer() != nil {
		t.Fatal("primary peer still references pair peer after unregister")
	}
	if pair.PairPeer() != nil {
		t.Fatal("pair peer still references primary peer after unregister")
	}
}

func TestPeerSetUnregisterPrimaryKeepsPairLinkForDisconnect(t *testing.T) {
	ps := newPeerSet()
	var id discover.NodeID
	id[0] = 2

	primaryRW := &stubMsgReadWriter{}
	pairRW := &stubMsgReadWriter{}

	primary := newPeer(eth63, p2p.NewPeer(id, "primary", nil), primaryRW)
	pair := newPeer(eth63, p2p.NewPeer(id, "pair", nil), pairRW)

	if err := ps.Register(primary); err != nil {
		t.Fatalf("register primary: %v", err)
	}
	if err := ps.Register(pair); err != p2p.ErrAddPairPeer {
		t.Fatalf("register pair: got %v want %v", err, p2p.ErrAddPairPeer)
	}
	if primary.pairRW() != pair.rw {
		t.Fatal("primary did not record pair writer")
	}
	if primary.PairPeer() != pair.Peer {
		t.Fatal("primary peer did not record pair peer")
	}

	if err := ps.UnregisterPeer(primary); err != nil {
		t.Fatalf("unregister primary: %v", err)
	}
	if got := ps.Peer(primary.id); got != nil {
		t.Fatal("primary peer still registered after unregister")
	}
	if primary.pairRW() != nil {
		t.Fatal("primary peer still references pair writer after unregister")
	}
	if primary.PairPeer() != pair.Peer {
		t.Fatal("primary peer lost pair link needed for disconnect cleanup")
	}
	if pair.PairPeer() != primary.Peer {
		t.Fatal("pair peer lost primary reference unexpectedly")
	}
}

func TestPeerPairRWConcurrentRegisterAndSend(t *testing.T) {
	ps := newPeerSet()
	var id discover.NodeID
	id[0] = 3

	primary := newPeer(eth63, p2p.NewPeer(id, "primary", nil), &stubMsgReadWriter{})
	pair := newPeer(eth63, p2p.NewPeer(id, "pair", nil), &stubMsgReadWriter{})

	if err := ps.Register(primary); err != nil {
		t.Fatalf("register primary: %v", err)
	}
	if err := ps.Register(pair); err != p2p.ErrAddPairPeer {
		t.Fatalf("register pair: got %v want %v", err, p2p.ErrAddPairPeer)
	}

	start := make(chan struct{})
	errc := make(chan error, 2)
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < 2000; i++ {
			if err := primary.SendBlockHeaders(nil); err != nil {
				errc <- fmt.Errorf("send block headers: %w", err)
				return
			}
		}
	}()

	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < 2000; i++ {
			if err := ps.UnregisterPeer(pair); err != nil {
				errc <- fmt.Errorf("unregister pair: %w", err)
				return
			}
			if err := ps.Register(pair); err != p2p.ErrAddPairPeer {
				errc <- fmt.Errorf("register pair: got %v want %v", err, p2p.ErrAddPairPeer)
				return
			}
		}
	}()

	close(start)
	wg.Wait()
	close(errc)

	for err := range errc {
		if err != nil {
			t.Fatal(err)
		}
	}
}

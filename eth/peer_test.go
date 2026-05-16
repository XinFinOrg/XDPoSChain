// Copyright 2023 The go-ethereum Authors
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
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/p2p"
	"github.com/XinFinOrg/XDPoSChain/p2p/enode"
)

type stubMsgReadWriter struct{}

func (*stubMsgReadWriter) ReadMsg() (p2p.Msg, error) {
	return p2p.Msg{}, io.EOF
}

func (*stubMsgReadWriter) WriteMsg(p2p.Msg) error {
	return nil
}

func TestPeerMsgWriterUsesAtomicPairWriter(t *testing.T) {
	var p peer

	primaryRW := &stubMsgReadWriter{}
	pairedRW := p2p.MsgReadWriter(&stubMsgReadWriter{})
	p.rw = primaryRW

	if got := p.msgWriter(); got != primaryRW {
		t.Fatal("msgWriter should return primary writer when pair writer is unset")
	}

	p.setPairWriter(&pairedRW)
	if got := p.msgWriter(); got != pairedRW {
		t.Fatal("msgWriter should return pair writer when one is registered")
	}

	p.clearPairWriter()
	if got := p.msgWriter(); got != primaryRW {
		t.Fatal("msgWriter should fall back to primary writer after clearing pair writer")
	}
}

func TestPeerSetUnregisterPairKeepsPrimaryAndClearsPairWriter(t *testing.T) {
	ps := newPeerSet()
	var id enode.ID
	id[0] = 1

	primaryRW := &stubMsgReadWriter{}
	pairRW := &stubMsgReadWriter{}

	primary := newPeer(eth63, p2p.NewPeer(id, "primary", nil), primaryRW)
	pair := newPeer(eth63, p2p.NewPeer(id, "pair", nil), pairRW)

	if err := ps.Register(primary); err != nil {
		t.Fatalf("register primary: %v", err)
	}
	if primary.isPair {
		t.Fatal("primary peer should not be marked as pair after primary registration")
	}
	if err := ps.Register(pair); err != p2p.ErrAddPairPeer {
		t.Fatalf("register pair: got %v want %v", err, p2p.ErrAddPairPeer)
	}
	if !pair.isPair {
		t.Fatal("paired peer should be marked as pair after duplicate registration")
	}
	if primary.pairWriter() != pair.rw {
		t.Fatal("primary did not record pair writer")
	}
	if pair.PairPeer() != primary.Peer {
		t.Fatal("pair peer did not record primary peer")
	}

	removedPrimary, err := ps.UnregisterPeer(pair)
	if err != nil {
		t.Fatalf("unregister pair: %v", err)
	}
	if removedPrimary {
		t.Fatal("pair unregister should not report primary removal")
	}
	if got := ps.Peer(primary.id); got != primary {
		t.Fatal("primary peer was removed while unregistering pair")
	}
	if primary.pairWriter() != nil {
		t.Fatal("primary peer still references pair writer after unregister")
	}
	if primary.PairPeer() != nil {
		t.Fatal("primary peer still references pair peer after unregister")
	}
	if pair.PairPeer() != nil {
		t.Fatal("pair peer still references primary peer after unregister")
	}
}

func TestPeerSetUnregisterPrimaryKeepsDisconnectLinkAndClearsPairBacklink(t *testing.T) {
	ps := newPeerSet()
	var id enode.ID
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
	if primary.pairWriter() != pair.rw {
		t.Fatal("primary did not record pair writer")
	}
	if primary.PairPeer() != pair.Peer {
		t.Fatal("primary peer did not record pair peer")
	}

	removedPrimary, err := ps.UnregisterPeer(primary)
	if err != nil {
		t.Fatalf("unregister primary: %v", err)
	}
	if !removedPrimary {
		t.Fatal("primary unregister should report primary removal")
	}
	if got := ps.Peer(primary.id); got != nil {
		t.Fatal("primary peer still registered after unregister")
	}
	if primary.pairWriter() != nil {
		t.Fatal("primary peer still references pair writer after unregister")
	}
	if primary.PairPeer() != pair.Peer {
		t.Fatal("primary peer lost pair link needed for disconnect cleanup")
	}
	if pair.PairPeer() != nil {
		t.Fatal("pair peer still references removed primary")
	}
}

func TestPeerSetUnregisterPairAfterDisconnectReturnsPairNotRegistered(t *testing.T) {
	ps := newPeerSet()
	var id enode.ID
	id[0] = 3

	primary := newPeer(eth63, p2p.NewPeer(id, "primary", nil), &stubMsgReadWriter{})
	pair := newPeer(eth63, p2p.NewPeer(id, "pair", nil), &stubMsgReadWriter{})

	if err := ps.Register(primary); err != nil {
		t.Fatalf("register primary: %v", err)
	}
	if err := ps.Register(pair); err != p2p.ErrAddPairPeer {
		t.Fatalf("register pair: got %v want %v", err, p2p.ErrAddPairPeer)
	}
	removedPrimary, err := ps.UnregisterPeer(pair)
	if err != nil {
		t.Fatalf("first unregister pair: %v", err)
	}
	if removedPrimary {
		t.Fatal("pair unregister should not report primary removal")
	}
	removedPrimary, err = ps.UnregisterPeer(pair)
	if err != errPairNotRegistered {
		t.Fatalf("second unregister pair: got %v want %v", err, errPairNotRegistered)
	}
	if removedPrimary {
		t.Fatal("stale pair unregister should not report primary removal")
	}
	if got := ps.Peer(primary.id); got != primary {
		t.Fatal("primary peer was removed after pair double unregister")
	}
	if primary.pairWriter() != nil {
		t.Fatal("primary peer still references pair writer after pair double unregister")
	}
	if primary.PairPeer() != nil {
		t.Fatal("primary peer still references pair peer after pair double unregister")
	}
	if pair.PairPeer() != nil {
		t.Fatal("pair peer still references primary peer after pair double unregister")
	}
}

func TestPeerSetUnregisterStalePairAfterPrimaryRemovalReturnsPairNotRegistered(t *testing.T) {
	ps := newPeerSet()
	var id enode.ID
	id[0] = 5

	primary := newPeer(eth63, p2p.NewPeer(id, "primary", nil), &stubMsgReadWriter{})
	pair := newPeer(eth63, p2p.NewPeer(id, "pair", nil), &stubMsgReadWriter{})

	if err := ps.Register(primary); err != nil {
		t.Fatalf("register primary: %v", err)
	}
	if err := ps.Register(pair); err != p2p.ErrAddPairPeer {
		t.Fatalf("register pair: got %v want %v", err, p2p.ErrAddPairPeer)
	}
	removedPrimary, err := ps.UnregisterPeer(primary)
	if err != nil {
		t.Fatalf("unregister primary: %v", err)
	}
	if !removedPrimary {
		t.Fatal("primary unregister should report primary removal")
	}
	removedPrimary, err = ps.UnregisterPeer(pair)
	if err != errPairNotRegistered {
		t.Fatalf("unregister stale pair: got %v want %v", err, errPairNotRegistered)
	}
	if removedPrimary {
		t.Fatal("stale pair unregister should not report primary removal")
	}
	if errors.Is(errPairNotRegistered, errNotRegistered) {
		t.Fatal("pair not registered should remain distinct from not registered")
	}
	removedPrimary, err = ps.UnregisterPeer(primary)
	if err != errNotRegistered {
		t.Fatalf("unregister stale primary: got %v want %v", err, errNotRegistered)
	}
	if removedPrimary {
		t.Fatal("stale primary unregister should not report primary removal")
	}
}

func TestPeerSetUnregisterStalePairAfterPrimaryClearsPairReturnsPairNotRegistered(t *testing.T) {
	ps := newPeerSet()
	var id enode.ID
	id[0] = 7

	primary := newPeer(eth63, p2p.NewPeer(id, "primary", nil), &stubMsgReadWriter{})
	pair := newPeer(eth63, p2p.NewPeer(id, "pair", nil), &stubMsgReadWriter{})

	if err := ps.Register(primary); err != nil {
		t.Fatalf("register primary: %v", err)
	}
	if err := ps.Register(pair); err != p2p.ErrAddPairPeer {
		t.Fatalf("register pair: got %v want %v", err, p2p.ErrAddPairPeer)
	}
	if !primary.ClearPairPeer(pair.Peer) {
		t.Fatal("primary pair link was not established")
	}
	primary.clearPairWriter()

	removedPrimary, err := ps.UnregisterPeer(pair)
	if err != errPairNotRegistered {
		t.Fatalf("unregister stale pair after primary clear: got %v want %v", err, errPairNotRegistered)
	}
	if removedPrimary {
		t.Fatal("stale pair unregister should not report primary removal")
	}
	if got := ps.Peer(primary.id); got != primary {
		t.Fatal("primary peer should remain registered after stale pair cleanup")
	}
	if primary.PairPeer() != nil {
		t.Fatal("primary peer should keep cleared pair reference")
	}
	if pair.PairPeer() != primary.Peer {
		t.Fatal("pair peer should retain stale primary reference for cleanup path")
	}
}

func TestPeerSetUnregisterRejectedDuplicatePairReturnsPairNotRegistered(t *testing.T) {
	ps := newPeerSet()
	var id enode.ID
	id[0] = 6

	primary := newPeer(eth63, p2p.NewPeer(id, "primary", nil), &stubMsgReadWriter{})
	pair := newPeer(eth63, p2p.NewPeer(id, "pair", nil), &stubMsgReadWriter{})
	rejectedPair := newPeer(eth63, p2p.NewPeer(id, "rejected-pair", nil), &stubMsgReadWriter{})

	if err := ps.Register(primary); err != nil {
		t.Fatalf("register primary: %v", err)
	}
	if err := ps.Register(pair); err != p2p.ErrAddPairPeer {
		t.Fatalf("register pair: got %v want %v", err, p2p.ErrAddPairPeer)
	}
	if err := ps.Register(rejectedPair); err != errAlreadyRegistered {
		t.Fatalf("register rejected pair: got %v want %v", err, errAlreadyRegistered)
	}
	if !rejectedPair.isPair {
		t.Fatal("rejected duplicate pair should retain pair role for cleanup semantics")
	}
	removedPrimary, err := ps.UnregisterPeer(rejectedPair)
	if err != errPairNotRegistered {
		t.Fatalf("unregister rejected pair: got %v want %v", err, errPairNotRegistered)
	}
	if removedPrimary {
		t.Fatal("rejected pair unregister should not report primary removal")
	}
	if rejectedPair.PairPeer() != nil {
		t.Fatal("rejected pair should not retain a pair peer link")
	}
	if primary.pairWriter() != pair.rw {
		t.Fatal("primary pair writer changed after rejected duplicate pair")
	}
}

func TestPeerPairRWConcurrentRegisterAndSend(t *testing.T) {
	ps := newPeerSet()
	var id enode.ID
	id[0] = 4

	primary := newPeer(eth63, p2p.NewPeer(id, "primary", nil), &stubMsgReadWriter{})
	pair := newPeer(eth63, p2p.NewPeer(id, "pair", nil), &stubMsgReadWriter{})

	if err := ps.Register(primary); err != nil {
		t.Fatalf("register primary: %v", err)
	}
	if err := ps.Register(pair); err != p2p.ErrAddPairPeer {
		t.Fatalf("register pair: got %v want %v", err, p2p.ErrAddPairPeer)
	}

	start := make(chan struct{})
	errc := make(chan error, 3)
	var lifecycleMu sync.Mutex
	var primaryCycles atomic.Int32
	var wg sync.WaitGroup
	wg.Add(3)

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
			lifecycleMu.Lock()
			removedPrimary, err := ps.UnregisterPeer(pair)
			if err != nil {
				lifecycleMu.Unlock()
				errc <- fmt.Errorf("unregister pair: %w", err)
				return
			}
			if removedPrimary {
				lifecycleMu.Unlock()
				errc <- fmt.Errorf("unregister pair: reported primary removal")
				return
			}
			if err := ps.Register(pair); err != p2p.ErrAddPairPeer {
				lifecycleMu.Unlock()
				errc <- fmt.Errorf("register pair: got %v want %v", err, p2p.ErrAddPairPeer)
				return
			}
			lifecycleMu.Unlock()
		}
	}()

	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < 200; i++ {
			lifecycleMu.Lock()
			removedPrimary, err := ps.UnregisterPeer(primary)
			if err != nil {
				lifecycleMu.Unlock()
				errc <- fmt.Errorf("unregister primary: %w", err)
				return
			}
			if !removedPrimary {
				lifecycleMu.Unlock()
				errc <- fmt.Errorf("unregister primary: did not report primary removal")
				return
			}
			primaryCycles.Add(1)
			if err := ps.Register(primary); err != nil {
				lifecycleMu.Unlock()
				errc <- fmt.Errorf("register primary: %v", err)
				return
			}
			if err := ps.Register(pair); err != p2p.ErrAddPairPeer {
				lifecycleMu.Unlock()
				errc <- fmt.Errorf("re-register pair after primary: got %v want %v", err, p2p.ErrAddPairPeer)
				return
			}
			lifecycleMu.Unlock()
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
	if primaryCycles.Load() == 0 {
		t.Fatal("primary unregister path was not exercised")
	}
	if got := ps.Peer(primary.id); got != primary {
		t.Fatal("primary peer was not restored after concurrent lifecycle churn")
	}
	if primary.pairWriter() != pair.rw {
		t.Fatal("primary peer did not restore pair writer after primary re-register")
	}
}

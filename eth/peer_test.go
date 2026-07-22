package eth

import "testing"

func TestPeerSetRegisterRejectsDuplicateID(t *testing.T) {
	peers := newPeerSet()
	first := &peer{id: "dup"}
	second := &peer{id: "dup"}

	if err := peers.Register(first); err != nil {
		t.Fatalf("first register failed: %v", err)
	}
	if err := peers.Register(second); err != errAlreadyRegistered {
		t.Fatalf("second register error mismatch: got %v want %v", err, errAlreadyRegistered)
	}
	if peers.Len() != 1 {
		t.Fatalf("peer set size mismatch: got %d want 1", peers.Len())
	}
	if got := peers.Peer("dup"); got != first {
		t.Fatalf("registered peer replaced: got %p want %p", got, first)
	}
}

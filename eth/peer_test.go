package eth

import "testing"

// TestPeerMarkRemovedOnce verifies that a peer's removal is claimed exactly once.
func TestPeerMarkRemovedOnce(t *testing.T) {
	p := &peer{}
	if !p.markRemoved() {
		t.Fatal("first markRemoved should claim the removal")
	}
	for i := 0; i < 10; i++ {
		if p.markRemoved() {
			t.Fatalf("markRemoved should not claim a removal after it was already claimed (iteration %d)", i)
		}
	}
}

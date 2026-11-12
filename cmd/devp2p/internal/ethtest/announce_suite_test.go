package ethtest

import (
	"testing"

	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/rlp"
)

// The large announcement cases assert on this rejection path
func TestLargeHeaderFailsSanityCheck(t *testing.T) {
	header := largeHeader()
	if err := header.SanityCheck(); err == nil {
		t.Fatal("expected oversized header to fail sanity check")
	}
}

// A body mismatch would make the node drop the payload silently instead of
// rejecting it for size
func TestLargeBlockBodyHashesConsistent(t *testing.T) {
	header := largeHeader()
	if header.TxHash != types.EmptyRootHash {
		t.Fatalf("wrong tx hash: have %s, want %s", header.TxHash, types.EmptyRootHash)
	}
	if header.UncleHash != types.EmptyUncleHash {
		t.Fatalf("wrong uncle hash: have %s, want %s", header.UncleHash, types.EmptyUncleHash)
	}
}

// Inside the frame cap, so a rejection must come from the sanity checks
func TestLargeBlockFitsFrameButNotChecks(t *testing.T) {
	b, err := rlp.EncodeToBytes(largeBlock())
	if err != nil {
		t.Fatalf("failed to encode oversized block: %v", err)
	}
	if len(b) < 4*1024*1024 {
		t.Fatalf("oversized block unexpectedly small: %d bytes", len(b))
	}
	// Past the 10MB frame cap the payload would never reach the sanity checks
	if len(b) >= 10*1024*1024 {
		t.Fatalf("oversized block exceeds the frame cap: %d bytes", len(b))
	}
}

// One block past the head keeps it inside the fetcher plausibility window
func TestUnknownSuccessorHashIsPlausible(t *testing.T) {
	s := loadTestSuite(t)
	hash, number := s.unknownSuccessorHash()
	if s.chain.findBlockByHash(hash) != nil {
		t.Fatal("expected announced hash to be unknown to the fixture chain")
	}
	if number != uint64(s.chain.Len()) {
		t.Fatalf("wrong announced number: have %d, want %d", number, s.chain.Len())
	}
}

package ethtest

import (
	"testing"

	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/rlp"
)

// TestLargeHeaderFailsSanityCheck verifies the oversized announcement payload
// trips the node's header sanity check, which is the rejection path the large
// announcement cases assert on.
func TestLargeHeaderFailsSanityCheck(t *testing.T) {
	header := largeHeader()
	if err := header.SanityCheck(); err == nil {
		t.Fatal("expected oversized header to fail sanity check")
	}
}

// TestLargeBlockBodyHashesConsistent verifies the oversized header carries
// body hashes consistent with its empty body, so a node rejects the payload
// for its size instead of silently dropping it for a body mismatch.
func TestLargeBlockBodyHashesConsistent(t *testing.T) {
	header := largeHeader()
	if header.TxHash != types.EmptyRootHash {
		t.Fatalf("wrong tx hash: have %s, want %s", header.TxHash, types.EmptyRootHash)
	}
	if header.UncleHash != types.EmptyUncleHash {
		t.Fatalf("wrong uncle hash: have %s, want %s", header.UncleHash, types.EmptyUncleHash)
	}
}

// TestLargeBlockFitsFrameButNotChecks verifies the oversized announcement
// payload fits inside the wire frame size cap, so a node's rejection must come
// from the announcement sanity checks rather than the frame limit.
func TestLargeBlockFitsFrameButNotChecks(t *testing.T) {
	b, err := rlp.EncodeToBytes(largeBlock())
	if err != nil {
		t.Fatalf("failed to encode oversized block: %v", err)
	}
	// The two multi-megabyte header fields alone exceed four megabytes.
	if len(b) < 4*1024*1024 {
		t.Fatalf("oversized block unexpectedly small: %d bytes", len(b))
	}
	// The node's protocol frame cap is 10MB; a payload past it would be
	// dropped at the frame layer and never reach the sanity checks.
	if len(b) >= 10*1024*1024 {
		t.Fatalf("oversized block exceeds the frame cap: %d bytes", len(b))
	}
}

// TestUnknownSuccessorHashIsPlausible verifies the hash announced by the block
// hash announcement cases is unknown to the fixture chain and points one block
// past its head, which keeps it inside the fetcher's plausibility window.
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

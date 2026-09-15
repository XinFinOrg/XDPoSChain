package core

import (
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// TestHeaderChainShouldHandleProposedBlock fixates the interface adaptation:
// *HeaderChain satisfies consensus.ChainReader only so the interface stays
// closed, but it stores no block bodies and deliberately does not implement
// consensus.BlockStorer. The shared proposed-block gate must therefore skip
// every block with SkipUnjudgeable — graded Error, not judge every block
// "not stored" — so a HeaderChain handed to the consensus engine by mistake
// cannot silently drop QC processing and voting behind an Info log.
func TestHeaderChainShouldHandleProposedBlock(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	genesis := &types.Header{Number: big.NewInt(0)}
	rawdb.WriteHeader(db, genesis)
	rawdb.WriteCanonicalHash(db, genesis.Hash(), 0)
	hc, err := NewHeaderChain(db, params.TestChainConfig, nil, func() bool { return false })
	if err != nil {
		t.Fatal("Fail to create header chain", err)
	}

	// A header stored header-only (the fast sync header phase shape): canonical
	// at its height, so the gate reaches the storage half — which a header
	// chain cannot answer — and must skip it as unjudgeable.
	if ok, reason, _ := consensus.ShouldHandleProposedBlock(hc, genesis); ok || reason != consensus.SkipUnjudgeable {
		t.Fatalf("a header chain must be skipped as unjudgeable by the proposed-block gate, got ok=%v reason=%q", ok, reason)
	}

	missing := &types.Header{Number: big.NewInt(5)}
	// The BlockStorer assertion runs before any chain read, so an absent
	// height is reported as unjudgeable too, not silently skipped on the
	// canonicality half.
	if ok, reason, canonicalHash := consensus.ShouldHandleProposedBlock(hc, missing); ok || reason != consensus.SkipUnjudgeable || canonicalHash != (common.Hash{}) {
		t.Fatalf("an absent height must also be reported as unjudgeable on a header chain, got ok=%v reason=%q canonicalHash=%v", ok, reason, canonicalHash)
	}

	// The block-retrieval stub itself.
	if block := hc.GetBlock(genesis.Hash(), 0); block != nil {
		t.Fatalf("HeaderChain.GetBlock must return nil, got %v", block)
	}
}

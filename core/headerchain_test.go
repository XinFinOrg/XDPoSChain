// Copyright 2026 The go-ethereum Authors
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
// *HeaderChain satisfies consensus.ChainReader but stores no bodies and does not
// implement consensus.BlockStorer, so the gate must skip it as SkipUnjudgeable
// rather than judge every block "not stored".
func TestHeaderChainShouldHandleProposedBlock(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	genesis := &types.Header{Number: big.NewInt(0)}
	rawdb.WriteHeader(db, genesis)
	rawdb.WriteCanonicalHash(db, genesis.Hash(), 0)
	hc, err := NewHeaderChain(db, params.TestChainConfig, nil, func() bool { return false })
	if err != nil {
		t.Fatal("Fail to create header chain", err)
	}

	// A header-only height is canonical, so the gate reaches the storage half a
	// header chain cannot answer.
	if ok, reason, _ := consensus.ShouldHandleProposedBlock(hc, genesis); ok || reason != consensus.SkipUnjudgeable {
		t.Fatalf("a header chain must be skipped as unjudgeable by the proposed-block gate, got ok=%v reason=%q", ok, reason)
	}

	missing := &types.Header{Number: big.NewInt(5)}
	// The BlockStorer check runs before any chain read, so an absent height is
	// unjudgeable too.
	if ok, reason, canonicalHash := consensus.ShouldHandleProposedBlock(hc, missing); ok || reason != consensus.SkipUnjudgeable || canonicalHash != (common.Hash{}) {
		t.Fatalf("an absent height must also be reported as unjudgeable on a header chain, got ok=%v reason=%q canonicalHash=%v", ok, reason, canonicalHash)
	}

	// The block-retrieval stub itself.
	if block := hc.GetBlock(genesis.Hash(), 0); block != nil {
		t.Fatalf("HeaderChain.GetBlock must return nil, got %v", block)
	}
}

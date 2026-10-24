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
	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/ethdb"
)

// ancestorTestChain builds a header-only canonical chain of the given height and
// returns it together with its headers in ascending height order, so a test can
// state the expected ancestor as headers[height-ancestor].
func ancestorTestChain(t *testing.T, height int) (*BlockChain, []*types.Header) {
	t.Helper()

	_, _, blockchain, err := newCanonical(ethash.NewFaker(), height, false)
	if err != nil {
		t.Fatalf("failed to build canonical chain: %v", err)
	}
	t.Cleanup(blockchain.Stop)

	headers := make([]*types.Header, height+1)
	for i := range headers {
		headers[i] = blockchain.GetHeaderByNumber(uint64(i))
		if headers[i] == nil {
			t.Fatalf("missing canonical header %d", i)
		}
		if i > 0 && headers[i].ParentHash != headers[i-1].Hash() {
			t.Fatalf("canonical header %d does not link to header %d", i, i-1)
		}
	}
	return blockchain, headers
}

// writeForkHeaders writes a branch of the given length forking off parent to the
// database, without making it canonical: the headers are readable by hash and
// number, but the canonical index still maps their heights to the real chain.
func writeForkHeaders(t *testing.T, db ethdb.Database, parent *types.Header, length int) []*types.Header {
	t.Helper()

	headers := make([]*types.Header, length)
	for i := range headers {
		headers[i] = &types.Header{
			ParentHash: parent.Hash(),
			Number:     new(big.Int).SetUint64(parent.Number.Uint64() + 1),
			Difficulty: parent.Difficulty,
			GasLimit:   parent.GasLimit,
			Time:       parent.Time + 1,
		}
		rawdb.WriteHeader(db, headers[i])
		parent = headers[i]
	}
	return headers
}

// TestHeaderChainGetAncestorCanonical pins the answers on the canonical chain and
// the two boundaries the caller has to know about: ancestor 0 is the block itself,
// and an ancestor at or beyond genesis yields the zero value.
func TestHeaderChainGetAncestorCanonical(t *testing.T) {
	blockchain, headers := ancestorTestChain(t, 10)
	head := headers[10]

	tests := []struct {
		name       string
		hash       common.Hash
		number     uint64
		ancestor   uint64
		wantHash   common.Hash
		wantNumber uint64
	}{
		{"same block", head.Hash(), 10, 0, head.Hash(), 10},
		{"parent", head.Hash(), 10, 1, headers[9].Hash(), 9},
		{"mid chain", head.Hash(), 10, 5, headers[5].Hash(), 5},
		{"genesis", head.Hash(), 10, 10, headers[0].Hash(), 0},
		{"beyond genesis", head.Hash(), 10, 11, common.Hash{}, 0},
		{"genesis has no ancestor", headers[0].Hash(), 0, 1, common.Hash{}, 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			budget := uint64(10)
			hash, number := blockchain.hc.GetAncestor(test.hash, test.number, test.ancestor, &budget)
			if hash != test.wantHash || number != test.wantNumber {
				t.Fatalf("ancestor lookup returned (%v, %d), want (%v, %d)", hash, number, test.wantHash, test.wantNumber)
			}
			if budget != 10 {
				t.Fatalf("canonical lookup consumed the non-canonical budget, %d of 10 left", budget)
			}
		})
	}
}

// TestHeaderChainGetAncestorCanonicalIndexOnly removes every intermediate header
// from the database, so the queried ancestor can only be answered from the
// canonical index: a lookup that walks headers one by one cannot find its way.
func TestHeaderChainGetAncestorCanonicalIndexOnly(t *testing.T) {
	blockchain, headers := ancestorTestChain(t, 10)
	for i := 1; i < len(headers)-1; i++ {
		rawdb.DeleteHeader(blockchain.db, headers[i].Hash(), uint64(i))
	}
	hc, err := NewHeaderChain(blockchain.db, blockchain.Config(), blockchain.Engine(), func() bool { return false })
	if err != nil {
		t.Fatalf("failed to reopen the header chain: %v", err)
	}
	budget := uint64(0)
	hash, number := hc.GetAncestor(headers[10].Hash(), 10, 5, &budget)
	if hash != headers[5].Hash() || number != 5 {
		t.Fatalf("ancestor lookup returned (%v, %d), want (%v, 5)", hash, number, headers[5].Hash())
	}
	if budget != 0 {
		t.Fatalf("canonical lookup consumed the non-canonical budget, %d left", budget)
	}
}

// TestHeaderChainGetAncestorOffCanonical covers origins that are not on the
// canonical chain: the walk towards the canonical chain is paid for out of the
// caller's budget, and once that is gone the lookup gives up.
func TestHeaderChainGetAncestorOffCanonical(t *testing.T) {
	const forkHeight = 4
	blockchain, headers := ancestorTestChain(t, 10)
	fork := writeForkHeaders(t, blockchain.db, headers[forkHeight], 3) // heights 5, 6, 7
	origin := fork[2]

	tests := []struct {
		name       string
		hash       common.Hash
		number     uint64
		ancestor   uint64
		budget     uint64
		wantHash   common.Hash
		wantNumber uint64
		wantBudget uint64
	}{
		// Three fork headers stand between the origin and the canonical chain.
		{"budget exactly covers the walk", origin.Hash(), 7, 4, 3, headers[3].Hash(), 3, 0},
		{"budget left over", origin.Hash(), 7, 4, 5, headers[3].Hash(), 3, 2},
		{"budget runs out", origin.Hash(), 7, 4, 2, common.Hash{}, 0, 0},
		{"no budget at all", origin.Hash(), 7, 4, 0, common.Hash{}, 0, 0},
		{"parent is read without budget", origin.Hash(), 7, 1, 0, fork[1].Hash(), 6, 0},
		{"unknown hash", common.HexToHash("0xdeadbeef"), 7, 4, 3, common.Hash{}, 0, 2},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			budget := test.budget
			hash, number := blockchain.hc.GetAncestor(test.hash, test.number, test.ancestor, &budget)
			if hash != test.wantHash || number != test.wantNumber {
				t.Fatalf("ancestor lookup returned (%v, %d), want (%v, %d)", hash, number, test.wantHash, test.wantNumber)
			}
			if budget != test.wantBudget {
				t.Fatalf("ancestor lookup left a budget of %d, want %d", budget, test.wantBudget)
			}
		})
	}
}

// TestBlockChainGetAncestor checks that the chain exposes the same lookup, which
// is what the protocol's header serving will call.
func TestBlockChainGetAncestor(t *testing.T) {
	blockchain, headers := ancestorTestChain(t, 10)
	budget := uint64(10)
	hash, number := blockchain.GetAncestor(headers[10].Hash(), 10, 3, &budget)
	if hash != headers[7].Hash() || number != 7 {
		t.Fatalf("ancestor lookup returned (%v, %d), want (%v, 7)", hash, number, headers[7].Hash())
	}
	if budget != 10 {
		t.Fatalf("canonical lookup consumed the non-canonical budget, %d of 10 left", budget)
	}
}

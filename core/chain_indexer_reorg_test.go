// Copyright 2026 The XDPoSChain Authors
// This file is part of the XDPoSChain library.
//
// The XDPoSChain library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The XDPoSChain library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the XDPoSChain library. If not, see <http://www.gnu.org/licenses/>.

package core

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/types"
)

// TestMinReorgStraddle pins down the section count of a child indexer after a
// reorg. A two level chain (parent sectionSize 1, child sectionSize 2) is fed
// blocks 0..100; then the chain reorgs to block 50 and blocks 51..100 are
// replaced by a new fork.
//
// A child must never retain a section holding blocks past the reorg point: with
// sectionSize 2 the child may keep 25 sections (blocks 0..49), because its
// section 25 (blocks 50..51) contains the invalidated block 51. Cascade the reorg
// point itself instead of the end of the parent's retained prefix and the child
// keeps 26 sections until verifyLastHead() rolls the invalid section back once
// the new fork block 51 is written - the intermittent "Canonical section count
// mismatch" of TestChainIndexerWithChildren.
func TestMinReorgStraddle(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	defer db.Close()

	sectionSizes := []uint64{1, 2}
	confirmsReqs := []uint64{0, 0}
	backends := make([]*testChainIndexBackend, len(sectionSizes))
	for i := range sectionSizes {
		backends[i] = &testChainIndexBackend{t: t, processCh: make(chan uint64)}
		backends[i].indexer = NewChainIndexer(db, rawdb.NewTable(db, string([]byte{byte(i)})), backends[i], sectionSizes[i], confirmsReqs[i], 0, fmt.Sprintf("indexer-%d", i))
		if i > 0 {
			backends[i-1].indexer.AddChildIndexer(backends[i].indexer)
		}
	}
	defer backends[0].indexer.Close()

	var gen int64
	inject := func(number uint64) {
		gen++
		header := &types.Header{Number: big.NewInt(int64(number)), Extra: big.NewInt(gen).Bytes()}
		if number > 0 {
			header.ParentHash = rawdb.ReadCanonicalHash(db, number-1)
		}
		rawdb.WriteHeader(db, header)
		rawdb.WriteCanonicalHash(db, header.Hash(), number)
	}
	notify := func(headNum, failNum uint64, reorg bool) {
		backends[0].indexer.newHead(headNum, reorg)
		if reorg {
			for _, backend := range backends {
				headNum = backend.reorg(headNum)
				backend.assertSections()
			}
			return
		}
		var cascade bool
		for _, backend := range backends {
			headNum, cascade = backend.assertBlocks(headNum, failNum)
			if !cascade {
				break
			}
			backend.assertSections()
		}
	}
	for i := uint64(0); i <= 100; i++ {
		inject(i)
	}
	notify(100, 100, false)

	// Reorg to block 50; blocks above 50 are replaced by a new fork.
	notify(50, 50, true)

	for i := uint64(51); i <= 100; i++ {
		inject(i)
		notify(i, i, false)
	}
}

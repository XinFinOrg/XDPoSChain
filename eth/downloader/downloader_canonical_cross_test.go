// Copyright 2025 The go-ethereum Authors
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

package downloader

import (
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
)

// TestCanonicalMirrorMatchesRealChain cross-validates the tester's fork-choice
// mirror (storeBlock / canonicalize / removeAbove / rebuildOwnHashes and the
// head getters) against a real core.BlockChain: the same blocks go through
// dl.InsertChain and blockchain.InsertChain, and the canonical table plus the
// canonical headers must agree at every height after every batch. The
// canonicalize early break (common ancestor reached), the equal-total-
// difficulty side-entry rule (the selfish-mining guard) and the heavier-
// takeover reorg all get independent evidence this way, instead of only the
// tester confirming its own behavior.
//
// The block material comes from core.GenerateChain, so every block has valid
// state and is importable into a real chain; the tester's fake state database
// only needs the parent-root markers it records itself.
func TestCanonicalMirrorMatchesRealChain(t *testing.T) {
	engine := ethash.NewFaker()
	genDb := rawdb.NewMemoryDatabase()
	testGspec.MustCommit(genDb)
	// main: 8 equal-difficulty blocks. fork: 8 equal-difficulty blocks
	// branching from main's height-4 block, with distinct extra data so the
	// hashes differ from main's blocks at the same heights. Fork blocks
	// 0..3 replay heights 5..8 at equal total difficulty (side entries on
	// both sides); fork block 4 reaches height 9 with a higher total
	// difficulty than main's head (reorg to the fork on both sides); the
	// tail extends it.
	main, _ := core.GenerateChain(testChainConfig, testGenesis, engine, genDb, 8, func(i int, gen *core.BlockGen) {})
	fork, _ := core.GenerateChain(testChainConfig, main[3], engine, genDb, 8, func(i int, gen *core.BlockGen) {
		gen.SetExtra([]byte("fork"))
	})

	dl := newTester()
	defer dl.terminate()
	realDb := rawdb.NewMemoryDatabase()
	testGspec.MustCommit(realDb)
	blockchain, err := core.NewBlockChain(realDb, nil, testGspec, engine, vm.Config{})
	if err != nil {
		t.Fatalf("failed to create real blockchain: %v", err)
	}

	// compare asserts that the tester's canonical table and canonical headers
	// match the real chain's markers at every height up to head.
	compare := func(stage string, head uint64) {
		t.Helper()
		for n := uint64(0); n <= head; n++ {
			want := blockchain.GetCanonicalHash(n)
			if got := dl.GetCanonicalHash(n); got != want {
				t.Fatalf("%s: canonical hash mismatch at height %d: tester %v, real %v", stage, n, got, want)
			}
			if want == (common.Hash{}) {
				continue
			}
			realHeader := blockchain.GetHeaderByNumber(n)
			gotHeader := dl.GetHeaderByNumber(n)
			if (realHeader == nil) != (gotHeader == nil) {
				t.Fatalf("%s: header presence mismatch at height %d: tester %v, real %v", stage, n, gotHeader, realHeader)
			}
			if realHeader != nil && gotHeader.Hash() != realHeader.Hash() {
				t.Fatalf("%s: canonical header mismatch at height %d: tester %v, real %v", stage, n, gotHeader.Hash(), realHeader.Hash())
			}
		}
	}

	steps := []struct {
		stage  string
		blocks types.Blocks
		head   uint64
	}{
		{"main chain", main, 8},
		{"fork side entries", fork[:4], 8},
		{"fork takeover", fork[4:5], 9},
		{"fork tail", fork[5:], 12},
	}
	for _, step := range steps {
		if i, err := dl.InsertChain(step.blocks); err != nil {
			t.Fatalf("%s: tester insert failed at %d: %v", step.stage, i, err)
		}
		if i, err := blockchain.InsertChain(step.blocks); err != nil {
			t.Fatalf("%s: real chain insert failed at %d: %v", step.stage, i, err)
		}
		compare(step.stage, step.head)
	}
	// The head getters must agree with the real chain's head as well.
	headNum, headHash := dl.canonicalHead(true)
	want := blockchain.CurrentBlock()
	if headNum != want.Number.Uint64() || headHash != want.Hash() {
		t.Fatalf("head mismatch: tester %d/%v, real %d/%v", headNum, headHash, want.Number.Uint64(), want.Hash())
	}
}

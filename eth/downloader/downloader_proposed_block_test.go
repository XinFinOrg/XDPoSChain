// Copyright 2015 The go-ethereum Authors
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
	"bytes"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/event"
	"github.com/XinFinOrg/XDPoSChain/log"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// makeTestBlockWithDifficulty builds an empty block on top of parent with a
// custom difficulty, so a shorter branch can out-cumulative-difficulty a
// longer one the way production reorgs are decided. The seed goes into the
// extra data, so chains from the same parent with different seeds are
// distinct forks.
func makeTestBlockWithDifficulty(parent *types.Block, difficulty int64, seed byte) *types.Block {
	header := &types.Header{
		ParentHash: parent.Hash(),
		Number:     new(big.Int).Add(parent.Number(), common.Big1),
		Difficulty: big.NewInt(difficulty),
		GasLimit:   params.GenesisGasLimit,
		Time:       parent.Header().Time + 10,
		Extra:      []byte{seed},
	}
	return types.NewBlockWithHeader(header).WithBody(types.Body{})
}

// makeTestBlock builds an empty block on top of parent with the default
// difficulty of one.
func makeTestBlock(parent *types.Block, seed byte) *types.Block {
	return makeTestBlockWithDifficulty(parent, common.Big1.Int64(), seed)
}

// extendTestChain builds n blocks on top of parent, seeding their extra data
// with seed, seed+1 and so on. parent is not included.
func extendTestChain(parent *types.Block, n int, seed byte) []*types.Block {
	chain := make([]*types.Block, 0, n)
	for i := 0; i < n; i++ {
		block := makeTestBlock(parent, seed+byte(i))
		chain = append(chain, block)
		parent = block
	}
	return chain
}

// assertProposedBlock checks the handleProposedBlock call count and, when
// wantTail is non-nil, the block the most recent call saw.
func assertProposedBlock(t *testing.T, dl *downloadTester, wantCalls int, wantTail *types.Block) {
	t.Helper()
	calls, got := dl.proposedState()
	if calls != wantCalls {
		t.Fatalf("handleProposedBlock ran %d times, want %d", calls, wantCalls)
	}
	if wantTail == nil {
		return
	}
	if got == nil || got.Hash() != wantTail.Hash() {
		t.Fatalf("handleProposedBlock ran on %v, want %v", got, wantTail.Hash())
	}
}

// TestImportBlockResultsProposedBlockHandler checks the downloader pre-filter:
// the handler runs only when the imported batch tail is both stored and
// canonical. The cases cover a parked tail, a stored side-chain tail, and a
// fast-sync height whose canonical header arrived before its body.
// The shared decision semantics are tested against a real BlockChain in
// consensus/tests/engine_v2_tests. The tester-contract tests below pin the
// storage and canonicality behavior this test relies on.
func TestImportBlockResultsProposedBlockHandler(t *testing.T) {
	t.Run("batch tail parked in the future queue", func(t *testing.T) {
		// A parked tail is neither stored nor canonical, so the handler must
		// not run.
		dl := newTester()
		defer dl.terminate()

		local := extendTestChain(dl.genesis, 4, 0)
		if _, err := dl.InsertChain(local); err != nil {
			t.Fatalf("failed to set up the local chain: %v", err)
		}
		// The batch continues the local head, like a queued batch does.
		batch := extendTestChain(local[len(local)-1], 4, 16)
		tail := batch[len(batch)-1]
		dl.parkTailOnce = true
		before, _ := dl.proposedState()
		if err := dl.downloader.importBlockResults(toFetchResults(batch)); err != nil {
			t.Fatalf("failed to import the queued batch: %v", err)
		}
		assertProposedBlock(t, dl, before, nil)
		if dl.GetBlock(tail.Hash(), tail.NumberU64()) != nil {
			t.Fatalf("queued batch tail unexpectedly stored")
		}
		if got := dl.GetCanonicalHash(tail.NumberU64()); got != (common.Hash{}) {
			t.Fatalf("parked tail height unexpectedly canonical: %v", got)
		}
	})

	t.Run("imported batch", func(t *testing.T) {
		// A fully written batch triggers the handler exactly once.
		dl := newTester()
		defer dl.terminate()

		batch := extendTestChain(dl.genesis, 4, 32)
		before, _ := dl.proposedState()
		if err := dl.downloader.importBlockResults(toFetchResults(batch)); err != nil {
			t.Fatalf("failed to import the batch: %v", err)
		}
		assertProposedBlock(t, dl, before+1, batch[len(batch)-1])
		if dl.GetBlock(batch[len(batch)-1].Hash(), batch[len(batch)-1].NumberU64()) == nil {
			t.Fatalf("imported batch tail not stored")
		}
	})

	t.Run("stored side-chain batch re-delivered", func(t *testing.T) {
		// A stored fork batch that is no longer the head must not reach the
		// handler: storage is not canonicality.
		dl := newTester()
		defer dl.terminate()

		fork := extendTestChain(dl.genesis, 4, 48)
		// Freshly stored, the fork is ahead of the local chain, so it
		// becomes the head and the handler firing once is expected.
		if err := dl.downloader.importBlockResults(toFetchResults(fork)); err != nil {
			t.Fatalf("failed to store the fork batch: %v", err)
		}
		// Growing the local chain past the fork turns its blocks into side
		// entries.
		local := extendTestChain(dl.genesis, 5, 64)
		if _, err := dl.InsertChain(local); err != nil {
			t.Fatalf("failed to set up the local chain: %v", err)
		}
		tail := fork[len(fork)-1]
		if dl.GetBlock(tail.Hash(), tail.NumberU64()) == nil {
			t.Fatalf("fork batch tail not stored")
		}
		// Re-delivering the stored fork must not reach the handler again.
		// Capture logs to pin the pre-filter's call-site grading: the skip
		// must surface at Info (PreFilterSkipLogLevel), not the Warn the same
		// reason gets at the handler.
		var logBuf bytes.Buffer
		glog := log.NewGlogHandler(log.NewTerminalHandlerWithLevel(&logBuf, log.LevelInfo, false))
		glog.Verbosity(log.LevelInfo)
		prevLog := log.Root()
		log.SetDefault(log.NewLogger(glog))
		defer log.SetDefault(prevLog)
		prefilterSkipsBefore := skippedProposedBlockPreFilter.Snapshot().Count()
		before, _ := dl.proposedState()
		if err := dl.downloader.importBlockResults(toFetchResults(fork)); err != nil {
			t.Fatalf("failed to re-import the fork batch: %v", err)
		}
		assertProposedBlock(t, dl, before, nil)
		if got := skippedProposedBlockPreFilter.Snapshot().Count(); got != prefilterSkipsBefore+1 {
			t.Fatalf("pre-filter skip not counted, before = %d, after = %d", prefilterSkipsBefore, got)
		}
		found := false
		for _, line := range strings.Split(logBuf.String(), "\n") {
			if strings.Contains(line, "skipped proposed block handler") {
				if !strings.HasPrefix(line, "INFO") {
					t.Fatalf("pre-filter skip must log at Info, got line %q", line)
				}
				if !strings.Contains(line, "non-canonical") {
					t.Fatalf("pre-filter skip must carry the reason, got line %q", line)
				}
				// The hash attribute key must match the other skip sites
				// (engine skipProposedBlock, the eth fetcher gate); "block
				// hash=" would drop this emitter from hash= filtering.
				if strings.Contains(line, "block hash=") {
					t.Fatalf("pre-filter skip hash key regressed to 'block hash', got line %q", line)
				}
				if !strings.Contains(line, "hash=") {
					t.Fatalf("pre-filter skip must carry the hash attribute, got line %q", line)
				}
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("pre-filter skip line not found in logs: %q", logBuf.String())
		}
	})

	t.Run("head advanced past the canonical tail", func(t *testing.T) {
		// The tail stays canonical at its own height even once the head
		// moved past it, so the handler must still run.
		dl := newTester()
		defer dl.terminate()

		base := extendTestChain(dl.genesis, 4, 80)
		if _, err := dl.InsertChain(base); err != nil {
			t.Fatalf("failed to set up the local chain: %v", err)
		}
		batch := extendTestChain(base[len(base)-1], 4, 96)
		dl.extendTailAfterInsert = func(tail *types.Block) *types.Block {
			// A concurrent import of the tail's child landing before
			// importBlockResults reads the head.
			return makeTestBlock(tail, 200)
		}
		before, _ := dl.proposedState()
		if err := dl.downloader.importBlockResults(toFetchResults(batch)); err != nil {
			t.Fatalf("failed to import the batch: %v", err)
		}
		assertProposedBlock(t, dl, before+1, batch[len(batch)-1])
	})

	t.Run("heavier fork stays canonical", func(t *testing.T) {
		// The head goes to the highest total difficulty, not to the last
		// insert, so a lighter chain stored later must not displace the
		// heavier fork.
		dl := newTester()
		defer dl.terminate()

		fork := extendTestChain(dl.genesis, 6, 112)
		if err := dl.downloader.importBlockResults(toFetchResults(fork)); err != nil {
			t.Fatalf("failed to store the fork batch: %v", err)
		}
		local := extendTestChain(dl.genesis, 2, 128)
		if _, err := dl.InsertChain(local); err != nil {
			t.Fatalf("failed to set up the local chain: %v", err)
		}
		// The fork is still canonical, so re-delivering it reaches the
		// handler again.
		before, _ := dl.proposedState()
		if err := dl.downloader.importBlockResults(toFetchResults(fork)); err != nil {
			t.Fatalf("failed to re-import the fork batch: %v", err)
		}
		assertProposedBlock(t, dl, before+1, fork[len(fork)-1])
	})

	t.Run("fast-sync canonical tail without body", func(t *testing.T) {
		// The header phase makes the tail's height canonical before its body
		// is imported, so HasBlock has to gate the handler too.
		dl := newTester()
		defer dl.terminate()

		batch := extendTestChain(dl.genesis, 4, 144)
		headers := make([]*types.Header, len(batch))
		for i, block := range batch {
			headers[i] = block.Header()
		}
		if _, err := dl.InsertHeaderChain(headers, 0); err != nil {
			t.Fatalf("failed to set up the header phase: %v", err)
		}
		// The tail height is canonical already, but its body is missing.
		tail := batch[len(batch)-1]
		if got := dl.GetCanonicalHash(tail.NumberU64()); got != tail.Hash() {
			t.Fatalf("tail height not canonical after the header phase: have %v, want %v", got, tail.Hash())
		}
		if dl.HasBlock(tail.Hash(), tail.NumberU64()) {
			t.Fatalf("tail block unexpectedly stored before the body phase")
		}
		dl.parkTailOnce = true
		before, _ := dl.proposedState()
		if err := dl.downloader.importBlockResults(toFetchResults(batch)); err != nil {
			t.Fatalf("failed to import the queued batch: %v", err)
		}
		assertProposedBlock(t, dl, before, nil)
		if dl.HasBlock(tail.Hash(), tail.NumberU64()) {
			t.Fatalf("queued batch tail unexpectedly stored")
		}
	})
}

// Tester-contract test: this verifies downloadTester's modeled behavior, not
// production code. See TestImportBlockResultsProposedBlockHandler for how
// these tester guarantees support the higher-level import cases.
// TestInsertChainErrorReportsPosition checks that a failing storeBlock is
// reported with the block's index in the batch and the batch length, so a
// broken batch can be located without re-deriving the position.
func TestInsertChainErrorReportsPosition(t *testing.T) {
	dl := newTester()
	defer dl.terminate()

	base := extendTestChain(dl.genesis, 2, 208)
	// A child hanging off a parent that is not in the chain.
	orphanChild := makeTestBlock(makeTestBlock(dl.genesis, 250), 251)

	t.Run("main loop", func(t *testing.T) {
		batch := []*types.Block{base[0], orphanChild}
		i, err := dl.InsertChain(batch)
		if err == nil {
			t.Fatalf("expected an error for the unknown parent")
		}
		want := fmt.Sprintf("InsertChain: unknown parent %s at position 1 / 2", orphanChild.ParentHash())
		if err.Error() != want {
			t.Fatalf("error mismatch: have %q, want %q", err.Error(), want)
		}
		if i != 1 {
			t.Fatalf("returned index mismatch: have %d, want 1", i)
		}
	})

	t.Run("parked tail prefix", func(t *testing.T) {
		dl.parkTailOnce = true
		batch := []*types.Block{orphanChild, base[1]}
		i, err := dl.InsertChain(batch)
		if err == nil {
			t.Fatalf("expected an error for the unknown parent")
		}
		want := fmt.Sprintf("InsertChain: unknown parent %s at position 0 / 2", orphanChild.ParentHash())
		if err.Error() != want {
			t.Fatalf("error mismatch: have %q, want %q", err.Error(), want)
		}
		if i != 0 {
			t.Fatalf("returned index mismatch: have %d, want 0", i)
		}
	})

	t.Run("extended tail child", func(t *testing.T) {
		// The hook's child fails on its unknown parent, reported at the
		// position right after the batch.
		dl.extendTailAfterInsert = func(tail *types.Block) *types.Block {
			return orphanChild
		}
		batch := []*types.Block{base[0], base[1]}
		i, err := dl.InsertChain(batch)
		if err == nil {
			t.Fatalf("expected an error for the unknown parent")
		}
		want := fmt.Sprintf("InsertChain: unknown parent %s at position 2 / 3", orphanChild.ParentHash())
		if err.Error() != want {
			t.Fatalf("error mismatch: have %q, want %q", err.Error(), want)
		}
		if i != 2 {
			t.Fatalf("returned index mismatch: have %d, want 2", i)
		}
	})
}

// Tester-contract test: this verifies downloadTester's modeled behavior, not
// production code. The rollback behavior checked here supports the canonical
// storage assumptions used by TestImportBlockResultsProposedBlockHandler.
// TestRollbackClearsCanonicalMarkers checks that Rollback drops the
// canonical entries of the removed blocks, so GetCanonicalHash stops
// reporting them, while the surviving ancestors stay canonical.
func TestRollbackClearsCanonicalMarkers(t *testing.T) {
	dl := newTester()
	defer dl.terminate()

	chain := extendTestChain(dl.genesis, 4, 208)
	if _, err := dl.InsertChain(chain); err != nil {
		t.Fatalf("failed to set up the chain: %v", err)
	}
	for _, block := range chain {
		if got := dl.GetCanonicalHash(block.NumberU64()); got != block.Hash() {
			t.Fatalf("height %d not canonical before the rollback: have %v, want %v", block.NumberU64(), got, block.Hash())
		}
	}

	rolledBack := chain[2:]
	hashes := make([]common.Hash, len(rolledBack))
	for i, block := range rolledBack {
		hashes[i] = block.Hash()
	}
	dl.Rollback(hashes)

	// The rolled-back heights no longer report a canonical hash.
	for _, block := range rolledBack {
		if got := dl.GetCanonicalHash(block.NumberU64()); got != (common.Hash{}) {
			t.Fatalf("height %d still canonical after the rollback: %v", block.NumberU64(), got)
		}
	}
	// The surviving ancestors keep their canonical entries.
	for _, block := range chain[:2] {
		if got := dl.GetCanonicalHash(block.NumberU64()); got != block.Hash() {
			t.Fatalf("ancestor height %d lost its canonical entry: have %v, want %v", block.NumberU64(), got, block.Hash())
		}
	}
	if got := dl.GetCanonicalHash(0); got != dl.genesis.Hash() {
		t.Fatalf("genesis height lost its canonical entry: have %v, want %v", got, dl.genesis.Hash())
	}
}

// toFetchResults converts a chain of blocks into the fetch-result shape
// importBlockResults consumes: headers plus empty transaction bodies.
func toFetchResults(blocks []*types.Block) []*fetchResult {
	results := make([]*fetchResult, 0, len(blocks))
	for _, block := range blocks {
		results = append(results, &fetchResult{Header: block.Header(), Transactions: types.Transactions{}})
	}
	return results
}

// Tester-contract test: this verifies downloadTester's modeled behavior, not
// production code. It checks that a reorg also removes stale canonical
// markers above the new head, as required by the import pre-filter tests.
// TestStoreBlockCleansStaleCanonicalMarkers checks that taking over the
// canonical table with a shorter but heavier branch drops the stale
// canonical markers above the new head, mirroring the reorg cleanup of
// real insertChain: without the cleanup, GetCanonicalHash keeps answering
// with the replaced branch at the heights above the new head.
func TestStoreBlockCleansStaleCanonicalMarkers(t *testing.T) {
	dl := newTester()
	defer dl.terminate()

	base := extendTestChain(dl.genesis, 2, 208)
	if _, err := dl.InsertChain(base); err != nil {
		t.Fatalf("failed to set up the base chain: %v", err)
	}
	baseHead := base[len(base)-1]

	// A longer branch of difficulty-1 blocks: heights baseHead+1..+3.
	longBranch := extendTestChain(baseHead, 3, 226)
	if _, err := dl.InsertChain(longBranch); err != nil {
		t.Fatalf("failed to import the long branch: %v", err)
	}

	// A shorter branch of difficulty-2 blocks: heights baseHead+1..+2
	// only, but its head carries the higher total difficulty.
	var shortBranch []*types.Block
	parent := baseHead
	for i := 0; i < 2; i++ {
		parent = makeTestBlockWithDifficulty(parent, 2, 240+byte(i))
		shortBranch = append(shortBranch, parent)
	}
	if _, err := dl.InsertChain(shortBranch); err != nil {
		t.Fatalf("failed to import the short heavier branch: %v", err)
	}

	// The short branch took the canonical table over up to its head.
	head := shortBranch[len(shortBranch)-1]
	if got := dl.GetCanonicalHash(head.NumberU64()); got != head.Hash() {
		t.Fatalf("heavier fork head not canonical: have %v, want %v", got, head.Hash())
	}
	if got := dl.GetCanonicalHash(shortBranch[0].NumberU64()); got != shortBranch[0].Hash() {
		t.Fatalf("replaced height %d lost its new canonical entry: have %v, want %v", shortBranch[0].NumberU64(), got, shortBranch[0].Hash())
	}
	// The heights above the new head must not answer with the replaced
	// branch; production reorg deletes those markers.
	above := longBranch[len(longBranch)-1]
	if got := dl.GetCanonicalHash(above.NumberU64()); got != (common.Hash{}) {
		t.Fatalf("stale canonical marker above the new head survived: have %v", got)
	}
}

// Tester-contract test: this verifies downloadTester's modeled behavior, not
// production code. It covers the canonical-choice tie-break used by the
// import pre-filter: a higher block number wins an equal-difficulty tie,
// while a same-height branch remains non-canonical.
// TestStoreBlockEqualDifficultyTieBreaksByNumber checks that the fork
// choice mirror of insertChain splits an equal-total-difficulty tie by
// number: a higher-height block takes over the canonical table while a
// same-height one stays a side entry, matching the selfish-mining guard
// of writeBlockWithState.
func TestStoreBlockEqualDifficultyTieBreaksByNumber(t *testing.T) {
	dl := newTester()
	defer dl.terminate()

	base := extendTestChain(dl.genesis, 2, 250)
	if _, err := dl.InsertChain(base); err != nil {
		t.Fatalf("failed to set up the base chain: %v", err)
	}
	baseHead := base[len(base)-1]

	// A difficulty-2 block at height baseHead+1 takes the head with a
	// strictly higher total difficulty.
	heavy := makeTestBlockWithDifficulty(baseHead, 2, 251)
	if _, err := dl.InsertChain([]*types.Block{heavy}); err != nil {
		t.Fatalf("failed to import the heavy fork: %v", err)
	}
	if got := dl.GetCanonicalHash(heavy.NumberU64()); got != heavy.Hash() {
		t.Fatalf("heavier fork head not canonical: have %v, want %v", got, heavy.Hash())
	}

	// A same-height block with the same total difficulty must not
	// displace the head.
	twin := makeTestBlockWithDifficulty(baseHead, 2, 252)
	if _, err := dl.InsertChain([]*types.Block{twin}); err != nil {
		t.Fatalf("failed to import the twin fork: %v", err)
	}
	if got := dl.GetCanonicalHash(twin.NumberU64()); got != heavy.Hash() {
		t.Fatalf("same-height equal-difficulty fork displaced the head: have %v, want %v", got, heavy.Hash())
	}

	// A branch of difficulty-1 blocks ties the head's total difficulty
	// exactly one height above it; production promotes that block, so
	// the mirror must too.
	tie := extendTestChain(baseHead, 2, 253)
	if _, err := dl.InsertChain(tie); err != nil {
		t.Fatalf("failed to import the tying branch: %v", err)
	}
	if got := dl.GetCanonicalHash(tie[1].NumberU64()); got != tie[1].Hash() {
		t.Fatalf("equal-difficulty higher-height fork not promoted: have %v, want %v", got, tie[1].Hash())
	}
	if got := dl.GetCanonicalHash(tie[0].NumberU64()); got != tie[0].Hash() {
		t.Fatalf("tying branch lost its canonical segment: have %v, want %v", got, tie[0].Hash())
	}
	if got := dl.GetCanonicalHash(baseHead.NumberU64()); got != baseHead.Hash() {
		t.Fatalf("reorg rewired the shared prefix: have %v, want %v", got, baseHead.Hash())
	}
}

// Tester-contract test: this verifies downloadTester's modeled behavior, not
// production code. It ensures the chain's head getters follow the canonical
// table after side-chain insertion and after a shorter, heavier branch takes
// over.
// TestHeadGettersFollowCanonicalTable checks that the head getters report
// the canonical head rather than the last stored block, the way production
// reads its own chain state: a lighter side chain stored after a heavier
// fork must not displace what CurrentHeader, CurrentBlock and
// CurrentSnapBlock report, and a shorter heavier branch taking over must
// move the getters onto its own head, off the replaced branch's tail.
func TestHeadGettersFollowCanonicalTable(t *testing.T) {
	dl := newTester()
	defer dl.terminate()

	fork := extendTestChain(dl.genesis, 6, 112)
	if err := dl.downloader.importBlockResults(toFetchResults(fork)); err != nil {
		t.Fatalf("failed to store the fork batch: %v", err)
	}
	local := extendTestChain(dl.genesis, 2, 128)
	if _, err := dl.InsertChain(local); err != nil {
		t.Fatalf("failed to set up the local chain: %v", err)
	}
	want := fork[len(fork)-1].NumberU64()
	if have := dl.CurrentHeader().Number.Uint64(); have != want {
		t.Fatalf("CurrentHeader reported the side chain: have %v, want %v", have, want)
	}
	if have := dl.CurrentBlock().Number.Uint64(); have != want {
		t.Fatalf("CurrentBlock reported the side chain: have %v, want %v", have, want)
	}
	if have := dl.CurrentSnapBlock().Number.Uint64(); have != want {
		t.Fatalf("CurrentSnapBlock reported the side chain: have %v, want %v", have, want)
	}

	// A shorter heavier branch taking over the canonical table must move the
	// head getters onto its own head and off the replaced branch's stale tail.
	dl2 := newTester()
	defer dl2.terminate()

	base := extendTestChain(dl2.genesis, 2, 208)
	if _, err := dl2.InsertChain(base); err != nil {
		t.Fatalf("failed to set up the base chain: %v", err)
	}
	baseHead := base[len(base)-1]
	longBranch := extendTestChain(baseHead, 3, 226)
	if _, err := dl2.InsertChain(longBranch); err != nil {
		t.Fatalf("failed to import the long branch: %v", err)
	}
	var shortBranch []*types.Block
	parent := baseHead
	for i := 0; i < 2; i++ {
		parent = makeTestBlockWithDifficulty(parent, 2, 240+byte(i))
		shortBranch = append(shortBranch, parent)
	}
	if _, err := dl2.InsertChain(shortBranch); err != nil {
		t.Fatalf("failed to import the short heavier branch: %v", err)
	}
	want = shortBranch[len(shortBranch)-1].NumberU64()
	if have := dl2.CurrentHeader().Number.Uint64(); have != want {
		t.Fatalf("CurrentHeader kept the replaced branch: have %v, want %v", have, want)
	}
	if have := dl2.CurrentBlock().Number.Uint64(); have != want {
		t.Fatalf("CurrentBlock kept the replaced branch: have %v, want %v", have, want)
	}
	if have := dl2.CurrentSnapBlock().Number.Uint64(); have != want {
		t.Fatalf("CurrentSnapBlock kept the replaced branch: have %v, want %v", have, want)
	}
}

// TestImportBlockResultsNilProposedBlockHandler pins the non-XDPoS shape of
// the import pre-filter: a downloader wired without a proposed-block handler
// (what NewProtocolManager passes for a non-XDPoS engine) skips the whole
// pre-filter block — no judgment, no counter movement, no log — and imports
// normally. Normalizing the nil callback to a no-op instead would make the
// pre-filter run and count skips for a handler that does nothing.
func TestImportBlockResultsNilProposedBlockHandler(t *testing.T) {
	dl := newTester()
	defer dl.terminate()

	local := extendTestChain(dl.genesis, 4, 0)
	if _, err := dl.InsertChain(local); err != nil {
		t.Fatalf("failed to set up the local chain: %v", err)
	}
	batch := extendTestChain(local[len(local)-1], 4, 16)
	tail := batch[len(batch)-1]

	// Rebuild the tester's downloader with a nil handler, mirroring the
	// non-XDPoS wiring in eth.NewProtocolManager. The original downloader is
	// terminated first so its goroutines do not leak.
	dl.downloader.Terminate()
	dl.downloader = New(dl.stateDb, new(event.TypeMux), dl, nil, dl.dropPeer, nil)

	before := skippedProposedBlockPreFilter.Snapshot().Count()
	if err := dl.downloader.importBlockResults(toFetchResults(batch)); err != nil {
		t.Fatalf("nil-handler import failed: %v", err)
	}
	if got := skippedProposedBlockPreFilter.Snapshot().Count(); got != before {
		t.Fatalf("pre-filter moved with a nil handler, before = %d, after = %d", before, got)
	}
	if dl.GetBlock(tail.Hash(), tail.NumberU64()) == nil {
		t.Fatalf("nil-handler import did not store the batch tail")
	}
}

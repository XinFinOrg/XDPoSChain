package core

import (
	"bytes"
	"math/big"
	"strings"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/log"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// newRollbackTestChain builds a chain of n empty blocks on a pristine database
// and returns it with the blocks that were imported.
func newRollbackTestChain(t *testing.T, n int) (*BlockChain, types.Blocks) {
	t.Helper()

	genesis := &Genesis{
		BaseFee: big.NewInt(params.InitialBaseFee),
		Config:  params.AllEthashProtocolChanges,
	}
	chain, err := NewBlockChain(rawdb.NewMemoryDatabase(), &CacheConfig{TrieDirtyDisabled: true}, genesis, ethash.NewFaker(), vm.Config{})
	if err != nil {
		t.Fatalf("failed to create chain: %v", err)
	}
	t.Cleanup(chain.Stop)
	if n == 0 {
		return chain, nil
	}
	// The blocks are empty, so the generation database only needs to answer for
	// the genesis the chain itself already committed.
	genDb := rawdb.NewMemoryDatabase()
	blocks := makeBlockChain(chain.chainConfig, chain.Genesis(), n, ethash.NewFaker(), genDb, 10)
	if _, err := chain.InsertChain(blocks); err != nil {
		t.Fatalf("failed to insert chain: %v", err)
	}
	return chain, blocks
}

// assertRollbackMarkers fails unless the three in-memory and the three persisted
// markers all name want.
func assertRollbackMarkers(t *testing.T, chain *BlockChain, want *types.Block) {
	t.Helper()

	if have := chain.CurrentHeader(); have.Hash() != want.Hash() {
		t.Errorf("header marker: have #%d %s, want #%d %s", have.Number, have.Hash(), want.Number(), want.Hash())
	}
	if have := chain.CurrentSnapBlock(); have.Hash() != want.Hash() {
		t.Errorf("snap marker: have #%d %s, want #%d %s", have.Number, have.Hash(), want.Number(), want.Hash())
	}
	if have := chain.CurrentBlock(); have.Hash() != want.Hash() {
		t.Errorf("block marker: have #%d %s, want #%d %s", have.Number, have.Hash(), want.Number(), want.Hash())
	}
	if have := rawdb.ReadHeadHeaderHash(chain.db); have != want.Hash() {
		t.Errorf("persisted header marker: have %s, want %s", have, want.Hash())
	}
	if have := rawdb.ReadHeadFastBlockHash(chain.db); have != want.Hash() {
		t.Errorf("persisted snap marker: have %s, want %s", have, want.Hash())
	}
	if have := rawdb.ReadHeadBlockHash(chain.db); have != want.Hash() {
		t.Errorf("persisted block marker: have %s, want %s", have, want.Hash())
	}
}

// TestRollbackMissingParentHeaderLeavesMarkers pins that a missing parent header
// aborts the rollback instead of dereferencing a nil header in SetCurrentHeader.
func TestRollbackMissingParentHeaderLeavesMarkers(t *testing.T) {
	chain, blocks := newRollbackTestChain(t, 3)
	head, parent := blocks[2], blocks[1]

	rawdb.DeleteHeader(chain.db, parent.Hash(), parent.NumberU64())
	chain.hc.headerCache.Purge()

	chain.Rollback([]common.Hash{head.Hash()})

	assertRollbackMarkers(t, chain, head)
}

// TestRollbackMissingParentBodyLeavesMarkers pins that a missing parent body
// aborts the rollback before any marker is published: the header branch resolves
// first, so the old order left the in-memory header on the parent while the disk
// still named the head.
func TestRollbackMissingParentBodyLeavesMarkers(t *testing.T) {
	chain, blocks := newRollbackTestChain(t, 3)
	head, parent := blocks[2], blocks[1]

	rawdb.DeleteBody(chain.db, parent.Hash(), parent.NumberU64())
	chain.bodyCache.Purge()
	chain.bodyRLPCache.Purge()
	chain.blockCache.Purge()

	chain.Rollback([]common.Hash{head.Hash()})

	assertRollbackMarkers(t, chain, head)
}

// TestRollbackGenesisDoesNotUnderflow pins the early return for a marker on the
// genesis block: the parent number would wrap to MaxUint64 unless the marker is
// refused before the lookup.
func TestRollbackGenesisDoesNotUnderflow(t *testing.T) {
	chain, _ := newRollbackTestChain(t, 0)
	genesis := chain.Genesis()

	var logBuf bytes.Buffer
	prevLog := log.Root()
	glog := log.NewGlogHandler(log.NewTerminalHandlerWithLevel(&logBuf, log.LevelTrace, false))
	glog.Verbosity(log.LevelTrace)
	log.SetDefault(log.NewLogger(glog))
	defer log.SetDefault(prevLog)

	chain.Rollback([]common.Hash{genesis.Hash()})

	if have := logBuf.String(); !strings.Contains(have, "genesis has no parent") {
		t.Fatalf("rollback did not refuse the genesis marker: %s", have)
	}
	assertRollbackMarkers(t, chain, genesis)
}

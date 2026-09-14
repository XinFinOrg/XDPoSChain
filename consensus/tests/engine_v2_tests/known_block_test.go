package engine_v2_tests

import (
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/stretchr/testify/assert"
)

// TestInsertChainKnownGapBlockRefreshesSnapshot rolls the head back below the
// gap block, drops its snapshot and re-imports the already executed blocks:
// the known-block path must move the head forward and rewrite the snapshot.
func TestInsertChainKnownGapBlockRefreshesSnapshot(t *testing.T) {
	skipLongInShortMode(t)
	config := params.TestXDPoSMockChainConfig
	gapNumber := config.XDPoS.V2.SwitchBlock.Uint64() + config.XDPoS.Epoch - config.XDPoS.Gap // 1350
	// The helper deliberately mis-signs every block whose round%5 == 3 (see
	// findSignerAndSignFn), so only rounds 450..452 survive a full VerifyHeaders.
	tipNumber := int(gapNumber) + 2

	blockchain, _, tip, _, _, _ := PrepareXDCTestBlockChainForV2Engine(t, tipNumber, config, nil)
	db := blockchain.ChainDb()

	var (
		blocks []*types.Block
		hashes []common.Hash
	)
	for n := gapNumber; n <= uint64(tipNumber); n++ {
		block := blockchain.GetBlockByNumber(n)
		if block == nil {
			t.Fatalf("block %d missing", n)
		}
		blocks = append(blocks, block)
		hashes = append(hashes, block.Hash())
	}
	gapHash := hashes[0]

	// Rollback only rewinds the head markers, bodies and state stay on disk.
	blockchain.Rollback(hashes)
	assert.Equal(t, gapNumber-1, blockchain.CurrentBlock().Number.Uint64())

	rawdb.DeleteXdposSnapshot(db, gapHash)
	has, err := rawdb.HasXdposV2Snapshot(db, gapHash)
	assert.Nil(t, err)
	assert.False(t, has, "gap block snapshot should be gone before re-import")

	n, err := blockchain.InsertChain(blocks)
	assert.Nil(t, err, "re-importing known blocks must not fail")
	assert.Equal(t, len(blocks), n)

	head := blockchain.CurrentBlock()
	assert.Equal(t, tip.NumberU64(), head.Number.Uint64())
	assert.Equal(t, tip.Hash(), head.Hash())

	has, err = rawdb.HasXdposV2Snapshot(db, gapHash)
	assert.Nil(t, err)
	assert.True(t, has, "known gap block reaching the head must refresh the snapshot")
}

package engine_v2_tests

import (
	"testing"
	"time"

	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/stretchr/testify/assert"
)

// TestInsertChainQueuesFutureBatchEndToEnd combines the two halves the
// future-batch fix relies on: the real XDPoS engine classifying children of a
// future block as ErrFutureBlock (timestamp check precedes the parent lookup),
// and insertChain consuming those results by queueing the whole tail instead
// of failing the import. The core stub-based tests pin the loop mechanics and
// the engine tests pin the classification; neither covers their composition,
// which is the exact online scenario the fix targets.
//
// Deliberately not skipped in -short mode: the whole run (910-block harness
// build included) stays well under a second, and this is the only test that
// covers the composition.
func TestInsertChainQueuesFutureBatchEndToEnd(t *testing.T) {
	config := params.TestXDPoSMockChainConfig
	blockchain, _, tip910, signer, signFn, _ := PrepareXDCTestBlockChainForV2Engine(t, 910, config, nil)
	t.Cleanup(blockchain.Stop)
	db := blockchain.ChainDb()

	// Build blocks 911..915 in memory only; none is written into the DB.
	switchBlock := config.XDPoS.V2.SwitchBlock.Int64()
	blocks := make([]*types.Block, 0, 5)
	current := tip910
	for n := 911; n <= 915; n++ {
		block := CreateBlock(
			blockchain,
			blockchain.Config(),
			current,
			n,
			int64(n)-switchBlock,
			signer.Hex(),
			signer,
			signFn,
			nil,
			nil,
			"",
		)
		blocks = append(blocks, block)
		current = block
	}

	// Re-timestamp the tail (912..915) into the near future. The hash changes
	// so the QC no longer matches, which is fine: the timestamp check also
	// precedes QC verification. Each re-stamped header also breaks the link to
	// its built child, so the parents are re-chained along the clone line. Park
	// the tail 15s inside addFutureBlock's 30s acceptance window: addFutureBlock
	// re-reads time.Now() at enqueue time, so the 15s of slack also absorbs a
	// wall-clock step back between stamping here and the enqueue check (a 25s
	// offset would leave only 5s and fail on a ~6s NTP step back), and it stays
	// far beyond the 100ms futureBlocksLoop period, so the queue cannot drain
	// before the assertions run.
	now := uint64(time.Now().Unix())
	var batch types.Blocks
	batch = append(batch, blocks[0]) // 911 keeps a past timestamp and imports
	parent := blocks[0]
	for _, block := range blocks[1:] {
		header := block.Header()
		header.ParentHash = parent.Hash()
		header.Time = now + 15
		parent = types.NewBlockWithHeader(header).WithBody(*block.Body())
		batch = append(batch, parent)
	}

	n, err := blockchain.InsertChain(batch)
	assert.Nil(t, err, "a future tail must not fail the import, the downloader would drop the peer")
	assert.Equal(t, len(batch), n)

	// The prefix imported, the tail did not reach the database.
	assert.Equal(t, blocks[0].NumberU64(), blockchain.CurrentBlock().Number.Uint64())
	assert.Equal(t, blocks[0].Hash(), blockchain.CurrentBlock().Hash())
	for _, block := range batch[1:] {
		assert.Nil(t, blockchain.GetBlockByNumber(block.NumberU64()), "future block %d must stay queued", block.NumberU64())
		assert.Nil(t, rawdb.ReadBadBlock(db, block.Hash()), "future block %d must not be reported as bad block", block.NumberU64())
	}
}

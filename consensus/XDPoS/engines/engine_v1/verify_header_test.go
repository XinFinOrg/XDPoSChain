package engine_v1

import (
	"math/big"
	"testing"
	"time"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS/utils"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/stretchr/testify/assert"
)

// futureTestChainReader mimics a chain that holds no verifiable ancestors: it
// hands out no headers, so any parent lookup has to fall back to the batch of
// headers passed to the engine.
type futureTestChainReader struct {
	consensus.ChainReader // nil; methods other than the overrides below are only reachable under a regressed engine ordering
	config                *params.ChainConfig
}

func (r *futureTestChainReader) Config() *params.ChainConfig {
	return r.config
}

func (r *futureTestChainReader) GetHeader(common.Hash, uint64) *types.Header {
	return nil
}

func (r *futureTestChainReader) GetHeaderByNumber(uint64) *types.Header {
	return nil
}

func (r *futureTestChainReader) GetHeaderByHash(common.Hash) *types.Header {
	return nil
}

func (r *futureTestChainReader) GetBlock(common.Hash, uint64) *types.Block {
	return nil
}

func (r *futureTestChainReader) GetBlockByNumber(uint64) *types.Block {
	return nil
}

func (r *futureTestChainReader) CurrentHeader() *types.Header {
	return nil
}

// futureTestHeader builds a header that passes all standalone v1 checks so that
// only the timestamp/parent ordering decides its fate.
func futureTestHeader(config *params.ChainConfig, number int64, parentHash common.Hash, timestamp uint64) *types.Header {
	header := &types.Header{
		Number:     big.NewInt(number),
		ParentHash: parentHash,
		Difficulty: big.NewInt(1),
		GasLimit:   1200000000,
		Time:       timestamp,
		Extra:      make([]byte, utils.ExtraVanity+utils.ExtraSeal),
		UncleHash:  utils.UncleHash,
	}
	if config.IsEIP1559(header.Number) {
		header.BaseFee = params.BaseFeeForBlock(config, header.Number)
	}
	return header
}

// TestFutureTimestampCheckPrecedesParentLookup pins the engine premise that the
// insertChain future-batch handling relies on: the timestamp check runs before
// the parent lookup, so a header whose parent is in the same batch and whose
// timestamp is in the future surfaces as ErrFutureBlock, never as
// ErrUnknownAncestor. If the checks are ever reordered, children of a future
// block stop being classified as future blocks and insertChain treats a valid
// delivery as an invalid chain, which makes the downloader drop the peer.
func TestFutureTimestampCheckPrecedesParentLookup(t *testing.T) {
	config := *params.TestXDPoSMockChainConfig
	xdpos := *config.XDPoS
	xdpos.SkipV1Validation = false // the timestamp check is part of full v1 validation
	config.XDPoS = &xdpos

	engine := New(&config, nil)
	reader := &futureTestChainReader{config: &config}

	now := uint64(time.Now().Unix())
	block1 := futureTestHeader(&config, 1, common.Hash{}, now)
	// Timestamp in the future and parent not resolvable from the reader: with
	// the checks in the wrong order this header would answer ErrUnknownAncestor.
	block2 := futureTestHeader(&config, 2, block1.Hash(), now+10000)

	// Single-header path: the parent (block1) is neither in a batch nor in the
	// database, so the parent lookup fails unless the timestamp check wins.
	err := engine.VerifyHeader(reader, block2, true)
	assert.Equal(t, consensus.ErrFutureBlock, err)

	// Batch path: the parent (block1) is in the same batch, so the parent
	// lookup can always succeed and must not mask the future classification.
	headers := []*types.Header{block1, block2}
	abort := make(chan struct{})
	results := make(chan error, len(headers))
	engine.VerifyHeaders(reader, headers, []bool{true, true}, abort, results)
	for i := 0; i < len(headers); i++ {
		select {
		case result := <-results:
			if i == 0 {
				// block1 has no verifiable ancestor on the stub reader and no
				// seal to recover; only the future classification of block2 is
				// under test.
				continue
			}
			assert.Equal(t, consensus.ErrFutureBlock, result)
		case <-time.After(5 * time.Second):
			t.Fatalf("timed out waiting for verify result %d", i)
		}
	}
}

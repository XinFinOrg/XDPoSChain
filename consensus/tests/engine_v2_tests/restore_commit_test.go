package engine_v2_tests

import (
	"testing"

	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS/engines/engine_v2"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/stretchr/testify/assert"
)

// restartEngine starts a fresh v2 engine over the chain and initialises it from the head, the
// way a restarted node does: nothing it committed before survives in memory.
func restartEngine(t *testing.T, blockchain *core.BlockChain) *engine_v2.XDPoS_v2 {
	t.Helper()
	engine, err := engine_v2.NewFaker(blockchain.Config(), blockchain.ChainDb(), make(chan int, 1), make(chan types.Round, 1))
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.Initial(blockchain, blockchain.CurrentBlock()); err != nil {
		t.Fatal(err)
	}
	return engine
}

// TestInitialRestoresCommittedBlockAfterTimeout covers a restart right after timeouts: the
// head's QC alone does not complete a 3-chain, so the committed block has to be recovered
// from the most recent 3-chain below the head.
func TestInitialRestoresCommittedBlockAfterTimeout(t *testing.T) {
	t.Parallel()
	// Blocks 901..906 carry rounds 1..6, so the QC of 906 commits 904.
	blockchain, _, currentBlock, signer, signFn, _ := PrepareXDCTestBlockChainForV2Engine(t, 906, params.TestXDPoSMockChainConfig, nil)

	// Timeouts above 906: rounds 8 and 10 leave no 3-chain among the top blocks.
	blockCoinBase := "0x111000000000000000000000000000000123"
	for i, round := range []int64{8, 10} {
		currentBlock = CreateBlock(blockchain, params.TestXDPoSMockChainConfig, currentBlock, 907+i, round, blockCoinBase, signer, signFn, nil, nil, "")
		if err := blockchain.InsertBlock(currentBlock); err != nil {
			t.Fatal(err)
		}
	}

	engine := restartEngine(t, blockchain)
	committed := engine.GetLatestCommittedBlockInfo()
	if assert.NotNil(t, committed) {
		assert.Equal(t, uint64(904), committed.Number.Uint64())
		assert.Equal(t, blockchain.GetHeaderByNumber(904).Hash(), committed.Hash)
		assert.Equal(t, types.Round(4), committed.Round)
	}
}

// TestInitialDoesNotCommitWithoutThreeChain covers a chain whose stored headers hold no 3-chain:
// nothing may be marked final early, so the committed block stays unknown.
func TestInitialDoesNotCommitWithoutThreeChain(t *testing.T) {
	t.Parallel()
	// Blocks 901 and 902 carry rounds 1 and 2; every block above skips a round.
	blockchain, _, currentBlock, signer, signFn, _ := PrepareXDCTestBlockChainForV2Engine(t, 902, params.TestXDPoSMockChainConfig, nil)

	blockCoinBase := "0x111000000000000000000000000000000123"
	for i, round := range []int64{4, 6, 8} {
		currentBlock = CreateBlock(blockchain, params.TestXDPoSMockChainConfig, currentBlock, 903+i, round, blockCoinBase, signer, signFn, nil, nil, "")
		if err := blockchain.InsertBlock(currentBlock); err != nil {
			t.Fatal(err)
		}
	}

	engine := restartEngine(t, blockchain)
	assert.Nil(t, engine.GetLatestCommittedBlockInfo())
}

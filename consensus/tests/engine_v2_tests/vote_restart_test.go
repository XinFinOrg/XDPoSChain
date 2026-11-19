package engine_v2_tests

import (
	"fmt"
	"testing"
	"time"

	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestVotedRoundSurvivesRestart checks that the highest round a node voted in
// is kept across a restart: an engine rebuilt on the same database must not
// vote again in that round, and must still vote in later rounds.
func TestVotedRoundSurvivesRestart(t *testing.T) {
	t.Parallel()
	config := params.TestXDPoSMockChainConfig
	blockchain, _, currentBlock, signer, signFn, _ := PrepareXDCTestBlockChainForV2Engine(t, 906, config, nil)
	engineV2 := blockchain.Engine().(*XDPoS.XDPoS).EngineV2

	// Vote for block 906 in round 6.
	engineV2.SetNewRoundFaker(blockchain, types.Round(5), false)
	require.NoError(t, engineV2.ProposedBlockHandler(blockchain, currentBlock.Header()))
	vote := expectVote(t, engineV2.BroadcastCh, 5*time.Second)
	require.Equal(t, types.Round(6), vote.ProposedBlockInfo.Round)

	// Restart: a fresh engine on the same database, same signer.
	restarted := XDPoS.NewFaker(blockchain.ChainDb(), config)
	restarted.Authorize(signer, signFn)
	restartedV2 := restarted.EngineV2
	_, _, _, _, highestVotedRound, _ := restartedV2.GetPropertiesFaker()
	assert.Equal(t, types.Round(6), highestVotedRound, "restarted engine must load the voted round")

	// The same proposal in the same round must not get a second vote.
	restartedV2.SetNewRoundFaker(blockchain, types.Round(5), false)
	require.NoError(t, restartedV2.ProposedBlockHandler(blockchain, currentBlock.Header()))
	expectNoVote(t, restartedV2.BroadcastCh, time.Second)

	// A proposal in the next round is voted for as usual.
	blockNum := 907
	block907 := CreateBlock(blockchain, config, currentBlock, blockNum, 7, fmt.Sprintf("0x111000000000000000000000000000000%03d", blockNum), signer, signFn, nil, nil, "")
	require.NoError(t, blockchain.InsertBlock(block907))
	require.NoError(t, restartedV2.ProposedBlockHandler(blockchain, block907.Header()))
	vote = expectVote(t, restartedV2.BroadcastCh, 5*time.Second)
	require.Equal(t, types.Round(7), vote.ProposedBlockInfo.Round)
	require.Equal(t, block907.Hash(), vote.ProposedBlockInfo.Hash)
}

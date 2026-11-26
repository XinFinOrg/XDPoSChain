package engine_v2_tests

import (
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/stretchr/testify/assert"
)

// TestProcessQCLeavesStateUntouchedWhenProposedBlockIsMissing pins that a QC
// for a block this node does not have fails before highestQuorumCert advances.
func TestProcessQCLeavesStateUntouchedWhenProposedBlockIsMissing(t *testing.T) {
	t.Parallel()
	blockchain, _, _, _, _, _ := PrepareXDCTestBlockChainForV2Engine(t, 906, params.TestXDPoSMockChainConfig, nil)
	engineV2 := blockchain.Engine().(*XDPoS.XDPoS).EngineV2

	beforeRound, beforeLockQC, beforeHighestQC, beforeTimeoutCert, beforeVotedRound, beforeCommit := engineV2.GetPropertiesFaker()
	// Snapshot the highest QC as values: comparing the shared pointer would see
	// an in-place rewrite of the same object on both sides and could never fail.
	beforeHighestQCHash := beforeHighestQC.ProposedBlockInfo.Hash
	beforeHighestQCRound := beforeHighestQC.ProposedBlockInfo.Round
	beforeHighestQCNumber := new(big.Int).Set(beforeHighestQC.ProposedBlockInfo.Number)
	qc := &types.QuorumCert{
		ProposedBlockInfo: &types.BlockInfo{
			Hash:   common.HexToHash("0xdeadbeef"),
			Number: new(big.Int).Add(beforeHighestQC.ProposedBlockInfo.Number, big.NewInt(1)),
			Round:  beforeHighestQC.ProposedBlockInfo.Round + 1,
		},
	}

	err := engineV2.ProcessQCFaker(blockchain, qc)
	assert.Error(t, err)

	round, lockQC, highestQC, timeoutCert, votedRound, commit := engineV2.GetPropertiesFaker()
	assert.Equal(t, beforeRound, round)
	assert.Equal(t, beforeLockQC, lockQC)
	assert.Equal(t, beforeHighestQCHash, highestQC.ProposedBlockInfo.Hash)
	assert.Equal(t, beforeHighestQCRound, highestQC.ProposedBlockInfo.Round)
	assert.Equal(t, beforeHighestQCNumber, highestQC.ProposedBlockInfo.Number)
	assert.Equal(t, beforeTimeoutCert, timeoutCert)
	assert.Equal(t, beforeVotedRound, votedRound)
	assert.Equal(t, beforeCommit, commit)
}

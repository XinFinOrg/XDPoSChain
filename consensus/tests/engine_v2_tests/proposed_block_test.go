package engine_v2_tests

import (
	"bytes"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/XinFinOrg/XDPoSChain/accounts/abi/bind/backends"
	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS/utils"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/log"
	"github.com/XinFinOrg/XDPoSChain/metrics"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/stretchr/testify/assert"
)

func TestShouldSendVoteMsgAndCommitGrandGrandParentBlock(t *testing.T) {
	// Block 901 is the first v2 block with round of 1
	blockchain, _, currentBlock, signer, signFn, _ := PrepareXDCTestBlockChainForV2Engine(t, 901, params.TestXDPoSMockChainConfig, nil)
	engineV2 := blockchain.Engine().(*XDPoS.XDPoS).EngineV2

	var extraField types.ExtraFields_v2
	err := utils.DecodeBytesExtraFields(currentBlock.Extra(), &extraField)
	if err != nil {
		t.Fatal("Fail to decode extra data", err)
	}

	err = engineV2.ProposedBlockHandler(blockchain, currentBlock.Header())
	if err != nil {
		t.Fatal("Fail propose proposedBlock handler", err)
	}

	voteMsg := <-engineV2.BroadcastCh
	poolSize := engineV2.GetVotePoolSizeFaker(voteMsg.(*types.Vote))

	assert.Equal(t, poolSize, 1)
	assert.NotNil(t, voteMsg)
	assert.Equal(t, currentBlock.Hash(), voteMsg.(*types.Vote).ProposedBlockInfo.Hash)

	round, _, highestQC, _, _, _ := engineV2.GetPropertiesFaker()
	// Shoud trigger setNewRound
	assert.Equal(t, types.Round(1), round)
	// Should not update the highestQC
	assert.Equal(t, types.Round(0), highestQC.ProposedBlockInfo.Round)

	// Insert another Block, but it won't trigger commit
	blockNum := 902
	blockCoinBase := fmt.Sprintf("0x111000000000000000000000000000000%03d", blockNum)
	block902 := CreateBlock(blockchain, params.TestXDPoSMockChainConfig, currentBlock, blockNum, 2, blockCoinBase, signer, signFn, nil, nil, "")
	err = blockchain.InsertBlock(block902)
	assert.Nil(t, err)
	err = engineV2.ProposedBlockHandler(blockchain, block902.Header())
	if err != nil {
		t.Fatal("Fail propose proposedBlock handler", err)
	}
	// Trigger send vote again but for a new round
	voteMsg = <-engineV2.BroadcastCh
	assert.NotNil(t, voteMsg)
	round, _, highestQC, _, _, _ = engineV2.GetPropertiesFaker()
	// Shoud trigger setNewRound
	assert.Equal(t, types.Round(2), round)
	assert.Equal(t, types.Round(1), highestQC.ProposedBlockInfo.Round)

	// Insert one more Block, but still won't trigger commit
	blockNum = 903
	blockCoinBase = fmt.Sprintf("0x111000000000000000000000000000000%03d", blockNum)
	block903 := CreateBlock(blockchain, params.TestXDPoSMockChainConfig, block902, blockNum, 3, blockCoinBase, signer, signFn, nil, nil, "")
	err = blockchain.InsertBlock(block903)
	assert.Nil(t, err)
	err = engineV2.ProposedBlockHandler(blockchain, block903.Header())
	if err != nil {
		t.Fatal("Fail propose proposedBlock handler", err)
	}
	// Trigger send vote again but for a new round
	voteMsg = <-engineV2.BroadcastCh
	assert.NotNil(t, voteMsg)
	round, _, highestQC, _, _, highestCommitBlock := engineV2.GetPropertiesFaker()
	// Shoud NOT trigger setNewRound as the new block parent QC is round 1 but the currentRound is already 2
	assert.Equal(t, types.Round(3), round)
	assert.Equal(t, types.Round(2), highestQC.ProposedBlockInfo.Round)
	assert.Nil(t, highestCommitBlock)

	// Insert one more Block, this time will trigger commit
	blockNum = 904
	blockCoinBase = fmt.Sprintf("0x111000000000000000000000000000000%03d", blockNum)
	block904 := CreateBlock(blockchain, params.TestXDPoSMockChainConfig, block903, blockNum, 4, blockCoinBase, signer, signFn, nil, nil, "")
	err = blockchain.InsertBlock(block904)
	assert.Nil(t, err)
	err = engineV2.ProposedBlockHandler(blockchain, block904.Header())
	if err != nil {
		t.Fatal("Fail propose proposedBlock handler", err)
	}
	// Trigger send vote again but for a new round
	voteMsg = <-engineV2.BroadcastCh
	assert.NotNil(t, voteMsg)
	round, _, highestQC, _, _, highestCommitBlock = engineV2.GetPropertiesFaker()

	assert.Equal(t, types.Round(4), round)
	assert.Equal(t, types.Round(3), highestQC.ProposedBlockInfo.Round)
	assert.Equal(t, currentBlock.Hash(), highestCommitBlock.Hash)
	assert.Equal(t, currentBlock.Number(), highestCommitBlock.Number)
	assert.Equal(t, types.Round(1), highestCommitBlock.Round)
}

func TestShouldNotCommitIfRoundsNotContinousFor3Rounds(t *testing.T) {
	skipLongInShortMode(t)
	// Block 901 is the first v2 block with round of 1
	blockchain, _, currentBlock, signer, signFn, _ := PrepareXDCTestBlockChainForV2Engine(t, 905, params.TestXDPoSMockChainConfig, nil)
	engineV2 := blockchain.Engine().(*XDPoS.XDPoS).EngineV2

	var extraField types.ExtraFields_v2
	err := utils.DecodeBytesExtraFields(currentBlock.Extra(), &extraField)
	if err != nil {
		t.Fatal("Fail to decode extra data", err)
	}

	err = engineV2.ProposedBlockHandler(blockchain, currentBlock.Header())
	if err != nil {
		t.Fatal("Fail propose proposedBlock handler", err)
	}

	voteMsg := <-engineV2.BroadcastCh
	assert.NotNil(t, voteMsg)
	assert.Equal(t, currentBlock.Hash(), voteMsg.(*types.Vote).ProposedBlockInfo.Hash)

	round, _, highestQC, _, _, highestCommitBlock := engineV2.GetPropertiesFaker()

	grandGrandParentBlock := blockchain.GetBlockByNumber(902)
	// Shoud trigger setNewRound
	assert.Equal(t, types.Round(5), round)
	assert.Equal(t, types.Round(4), highestQC.ProposedBlockInfo.Round)
	assert.Equal(t, grandGrandParentBlock.Hash(), highestCommitBlock.Hash)
	assert.Equal(t, grandGrandParentBlock.Number(), highestCommitBlock.Number)
	assert.Equal(t, types.Round(2), highestCommitBlock.Round)

	// Injecting new block which have gaps in the round number (Round 7 instead of 6)
	blockNum := 906
	blockCoinBase := fmt.Sprintf("0x111000000000000000000000000000000%03d", blockNum)
	block906 := CreateBlock(blockchain, params.TestXDPoSMockChainConfig, currentBlock, blockNum, 7, blockCoinBase, signer, signFn, nil, nil, "")
	err = blockchain.InsertBlock(block906)
	assert.Nil(t, err)
	err = engineV2.ProposedBlockHandler(blockchain, block906.Header())
	if err != nil {
		t.Fatal("Fail propose proposedBlock handler", err)
	}
	// Trigger send vote again but for a new round
	voteMsg = <-engineV2.BroadcastCh
	assert.NotNil(t, voteMsg)
	round, _, highestQC, _, _, highestCommitBlock = engineV2.GetPropertiesFaker()
	grandGrandParentBlock = blockchain.GetBlockByNumber(903)

	assert.Equal(t, types.Round(6), round)
	assert.Equal(t, types.Round(5), highestQC.ProposedBlockInfo.Round)
	// It commit its grandgrandparent block
	assert.Equal(t, grandGrandParentBlock.Hash(), highestCommitBlock.Hash)
	assert.Equal(t, grandGrandParentBlock.Number(), highestCommitBlock.Number)
	assert.Equal(t, types.Round(3), highestCommitBlock.Round)

	blockNum = 907
	blockCoinBase = fmt.Sprintf("0x111000000000000000000000000000000%03d", blockNum)
	block907 := CreateBlock(blockchain, params.TestXDPoSMockChainConfig, block906, blockNum, 8, blockCoinBase, signer, signFn, nil, nil, "")
	err = blockchain.InsertBlock(block907)
	assert.Nil(t, err)
	err = engineV2.ProposedBlockHandler(blockchain, block907.Header())
	if err != nil {
		t.Fatal("Fail propose proposedBlock handler", err)
	}
	// Trigger send vote again but for a new round
	voteMsg = <-engineV2.BroadcastCh
	assert.NotNil(t, voteMsg)
	round, _, highestQC, _, _, highestCommitBlock = engineV2.GetPropertiesFaker()

	assert.Equal(t, types.Round(8), round)
	assert.Equal(t, types.Round(7), highestQC.ProposedBlockInfo.Round)
	// Should NOT commit, the `grandGrandParentBlock` is still on blockNum 903
	assert.Equal(t, grandGrandParentBlock.Hash(), highestCommitBlock.Hash)
	assert.Equal(t, grandGrandParentBlock.Number(), highestCommitBlock.Number)
	assert.Equal(t, types.Round(3), highestCommitBlock.Round)
}

func TestProposedBlockMessageHandlerSuccessfullyGenerateVote(t *testing.T) {
	blockchain, _, currentBlock, _, _, _ := PrepareXDCTestBlockChainForV2Engine(t, 906, params.TestXDPoSMockChainConfig, nil)
	engineV2 := blockchain.Engine().(*XDPoS.XDPoS).EngineV2

	// Set current round to 5
	engineV2.SetNewRoundFaker(blockchain, types.Round(5), false)

	var extraField types.ExtraFields_v2
	err := utils.DecodeBytesExtraFields(currentBlock.Extra(), &extraField)
	if err != nil {
		t.Fatal("Fail to decode extra data", err)
	}

	err = engineV2.ProposedBlockHandler(blockchain, currentBlock.Header())
	if err != nil {
		t.Fatal("Fail propose proposedBlock handler", err)
	}

	voteMsg := <-engineV2.BroadcastCh
	assert.NotNil(t, voteMsg)
	assert.Equal(t, currentBlock.Hash(), voteMsg.(*types.Vote).ProposedBlockInfo.Hash)

	round, _, highestQC, _, _, _ := engineV2.GetPropertiesFaker()
	// Shoud trigger setNewRound
	assert.Equal(t, types.Round(6), round)
	assert.Equal(t, extraField.QuorumCert.Signatures, highestQC.Signatures)
}

// Should not set new round if proposedBlockInfo round is less than currentRound.
// NOTE: This shall not even happen because we have `verifyQC` before being passed into ProposedBlockHandler
func TestShouldNotSetNewRound(t *testing.T) {
	blockchain, _, currentBlock, _, _, _ := PrepareXDCTestBlockChainForV2Engine(t, 906, params.TestXDPoSMockChainConfig, nil)
	engineV2 := blockchain.Engine().(*XDPoS.XDPoS).EngineV2

	// Set current round to 6
	engineV2.SetNewRoundFaker(blockchain, types.Round(6), false)

	var extraField types.ExtraFields_v2
	err := utils.DecodeBytesExtraFields(currentBlock.Extra(), &extraField)
	if err != nil {
		t.Fatal("Fail to decode extra data", err)
	}

	err = engineV2.ProposedBlockHandler(blockchain, currentBlock.Header())
	if err != nil {
		t.Fatal("Fail propose proposedBlock handler", err)
	}

	round, _, highestQC, _, _, _ := engineV2.GetPropertiesFaker()
	// Shoud not trigger setNewRound
	assert.Equal(t, types.Round(6), round)
	assert.Equal(t, extraField.QuorumCert.Signatures, highestQC.Signatures)
}

func TestShouldNotSendVoteMessageIfAlreadyVoteForThisRound(t *testing.T) {
	skipLongInShortMode(t)
	blockchain, _, currentBlock, _, _, _ := PrepareXDCTestBlockChainForV2Engine(t, 906, params.TestXDPoSMockChainConfig, nil)
	engineV2 := blockchain.Engine().(*XDPoS.XDPoS).EngineV2

	// Set current round to 5
	engineV2.SetNewRoundFaker(blockchain, types.Round(5), false)

	err := engineV2.ProposedBlockHandler(blockchain, currentBlock.Header())
	if err != nil {
		t.Fatal("Fail propose proposedBlock handler", err)
	}

	voteMsg := <-engineV2.BroadcastCh
	assert.NotNil(t, voteMsg)
	assert.Equal(t, currentBlock.Hash(), voteMsg.(*types.Vote).ProposedBlockInfo.Hash)

	round, _, _, _, highestVotedRound, _ := engineV2.GetPropertiesFaker()
	// Shoud trigger setNewRound
	assert.Equal(t, types.Round(6), round)
	assert.Equal(t, types.Round(6), highestVotedRound)

	// Let's send again, this time, it shall not broadcast any vote message, because HigestVoteRound is same as currentRound
	err = engineV2.ProposedBlockHandler(blockchain, currentBlock.Header())
	if err != nil {
		t.Fatal("Fail propose proposedBlock handler again", err)
	}
	// Should not receive anything from the channel
	select {
	case <-engineV2.BroadcastCh:
		t.Fatal("Should not trigger vote")
	case <-time.After(3 * time.Second):
		// Shoud not trigger setNewRound
		round, _, _, _, highestVotedRound, _ = engineV2.GetPropertiesFaker()
		assert.Equal(t, types.Round(6), round)
		assert.Equal(t, types.Round(6), highestVotedRound)
	}
}

func TestShouldNotSendVoteMsgIfBlockInfoRoundNotEqualCurrentRound(t *testing.T) {
	skipLongInShortMode(t)
	blockchain, _, currentBlock, _, _, _ := PrepareXDCTestBlockChainForV2Engine(t, 906, params.TestXDPoSMockChainConfig, nil)
	engineV2 := blockchain.Engine().(*XDPoS.XDPoS).EngineV2

	// Set current round to 8
	engineV2.SetNewRoundFaker(blockchain, types.Round(8), false)

	var extraField types.ExtraFields_v2
	err := utils.DecodeBytesExtraFields(currentBlock.Extra(), &extraField)
	if err != nil {
		t.Fatal("Fail to decode extra data", err)
	}

	err = engineV2.ProposedBlockHandler(blockchain, currentBlock.Header())
	if err != nil {
		t.Fatal("Fail propose proposedBlock handler", err)
	}
	// Should not receive anything from the channel
	select {
	case <-engineV2.BroadcastCh:
		t.Fatal("Should not trigger vote")
	case <-time.After(3 * time.Second):
		// Shoud not trigger setNewRound
		round, _, _, _, _, _ := engineV2.GetPropertiesFaker()
		assert.Equal(t, types.Round(8), round)
	}
}

/*
		Block and round relationship diagram for this test
		... - 13(3) - 14(4) - 15(5) - 16(6)
	            \ 14'(7)
*/
func TestShouldNotSendVoteMsgIfBlockNotExtendedFromAncestor(t *testing.T) {
	skipLongInShortMode(t)
	// Block number 905, 906 have forks and forkedBlock is the 906th
	var numOfForks = new(int)
	*numOfForks = 3
	blockchain, _, currentBlock, _, _, forkedBlock := PrepareXDCTestBlockChainForV2Engine(t, 906, params.TestXDPoSMockChainConfig, &ForkedBlockOptions{numOfForkedBlocks: numOfForks})
	engineV2 := blockchain.Engine().(*XDPoS.XDPoS).EngineV2

	var extraField types.ExtraFields_v2
	err := utils.DecodeBytesExtraFields(forkedBlock.Extra(), &extraField)
	if err != nil {
		t.Fatal("Fail to decode extra data", err)
	}
	assert.Equal(t, types.Round(9), extraField.Round)

	// Process the QC carried by block 906 to set the lockQC without voting,
	// so the negative case below is not blocked by the highestVotedRound
	// voting-rule gate. The lockQC is the QC embedded in the block the QC
	// points at, i.e. block 905's own QC pointing at block 904.
	var extra906 types.ExtraFields_v2
	err = utils.DecodeBytesExtraFields(currentBlock.Extra(), &extra906)
	if err != nil {
		t.Fatal("Fail to decode extra data of block 906", err)
	}
	err = engineV2.ProcessQCFaker(blockchain, extra906.QuorumCert)
	if err != nil {
		t.Fatal("Fail to process QC of block 906", err)
	}

	// Negative case: propose the canonical block 903, whose height is below
	// the locked ancestor block 904. verifyVotingRule must reject it as not
	// extending from the lockQC ancestor, so no vote is broadcast. The
	// block is canonical on purpose, so the entry canonicality re-check of
	// ProposedBlockHandler does not short-circuit the branch under test.
	olderCanonicalBlock := blockchain.GetBlockByNumber(903)
	assert.Equal(t, olderCanonicalBlock.Hash(), blockchain.GetCanonicalHash(olderCanonicalBlock.NumberU64()))
	engineV2.SetNewRoundFaker(blockchain, types.Round(3), false)
	err = engineV2.ProposedBlockHandler(blockchain, olderCanonicalBlock.Header())
	if err != nil {
		t.Fatal("Fail propose proposedBlock handler", err)
	}
	// Should not receive anything from the channel
	select {
	case <-engineV2.BroadcastCh:
		t.Fatal("Should not trigger vote")
	case <-time.After(3 * time.Second):
		// Shoud not trigger setNewRound
		round, _, _, _, _, _ := engineV2.GetPropertiesFaker()
		assert.Equal(t, types.Round(3), round)
	}

	// Positive control: the canonical block 906 extends the locked ancestor,
	// so its vote is broadcast as usual.
	err = engineV2.ProposedBlockHandler(blockchain, currentBlock.Header())
	if err != nil {
		t.Fatal("Error while handling block 16", err)
	}
	vote := <-engineV2.BroadcastCh
	assert.Equal(t, types.Round(6), vote.(*types.Vote).ProposedBlockInfo.Round)
}

// Block and round relationship diagram for this test:
// 904(4) - 905(5) - 906(6)       (canonical)
// \ 904'(7) - 905'(8) - 906'(9)   (fork)
//
// The proposed block is canonical and higher than the locked ancestor, but
// the locked ancestor belongs to a fork that has been reorged away. This
// forces isExtendingFromAncestor to walk back through the proposed block's
// parents before the final hash comparison rejects it. The contrasting test
// above uses a proposed block below the locked ancestor, so that walk does
// not run.
//
// Only the non-matching branch of the parent walk is reachable through the
// handler. Reaching the ancestor would require proposing the forked block,
// which ProposedBlockHandler rejects at its canonicality check first.
func TestShouldNotSendVoteMsgIfCanonicalBlockNotExtendedFromForkedAncestor(t *testing.T) {
	skipLongInShortMode(t)
	// Block number 905, 906 have forks and forkedBlock is the 906th
	var numOfForks = new(int)
	*numOfForks = 3
	blockchain, _, currentBlock, _, _, forkedBlock := PrepareXDCTestBlockChainForV2Engine(t, 906, params.TestXDPoSMockChainConfig, &ForkedBlockOptions{numOfForkedBlocks: numOfForks})
	defer blockchain.Stop()
	engineV2 := blockchain.Engine().(*XDPoS.XDPoS).EngineV2

	forkedAncestor := blockchain.GetBlockByHash(blockchain.GetBlockByHash(forkedBlock.ParentHash()).ParentHash())
	assert.NotEqual(t, blockchain.GetCanonicalHash(forkedAncestor.NumberU64()), forkedAncestor.Hash())

	// Process the QC carried by the canonical block 906, then the QC carried
	// by the forked block 906', to set the lockQC without voting, so the
	// negative case below is not blocked by the highestVotedRound voting-rule
	// gate. The lockQC is the QC embedded in the block the processed QC
	// points at: the first call leaves it at the canonical block 905's own
	// QC (pointing at the canonical block 904), and the second call replaces
	// it with the forked block 905's own QC, which points at the forked
	// block 904'.
	var extra906 types.ExtraFields_v2
	err := utils.DecodeBytesExtraFields(currentBlock.Extra(), &extra906)
	if err != nil {
		t.Fatal("Fail to decode extra data of block 906", err)
	}
	err = engineV2.ProcessQCFaker(blockchain, extra906.QuorumCert)
	if err != nil {
		t.Fatal("Fail to process QC of block 906", err)
	}

	var extraForked906 types.ExtraFields_v2
	err = utils.DecodeBytesExtraFields(forkedBlock.Extra(), &extraForked906)
	if err != nil {
		t.Fatal("Fail to decode extra data of forked block 906'", err)
	}
	err = engineV2.ProcessQCFaker(blockchain, extraForked906.QuorumCert)
	if err != nil {
		t.Fatal("Fail to process QC of forked block 906'", err)
	}

	// Pin the preconditions the negative case below relies on: the lockQC
	// points at the forked ancestor and the current round leaves room for a
	// vote on the canonical block 906 (round 6).
	_, lockQC, _, _, highestVotedRound, _ := engineV2.GetPropertiesFaker()
	if assert.NotNil(t, lockQC) {
		assert.Equal(t, forkedAncestor.Hash(), lockQC.ProposedBlockInfo.Hash)
	}
	assert.Equal(t, types.Round(0), highestVotedRound)

	// Negative case: propose the canonical block 906. It passes the entry
	// canonicality re-check of ProposedBlockHandler on purpose, so the branch
	// under test is verifyVotingRule: the block's QC round does not outrank
	// the lockQC round, so isExtendingFromAncestor walks two parents down to
	// the canonical block 904, which is not the forked ancestor 904', and the
	// vote must be dropped.
	engineV2.SetNewRoundFaker(blockchain, types.Round(6), false)
	err = engineV2.ProposedBlockHandler(blockchain, currentBlock.Header())
	if err != nil {
		t.Fatal("Fail propose proposedBlock handler", err)
	}
	// Should not receive anything from the channel
	select {
	case <-engineV2.BroadcastCh:
		t.Fatal("Should not trigger vote")
	case <-time.After(3 * time.Second):
		// Should not trigger setNewRound
		round, lockQC, _, _, _, _ := engineV2.GetPropertiesFaker()
		assert.Equal(t, types.Round(6), round)
		if assert.NotNil(t, lockQC) {
			assert.Equal(t, forkedAncestor.Hash(), lockQC.ProposedBlockInfo.Hash)
		}
	}
}

func TestShouldSendVoteMsg(t *testing.T) {
	// Block number 15, 16 have forks and forkedBlock is the 16th
	blockchain, _, _, _, _, _ := PrepareXDCTestBlockChainForV2Engine(t, 903, params.TestXDPoSMockChainConfig, nil)
	engineV2 := blockchain.Engine().(*XDPoS.XDPoS).EngineV2

	// Block 901 is first v2 block
	for i := 901; i < 904; i++ {
		blockHeader := blockchain.GetBlockByNumber(uint64(i)).Header()
		err := engineV2.ProposedBlockHandler(blockchain, blockHeader)
		if err != nil {
			t.Fatal(err)
		}
		round, _, _, _, _, _ := engineV2.GetPropertiesFaker()
		assert.Equal(t, types.Round(i-900), round)
		vote := <-engineV2.BroadcastCh
		assert.Equal(t, round, vote.(*types.Vote).ProposedBlockInfo.Round)
	}
}

func TestProposedBlockMessageHandlerNotGenerateVoteIfSignerNotInMNlist(t *testing.T) {
	skipLongInShortMode(t)
	blockchain, _, currentBlock, _, _, _ := PrepareXDCTestBlockChainForV2Engine(t, 906, params.TestXDPoSMockChainConfig, nil)
	engineV2 := blockchain.Engine().(*XDPoS.XDPoS).EngineV2
	differentSigner, differentSignFn, err := backends.SimulateWalletAddressAndSignFn()
	assert.Nil(t, err)
	// Let's change the address
	engineV2.Authorize(differentSigner, differentSignFn)

	// Set current round to 5
	engineV2.SetNewRoundFaker(blockchain, types.Round(5), false)

	var extraField types.ExtraFields_v2
	err = utils.DecodeBytesExtraFields(currentBlock.Extra(), &extraField)
	if err != nil {
		t.Fatal("Fail to decode extra data", err)
	}

	err = engineV2.ProposedBlockHandler(blockchain, currentBlock.Header())
	if err != nil {
		t.Fatal("Fail propose proposedBlock handler", err)
	}

	// Should not receive anything from the channel
	select {
	case <-engineV2.BroadcastCh:
		t.Fatal("Should not trigger vote")
	case <-time.After(2 * time.Second):
		// Shoud not trigger setNewRound
		round, _, _, _, _, _ := engineV2.GetPropertiesFaker()
		assert.Equal(t, types.Round(6), round)
	}
}

// TestProposedBlockHandlerSkipsNonCanonicalBlock pins the canonicality and
// storage re-check directly in front of processQC: the callers' gates race
// with concurrent imports, and processQC updates highestQuorumCert, the lock
// QC and the commit block before its own existence check, which a stored
// side-chain block passes. The forked block below is exactly what the
// window leaves behind: stored, with a valid parent QC, but no longer
// canonical at its height.
func TestProposedBlockHandlerSkipsNonCanonicalBlock(t *testing.T) {
	var numOfForks = new(int)
	*numOfForks = 1
	blockchain, _, currentBlock, _, _, forkedBlock := PrepareXDCTestBlockChainForV2Engine(t, 906, params.TestXDPoSMockChainConfig, &ForkedBlockOptions{numOfForkedBlocks: numOfForks})
	defer blockchain.Stop()
	engineV2 := blockchain.Engine().(*XDPoS.XDPoS).EngineV2

	// Precondition: the fork is stored but is not canonical at its height.
	assert.NotNil(t, blockchain.GetBlockByHash(forkedBlock.Hash()))
	assert.NotEqual(t, forkedBlock.Hash(), blockchain.GetCanonicalHash(forkedBlock.NumberU64()))
	assert.Equal(t, currentBlock.Hash(), blockchain.GetCanonicalHash(forkedBlock.NumberU64()))

	beforeRound, beforeLockQC, beforeHighestQC, beforeTimeoutCert, beforeVotedRound, beforeCommit := engineV2.GetPropertiesFaker()
	skippedBefore := skippedProposedBlockCount(t)
	nonCanonicalBefore := skipReasonCounterCount(t, "skipped-proposed-block/non-canonical")
	err := engineV2.ProposedBlockHandler(blockchain, forkedBlock.Header())
	assert.Nil(t, err)
	assert.Equal(t, skippedBefore+1, skippedProposedBlockCount(t), "the first-gate skip must increment skipped-proposed-block")
	assert.Equal(t, nonCanonicalBefore+1, skipReasonCounterCount(t, "skipped-proposed-block/non-canonical"), "the first-gate skip must increment the non-canonical reason counter")

	round, lockQC, highestQC, timeoutCert, votedRound, commit := engineV2.GetPropertiesFaker()
	assert.Equal(t, beforeRound, round)
	assert.Equal(t, beforeLockQC, lockQC)
	assert.Equal(t, beforeHighestQC, highestQC)
	assert.Equal(t, beforeTimeoutCert, timeoutCert)
	assert.Equal(t, beforeVotedRound, votedRound)
	assert.Equal(t, beforeCommit, commit)

	// Neither commitBlocks nor setNewRound (processQC's other state writes —
	// commit, round bump, timeoutPool clear, newRoundCh signal) may have run:
	// the gate sits before processQC. The engine state assertions above cover
	// the fields; here we pin that no newRoundCh signal was emitted either.
	// The handler runs synchronously and NewRoundCh is buffered, so a
	// non-blocking read right after the call is deterministic — no clock wait
	// that could let the round timeout fire instead.
	chainEngine := blockchain.Engine().(*XDPoS.XDPoS)
	select {
	case newRound := <-chainEngine.NewRoundCh:
		t.Fatalf("non-canonical block must not advance the round, got newRoundCh signal %v", newRound)
	default:
	}

	// A non-canonical block must not reach the vote broadcast either.
	select {
	case vote := <-engineV2.BroadcastCh:
		t.Fatalf("non-canonical block must not trigger a vote, got round %v", vote.(*types.Vote).ProposedBlockInfo.Round)
	case <-time.After(2 * time.Second):
	}
}

// TestProposedBlockHandlerCoversMinerSelfVotePath mirrors the miner's
// self-vote path (miner/worker.go: after WriteBlockWithState returns, the
// worker calls HandleProposedBlock on its own block) against both write
// outcomes the worker can observe. The miner calls the same handler these
// tests drive, so this test makes that coupling explicit: a gate-semantic
// change that would silently stop the proposer from advancing processQC and
// self-voting must fail here first.
func TestProposedBlockHandlerCoversMinerSelfVotePath(t *testing.T) {
	var numOfForks = new(int)
	*numOfForks = 1
	blockchain, _, currentBlock, _, _, forkedBlock := PrepareXDCTestBlockChainForV2Engine(t, 906, params.TestXDPoSMockChainConfig, &ForkedBlockOptions{numOfForkedBlocks: numOfForks})
	defer blockchain.Stop()
	engineV2 := blockchain.Engine().(*XDPoS.XDPoS).EngineV2

	// Own block written as canonical (WriteBlockWithState returned
	// core.CanonStatTy): the gate must let it through, processQC runs and the
	// self-vote is broadcast. No skip counter may move.
	skippedBefore := skippedProposedBlockCount(t)
	err := engineV2.ProposedBlockHandler(blockchain, currentBlock.Header())
	assert.Nil(t, err)
	vote := <-engineV2.BroadcastCh
	assert.Equal(t, currentBlock.Hash(), vote.(*types.Vote).ProposedBlockInfo.Hash)
	assert.Equal(t, types.Round(6), vote.(*types.Vote).ProposedBlockInfo.Round)
	assert.Equal(t, skippedBefore, skippedProposedBlockCount(t), "a canonical self-mined block must pass the gate without any skip")

	// Competing block at the same height written as a side chain
	// (WriteBlockWithState returned core.SideStatTy, i.e. the peer's block
	// landed first): the gate must skip it — no processQC, no self-vote —
	// counting the non-canonical reason.
	assert.NotNil(t, blockchain.GetBlockByHash(forkedBlock.Hash()))
	assert.NotEqual(t, forkedBlock.Hash(), blockchain.GetCanonicalHash(forkedBlock.NumberU64()))
	nonCanonicalBefore := skipReasonCounterCount(t, "skipped-proposed-block/non-canonical")
	err = engineV2.ProposedBlockHandler(blockchain, forkedBlock.Header())
	assert.Nil(t, err)
	assert.Equal(t, skippedBefore+1, skippedProposedBlockCount(t), "a side-chain self-mined block must be skipped by the gate")
	assert.Equal(t, nonCanonicalBefore+1, skipReasonCounterCount(t, "skipped-proposed-block/non-canonical"), "the side-chain skip must increment the non-canonical reason counter")

	select {
	case vote := <-engineV2.BroadcastCh:
		t.Fatalf("a side-chain self-mined block must not trigger a vote, got round %v", vote.(*types.Vote).ProposedBlockInfo.Round)
	case <-time.After(2 * time.Second):
	}
}

// reorgingChainReader simulates a concurrent reorg landing inside the
// handler: x.lock does not block InsertChain, so the canonical answer for
// a height can change between two judgment gates. The injection is anchored
// on the gate boundary, not on read ordinals: every ShouldHandleProposedBlock
// call that gets past the canonicality check ends in exactly one HasBlock of
// the watched height (the judgment's contract, fixated at the unit level in
// consensus/proposed_block_test.go), so the wrapper counts those HasBlock
// calls as completed gates and serves the fork header on every read of the
// watched height once truthfulGates gates have completed. Reads added in
// front of or between the handler's gates therefore stay truthful and cannot
// consume the fork early — the injection tracks where the reorg lands
// relative to the gates, not how many times the handler happens to read.
type reorgingChainReader struct {
	consensus.ChainReader
	watchNumber   uint64
	truthfulGates int
	forkHeader    *types.Header

	// gates counts the completed judgment gates (HasBlock calls of the
	// watched height); it is the injection anchor, not an assertion.
	gates int
}

func (r *reorgingChainReader) GetHeaderByNumber(number uint64) *types.Header {
	if number == r.watchNumber && r.gates >= r.truthfulGates {
		return r.forkHeader
	}
	return r.ChainReader.GetHeaderByNumber(number)
}

// HasBlock forwards the storage half of the proposed-block judgment to the
// wrapped chain, which must be a consensus.BlockStorer — the wrapper only
// rewrites canonicality, never storage. Each HasBlock of the watched height
// marks one completed judgment gate (the canonicality half passed), which is
// what drives the fork injection above.
func (r *reorgingChainReader) HasBlock(hash common.Hash, number uint64) bool {
	if number == r.watchNumber {
		r.gates++
	}
	return r.ChainReader.(consensus.BlockStorer).HasBlock(hash, number)
}

// TestProposedBlockHandlerSkipsReorgedBlockBeforeProcessQC covers the first
// re-check point, directly in front of processQC: x.lock does not block
// InsertChain, so a concurrent import can take the height over before the
// handler reaches it. The wrapper serves the fork header from the first read
// of the watched height on, making the reorg deterministic instead of racing
// a real InsertChain. Block 906's embedded QC certifies block 905 at round 5,
// higher than the engine's initial highestQuorumCert (round 0), so any
// processQC run would visibly move the engine state — exactly what the gate
// must prevent for a reorged-away block.
func TestProposedBlockHandlerSkipsReorgedBlockBeforeProcessQC(t *testing.T) {
	skipLongInShortMode(t)
	var numOfForks = new(int)
	*numOfForks = 1
	blockchain, _, currentBlock, _, _, forkedBlock := PrepareXDCTestBlockChainForV2Engine(t, 906, params.TestXDPoSMockChainConfig, &ForkedBlockOptions{numOfForkedBlocks: numOfForks})
	defer blockchain.Stop()
	engineV2 := blockchain.Engine().(*XDPoS.XDPoS).EngineV2

	// Precondition: the fork sits at the same height but is not canonical.
	assert.NotNil(t, blockchain.GetBlockByHash(forkedBlock.Hash()))
	assert.Equal(t, forkedBlock.NumberU64(), currentBlock.NumberU64())
	assert.NotEqual(t, forkedBlock.Hash(), blockchain.GetCanonicalHash(forkedBlock.NumberU64()))

	// The height is already reorged when the handler first reads it: zero
	// truthful gates.
	chain := &reorgingChainReader{
		ChainReader:   blockchain,
		watchNumber:   currentBlock.NumberU64(),
		truthfulGates: 0,
		forkHeader:    forkedBlock.Header(),
	}
	beforeRound, beforeLockQC, beforeHighQC, beforeHighTC, beforeVotedRound, beforeCommitBlock := engineV2.GetPropertiesFaker()
	err := engineV2.ProposedBlockHandler(chain, currentBlock.Header())
	assert.Nil(t, err)

	// The block was reorged away before processQC: the engine state must be
	// untouched — no QC processed, nothing locked, nothing committed, no
	// round advanced.
	afterRound, afterLockQC, afterHighQC, afterHighTC, afterVotedRound, afterCommitBlock := engineV2.GetPropertiesFaker()
	assert.Equal(t, beforeRound, afterRound)
	assert.Equal(t, beforeLockQC, afterLockQC)
	assert.Equal(t, beforeHighQC, afterHighQC)
	assert.Equal(t, beforeHighTC, afterHighTC)
	assert.Equal(t, beforeVotedRound, afterVotedRound)
	assert.Equal(t, beforeCommitBlock, afterCommitBlock)

	// Nothing may be broadcast either.
	select {
	case vote := <-engineV2.BroadcastCh:
		t.Fatalf("a block reorged away before processQC must not be voted for, got vote for round %v hash %v", vote.(*types.Vote).ProposedBlockInfo.Round, vote.(*types.Vote).ProposedBlockInfo.Hash)
	case <-time.After(2 * time.Second):
	}

	// No gate anchor needed: truthfulGates is 0, so every read of the watched
	// height sees the fork and the handler skips before processQC no matter
	// where the gates sit — the state anchors above cover the drift.
}

// TestProposedBlockHandlerDropsVoteForReorgedBlock covers the second
// re-check point, right before sendVote: x.lock does not block InsertChain,
// so a concurrent import can take the height over after processQC ran on the
// still canonical block but before the vote is broadcast. The wrapper serves
// the real canonical header to the pre-processQC re-check and the fork
// header from then on, making the mid-handler reorg deterministic instead of
// racing a real InsertChain. processQC legitimately runs in this window (the
// block was canonical when it read the chain, so its state write is
// expected); the vote is what must be dropped.
func TestProposedBlockHandlerDropsVoteForReorgedBlock(t *testing.T) {
	skipLongInShortMode(t)
	var numOfForks = new(int)
	*numOfForks = 1
	// Height 906, not 901: the state anchor below needs a processQC run
	// that visibly moves the engine. Block 901's embedded QC certifies
	// block 900 at round 0, which the engine already holds — processQC
	// would be a complete state no-op there. Block 906's QC certifies
	// block 905 at round 5, strictly above the engine's initial state,
	// so a successful processQC run advances highestQuorumCert, lockQC,
	// currentRound and the commit block and the anchor can detect it.
	blockchain, _, currentBlock, _, _, forkedBlock := PrepareXDCTestBlockChainForV2Engine(t, 906, params.TestXDPoSMockChainConfig, &ForkedBlockOptions{numOfForkedBlocks: numOfForks})
	defer blockchain.Stop()
	engineV2 := blockchain.Engine().(*XDPoS.XDPoS).EngineV2

	// Precondition: the fork sits at the same height but is not canonical.
	assert.NotNil(t, blockchain.GetBlockByHash(forkedBlock.Hash()))
	assert.Equal(t, forkedBlock.NumberU64(), currentBlock.NumberU64())
	assert.NotEqual(t, forkedBlock.Hash(), blockchain.GetCanonicalHash(forkedBlock.NumberU64()))

	// One truthful gate — the pre-processQC re-check; every read of this
	// height from the gate's completion on sees the reorg. The injection is
	// anchored on gate completion (HasBlock of the watched height), so reads
	// added in front of the first gate stay truthful instead of consuming
	// the fork there.
	chain := &reorgingChainReader{
		ChainReader:   blockchain,
		watchNumber:   currentBlock.NumberU64(),
		truthfulGates: 1,
		forkHeader:    forkedBlock.Header(),
	}
	beforeRound, _, beforeHighQC, _, _, _ := engineV2.GetPropertiesFaker()
	skippedBefore := skippedProposedBlockCount(t)
	err := engineV2.ProposedBlockHandler(chain, currentBlock.Header())
	assert.Nil(t, err)
	assert.Equal(t, skippedBefore+1, skippedProposedBlockCount(t), "the pre-vote drop must increment skipped-proposed-block")

	// State anchor: processQC must have run and moved the engine between
	// the two gates. With truthfulGates 1 the pre-processQC gate still sees
	// the canonical header, so a reorg can only take over after that gate
	// completes. The injection itself is anchored on gate completion, not on
	// read ordinals, so reads added in front of or between the gates stay
	// truthful and cannot turn this into a pre-processQC skip. Only a
	// genuine pre-vote reorg lets processQC advance the state while the vote
	// is still dropped; any drift breaks the assertions below loudly.
	// The retained processQC state write is expected behavior, not a pending
	// fix: block 906's embedded QC certifies its parent 905, and that
	// certification stays valid even after 906 is reorged away, so advancing
	// highestQuorumCert/lockQC/the commit block on it is semantically right —
	// the reorg only invalidates the vote for 906 itself, which is exactly
	// what this test pins down (see also the second gate in engine.go).
	afterRound, afterLockQC, afterHighQC, _, _, afterCommitBlock := engineV2.GetPropertiesFaker()
	assert.Greater(t, afterRound, beforeRound, "processQC must have advanced the current round")
	assert.Greater(t, afterHighQC.ProposedBlockInfo.Round, beforeHighQC.ProposedBlockInfo.Round, "processQC must have advanced highestQuorumCert")
	assert.NotNil(t, afterLockQC, "processQC must have locked a parent QC")
	assert.NotNil(t, afterCommitBlock, "processQC must have committed a block")

	// The block was reorged away before the vote: nothing may be broadcast.
	select {
	case vote := <-engineV2.BroadcastCh:
		t.Fatalf("a block reorged away before the vote must not be voted for, got vote for round %v hash %v", vote.(*types.Vote).ProposedBlockInfo.Round, vote.(*types.Vote).ProposedBlockInfo.Hash)
	case <-time.After(2 * time.Second):
	}

}

// TestProposedBlockHandlerSkipsBlockWithoutBody covers the storage half of
// the gate: canonicality is a property of the header, not of the block, so
// the fast sync header phase marks a height canonical before its body lands,
// and the fetcher calls this handler after an insertBlock that can return
// nil without writing anything (fast sync, and the downloadingBlock
// short circuit). Only the downloader gates on storage, so the other
// callers are covered here: a canonical header without a body must not
// reach processQC or the vote broadcast, and must leave the engine state
// untouched.
func TestProposedBlockHandlerSkipsBlockWithoutBody(t *testing.T) {
	skipLongInShortMode(t)
	blockchain, _, currentBlock, signer, signFn, _ := PrepareXDCTestBlockChainForV2Engine(t, 906, params.TestXDPoSMockChainConfig, nil)
	defer blockchain.Stop()
	engineV2 := blockchain.Engine().(*XDPoS.XDPoS).EngineV2

	// Insert a valid header for height 907 header-only, the way the fast
	// sync header phase does: the height becomes canonical before any body
	// is written. The block is built with the chain's own config so the
	// header passes ValidateHeaderChain.
	testConfig := legacyExecutionConfigForV2Tests(params.TestXDPoSMockChainConfig)
	header907 := CreateBlock(blockchain, testConfig, currentBlock, 907, 7, signer.Hex(), signer, signFn, nil, nil, "").Header()
	if _, err := blockchain.InsertHeaderChain([]*types.Header{header907}, 0); err != nil {
		t.Fatal("Fail to insert header chain", err)
	}
	assert.Equal(t, header907.Hash(), blockchain.GetCanonicalHash(907))
	assert.Nil(t, blockchain.GetBlock(header907.Hash(), 907))

	before, beforeLockQC, beforeHighQC, beforeHighTC, beforeVotedRound, beforeCommitBlock := engineV2.GetPropertiesFaker()
	err := engineV2.ProposedBlockHandler(blockchain, header907)
	if err != nil {
		t.Fatal("Fail propose proposedBlock handler", err)
	}
	// Should not receive anything from the channel
	select {
	case <-engineV2.BroadcastCh:
		t.Fatal("Should not trigger vote")
	case <-time.After(3 * time.Second):
	}

	// The engine state must be untouched: no QC processed, nothing voted,
	// no round advanced.
	after, afterLockQC, afterHighQC, afterHighTC, afterVotedRound, afterCommitBlock := engineV2.GetPropertiesFaker()
	assert.Equal(t, before, after)
	assert.Equal(t, beforeLockQC, afterLockQC)
	assert.Equal(t, beforeHighQC, afterHighQC)
	assert.Equal(t, beforeHighTC, afterHighTC)
	assert.Equal(t, beforeVotedRound, afterVotedRound)
	assert.Equal(t, beforeCommitBlock, afterCommitBlock)
}

// TestProposedBlockHandlerGradesSkipLogLevelByReason fixates the skip-log
// grading: the reorg-race skips (SkipNonCanonical, SkipNoCanonicalHeader)
// surface as Warn — the fast sync header phase marks heights canonical, so
// a missing marker is never a routine sync state — while SkipBodyNotStored,
// the one routine sync skip, stays at Info so a Warn per header-only fast
// sync height cannot drown the level reserved for anomalies.
func TestProposedBlockHandlerGradesSkipLogLevelByReason(t *testing.T) {
	var numOfForks = new(int)
	*numOfForks = 1
	blockchain, _, currentBlock, signer, signFn, forkedBlock := PrepareXDCTestBlockChainForV2Engine(t, 906, params.TestXDPoSMockChainConfig, &ForkedBlockOptions{numOfForkedBlocks: numOfForks})
	defer blockchain.Stop()
	engineV2 := blockchain.Engine().(*XDPoS.XDPoS).EngineV2

	// Capture the handler's own skip logs and assert on the level prefix of
	// the specific skip line, so unrelated background logs cannot interfere.
	var logBuf bytes.Buffer
	prevLog := log.Root()
	glog := log.NewGlogHandler(log.NewTerminalHandlerWithLevel(&logBuf, log.LevelInfo, false))
	glog.Verbosity(log.LevelInfo)
	log.SetDefault(log.NewLogger(glog))
	defer log.SetDefault(prevLog)

	levelOf := func(msg string) string {
		for _, line := range strings.Split(logBuf.String(), "\n") {
			if strings.Contains(line, msg) {
				return strings.Fields(line)[0]
			}
		}
		return ""
	}

	// A fork block is a genuine reorg-race skip: it must stay at Warn.
	err := engineV2.ProposedBlockHandler(blockchain, forkedBlock.Header())
	assert.Nil(t, err)
	assert.Equal(t, "WARN", levelOf(consensus.SkipSiteProposedBlockHandler+" skip block before processQC"),
		"a non-canonical skip is a reorg race and must stay at Warn, have %q", logBuf.String())

	// A height with no canonical header at all is a reorg-race skip too:
	// markers only go missing above a contested head (a fork growing past
	// the local chain, a displaced tip re-delivered, or a concurrent reorg),
	// so it must stay at Warn. Reuse the fork header's extra data (so
	// getExtraFields still parses) at a height nothing occupies.
	noCanonical := *forkedBlock.Header()
	noCanonical.Number = big.NewInt(99999)
	logBuf.Reset()
	err = engineV2.ProposedBlockHandler(blockchain, &noCanonical)
	assert.Nil(t, err)
	assert.Equal(t, "WARN", levelOf(consensus.SkipSiteProposedBlockHandler+" skip block before processQC"),
		"a no-canonical-header skip is a reorg race and must stay at Warn, have %q", logBuf.String())

	// A canonical header without a stored body is the one routine skip: the
	// fast sync header phase marks a height canonical before its body lands,
	// so it must stay at Info. Build the shape the way that phase does —
	// InsertHeaderChain one height past the canonical tip — mirroring
	// TestProposedBlockHandlerSkipsBlockWithoutBody, and assert the level of
	// the very same skip line the two reorg-race sections above graded to Warn.
	testConfig := legacyExecutionConfigForV2Tests(params.TestXDPoSMockChainConfig)
	header907 := CreateBlock(blockchain, testConfig, currentBlock, 907, 7, signer.Hex(), signer, signFn, nil, nil, "").Header()
	if _, err := blockchain.InsertHeaderChain([]*types.Header{header907}, 0); err != nil {
		t.Fatal("Fail to insert header chain", err)
	}
	assert.Equal(t, header907.Hash(), blockchain.GetCanonicalHash(907))
	assert.Nil(t, blockchain.GetBlock(header907.Hash(), 907))
	logBuf.Reset()
	err = engineV2.ProposedBlockHandler(blockchain, header907)
	assert.Nil(t, err)
	assert.Equal(t, "INFO", levelOf(consensus.SkipSiteProposedBlockHandler+" skip block before processQC"),
		"a body-not-stored skip is routine fast-sync state and must stay at Info, have %q", logBuf.String())
}

// TestProposedBlockHandlerSkipsUnjudgeableChain was removed when the
// proposed-block entry points started requiring consensus.ProposedBlockChain:
// a chain without HasBlock can no longer reach the handler — the wiring
// fails at compile time instead. The runtime unjudgeable contract lives on
// only in the narrow CanonicalChain defense inside
// consensus.ShouldHandleProposedBlock, pinned at the helper level by
// TestShouldHandleProposedBlock (header-only-chain cases) and the
// skipReasons grading tests in consensus/proposed_block_test.go.

// TestProposedBlockHandlerSkipsNilHeader pins the engine-side nil-header
// contract: getExtraFields dereferences header.Number before the
// ShouldHandleProposedBlock guard runs, so the handler must judge the nil
// shapes itself — no panic, an Error-level skip through the skip table (a
// caller bug is graded like a wiring bug), nil returned, and no counter
// increment (a caller bug is not a block observation).
func TestProposedBlockHandlerSkipsNilHeader(t *testing.T) {
	blockchain, _, _, _, _, _ := PrepareXDCTestBlockChainForV2Engine(t, 901, params.TestXDPoSMockChainConfig, nil)
	defer blockchain.Stop()
	engineV2 := blockchain.Engine().(*XDPoS.XDPoS).EngineV2

	// Capture the handler's logs and assert the nil-header skip surfaces
	// at Error — a caller bug, graded like the wiring bugs.
	var logBuf bytes.Buffer
	prevLog := log.Root()
	glog := log.NewGlogHandler(log.NewTerminalHandlerWithLevel(&logBuf, log.LevelInfo, false))
	glog.Verbosity(log.LevelInfo)
	log.SetDefault(log.NewLogger(glog))
	defer log.SetDefault(prevLog)

	// Both nil shapes must be judged before getExtraFields dereferences
	// header.Number: a fully nil header and a header without a number.
	shapes := map[string]*types.Header{"nil": nil, "nil number": {}}
	before := skippedProposedBlockCount(t)
	for name, header := range shapes {
		assert.Nil(t, engineV2.ProposedBlockHandler(blockchain, header),
			"a %s header is a caller bug and must skip, not panic or error", name)
	}
	assert.Equal(t, before, skippedProposedBlockCount(t),
		"a caller-bug skip must not touch the block-observation counter")

	found := 0
	for _, line := range strings.Split(logBuf.String(), "\n") {
		if strings.Contains(line, "skip block: nil header") {
			assert.True(t, strings.HasPrefix(line, "ERROR"), "nil-header skip must log at Error, got line %q", line)
			found++
		}
	}
	assert.Equal(t, 2, found, "both nil shapes must be logged, have %q", logBuf.String())
}

// TestProposedBlockHandlerSkipsNonCanonicalBlockWithMalformedExtra pins the
// ordering between the skip judgment and extra parsing: the judgment reads
// only the header's place in the chain, so a block that must be skipped
// skips (nil) even when its extra data is malformed — surfacing an error
// would make the fetcher treat the skip as an import failure and suppress
// the block's broadcast.
func TestProposedBlockHandlerSkipsNonCanonicalBlockWithMalformedExtra(t *testing.T) {
	var numOfForks = new(int)
	*numOfForks = 1
	blockchain, _, _, _, _, forkedBlock := PrepareXDCTestBlockChainForV2Engine(t, 906, params.TestXDPoSMockChainConfig, &ForkedBlockOptions{numOfForkedBlocks: numOfForks})
	defer blockchain.Stop()
	engineV2 := blockchain.Engine().(*XDPoS.XDPoS).EngineV2

	// Precondition: the fork is stored but is not canonical at its height.
	assert.NotNil(t, blockchain.GetBlockByHash(forkedBlock.Hash()))
	assert.NotEqual(t, forkedBlock.Hash(), blockchain.GetCanonicalHash(forkedBlock.NumberU64()))

	// Corrupt the fork header's extra data so getExtraFields cannot decode
	// it; the corrupted copy stays non-canonical at its height (its hash no
	// longer matches the canonical entry either).
	header := *forkedBlock.Header()
	header.Extra = []byte("malformed extra")
	assert.NotEqual(t, header.Hash(), blockchain.GetCanonicalHash(header.Number.Uint64()))

	skippedBefore := skippedProposedBlockCount(t)
	err := engineV2.ProposedBlockHandler(blockchain, &header)
	assert.Nil(t, err, "a skippable block must skip even when its extra data is malformed")
	assert.Equal(t, skippedBefore+1, skippedProposedBlockCount(t), "the skip must increment skipped-proposed-block")

	// The skip must not reach the vote broadcast.
	select {
	case vote := <-engineV2.BroadcastCh:
		t.Fatalf("malformed-extra block must not trigger a vote, got %v", vote)
	default:
	}
}

// skippedProposedBlockCount reads the engine gates' skip counter through the
// metrics registry — the counter lives in the engine package and is otherwise
// invisible from this external test package.
//
// The assertions in this file compare counts before and after a call on the
// global registry, so no case in this file may use t.Parallel(): parallel
// cases touching the same counter would race on the before/after deltas.
func skippedProposedBlockCount(t *testing.T) int64 {
	t.Helper()
	counter, ok := metrics.Get("skipped-proposed-block").(*metrics.Counter)
	if !ok {
		t.Fatal("skipped-proposed-block is not registered in the metrics registry")
	}
	return counter.Snapshot().Count()
}

// skipReasonCounterCount reads a per-reason counter through the metrics
// registry; the counters live in the consensus package and are otherwise
// invisible from this external test package. Same no-t.Parallel() contract
// as skippedProposedBlockCount.
func skipReasonCounterCount(t *testing.T, name string) int64 {
	t.Helper()
	counter, ok := metrics.Get(name).(*metrics.Counter)
	if !ok {
		t.Fatalf("%s is not registered in the metrics registry", name)
	}
	return counter.Snapshot().Count()
}

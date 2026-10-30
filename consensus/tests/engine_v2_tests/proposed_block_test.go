package engine_v2_tests

import (
	"bytes"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/XinFinOrg/XDPoSChain/accounts/abi/bind/backends"
	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS/utils"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/internal/testshort"
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
	testshort.Skip(t)
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

	// Process block 906's QC to set the lockQC without voting, so the
	// highestVotedRound gate does not block the negative case below.
	var extra906 types.ExtraFields_v2
	err = utils.DecodeBytesExtraFields(currentBlock.Extra(), &extra906)
	if err != nil {
		t.Fatal("Fail to decode extra data of block 906", err)
	}
	err = engineV2.ProcessQCFaker(blockchain, extra906.QuorumCert)
	if err != nil {
		t.Fatal("Fail to process QC of block 906", err)
	}

	// Negative case: canonical block 903 sits below the locked ancestor 904, so
	// verifyVotingRule must reject it without a vote.
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

	// Positive control: block 906 extends the locked ancestor.
	err = engineV2.ProposedBlockHandler(blockchain, currentBlock.Header())
	if err != nil {
		t.Fatal("Error while handling block 16", err)
	}
	vote := <-engineV2.BroadcastCh
	assert.Equal(t, types.Round(6), vote.(*types.Vote).ProposedBlockInfo.Round)
}

/*
	Block and round relationship diagram for this test
	... - 904(4) - 905(5) - 906(6)   (canonical)
	      \ 904'(7) - 905'(8) - 906'(9)   (fork)

The proposed block is canonical and higher than the locked ancestor, which
sits on a reorged-away fork: the parent walk runs, and only its final hash
comparison can reject the block. The walk's positive branch is unreachable
through the handler, because the entry canonicality gate short-circuits a
block on the fork chain itself.
*/
func TestShouldNotSendVoteMsgIfCanonicalBlockNotExtendedFromForkedAncestor(t *testing.T) {
	// Block number 905, 906 have forks and forkedBlock is the 906th
	var numOfForks = new(int)
	*numOfForks = 3
	blockchain, _, currentBlock, _, _, forkedBlock := PrepareXDCTestBlockChainForV2Engine(t, 906, params.TestXDPoSMockChainConfig, &ForkedBlockOptions{numOfForkedBlocks: numOfForks})
	engineV2 := blockchain.Engine().(*XDPoS.XDPoS).EngineV2

	forkedAncestor := blockchain.GetBlockByHash(blockchain.GetBlockByHash(forkedBlock.ParentHash()).ParentHash())
	assert.NotEqual(t, blockchain.GetCanonicalHash(forkedAncestor.NumberU64()), forkedAncestor.Hash())

	// Process block 906's QC, then forked 906's, so the lockQC ends on the
	// forked ancestor 904' without voting.
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

	// The lockQC sits on the forked ancestor, and round 6 leaves room for a vote.
	_, lockQC, _, _, highestVotedRound, _ := engineV2.GetPropertiesFaker()
	if assert.NotNil(t, lockQC) {
		assert.Equal(t, forkedAncestor.Hash(), lockQC.ProposedBlockInfo.Hash)
	}
	assert.Equal(t, types.Round(0), highestVotedRound)

	// Negative case: block 906 is canonical, so the branch under test is
	// verifyVotingRule — the walk reaches block 904, not the forked 904', and
	// the vote must be dropped.
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

// TestProposedBlockHandlerSkipsNonCanonicalBlock covers the re-check in front of
// processQC: a stored side-chain block passes processQC's own existence check,
// but is not canonical at its height.
func TestProposedBlockHandlerSkipsNonCanonicalBlock(t *testing.T) {
	var numOfForks = new(int)
	*numOfForks = 1
	blockchain, _, currentBlock, _, _, forkedBlock := PrepareXDCTestBlockChainForV2Engine(t, 906, params.TestXDPoSMockChainConfig, &ForkedBlockOptions{numOfForkedBlocks: numOfForks})
	engineV2 := blockchain.Engine().(*XDPoS.XDPoS).EngineV2

	// Precondition: the fork is stored but is not canonical at its height.
	assert.NotNil(t, blockchain.GetBlockByHash(forkedBlock.Hash()))
	assert.NotEqual(t, forkedBlock.Hash(), blockchain.GetCanonicalHash(forkedBlock.NumberU64()))
	assert.Equal(t, currentBlock.Hash(), blockchain.GetCanonicalHash(forkedBlock.NumberU64()))

	beforeRound, beforeLockQC, beforeHighestQC, beforeTimeoutCert, beforeVotedRound, beforeCommit := engineV2.GetPropertiesFaker()
	skippedBefore := skippedProposedBlockCount(t)
	err := engineV2.ProposedBlockHandler(blockchain, forkedBlock.Header())
	assert.Nil(t, err)
	assert.Equal(t, skippedBefore+1, skippedProposedBlockCount(t), "the first-gate skip must increment consensus/skipped-proposed-block")

	round, lockQC, highestQC, timeoutCert, votedRound, commit := engineV2.GetPropertiesFaker()
	assert.Equal(t, beforeRound, round)
	assert.Equal(t, beforeLockQC, lockQC)
	assert.Equal(t, beforeHighestQC, highestQC)
	assert.Equal(t, beforeTimeoutCert, timeoutCert)
	assert.Equal(t, beforeVotedRound, votedRound)
	assert.Equal(t, beforeCommit, commit)

	// processQC's other writes — commit, round bump, timeoutPool clear,
	// newRoundCh signal — must not have run either, since the gate sits before
	// it.
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

// reorgingChainReader simulates a reorg landing inside the handler: x.lock does
// not block InsertChain, so the canonical answer can change between the two
// gates. It counts the HasBlock call that ends each gate and serves the fork
// header from the next read on.
type reorgingChainReader struct {
	t *testing.T
	consensus.ChainReader
	watchNumber   uint64
	truthfulGates int
	forkHeader    *types.Header

	// gates counts completed judgment gates at the watched height.
	gates int
}

func (r *reorgingChainReader) GetHeaderByNumber(number uint64) *types.Header {
	if number == r.watchNumber && r.gates >= r.truthfulGates {
		return r.forkHeader
	}
	return r.ChainReader.GetHeaderByNumber(number)
}

// HasBlock forwards the storage half to the wrapped chain, counting one
// completed judgment gate per call at the watched height.
func (r *reorgingChainReader) HasBlock(hash common.Hash, number uint64) bool {
	if number == r.watchNumber {
		r.gates++
	}
	storer, ok := r.ChainReader.(consensus.BlockStorer)
	if !ok {
		r.t.Fatalf("reorgingChainReader wraps a chain that does not implement consensus.BlockStorer")
	}
	return storer.HasBlock(hash, number)
}

// TestProposedBlockHandlerSkipsReorgedBlockBeforeProcessQC covers the first
// re-check, in front of processQC: block 906's QC certifies 905 at round 5, so
// a processQC run would visibly move the engine state — exactly what the gate
// must prevent. The wrapper serves the fork header from the first read on.
func TestProposedBlockHandlerSkipsReorgedBlockBeforeProcessQC(t *testing.T) {
	var numOfForks = new(int)
	*numOfForks = 1
	blockchain, _, currentBlock, _, _, forkedBlock := PrepareXDCTestBlockChainForV2Engine(t, 906, params.TestXDPoSMockChainConfig, &ForkedBlockOptions{numOfForkedBlocks: numOfForks})
	engineV2 := blockchain.Engine().(*XDPoS.XDPoS).EngineV2

	// Precondition: the fork sits at the same height but is not canonical.
	assert.NotNil(t, blockchain.GetBlockByHash(forkedBlock.Hash()))
	assert.Equal(t, forkedBlock.NumberU64(), currentBlock.NumberU64())
	assert.NotEqual(t, forkedBlock.Hash(), blockchain.GetCanonicalHash(forkedBlock.NumberU64()))

	// The height is already reorged: zero truthful gates.
	chain := &reorgingChainReader{
		t:             t,
		ChainReader:   blockchain,
		watchNumber:   currentBlock.NumberU64(),
		truthfulGates: 0,
		forkHeader:    forkedBlock.Header(),
	}
	beforeRound, beforeLockQC, beforeHighQC, beforeHighTC, beforeVotedRound, beforeCommitBlock := engineV2.GetPropertiesFaker()
	err := engineV2.ProposedBlockHandler(chain, currentBlock.Header())
	assert.Nil(t, err)

	// The block was reorged away before processQC, so no engine state may move:
	// no QC processed, nothing locked, nothing committed, no round advance.
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

	// truthfulGates is 0, so every read of the watched height sees the fork.
}

// TestProposedBlockHandlerDropsVoteForReorgedBlock covers the re-check before
// sendVote: processQC legitimately runs on a block that was canonical when it
// read the chain, and only the vote must be dropped when the height is taken
// over in between.
func TestProposedBlockHandlerDropsVoteForReorgedBlock(t *testing.T) {
	var numOfForks = new(int)
	*numOfForks = 1
	// Height 906, not 901: block 901's QC certifies 900 at round 0, which the
	// engine already holds, so processQC would be a no-op. Block 906's QC
	// certifies 905 at round 5, so the state anchor can observe the advance.
	blockchain, _, currentBlock, _, _, forkedBlock := PrepareXDCTestBlockChainForV2Engine(t, 906, params.TestXDPoSMockChainConfig, &ForkedBlockOptions{numOfForkedBlocks: numOfForks})
	engineV2 := blockchain.Engine().(*XDPoS.XDPoS).EngineV2

	// Precondition: the fork sits at the same height but is not canonical.
	assert.NotNil(t, blockchain.GetBlockByHash(forkedBlock.Hash()))
	assert.Equal(t, forkedBlock.NumberU64(), currentBlock.NumberU64())
	assert.NotEqual(t, forkedBlock.Hash(), blockchain.GetCanonicalHash(forkedBlock.NumberU64()))

	// One truthful gate: every read after the pre-processQC re-check sees the
	// reorg.
	chain := &reorgingChainReader{
		t:             t,
		ChainReader:   blockchain,
		watchNumber:   currentBlock.NumberU64(),
		truthfulGates: 1,
		forkHeader:    forkedBlock.Header(),
	}
	beforeRound, _, beforeHighQC, _, _, _ := engineV2.GetPropertiesFaker()
	skippedBefore := skippedProposedBlockCount(t)
	err := engineV2.ProposedBlockHandler(chain, currentBlock.Header())
	assert.Nil(t, err)
	assert.Equal(t, skippedBefore+1, skippedProposedBlockCount(t), "the pre-vote drop must increment consensus/skipped-proposed-block")

	// processQC runs between the gates, so the state must have moved: only a
	// genuine pre-vote reorg drops the vote after it. Its writes stay correct —
	// block 906's QC certifies parent 905, which holds even after 906 is
	// reorged away.
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

// TestProposedBlockHandlerSkipsBlockWithoutBody covers the storage half: the
// fast sync header phase marks a height canonical before its body lands, so a
// canonical header without a body must not reach processQC or the vote path,
// and must leave the engine state untouched.
func TestProposedBlockHandlerSkipsBlockWithoutBody(t *testing.T) {
	blockchain, _, currentBlock, signer, signFn, _ := PrepareXDCTestBlockChainForV2Engine(t, 906, params.TestXDPoSMockChainConfig, nil)
	engineV2 := blockchain.Engine().(*XDPoS.XDPoS).EngineV2

	// Insert block 907's header only, the way the fast sync header phase does:
	// the height becomes canonical before any body exists.
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

	// No QC processed, nothing voted, no round advanced.
	after, afterLockQC, afterHighQC, afterHighTC, afterVotedRound, afterCommitBlock := engineV2.GetPropertiesFaker()
	assert.Equal(t, before, after)
	assert.Equal(t, beforeLockQC, afterLockQC)
	assert.Equal(t, beforeHighQC, afterHighQC)
	assert.Equal(t, beforeHighTC, afterHighTC)
	assert.Equal(t, beforeVotedRound, afterVotedRound)
	assert.Equal(t, beforeCommitBlock, afterCommitBlock)
}

// lockedBuffer is a bytes.Buffer safe for concurrent use: the engine's
// background goroutines (the round countdown) log through the global logger
// while the test reads the captured output.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func (b *lockedBuffer) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf.Reset()
}

// TestProposedBlockHandlerGradesSkipLogLevelByReason pins the grading: reorg
// races Warn, while the routine body-not-stored skip stays at Info so it cannot
// drown the level reserved for anomalies.
func TestProposedBlockHandlerGradesSkipLogLevelByReason(t *testing.T) {
	var numOfForks = new(int)
	*numOfForks = 1
	blockchain, _, currentBlock, signer, signFn, forkedBlock := PrepareXDCTestBlockChainForV2Engine(t, 906, params.TestXDPoSMockChainConfig, &ForkedBlockOptions{numOfForkedBlocks: numOfForks})
	engineV2 := blockchain.Engine().(*XDPoS.XDPoS).EngineV2

	// Capture the handler's own skip logs, so background logs cannot interfere.
	logBuf := new(lockedBuffer)
	prevLog := log.Root()
	glog := log.NewGlogHandler(log.NewTerminalHandlerWithLevel(logBuf, log.LevelInfo, false))
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
	assert.Equal(t, "WARN", levelOf("skip block before processQC"),
		"a non-canonical skip is a reorg race and must stay at Warn, have %q", logBuf.String())

	// An absent canonical height is a reorg race too, so it stays at Warn: reuse
	// the fork header's extra data at an unoccupied height.
	noCanonical := *forkedBlock.Header()
	noCanonical.Number = big.NewInt(99999)
	logBuf.Reset()
	err = engineV2.ProposedBlockHandler(blockchain, &noCanonical)
	assert.Nil(t, err)
	assert.Equal(t, "WARN", levelOf("skip block before processQC"),
		"a no-canonical-header skip is a reorg race and must stay at Warn, have %q", logBuf.String())

	// A canonical header without a body is the one routine skip, so it stays at
	// Info: build it the way the fast sync header phase does.
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
	assert.Equal(t, "INFO", levelOf("skip block before processQC"),
		"a body-not-stored skip is routine fast-sync state and must stay at Info, have %q", logBuf.String())
}

// chainReaderOnly hides the BlockStorer half, the shape a wrapped or replaced
// chain type presents to the handler.
type chainReaderOnly struct {
	consensus.ChainReader
}

// TestProposedBlockHandlerSkipsUnjudgeableChain pins "unjudgeable is a skip,
// not a failure": the type hides BlockStorer, so the judgment skips at Error
// and returns nil — never an error, which the fetcher would read as an import
// failure.
func TestProposedBlockHandlerSkipsUnjudgeableChain(t *testing.T) {
	blockchain, _, currentBlock, _, _, _ := PrepareXDCTestBlockChainForV2Engine(t, 901, params.TestXDPoSMockChainConfig, nil)
	engineV2 := blockchain.Engine().(*XDPoS.XDPoS).EngineV2

	// The unjudgeable skip must surface at Error: a liveness halt, not a race.
	logBuf := new(lockedBuffer)
	prevLog := log.Root()
	glog := log.NewGlogHandler(log.NewTerminalHandlerWithLevel(logBuf, log.LevelInfo, false))
	glog.Verbosity(log.LevelInfo)
	log.SetDefault(log.NewLogger(glog))
	defer log.SetDefault(prevLog)
	err := engineV2.ProposedBlockHandler(chainReaderOnly{blockchain}, currentBlock.Header())
	assert.Nil(t, err, "an unjudgeable chain must not surface an error to the caller")

	// The skip must surface at Error and never reach processQC or the vote path.
	found := false
	for _, line := range strings.Split(logBuf.String(), "\n") {
		if strings.Contains(line, "skip block before processQC") {
			assert.True(t, strings.HasPrefix(line, "ERROR"), "unjudgeable skip must log at Error, got line %q", line)
			assert.Contains(t, line, "unjudgeable", "unjudgeable skip must carry the reason, got line %q", line)
			found = true
			break
		}
	}
	assert.True(t, found, "unjudgeable skip line not found in logs: %q", logBuf.String())

	select {
	case vote := <-engineV2.BroadcastCh:
		t.Fatalf("unjudgeable chain must not drive the vote path, got %v", vote)
	case <-time.After(2 * time.Second):
	}
}

// skippedProposedBlockCount reads the engine gates' counter from the registry.
// Counts are compared before and after a call, so no case here may run in
// parallel.
func skippedProposedBlockCount(t *testing.T) int64 {
	t.Helper()
	counter, ok := metrics.Get("consensus/skipped-proposed-block").(*metrics.Counter)
	if !ok {
		t.Fatal("consensus/skipped-proposed-block is not registered in the metrics registry")
	}
	return counter.Snapshot().Count()
}

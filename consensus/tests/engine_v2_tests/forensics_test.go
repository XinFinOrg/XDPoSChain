package engine_v2_tests

import (
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/XinFinOrg/XDPoSChain/accounts"
	"github.com/XinFinOrg/XDPoSChain/accounts/abi/bind/backends"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS/utils"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/stretchr/testify/assert"
)

func TestProcessQcShallSetForensicsCommittedQc(t *testing.T) {
	blockchain, _, currentBlock, signer, signFn, _ := PrepareXDCTestBlockChainForV2Engine(t, 905, params.TestXDPoSMockChainConfig, nil)
	engineV2 := blockchain.Engine().(*XDPoS.XDPoS).EngineV2

	// Assuming we are getting block 906 which have QC pointing at block 905
	blockInfo := &types.BlockInfo{
		Hash:   currentBlock.Hash(),
		Round:  types.Round(5),
		Number: big.NewInt(905),
	}
	voteForSign := &types.VoteForSign{
		ProposedBlockInfo: blockInfo,
		GapNumber:         450,
	}
	voteSigningHash := types.VoteSigHash(voteForSign)

	// Set round to 5
	engineV2.SetNewRoundFaker(blockchain, types.Round(5), false)
	// Create three vote messages which will not reach vote pool threshold
	signedHash, err := signFn(accounts.Account{Address: signer}, voteSigningHash.Bytes())
	assert.Nil(t, err)
	voteMsg := &types.Vote{
		ProposedBlockInfo: blockInfo,
		Signature:         signedHash,
		GapNumber:         450,
	}
	err = engineV2.VoteHandler(blockchain, voteMsg)
	assert.Nil(t, err)

	signedHash = SignHashByPK(acc1Key, voteSigningHash.Bytes())
	voteMsg = &types.Vote{
		ProposedBlockInfo: blockInfo,
		Signature:         signedHash,
		GapNumber:         450,
	}
	err = engineV2.VoteHandler(blockchain, voteMsg)
	assert.Nil(t, err)

	signedHash = SignHashByPK(acc2Key, voteSigningHash.Bytes())
	voteMsg = &types.Vote{
		ProposedBlockInfo: blockInfo,
		Signature:         signedHash,
		GapNumber:         450,
	}
	err = engineV2.VoteHandler(blockchain, voteMsg)
	assert.Nil(t, err)

	// Create another vote which is signed by someone not from the master node list
	randomSigner, randomSignFn, err := backends.SimulateWalletAddressAndSignFn()
	assert.Nil(t, err)
	randomlySignedHash, err := randomSignFn(accounts.Account{Address: randomSigner}, voteSigningHash.Bytes())
	assert.Nil(t, err)
	voteMsg = &types.Vote{
		ProposedBlockInfo: blockInfo,
		Signature:         randomlySignedHash,
		GapNumber:         450,
	}
	err = engineV2.VoteHandler(blockchain, voteMsg)
	assert.Nil(t, err)

	// Create a vote message that should trigger vote pool hook and increment the round to 6
	signedHash = SignHashByPK(acc3Key, voteSigningHash.Bytes())
	voteMsg = &types.Vote{
		ProposedBlockInfo: blockInfo,
		Signature:         signedHash,
		GapNumber:         450,
	}

	err = engineV2.VoteHandler(blockchain, voteMsg)
	assert.Nil(t, err)

	time.Sleep(5000 * time.Millisecond)
	assert.Equal(t, 3, len(engineV2.GetForensicsFaker().GetCommittedQCs()))
}

func TestSetCommittedQCsInOrder(t *testing.T) {
	blockchain, _, currentBlock, _, _, _ := PrepareXDCTestBlockChainForV2Engine(t, 905, params.TestXDPoSMockChainConfig, nil)
	forensics := blockchain.Engine().(*XDPoS.XDPoS).EngineV2.GetForensicsFaker()

	var headers []types.Header
	var decodedExtraField types.ExtraFields_v2
	// Decode the qc1 and qc2
	err := utils.DecodeBytesExtraFields(currentBlock.Header().Extra, &decodedExtraField)
	assert.Nil(t, err)
	err = forensics.SetCommittedQCs(append(headers, *blockchain.GetHeaderByNumber(903), *blockchain.GetHeaderByNumber(902)), *decodedExtraField.QuorumCert)
	assert.NotNil(t, err)
	assert.Equal(t, "headers shall be on the same chain and in the right order", err.Error())

	err = forensics.SetCommittedQCs(append(headers, *blockchain.GetHeaderByNumber(903), *blockchain.GetHeaderByNumber(904)), *decodedExtraField.QuorumCert)
	assert.Nil(t, err)
	assert.Equal(t, 3, len(forensics.GetCommittedQCs()))

	// Test previous blocks
	err = utils.DecodeBytesExtraFields(blockchain.GetHeaderByNumber(904).Extra, &decodedExtraField)
	assert.Nil(t, err)
	err = forensics.SetCommittedQCs(append(headers, *blockchain.GetHeaderByNumber(902), *blockchain.GetHeaderByNumber(903)), *decodedExtraField.QuorumCert)
	assert.Nil(t, err)
	assert.Equal(t, 3, len(forensics.GetCommittedQCs()))
}

// TestSetCommittedQCsConcurrent records from several goroutines at once, the
// way commitBlocks does: the race detector is the assertion.
func TestSetCommittedQCsConcurrent(t *testing.T) {
	blockchain, _, currentBlock, _, _, _ := PrepareXDCTestBlockChainForV2Engine(t, 905, params.TestXDPoSMockChainConfig, nil)
	forensics := blockchain.Engine().(*XDPoS.XDPoS).EngineV2.GetForensicsFaker()

	var decodedExtraField types.ExtraFields_v2
	err := utils.DecodeBytesExtraFields(currentBlock.Header().Extra, &decodedExtraField)
	assert.Nil(t, err)
	headers := []types.Header{*blockchain.GetHeaderByNumber(903), *blockchain.GetHeaderByNumber(904)}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				if err := forensics.SetCommittedQCs(headers, *decodedExtraField.QuorumCert); err != nil {
					t.Errorf("SetCommittedQCs failed: %v", err)
					return
				}
				if got := len(forensics.GetCommittedQCs()); got != 3 {
					t.Errorf("GetCommittedQCs returned %d QCs, want 3", got)
					return
				}
			}
		}()
	}
	wg.Wait()
	assert.Equal(t, 3, len(forensics.GetCommittedQCs()))
}

// Happty path
func TestForensicsMonitoring(t *testing.T) {
	blockchain, _, currentBlock, _, _, _ := PrepareXDCTestBlockChainForV2Engine(t, 915, params.TestXDPoSMockChainConfig, nil)
	forensics := blockchain.Engine().(*XDPoS.XDPoS).EngineV2.GetForensicsFaker()
	var decodedCurrentblockExtraField types.ExtraFields_v2
	// Decode the QC from latest block
	err := utils.DecodeBytesExtraFields(currentBlock.Header().Extra, &decodedCurrentblockExtraField)
	assert.Nil(t, err)
	incomingQC := decodedCurrentblockExtraField.QuorumCert
	// Now, let's try set committed blocks, where the highestedCommitted blocks are 905, 906 and 907
	var headers []types.Header
	var decodedBlock905ExtraField types.ExtraFields_v2
	err = utils.DecodeBytesExtraFields(blockchain.GetHeaderByNumber(905).Extra, &decodedBlock905ExtraField)
	assert.Nil(t, err)

	err = forensics.SetCommittedQCs(append(headers, *blockchain.GetHeaderByNumber(903), *blockchain.GetHeaderByNumber(904)), *decodedBlock905ExtraField.QuorumCert)
	assert.Nil(t, err)
	var newIncomingQcHeaders []types.Header
	newIncomingQcHeaders = append(newIncomingQcHeaders, *blockchain.GetHeaderByNumber(913), *blockchain.GetHeaderByNumber(914))
	err = forensics.ForensicsMonitoring(blockchain, blockchain.Engine().(*XDPoS.XDPoS).EngineV2, newIncomingQcHeaders, *incomingQC)
	assert.Nil(t, err)
}

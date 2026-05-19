package engine_v2_tests

import (
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/accounts"
	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS/utils"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/stretchr/testify/assert"
)

// TestVoteQCGeneration_DeduplicatesByzantineSigner verifies that when the vote
// pool contains two pool entries from the same signer (the byzantine
// amplification scenario described in the refactor), QC generation succeeds
// and the resulting QC contains exactly one signature per unique signer.
//
// In production the pool keys by vote-hash so byte-identical votes naturally
// dedupe; this test simulates an attacker using non-deterministic signing by
// inserting two pool entries that resolve to the same signer.
func TestVoteQCGeneration_DeduplicatesByzantineSigner(t *testing.T) {
	blockchain, _, currentBlock, signer, signFn, _ := PrepareXDCTestBlockChainForV2Engine(t, 901, params.TestXDPoSMockChainConfig, nil)
	engineV2 := blockchain.Engine().(*XDPoS.XDPoS).EngineV2

	blockInfo := &types.BlockInfo{
		Hash:   currentBlock.Hash(),
		Round:  types.Round(1),
		Number: big.NewInt(901),
	}
	voteForSign := &types.VoteForSign{ProposedBlockInfo: blockInfo, GapNumber: 450}
	voteSigningHash := types.VoteSigHash(voteForSign)

	engineV2.SetNewRoundFaker(blockchain, types.Round(1), false)

	sigSigner, err := signFn(accounts.Account{Address: signer}, voteSigningHash.Bytes())
	assert.Nil(t, err)
	sigAcc1 := SignHashByPK(acc1Key, voteSigningHash.Bytes())
	sigAcc2 := SignHashByPK(acc2Key, voteSigningHash.Bytes())
	sigAcc3 := SignHashByPK(acc3Key, voteSigningHash.Bytes())

	build := func(sig types.Signature, addr common.Address) *types.Vote {
		v := &types.Vote{ProposedBlockInfo: blockInfo, Signature: sig, GapNumber: 450}
		v.SetSigner(addr)
		return v
	}

	pooledVotes := map[common.Hash]utils.PoolObj{
		common.HexToHash("0x01"): build(sigSigner, signer),
		common.HexToHash("0x02"): build(sigAcc1, acc1Addr),
		common.HexToHash("0x03"): build(sigAcc2, acc2Addr),
		common.HexToHash("0x04"): build(sigAcc3, acc3Addr),
		// duplicate of acc1 — different map key but same signer/sig
		common.HexToHash("0x05"): build(sigAcc1, acc1Addr),
	}

	currentVoteMsg := build(sigAcc3, acc3Addr)
	proposedHeader := blockchain.GetHeaderByHash(currentBlock.Hash())

	err = engineV2.OnVotePoolThresholdReachedFaker(blockchain, pooledVotes, currentVoteMsg, proposedHeader)
	assert.Nil(t, err, "QC generation should succeed despite duplicate")

	_, _, highestQC, _, _, _ := engineV2.GetPropertiesFaker()
	assert.Equal(t, types.Round(1), highestQC.ProposedBlockInfo.Round, "QC should be set for round 1")
	assert.Len(t, highestQC.Signatures, 4, "QC should contain exactly 4 signatures, duplicate dropped")

	// Each surviving signature must come from a distinct masternode.
	expectedSigs := []types.Signature{sigSigner, sigAcc1, sigAcc2, sigAcc3}
	assert.ElementsMatch(t, expectedSigs, highestQC.Signatures)
}

// TestVoteQCGeneration_BelowThresholdAfterDedupSkipsQC verifies that when
// duplicates inflate the pool past threshold but the unique-signer count
// after dedup is below threshold, no QC is generated. This is the byzantine
// "trip threshold with padding" scenario the new dedup defends against.
func TestVoteQCGeneration_BelowThresholdAfterDedupSkipsQC(t *testing.T) {
	blockchain, _, currentBlock, signer, signFn, _ := PrepareXDCTestBlockChainForV2Engine(t, 901, params.TestXDPoSMockChainConfig, nil)
	engineV2 := blockchain.Engine().(*XDPoS.XDPoS).EngineV2

	blockInfo := &types.BlockInfo{Hash: currentBlock.Hash(), Round: types.Round(1), Number: big.NewInt(901)}
	voteSigningHash := types.VoteSigHash(&types.VoteForSign{ProposedBlockInfo: blockInfo, GapNumber: 450})

	engineV2.SetNewRoundFaker(blockchain, types.Round(1), false)

	sigSigner, err := signFn(accounts.Account{Address: signer}, voteSigningHash.Bytes())
	assert.Nil(t, err)
	sigAcc1 := SignHashByPK(acc1Key, voteSigningHash.Bytes())

	build := func(sig types.Signature, addr common.Address) *types.Vote {
		v := &types.Vote{ProposedBlockInfo: blockInfo, Signature: sig, GapNumber: 450}
		v.SetSigner(addr)
		return v
	}

	// Pool has 4 entries (enough to trip threshold by raw count), but only 2
	// unique signers — below the 4-of-4 threshold for this test config.
	pooledVotes := map[common.Hash]utils.PoolObj{
		common.HexToHash("0x01"): build(sigSigner, signer),
		common.HexToHash("0x02"): build(sigAcc1, acc1Addr),
		common.HexToHash("0x03"): build(sigAcc1, acc1Addr), // dup
		common.HexToHash("0x04"): build(sigAcc1, acc1Addr), // dup
	}

	currentVoteMsg := build(sigAcc1, acc1Addr)
	proposedHeader := blockchain.GetHeaderByHash(currentBlock.Hash())

	err = engineV2.OnVotePoolThresholdReachedFaker(blockchain, pooledVotes, currentVoteMsg, proposedHeader)
	assert.Nil(t, err, "no error returned even when threshold is missed")

	_, _, highestQC, _, _, _ := engineV2.GetPropertiesFaker()
	assert.Equal(t, types.Round(0), highestQC.ProposedBlockInfo.Round, "no QC should be generated; highestQC stays at default")
}

// TestTCGeneration_DeduplicatesByzantineSigner is the timeout-side mirror:
// duplicates in the timeout pool from the same signer must be dropped, and
// the resulting TC must contain only one signature per unique signer.
func TestTCGeneration_DeduplicatesByzantineSigner(t *testing.T) {
	blockchain, _, _, signer, signFn, _ := PrepareXDCTestBlockChainForV2Engine(t, 905, params.TestXDPoSMockChainConfig, nil)
	engineV2 := blockchain.Engine().(*XDPoS.XDPoS).EngineV2

	engineV2.SetNewRoundFaker(blockchain, types.Round(5), false)

	timeoutSigningHash := types.TimeoutSigHash(&types.TimeoutForSign{
		Round:     types.Round(5),
		GapNumber: 450,
	})

	sigSigner, err := signFn(accounts.Account{Address: signer}, timeoutSigningHash.Bytes())
	assert.Nil(t, err)
	sigAcc1 := SignHashByPK(acc1Key, timeoutSigningHash.Bytes())
	sigAcc2 := SignHashByPK(acc2Key, timeoutSigningHash.Bytes())
	sigAcc3 := SignHashByPK(acc3Key, timeoutSigningHash.Bytes())

	build := func(sig types.Signature, addr common.Address) *types.Timeout {
		t := &types.Timeout{Round: types.Round(5), Signature: sig, GapNumber: 450}
		t.SetSigner(addr)
		return t
	}

	pooledTimeouts := map[common.Hash]utils.PoolObj{
		common.HexToHash("0x01"): build(sigSigner, signer),
		common.HexToHash("0x02"): build(sigAcc1, acc1Addr),
		common.HexToHash("0x03"): build(sigAcc2, acc2Addr),
		common.HexToHash("0x04"): build(sigAcc3, acc3Addr),
		// duplicate of acc1
		common.HexToHash("0x05"): build(sigAcc1, acc1Addr),
	}

	currentTimeoutMsg := build(sigAcc3, acc3Addr)

	err = engineV2.OnTimeoutPoolThresholdReachedFaker(blockchain, pooledTimeouts, currentTimeoutMsg, 450)
	assert.Nil(t, err, "TC generation should succeed despite duplicate")

	_, _, _, highestTC, _, _ := engineV2.GetPropertiesFaker()
	assert.NotNil(t, highestTC)
	assert.Equal(t, types.Round(5), highestTC.Round)
	assert.Equal(t, uint64(450), highestTC.GapNumber)
	assert.Len(t, highestTC.Signatures, 4, "TC should contain exactly 4 signatures, duplicate dropped")

	expectedSigs := []types.Signature{sigSigner, sigAcc1, sigAcc2, sigAcc3}
	assert.ElementsMatch(t, expectedSigs, highestTC.Signatures)
}

// TestTCGeneration_BelowThresholdAfterDedupSkipsTC: timeout-side analogue —
// pool tripped only by duplicates, unique signer count below threshold,
// so no TC should be produced.
func TestTCGeneration_BelowThresholdAfterDedupSkipsTC(t *testing.T) {
	blockchain, _, _, signer, signFn, _ := PrepareXDCTestBlockChainForV2Engine(t, 905, params.TestXDPoSMockChainConfig, nil)
	engineV2 := blockchain.Engine().(*XDPoS.XDPoS).EngineV2

	engineV2.SetNewRoundFaker(blockchain, types.Round(5), false)

	timeoutSigningHash := types.TimeoutSigHash(&types.TimeoutForSign{
		Round:     types.Round(5),
		GapNumber: 450,
	})

	sigSigner, err := signFn(accounts.Account{Address: signer}, timeoutSigningHash.Bytes())
	assert.Nil(t, err)
	sigAcc1 := SignHashByPK(acc1Key, timeoutSigningHash.Bytes())

	build := func(sig types.Signature, addr common.Address) *types.Timeout {
		t := &types.Timeout{Round: types.Round(5), Signature: sig, GapNumber: 450}
		t.SetSigner(addr)
		return t
	}

	pooledTimeouts := map[common.Hash]utils.PoolObj{
		common.HexToHash("0x01"): build(sigSigner, signer),
		common.HexToHash("0x02"): build(sigAcc1, acc1Addr),
		common.HexToHash("0x03"): build(sigAcc1, acc1Addr),
		common.HexToHash("0x04"): build(sigAcc1, acc1Addr),
	}

	currentTimeoutMsg := build(sigAcc1, acc1Addr)

	err = engineV2.OnTimeoutPoolThresholdReachedFaker(blockchain, pooledTimeouts, currentTimeoutMsg, 450)
	assert.Nil(t, err, "no error when threshold missed after dedup")

	_, _, _, highestTC, _, _ := engineV2.GetPropertiesFaker()
	// highestTC starts as a default zero value (Round 0); no TC should be set.
	if highestTC != nil {
		assert.Equal(t, types.Round(0), highestTC.Round, "no TC should be generated; default highestTC remains")
	}
}

package engine_v2_tests

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS/utils"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/eth/bft"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/stretchr/testify/assert"
)

func TestSyncInfoShouldSuccessfullyUpdateByQC(t *testing.T) {
	t.Parallel()
	// Block 901 is the first v2 block with starting round of 0
	blockchain, _, currentBlock, _, _, _ := PrepareXDCTestBlockChainForV2Engine(t, 905, params.TestXDPoSMockChainConfig, nil)
	engineV2 := blockchain.Engine().(*XDPoS.XDPoS).EngineV2

	var extraField types.ExtraFields_v2
	err := utils.DecodeBytesExtraFields(currentBlock.Extra(), &extraField)
	if err != nil {
		t.Fatal("Fail to decode extra data", err)
	}

	syncInfoMsg := &types.SyncInfo{
		HighestQuorumCert: extraField.QuorumCert,
		HighestTimeoutCert: &types.TimeoutCert{
			Round:      types.Round(2),
			Signatures: []types.Signature{},
		},
	}

	// The certificate is fabricated (a round, no signatures), so the handler
	// reports it; the QC in the same message must still be processed.
	err = engineV2.SyncInfoHandler(blockchain, syncInfoMsg)
	assert.Error(t, err)
	round, _, highestQuorumCert, _, _, highestCommitBlock := engineV2.GetPropertiesFaker()
	// QC is parent block's qc, which is pointing at round 4, hence 4 + 1 = 5
	assert.Equal(t, types.Round(5), round)
	assert.Equal(t, extraField.QuorumCert, highestQuorumCert)
	assert.Equal(t, types.Round(2), highestCommitBlock.Round)
	assert.Equal(t, big.NewInt(902), highestCommitBlock.Number)
}

func TestSyncInfoShouldSuccessfullyUpdateByTC(t *testing.T) {
	t.Parallel()
	// Block 901 is the first v2 block with starting round of 0
	blockchain, _, currentBlock, _, _, _ := PrepareXDCTestBlockChainForV2Engine(t, 905, params.TestXDPoSMockChainConfig, nil)
	engineV2 := blockchain.Engine().(*XDPoS.XDPoS).EngineV2

	var extraField types.ExtraFields_v2
	err := utils.DecodeBytesExtraFields(currentBlock.Extra(), &extraField)
	if err != nil {
		t.Fatal("Fail to decode extra data", err)
	}

	// SyncInfoHandler only adopts a certificate it can verify, so sign this one
	// with the epoch's masternodes like an honest TC.
	timeoutForSign := &types.TimeoutForSign{
		Round:     types.Round(900),
		GapNumber: 450,
	}
	highestTC := &types.TimeoutCert{
		Round: timeoutForSign.Round,
		Signatures: []types.Signature{
			SignHashByPK(acc1Key, types.TimeoutSigHash(timeoutForSign).Bytes()),
			SignHashByPK(acc2Key, types.TimeoutSigHash(timeoutForSign).Bytes()),
			SignHashByPK(acc3Key, types.TimeoutSigHash(timeoutForSign).Bytes()),
			SignHashByPK(voterKey, types.TimeoutSigHash(timeoutForSign).Bytes()),
		},
		GapNumber: timeoutForSign.GapNumber,
	}

	syncInfoMsg := &types.SyncInfo{
		HighestQuorumCert:  extraField.QuorumCert,
		HighestTimeoutCert: highestTC,
	}

	err = engineV2.SyncInfoHandler(blockchain, syncInfoMsg)
	if err != nil {
		t.Fatal(err)
	}
	round, _, highestQuorumCert, _, _, _ := engineV2.GetPropertiesFaker()
	assert.Equal(t, types.Round(901), round)
	assert.Equal(t, extraField.QuorumCert, highestQuorumCert)
}

func TestSkipVerifySyncInfoIfBothQcTcNotQualified(t *testing.T) {
	t.Parallel()
	blockchain, _, _, _, _, _ := PrepareXDCTestBlockChainForV2Engine(t, 905, params.TestXDPoSMockChainConfig, nil)
	engineV2 := blockchain.Engine().(*XDPoS.XDPoS).EngineV2

	// Make the Highest QC in syncInfo point to an old block to simulate it's no longer qualified
	parentBlock := blockchain.GetBlockByNumber(903)
	var extraField types.ExtraFields_v2
	err := utils.DecodeBytesExtraFields(parentBlock.Extra(), &extraField)
	if err != nil {
		t.Fatal("Fail to decode extra data", err)
	}

	highestTC := &types.TimeoutCert{
		Round:      types.Round(5),
		Signatures: []types.Signature{},
	}

	syncInfoMsg := &types.SyncInfo{
		HighestQuorumCert:  extraField.QuorumCert,
		HighestTimeoutCert: highestTC,
	}

	engineV2.SetPropertiesFaker(syncInfoMsg.HighestQuorumCert, syncInfoMsg.HighestTimeoutCert)

	verified, err := engineV2.VerifySyncInfoMessage(blockchain, syncInfoMsg)
	assert.False(t, verified)
	assert.Nil(t, err)
}

// A node that has never formed a TC holds the bootstrap TC (round 0, no signatures) and
// puts it into every syncInfo it sends. The QC in such a message is the only way for a
// node that missed a QC to catch up, so the placeholder TC must not invalidate it.
func TestVerifySyncInfoWithNewerQCAndBootstrapTC(t *testing.T) {
	t.Parallel()
	blockchain, _, currentBlock, _, _, _ := PrepareXDCTestBlockChainForV2Engine(t, 905, params.TestXDPoSMockChainConfig, nil)
	engineV2 := blockchain.Engine().(*XDPoS.XDPoS).EngineV2

	// The incoming syncInfo carries the newer QC, taken from the chain head.
	var incoming types.ExtraFields_v2
	if err := utils.DecodeBytesExtraFields(currentBlock.Extra(), &incoming); err != nil {
		t.Fatal("Fail to decode extra data", err)
	}

	// Our node sits on an older QC and has never seen a TC, exactly like a node whose
	// votes fell short of the threshold at network start.
	var older types.ExtraFields_v2
	if err := utils.DecodeBytesExtraFields(blockchain.GetBlockByNumber(903).Extra(), &older); err != nil {
		t.Fatal("Fail to decode extra data", err)
	}
	bootstrapTC := &types.TimeoutCert{
		Round:      types.Round(0),
		Signatures: []types.Signature{},
	}
	engineV2.SetPropertiesFaker(older.QuorumCert, bootstrapTC)

	syncInfoMsg := &types.SyncInfo{
		HighestQuorumCert:  incoming.QuorumCert,
		HighestTimeoutCert: bootstrapTC,
	}

	verified, err := engineV2.VerifySyncInfoMessage(blockchain, syncInfoMsg)
	assert.Nil(t, err, "the bootstrap TC must not invalidate a syncInfo whose QC is newer and valid")
	assert.True(t, verified)
}

// The exemption is deliberately narrow: it covers only the empty placeholder, and any TC
// that actually carries signatures is still put through verifyTC in full. This pins that
// boundary, so the exemption cannot be widened by sending a TC with a bogus signature set.
//
// The trade-off it also documents: a TC that would never be processed anyway - here one
// staler than the one we hold - still invalidates the whole message, discarding a QC we do
// need. Verifying only the certificate that is ahead of ours would avoid that, at the cost
// of a broader change to the syncInfo path.
func TestVerifySyncInfoStillVerifiesNonEmptyTC(t *testing.T) {
	t.Parallel()
	blockchain, _, currentBlock, _, _, _ := PrepareXDCTestBlockChainForV2Engine(t, 905, params.TestXDPoSMockChainConfig, nil)
	engineV2 := blockchain.Engine().(*XDPoS.XDPoS).EngineV2

	var incoming types.ExtraFields_v2
	if err := utils.DecodeBytesExtraFields(currentBlock.Extra(), &incoming); err != nil {
		t.Fatal("Fail to decode extra data", err)
	}
	var older types.ExtraFields_v2
	if err := utils.DecodeBytesExtraFields(blockchain.GetBlockByNumber(903).Extra(), &older); err != nil {
		t.Fatal("Fail to decode extra data", err)
	}

	// We already hold a newer TC than the one being sent to us.
	ourTC := &types.TimeoutCert{
		Round:      types.Round(5),
		Signatures: []types.Signature{},
	}
	engineV2.SetPropertiesFaker(older.QuorumCert, ourTC)

	// Their TC carries a signature, so it is not the placeholder and gets verified: round 1
	// with gap number 0, which has no snapshot here, so verification fails.
	staleTC := &types.TimeoutCert{
		Round:      types.Round(1),
		Signatures: []types.Signature{SignHashByPK(acc1Key, types.TimeoutSigHash(&types.TimeoutForSign{Round: types.Round(1), GapNumber: 0}).Bytes())},
		GapNumber:  0,
	}

	syncInfoMsg := &types.SyncInfo{
		HighestQuorumCert:  incoming.QuorumCert,
		HighestTimeoutCert: staleTC,
	}

	verified, err := engineV2.VerifySyncInfoMessage(blockchain, syncInfoMsg)
	assert.NotNil(t, err, "a TC carrying signatures must still be verified, not exempted")
	assert.False(t, verified)
}

func TestVerifySyncInfoIfTCRoundIsAtNextEpoch(t *testing.T) {
	t.Parallel()
	blockchain, _, _, _, _, _ := PrepareXDCTestBlockChainForV2Engine(t, 905, params.TestXDPoSMockChainConfig, nil)
	engineV2 := blockchain.Engine().(*XDPoS.XDPoS).EngineV2

	// Make the Highest QC in syncInfo point to an old block to simulate it's no longer qualified
	parentBlock := blockchain.GetBlockByNumber(903)
	var extraField types.ExtraFields_v2
	err := utils.DecodeBytesExtraFields(parentBlock.Extra(), &extraField)
	if err != nil {
		t.Fatal("Fail to decode extra data", err)
	}

	highestTC := &types.TimeoutCert{
		Round:      types.Round(899),
		Signatures: []types.Signature{},
	}

	timeoutForSign := &types.TimeoutForSign{
		Round:     types.Round(900),
		GapNumber: 450,
	}

	// Sign from acc 1, 2, 3 and voter
	acc1SignedHash := SignHashByPK(acc1Key, types.TimeoutSigHash(timeoutForSign).Bytes())
	acc2SignedHash := SignHashByPK(acc2Key, types.TimeoutSigHash(timeoutForSign).Bytes())
	acc3SignedHash := SignHashByPK(acc3Key, types.TimeoutSigHash(timeoutForSign).Bytes())
	voterSignedHash := SignHashByPK(voterKey, types.TimeoutSigHash(timeoutForSign).Bytes())

	var signatures []types.Signature
	signatures = append(signatures, acc1SignedHash, acc2SignedHash, acc3SignedHash, voterSignedHash)

	syncInfoTC := &types.TimeoutCert{
		Round:      timeoutForSign.Round,
		Signatures: signatures,
		GapNumber:  timeoutForSign.GapNumber,
	}

	syncInfoMsg := &types.SyncInfo{
		HighestQuorumCert:  extraField.QuorumCert,
		HighestTimeoutCert: syncInfoTC,
	}

	engineV2.SetPropertiesFaker(syncInfoMsg.HighestQuorumCert, highestTC)

	verified, err := engineV2.VerifySyncInfoMessage(blockchain, syncInfoMsg)
	assert.True(t, verified)
	assert.Nil(t, err)
}

func TestVerifySyncInfoIfTcUseDifferentEpoch(t *testing.T) {
	t.Parallel()
	config := params.TestXDPoSMockChainConfig
	blockchain, _, currentBlock, signer, signFn, _ := PrepareXDCTestBlockChainForV2Engine(t, 1349, config, nil)
	adaptor := blockchain.Engine().(*XDPoS.XDPoS)
	x := adaptor.EngineV2

	// Insert block 1350
	t.Logf("Inserting block with propose at 1350...")
	blockCoinbaseA := "0xaaa0000000000000000000000000000000001350"
	// NOTE: voterAddr never exist in the Masternode list, but all acc1,2,3 already does
	tx, err := voteTX(37117, 0, signer.String())
	if err != nil {
		t.Fatal(err)
	}
	//Get from block validator error message
	merkleRoot := "8a355a8636d1aae24d5a63df0318534e09110891d6ab7bf20587da64725083be"
	header := &types.Header{
		Root:       common.HexToHash(merkleRoot),
		Number:     big.NewInt(int64(1350)),
		ParentHash: currentBlock.Hash(),
		Coinbase:   common.HexToAddress(blockCoinbaseA),
	}

	header.Extra = generateV2Extra(450, currentBlock, signer, signFn, nil)

	parentBlock, err := createBlockFromHeader(blockchain, header, []*types.Transaction{tx}, signer, signFn, config)
	assert.Nil(t, err)
	err = blockchain.InsertBlock(parentBlock)
	assert.Nil(t, err)
	t.Logf("Inserting block from 1351 to 1799...")
	for i := 1351; i <= 1799; i++ {
		blockCoinbase := fmt.Sprintf("0xaaa000000000000000000000000000000000%4d", i)
		//Get from block validator error message
		header = &types.Header{
			Root:       common.HexToHash(merkleRoot),
			Number:     big.NewInt(int64(i)),
			ParentHash: parentBlock.Hash(),
			Coinbase:   common.HexToAddress(blockCoinbase),
		}

		header.Extra = generateV2Extra(int64(i)-900, parentBlock, signer, signFn, nil)

		block, err := createBlockFromHeader(blockchain, header, nil, signer, signFn, config)
		if err != nil {
			t.Fatal(err)
		}
		err = blockchain.InsertBlock(block)
		assert.Nil(t, err)
		parentBlock = block
	}
	t.Logf("build epoch block with new set of masternodes")
	blockCoinbase := fmt.Sprintf("0xaaa0000000000000000000000000000000001800")
	//Get from block validator error message
	header = &types.Header{
		Root:       common.HexToHash(merkleRoot),
		Number:     big.NewInt(int64(1800)),
		ParentHash: parentBlock.Hash(),
		Coinbase:   common.HexToAddress(blockCoinbase),
	}

	header.Extra = generateV2Extra(900, parentBlock, signer, signFn, nil)
	validators := []byte{}

	snap, err := x.GetSnapshot(blockchain, parentBlock.Header())
	assert.Nil(t, err)

	for _, v := range snap.NextEpochCandidates {
		validators = append(validators, v[:]...)
	}
	// set up 1 more masternode to make it difference
	validators = append(validators, voterAddr[:]...)
	header.Validators = validators
	block, err := createBlockFromHeader(blockchain, header, nil, signer, signFn, config)
	if err != nil {
		t.Fatal(err)
	}
	err = blockchain.InsertBlock(block)
	assert.Nil(t, err)
	parentBlock = block

	var extraField types.ExtraFields_v2
	err = utils.DecodeBytesExtraFields(parentBlock.Extra(), &extraField)
	if err != nil {
		t.Fatal("Fail to decode extra data", err)
	}

	timeoutForSign := &types.TimeoutForSign{
		Round:     types.Round(899),
		GapNumber: 450,
	}

	// Sign from acc 1, 2, 3 and voter
	acc1SignedHash := SignHashByPK(acc1Key, types.TimeoutSigHash(timeoutForSign).Bytes())
	acc2SignedHash := SignHashByPK(acc2Key, types.TimeoutSigHash(timeoutForSign).Bytes())
	acc3SignedHash := SignHashByPK(acc3Key, types.TimeoutSigHash(timeoutForSign).Bytes())
	voterSignedHash := SignHashByPK(voterKey, types.TimeoutSigHash(timeoutForSign).Bytes())

	var signatures []types.Signature
	signatures = append(signatures, acc1SignedHash, acc2SignedHash, acc3SignedHash, voterSignedHash)

	newTC := &types.TimeoutCert{
		Round:      timeoutForSign.Round,
		Signatures: signatures,
		GapNumber:  timeoutForSign.GapNumber,
	}

	syncInfoMsg := &types.SyncInfo{
		HighestQuorumCert:  extraField.QuorumCert,
		HighestTimeoutCert: newTC,
	}

	x.SetPropertiesFaker(syncInfoMsg.HighestQuorumCert, &types.TimeoutCert{
		Round:      types.Round(898),
		Signatures: []types.Signature{},
	})

	verified, err := x.VerifySyncInfoMessage(blockchain, syncInfoMsg)
	assert.True(t, verified)
	assert.Nil(t, err)
}

// A node keeps its highest TC in memory while its head moves on, and
// OnCountdownTimeout sends that certificate with every timeout-sync SyncInfo.
// Once the head is more than epoch*3 past the certificate's gap block, the
// receiving node must still process the QC in the message: dropping the whole
// message would cost it the QC it needs to catch up. The certificate itself is
// removed from the message, because callers relay the message before the
// handler runs.
func TestVerifySyncInfoProcessesQCWhenTCGapOutOfWindow(t *testing.T) {
	t.Parallel()
	// Head 3255 is 2805 blocks past gap block 450, beyond the 2700 window of
	// the 900/450 test schedule.
	blockchain, _, currentBlock, _, _, _ := PrepareXDCTestBlockChainForV2Engine(t, 3255, params.TestXDPoSMockChainConfig, nil)
	engineV2 := blockchain.Engine().(*XDPoS.XDPoS).EngineV2

	var incoming types.ExtraFields_v2
	if err := utils.DecodeBytesExtraFields(currentBlock.Extra(), &incoming); err != nil {
		t.Fatal("Fail to decode extra data", err)
	}
	var older types.ExtraFields_v2
	if err := utils.DecodeBytesExtraFields(blockchain.GetBlockByNumber(903).Extra(), &older); err != nil {
		t.Fatal("Fail to decode extra data", err)
	}
	engineV2.SetPropertiesFaker(older.QuorumCert, &types.TimeoutCert{})

	// Two variants that differ only in the TC round, the field a peer would
	// forge. SyncInfo.Hash() covers the certificate, so on the wire these are
	// two distinct messages that hash-based deduplication cannot merge.
	variant := func(round types.Round) *types.SyncInfo {
		return &types.SyncInfo{
			HighestQuorumCert:  incoming.QuorumCert,
			HighestTimeoutCert: &types.TimeoutCert{Round: round, Signatures: []types.Signature{{1}}, GapNumber: 450},
		}
	}
	first, second := variant(types.Round(2)), variant(types.Round(3))
	assert.NotEqual(t, first.Hash(), second.Hash(), "the forged variants must be distinct before verification")

	verified, err := engineV2.VerifySyncInfoMessage(blockchain, first)
	assert.Nil(t, err)
	assert.True(t, verified, "an out-of-window TC must not discard the QC in the same syncInfo")

	// The certificate is treated as absent, so the message a caller relays
	// carries the QC only.
	assert.Equal(t, types.Round(0), first.HighestTimeoutCert.Round, "an out-of-window TC must be removed from the message")
	assert.Empty(t, first.HighestTimeoutCert.Signatures)
	assert.Zero(t, first.HighestTimeoutCert.GapNumber)

	verified, err = engineV2.VerifySyncInfoMessage(blockchain, second)
	assert.Nil(t, err)
	assert.True(t, verified)
	assert.Equal(t, first.Hash(), second.Hash(), "removing the certificate must collapse every forged variant to one relay hash")
}

// SyncInfoHandler must still process the QC in a SyncInfo whose certificate is
// outside the window, and must not adopt that certificate.
func TestSyncInfoHandlerSkipsOutOfWindowTC(t *testing.T) {
	t.Parallel()
	blockchain, _, currentBlock, _, _, _ := PrepareXDCTestBlockChainForV2Engine(t, 3255, params.TestXDPoSMockChainConfig, nil)
	engineV2 := blockchain.Engine().(*XDPoS.XDPoS).EngineV2

	var incoming types.ExtraFields_v2
	if err := utils.DecodeBytesExtraFields(currentBlock.Extra(), &incoming); err != nil {
		t.Fatal("Fail to decode extra data", err)
	}
	var older types.ExtraFields_v2
	if err := utils.DecodeBytesExtraFields(blockchain.GetBlockByNumber(903).Extra(), &older); err != nil {
		t.Fatal("Fail to decode extra data", err)
	}
	engineV2.SetPropertiesFaker(older.QuorumCert, &types.TimeoutCert{})

	syncInfoMsg := &types.SyncInfo{
		HighestQuorumCert:  incoming.QuorumCert,
		HighestTimeoutCert: &types.TimeoutCert{Round: types.Round(2), Signatures: []types.Signature{{1}}, GapNumber: 450},
	}

	err := engineV2.SyncInfoHandler(blockchain, syncInfoMsg)
	assert.Nil(t, err)

	_, _, highestQuorumCert, highestTC, _, _ := engineV2.GetPropertiesFaker()
	assert.Equal(t, incoming.QuorumCert, highestQuorumCert, "the QC in the same message must still be processed")
	assert.Equal(t, types.Round(0), highestTC.Round, "an out-of-window TC must not become the highest TC")
}

// VerifySyncInfoMessage never authenticated the certificate it let through, and
// the head can move it back inside the window by the time the handler runs, so
// the handler must verify it before adopting it. Gap block 450 has a snapshot at
// head 1400, so both cases below reach the checks that follow getSnapshot.
func TestSyncInfoHandlerVerifiesTCBeforeAdopting(t *testing.T) {
	t.Parallel()
	blockchain, _, currentBlock, _, _, _ := PrepareXDCTestBlockChainForV2Engine(t, 1400, params.TestXDPoSMockChainConfig, nil)
	engineV2 := blockchain.Engine().(*XDPoS.XDPoS).EngineV2

	var incoming types.ExtraFields_v2
	if err := utils.DecodeBytesExtraFields(currentBlock.Extra(), &incoming); err != nil {
		t.Fatal("Fail to decode extra data", err)
	}
	handler := func(tc *types.TimeoutCert) error {
		return engineV2.SyncInfoHandler(blockchain, &types.SyncInfo{HighestQuorumCert: incoming.QuorumCert, HighestTimeoutCert: tc})
	}
	signedHash := types.TimeoutSigHash(&types.TimeoutForSign{Round: types.Round(2), GapNumber: 450}).Bytes()

	// Signatures that recover cleanly and meet the threshold, but whose signers
	// are outside the masternode set: the certificate must fail the signature
	// check rather than the snapshot lookup.
	t.Run("signature mismatch", func(t *testing.T) {
		var signatures []types.Signature
		for _, key := range []*ecdsa.PrivateKey{protector1Key, protector2Key, observer1Key, observer2Key} {
			signatures = append(signatures, SignHashByPK(key, signedHash))
		}
		err := handler(&types.TimeoutCert{Round: types.Round(2), Signatures: signatures, GapNumber: 450})
		if assert.Error(t, err, "a certificate nobody in the masternode set signed must be reported") {
			assert.Contains(t, err.Error(), "signature mis-match")
		}
		_, _, _, highestTC, _, _ := engineV2.GetPropertiesFaker()
		assert.Equal(t, types.Round(0), highestTC.Round, "an unauthenticated TC must not become the highest TC")
	})

	// One valid masternode signature is below certThreshold (4 of 5 here): the
	// certificate must be refused at the threshold check.
	t.Run("below signature threshold", func(t *testing.T) {
		err := handler(&types.TimeoutCert{Round: types.Round(2), Signatures: []types.Signature{SignHashByPK(acc1Key, signedHash)}, GapNumber: 450})
		assert.ErrorIs(t, err, utils.ErrInvalidTCSignatures)
		_, _, _, highestTC, _, _ := engineV2.GetPropertiesFaker()
		assert.Equal(t, types.Round(0), highestTC.Round)
	})
}

// A restarted node holds the blank certificate (round 0, no signatures) and puts
// it into every SyncInfo. The handler must skip verification for it, or every
// such message would report an error even though its QC was processed.
func TestSyncInfoHandlerSkipsBlankTC(t *testing.T) {
	t.Parallel()
	blockchain, _, currentBlock, _, _, _ := PrepareXDCTestBlockChainForV2Engine(t, 905, params.TestXDPoSMockChainConfig, nil)
	engineV2 := blockchain.Engine().(*XDPoS.XDPoS).EngineV2

	var incoming types.ExtraFields_v2
	if err := utils.DecodeBytesExtraFields(currentBlock.Extra(), &incoming); err != nil {
		t.Fatal("Fail to decode extra data", err)
	}
	syncInfoMsg := &types.SyncInfo{
		HighestQuorumCert:  incoming.QuorumCert,
		HighestTimeoutCert: &types.TimeoutCert{Round: types.Round(0), Signatures: []types.Signature{}},
	}

	err := engineV2.SyncInfoHandler(blockchain, syncInfoMsg)
	assert.Nil(t, err, "the blank TC must not turn a processed QC into an error")

	round, _, highestQuorumCert, highestTC, _, _ := engineV2.GetPropertiesFaker()
	assert.Equal(t, types.Round(5), round)
	assert.Equal(t, incoming.QuorumCert, highestQuorumCert)
	assert.Equal(t, types.Round(0), highestTC.Round)
}

// A node keeps its highest TC in memory while its head moves on, and
// OnCountdownTimeout sends that certificate with every timeout-sync SyncInfo.
// Once the head is more than epoch*3 past the certificate's gap block, the
// receiving node must still process the QC in the message, and the handler must
// keep refusing the certificate at the new head. VerifySyncInfoMessage removes
// such a certificate, so the guard is exercised with it still attached, the
// state a caller that skipped that step would hand over.
func TestSyncInfoHandlerRejectsTCWhenHeadMovesItIntoWindow(t *testing.T) {
	t.Parallel()
	blockchain, _, currentBlock, signer, signFn, _ := PrepareXDCTestBlockChainForV2Engine(t, 905, params.TestXDPoSMockChainConfig, nil)
	engineV2 := blockchain.Engine().(*XDPoS.XDPoS).EngineV2

	var incoming types.ExtraFields_v2
	if err := utils.DecodeBytesExtraFields(currentBlock.Extra(), &incoming); err != nil {
		t.Fatal("Fail to decode extra data", err)
	}
	var older types.ExtraFields_v2
	if err := utils.DecodeBytesExtraFields(blockchain.GetBlockByNumber(903).Extra(), &older); err != nil {
		t.Fatal("Fail to decode extra data", err)
	}
	engineV2.SetPropertiesFaker(older.QuorumCert, &types.TimeoutCert{})

	// At head 905 gap block 4050 is 3145 blocks away, outside epoch*3.
	outOfWindowTC := func() *types.TimeoutCert {
		return &types.TimeoutCert{Round: types.Round(2), Signatures: []types.Signature{{1}}, GapNumber: 4050}
	}
	syncInfoMsg := &types.SyncInfo{HighestQuorumCert: incoming.QuorumCert, HighestTimeoutCert: outOfWindowTC()}
	verified, err := engineV2.VerifySyncInfoMessage(blockchain, syncInfoMsg)
	assert.Nil(t, err)
	assert.True(t, verified, "an out-of-window TC must not discard the QC")
	assert.Equal(t, types.Round(0), syncInfoMsg.HighestTimeoutCert.Round, "the certificate must not stay attached for the caller to relay")

	// Advance the head to 1400, where the same gap is inside the window. Gap
	// block 4050 has no canonical header here either, so what this pins is that
	// the handler re-runs the window and snapshot checks on the new head.
	parent := currentBlock
	for i := 906; i <= 1400; i++ {
		block := CreateBlock(blockchain, params.TestXDPoSMockChainConfig, parent, i, int64(i)-params.TestXDPoSMockChainConfig.XDPoS.V2.SwitchBlock.Int64(), signer.Hex(), signer, signFn, nil, nil, "")
		if err := blockchain.InsertBlock(block); err != nil {
			t.Fatal(err)
		}
		parent = block
	}

	unremoved := &types.SyncInfo{HighestQuorumCert: incoming.QuorumCert, HighestTimeoutCert: outOfWindowTC()}
	err = engineV2.SyncInfoHandler(blockchain, unremoved)
	assert.Error(t, err, "the handler must refuse the certificate at the new head instead of adopting it")

	_, _, _, highestTC, _, _ := engineV2.GetPropertiesFaker()
	assert.Equal(t, types.Round(0), highestTC.Round, "a TC the handler never verified must not be adopted")
}

// The certificate the window admits is authenticated and stays on the message,
// so the handler adopts it: removing a rejected certificate must not remove an
// accepted one.
func TestSyncInfoHandlerAdoptsVerifiedTC(t *testing.T) {
	t.Parallel()
	// Gap block 450 has a snapshot at head 1400, and the gap is inside the
	// epoch*3 window there.
	blockchain, _, currentBlock, _, _, _ := PrepareXDCTestBlockChainForV2Engine(t, 1400, params.TestXDPoSMockChainConfig, nil)
	engineV2 := blockchain.Engine().(*XDPoS.XDPoS).EngineV2

	var incoming types.ExtraFields_v2
	if err := utils.DecodeBytesExtraFields(currentBlock.Extra(), &incoming); err != nil {
		t.Fatal("Fail to decode extra data", err)
	}

	signedHash := types.TimeoutSigHash(&types.TimeoutForSign{Round: types.Round(2), GapNumber: 450}).Bytes()
	var signatures []types.Signature
	for _, key := range []*ecdsa.PrivateKey{acc1Key, acc2Key, acc3Key, voterKey} {
		signatures = append(signatures, SignHashByPK(key, signedHash))
	}
	syncInfoMsg := &types.SyncInfo{
		HighestQuorumCert:  incoming.QuorumCert,
		HighestTimeoutCert: &types.TimeoutCert{Round: types.Round(2), Signatures: signatures, GapNumber: 450},
	}

	verified, err := engineV2.VerifySyncInfoMessage(blockchain, syncInfoMsg)
	assert.Nil(t, err)
	assert.True(t, verified)
	assert.Equal(t, types.Round(2), syncInfoMsg.HighestTimeoutCert.Round, "a verified certificate must stay on the message")

	assert.Nil(t, engineV2.SyncInfoHandler(blockchain, syncInfoMsg))
	_, _, _, highestTC, _, _ := engineV2.GetPropertiesFaker()
	assert.Equal(t, types.Round(2), highestTC.Round, "the handler must adopt the certificate it verified")
}

// Bfter relays a SyncInfo before SyncInfoHandler runs, and SyncInfo.Hash()
// covers the certificate, so an unauthenticated certificate left attached would
// be forwarded and would give every forged TC round its own relay. The payload
// that reaches the broadcast channel for an out-of-window certificate must
// therefore carry no certificate at all.
func TestSyncInfoRelayPayloadDropsOutOfWindowTC(t *testing.T) {
	t.Parallel()
	blockchain, _, currentBlock, _, _, _ := PrepareXDCTestBlockChainForV2Engine(t, 3255, params.TestXDPoSMockChainConfig, nil)
	engineV2 := blockchain.Engine().(*XDPoS.XDPoS).EngineV2

	var incoming types.ExtraFields_v2
	if err := utils.DecodeBytesExtraFields(currentBlock.Extra(), &incoming); err != nil {
		t.Fatal("Fail to decode extra data", err)
	}
	var older types.ExtraFields_v2
	if err := utils.DecodeBytesExtraFields(blockchain.GetBlockByNumber(903).Extra(), &older); err != nil {
		t.Fatal("Fail to decode extra data", err)
	}
	engineV2.SetPropertiesFaker(older.QuorumCert, &types.TimeoutCert{})

	// SetConsensusFuns points the Bfter at the engine's broadcast channel, and
	// SyncInfo enqueues the message there before running the handler.
	b := bft.New(bft.BroadcastFns{}, blockchain, func() uint64 { return 3255 })
	b.InitEpochNumber()
	b.SetConsensusFuns(blockchain.Engine())

	syncInfoMsg := &types.SyncInfo{
		HighestQuorumCert:  incoming.QuorumCert,
		HighestTimeoutCert: &types.TimeoutCert{Round: types.Round(2), Signatures: []types.Signature{{1}}, GapNumber: 450},
	}
	errCh := make(chan error, 1)
	go func() { errCh <- b.SyncInfo("peer", syncInfoMsg) }()

	// The engine broadcasts timeouts, and on the timeout-sync threshold its own
	// SyncInfo, on the same channel; accept only the message under test.
	wantQC := incoming.QuorumCert.ProposedBlockInfo.Number
	deadline := time.After(5 * time.Second)
	var relayed *types.SyncInfo
	for relayed == nil {
		select {
		case raw := <-engineV2.BroadcastCh:
			if si, ok := raw.(*types.SyncInfo); ok && si.HighestQuorumCert != nil && si.HighestQuorumCert.ProposedBlockInfo.Number.Cmp(wantQC) == 0 {
				relayed = si
			}
		case <-deadline:
			t.Fatal("the SyncInfo under test never reached the broadcast channel")
		}
	}
	assert.NoError(t, <-errCh)
	assert.Equal(t, types.Round(0), relayed.HighestTimeoutCert.Round, "an unauthenticated TC must not be relayed")
	assert.Empty(t, relayed.HighestTimeoutCert.Signatures)
	assert.Zero(t, relayed.HighestTimeoutCert.GapNumber)
}

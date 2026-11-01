package engine_v2_tests

import (
	"math/big"
	"testing"
	"time"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS/utils"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/stretchr/testify/assert"
)

// TestInitialFirstV2Block tests initial first v 2 block.
func TestInitialFirstV2Block(t *testing.T) {
	t.Parallel()
	blockchain, _, currentBlock, _, _, _ := PrepareXDCTestBlockChainForV2Engine(t, 900, params.TestXDPoSMockChainConfig, nil)
	adaptor := blockchain.Engine().(*XDPoS.XDPoS)
	header := currentBlock.Header()

	// the bootstrap snapshot is rebuilt on demand even before initial
	snap, err := adaptor.EngineV2.GetSnapshot(blockchain, currentBlock.Header())
	assert.Nil(t, err)
	assert.Equal(t, uint64(450), snap.Number)

	err = adaptor.EngineV2.Initial(blockchain, header)
	assert.Nil(t, err)

	round, _, highQC, _, _, _ := adaptor.EngineV2.GetPropertiesFaker()
	blockInfo := &types.BlockInfo{
		Hash:   header.Hash(),
		Round:  types.Round(0),
		Number: header.Number,
	}
	expectedQuorumCert := &types.QuorumCert{
		ProposedBlockInfo: blockInfo,
		Signatures:        nil,
		GapNumber:         blockchain.Config().XDPoS.V2.SwitchBlock.Uint64() - blockchain.Config().XDPoS.Gap,
	}
	assert.Equal(t, types.Round(1), round)
	assert.Equal(t, expectedQuorumCert, highQC)

	// Test snapshot
	snap, err = adaptor.EngineV2.GetSnapshot(blockchain, currentBlock.Header())
	assert.Nil(t, err)
	assert.Equal(t, uint64(450), snap.Number)

	// Test Running channels
	minePeriod := <-adaptor.MinePeriodCh
	assert.Equal(t, blockchain.Config().XDPoS.V2.GetCurrentConfig().MinePeriod, minePeriod)

	t.Logf("Waiting %d secs for timeout to happen", blockchain.Config().XDPoS.V2.GetCurrentConfig().TimeoutPeriod)
	timeoutMsg := <-adaptor.EngineV2.BroadcastCh
	assert.NotNil(t, timeoutMsg)
	assert.Equal(t, types.Round(1), timeoutMsg.(*types.Timeout).Round)
}

// TestInitialOtherV2Block tests initial other v 2 block.
func TestInitialOtherV2Block(t *testing.T) {
	t.Parallel()
	// insert new block with new extra fields
	blockchain, _, currentBlock, signer, signFn, _ := PrepareXDCTestBlockChainForV2Engine(t, 900, params.TestXDPoSMockChainConfig, nil)
	adaptor := blockchain.Engine().(*XDPoS.XDPoS)

	blockCoinBase := "0x111000000000000000000000000000000123"
	for blockNum := 901; blockNum <= 910; blockNum++ {
		currentBlock = CreateBlock(blockchain, params.TestXDPoSMockChainConfig, currentBlock, blockNum, int64(blockNum-900), blockCoinBase, signer, signFn, nil, nil, "")
		err := blockchain.InsertBlock(currentBlock)
		assert.Nil(t, err)
	}

	// v2
	blockInfo := &types.BlockInfo{
		Hash:   currentBlock.Header().Hash(),
		Round:  types.Round(10),
		Number: big.NewInt(910),
	}
	quorumCert := &types.QuorumCert{
		ProposedBlockInfo: blockInfo,
		Signatures:        nil, // after decode it got default value []utils.Signature{}
		GapNumber:         450,
	}
	extra := types.ExtraFields_v2{
		Round:      11,
		QuorumCert: quorumCert,
	}
	extraBytes, err := extra.EncodeToBytes()
	assert.Nil(t, err)

	header := &types.Header{
		Root:       common.HexToHash("35999dded35e8db12de7e6c1471eb9670c162eec616ecebbaf4fddd4676fb930"),
		Number:     big.NewInt(int64(911)),
		ParentHash: currentBlock.Hash(),
		Coinbase:   common.HexToAddress("0x111000000000000000000000000000000123"),
	}
	header.Extra = extraBytes

	block, err := createBlockFromHeader(blockchain, header, nil, signer, signFn, blockchain.Config())
	if err != nil {
		t.Fatal(err)
	}
	err = blockchain.InsertBlock(block)
	assert.Nil(t, err)
	// Initialise
	err = adaptor.EngineV2.Initial(blockchain, block.Header())
	assert.Nil(t, err)

	round, _, highQC, _, _, _ := adaptor.EngineV2.GetPropertiesFaker()
	// The head 911 carries round 11: highestQC points at 911 itself
	// (signatures unavailable) and the next round is 12.
	expectedQuorumCert := &types.QuorumCert{
		ProposedBlockInfo: &types.BlockInfo{
			Hash:   block.Hash(),
			Round:  types.Round(11),
			Number: big.NewInt(911),
		},
		Signatures: nil,
		GapNumber:  450,
	}
	assert.Equal(t, types.Round(12), round)
	assert.Equal(t, expectedQuorumCert, highQC)

	// Test snapshot
	snap, err := adaptor.EngineV2.GetSnapshot(blockchain, block.Header())
	assert.Nil(t, err)
	assert.Equal(t, uint64(450), snap.Number)
}

// TestSnapshotShouldAlreadyBeCreatedByGapRefresh tests snapshot should already be created
// by the gap block refresh, which writes it together with the head markers.
func TestSnapshotShouldAlreadyBeCreatedByGapRefresh(t *testing.T) {
	t.Parallel()
	// insert new block with new extra fields
	blockchain, _, currentBlock, _, _, _ := PrepareXDCTestBlockChainForV2Engine(t, 1800, params.TestXDPoSMockChainConfig, nil)
	adaptor := blockchain.Engine().(*XDPoS.XDPoS)

	snap, err := adaptor.EngineV2.GetSnapshot(blockchain, currentBlock.Header())
	assert.Nil(t, err)
	assert.Equal(t, uint64(1350), snap.Number)
}

// TestInitialWithWrongSwitchNumber tests initial with wrong switch number.
func TestInitialWithWrongSwitchNumber(t *testing.T) {
	t.Parallel()
	config := params.TestXDPoSMockChainConfig.Clone()
	if config == nil {
		t.Fatal("expected cloned config")
	}

	blockchain, _, currentBlock, _, _, _ := PrepareXDCTestBlockChainForV2Engine(t, 800, config, nil)
	adaptor := blockchain.Engine().(*XDPoS.XDPoS)
	header := currentBlock.Header()
	config.XDPoS.V2.SwitchBlock = big.NewInt(800) // not epoch number

	err := adaptor.EngineV2.Initial(blockchain, header)
	assert.NotNil(t, err)
}

// TestInitialPreparesHeadSuccessorAfterReconcile checks that after the
// reconciliation the head is a valid mining parent (the pre-fix view rejected
// its successor with ErrNotReadyToPropose) and the wire extra carries the
// head's own embedded QC, never the signatureless reconstructed one.
func TestInitialPreparesHeadSuccessorAfterReconcile(t *testing.T) {
	blockchain, _, currentBlock, signer, signFn, _ := PrepareXDCTestBlockChainForV2Engine(t, 900, params.TestXDPoSMockChainConfig, nil)
	adaptor := blockchain.Engine().(*XDPoS.XDPoS)

	blockCoinBase := "0x111000000000000000000000000000000123"
	for blockNum := 901; blockNum <= 910; blockNum++ {
		currentBlock = CreateBlock(blockchain, params.TestXDPoSMockChainConfig, currentBlock, blockNum, int64(blockNum-900), blockCoinBase, signer, signFn, nil, nil, "")
		err := blockchain.InsertBlock(currentBlock)
		assert.Nil(t, err)
	}

	// Head block 911: round 11, carrying QC(910) — QC(911) lives in the
	// not-yet-existing block 912, the deadlock shape. Built through the helper
	// so the QC carries real signatures: the batch verification below is the
	// whole point, and a hand-made signatureless QC would fail it on the
	// signature count alone (as in TestInitialOtherV2Block).
	block911 := CreateBlock(blockchain, blockchain.Config(), currentBlock, 911, 11, blockCoinBase, signer, signFn, nil, nil, "")
	err := blockchain.InsertBlock(block911)
	assert.Nil(t, err)

	err = adaptor.EngineV2.Initial(blockchain, block911.Header())
	assert.Nil(t, err)
	// The reconciliation moves the view one round past the head: block 911 was
	// produced in round 11, so the engine waits on round 12 instead of
	// re-proposing the head in round 11.
	currentRound, _, highQC, _, _, _ := adaptor.EngineV2.GetPropertiesFaker()
	assert.Equal(t, types.Round(12), currentRound)
	assert.Equal(t, types.Round(11), highQC.ProposedBlockInfo.Round)

	// Prepare a successor of the head; rotate the round until the signer is
	// the leader, since the rotation index is deployment-dependent.
	header912 := &types.Header{
		Root:       common.HexToHash("35999dded35e8db12de7e6c1471eb9670c162eec616ecebbaf4fddd4676fb930"),
		ParentHash: block911.Hash(),
		Number:     big.NewInt(912),
		GasLimit:   testGasLimit,
		Time:       uint64(time.Now().Unix()),
		Coinbase:   signer,
	}
	prepared := false
	leaderRound := types.Round(0)
	for r := types.Round(12); r < types.Round(12)+50; r++ {
		adaptor.EngineV2.SetNewRoundFaker(blockchain, r, false)
		err = adaptor.EngineV2.Prepare(blockchain, header912)
		if err == nil {
			prepared = true
			leaderRound = r
			break
		}
		assert.Equal(t, consensus.ErrNotReadyToMine, err)
	}
	assert.True(t, prepared)

	// The wire extra carries the head's embedded QC(910), never the
	// signatureless reconstructed QC(911).
	var decoded types.ExtraFields_v2
	err = utils.DecodeBytesExtraFields(header912.Extra, &decoded)
	assert.Nil(t, err)
	assert.Equal(t, leaderRound, decoded.Round)
	assert.Equal(t, currentBlock.Hash(), decoded.QuorumCert.ProposedBlockInfo.Hash)
	assert.Equal(t, types.Round(10), decoded.QuorumCert.ProposedBlockInfo.Round)

	// Import the block the way a node that is behind does: a batch hands every
	// header in together with its predecessors, and that is where a QC which
	// does not certify the parent has to be handled.
	block912, err := createBlockFromHeader(blockchain, header912, nil, signer, signFn, blockchain.Config())
	assert.Nil(t, err)
	abort, results := adaptor.VerifyHeaders(blockchain, []*types.Header{block911.Header(), block912.Header()}, []bool{true, true})
	defer close(abort)
	for i := 0; i < 2; i++ {
		assert.Nil(t, <-results, "header %d failed verification", 911+i)
	}
	_, err = blockchain.InsertChain([]*types.Block{block912})
	assert.Nil(t, err, "the reconciled block must be importable")
}

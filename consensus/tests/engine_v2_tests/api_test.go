package engine_v2_tests

import (
	"encoding/json"
	"math/big"
	"reflect"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/eth/hooks"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/XinFinOrg/XDPoSChain/rpc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetMissedRoundsInEpochByBlockNumOnlyForV2Consensus(t *testing.T) {
	skipLongInShortMode(t)
	_, bc, _, _, _ := PrepareXDCTestBlockChainWith128Candidates(t, 1802, params.TestXDPoSMockChainConfig)

	engine := bc.BlockChain().Engine().(*XDPoS.XDPoS)
	blockNum := rpc.BlockNumber(123)

	data, err := engine.APIs(bc.BlockChain())[0].Service.(*XDPoS.API).GetMissedRoundsInEpochByBlockNum(&blockNum)

	assert.EqualError(t, err, "not supported in the v1 consensus")
	assert.Nil(t, data)
}

func TestGetMissedRoundsInEpochByBlockNumReturnEmptyForV2(t *testing.T) {
	skipLongInShortMode(t)
	_, bc, cb, _, _ := PrepareXDCTestBlockChainWith128Candidates(t, 1802, params.TestXDPoSMockChainConfig)

	engine := bc.BlockChain().Engine().(*XDPoS.XDPoS)
	blockNum := rpc.BlockNumber(cb.NumberU64())

	data, err := engine.APIs(bc.BlockChain())[0].Service.(*XDPoS.API).GetMissedRoundsInEpochByBlockNum(&blockNum)

	assert.Nil(t, err)
	assert.Equal(t, types.Round(900), data.EpochRound)
	assert.Equal(t, big.NewInt(1800), data.EpochBlockNumber)
	assert.Equal(t, 0, len(data.MissedRounds))

	blockNum = rpc.BlockNumber(1800)

	data, err = engine.APIs(bc.BlockChain())[0].Service.(*XDPoS.API).GetMissedRoundsInEpochByBlockNum(&blockNum)

	assert.Nil(t, err)
	assert.Equal(t, types.Round(900), data.EpochRound)
	assert.Equal(t, big.NewInt(1800), data.EpochBlockNumber)
	assert.Equal(t, 0, len(data.MissedRounds))

	blockNum = rpc.BlockNumber(1801)

	data, err = engine.APIs(bc.BlockChain())[0].Service.(*XDPoS.API).GetMissedRoundsInEpochByBlockNum(&blockNum)

	assert.Nil(t, err)
	assert.Equal(t, types.Round(900), data.EpochRound)
	assert.Equal(t, big.NewInt(1800), data.EpochBlockNumber)
	assert.Equal(t, 0, len(data.MissedRounds))
}

func TestGetMissedRoundsInEpochByBlockNumReturnEmptyForV2FistEpoch(t *testing.T) {
	skipLongInShortMode(t)
	_, bc, _, _, _ := PrepareXDCTestBlockChainWith128Candidates(t, 1802, params.TestXDPoSMockChainConfig)

	engine := bc.BlockChain().Engine().(*XDPoS.XDPoS)
	blockNum := rpc.BlockNumber(901)

	data, err := engine.APIs(bc.BlockChain())[0].Service.(*XDPoS.API).GetMissedRoundsInEpochByBlockNum(&blockNum)

	assert.Nil(t, err)
	assert.Equal(t, types.Round(1), data.EpochRound)
	assert.Equal(t, big.NewInt(901), data.EpochBlockNumber)
	assert.Equal(t, 0, len(data.MissedRounds))
}

func TestGetMissedRoundsInEpochByBlockNum(t *testing.T) {
	skipLongInShortMode(t)
	blockchain, bc, currentBlock, signer, signFn := PrepareXDCTestBlockChainWith128Candidates(t, 1802, params.TestXDPoSMockChainConfig)
	chainConfig := params.TestXDPoSMockChainConfig
	engine := bc.BlockChain().Engine().(*XDPoS.XDPoS)
	blockCoinBase := signer.Hex()

	startingBlockNum := currentBlock.Number().Int64() + 1
	// Skipped the round
	roundNumber := startingBlockNum - chainConfig.XDPoS.V2.SwitchBlock.Int64() + 2
	block := CreateBlock(blockchain, chainConfig, currentBlock, int(startingBlockNum), roundNumber, blockCoinBase, signer, signFn, nil, nil, "b345a8560bd51926803dd17677c9f0751193914a851a4ec13063d6bf50220b53")
	err := blockchain.InsertBlock(block)
	if err != nil {
		t.Fatal(err)
	}

	blockNum := rpc.BlockNumber(1803)

	data, err := engine.APIs(bc.BlockChain())[0].Service.(*XDPoS.API).GetMissedRoundsInEpochByBlockNum(&blockNum)

	assert.Nil(t, err)
	assert.Equal(t, types.Round(900), data.EpochRound)
	assert.Equal(t, big.NewInt(1800), data.EpochBlockNumber)
	assert.Equal(t, 2, len(data.MissedRounds))
	assert.NotEmpty(t, data.MissedRounds[0].Miner)
	assert.Equal(t, data.MissedRounds[0].Round, types.Round(903))
	assert.Equal(t, data.MissedRounds[0].CurrentBlockNum, big.NewInt(1803))
	assert.Equal(t, data.MissedRounds[0].ParentBlockNum, big.NewInt(1802))
	assert.NotEmpty(t, data.MissedRounds[1].Miner)
	assert.Equal(t, data.MissedRounds[1].Round, types.Round(904))
	assert.Equal(t, data.MissedRounds[0].CurrentBlockNum, big.NewInt(1803))
	assert.Equal(t, data.MissedRounds[0].ParentBlockNum, big.NewInt(1802))

	assert.NotEqual(t, data.MissedRounds[0].Miner, data.MissedRounds[1].Miner)
}

func TestGetEpochNumbersBetween(t *testing.T) {
	skipLongInShortMode(t)
	_, bc, _, _, _ := PrepareXDCTestBlockChainWith128Candidates(t, 1802, params.TestXDPoSMockChainConfig)

	engine := bc.BlockChain().Engine().(*XDPoS.XDPoS)

	begin := rpc.BlockNumber(1800)
	end := rpc.BlockNumber(1802)
	numbers, err := engine.APIs(bc.BlockChain())[0].Service.(*XDPoS.API).GetEpochNumbersBetween(&begin, &end)

	assert.True(t, reflect.DeepEqual([]uint64{1800}, numbers))
	assert.Nil(t, err)

	begin = rpc.BlockNumber(1799)
	end = rpc.BlockNumber(1802)
	numbers, err = engine.APIs(bc.BlockChain())[0].Service.(*XDPoS.API).GetEpochNumbersBetween(&begin, &end)

	assert.True(t, reflect.DeepEqual([]uint64{1800}, numbers))
	assert.Nil(t, err)

	begin = rpc.BlockNumber(1799)
	end = rpc.BlockNumber(1802)
	numbers, err = engine.APIs(bc.BlockChain())[0].Service.(*XDPoS.API).GetEpochNumbersBetween(&begin, &end)

	assert.True(t, reflect.DeepEqual([]uint64{1800}, numbers))
	assert.Nil(t, err)

	begin = rpc.BlockNumber(901)
	end = rpc.BlockNumber(1802)
	numbers, err = engine.APIs(bc.BlockChain())[0].Service.(*XDPoS.API).GetEpochNumbersBetween(&begin, &end)

	assert.True(t, reflect.DeepEqual([]uint64{901, 1800}, numbers))
	assert.Nil(t, err)

	// 900 is V1, not V2, so error
	begin = rpc.BlockNumber(900)
	end = rpc.BlockNumber(1802)
	numbers, err = engine.APIs(bc.BlockChain())[0].Service.(*XDPoS.API).GetEpochNumbersBetween(&begin, &end)

	assert.Nil(t, numbers)
	assert.EqualError(t, err, "not supported in the v1 consensus")

	// 1803 not exist
	begin = rpc.BlockNumber(901)
	end = rpc.BlockNumber(1803)
	numbers, err = engine.APIs(bc.BlockChain())[0].Service.(*XDPoS.API).GetEpochNumbersBetween(&begin, &end)

	assert.Nil(t, numbers)
	assert.EqualError(t, err, "illegal end block number 1803")

	// 1803 not exist
	begin = rpc.BlockNumber(1803)
	end = rpc.BlockNumber(1803)
	numbers, err = engine.APIs(bc.BlockChain())[0].Service.(*XDPoS.API).GetEpochNumbersBetween(&begin, &end)

	assert.Nil(t, numbers)
	assert.EqualError(t, err, "illegal begin block number 1803")
}
func TestGetBlockByEpochNumber(t *testing.T) {
	skipLongInShortMode(t)
	blockchain, _, currentBlock, signer, signFn := PrepareXDCTestBlockChainWithPenaltyForV2Engine(t, 1802, params.TestXDPoSMockChainConfig)

	blockCoinBase := "0x111000000000000000000000000000000123"
	largeRound := int64(1800)
	newBlock := CreateBlock(blockchain, params.TestXDPoSMockChainConfig, currentBlock, int(currentBlock.NumberU64())+1, largeRound, blockCoinBase, signer, signFn, nil, nil, currentBlock.Header().Root.Hex())
	err := blockchain.InsertBlock(newBlock)
	assert.Nil(t, err)
	largeRound2 := int64(3600)
	newBlock2 := CreateBlock(blockchain, params.TestXDPoSMockChainConfig, newBlock, int(newBlock.NumberU64())+1, largeRound2, blockCoinBase, signer, signFn, nil, nil, newBlock.Header().Root.Hex())
	err = blockchain.InsertBlock(newBlock2)
	assert.Nil(t, err)

	// block num, round, epoch is as follows
	// 900,0,1 (v2 switch block, not v2 epoch switch block)
	// 901,1,1 (1st epoch switch block)
	// 902,2,1
	// ...
	// 1800,900,2 (2nd epoch switch block)
	// 1801,901,2
	// 1802,902,2
	// 1803,1800,3 (epoch switch)
	// epoch 4 has no block
	// 1804,3600,5 (epoch switch)
	engine := blockchain.Engine().(*XDPoS.XDPoS)

	// init the snapshot, otherwise getEpochSwitchInfo would return error
	checkpointHeader := blockchain.GetHeaderByNumber(blockchain.Config().XDPoS.V2.SwitchBlock.Uint64() + 1)
	err = engine.Initial(blockchain, checkpointHeader)
	assert.Nil(t, err)

	info, err := engine.APIs(blockchain)[0].Service.(*XDPoS.API).GetBlockInfoByEpochNum(0)
	assert.Equal(t, info.EpochConsensusVersion, "v1")
	assert.Nil(t, err)

	info, err = engine.APIs(blockchain)[0].Service.(*XDPoS.API).GetBlockInfoByEpochNum(1)
	assert.Equal(t, *info.EpochRound, types.Round(1))
	assert.Equal(t, info.EpochConsensusVersion, "v2")
	assert.Nil(t, err)

	info, err = engine.APIs(blockchain)[0].Service.(*XDPoS.API).GetBlockInfoByEpochNum(2)
	assert.Equal(t, *info.EpochRound, types.Round(900))
	assert.Equal(t, info.EpochConsensusVersion, "v2")
	assert.Nil(t, err)

	info, err = engine.APIs(blockchain)[0].Service.(*XDPoS.API).GetBlockInfoByEpochNum(3)
	assert.Equal(t, *info.EpochRound, types.Round(largeRound))
	assert.Equal(t, info.EpochConsensusVersion, "v2")
	assert.Nil(t, err)

	info, err = engine.APIs(blockchain)[0].Service.(*XDPoS.API).GetBlockInfoByEpochNum(4)
	assert.NotNil(t, err)
	assert.Nil(t, info)

	info, err = engine.APIs(blockchain)[0].Service.(*XDPoS.API).GetBlockInfoByEpochNum(5)
	assert.Equal(t, *info.EpochRound, types.Round(largeRound2))
	assert.Equal(t, info.EpochConsensusVersion, "v2")
	assert.Nil(t, err)

	info, err = engine.APIs(blockchain)[0].Service.(*XDPoS.API).GetBlockInfoByEpochNum(6)
	assert.NotNil(t, err)
	assert.Nil(t, info)
}

// TestGetSigningTxCountByEpochMatchesRewardWindow checks that the count for an epoch is the one
// the reward hook pays for it. The epoch before 3600 has the sign slots 2715..3585: the previous
// epoch switch 2700 is a multiple of MergeSignRange but not a slot, and a signature for the last
// slot that is only mined in the next epoch (block 3700) still counts.
func TestGetSigningTxCountByEpochMatchesRewardWindow(t *testing.T) {
	skipLongInShortMode(t)
	b, err := json.Marshal(params.TestXDPoSMockChainConfig)
	require.NoError(t, err)
	var config params.ChainConfig
	require.NoError(t, json.Unmarshal(b, &config))
	config.XDPoS.V2.SwitchBlock.SetUint64(1800)
	config.XDPoS.V2.SwitchEpoch = 2

	epoch := config.XDPoS.Epoch // 900
	blockchain, _, _, signer, signFn := PrepareXDCTestBlockChainWithProtectorObserver(t, int(epoch)*5+10, &config)
	adaptor := blockchain.Engine().(*XDPoS.XDPoS)
	api := adaptor.APIs(blockchain)[0].Service.(*XDPoS.API)

	header2700 := blockchain.GetHeaderByNumber(epoch * 3)
	header3599 := blockchain.GetHeaderByNumber(epoch*4 - 1)
	header3700 := blockchain.GetHeaderByNumber(epoch*4 + 100)
	header4500 := blockchain.GetHeaderByNumber(epoch * 5)
	require.Contains(t, adaptor.GetMasternodesFromCheckpointHeader(header2700), acc1Addr)

	var slots []*types.Header
	for i := epoch*3 + 1; i < epoch*4; i++ {
		if i%common.MergeSignRange == 0 {
			slots = append(slots, blockchain.GetHeaderByNumber(i))
		}
	}
	require.Len(t, slots, 59)
	last := slots[len(slots)-1]
	require.Equal(t, uint64(3585), last.Number.Uint64())

	// signer signs every slot, but its signature for the last one is mined in the next epoch;
	// acc1 signs the previous epoch switch block and two slots.
	var txs []*types.Transaction
	for _, h := range slots[:len(slots)-1] {
		tx, err := signingTxWithSignerFn(h, 0, signer, signFn)
		require.NoError(t, err)
		txs = append(txs, tx)
	}
	for _, h := range []*types.Header{header2700, slots[0], slots[1]} {
		tx, err := signingTxWithKey(h, 0, acc1Key)
		require.NoError(t, err)
		txs = append(txs, tx)
	}
	adaptor.CacheSigningTxs(header3599.Hash(), txs)
	late, err := signingTxWithSignerFn(last, 0, signer, signFn)
	require.NoError(t, err)
	adaptor.CacheSigningTxs(header3700.Hash(), []*types.Transaction{late})

	got, err := api.GetSigningTxCountByEpoch(rpc.BlockNumber(epoch * 4))
	require.NoError(t, err)
	require.Equal(t, uint64(59), got[signer], "the late-mined signature for slot 3585 counts")
	require.Equal(t, uint64(2), got[acc1Addr], "the switch block 2700 is not a sign slot")

	round4500, err := adaptor.EngineV2.GetRoundNumber(header4500)
	require.NoError(t, err)
	paid, signSlots, _, err := hooks.GetSigningTxCount(adaptor, blockchain, header4500, adaptor.EngineV2.Config(uint64(round4500)))
	require.NoError(t, err)
	require.Equal(t, uint64(59), signSlots)
	for addr, log := range paid[hooks.MasterNodeBeneficiary] {
		require.Equal(t, log.Sign, got[addr], "sign count of %s differs from the reward hook", addr.Hex())
	}
	require.Len(t, paid[hooks.MasterNodeBeneficiary], 2)
}

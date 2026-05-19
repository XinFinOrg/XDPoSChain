package engine_v2_tests

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS/utils"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/eth/hooks"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/stretchr/testify/assert"
)

// TestHookPenaltyV2Mining tests hook penalty v 2 mining.
func TestHookPenaltyV2Mining(t *testing.T) {
	skipLongInShortMode(t)
	config := params.TestXDPoSMockChainConfig
	blockchain, _, _, _, _, _ := PrepareXDCTestBlockChainForV2Engine(t, int(config.XDPoS.Epoch)*3, config, nil)
	adaptor := blockchain.Engine().(*XDPoS.XDPoS)
	hooks.AttachConsensusV2Hooks(adaptor, blockchain, config)
	assert.NotNil(t, adaptor.EngineV2.HookPenalty)
	var extraField types.ExtraFields_v2
	// 901 is the first v2 block
	header901 := blockchain.GetHeaderByNumber(config.XDPoS.Epoch + 1)
	err := utils.DecodeBytesExtraFields(header901.Extra, &extraField)
	assert.Nil(t, err)
	masternodes := adaptor.GetMasternodesFromCheckpointHeader(header901)
	assert.Equal(t, 5, len(masternodes))
	header2100 := blockchain.GetHeaderByNumber(config.XDPoS.Epoch * 3)
	penalty, err := adaptor.EngineV2.HookPenalty(blockchain, big.NewInt(int64(config.XDPoS.Epoch*3)), header2100.ParentHash, masternodes)
	assert.Nil(t, err)
	// when we prepare the chain, we include all 5 signers as coinbase except one signer
	// header2100 records 5 masternodes, so penalty contains 5-4=1 address
	assert.Equal(t, 1, len(penalty))
	contains := false
	for _, mn := range common.RemoveItemFromArray(masternodes, penalty) {
		if mn == header901.Coinbase {
			contains = true
		}
	}
	assert.True(t, contains)
	// set adaptor round/qc to that of 2099
	err = utils.DecodeBytesExtraFields(header2100.Extra, &extraField)
	assert.Nil(t, err)
	err = adaptor.EngineV2.ProcessQCFaker(blockchain, extraField.QuorumCert)
	assert.Nil(t, err)
	// coinbase is a faker signer
	headerMining := &types.Header{
		ParentHash: header2100.ParentHash,
		Number:     header2100.Number,
		GasLimit:   testGasLimit,
		Time:       header2100.Time,
		Coinbase:   acc1Addr,
	}
	// Force to make the node to be at its round to mine, otherwise won't pass the yourturn masternodes check
	// We have 19 nodes in total (20 candidates in snapshot - 1 penalty) and the fake signer is always at the 18th(last) in the list.
	// Hence int(config.XDPoS.Epoch)*3+18-900, the +18 means is to force to next 18 round and -900 is the relative round number to block number int(config.XDPoS.Epoch)*3
	adaptor.EngineV2.SetNewRoundFaker(blockchain, types.Round(int(config.XDPoS.Epoch)*3+18-900), false)
	// The test default signer is not in the masternodes, so we set the faker signer
	adaptor.EngineV2.AuthorizeFaker(acc1Addr)
	err = adaptor.Prepare(blockchain, headerMining)
	assert.Nil(t, err)
	assert.Equal(t, 1, len(headerMining.Penalties)/common.AddressLength)
	// 20 candidates (set by PrepareXDCTestBlockChainForV2Engine) - 1 penalty = 19
	assert.Equal(t, 19, len(headerMining.Validators)/common.AddressLength)
}

// TestHookPenaltyV2Comeback tests hook penalty v 2 comeback.
func TestHookPenaltyV2Comeback(t *testing.T) {
	skipLongInShortMode(t)
	config := params.TestXDPoSMockChainConfig
	blockchain, _, _, signer, signFn := PrepareXDCTestBlockChainWithPenaltyForV2Engine(t, int(config.XDPoS.Epoch)*3, config)
	adaptor := blockchain.Engine().(*XDPoS.XDPoS)
	hooks.AttachConsensusV2Hooks(adaptor, blockchain, config)
	assert.NotNil(t, adaptor.EngineV2.HookPenalty)
	var extraField types.ExtraFields_v2
	// 901 is the first v2 block
	header901 := blockchain.GetHeaderByNumber(config.XDPoS.Epoch + 1)
	err := utils.DecodeBytesExtraFields(header901.Extra, &extraField)
	assert.Nil(t, err)
	masternodes := adaptor.GetMasternodesFromCheckpointHeader(header901)
	assert.Equal(t, 5, len(masternodes))
	header2100 := blockchain.GetHeaderByNumber(config.XDPoS.Epoch * 3)
	penalty, err := adaptor.EngineV2.HookPenalty(blockchain, big.NewInt(int64(config.XDPoS.Epoch*3)), header2100.ParentHash, masternodes)
	assert.Nil(t, err)
	// The pre-upgrade comeback window remains pinned to the historical
	// LimitPenaltyEpochV2 constant, so the prior penalty can already return here.
	assert.Equal(t, 2, len(penalty))
	header2085 := blockchain.GetHeaderByNumber(config.XDPoS.Epoch*3 - common.MergeSignRange)
	// Force a signing tx into cache so the comeback signer is removed from the
	// penalty set while the missing miner remains.
	tx, err := signingTxWithSignerFn(header2085, 0, signer, signFn)
	assert.Nil(t, err)
	adaptor.CacheSigningTxs(header2085.Hash(), []*types.Transaction{tx})
	penalty, err = adaptor.EngineV2.HookPenalty(blockchain, big.NewInt(int64(config.XDPoS.Epoch*3)), header2100.ParentHash, masternodes)
	assert.Nil(t, err)
	assert.Equal(t, 1, len(penalty))
}

// TestHookPenaltyV2Jump tests hook penalty v 2 jump.
func TestHookPenaltyV2Jump(t *testing.T) {
	skipLongInShortMode(t)
	config := params.TestXDPoSMockChainConfig
	end := int(config.XDPoS.Epoch)*3 - common.MergeSignRange
	blockchain, _, _, _, _ := PrepareXDCTestBlockChainWithPenaltyForV2Engine(t, int(config.XDPoS.Epoch)*3, config)
	adaptor := blockchain.Engine().(*XDPoS.XDPoS)
	hooks.AttachConsensusV2Hooks(adaptor, blockchain, config)
	assert.NotNil(t, adaptor.EngineV2.HookPenalty)
	var extraField types.ExtraFields_v2
	// 901 is the first v2 block
	header901 := blockchain.GetHeaderByNumber(config.XDPoS.Epoch + 1)
	err := utils.DecodeBytesExtraFields(header901.Extra, &extraField)
	assert.Nil(t, err)
	masternodes := adaptor.GetMasternodesFromCheckpointHeader(header901)
	assert.Equal(t, 5, len(masternodes))
	header2685 := blockchain.GetHeaderByNumber(uint64(end))
	adaptor.EngineV2.SetNewRoundFaker(blockchain, types.Round(config.XDPoS.Epoch*3), false)
	// Before the penalty upgrade, comeback still uses the historical
	// LimitPenaltyEpochV2 constant, so the prior penalty is already eligible.
	penalty, err := adaptor.EngineV2.HookPenalty(blockchain, header2685.Number, header2685.ParentHash, masternodes)
	assert.Nil(t, err)
	assert.Equal(t, 2, len(penalty))
}

// Test calculate penalty under startRange blocks, currently is 150
func TestHookPenaltyV2LessThen150Blocks(t *testing.T) {
	skipLongInShortMode(t)
	config := params.TestXDPoSMockChainConfig
	blockchain, _, _, _, _ := PrepareXDCTestBlockChainWithPenaltyForV2Engine(t, int(config.XDPoS.Epoch)*3, config)
	adaptor := blockchain.Engine().(*XDPoS.XDPoS)
	hooks.AttachConsensusV2Hooks(adaptor, blockchain, config)
	assert.NotNil(t, adaptor.EngineV2.HookPenalty)
	var extraField types.ExtraFields_v2
	// 901 is the first v2 block
	header901 := blockchain.GetHeaderByNumber(config.XDPoS.Epoch + 1)
	err := utils.DecodeBytesExtraFields(header901.Extra, &extraField)
	assert.Nil(t, err)
	masternodes := adaptor.GetMasternodesFromCheckpointHeader(header901)
	assert.Equal(t, 5, len(masternodes))
	header1900 := blockchain.GetHeaderByNumber(1900)
	adaptor.EngineV2.SetNewRoundFaker(blockchain, types.Round(config.XDPoS.Epoch*3), false)
	// The pre-upgrade comeback window remains pinned to the historical
	// LimitPenaltyEpochV2 constant, so the prior penalty can still return here.
	penalty, err := adaptor.EngineV2.HookPenalty(blockchain, header1900.Number, header1900.ParentHash, masternodes)
	assert.Nil(t, err)
	assert.Equal(t, 2, len(penalty))
}

// TestGetPenalties tests get penalties.
func TestGetPenalties(t *testing.T) {
	skipLongInShortMode(t)
	config := params.TestXDPoSMockChainConfig
	blockchain, _, _, _, _ := PrepareXDCTestBlockChainWithPenaltyForV2Engine(t, int(config.XDPoS.Epoch)*3, config)
	adaptor := blockchain.Engine().(*XDPoS.XDPoS)

	header2699 := blockchain.GetHeaderByNumber(2699)
	header1801 := blockchain.GetHeaderByNumber(1801)

	penalty2699 := adaptor.EngineV2.GetPenalties(blockchain, header2699)
	penalty1801 := adaptor.EngineV2.GetPenalties(blockchain, header1801)

	assert.Equal(t, 1, len(penalty2699))
	assert.Equal(t, 1, len(penalty1801))
}

// TestHookPenaltyParolee tests that a penalty stays enough epoch, it will not be penalty.
// but if it does not stays enough, it will still be penalty.
func TestHookPenaltyParolee(t *testing.T) {
	skipLongInShortMode(t)
	b, err := json.Marshal(params.TestXDPoSMockChainConfig)
	assert.Nil(t, err)

	var config params.ChainConfig
	err = json.Unmarshal(b, &config)
	assert.Nil(t, err)
	b, err = json.Marshal(config)
	assert.Nil(t, err)
	err = json.Unmarshal(b, &config)
	assert.Nil(t, err)

	blockchain, _, _, signer, signFn := PrepareXDCTestBlockChainWithPenaltyForV2Engine(t, int(config.XDPoS.Epoch)*4, &config)
	adaptor := blockchain.Engine().(*XDPoS.XDPoS)
	hooks.AttachConsensusV2Hooks(adaptor, blockchain, &config)
	assert.NotNil(t, adaptor.EngineV2.HookPenalty)
	var extraField types.ExtraFields_v2
	// 901 is the first v2 block
	header901 := blockchain.GetHeaderByNumber(config.XDPoS.Epoch + 1)
	err = utils.DecodeBytesExtraFields(header901.Extra, &extraField)
	assert.Nil(t, err)
	masternodes := adaptor.GetMasternodesFromCheckpointHeader(header901)
	assert.Equal(t, 5, len(masternodes))
	header2700 := blockchain.GetHeaderByNumber(config.XDPoS.Epoch * 3)
	header2685 := blockchain.GetHeaderByNumber(config.XDPoS.Epoch*3 - common.MergeSignRange)
	// forcely insert signing tx into cache, to cancel comeback. since no comeback, penalty is 1
	tx, err := signingTxWithSignerFn(header2685, 0, signer, signFn)
	assert.Nil(t, err)
	adaptor.CacheSigningTxs(header2685.Hash(), []*types.Transaction{tx})
	penalty, err := adaptor.EngineV2.HookPenalty(blockchain, big.NewInt(int64(config.XDPoS.Epoch*3)), header2700.ParentHash, masternodes)
	assert.Nil(t, err)
	// 2700 not trigger parole yet
	assert.Equal(t, 1, len(penalty))
	header3600 := blockchain.GetHeaderByNumber(config.XDPoS.Epoch * 4)
	penalty, err = adaptor.EngineV2.HookPenalty(blockchain, big.NewInt(int64(config.XDPoS.Epoch*4)), header3600.ParentHash, masternodes)
	assert.Nil(t, err)
	// The legacy pre-upgrade comeback logic is already eligible here, so the
	// prior penalty still appears unless the signer proves itself in range.
	assert.Equal(t, 2, len(penalty))
	header3585 := blockchain.GetHeaderByNumber(config.XDPoS.Epoch*4 - common.MergeSignRange)
	// Force a signing tx into the legacy comeback window so the prior penalty is removed.
	tx, err = signingTxWithSignerFn(header3585, 0, signer, signFn)
	assert.Nil(t, err)
	adaptor.CacheSigningTxs(header3585.Hash(), []*types.Transaction{tx})
	penalty, err = adaptor.EngineV2.HookPenalty(blockchain, big.NewInt(int64(config.XDPoS.Epoch*4)), header3600.ParentHash, masternodes)
	assert.Nil(t, err)
	assert.Equal(t, 1, len(penalty))

	header3570 := blockchain.GetHeaderByNumber(config.XDPoS.Epoch*4 - common.MergeSignRange*2)
	// forcely insert signing tx into cache, to cancel comeback. since no comeback, penalty is 1
	tx, err = signingTxWithSignerFn(header3570, 0, signer, signFn)
	assert.Nil(t, err)
	adaptor.CacheSigningTxs(header3570.Hash(), []*types.Transaction{tx})
	penalty, err = adaptor.EngineV2.HookPenalty(blockchain, big.NewInt(int64(config.XDPoS.Epoch*4)), header3600.ParentHash, masternodes)
	assert.Nil(t, err)
	assert.Equal(t, 1, len(penalty))

}

// TestHookPenaltyParoleePerformance tests hook penalty parolee performance.
func TestHookPenaltyParoleePerformance(t *testing.T) {
	skipLongInShortMode(t)
	b, err := json.Marshal(params.TestXDPoSMockChainConfig)
	assert.Nil(t, err)
	configString := string(b)

	var config params.ChainConfig
	err = json.Unmarshal([]byte(configString), &config)
	assert.Nil(t, err)
	b, err = json.Marshal(config)
	assert.Nil(t, err)
	err = json.Unmarshal(b, &config)
	assert.Nil(t, err)

	// 900 1800 2700 3600(not) 4500 5400 has penalty except 3600
	penaltyOrNot := []bool{true, true, true, false, true, true}
	blockchain, _, _, signer, signFn := PrepareXDCTestBlockChainWithPenaltyCustomized(t, int(config.XDPoS.Epoch)*7, &config, penaltyOrNot)
	adaptor := blockchain.Engine().(*XDPoS.XDPoS)
	hooks.AttachConsensusV2Hooks(adaptor, blockchain, &config)
	assert.NotNil(t, adaptor.EngineV2.HookPenalty)
	var extraField types.ExtraFields_v2
	// 901 is the first v2 block
	header901 := blockchain.GetHeaderByNumber(config.XDPoS.Epoch + 1)
	err = utils.DecodeBytesExtraFields(header901.Extra, &extraField)
	assert.Nil(t, err)
	masternodes := adaptor.GetMasternodesFromCheckpointHeader(header901)
	assert.Equal(t, 5, len(masternodes))

	header6285 := blockchain.GetHeaderByNumber(config.XDPoS.Epoch*7 - common.MergeSignRange)
	// forcely insert signing tx into cache, to cancel comeback
	tx, err := signingTxWithSignerFn(header6285, 0, signer, signFn)
	assert.Nil(t, err)
	adaptor.CacheSigningTxs(header6285.Hash(), []*types.Transaction{tx})
	header6270 := blockchain.GetHeaderByNumber(config.XDPoS.Epoch*7 - common.MergeSignRange*2)
	// forcely insert signing tx into cache, to cancel comeback
	tx, err = signingTxWithSignerFn(header6270, 0, signer, signFn)
	assert.Nil(t, err)
	adaptor.CacheSigningTxs(header6270.Hash(), []*types.Transaction{tx})

	header6300 := blockchain.GetHeaderByNumber(config.XDPoS.Epoch * 7)
	penalty, err := adaptor.EngineV2.HookPenalty(blockchain, big.NewInt(int64(config.XDPoS.Epoch*7)), header6300.ParentHash, masternodes)
	assert.Nil(t, err)
	// The cached signing txs cancel the comeback path, so only the missing miner remains penalized.
	assert.Equal(t, 1, len(penalty))

}

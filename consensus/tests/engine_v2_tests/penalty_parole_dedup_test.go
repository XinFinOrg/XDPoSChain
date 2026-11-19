package engine_v2_tests

import (
	"encoding/json"
	"math/big"
	"slices"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS/utils"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/eth/hooks"
	"github.com/XinFinOrg/XDPoSChain/internal/testshort"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/stretchr/testify/assert"
)

// TestHookPenaltyParoleCountsDistinctSignedBlocks checks that, after
// TIPUpgradePenalty, a penalised candidate's signing transactions count toward
// the parole threshold once per signed block: repeated signatures of one block
// do not add up, distinct signed blocks do.
func TestHookPenaltyParoleCountsDistinctSignedBlocks(t *testing.T) {
	t.Parallel()
	testshort.Skip(t)
	b, err := json.Marshal(params.TestXDPoSMockChainConfig)
	assert.Nil(t, err)
	var config params.ChainConfig
	err = json.Unmarshal(b, &config)
	assert.Nil(t, err)

	epoch := config.XDPoS.Epoch
	// The test signer is penalised in every epoch, so it is a parolee by the
	// last checkpoint of the chain.
	blockchain, _, _, signer, signFn := PrepareXDCTestBlockChainWithPenaltyCustomized(t, int(epoch)*4, &config, nil)
	// The chain is built on its own copy of the config with the fork pushed out;
	// the parole rule under test is the one after TIPUpgradePenalty.
	blockchain.Config().TIPUpgradePenaltyBlock = big.NewInt(0)
	adaptor := blockchain.Engine().(*XDPoS.XDPoS)
	hooks.AttachConsensusV2Hooks(adaptor, blockchain, blockchain.Config())

	header901 := blockchain.GetHeaderByNumber(epoch + 1)
	masternodes := adaptor.GetMasternodesFromCheckpointHeader(header901)
	checkpoint := blockchain.GetHeaderByNumber(epoch * 4)
	number := big.NewInt(int64(epoch * 4))
	var extraField types.ExtraFields_v2
	err = utils.DecodeBytesExtraFields(checkpoint.Extra, &extraField)
	assert.Nil(t, err)
	minSigning := adaptor.EngineV2.Config(uint64(extraField.Round)).MinimumSigningTx
	if minSigning < 2 {
		t.Fatalf("test needs a parole threshold of at least 2 signing txs, have %d", minSigning)
	}

	penalised := func() bool {
		t.Helper()
		penalty, err := adaptor.EngineV2.HookPenalty(blockchain, number, checkpoint.ParentHash, masternodes)
		assert.Nil(t, err)
		return slices.Contains(penalty, signer)
	}
	assert.True(t, penalised(), "a parolee that signed nothing must stay penalised")

	// The threshold in signing txs, all for the same block.
	signed := blockchain.GetHeaderByNumber(epoch*4 - common.MergeSignRange)
	repeated := make([]*types.Transaction, 0, minSigning)
	for nonce := range uint64(minSigning) {
		tx, err := signingTxWithSignerFn(signed, nonce, signer, signFn)
		assert.Nil(t, err)
		repeated = append(repeated, tx)
	}
	adaptor.CacheSigningTxs(signed.Hash(), repeated)
	assert.True(t, penalised(), "repeated signatures of one block must count once toward parole")

	// One signing tx for each of threshold-1 further blocks reaches the threshold.
	for i := 2; i <= minSigning; i++ {
		signed := blockchain.GetHeaderByNumber(epoch*4 - common.MergeSignRange*uint64(i))
		tx, err := signingTxWithSignerFn(signed, uint64(minSigning+i), signer, signFn)
		assert.Nil(t, err)
		adaptor.CacheSigningTxs(signed.Hash(), []*types.Transaction{tx})
	}
	assert.False(t, penalised(), "signatures of distinct blocks reaching the threshold must release the parolee")
}

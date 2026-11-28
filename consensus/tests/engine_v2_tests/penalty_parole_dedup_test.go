package engine_v2_tests

import (
	"encoding/json"
	"math/big"
	"slices"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/accounts"
	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS/utils"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/eth/hooks"
	"github.com/XinFinOrg/XDPoSChain/internal/testshort"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/stretchr/testify/assert"
)

// paroleFixture is a chain whose test signer is a parolee at the last
// checkpoint, with the parole rule after TIPUpgradePenalty in force.
type paroleFixture struct {
	blockchain *core.BlockChain
	adaptor    *XDPoS.XDPoS
	signer     common.Address
	signFn     func(account accounts.Account, hash []byte) ([]byte, error)
	epoch      uint64
	minSigning int
	penalised  func() bool
}

func newParoleFixture(t *testing.T) *paroleFixture {
	t.Helper()
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

	f := &paroleFixture{
		blockchain: blockchain,
		adaptor:    adaptor,
		signer:     signer,
		signFn:     signFn,
		epoch:      epoch,
		minSigning: minSigning,
	}
	f.penalised = func() bool {
		t.Helper()
		penalty, err := adaptor.EngineV2.HookPenalty(blockchain, number, checkpoint.ParentHash, masternodes)
		assert.Nil(t, err)
		return slices.Contains(penalty, signer)
	}
	assert.True(t, f.penalised(), "a parolee that signed nothing must stay penalised")
	return f
}

// TestHookPenaltyParoleCountsDistinctSignedBlocks checks that, after
// TIPUpgradePenalty, a penalised candidate's signing transactions count toward
// the parole threshold once per signed block: repeated signatures of one block
// do not add up, distinct signed blocks do.
func TestHookPenaltyParoleCountsDistinctSignedBlocks(t *testing.T) {
	t.Parallel()
	testshort.Skip(t)
	f := newParoleFixture(t)
	epoch, minSigning := f.epoch, f.minSigning

	// The threshold in signing txs, all for the same block.
	signed := f.blockchain.GetHeaderByNumber(epoch*4 - common.MergeSignRange)
	repeated := make([]*types.Transaction, 0, minSigning)
	for nonce := range uint64(minSigning) {
		tx, err := signingTxWithSignerFn(signed, nonce, f.signer, f.signFn)
		assert.Nil(t, err)
		repeated = append(repeated, tx)
	}
	f.adaptor.CacheSigningTxs(signed.Hash(), repeated)
	assert.True(t, f.penalised(), "repeated signatures of one block must count once toward parole")

	// One signing tx for each of threshold-1 further blocks reaches the threshold.
	for i := 2; i <= minSigning; i++ {
		signed := f.blockchain.GetHeaderByNumber(epoch*4 - common.MergeSignRange*uint64(i))
		tx, err := signingTxWithSignerFn(signed, uint64(minSigning+i), f.signer, f.signFn)
		assert.Nil(t, err)
		f.adaptor.CacheSigningTxs(signed.Hash(), []*types.Transaction{tx})
	}
	assert.False(t, f.penalised(), "signatures of distinct blocks reaching the threshold must release the parolee")
}

// TestHookPenaltyParoleCountsDuplicateInLaterBlock is the chain-shaped variant
// of the test above: a signing tx is included in a block after the one it
// signs, and the repeated signature of the same block lands in a later block
// than the first one.
func TestHookPenaltyParoleCountsDuplicateInLaterBlock(t *testing.T) {
	t.Parallel()
	testshort.Skip(t)
	f := newParoleFixture(t)
	epoch, minSigning := f.epoch, f.minSigning

	// Signing txs per including block, cached once all are placed.
	included := map[uint64][]*types.Transaction{}
	nonce := uint64(0)
	include := func(signedNumber, inBlock uint64) {
		t.Helper()
		assert.Greater(t, inBlock, signedNumber, "a signing tx is included after the block it signs")
		assert.Less(t, inBlock, epoch*4, "the including block must be in the scanned epoch")
		tx, err := signingTxWithSignerFn(f.blockchain.GetHeaderByNumber(signedNumber), nonce, f.signer, f.signFn)
		assert.Nil(t, err)
		nonce++
		included[inBlock] = append(included[inBlock], tx)
	}
	cache := func() {
		t.Helper()
		for number, txs := range included {
			f.adaptor.CacheSigningTxs(f.blockchain.GetHeaderByNumber(number).Hash(), txs)
		}
	}

	// The threshold in signing txs for one block: the first in the next block,
	// each repeat in a later block than the previous one.
	signed := epoch*4 - common.MergeSignRange*uint64(minSigning+1)
	for i := 1; i <= minSigning; i++ {
		include(signed, signed+uint64(i))
	}
	cache()
	assert.True(t, f.penalised(), "a repeated signature in a later block must not count again toward parole")

	// Threshold-1 further distinct blocks, each signed in its next block, reach the threshold.
	for i := 1; i < minSigning; i++ {
		other := epoch*4 - common.MergeSignRange*uint64(i)
		include(other, other+1)
	}
	cache()
	assert.False(t, f.penalised(), "signatures of distinct blocks reaching the threshold must release the parolee")
}

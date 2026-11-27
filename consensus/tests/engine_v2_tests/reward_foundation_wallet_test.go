package engine_v2_tests

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/eth/hooks"
	"github.com/XinFinOrg/XDPoSChain/internal/testshort"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHookRewardV2FoundationWalletRotation checks that the foundation share
// goes to the old wallet at checkpoints before TIPFoundationWalletBlock and to
// the new wallet from that block on, and that nothing else in the split moves.
func TestHookRewardV2FoundationWalletRotation(t *testing.T) {
	t.Parallel()
	testshort.Skip(t)
	b, err := json.Marshal(params.TestXDPoSMockChainConfig)
	require.NoError(t, err)
	var config params.ChainConfig
	require.NoError(t, json.Unmarshal(b, &config))
	config.XDPoS.V2.SwitchBlock.SetUint64(1800)

	epoch := config.XDPoS.Epoch
	oldWallet := config.XDPoS.FoundationWalletAddr
	newWallet := common.HexToAddress("0x00000000000000000000000000000000000f0a0d")
	config.TIPFoundationWalletBlock = new(big.Int).SetUint64(epoch * 4)
	config.XDPoS.NewFoundationWalletAddr = newWallet

	blockchain, _, _, signer, signFn, _ := PrepareXDCTestBlockChainForV2Engine(t, int(epoch)*5, &config, nil)
	adaptor := blockchain.Engine().(*XDPoS.XDPoS)
	hooks.AttachConsensusV2Hooks(adaptor, blockchain, &config)

	ownerShare, _ := new(big.Int).SetString("225000000000000000000", 10)
	foundationShare, _ := new(big.Int).SetString("25000000000000000000", 10)

	payAt := func(signedAt, includedAt, checkpoint uint64) (map[common.Address]*big.Int, common.Address, *big.Int, *big.Int) {
		t.Helper()
		tx, err := signingTxWithSignerFn(blockchain.GetHeaderByNumber(signedAt), 0, signer, signFn)
		require.NoError(t, err)
		adaptor.CacheSigningTxs(blockchain.GetHeaderByNumber(includedAt).Hash(), []*types.Transaction{tx})
		statedb, err := blockchain.StateAt(blockchain.GetHeaderByNumber(checkpoint - 1).Root)
		require.NoError(t, err)
		parentState := statedb.Copy()
		oldBefore := new(big.Int).Set(statedb.GetBalance(oldWallet))
		newBefore := new(big.Int).Set(statedb.GetBalance(newWallet))
		reward, err := adaptor.EngineV2.HookReward(blockchain, statedb, parentState, blockchain.GetHeaderByNumber(checkpoint))
		require.NoError(t, err)
		result := reward["rewards"].(map[common.Address]interface{})
		require.Len(t, result, 1)
		var split map[common.Address]*big.Int
		for _, x := range result {
			split = x.(map[common.Address]*big.Int)
		}
		oldDelta := new(big.Int).Sub(new(big.Int).Set(statedb.GetBalance(oldWallet)), oldBefore)
		newDelta := new(big.Int).Sub(new(big.Int).Set(statedb.GetBalance(newWallet)), newBefore)
		return split, parentState.GetCandidateOwner(signer), oldDelta, newDelta
	}

	// Checkpoint 2700 is before the fork: the old wallet is paid.
	split, owner, oldDelta, newDelta := payAt(epoch+15, epoch+16, epoch*3)
	assert.Zero(t, ownerShare.Cmp(split[owner]))
	assert.Zero(t, foundationShare.Cmp(split[oldWallet]))
	assert.NotContains(t, split, newWallet)
	assert.Zero(t, foundationShare.Cmp(oldDelta))
	assert.Zero(t, newDelta.Sign())

	// Checkpoint 3600 is the fork block: the new wallet is paid instead.
	split, owner, oldDelta, newDelta = payAt(epoch*2+885, epoch*3+16, epoch*4)
	assert.Zero(t, ownerShare.Cmp(split[owner]))
	assert.Zero(t, foundationShare.Cmp(split[newWallet]))
	assert.NotContains(t, split, oldWallet)
	assert.Zero(t, oldDelta.Sign())
	assert.Zero(t, foundationShare.Cmp(newDelta))
}

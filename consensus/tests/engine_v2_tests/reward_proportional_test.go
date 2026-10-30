package engine_v2_tests

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/eth/hooks"
	"github.com/XinFinOrg/XDPoSChain/eth/util"
	"github.com/XinFinOrg/XDPoSChain/internal/testshort"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHookRewardProportional drives HookReward across the TIPProportionalReward
// fork. The shared V2 helper keeps TIPFixedRewardBlock in the future, so the
// proportional run also checks that the fork works without TIPFixedReward. The
// rewarded epoch for header4500 is [2701, 3599]; signers sign a known subset of
// its sign slots, and every role must be paid perNodeReward * sign / signSlots.
// The same signing set is then rewarded with only TIPFixedReward active, which
// must pay the full per-node reward and leave signSlots out of the result.
func TestHookRewardProportional(t *testing.T) {
	testshort.Skip(t)
	b, err := json.Marshal(params.TestXDPoSMockChainConfig)
	assert.Nil(t, err)
	var config params.ChainConfig
	err = json.Unmarshal(b, &config)
	assert.Nil(t, err)
	// set switch to 1800, so that it covers 901-1799, 1800-2700 two epochs
	config.XDPoS.V2.SwitchBlock.SetUint64(1800)
	config.XDPoS.V2.SwitchEpoch = 2
	b, err = json.Marshal(config)
	assert.Nil(t, err)
	err = json.Unmarshal(b, &config)
	assert.Nil(t, err)

	epoch := config.XDPoS.Epoch // 900
	blockchain, _, _, signer, signFn := PrepareXDCTestBlockChainWithProtectorObserver(t, int(epoch)*5+10, &config)
	require.NotNil(t, blockchain.Config().TIPFixedRewardBlock)
	require.False(t, blockchain.Config().IsTIPFixedReward(big.NewInt(int64(epoch)*5)), "helper must keep TIPFixedReward off")

	adaptor := blockchain.Engine().(*XDPoS.XDPoS)
	hooks.AttachConsensusV2Hooks(adaptor, blockchain, &config)
	require.NotNil(t, adaptor.EngineV2.HookReward)

	header2700 := blockchain.GetHeaderByNumber(epoch * 3)
	header3599 := blockchain.GetHeaderByNumber(epoch*4 - 1)
	header4499 := blockchain.GetHeaderByNumber(epoch*5 - 1)
	header4500 := blockchain.GetHeaderByNumber(epoch * 5)

	var slots []*types.Header
	for i := uint64(2701); i <= 3599; i++ {
		if i%common.MergeSignRange == 0 {
			slots = append(slots, blockchain.GetHeaderByNumber(i))
		}
	}
	signSlots := uint64(len(slots))
	require.Equal(t, uint64(59), signSlots)

	masternodes := adaptor.GetMasternodesFromCheckpointHeader(header2700)
	round4500, err := adaptor.EngineV2.GetRoundNumber(header4500)
	require.Nil(t, err)
	currentConfig := adaptor.EngineV2.Config(uint64(round4500))
	standbyPool := adaptor.EngineV2.GetStandbynodes(blockchain, header2700)
	protectorEnd := min(currentConfig.MaxProtectorNodes, len(standbyPool))
	observerEnd := min(protectorEnd+currentConfig.MaxObserverNodes, len(standbyPool))
	require.Contains(t, masternodes, signer)
	require.Contains(t, masternodes, acc1Addr)
	require.Contains(t, standbyPool[:protectorEnd], protector1Addr)
	require.Contains(t, standbyPool[:protectorEnd], protector2Addr)
	require.Contains(t, standbyPool[protectorEnd:observerEnd], observer2Addr)

	// Signing counts per address: signer and protector1 sign every slot, the
	// others a known subset.
	var txs []*types.Transaction
	wantSign := map[common.Address]uint64{signer: signSlots, protector1Addr: signSlots}
	for i, h := range slots {
		tx, err := signingTxWithSignerFn(h, 0, signer, signFn)
		require.Nil(t, err)
		txs = append(txs, tx)
		tx, err = signingTxWithKey(h, 0, protector1Key)
		require.Nil(t, err)
		txs = append(txs, tx)
		if i%2 == 0 {
			tx, err = signingTxWithKey(h, 0, acc1Key)
			require.Nil(t, err)
			txs = append(txs, tx)
			wantSign[acc1Addr]++
		}
		if i < 20 {
			tx, err = signingTxWithKey(h, 0, protector2Key)
			require.Nil(t, err)
			txs = append(txs, tx)
			wantSign[protector2Addr]++
		}
		if i%2 == 1 {
			tx, err = signingTxWithKey(h, 0, observer2Key)
			require.Nil(t, err)
			txs = append(txs, tx)
			wantSign[observer2Addr]++
		}
	}
	// A duplicate signing tx in the same slot must not be counted twice.
	dup, err := signingTxWithKey(slots[0], 0, protector2Key)
	require.Nil(t, err)
	txs = append(txs, dup)
	adaptor.CacheSigningTxs(header3599.Hash(), txs)

	perNodeReward := func(r float64) *big.Int {
		f := new(big.Float).Mul(new(big.Float).SetFloat64(r), new(big.Float).SetUint64(params.Ether))
		v, _ := f.Int(nil)
		return util.RewardInflation(blockchain, v, header4500.Number.Uint64(), common.BlocksPerYear)
	}
	roles := []struct {
		signersKey string
		rewardsKey string
		perNode    *big.Int
	}{
		{"signers", "rewards", perNodeReward(currentConfig.MasternodeReward)},
		{"signersProtector", "rewardsProtector", perNodeReward(currentConfig.ProtectorReward)},
		{"signersObserver", "rewardsObserver", perNodeReward(currentConfig.ObserverReward)},
	}
	sumHolderRewards := func(reward map[string]interface{}) *big.Int {
		sum := new(big.Int)
		for _, role := range roles {
			for _, holders := range reward[role.rewardsKey].(map[common.Address]interface{}) {
				for _, v := range holders.(map[common.Address]*big.Int) {
					sum.Add(sum, v)
				}
			}
		}
		return sum
	}

	// Proportional run: TIPProportionalReward on, TIPFixedReward off.
	blockchain.Config().TIPProportionalRewardBlock = big.NewInt(0)
	statedb, err := blockchain.StateAt(header4499.Root)
	require.Nil(t, err)
	reward, err := adaptor.EngineV2.HookReward(blockchain, statedb, statedb.Copy(), header4500)
	require.Nil(t, err)
	assert.Equal(t, signSlots, reward["signSlots"])
	checked := 0
	for _, role := range roles {
		signers := reward[role.signersKey].(map[common.Address]*hooks.RewardLog)
		for addr, rLog := range signers {
			want, ok := wantSign[addr]
			require.True(t, ok, "unexpected signer %s in %s", addr.Hex(), role.signersKey)
			assert.Equal(t, want, rLog.Sign, "sign count of %s", addr.Hex())
			expected := new(big.Int).Mul(role.perNode, new(big.Int).SetUint64(rLog.Sign))
			expected.Div(expected, new(big.Int).SetUint64(signSlots))
			assert.Zero(t, expected.Cmp(rLog.Reward), "%s reward: have %v want %v", addr.Hex(), rLog.Reward, expected)
			checked++
		}
	}
	assert.Equal(t, len(wantSign), checked)
	epochNum := config.XDPoS.V2.SwitchEpoch + uint64(round4500)/epoch
	assert.Zero(t, sumHolderRewards(reward).Cmp(statedb.GetPostMinted(epochNum).Big()), "PostMinted must equal what was actually paid")

	// Fixed run: only TIPFixedReward on.
	blockchain.Config().TIPProportionalRewardBlock = nil
	blockchain.Config().TIPFixedRewardBlock = big.NewInt(0)
	statedb, err = blockchain.StateAt(header4499.Root)
	require.Nil(t, err)
	reward, err = adaptor.EngineV2.HookReward(blockchain, statedb, statedb.Copy(), header4500)
	require.Nil(t, err)
	_, hasSignSlots := reward["signSlots"]
	assert.False(t, hasSignSlots)
	for _, role := range roles {
		for addr, rLog := range reward[role.signersKey].(map[common.Address]*hooks.RewardLog) {
			assert.Zero(t, role.perNode.Cmp(rLog.Reward), "%s fixed reward: have %v want %v", addr.Hex(), rLog.Reward, role.perNode)
		}
	}
}

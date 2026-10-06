package engine_v2_tests

import (
	"encoding/json"
	"fmt"
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/eth/hooks"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/stretchr/testify/assert"
)

// voteTXForCandidateWithAmount is voteTX (see helper.go) parameterized by the
// vote amount, so a test can move a candidate's stake by more than the fixed
// 60000 wei voteTX always sends.
func voteTXForCandidateWithAmount(gasLimit uint64, nonce uint64, addr string, amount *big.Int) (*types.Transaction, error) {
	vote := "6dd7d8ea" // VoteMethod = "0x6dd7d8ea"
	action := fmt.Sprintf("%s%s%s", vote, "000000000000000000000000", addr[3:])
	data := common.Hex2Bytes(action)
	gasPrice := big.NewInt(0)
	to := common.MasternodeVotingSMCBinary
	tx := types.NewTransaction(nonce, to, amount, gasLimit, gasPrice, data)

	return types.SignTx(tx, types.LatestSignerForChainID(big.NewInt(chainID)), voterKey)
}

// TestGetSigningTxCountUsesHistoricalStandbynodes covers the fix in commit
// 4de9fc4278a325a57824d7b66d330fe50de564bd ("fix(reward): use getStandby node
// to get same state of masternode set").
//
// Before the fix, GetSigningTxCount computed the protector/observer pool for
// a historical reward epoch by reading candidate stake from the CURRENT tip
// state (parentState.GetCandidates()), even though the epoch being rewarded
// is two epoch-switches in the past. After the fix, it reads
// c.GetStandbynodes(chain, h), which is derived from h's own historical
// snapshot and does not move when later votes change candidate stakes.
//
// This test drives that divergence directly: it casts a large vote for
// observer2Addr *after* the historical epoch's snapshot has already been
// taken (i.e. after the gap block for the epoch starting at header2700), but
// before the tip state used by the old code is read (at header4499). That
// vote is big enough to flip which candidates land in the protector vs
// observer tier if (and only if) tip-state, rather than historical
// snapshot state, is used to rank them.
//
// The expected split is computed independently via
// adaptor.EngineV2.GetStandbynodes(blockchain, h) plus the same min()-based
// tiering api.go's splitStandbyPool uses, so the test is self-checking
// against the fixed code's own documented contract rather than hardcoded
// magic addresses.
func TestGetSigningTxCountUsesHistoricalStandbynodes(t *testing.T) {
	skipLongInShortMode(t)
	b, err := json.Marshal(params.TestXDPoSMockChainConfig)
	assert.Nil(t, err)
	configString := string(b)

	var config params.ChainConfig
	err = json.Unmarshal([]byte(configString), &config)
	assert.Nil(t, err)
	// set switch to 1800, so that it covers 901-1799, 1800-2700 two epochs
	config.XDPoS.V2.SwitchBlock.SetUint64(1800)
	config.XDPoS.V2.SwitchEpoch = 2
	b, err = json.Marshal(config)
	assert.Nil(t, err)
	err = json.Unmarshal(b, &config)
	assert.Nil(t, err)

	epoch := config.XDPoS.Epoch // 900
	numOfBlocks := int(epoch)*5 + 10

	// Build the chain up to (and including) block 2999: this covers the gap
	// block (2250) whose contract-state snapshot backs header2700's
	// standby pool, and header2700 itself.
	blockchain, _, currentBlock, signer, signFn := PrepareXDCTestBlockChainWithProtectorObserver(t, 2999, &config)

	// The shared V2 test helper (legacyExecutionConfigForV2Tests) forces
	// TIPUpgradeRewardBlock far into the future on the config it actually
	// builds the chain with, regardless of what the caller set beforehand
	// (AttachConsensusV2Hooks's chainConfig parameter is unused; HookReward
	// always reads chain.Config(), i.e. blockchain.Config()). Flip it back on
	// here so the protector/observer branch this commit touches is actually
	// exercised, which is why the existing TestHookRewardAfterUpgrade /
	// TestFinalizeAfterUpgrade never exercise it.
	blockchain.Config().TIPUpgradeRewardBlock = big.NewInt(0)

	// Insert one hand-built block at 3000 containing a real vote transaction
	// that raises observer2Addr's stake by 1e9 (from 999999 to ~1.001e9),
	// pushing it above the pack of masternode-cap (1e9) candidates. This
	// happens strictly after the gap block (2250) backing header2700's
	// snapshot, so the fixed code (which reads that frozen snapshot) must
	// not see it, while the pre-fix code (which read live tip state) would.
	voteAmount := big.NewInt(1_000_000_000)
	voteTx, err := voteTXForCandidateWithAmount(200000, 0, observer2Addr.String(), voteAmount)
	assert.Nil(t, err)

	roundNumber3000 := int64(3000) - config.XDPoS.V2.SwitchBlock.Int64()
	header3000 := &types.Header{
		Root:       common.HexToHash("f5f180a2b7822fae18ce6d295a5c08d0315db5a96c8f3738303e320b6646b81c"),
		Number:     big.NewInt(3000),
		ParentHash: currentBlock.Hash(),
		Coinbase:   common.HexToAddress(signer.Hex()),
		Extra:      generateV2Extra(roundNumber3000, currentBlock, signer, signFn, nil),
	}
	block3000, err := createBlockFromHeader(blockchain, header3000, []*types.Transaction{voteTx}, signer, signFn, &config)
	assert.Nil(t, err)
	err = blockchain.InsertBlock(block3000)
	assert.Nil(t, err)
	currentBlock = block3000

	// Continue building the rest of the chain (3001..numOfBlocks) the same
	// way PrepareXDCTestBlockChainWithProtectorObserver's own loop does,
	// past the vote block. No further penalties or "first v2 block" special
	// cases apply beyond block 2999.
	for i := 3001; i <= numOfBlocks; i++ {
		roundNumber := int64(i) - config.XDPoS.V2.SwitchBlock.Int64()
		block := CreateBlock(blockchain, &config, currentBlock, i, roundNumber, signer.Hex(), signer, signFn, nil, nil, "f5f180a2b7822fae18ce6d295a5c08d0315db5a96c8f3738303e320b6646b81c")
		err = blockchain.InsertBlock(block)
		assert.Nil(t, err)
		currentBlock = block
	}

	adaptor := blockchain.Engine().(*XDPoS.XDPoS)
	hooks.AttachConsensusV2Hooks(adaptor, blockchain, &config)
	assert.NotNil(t, adaptor.EngineV2.HookReward)

	header2700 := blockchain.GetHeaderByNumber(epoch * 3)
	header2715 := blockchain.GetHeaderByNumber(epoch*3 + 15)
	header3585 := blockchain.GetHeaderByNumber(epoch*4 - 15)
	header3599 := blockchain.GetHeaderByNumber(epoch*4 - 1)
	header4499 := blockchain.GetHeaderByNumber(epoch*5 - 1)
	header4500 := blockchain.GetHeaderByNumber(epoch * 5)
	assert.NotNil(t, header2700)
	assert.NotNil(t, header4500)

	// Each of the four keys signs once inside the reward epoch [2701,3599].
	// Cache them under header3599's hash (itself within the walked range),
	// exactly mirroring the tx4..tx8 pattern already used by
	// TestHookRewardAfterUpgrade.
	txProtector1, err := signingTxWithKey(header2715, 0, protector1Key)
	assert.Nil(t, err)
	txProtector2, err := signingTxWithKey(header3585, 0, protector2Key)
	assert.Nil(t, err)
	txObserver1, err := signingTxWithKey(header2715, 0, observer1Key)
	assert.Nil(t, err)
	txObserver2, err := signingTxWithKey(header3585, 0, observer2Key)
	assert.Nil(t, err)
	adaptor.CacheSigningTxs(header3599.Hash(), []*types.Transaction{txProtector1, txProtector2, txObserver1, txObserver2})

	// Independently compute the expected protector/observer split for
	// header2700 from the fixed code's own documented contract: the
	// standby pool as of header2700's historical snapshot, tiered via the
	// same min()-based split GetSigningTxCount and api.go's
	// splitStandbyPool both use.
	round4500, err := adaptor.EngineV2.GetRoundNumber(header4500)
	assert.Nil(t, err)
	currentConfig := adaptor.EngineV2.Config(uint64(round4500))
	standbyPool := adaptor.EngineV2.GetStandbynodes(blockchain, header2700)
	protectorEnd := min(currentConfig.MaxProtectorNodes, len(standbyPool))
	observerEnd := min(protectorEnd+currentConfig.MaxObserverNodes, len(standbyPool))
	expectedProtector := standbyPool[:protectorEnd]
	expectedObserver := standbyPool[protectorEnd:observerEnd]

	t.Logf("standby pool for header2700: %v", standbyPool)
	t.Logf("expected protector tier: %v", expectedProtector)
	t.Logf("expected observer tier: %v", expectedObserver)

	inSlice := func(addr common.Address, list []common.Address) bool {
		for _, a := range list {
			if a == addr {
				return true
			}
		}
		return false
	}

	// Sanity-check our hand-picked signers against the independently
	// computed split, so the reward assertions below are meaningful: this
	// must reflect header2700's HISTORICAL (pre-vote) standing, unaffected
	// by the later vote for observer2Addr. On the candidate/stake state as
	// of header2700's own epoch, observer2Addr (not observer1Addr) is the
	// sole address that lands in the single observer slot; observer1Addr
	// falls just short and is not rewarded at all. protector1Addr and
	// protector2Addr are comfortably within the 17-wide protector tier.
	assert.True(t, inSlice(protector1Addr, expectedProtector), "protector1Addr expected in protector tier")
	assert.True(t, inSlice(protector2Addr, expectedProtector), "protector2Addr expected in protector tier (pre-vote standing)")
	assert.True(t, inSlice(observer2Addr, expectedObserver), "observer2Addr expected in observer tier (pre-vote standing)")
	assert.False(t, inSlice(observer1Addr, expectedProtector) || inSlice(observer1Addr, expectedObserver), "observer1Addr should not be rewarded on header2700's historical standing")

	// Now drive the actual fixed code and assert it matches.
	statedb, err := blockchain.StateAt(header4499.Root)
	assert.Nil(t, err)
	parentState := statedb.Copy()
	reward, err := adaptor.EngineV2.HookReward(blockchain, statedb, parentState, header4500)
	assert.Nil(t, err)

	signersProtector, ok := reward["signersProtector"].(map[common.Address]*hooks.RewardLog)
	assert.True(t, ok, "expected signersProtector in reward map")
	signersObserver, ok := reward["signersObserver"].(map[common.Address]*hooks.RewardLog)
	assert.True(t, ok, "expected signersObserver in reward map")

	t.Logf("actual signersProtector: %v", addrList(signersProtector))
	t.Logf("actual signersObserver: %v", addrList(signersObserver))

	// protector1Addr and protector2Addr signed and both sit in the
	// historical protector tier: they must be rewarded as protectors.
	if log, ok := signersProtector[protector1Addr]; assert.True(t, ok, "protector1Addr should be counted as a protector signer") {
		assert.Equal(t, uint64(1), log.Sign)
	}
	if log, ok := signersProtector[protector2Addr]; assert.True(t, ok, "protector2Addr should be counted as a protector signer") {
		assert.Equal(t, uint64(1), log.Sign)
	}
	// observer1Addr signed but is not part of header2700's historical
	// standby membership at all: it must not be credited to either tier.
	_, o1AsProtector := signersProtector[observer1Addr]
	_, o1AsObserver := signersObserver[observer1Addr]
	assert.False(t, o1AsProtector, "observer1Addr must not be counted as a protector signer")
	assert.False(t, o1AsObserver, "observer1Addr must not be counted as an observer signer")

	// observer2Addr signed and, on header2700's historical standing, sits
	// in the sole observer slot: it must be rewarded as an observer, not a
	// protector. If it shows up as a protector instead, that is exactly the
	// bug this commit fixes: the vote cast for observer2Addr at block 3000
	// (well after header2700's snapshot was taken, comfortably before the
	// tip state at header4499) would have promoted it into the protector
	// tier had ranking been read from the current tip instead of from
	// header2700's own historical snapshot.
	_, o2AsProtector := signersProtector[observer2Addr]
	assert.False(t, o2AsProtector, "observer2Addr must not be counted as a protector signer (that would mean tip state, not history, was used)")
	if log, ok := signersObserver[observer2Addr]; assert.True(t, ok, "observer2Addr should be counted as an observer signer") {
		assert.Equal(t, uint64(1), log.Sign)
	}
}

func addrList(m map[common.Address]*hooks.RewardLog) []common.Address {
	out := make([]common.Address, 0, len(m))
	for a := range m {
		out = append(out, a)
	}
	return out
}

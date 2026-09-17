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
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/stretchr/testify/assert"
)

// TestGetSigningTxCountObserverBoundaryTie is a whole-function regression
// test for https://github.com/XinFinOrg/XDPoSChain/pull/2577.
//
// Before the fix, GetSigningTxCount rebuilt its own protector/observer
// candidate list from parentState.GetCandidates() and ranked it with a
// STABLE sort. The fix instead reads the historical standby pool from
// GetStandbynodes, whose order comes from core.BlockChain.UpdateM1's
// xdc_sort.Slice call - which is explicitly documented as NOT stable.
//
// The shared protector/observer test fixture already contains a tie that
// straddles a tier boundary: observer1Addr and observer2Addr are deployed
// with the same (lower) stake, and MaxObserverNodes is 1, so only one of
// them can be "the" observer. Which one depends entirely on sort
// stability - this test drives the real, exported GetSigningTxCount
// against a full blockchain/state/engine and asserts its output matches
// the real production ordering (observer2Addr wins the slot), not the
// pre-fix stable-sort ordering (which would have picked observer1Addr).
func TestGetSigningTxCountObserverBoundaryTie(t *testing.T) {
	skipLongInShortMode(t)
	b, err := json.Marshal(params.TestXDPoSMockChainConfig)
	assert.Nil(t, err)
	configString := string(b)

	var config params.ChainConfig
	err = json.Unmarshal([]byte(configString), &config)
	assert.Nil(t, err)
	config.XDPoS.V2.SwitchBlock.SetUint64(1800)
	b, err = json.Marshal(config)
	assert.Nil(t, err)
	err = json.Unmarshal(b, &config)
	assert.Nil(t, err)

	// Needs 2 full v2 epochs after the switch so the reward-epoch checkpoint
	// GetSigningTxCount walks back to (h below) is itself a v2 header;
	// GetStandbynodes only works on v2 epoch-switch headers.
	blockchain, _, _, _, _ := PrepareXDCTestBlockChainWithProtectorObserver(t, int(config.XDPoS.Epoch)*5+10, &config)
	adaptor := blockchain.Engine().(*XDPoS.XDPoS)

	// Activate the reward upgrade so GetSigningTxCount exercises the
	// protector/observer branch under test.
	blockchain.Config().TIPUpgradeRewardBlock = big.NewInt(0)

	trigger := blockchain.GetHeaderByNumber(config.XDPoS.Epoch * 5)
	// h is the epoch-switch checkpoint GetSigningTxCount walks back to (2
	// reward-epochs behind trigger): the nodes it keeps, and the reward
	// window it counts signatures over, are both anchored here.
	h := blockchain.GetHeaderByNumber(config.XDPoS.Epoch * 3)

	parentStateAtTriggerParent, err := blockchain.StateAt(blockchain.GetHeaderByNumber(config.XDPoS.Epoch*5 - 1).Root)
	assert.Nil(t, err)
	parentState := parentStateAtTriggerParent.Copy()

	round, err := adaptor.EngineV2.GetRoundNumber(trigger)
	assert.Nil(t, err)
	currentConfig := adaptor.EngineV2.Config(uint64(round))

	// --- Reproduce the pre-fix ordering from the exact same raw candidate
	// list and caps GetSigningTxCount used to read directly, before this
	// fix.
	rawCandidates := parentState.GetCandidates()
	var buggyMs []utils.Masternode
	for _, c := range rawCandidates {
		if !c.IsZero() {
			buggyMs = append(buggyMs, utils.Masternode{Address: c, Stake: parentState.GetCandidateCap(c)})
		}
	}
	slices.SortStableFunc(buggyMs, func(a, b utils.Masternode) int {
		return b.Stake.Cmp(a.Stake)
	})
	excluded := map[common.Address]struct{}{}
	for _, p := range common.ExtractAddressFromBytes(h.Penalties) {
		excluded[p] = struct{}{}
	}
	for _, m := range adaptor.GetMasternodesFromCheckpointHeader(h) {
		excluded[m] = struct{}{}
	}
	var buggyStandby []common.Address
	for _, m := range buggyMs {
		if _, ok := excluded[m.Address]; !ok {
			buggyStandby = append(buggyStandby, m.Address)
		}
	}
	protectorEnd := min(currentConfig.MaxProtectorNodes, len(buggyStandby))
	observerEnd := min(protectorEnd+currentConfig.MaxObserverNodes, len(buggyStandby))
	buggyObserverTier := buggyStandby[protectorEnd:observerEnd]

	// --- The real, current production ordering.
	realStandby := adaptor.EngineV2.GetStandbynodes(blockchain, h)
	protectorEnd2 := min(currentConfig.MaxProtectorNodes, len(realStandby))
	observerEnd2 := min(protectorEnd2+currentConfig.MaxObserverNodes, len(realStandby))
	realObserverTier := realStandby[protectorEnd2:observerEnd2]

	// Guard the fixture: if this ever stops reproducing the tie (e.g. the
	// shared test fixture's candidate caps change), fail loudly instead of
	// silently testing nothing.
	if !(len(buggyObserverTier) == 1 && buggyObserverTier[0] == observer1Addr) {
		t.Fatalf("fixture no longer reproduces the pre-fix boundary tie: stable-sort observer tier = %v, want [%v]", buggyObserverTier, observer1Addr)
	}
	if !(len(realObserverTier) == 1 && realObserverTier[0] == observer2Addr) {
		t.Fatalf("fixture no longer reproduces production's real standby-pool ordering: observer tier = %v, want [%v]", realObserverTier, observer2Addr)
	}

	// --- Drive the actual whole function under test: both tied
	// candidates sign, then check which beneficiary bucket
	// GetSigningTxCount puts each of their rewards under.
	signedHeader := blockchain.GetHeaderByNumber(h.Number.Uint64() + 15) // multiple of common.MergeSignRange
	containerHeader := blockchain.GetHeaderByNumber(h.Number.Uint64() + 16)

	tx1, err := signingTxWithKey(signedHeader, 0, observer1Key)
	assert.Nil(t, err)
	tx2, err := signingTxWithKey(signedHeader, 1, observer2Key)
	assert.Nil(t, err)
	adaptor.CacheSigningTxs(containerHeader.Hash(), []*types.Transaction{tx1, tx2})

	signers, _, err := hooks.GetSigningTxCount(adaptor, blockchain, trigger, parentState, currentConfig)
	assert.Nil(t, err)

	_, observer2IsObserver := signers[hooks.ObserverNodeBeneficiary][observer2Addr]
	_, observer2IsProtector := signers[hooks.ProtectorNodeBeneficiary][observer2Addr]
	assert.True(t, observer2IsObserver, "observer2Addr should win the tied observer slot, matching production's real standby-pool ordering")
	assert.False(t, observer2IsProtector)

	_, observer1IsObserver := signers[hooks.ObserverNodeBeneficiary][observer1Addr]
	_, observer1IsProtector := signers[hooks.ProtectorNodeBeneficiary][observer1Addr]
	assert.False(t, observer1IsObserver, "observer1Addr lost the tied observer slot under production's real ordering and should not be rewarded as observer")
	assert.False(t, observer1IsProtector)
}

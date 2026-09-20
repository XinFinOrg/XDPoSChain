package engine_v1_tests

import (
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/eth/hooks"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/stretchr/testify/require"
)

// TestHookVerifyMNsUsesTheGivenParentNotTheCanonicalHeight pins which block the
// validators are derived from: the parent the caller hands in, not the canonical
// block of the parent's height.
//
// A checkpoint on a fork has a parent that only the verifier's batch knows; the
// local chain can only answer for that height with the canonical block, which
// belongs to the competing branch. Looking the parent up by height would judge
// the checkpoint against that branch's randomize values, and the set asserted
// here is the one of the block that was actually handed in.
func TestHookVerifyMNsUsesTheGivenParentNotTheCanonicalHeight(t *testing.T) {
	const checkpoint = uint64(900)

	blockchain, _, canonicalParent, _, _ := PrepareXDCTestBlockChain(t, int(checkpoint-1), params.TestXDPoSMockChainConfig)
	engine := blockchain.Engine().(*XDPoS.XDPoS)
	hooks.AttachConsensusV1Hooks(engine, blockchain, blockchain.Config())

	canonicalState, err := blockchain.StateAt(canonicalParent.Root())
	require.NoError(t, err)
	masternodes := canonicalState.GetCandidates()
	require.NotEmpty(t, masternodes)

	// The fork's parent sits at the same height as the canonical block but is a
	// different block, carrying a randomize state the canonical one does not.
	forkState := canonicalState.Copy()
	for i, addr := range masternodes {
		setRandomizeState(t, forkState, addr, int64(i)+headRandomizeOffset)
	}
	// Commit the fork's state by itself: the hook opens it through the chain's
	// state cache, and this block never becomes part of the local chain.
	forkRoot, err := forkState.Commit(0, false)
	require.NoError(t, err)
	forkParent := &types.Header{
		Root:       forkRoot,
		Number:     canonicalParent.Number(),
		ParentHash: canonicalParent.ParentHash(),
		Coinbase:   common.HexToAddress("0xbbb0000000000000000000000000000000000000"),
	}
	require.NotEqual(t, canonicalParent.Hash(), forkParent.Hash())

	checkpointHeader := &types.Header{
		Number:     new(big.Int).SetUint64(checkpoint),
		ParentHash: forkParent.Hash(),
		Validators: validatorsFromState(t, forkState, masternodes),
	}
	// Deriving from the canonical block of that height yields another set, which
	// is what makes this case tell the two readings apart.
	require.NotEqual(t, checkpointHeader.Validators, validatorsFromState(t, canonicalState, masternodes))

	require.NoError(t, engine.EngineV1.HookVerifyMNs(forkParent, checkpointHeader, masternodes))
}

// validatorsFromState derives the validators the hook should produce from the
// randomize values of the state it reads.
func validatorsFromState(t *testing.T, statedb *state.StateDB, masternodes []common.Address) []byte {
	t.Helper()
	validators, err := validatorsFromRandoms(randomizeValuesFrom(statedb, masternodes), int64(len(masternodes)))
	require.NoError(t, err)
	return validators
}

// TestHookVerifyMNsRejectsAParentWithoutLocalState pins what the hook does when
// the parent it is handed has no state on this node: it reports the missing
// state instead of answering from the head.
//
// A checkpoint that arrives with a fork has a parent only the verifier's batch
// holds, and by the time the header is verified that parent has not been
// executed, so the trie its root names is absent. The step below deliberately
// gives the checkpoint the validators that reading the head would derive, which
// is what makes the two readings tell each other apart: a fallback to the head
// would accept this header, so accepting it here is exactly the regression this
// test exists to catch.
//
// The state is missing at the trie the root names, so opening it is what fails.
// A state that opens but cannot be read is a different path and not this test's
// subject.
func TestHookVerifyMNsRejectsAParentWithoutLocalState(t *testing.T) {
	const checkpoint = uint64(common.EpocBlockRandomize)

	blockchain, _, head, _, _ := PrepareXDCTestBlockChain(t, 20, params.TestXDPoSMockChainConfig)
	engine := blockchain.Engine().(*XDPoS.XDPoS)
	hooks.AttachConsensusV1Hooks(engine, blockchain, blockchain.Config())

	headState, err := blockchain.StateAt(head.Root())
	require.NoError(t, err)
	masternodes := headState.GetCandidates()
	require.NotEmpty(t, masternodes)

	// The head's root with one byte flipped names a trie this node does not
	// hold, while the head's own state stays available.
	absentRoot := head.Root()
	absentRoot[0] ^= 0xff
	_, err = blockchain.StateAt(absentRoot)
	require.Error(t, err, "the fixture must not hold state for %s", absentRoot)

	parent := &types.Header{
		Root:       absentRoot,
		Number:     new(big.Int).SetUint64(checkpoint - 1),
		ParentHash: head.Hash(),
		Coinbase:   common.HexToAddress("0xdead000000000000000000000000000000000000"),
	}
	checkpointHeader := &types.Header{
		Number:     new(big.Int).SetUint64(checkpoint),
		ParentHash: parent.Hash(),
		Validators: validatorsFromState(t, headState, masternodes),
	}

	err = engine.EngineV1.HookVerifyMNs(parent, checkpointHeader, masternodes)
	require.Error(t, err)
}

// TestHookGetSignersFromContractRejectsAGapBlockWithoutLocalState pins the same
// rejection on the signers fallback: the candidates come from the state of the
// gap block, so a gap block whose state this node does not hold is reported
// rather than answered from the head.
func TestHookGetSignersFromContractRejectsAGapBlockWithoutLocalState(t *testing.T) {
	blockchain, _, head, _, _ := PrepareXDCTestBlockChain(t, 20, params.TestXDPoSMockChainConfig)
	engine := blockchain.Engine().(*XDPoS.XDPoS)
	hooks.AttachConsensusV1Hooks(engine, blockchain, blockchain.Config())

	// Reading the head would find candidates, which is what a fallback to the
	// head would answer with, so the head's state has to be populated for this
	// test to tell the two readings apart.
	headState, err := blockchain.StateAt(head.Root())
	require.NoError(t, err)
	require.NotEmpty(t, headState.GetCandidates())

	absentRoot := head.Root()
	absentRoot[0] ^= 0xff
	_, err = blockchain.StateAt(absentRoot)
	require.Error(t, err, "the fixture must not hold state for %s", absentRoot)

	gapHeader := &types.Header{
		Root:       absentRoot,
		Number:     head.Number(),
		ParentHash: head.ParentHash(),
		Coinbase:   common.HexToAddress("0xddd0000000000000000000000000000000000000"),
	}

	_, err = engine.EngineV1.HookGetSignersFromContract(gapHeader)
	require.Error(t, err)
}

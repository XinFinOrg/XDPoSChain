package engine_v1_tests

import (
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS"
	"github.com/XinFinOrg/XDPoSChain/consensus/tests/xdpos_test_utils"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/eth/hooks"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/stretchr/testify/require"
)

// TestHookGetSignersFromContractWithoutIPC pins the point of the change: the
// hook answers from the state of the block it is asked about, so a node with no
// IPC endpoint of its own can still fall back to the signers from the contract.
//
// The fixture points blockchain.Client at its simulated backend, which is what
// the old implementation answered through. Clearing Client and IPCEndpoint
// leaves the state read as the only way to the signers: the old implementation
// stops on the dial to the empty endpoint, the new one returns the set.
func TestHookGetSignersFromContractWithoutIPC(t *testing.T) {
	blockchain, _, head, _, _ := PrepareXDCTestBlockChain(t, 20, params.TestXDPoSMockChainConfig)
	engine := blockchain.Engine().(*XDPoS.XDPoS)
	hooks.AttachConsensusV1Hooks(engine, blockchain, blockchain.Config())

	blockchain.Client = nil
	blockchain.IPCEndpoint = ""

	signers, err := engine.EngineV1.HookGetSignersFromContract(head.Header())
	require.NoError(t, err)
	require.NotEmpty(t, signers)

	statedb, err := blockchain.StateAt(head.Root())
	require.NoError(t, err)
	require.NoError(t, statedb.Error())

	// The same candidate set, ordered by descending stake.
	require.ElementsMatch(t, statedb.GetCandidates(), signers)
	for i := 1; i < len(signers); i++ {
		previous := statedb.GetCandidateCap(signers[i-1])
		current := statedb.GetCandidateCap(signers[i])
		require.True(t, previous.Cmp(current) >= 0, "signers are not ordered by descending stake: %v before %v", previous, current)
	}
}

// TestHookGetSignersFromContractUsesRequestedBlockState pins where the stakes
// come from. The hook takes the candidates from the state of the block it is
// asked about, and the stakes must come from that same block: the old
// implementation asked the contract without a block number, so it answered from
// the head, and a stake that moved between the two blocks put the fallback at
// odds with the set the chain derives for that epoch.
//
// Client is left as the fixture set it, so this test is about the reading
// itself rather than about a missing endpoint. Note the limit of what the
// assertion below can observe: on this fixture the old implementation stops
// before it can answer at all - the simulated backend does not apply eth_call's
// gas defaults, so its contract call fails on "intrinsic gas too low" - and no
// fixture-only arrangement makes the old implementation read the head while
// keeping the endpoint productive. The assertion therefore pins the ordering of
// the new implementation: any reading that took the stakes from the head would
// place the subject, whose stake the head has drained, somewhere after the
// first signer.
func TestHookGetSignersFromContractUsesRequestedBlockState(t *testing.T) {
	blockchain, _, head, _, _ := PrepareXDCTestBlockChain(t, 20, params.TestXDPoSMockChainConfig)
	engine := blockchain.Engine().(*XDPoS.XDPoS)
	hooks.AttachConsensusV1Hooks(engine, blockchain, blockchain.Config())

	statedb, err := blockchain.StateAt(head.Root())
	require.NoError(t, err)

	candidates := statedb.GetCandidates()
	require.Greater(t, len(candidates), 1)
	subject := candidates[0]
	highest := highestCandidateCap(statedb, candidates)

	// The block the hook will be asked about: the subject holds the highest
	// stake, so it must lead the set derived from that block.
	askedState := statedb.Copy()
	xdpos_test_utils.SetCandidateCap(askedState, subject, new(big.Int).Add(highest, big.NewInt(1)))
	askedRoot := askedState.IntermediateRoot(false)
	asked := types.NewBlockWithHeader(&types.Header{
		Root:       askedRoot,
		Number:     new(big.Int).Add(head.Number(), big.NewInt(1)),
		ParentHash: head.Hash(),
		Coinbase:   common.HexToAddress("0xaaa0000000000000000000000000000000000001"),
	})
	_, err = blockchain.WriteBlockWithState(asked, nil, askedState, nil, nil)
	require.NoError(t, err)

	// Drain the subject's stake and make that the head: under the head's state
	// the subject has no stake left, so a reading pinned to the head cannot
	// place it first. That difference is what this test asserts on.
	headState, err := blockchain.StateAt(askedRoot)
	require.NoError(t, err)
	headState.SetState(common.MasternodeVotingSMCBinary, xdpos_test_utils.CandidateCapSlot(subject), common.Hash{})
	headRoot := headState.IntermediateRoot(false)
	require.NotEqual(t, askedRoot, headRoot)
	newHead := types.NewBlockWithHeader(&types.Header{
		Root:       headRoot,
		Number:     new(big.Int).Add(head.Number(), big.NewInt(2)),
		ParentHash: asked.Hash(),
		Coinbase:   common.HexToAddress("0xaaa0000000000000000000000000000000000002"),
	})
	_, err = blockchain.WriteBlockWithState(newHead, nil, headState, nil, nil)
	require.NoError(t, err)
	require.Equal(t, newHead.NumberU64(), blockchain.CurrentBlock().Number.Uint64())

	signers, err := engine.EngineV1.HookGetSignersFromContract(asked.Header())
	require.NoError(t, err)

	require.Equal(t, subject, signers[0], "the signers must be ordered by the stake of the block the hook was asked about")
	require.Equal(t, len(candidates), len(signers))
}

func highestCandidateCap(statedb *state.StateDB, candidates []common.Address) *big.Int {
	highest := new(big.Int)
	for _, candidate := range candidates {
		if cap := statedb.GetCandidateCap(candidate); cap.Cmp(highest) > 0 {
			highest = cap
		}
	}
	return highest
}

// TestHookGetSignersFromContractRejectsNilHeader pins the contract of the hook
// now that the gap block header is handed in by the caller: a nil header is
// reported instead of being dereferenced.
func TestHookGetSignersFromContractRejectsNilHeader(t *testing.T) {
	blockchain, _, _, _, _ := PrepareXDCTestBlockChain(t, 1, params.TestXDPoSMockChainConfig)
	engine := blockchain.Engine().(*XDPoS.XDPoS)
	hooks.AttachConsensusV1Hooks(engine, blockchain, blockchain.Config())

	_, err := engine.EngineV1.HookGetSignersFromContract(nil)
	require.Error(t, err)
}

// TestHookGetSignersFromContractTakesABatchOnlyGapHeader pins that the hook
// reads the state of the header it is given, not of a block looked up locally.
//
// The gap block of a checkpoint that arrives with a fork is only in the batch
// the verifier holds; here its header is built on the head's state but never
// written to the chain, so a lookup by hash finds nothing and dereferencing it
// would panic. The state read must still answer.
func TestHookGetSignersFromContractTakesABatchOnlyGapHeader(t *testing.T) {
	blockchain, _, head, _, _ := PrepareXDCTestBlockChain(t, 20, params.TestXDPoSMockChainConfig)
	engine := blockchain.Engine().(*XDPoS.XDPoS)
	hooks.AttachConsensusV1Hooks(engine, blockchain, blockchain.Config())

	blockchain.Client = nil
	blockchain.IPCEndpoint = ""

	gapHeader := &types.Header{
		Root:       head.Root(),
		Number:     head.Number(),
		ParentHash: head.ParentHash(),
		Coinbase:   common.HexToAddress("0xccc0000000000000000000000000000000000000"),
	}
	require.Nil(t, blockchain.GetBlockByHash(gapHeader.Hash()), "the gap block must not exist in the local chain for this case")

	signers, err := engine.EngineV1.HookGetSignersFromContract(gapHeader)
	require.NoError(t, err)
	require.NotEmpty(t, signers)

	statedb, err := blockchain.StateAt(gapHeader.Root)
	require.NoError(t, err)
	require.ElementsMatch(t, statedb.GetCandidates(), signers)
}

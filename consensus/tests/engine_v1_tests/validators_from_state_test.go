package engine_v1_tests

import (
	"math/big"
	"strconv"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS"
	"github.com/XinFinOrg/XDPoSChain/contracts"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/eth/hooks"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/stretchr/testify/require"
)

// TestHookValidatorDoesNotNeedAnIPCEndpoint pins the point of the change behind
// getValidatorsAtNumber: the validators come off the state of the block the call
// is pinned to, so a node with no IPC endpoint of its own can still produce them.
//
// The fixture points blockchain.Client at its simulated backend, which is what
// the old implementation answered through. Clearing Client and IPCEndpoint
// leaves the state read as the only way to the randomize values: the old
// implementation stops on the dial to the empty endpoint, the new one returns
// the validators.
//
// HookValidator is the entry point used here because it is the one that produces
// the validators. HookVerifyMNs only compares a header against them, and the
// block that comparison is pinned to is covered by
// TestCheckpointSyncValidatorVerificationUsesParentState.
//
// The randomize values are put into the block the call is pinned to, and they are
// put there through slots worked out here rather than through the helpers
// StateDB.GetSecret and StateDB.GetOpening read through. That is what lets this
// test say something about the values themselves: the fixture carries no
// randomize data at all, so a reading that landed on other slots would answer
// zeros, and zeros still amount to a set of validators. Asserting that some
// validators came back would therefore miss it, and even deriving the expected
// set by reading the state back with the production helpers would miss it too,
// because both sides would drift together. What is asserted instead is the set
// the values put into those slots have to produce.
func TestHookValidatorDoesNotNeedAnIPCEndpoint(t *testing.T) {
	blockchain, _, head, _, _ := PrepareXDCTestBlockChain(t, 20, params.TestXDPoSMockChainConfig)
	engine := blockchain.Engine().(*XDPoS.XDPoS)
	hooks.AttachConsensusV1Hooks(engine, blockchain, blockchain.Config())

	masternodes, err := engine.EngineV1.GetAuthorisedSignersFromSnapshot(blockchain, head.Header())
	require.NoError(t, err)
	require.NotEmpty(t, masternodes)

	// Give every masternode a randomize value of its own in the block after the
	// head, which is the block the call below is pinned to: each value then
	// decides part of m2, so none of them can be read wrong unnoticed.
	parentState, err := blockchain.StateAt(head.Root())
	require.NoError(t, err)
	randoms := make([]int64, 0, len(masternodes))
	for i, addr := range masternodes {
		random := int64(i + 1)
		writeRandomizeFromABISlots(t, parentState, addr, random)
		randoms = append(randoms, random)
	}
	parent := types.NewBlockWithHeader(&types.Header{
		Root:       parentState.IntermediateRoot(false),
		Number:     new(big.Int).Add(head.Number(), common.Big1),
		ParentHash: head.Hash(),
		Coinbase:   common.HexToAddress("0xaaa0000000000000000000000000000000000001"),
	})
	_, err = blockchain.WriteBlockWithState(parent, nil, parentState, nil, nil)
	require.NoError(t, err)
	require.Equal(t, parent.NumberU64(), blockchain.CurrentBlock().Number.Uint64())

	// The values have to be found where they were written. This is the assertion
	// that fails when the reading answers from other slots, which would otherwise
	// still produce a set of validators of its own.
	readBack, err := blockchain.StateAt(parent.Root())
	require.NoError(t, err)
	for i, addr := range masternodes {
		random, err := contracts.DecryptRandomizeFromSecretsAndOpening(readBack.GetSecret(addr), readBack.GetOpening(addr))
		require.NoError(t, err)
		require.Equal(t, randoms[i], random, "the randomize values must come from the slots they were written to")
	}

	m2, err := contracts.GenM2FromRandomize(randoms, int64(len(masternodes)))
	require.NoError(t, err)
	expected := contracts.BuildValidatorFromM2(m2)

	blockchain.Client = nil
	blockchain.IPCEndpoint = ""

	validators, err := engine.EngineV1.HookValidator(&types.Header{
		Number:     new(big.Int).Add(parent.Number(), common.Big1),
		ParentHash: parent.Hash(),
	}, masternodes)
	require.NoError(t, err)
	require.Equal(t, expected, validators,
		"the validators must be derived from the randomize values of the block the call is pinned to")
}

// writeRandomizeFromABISlots writes randomSecret and randomOpening for one
// masternode at the slots the contract declares them in, derived here from how
// solidity lays a mapping and a dynamic array out, rather than through the
// helpers StateDB.GetSecret and StateDB.GetOpening use, so that a mistake in
// those helpers is not a mistake this test shares.
//
// Those slots are the right ones because the contract is: the code the genesis
// allocs put at common.RandomizeSMCBinary is byte for byte the runtime code
// abigen produced from contracts/randomize/contract/XDCRandomize.sol, where
// randomSecret is declared first, at slot 0, and randomOpening second, at slot 1.
func writeRandomizeFromABISlots(t *testing.T, statedb *state.StateDB, addr common.Address, random int64) {
	t.Helper()

	var opening [32]byte
	copy(opening[:], []byte("validators-from-state-randomize-key")) // deterministic, one per test run
	encrypted := contracts.Encrypt(opening[:], strconv.FormatInt(random, 10))
	var secret [32]byte
	copy(secret[:], common.LeftPadBytes([]byte(encrypted), 32))

	// mapping(address => bytes32[]) at slot 0: the length sits at keccak256(key ‖
	// 0) and the elements follow keccak256(keccak256(key ‖ 0)), one slot each.
	lengthSlot := crypto.Keccak256Hash(addr.Hash().Bytes(), common.BigToHash(new(big.Int)).Bytes())
	statedb.SetState(common.RandomizeSMCBinary, lengthSlot, common.BigToHash(big.NewInt(1)))
	statedb.SetState(common.RandomizeSMCBinary, crypto.Keccak256Hash(lengthSlot.Bytes()), secret)

	// mapping(address => bytes32) at slot 1: the value sits at keccak256(key ‖ 1).
	openingSlot := crypto.Keccak256Hash(addr.Hash().Bytes(), common.BigToHash(big.NewInt(1)).Bytes())
	statedb.SetState(common.RandomizeSMCBinary, openingSlot, opening)
}

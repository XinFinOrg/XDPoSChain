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
	"github.com/XinFinOrg/XDPoSChain/eth/hooks"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/stretchr/testify/require"
)

// Regression test for sync-time checkpoint verification.
//
// Scenario:
// 1) Build chain up to block 899.
// 2) Precompute checkpoint #900's validators from parent(#899) state.
// 3) Advance the chain with #900, whose randomize state differs from parent(#899).
// 4) Re-verify old checkpoint header #900 while the head is #900.
//
// HookVerifyMNs must read the randomize values pinned to the parent block. Were
// it to read them at the head, step (4) would return
// ErrInvalidCheckpointValidators.
func TestCheckpointSyncValidatorVerificationUsesParentState(t *testing.T) {
	const checkpointNumber = uint64(900)

	blockchain, _, parentBlock, _, _ := PrepareXDCTestBlockChain(t, int(checkpointNumber-1), params.TestXDPoSMockChainConfig)
	require.Equal(t, checkpointNumber-1, parentBlock.NumberU64())

	engine := blockchain.Engine().(*XDPoS.XDPoS)
	hooks.AttachConsensusV1Hooks(engine, blockchain, blockchain.Config())
	masternodes, err := engine.EngineV1.GetAuthorisedSignersFromSnapshot(blockchain, parentBlock.Header())
	require.NoError(t, err)
	require.NotEmpty(t, masternodes)

	parentState, err := blockchain.StateAt(parentBlock.Root())
	require.NoError(t, err)
	parentRandoms := randomizeValuesFrom(parentState, masternodes)
	validatorsAtParent, err := validatorsFromRandoms(parentRandoms, int64(len(masternodes)))
	require.NoError(t, err)

	// Advance the chain with #900 carrying a randomize state different from the
	// parent's, so that the parent view and the head view disagree.
	headState, err := blockchain.StateAt(parentBlock.Root())
	require.NoError(t, err)
	headRandoms := make([]int64, 0, len(masternodes))
	for i, addr := range masternodes {
		random := int64(i) + headRandomizeOffset
		setRandomizeState(t, headState, addr, random)
		headRandoms = append(headRandoms, random)
	}
	headRoot := headState.IntermediateRoot(false)
	head := types.NewBlockWithHeader(&types.Header{
		Root:       headRoot,
		Number:     new(big.Int).SetUint64(checkpointNumber),
		ParentHash: parentBlock.Hash(),
		Coinbase:   common.HexToAddress("0xaaa0000000000000000000000000000000000900"),
	})
	_, err = blockchain.WriteBlockWithState(head, nil, headState, nil, nil)
	require.NoError(t, err)
	require.Equal(t, checkpointNumber, blockchain.CurrentBlock().Number.Uint64())

	validatorsAtHead, err := validatorsFromRandoms(headRandoms, int64(len(masternodes)))
	require.NoError(t, err)
	require.NotEqual(t, validatorsAtHead, validatorsAtParent,
		"the parent view and the head view must differ, otherwise this test cannot tell them apart")

	checkpointHeader := &types.Header{
		Root:       headRoot,
		Number:     new(big.Int).SetUint64(checkpointNumber),
		ParentHash: parentBlock.Hash(),
		Coinbase:   head.Coinbase(),
		Validators: validatorsAtParent,
	}

	// This used to be paired with an explicit check that err is not
	// ErrInvalidCheckpointValidators. That check was always true once NoError
	// passed, so the guard against the historical failure signature is the
	// NoError above plus the NotEqual on the derived validators at the top.
	err = engine.EngineV1.HookVerifyMNs(parentBlock.Header(), checkpointHeader, masternodes)
	require.NoError(t, err)
}

// headRandomizeOffset keeps the head's randomize values away from the zeros the
// parent state carries.
const headRandomizeOffset = int64(1000)

// randomizeValuesFrom reads the randomize value of every masternode the same way
// getValidatorsAtNumber does, but from the state passed in.
func randomizeValuesFrom(statedb *state.StateDB, masternodes []common.Address) []int64 {
	randoms := make([]int64, 0, len(masternodes))
	for _, addr := range masternodes {
		random, err := contracts.DecryptRandomizeFromSecretsAndOpening(statedb.GetSecret(addr), statedb.GetOpening(addr))
		if err != nil {
			// A failed decrypt leaves the value at zero; the hook surfaces
			// StateDB.Error() separately.
			random = 0
		}
		randoms = append(randoms, random)
	}
	return randoms
}

// setRandomizeState writes the encrypted secret and the opening a masternode
// would have committed, so the state carries random as its randomize value.
//
// The slots are derived with the same helpers StateDB.GetSecret and
// StateDB.GetOpening use (core/state/statedb_utils.go), so a layout change
// moves both sides together and this test cannot catch it: what it anchors is
// the declaration order in contracts/randomize/contract/XDCRandomize.sol, where
// randomSecret is slot 0 and randomOpening is slot 1.
func setRandomizeState(t *testing.T, statedb *state.StateDB, addr common.Address, random int64) {
	t.Helper()

	var opening [32]byte
	copy(opening[:], []byte("checkpoint-sync-randomize-key-000")) // 32 bytes prefix, deterministic

	encrypted := contracts.Encrypt(opening[:], strconv.FormatInt(random, 10))
	var secret [32]byte
	copy(secret[:], common.LeftPadBytes([]byte(encrypted), 32))

	// randomSecret is mapping(address => bytes32[]): slot 0, a single element.
	locSecret := state.GetLocMappingAtKey(addr.Hash(), 0)
	statedb.SetState(common.RandomizeSMCBinary, common.BigToHash(locSecret), common.BigToHash(big.NewInt(1)))
	statedb.SetState(common.RandomizeSMCBinary, state.GetLocDynamicArrAtElement(common.BigToHash(locSecret), 0, 1), secret)
	// randomOpening is mapping(address => bytes32): slot 1.
	locOpening := state.GetLocMappingAtKey(addr.Hash(), 1)
	statedb.SetState(common.RandomizeSMCBinary, common.BigToHash(locOpening), opening)
}

func validatorsFromRandoms(randoms []int64, lenSigners int64) ([]byte, error) {
	m2, err := contracts.GenM2FromRandomize(randoms, lenSigners)
	if err != nil {
		return nil, err
	}
	return contracts.BuildValidatorFromM2(m2), nil
}

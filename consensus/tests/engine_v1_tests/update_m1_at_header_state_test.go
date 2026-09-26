package engine_v1_tests

import (
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus/tests/xdpos_test_utils"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/stretchr/testify/require"
)

// UpdateM1At must read the candidates off the state committed at the header it
// is given, not off the state of the head. The v1 engine keys the set it
// receives by that very header, so reading the head would store, as the set of
// the named block, a set that belongs to another one.
//
// The two states are built to select different sets: the block that is made
// canonical here holds stakes that decrease over the stored candidate order, so
// its set is the head of that order, while the state of the header the refresh
// is asked for increases them, which selects the tail. Both are read back
// through the engine, so a refresh that ignored the header's root cannot produce
// the set the second assertion asks for.
func TestUpdateM1AtReadsTheStateOfTheHeaderItIsGiven(t *testing.T) {
	config := params.TestXDPoSMockChainConfig
	blockchain, _, currentBlock, signer, signFn := PrepareXDCTestBlockChain(t, GAP-1, config)

	headState, err := blockchain.StateAt(currentBlock.Root())
	require.NoError(t, err)
	candidates := headState.GetCandidates()
	require.Greater(t, len(candidates), common.MaxMasternodes,
		"the fixture must carry more candidates than the legacy cap, otherwise the stakes cannot decide who is dropped")

	// Make the block that is about to be written the head with a strictly
	// decreasing stake over the stored candidate order: the cap then keeps the
	// first MaxMasternodes candidates of that order.
	for i, candidate := range candidates {
		xdpos_test_utils.SetCandidateCap(headState, candidate, big.NewInt(int64(len(candidates)-i)))
	}
	expectedAtHead := make(signersList, common.MaxMasternodes)
	for _, candidate := range candidates[:common.MaxMasternodes] {
		expectedAtHead[candidate.Hex()] = true
	}

	header := &types.Header{
		Root:       headState.IntermediateRoot(false),
		Number:     big.NewInt(int64(GAP)),
		ParentHash: currentBlock.Hash(),
		Coinbase:   common.HexToAddress("0xaaa0000000000000000000000000000000000450"),
	}
	blockA, err := createBlockFromHeader(blockchain, header, nil, signer, signFn, config)
	require.NoError(t, err)
	_, err = blockchain.WriteBlockWithState(blockA, nil, headState, nil, nil)
	require.NoError(t, err)
	require.Equal(t, uint64(GAP), blockchain.CurrentBlock().Number.Uint64(),
		"the head must be the gap block the refresh runs for")

	headSigners, err := GetSnapshotSigner(blockchain, blockA.Header())
	require.NoError(t, err)
	require.Equal(t, expectedAtHead, headSigners,
		"the head must carry the set of the state it was written with")

	// Commit a second state for that same block, with the stakes reversed: the
	// highest ones are now the tail of the stored order.
	headerState, err := blockchain.StateAt(blockA.Root())
	require.NoError(t, err)
	for i, candidate := range candidates {
		xdpos_test_utils.SetCandidateCap(headerState, candidate, big.NewInt(int64(i+1)))
	}
	headerRoot, err := headerState.Commit(blockA.NumberU64(), config.IsEIP158(blockA.Number()))
	require.NoError(t, err)
	expectedAtHeader := make(signersList, common.MaxMasternodes)
	for _, candidate := range candidates[len(candidates)-common.MaxMasternodes:] {
		expectedAtHeader[candidate.Hex()] = true
	}
	require.NotEqual(t, expectedAtHead, expectedAtHeader,
		"the two states must select different sets, otherwise this case cannot tell them apart")

	// The header of that same block, rooted at the state above and not at the
	// state of the head, and no longer the block that is canonical.
	otherHeader := *blockA.Header()
	otherHeader.Root = headerRoot
	require.NotEqual(t, blockA.Hash(), otherHeader.Hash(),
		"the header must name a block that is not the one the chain has made canonical")

	require.NoError(t, blockchain.UpdateM1At(&otherHeader))

	otherSigners, err := GetSnapshotSigner(blockchain, &otherHeader)
	require.NoError(t, err)
	require.Equal(t, expectedAtHeader, otherSigners,
		"the set must be derived from the state committed at the given header, not from the head")

	// The refresh of one block must not rewrite the set of another.
	headSigners, err = GetSnapshotSigner(blockchain, blockA.Header())
	require.NoError(t, err)
	require.Equal(t, expectedAtHead, headSigners,
		"the set of the canonical block must be left as it was")
}

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

// The next-epoch masternode refresh must not need the node's own IPC endpoint.
// UpdateM1At used to read the candidates from the state but fetch every
// candidate cap from the voting contract over IPC, so a node without an IPC
// endpoint (for instance one started with --ipcdisable) failed the refresh on
// every gap block and the call sites turn that failure into log.Crit.
//
// The gap block is built here rather than taken from the fixture so that the
// stakes are known: the caps are written as a strictly increasing sequence over
// the candidate order the state stores them in. This legacy configuration
// postpones TIPIncreaseMasternodes and puts this block before the v2 switch, so
// engine_v1.UpdateMasternodes caps the set at common.MaxMasternodes, and that
// cap has to cut the fixture's candidates down to it. The set that survives is
// then the tail of that sequence, in the reverse of the stored order: a refresh
// that read no stakes, read them off another block's state or kept the order the
// candidates are stored in cannot produce it. v1 keeps the set in a map, so only
// its membership can be read back, not the order; the v2 counterpart in
// engine_v2_tests, where the snapshot keeps the order, asserts both.
//
// The endpoint is dropped before the gap block is written, so what is pinned is
// the crossing itself: the refresh runs inside writeBlockWithState as the head is
// advanced to that block. A refresh that still read the stakes over IPC fails
// there and takes the call site's log.Crit, which stops this test binary exactly
// the way it stops a node started with --ipcdisable.
func TestUpdateM1AtDoesNotNeedAnIPCEndpoint(t *testing.T) {
	config := params.TestXDPoSMockChainConfig
	blockchain, _, currentBlock, signer, signFn := PrepareXDCTestBlockChain(t, GAP-1, config)

	gapState, err := blockchain.StateAt(currentBlock.Root())
	require.NoError(t, err)
	candidates := gapState.GetCandidates()
	require.Greater(t, len(candidates), common.MaxMasternodes,
		"the fixture must carry more candidates than the legacy cap, otherwise the stakes cannot decide who is dropped")
	for i, candidate := range candidates {
		xdpos_test_utils.SetCandidateCap(gapState, candidate, big.NewInt(int64(i+1)))
	}
	expected := make(signersList, common.MaxMasternodes)
	for _, candidate := range candidates[len(candidates)-common.MaxMasternodes:] {
		expected[candidate.Hex()] = true
	}

	// PrepareXDCTestBlockChain injects a client into the chain. Drop it and the
	// endpoint to model a node that has no IPC at all, before the gap block is
	// written, so the refresh below runs on a node that has none.
	blockchain.Client = nil
	blockchain.IPCEndpoint = ""

	// Insert the gap block, which is where the refresh runs. It is written with
	// the state above, so the head the refresh reads carries those caps.
	header := &types.Header{
		Root:       gapState.IntermediateRoot(false),
		Number:     big.NewInt(int64(GAP)),
		ParentHash: currentBlock.Hash(),
		Coinbase:   common.HexToAddress("0xaaa0000000000000000000000000000000000450"),
	}
	blockA, err := createBlockFromHeader(blockchain, header, nil, signer, signFn, config)
	require.NoError(t, err)
	_, err = blockchain.WriteBlockWithState(blockA, nil, gapState, nil, nil)
	require.NoError(t, err)
	require.Equal(t, uint64(GAP), blockchain.CurrentBlock().Number.Uint64(),
		"the head must be the gap block the refresh is for")

	// The refresh above also has to read the right stakes, and it is the set the
	// snapshot kept that says whether it did.
	signers, err := GetSnapshotSigner(blockchain, blockA.Header())
	require.NoError(t, err)
	require.Equal(t, expected, signers,
		"the set must be the highest-stake candidates of the gap block state")
}

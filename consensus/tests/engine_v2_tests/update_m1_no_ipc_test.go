package engine_v2_tests

import (
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS"
	"github.com/XinFinOrg/XDPoSChain/consensus/tests/xdpos_test_utils"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/stretchr/testify/require"
)

// The next-epoch masternode refresh must not need the node's own IPC endpoint.
// UpdateM1 used to read the candidates from the state but fetch every candidate
// cap from the voting contract over IPC, so a node without an IPC endpoint (for
// instance one started with --ipcdisable) failed the refresh on every gap block
// and the call sites turn that failure into log.Crit.
//
// The gap block is built here rather than taken from the fixture so that the
// stakes are known and the order the refresh must produce is unique: the caps
// are written as a strictly increasing sequence over the candidate order the
// state stores them in, so a refresh keyed on those stakes has to hand the set
// back in the exact reverse of that order. No fixture stake distribution is
// relied on, and a refresh that read the stakes as zeros cannot produce it.
//
// The endpoint is dropped before the gap block is written, so what is pinned is
// the crossing itself: the refresh runs inside writeBlockWithState as the head is
// advanced to that block. A refresh that still read the stakes over IPC fails
// there and takes the call site's log.Crit, which stops this test binary exactly
// the way it stops a node started with --ipcdisable.
func TestUpdateM1DoesNotNeedAnIPCEndpoint(t *testing.T) {
	skipLongInShortMode(t)
	config := params.TestXDPoSMockChainConfig
	blockchain, _, currentBlock, signer, signFn, _ := PrepareXDCTestBlockChainForV2Engine(t, int(config.XDPoS.Epoch+config.XDPoS.Gap)-1, config, nil)

	gapState, err := blockchain.StateAt(currentBlock.Root())
	require.NoError(t, err)
	candidates := gapState.GetCandidates()
	require.Greater(t, len(candidates), 1, "the fixture must carry candidates to order")
	for i, candidate := range candidates {
		xdpos_test_utils.SetCandidateCap(gapState, candidate, big.NewInt(int64(i+1)))
	}
	expected := make([]common.Address, len(candidates))
	for i, candidate := range candidates {
		expected[len(candidates)-1-i] = candidate
	}

	// PrepareXDCTestBlockChainForV2Engine injects a client into the chain. Drop
	// it and the endpoint to model a node that has no IPC at all, before the gap
	// block is written, so the refresh below runs on a node that has none.
	blockchain.Client = nil
	blockchain.IPCEndpoint = ""

	// Insert the gap block, which is where the refresh runs. It is written with
	// the state above, so the head the refresh reads carries those caps.
	header := &types.Header{
		Root:       gapState.IntermediateRoot(false),
		Number:     big.NewInt(int64(config.XDPoS.Epoch + config.XDPoS.Gap)),
		ParentHash: currentBlock.Hash(),
		Coinbase:   common.HexToAddress("0xaaa0000000000000000000000000000000001350"),
		Extra:      generateV2Extra(450, currentBlock, signer, signFn, nil),
	}
	parentBlock := types.NewBlockWithHeader(header)
	_, err = blockchain.WriteBlockWithState(parentBlock, nil, gapState, nil, nil)
	require.NoError(t, err)
	require.Equal(t, parentBlock.NumberU64(), blockchain.CurrentBlock().Number.Uint64())

	// The set and its order are read back from the snapshot the refresh wrote:
	// UpdateMasternodes stores the addresses in the order the stakes produced.
	//
	// getSnapshot resolves the snapshot from the number it is given by walking
	// back to that epoch's gap block, so asking for the first block of the epoch
	// this set was prepared for is what returns the snapshot written above.
	adaptor := blockchain.Engine().(*XDPoS.XDPoS)
	preparedEpoch := &types.Header{Number: new(big.Int).Add(parentBlock.Number(), new(big.Int).SetUint64(config.XDPoS.Gap))}
	snap, err := adaptor.EngineV2.GetSnapshot(blockchain, preparedEpoch)
	require.NoError(t, err)
	require.Equal(t, parentBlock.Hash(), snap.Hash, "the snapshot must be the one this refresh wrote")
	require.Equal(t, expected, snap.NextEpochCandidates, "the set must be ordered by the stakes of the gap block state, not by the order the candidates are stored in")
}

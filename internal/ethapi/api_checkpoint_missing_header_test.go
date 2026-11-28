package ethapi

import (
	"context"
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/XinFinOrg/XDPoSChain/rpc"
	"github.com/stretchr/testify/require"
)

// missingHeaderChain serves no header at all, which is what a node sees for a
// block whose canonical hash is gone.
type missingHeaderChain struct{ consensus.ChainReader }

func (missingHeaderChain) GetHeaderByNumber(uint64) *types.Header { return nil }

func (missingHeaderChain) GetHeaderByHash(common.Hash) *types.Header { return nil }

// headOnlyBackend returns a fixed current header: backendMock reports none, and
// the checkpoint lookups below read CurrentBlock first.
type headOnlyBackend struct {
	*backendMock
	head *types.Header
}

func (b *headOnlyBackend) CurrentBlock() *types.Header { return b.head }

// BlockByNumber answers with a block at every height: the block is still there,
// only the checkpoint lookup failed.
func (b *headOnlyBackend) BlockByNumber(ctx context.Context, number rpc.BlockNumber) (*types.Block, error) {
	return types.NewBlockWithHeader(&types.Header{Number: big.NewInt(0)}), nil
}

func newMissingHeaderAPI(t *testing.T) *BlockChainAPI {
	t.Helper()

	backend := &headOnlyBackend{
		backendMock: newBackendMock(),
		head:        &types.Header{Number: big.NewInt(1100)},
	}
	backend.config = params.TestXDPoSMockChainConfig
	backend.engine = XDPoS.NewFaker(rawdb.NewMemoryDatabase(), params.TestXDPoSMockChainConfig)

	return NewBlockChainAPI(backend, missingHeaderChain{})
}

// The epoch switch block that has to vouch for the queried block's signing
// range is gone, so the nearest signed block is unknown; returning one anyway
// would report the range as signed.
func TestFindNearestSignedBlockMissingHeader(t *testing.T) {
	t.Parallel()

	api := newMissingHeaderAPI(t)
	block := types.NewBlockWithHeader(&types.Header{Number: big.NewInt(1100)})

	if got := api.findNearestSignedBlock(context.Background(), block); got != nil {
		t.Fatalf("findNearestSignedBlock with a missing header: have %v, want nil", got)
	}
}

func TestGetCheckpointFromEpochMissingHeader(t *testing.T) {
	t.Parallel()

	api := newMissingHeaderAPI(t)

	checkpointNumber, epochNumber, err := api.GetCheckpointFromEpoch(context.Background(), rpc.LatestEpochNumber)
	require.Error(t, err)
	require.Contains(t, err.Error(), "header 1100 not found")
	require.Equal(t, rpc.BlockNumber(0), checkpointNumber)
	require.Equal(t, rpc.EpochNumber(0), epochNumber)
}

// The candidate RPCs must surface the failed lookup instead of reading the
// genesis block as if it were the current checkpoint.
func TestGetCandidatesSurfacesCheckpointError(t *testing.T) {
	t.Parallel()

	api := newMissingHeaderAPI(t)

	result, err := api.GetCandidates(context.Background(), rpc.LatestEpochNumber)
	require.Error(t, err)
	require.Contains(t, err.Error(), "header 1100 not found")
	require.Equal(t, false, result[fieldSuccess])
}

func TestGetCandidateStatusSurfacesCheckpointError(t *testing.T) {
	t.Parallel()

	api := newMissingHeaderAPI(t)

	result, err := api.GetCandidateStatus(context.Background(), common.Address{}, rpc.LatestEpochNumber)
	require.Error(t, err)
	require.Contains(t, err.Error(), "header 1100 not found")
	require.Equal(t, false, result[fieldSuccess])
}

package XDPoS

import (
	"context"
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS/utils"
	"github.com/XinFinOrg/XDPoSChain/core/forkid"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/XinFinOrg/XDPoSChain/params/forks"
	"github.com/XinFinOrg/XDPoSChain/rpc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type configChainMock struct {
	genesis *types.Header
	current *types.Header
	config  *params.ChainConfig
}

func newConfigChainMock() *configChainMock {
	return newConfigChainMockWithCurrent(1500)
}

func newConfigChainMockWithCurrent(current uint64) *configChainMock {
	return &configChainMock{
		genesis: &types.Header{Number: big.NewInt(0)},
		current: &types.Header{Number: new(big.Int).SetUint64(current), BaseFee: big.NewInt(10)},
		config: &params.ChainConfig{
			ChainID:             big.NewInt(42),
			HomesteadBlock:      big.NewInt(0),
			DAOForkSupport:      true,
			EIP150Block:         big.NewInt(0),
			EIP155Block:         big.NewInt(0),
			EIP158Block:         big.NewInt(0),
			ByzantiumBlock:      big.NewInt(0),
			ConstantinopleBlock: big.NewInt(0),
			PetersburgBlock:     big.NewInt(0),
			IstanbulBlock:       big.NewInt(0),
			BerlinBlock:         big.NewInt(0),
			Eip1559Block:        big.NewInt(1000),
			XDPoS:               &params.XDPoSConfig{V2: &params.V2{SwitchBlock: big.NewInt(1500)}},
		},
	}
}

func (m *configChainMock) Config() *params.ChainConfig { return m.config }

func (m *configChainMock) CurrentHeader() *types.Header { return m.current }

func (m *configChainMock) GetHeader(hash common.Hash, number uint64) *types.Header {
	header := m.GetHeaderByNumber(number)
	if header != nil && header.Hash() == hash {
		return header
	}
	return nil
}

func (m *configChainMock) GetHeaderByNumber(number uint64) *types.Header {
	switch number {
	case 0:
		return m.genesis
	case m.current.Number.Uint64():
		return m.current
	default:
		return nil
	}
}

func (m *configChainMock) GetHeaderByHash(hash common.Hash) *types.Header {
	if m.genesis.Hash() == hash {
		return m.genesis
	}
	if m.current.Hash() == hash {
		return m.current
	}
	return nil
}

func (m *configChainMock) GetBlock(hash common.Hash, number uint64) *types.Block {
	header := m.GetHeader(hash, number)
	if header == nil {
		return nil
	}
	return types.NewBlockWithHeader(header)
}

var _ consensus.ChainReader = (*configChainMock)(nil)

func TestCalculateSignersVote(t *testing.T) {
	info := make(map[string]SignerTypes)
	votes := utils.NewPool()
	masternodes := []common.Address{{1}, {2}, {3}}

	vote1 := types.Vote{
		Signature: types.Signature{1},
		ProposedBlockInfo: &types.BlockInfo{
			Hash:   common.Hash{1},
			Round:  types.Round(10),
			Number: big.NewInt(910),
		},
		GapNumber: 450,
	}
	vote1.SetSigner(common.Address{1})

	vote2 := types.Vote{
		Signature: types.Signature{2},
		ProposedBlockInfo: &types.BlockInfo{
			Hash:   common.Hash{1},
			Round:  types.Round(10),
			Number: big.NewInt(910),
		},
		GapNumber: 450,
	}
	vote2.SetSigner(common.Address{2})

	votes.Add(&vote1)
	votes.Add(&vote2)

	calculateSigners(info, votes.Get(), masternodes)
	assert.Equal(t, info["10:450:910:0x0100000000000000000000000000000000000000000000000000000000000000"].CurrentNumber, 2)
}

func TestCalculateSignersTimeout(t *testing.T) {
	info := make(map[string]SignerTypes)
	timeouts := utils.NewPool()
	masternodes := []common.Address{{1}, {2}, {3}}

	timeout1 := types.Timeout{
		Signature: types.Signature{1},
		Round:     types.Round(10),
		GapNumber: 450,
	}
	timeout1.SetSigner(common.Address{1})

	timeout2 := types.Timeout{
		Signature: types.Signature{2},
		Round:     types.Round(10),
		GapNumber: 450,
	}
	timeout1.SetSigner(common.Address{2})

	timeouts.Add(&timeout1)
	timeouts.Add(&timeout2)

	calculateSigners(info, timeouts.Get(), masternodes)
	assert.Equal(t, info["10:450"].CurrentNumber, 2)
}

func TestAPIGetConfig(t *testing.T) {
	chain := newConfigChainMockWithCurrent(1500)
	api := &API{chain: chain}

	resp, err := api.GetConfig(context.Background())
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotNil(t, resp.Current)
	require.Equal(t, uint64(1500), resp.Current.ActivationBlock)
	require.Contains(t, resp.Current.ActiveForks, forks.XDPoSV2.String())
	require.Nil(t, resp.Next)
	require.Nil(t, resp.Last)
	require.Equal(t, chain.config.ChainID, (*big.Int)(resp.Current.ChainId))
	forkID := forkid.NewID(chain.config, types.NewBlockWithHeader(chain.genesis), resp.Current.ActivationBlock).Hash
	require.Equal(t, forkID[:], []byte(resp.Current.ForkId))
	require.NotNil(t, configBackend{chain: chain}.CurrentHeader())
	genesis, err := configBackend{chain: chain}.HeaderByNumber(context.Background(), rpc.BlockNumber(0))
	require.NoError(t, err)
	require.NotNil(t, genesis)
}

func TestAPIGetConfig_BeforeXDPoSV2Switch(t *testing.T) {
	chain := newConfigChainMockWithCurrent(1400)
	api := &API{chain: chain}

	resp, err := api.GetConfig(context.Background())
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotNil(t, resp.Current)
	require.NotNil(t, resp.Next)
	require.NotNil(t, resp.Last)

	require.Equal(t, uint64(1000), resp.Current.ActivationBlock)
	require.NotContains(t, resp.Current.ActiveForks, forks.XDPoSV2.String())

	require.Equal(t, uint64(1500), resp.Next.ActivationBlock)
	require.Contains(t, resp.Next.ActiveForks, forks.XDPoSV2.String())
	require.Equal(t, uint64(1500), resp.Last.ActivationBlock)
}

// Copyright (c) 2026 XDPoSChain
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.

package XDPoS

import (
	"context"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS/utils"
	"github.com/XinFinOrg/XDPoSChain/core/forkid"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/XinFinOrg/XDPoSChain/params/forks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type configChainMock struct {
	genesis *types.Header
	current *types.Header
	config  *params.ChainConfig
}

func newConfigChainMockWithCurrent(current uint64) *configChainMock {
	return &configChainMock{
		genesis: &types.Header{Number: big.NewInt(0)},
		current: &types.Header{Number: new(big.Int).SetUint64(current)},
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
			EIP1559Block:        big.NewInt(1000),
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

func TestJsonNumberToBigInt(t *testing.T) {
	tests := []struct {
		name   string
		input  json.Number
		want   *big.Int
		wantOk bool
	}{
		{
			name:   "plain decimal integer",
			input:  json.Number("4500000000000000000000"),
			want:   new(big.Int).Mul(big.NewInt(45), new(big.Int).Exp(big.NewInt(10), big.NewInt(20), nil)),
			wantOk: true,
		},
		{
			name:   "scientific notation 4.5e+21",
			input:  json.Number("4.5e+21"),
			want:   new(big.Int).Mul(big.NewInt(45), new(big.Int).Exp(big.NewInt(10), big.NewInt(20), nil)),
			wantOk: true,
		},
		{
			name:   "scientific notation 1e+18",
			input:  json.Number("1e+18"),
			want:   new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil),
			wantOk: true,
		},
		{
			name:   "scientific notation uppercase E",
			input:  json.Number("4.5E+21"),
			want:   new(big.Int).Mul(big.NewInt(45), new(big.Int).Exp(big.NewInt(10), big.NewInt(20), nil)),
			wantOk: true,
		},
		{
			name:   "zero",
			input:  json.Number("0"),
			want:   big.NewInt(0),
			wantOk: true,
		},
		{
			name:   "small integer",
			input:  json.Number("12345"),
			want:   big.NewInt(12345),
			wantOk: true,
		},
		{
			name:   "fractional value truncates",
			input:  json.Number("1.23e+1"),
			want:   big.NewInt(12),
			wantOk: true,
		},
		{
			name:   "decimal without exponent",
			input:  json.Number("123.456"),
			want:   big.NewInt(123),
			wantOk: true,
		},
		{
			name:   "decimal whole number",
			input:  json.Number("1000.0"),
			want:   big.NewInt(1000),
			wantOk: true,
		},
		{
			name:   "negative integer",
			input:  json.Number("-500"),
			want:   big.NewInt(-500),
			wantOk: true,
		},
		{
			name:   "invalid string",
			input:  json.Number("not_a_number"),
			want:   nil,
			wantOk: false,
		},
		{
			name:   "empty string",
			input:  json.Number(""),
			want:   nil,
			wantOk: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := jsonNumberToBigInt(tt.input)
			if tt.wantOk {
				require.True(t, ok, "input %q: parse failed, expected %s", tt.input, tt.want)
				assert.Equal(t, 0, tt.want.Cmp(got), "input %q: expected %s but got %s", tt.input, tt.want, got)
			} else {
				assert.False(t, ok, "input %q: expected parse failure but got %v", tt.input, got)
				assert.Nil(t, got, "input %q: expected nil but got %v", tt.input, got)
			}
		})
	}
}

// standbyAddrs returns n deterministic, distinct addresses standing in for a
// stake-descending standby pool.
func standbyAddrs(n int) []common.Address {
	out := make([]common.Address, n)
	for i := range out {
		out[i][0] = byte(i + 1)
	}
	return out
}

// TestSplitStandbyPoolPreUpgrade asserts that before the TIPUpgradeReward fork the
// whole standby pool is returned unsplit and no protector/observer tier is set,
// regardless of the configured caps.
func TestSplitStandbyPoolPreUpgrade(t *testing.T) {
	pool := standbyAddrs(5)

	info := MasternodesStatus{tipUpgradeReward: false}
	info.splitStandbyPool(pool, 3, 1) // caps must be ignored pre-upgrade

	assert.Equal(t, pool, info.Standbynodes)
	assert.Equal(t, 5, info.StandbynodesLen)
	assert.Nil(t, info.Protectornodes)
	assert.Nil(t, info.Observernodes)
	assert.Zero(t, info.ProtectorLen)
	assert.Zero(t, info.ObserverLen)
}

// TestSplitStandbyPoolPostUpgrade asserts that from the TIPUpgradeReward fork the
// standby pool is split deterministically according to the protector/observer caps,
// clamped to the pool size, and that the three tiers always reconcile back to the
// full pool.
func TestSplitStandbyPoolPostUpgrade(t *testing.T) {
	pool := standbyAddrs(10)

	tests := []struct {
		name          string
		maxProtector  int
		maxObserver   int
		wantProtector int
		wantObserver  int
		wantStandby   int
	}{
		{"caps within pool", 3, 4, 3, 4, 3},
		{"exact fit", 4, 6, 4, 6, 0},
		{"only protector tier", 4, 0, 4, 0, 6},
		{"zero caps keep all standby", 0, 0, 0, 0, 10},
		{"protector cap exceeds pool", 20, 5, 10, 0, 0},
		{"protector fills, observer overflows", 6, 20, 6, 4, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := MasternodesStatus{tipUpgradeReward: true}
			info.splitStandbyPool(pool, tt.maxProtector, tt.maxObserver)

			assert.Equal(t, tt.wantProtector, info.ProtectorLen)
			assert.Equal(t, tt.wantObserver, info.ObserverLen)
			assert.Equal(t, tt.wantStandby, info.StandbynodesLen)
			assert.Len(t, info.Protectornodes, tt.wantProtector)
			assert.Len(t, info.Observernodes, tt.wantObserver)
			assert.Len(t, info.Standbynodes, tt.wantStandby)

			// Deterministic order: protectors are the top slice, observers the
			// next, standbys the remainder.
			assert.Equal(t, pool[:tt.wantProtector], info.Protectornodes)
			assert.Equal(t, pool[tt.wantProtector:tt.wantProtector+tt.wantObserver], info.Observernodes)

			// Reconciliation: the tiers concatenate back to the full pool.
			got := make([]common.Address, 0, len(pool))
			got = append(got, info.Protectornodes...)
			got = append(got, info.Observernodes...)
			got = append(got, info.Standbynodes...)
			assert.Equal(t, pool, got)
		})
	}
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
	genesis, err := configBackend{chain: chain}.GenesisHeader(context.Background())
	require.NoError(t, err)
	require.NotNil(t, genesis)
}

func TestConfigBackendGenesisHeaderReturnsErrorWhenMissing(t *testing.T) {
	chain := newConfigChainMockWithCurrent(1500)
	chain.genesis = nil

	genesis, err := configBackend{chain: chain}.GenesisHeader(context.Background())
	require.Error(t, err)
	require.Nil(t, genesis)
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

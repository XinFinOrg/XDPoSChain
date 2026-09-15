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

package chainconfigview

import (
	"context"
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/common/hexutil"
	"github.com/XinFinOrg/XDPoSChain/core/forkid"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/params"
)

type stubBackend struct {
	genesis *types.Header
	current *types.Header
	cfg     *params.ChainConfig
}

func (b stubBackend) GenesisHeader(context.Context) (*types.Header, error) { return b.genesis, nil }
func (b stubBackend) CurrentHeader() *types.Header                         { return b.current }
func (b stubBackend) ChainConfig() *params.ChainConfig                     { return b.cfg }

func TestConfigBlocksSingleForkAfterHead(t *testing.T) {
	cfg := &params.ChainConfig{
		BerlinBlock: big.NewInt(1000),
	}

	current, next, last := configBlocks(cfg, 2000)
	if current == nil || current.Uint64() != 1000 {
		t.Fatalf("current = %v, want 1000", current)
	}
	if next != nil {
		t.Fatalf("next = %v, want nil", next)
	}
	if last != nil {
		t.Fatalf("last = %v, want nil", last)
	}
}

func TestConfigBlocksHeadBeyondAllForks(t *testing.T) {
	cfg := &params.ChainConfig{
		BerlinBlock:  big.NewInt(1000),
		EIP1559Block: big.NewInt(2000),
	}

	current, next, last := configBlocks(cfg, 3000)
	if current == nil || current.Uint64() != 2000 {
		t.Fatalf("current = %v, want 2000", current)
	}
	if next != nil {
		t.Fatalf("next = %v, want nil", next)
	}
	if last != nil {
		t.Fatalf("last = %v, want nil", last)
	}
}

func TestConfigBlocksWithFutureTransitionKeepsLast(t *testing.T) {
	cfg := &params.ChainConfig{
		BerlinBlock: big.NewInt(1000),
		LondonBlock: big.NewInt(2000),
		MergeBlock:  big.NewInt(3000),
	}

	current, next, last := configBlocks(cfg, 1500)
	if current == nil || current.Uint64() != 1000 {
		t.Fatalf("current = %v, want 1000", current)
	}
	if next == nil || next.Uint64() != 2000 {
		t.Fatalf("next = %v, want 2000", next)
	}
	if last == nil || last.Uint64() != 3000 {
		t.Fatalf("last = %v, want 3000", last)
	}
}

func TestBuildHeadBeyondAllForksOmitsNextAndLast(t *testing.T) {
	cfg := &params.ChainConfig{
		ChainID:      big.NewInt(51),
		BerlinBlock:  big.NewInt(1000),
		EIP1559Block: big.NewInt(2000),
		Ethash:       new(params.EthashConfig),
	}

	resp, err := Build(context.Background(), stubBackend{
		genesis: &types.Header{Number: big.NewInt(0)},
		current: &types.Header{Number: big.NewInt(3000)},
		cfg:     cfg,
	})
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}
	if resp.Current == nil || resp.Current.ActivationBlock != 2000 {
		t.Fatalf("current = %+v, want activation block 2000", resp.Current)
	}
	if resp.Next != nil {
		t.Fatalf("next = %v, want nil", resp.Next)
	}
	if resp.Last != nil {
		t.Fatalf("last = %v, want nil", resp.Last)
	}
}

func TestBuildWithoutScheduledForks(t *testing.T) {
	cfg := &params.ChainConfig{
		ChainID: big.NewInt(51),
		Ethash:  new(params.EthashConfig),
	}

	resp, err := Build(context.Background(), stubBackend{
		genesis: &types.Header{Number: big.NewInt(0)},
		current: &types.Header{Number: big.NewInt(25)},
		cfg:     cfg,
	})
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}
	if resp.Current == nil {
		t.Fatal("current = nil, want genesis config")
	}
	if resp.Current.ActivationBlock != 0 {
		t.Fatalf("current activation block = %d, want 0", resp.Current.ActivationBlock)
	}
	if resp.Next != nil {
		t.Fatalf("next = %v, want nil", resp.Next)
	}
	if resp.Last != nil {
		t.Fatalf("last = %v, want nil", resp.Last)
	}
}

func BenchmarkAssembleConfig(b *testing.B) {
	cfg := params.TestnetChainConfig.Clone()
	genesis := types.NewBlockWithHeader(&types.Header{Number: big.NewInt(0)})
	num := big.NewInt(90_000_000)

	b.Run("current", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = assembleConfig(cfg, genesis, num)
		}
	})
	b.Run("legacy", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = assembleConfigLegacy(cfg, genesis, num)
		}
	})
}

func assembleConfigLegacy(cfg *params.ChainConfig, genesis *types.Block, num *big.Int) *ConfigEntry {
	if num == nil {
		return nil
	}

	rules := cfg.Rules(num)
	precompiles := make(map[string]common.Address)
	for addr, precompile := range vm.ActivePrecompiledContracts(rules) {
		precompiles[precompile.Name()] = addr
	}
	block := num.Uint64()
	id := forkid.NewID(cfg, genesis, block).Hash
	return &ConfigEntry{
		ActivationBlock: block,
		ChainId:         (*hexutil.Big)(cfg.ChainID),
		ForkId:          id[:],
		ActiveForks:     cfg.ActiveForks(num),
		Precompiles:     precompiles,
		SystemContracts: cfg.ActiveSystemContracts(block),
	}
}

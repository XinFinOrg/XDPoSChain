package configapi

import (
	"context"
	"fmt"
	"math/big"
	"slices"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/common/hexutil"
	"github.com/XinFinOrg/XDPoSChain/core/forkid"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/XinFinOrg/XDPoSChain/rpc"
)

type Backend interface {
	HeaderByNumber(ctx context.Context, number rpc.BlockNumber) (*types.Header, error)
	CurrentHeader() *types.Header
	ChainConfig() *params.ChainConfig
}

type ConfigEntry struct {
	ActivationBlock uint64                    `json:"activationBlock"`
	ChainId         *hexutil.Big              `json:"chainId"`
	ForkId          hexutil.Bytes             `json:"forkId"`
	ActiveForks     []string                  `json:"activeForks"`
	Precompiles     map[string]common.Address `json:"precompiles"`
	SystemContracts map[string]common.Address `json:"systemContracts"`
}

type ConfigResponse struct {
	Current *ConfigEntry `json:"current"`
	Next    *ConfigEntry `json:"next"`
	Last    *ConfigEntry `json:"last"`
}

func Build(ctx context.Context, backend Backend) (*ConfigResponse, error) {
	genesis, err := backend.HeaderByNumber(ctx, 0)
	if err != nil {
		return nil, fmt.Errorf("unable to load genesis: %w", err)
	}
	if genesis == nil {
		return nil, fmt.Errorf("unable to load genesis: nil header")
	}
	genesisBlock := types.NewBlockWithHeader(genesis)

	current := backend.CurrentHeader()
	if current == nil {
		return nil, fmt.Errorf("unable to load current header: nil header")
	}
	if current.Number == nil {
		return nil, fmt.Errorf("unable to load current header: nil number")
	}
	cfg := backend.ChainConfig()
	if cfg == nil {
		return nil, fmt.Errorf("unable to load chain config: nil config")
	}

	currentBlock, nextBlock, lastBlock := configBlocks(cfg, current.Number.Uint64())
	resp := ConfigResponse{
		Current: assembleConfig(cfg, genesisBlock, currentBlock),
		Next:    assembleConfig(cfg, genesisBlock, nextBlock),
		Last:    assembleConfig(cfg, genesisBlock, lastBlock),
	}
	if resp.Next == nil {
		resp.Last = nil
	}
	return &resp, nil
}

func configBlocks(cfg *params.ChainConfig, head uint64) (*big.Int, *big.Int, *big.Int) {
	forkBlocks := cfg.GatherForks()
	if len(forkBlocks) == 0 {
		return new(big.Int), nil, nil
	}
	idx, found := slices.BinarySearch(forkBlocks, head)
	if found {
		idx++
	}

	current := new(big.Int)
	if idx > 0 {
		current.SetUint64(forkBlocks[idx-1])
	}

	var next *big.Int
	if idx < len(forkBlocks) {
		next = new(big.Int).SetUint64(forkBlocks[idx])
	}

	last := new(big.Int).SetUint64(forkBlocks[len(forkBlocks)-1])
	return current, next, last
}

func assembleConfig(cfg *params.ChainConfig, genesis *types.Block, num *big.Int) *ConfigEntry {
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

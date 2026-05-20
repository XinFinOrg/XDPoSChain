package XDCx

import (
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/common/lru"
	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/params"
)

type tokenDecimalTestChain struct {
	header *types.Header
	config *params.ChainConfig
	engine consensus.Engine
}

// Engine returns the consensus engine used by the test chain reader.
func (c *tokenDecimalTestChain) Engine() consensus.Engine {
	return c.engine
}

// GetHeader returns nil because this stub only exposes the current header.
func (c *tokenDecimalTestChain) GetHeader(common.Hash, uint64) *types.Header {
	return nil
}

// CurrentHeader returns the header configured for the test chain reader.
func (c *tokenDecimalTestChain) CurrentHeader() *types.Header {
	return c.header
}

// Config returns the chain config configured for the test chain reader.
func (c *tokenDecimalTestChain) Config() *params.ChainConfig {
	return c.config
}

// TestGetTokenDecimalWithoutRelayerConfigDoesNotPanic tests get token decimal without relayer config does not panic.
func TestGetTokenDecimalWithoutRelayerConfigDoesNotPanic(t *testing.T) {
	t.Parallel()

	statedb, err := state.New(types.EmptyRootHash, state.NewDatabase(rawdb.NewMemoryDatabase()))
	if err != nil {
		t.Fatalf("failed to create state db: %v", err)
	}
	if err := statedb.EnsureChainConfig(&params.ChainConfig{}); err != nil {
		t.Fatalf("failed to attach chain config: %v", err)
	}

	chain := &tokenDecimalTestChain{
		header: &types.Header{
			Number:     big.NewInt(1),
			Difficulty: big.NewInt(0),
			GasLimit:   1000000,
		},
		config: params.TestChainConfig,
		engine: ethash.NewFaker(),
	}

	XDCx := &XDCX{tokenDecimalCache: lru.NewCache[common.Address, *big.Int](defaultCacheLimit)}
	tokenAddr := common.HexToAddress("0x1000000000000000000000000000000000000001")

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("GetTokenDecimal panicked without relayer config: %v", r)
		}
	}()

	if _, err := XDCx.GetTokenDecimal(chain, statedb, tokenAddr); err == nil {
		t.Fatal("expected GetTokenDecimal to surface the contract call error")
	}
}

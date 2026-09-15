package core

import (
	"math/big"
	"testing"

	ethereum "github.com/XinFinOrg/XDPoSChain"
	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/params"
)

type tokenValidatorTestChain struct {
	header *types.Header
	config *params.ChainConfig
	engine consensus.Engine
}

func (c *tokenValidatorTestChain) Engine() consensus.Engine {
	return c.engine
}

func (c *tokenValidatorTestChain) GetHeader(common.Hash, uint64) *types.Header {
	return nil
}

func (c *tokenValidatorTestChain) CurrentHeader() *types.Header {
	return c.header
}

func (c *tokenValidatorTestChain) Config() *params.ChainConfig {
	return c.config
}

func TestCallContractWithStateAttachesChainConfigBeforeTRC21Read(t *testing.T) {
	t.Parallel()

	statedb, err := state.New(types.EmptyRootHash, state.NewDatabase(rawdb.NewMemoryDatabase()))
	if err != nil {
		t.Fatalf("failed to create state db: %v", err)
	}
	if statedb.ChainConfig() != nil {
		t.Fatal("expected fresh state db to start without chain config")
	}

	chainConfig := params.TestChainConfig
	chain := &tokenValidatorTestChain{
		header: &types.Header{
			Number:     big.NewInt(1),
			Difficulty: big.NewInt(0),
			GasLimit:   1000000,
		},
		config: chainConfig,
		engine: ethash.NewFaker(),
	}
	contractAddr := common.HexToAddress("0x1000000000000000000000000000000000000001")
	call := ethereum.CallMsg{
		From: common.HexToAddress("0x2000000000000000000000000000000000000002"),
		To:   &contractAddr,
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("CallContractWithState panicked: %v", r)
		}
	}()

	_, _ = CallContractWithState(call, chain, statedb)

	if statedb.ChainConfig() != chainConfig {
		t.Fatal("expected CallContractWithState to attach chain config to state db")
	}
}

func TestCallContractWithStateRejectsMissingChainConfig(t *testing.T) {
	t.Parallel()

	statedb, err := state.New(types.EmptyRootHash, state.NewDatabase(rawdb.NewMemoryDatabase()))
	if err != nil {
		t.Fatalf("failed to create state db: %v", err)
	}
	chain := &tokenValidatorTestChain{
		header: &types.Header{
			Number:     big.NewInt(1),
			Difficulty: big.NewInt(0),
			GasLimit:   1000000,
		},
		config: nil,
		engine: ethash.NewFaker(),
	}
	contractAddr := common.HexToAddress("0x1000000000000000000000000000000000000001")
	call := ethereum.CallMsg{
		From: common.HexToAddress("0x2000000000000000000000000000000000000002"),
		To:   &contractAddr,
	}

	_, err = CallContractWithState(call, chain, statedb)
	if err == nil || err.Error() != "state: missing chain config for state access" {
		t.Fatalf("unexpected error: %v", err)
	}
}

package XDPoS

import (
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/stretchr/testify/assert"
)

func TestAdaptorShouldShareDbWithV1Engine(t *testing.T) {
	database := rawdb.NewMemoryDatabase()
	config := params.TestXDPoSMockChainConfig
	engine := New(config, database)

	assert := assert.New(t)
	assert.Equal(engine.EngineV1.GetDb(), engine.GetDb())
}

func TestVerifyHeadersRejectsMixedConsensusBatch(t *testing.T) {
	database := rawdb.NewMemoryDatabase()
	config := params.TestXDPoSMockChainConfig
	engine := New(config, database)

	headers := []*types.Header{
		{Number: big.NewInt(900)},
		{Number: big.NewInt(901)},
	}
	fullVerifies := []bool{false, false}

	abort, results := engine.VerifyHeaders(nil, headers, fullVerifies)
	defer close(abort)

	assert.ErrorIs(t, <-results, ErrMixedConsensusBatch)
	assert.ErrorIs(t, <-results, ErrMixedConsensusBatch)
}

package engine_v2

import (
	"testing"

	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/stretchr/testify/assert"
)

func TestNewRequiresStartupValidatedV2Config(t *testing.T) {
	chainConfig := params.TestnetChainConfig.Clone()
	chainConfig.XDPoS = chainConfig.XDPoS.Clone()
	chainConfig.XDPoS.V2 = nil

	engine, err := New(chainConfig, rawdb.NewMemoryDatabase(), make(chan int), make(chan types.Round, 1))
	assert.Nil(t, engine)
	assert.EqualError(t, err, "engine_v2.New requires startup-validated XDPoS V2 config")
}

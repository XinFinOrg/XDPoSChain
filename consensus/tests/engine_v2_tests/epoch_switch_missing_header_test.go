package engine_v2_tests

import (
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/stretchr/testify/assert"
)

// missingHeaderChainReader serves every header from the wrapped reader except the
// one block number the test removes.
type missingHeaderChainReader struct {
	consensus.ChainReader
	missing uint64
}

func (r *missingHeaderChainReader) GetHeaderByNumber(number uint64) *types.Header {
	if number == r.missing {
		return nil
	}
	return r.ChainReader.GetHeaderByNumber(number)
}

func TestGetCurrentEpochSwitchBlockMissingHeader(t *testing.T) {
	t.Parallel()
	blockchain, _, _, _, _, _ := PrepareXDCTestBlockChainForV2Engine(t, 900, params.TestXDPoSMockChainConfig, nil)
	adaptor := blockchain.Engine().(*XDPoS.XDPoS)

	// 902 is past V2.SwitchBlock (900), so the adaptor routes to the v2 engine.
	checkpointNumber, epochNumber, err := adaptor.GetCurrentEpochSwitchBlock(
		&missingHeaderChainReader{ChainReader: blockchain, missing: 902}, big.NewInt(902))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "header 902 not found")
	assert.Equal(t, uint64(0), checkpointNumber)
	assert.Equal(t, uint64(0), epochNumber)
}

package engine_v2

import (
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
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

// After a head rewind the stored highestQuorumCert can still name a block the
// chain reader no longer holds. The lookup must then return nil, leaving the
// caller (XDPoS.FindParentBlockToAssign) to fall back to the current head, and
// must not panic or fabricate a parent.
func TestFindParentBlockToAssignStaleQC(t *testing.T) {
	x, chain, _ := newRepairFixture(t, 1350, []common.Address{{0x1}}, []*big.Int{big.NewInt(10)})
	x.highestQuorumCert = &types.QuorumCert{
		ProposedBlockInfo: &types.BlockInfo{
			Hash:   common.Hash{0x1},
			Round:  types.Round(1),
			Number: big.NewInt(1349),
		},
		Signatures: []types.Signature{},
	}

	assert.Nil(t, x.FindParentBlockToAssign(chain))
}

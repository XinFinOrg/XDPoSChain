package eth

import (
	"context"
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	internalethapi "github.com/XinFinOrg/XDPoSChain/internal/ethapi"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/XinFinOrg/XDPoSChain/rpc"
	"github.com/stretchr/testify/require"
)

// The block signer RPCs used to dial the node's own IPC endpoint before answering, although the
// answer comes from blocks the chain already holds. A node started with --ipcdisable has no
// endpoint to dial, so eth_getBlockSignersByHash and eth_getBlockSignersByNumber failed there.
//
// The chain below has no IPC endpoint at all. Its genesis extra data is a checkpoint header
// (vanity, the masternode address, the seal), so GetMasternodes answers with that masternode and
// the request reaches the code that used to dial. Genesis is the queried block, so there is no
// signed block to scan and the answer is an empty signer list.
func newBlockSignersFixture(t *testing.T) (*internalethapi.BlockChainAPI, *types.Block) {
	t.Helper()

	masternode := common.Address{0x01}
	extraData := make([]byte, 32)
	extraData = append(extraData, masternode.Bytes()...)
	extraData = append(extraData, make([]byte, crypto.SignatureLength)...)

	db := rawdb.NewMemoryDatabase()
	engine := XDPoS.NewFaker(db, params.TestXDPoSMockChainConfig)
	require.NotNil(t, engine)
	genesis := &core.Genesis{
		Config:    params.TestXDPoSMockChainConfig,
		BaseFee:   big.NewInt(params.InitialBaseFee),
		ExtraData: extraData,
	}
	chain, err := core.NewBlockChain(db, nil, genesis, engine, vm.Config{})
	require.NoError(t, err)
	t.Cleanup(chain.Stop)

	backend := &EthAPIBackend{eth: &Ethereum{blockchain: chain, engine: engine}}
	// What a node started with --ipcdisable cannot offer.
	require.Empty(t, chain.IPCEndpoint)
	require.Nil(t, chain.Client)

	block := chain.GetBlockByNumber(0)
	require.NotNil(t, block)

	api := internalethapi.NewBlockChainAPI(backend, chain)
	// The RPCs answer before reaching the code that used to dial when GetMasternodes comes
	// back empty, so pin the masternode the genesis extra data names: without it the test
	// would pass while covering nothing.
	masternodes, err := api.GetMasternodes(context.Background(), block)
	require.NoError(t, err)
	require.Equal(t, []common.Address{masternode}, masternodes)

	return api, block
}

func TestGetBlockSignersDoesNotNeedAnIPCEndpoint(t *testing.T) {
	api, genesis := newBlockSignersFixture(t)

	signers, err := api.GetBlockSignersByNumber(context.Background(), rpc.BlockNumber(0))
	require.NoError(t, err)
	require.Empty(t, signers)

	signers, err = api.GetBlockSignersByHash(context.Background(), genesis.Hash())
	require.NoError(t, err)
	require.Empty(t, signers)
}

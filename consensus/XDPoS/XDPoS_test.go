package XDPoS

import (
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
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

func TestCacheNoneTIPSigningTxsSupportsRawReceiptsWithoutTxHash(t *testing.T) {
	database := rawdb.NewMemoryDatabase()
	config := params.TestXDPoSMockChainConfig
	engine := New(config, database)

	signingTx := types.NewTransaction(
		0,
		common.BlockSignersBinary,
		big.NewInt(0),
		200000,
		big.NewInt(0),
		append(common.Hex2Bytes(common.HexSignMethod), make([]byte, 64)...),
	)
	normalTx := types.NewTransaction(
		1,
		common.Address{0x1},
		big.NewInt(0),
		21000,
		big.NewInt(0),
		nil,
	)
	receipts := []*types.Receipt{
		{Status: types.ReceiptStatusSuccessful},
		{Status: types.ReceiptStatusSuccessful},
	}

	cached := engine.CacheNoneTIPSigningTxs(&types.Header{Number: big.NewInt(1)}, []*types.Transaction{signingTx, normalTx}, receipts)

	assert.Len(t, cached, 1)
	assert.Equal(t, signingTx.Hash(), cached[0].Hash())
}

func TestCacheNoneTIPSigningTxsSkipsFailedSigningReceiptByIndex(t *testing.T) {
	database := rawdb.NewMemoryDatabase()
	config := params.TestXDPoSMockChainConfig
	engine := New(config, database)

	signingTx := types.NewTransaction(
		0,
		common.BlockSignersBinary,
		big.NewInt(0),
		200000,
		big.NewInt(0),
		append(common.Hex2Bytes(common.HexSignMethod), make([]byte, 64)...),
	)
	receipts := []*types.Receipt{{Status: types.ReceiptStatusFailed}}

	cached := engine.CacheNoneTIPSigningTxs(&types.Header{Number: big.NewInt(1)}, []*types.Transaction{signingTx}, receipts)

	assert.Empty(t, cached)
}

func TestCacheNoneTIPSigningTxsWithRawReceiptRoundTrip(t *testing.T) {
	database := rawdb.NewMemoryDatabase()
	config := params.TestXDPoSMockChainConfig
	engine := New(config, database)
	blockHash := common.HexToHash("0x1234")
	blockNumber := uint64(1)

	signingTx := types.NewTransaction(
		0,
		common.BlockSignersBinary,
		big.NewInt(0),
		200000,
		big.NewInt(0),
		append(common.Hex2Bytes(common.HexSignMethod), make([]byte, 64)...),
	)
	receipts := []*types.Receipt{{
		Status:            types.ReceiptStatusSuccessful,
		CumulativeGasUsed: 200000,
		TxHash:            signingTx.Hash(),
	}}

	rawdb.WriteReceipts(database, blockHash, blockNumber, receipts)
	rawReceipts := rawdb.ReadRawReceipts(database, blockHash, blockNumber)

	assert.Len(t, rawReceipts, 1)
	assert.Equal(t, common.Hash{}, rawReceipts[0].TxHash)

	cached := engine.CacheNoneTIPSigningTxs(&types.Header{Number: big.NewInt(int64(blockNumber))}, []*types.Transaction{signingTx}, rawReceipts)

	assert.Len(t, cached, 1)
	assert.Equal(t, signingTx.Hash(), cached[0].Hash())
}

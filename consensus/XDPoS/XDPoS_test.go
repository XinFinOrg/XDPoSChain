package XDPoS

import (
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus"
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

type verifyReaderMock struct {
	config         *params.ChainConfig
	fallbackHeader *types.Header
	fallbackBlock  *types.Block
}

func (m *verifyReaderMock) Config() *params.ChainConfig {
	return m.config
}

func (m *verifyReaderMock) CurrentHeader() *types.Header {
	return m.fallbackHeader
}

func (m *verifyReaderMock) GetHeader(hash common.Hash, number uint64) *types.Header {
	if m.fallbackHeader != nil && m.fallbackHeader.Hash() == hash && m.fallbackHeader.Number.Uint64() == number {
		return m.fallbackHeader
	}
	return nil
}

func (m *verifyReaderMock) GetHeaderByNumber(number uint64) *types.Header {
	if m.fallbackHeader != nil && m.fallbackHeader.Number.Uint64() == number {
		return m.fallbackHeader
	}
	return nil
}

func (m *verifyReaderMock) GetHeaderByHash(hash common.Hash) *types.Header {
	if m.fallbackHeader != nil && m.fallbackHeader.Hash() == hash {
		return m.fallbackHeader
	}
	return nil
}

func (m *verifyReaderMock) GetBlock(hash common.Hash, number uint64) *types.Block {
	if m.fallbackBlock != nil && m.fallbackBlock.Hash() == hash && m.fallbackBlock.NumberU64() == number {
		return m.fallbackBlock
	}
	return nil
}

var _ consensus.ChainReader = (*verifyReaderMock)(nil)

func TestVerifyChainReaderShadowsBatchHeaders(t *testing.T) {
	fallback := &types.Header{Number: big.NewInt(10)}
	mock := &verifyReaderMock{config: params.TestXDPoSMockChainConfig, fallbackHeader: fallback}

	parent := &types.Header{Number: big.NewInt(100)}
	child := &types.Header{Number: big.NewInt(101), ParentHash: parent.Hash()}
	reader := newVerifyChainReader(mock, []*types.Header{parent, child})

	byHashNumber := reader.GetHeader(parent.Hash(), parent.Number.Uint64())
	assert.NotNil(t, byHashNumber)
	assert.Equal(t, parent.Hash(), byHashNumber.Hash())

	byHash := reader.GetHeaderByHash(parent.Hash())
	assert.NotNil(t, byHash)
	assert.Equal(t, parent.Hash(), byHash.Hash())

	byNumber := reader.GetHeaderByNumber(parent.Number.Uint64())
	assert.NotNil(t, byNumber)
	assert.Equal(t, parent.Hash(), byNumber.Hash())

	batchBlock := reader.GetBlock(parent.Hash(), parent.Number.Uint64())
	assert.NotNil(t, batchBlock)
	assert.Equal(t, parent.Hash(), batchBlock.Hash())
	assert.Equal(t, parent.Number.Uint64(), batchBlock.NumberU64())
}

func TestVerifyChainReaderFallbackToUnderlyingChain(t *testing.T) {
	fallbackHeader := &types.Header{Number: big.NewInt(42)}
	fallbackBlock := types.NewBlockWithHeader(fallbackHeader)
	mock := &verifyReaderMock{
		config:         params.TestXDPoSMockChainConfig,
		fallbackHeader: fallbackHeader,
		fallbackBlock:  fallbackBlock,
	}

	reader := newVerifyChainReader(mock, nil)

	assert.Equal(t, fallbackHeader.Hash(), reader.GetHeaderByHash(fallbackHeader.Hash()).Hash())
	assert.Equal(t, fallbackHeader.Hash(), reader.GetHeaderByNumber(fallbackHeader.Number.Uint64()).Hash())
	assert.Equal(t, fallbackHeader.Hash(), reader.GetHeader(fallbackHeader.Hash(), fallbackHeader.Number.Uint64()).Hash())
	assert.Equal(t, fallbackBlock.Hash(), reader.GetBlock(fallbackBlock.Hash(), fallbackBlock.NumberU64()).Hash())
}

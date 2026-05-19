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

type stubChainReader struct {
	config          *params.ChainConfig
	headersByHash   map[common.Hash]*types.Header
	headersByNumber map[uint64]*types.Header
	blocksByHashNo  map[blockKey]*types.Block
}

type blockKey struct {
	hash   common.Hash
	number uint64
}

var _ consensus.ChainReader = (*stubChainReader)(nil)

func (s *stubChainReader) Config() *params.ChainConfig { return s.config }

func (s *stubChainReader) CurrentHeader() *types.Header { return nil }

func (s *stubChainReader) GetHeader(hash common.Hash, number uint64) *types.Header {
	header := s.GetHeaderByHash(hash)
	if header == nil || header.Number == nil || header.Number.Uint64() != number {
		return nil
	}
	return header
}

func (s *stubChainReader) GetHeaderByNumber(number uint64) *types.Header {
	if s.headersByNumber == nil {
		return nil
	}
	return s.headersByNumber[number]
}

func (s *stubChainReader) GetHeaderByHash(hash common.Hash) *types.Header {
	if s.headersByHash == nil {
		return nil
	}
	return s.headersByHash[hash]
}

func (s *stubChainReader) GetBlock(hash common.Hash, number uint64) *types.Block {
	if s.blocksByHashNo == nil {
		return nil
	}
	return s.blocksByHashNo[blockKey{hash: hash, number: number}]
}

func TestNewVerifyChainReaderWithNilChainReturnsNilSafeReader(t *testing.T) {
	reader := NewVerifyHeadersChainReader(nil, []*types.Header{{Number: big.NewInt(1)}}, nil).(*verifyChainReader)
	assert.NotNil(t, reader)
	assert.Nil(t, reader.Config())
	assert.Nil(t, reader.CurrentHeader())
	assert.Nil(t, reader.GetHeaderByNumber(2))
	assert.Nil(t, reader.GetHeaderByHash(common.Hash{}))
	assert.Nil(t, reader.GetHeader(common.Hash{}, 2))
	assert.Nil(t, reader.GetBlock(common.Hash{}, 2))
}

func TestVerifyChainReaderShadowsHeaderByNumber(t *testing.T) {
	baseHeader := &types.Header{Number: big.NewInt(100), Time: 1}
	batchHeader := &types.Header{Number: big.NewInt(100), Time: 2}

	base := &stubChainReader{
		config:          params.TestXDPoSMockChainConfig,
		headersByHash:   map[common.Hash]*types.Header{baseHeader.Hash(): baseHeader},
		headersByNumber: map[uint64]*types.Header{100: baseHeader},
	}

	reader := NewVerifyHeadersChainReader(base, []*types.Header{batchHeader}, nil).(*verifyChainReader)
	resolved := reader.GetHeaderByNumber(100)
	assert.NotNil(t, resolved)
	assert.Equal(t, batchHeader.Hash(), resolved.Hash())
}

func TestVerifyChainReaderResolvesParentFromBatch(t *testing.T) {
	parent := &types.Header{Number: big.NewInt(900), Time: 1}
	child := &types.Header{Number: big.NewInt(901), ParentHash: parent.Hash(), Time: 2}

	base := &stubChainReader{
		config:          params.TestXDPoSMockChainConfig,
		headersByHash:   map[common.Hash]*types.Header{},
		headersByNumber: map[uint64]*types.Header{},
	}

	reader := NewVerifyHeadersChainReader(base, []*types.Header{parent, child}, nil).(*verifyChainReader)
	resolved := reader.GetHeader(child.ParentHash, child.Number.Uint64()-1)
	assert.NotNil(t, resolved)
	assert.Equal(t, parent.Hash(), resolved.Hash())
}

func TestVerifyChainReaderDoesNotFabricateBatchBlocks(t *testing.T) {
	batchHeader := &types.Header{Number: big.NewInt(100), Time: 2}

	base := &stubChainReader{
		config:          params.TestXDPoSMockChainConfig,
		headersByHash:   map[common.Hash]*types.Header{},
		headersByNumber: map[uint64]*types.Header{},
	}

	reader := NewVerifyHeadersChainReader(base, []*types.Header{batchHeader}, nil).(*verifyChainReader)
	assert.Nil(t, reader.GetBlock(batchHeader.Hash(), batchHeader.Number.Uint64()))
}

func TestVerifyChainReaderExposesRealBatchBlocks(t *testing.T) {
	batchHeader := &types.Header{Number: big.NewInt(100), Time: 2}
	batchBlock := types.NewBlockWithHeader(batchHeader)

	base := &stubChainReader{
		config:          params.TestXDPoSMockChainConfig,
		headersByHash:   map[common.Hash]*types.Header{},
		headersByNumber: map[uint64]*types.Header{},
	}

	reader := NewVerifyHeadersChainReader(base, []*types.Header{batchHeader}, []*types.Block{batchBlock}).(*verifyChainReader)
	assert.Same(t, batchBlock, reader.GetBlock(batchHeader.Hash(), batchHeader.Number.Uint64()))
}

func TestVerifyChainReaderDelegatesBlockLookupToBaseChain(t *testing.T) {
	baseHeader := &types.Header{Number: big.NewInt(100), Time: 1}
	baseBlock := types.NewBlockWithHeader(baseHeader)

	base := &stubChainReader{
		config:          params.TestXDPoSMockChainConfig,
		headersByHash:   map[common.Hash]*types.Header{baseHeader.Hash(): baseHeader},
		headersByNumber: map[uint64]*types.Header{100: baseHeader},
		blocksByHashNo:  map[blockKey]*types.Block{{hash: baseHeader.Hash(), number: 100}: baseBlock},
	}

	reader := NewVerifyHeadersChainReader(base, nil, nil).(*verifyChainReader)
	assert.Same(t, baseBlock, reader.GetBlock(baseHeader.Hash(), 100))
}

func TestVerifyChainReaderReusesExistingWrapper(t *testing.T) {
	firstHeader := &types.Header{Number: big.NewInt(100), Time: 1}
	secondHeader := &types.Header{Number: big.NewInt(101), Time: 2}
	firstBlock := types.NewBlockWithHeader(firstHeader)
	secondBlock := types.NewBlockWithHeader(secondHeader)

	reader := NewVerifyHeadersChainReader(nil, []*types.Header{firstHeader}, []*types.Block{firstBlock})
	reused := NewVerifyHeadersChainReader(reader, []*types.Header{secondHeader}, []*types.Block{secondBlock})

	assert.Same(t, reader, reused)
	wrapped := reused.(*verifyChainReader)
	assert.Same(t, firstBlock, wrapped.GetBlock(firstHeader.Hash(), firstHeader.Number.Uint64()))
	assert.Nil(t, wrapped.GetHeaderByNumber(secondHeader.Number.Uint64()))
	assert.Nil(t, wrapped.GetBlock(secondHeader.Hash(), secondHeader.Number.Uint64()))
}

func TestVerifyHeadersMixedWithNilChainDoesNotPanic(t *testing.T) {
	database := rawdb.NewMemoryDatabase()
	config := params.TestXDPoSMockChainConfig
	engine, err := New(config, database)
	assert.NoError(t, err)

	headers := []*types.Header{
		{Number: big.NewInt(900)},
		{Number: big.NewInt(901), Validator: make([]byte, 65)},
	}
	fullVerifies := []bool{false, false}

	assert.NotPanics(t, func() {
		abort, results := engine.VerifyHeaders(nil, headers, fullVerifies)
		defer close(abort)

		err1 := <-results
		err2 := <-results
		_ = err1
		_ = err2
	})
}

func TestVerifyHeadersMixedEmitsV1ThenV2(t *testing.T) {
	database := rawdb.NewMemoryDatabase()
	config := params.TestXDPoSMockChainConfig
	engine, err := New(config, database)
	assert.NoError(t, err)

	base := &stubChainReader{
		config: config,
		headersByNumber: map[uint64]*types.Header{
			450: {Number: big.NewInt(450)},
			900: {Number: big.NewInt(900)},
		},
	}

	headers := []*types.Header{
		{Number: big.NewInt(900)},
		{Number: big.NewInt(901)},
	}
	fullVerifies := []bool{false, false}

	abort, results := engine.VerifyHeaders(base, headers, fullVerifies)
	defer close(abort)

	err1 := <-results
	err2 := <-results

	assert.NoError(t, err1)
	assert.Error(t, err2)
}

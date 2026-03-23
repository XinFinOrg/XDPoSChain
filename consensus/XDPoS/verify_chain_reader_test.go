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
}

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

func (s *stubChainReader) GetBlock(common.Hash, uint64) *types.Block { return nil }

func TestNewVerifyChainReaderWithNilChainReturnsNilSafeReader(t *testing.T) {
	reader := newVerifyChainReader(nil, []*types.Header{{Number: big.NewInt(1)}})
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

	reader := newVerifyChainReader(base, []*types.Header{batchHeader})
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

	reader := newVerifyChainReader(base, []*types.Header{parent, child})
	resolved := reader.GetHeader(child.ParentHash, child.Number.Uint64()-1)
	assert.NotNil(t, resolved)
	assert.Equal(t, parent.Hash(), resolved.Hash())
}

func TestVerifyHeadersMixedWithNilChainDoesNotPanic(t *testing.T) {
	database := rawdb.NewMemoryDatabase()
	config := params.TestXDPoSMockChainConfig
	engine := New(config, database)

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
	engine := New(config, database)

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

var _ consensus.ChainReader = (*stubChainReader)(nil)

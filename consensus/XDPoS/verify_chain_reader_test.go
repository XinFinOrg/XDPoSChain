package XDPoS

import (
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/XinFinOrg/XDPoSChain/trie"
	"github.com/stretchr/testify/assert"
)

func makeTestBlock(number int64, time int64, txs ...*types.Transaction) *types.Block {
	header := &types.Header{
		Number:     big.NewInt(number),
		Time:       big.NewInt(time),
		Difficulty: big.NewInt(1),
		GasLimit:   1_000_000,
	}
	return types.NewBlock(header, txs, nil, nil, trie.NewStackTrie(nil))
}

type stubVerifyChainReader struct {
	config          *params.ChainConfig
	currentHeader   *types.Header
	headersByHash   map[common.Hash]*types.Header
	headersByNumber map[uint64]*types.Header
	blocksByHashNo  map[hashAndNumber]*types.Block
}

func (s *stubVerifyChainReader) Config() *params.ChainConfig { return s.config }

func (s *stubVerifyChainReader) CurrentHeader() *types.Header { return s.currentHeader }

func (s *stubVerifyChainReader) GetHeader(hash common.Hash, number uint64) *types.Header {
	header := s.GetHeaderByHash(hash)
	if header == nil || header.Number == nil || header.Number.Uint64() != number {
		return nil
	}
	return header
}

func (s *stubVerifyChainReader) GetHeaderByNumber(number uint64) *types.Header {
	if s.headersByNumber == nil {
		return nil
	}
	return s.headersByNumber[number]
}

func (s *stubVerifyChainReader) GetHeaderByHash(hash common.Hash) *types.Header {
	if s.headersByHash == nil {
		return nil
	}
	return s.headersByHash[hash]
}

func (s *stubVerifyChainReader) GetBlock(hash common.Hash, number uint64) *types.Block {
	if s.blocksByHashNo == nil {
		return nil
	}
	return s.blocksByHashNo[hashAndNumber{hash: hash, number: number}]
}

func TestVerifyChainReaderWithNilChainIsNilSafe(t *testing.T) {
	batchHeader := &types.Header{Number: big.NewInt(1)}
	reader := NewVerifyHeadersChainReader(nil, []*types.Header{batchHeader}, nil).(*verifyChainReader)

	assert.NotNil(t, reader)
	assert.Nil(t, reader.Config())
	assert.Nil(t, reader.CurrentHeader())
	assert.Equal(t, batchHeader.Hash(), reader.GetHeaderByNumber(1).Hash())
	assert.Equal(t, batchHeader.Hash(), reader.GetHeaderByHash(batchHeader.Hash()).Hash())
	assert.Equal(t, batchHeader.Hash(), reader.GetHeader(batchHeader.Hash(), 1).Hash())
	assert.Nil(t, reader.GetBlock(batchHeader.Hash(), 1))
	assert.Nil(t, reader.GetHeader(common.Hash{}, 2))
	assert.Nil(t, reader.GetBlock(common.Hash{}, 2))
}

func TestVerifyChainReaderShadowsBatchEntries(t *testing.T) {
	baseHeader := &types.Header{Number: big.NewInt(100), Time: big.NewInt(1)}
	batchHeader := &types.Header{Number: big.NewInt(100), Time: big.NewInt(2)}
	batchTx := types.NewTransaction(1, common.Address{0x1}, big.NewInt(1), 21000, big.NewInt(1), []byte{0x1})
	batchBlock := makeTestBlock(100, 2, batchTx)
	batchHeader = batchBlock.Header()
	currentHeader := &types.Header{Number: big.NewInt(99), Time: big.NewInt(3)}
	baseBlock := types.NewBlockWithHeader(baseHeader)

	base := &stubVerifyChainReader{
		config:        params.TestXDPoSMockChainConfig,
		currentHeader: currentHeader,
		headersByHash: map[common.Hash]*types.Header{baseHeader.Hash(): baseHeader},
		headersByNumber: map[uint64]*types.Header{
			100: baseHeader,
		},
		blocksByHashNo: map[hashAndNumber]*types.Block{
			{hash: baseHeader.Hash(), number: 100}: baseBlock,
		},
	}

	reader := NewVerifyHeadersChainReader(base, []*types.Header{batchHeader}, []*types.Block{batchBlock}).(*verifyChainReader)

	assert.Equal(t, params.TestXDPoSMockChainConfig, reader.Config())
	assert.Equal(t, currentHeader.Hash(), reader.CurrentHeader().Hash())
	assert.Equal(t, batchHeader.Hash(), reader.GetHeaderByNumber(100).Hash())
	assert.Equal(t, batchHeader.Hash(), reader.GetHeaderByHash(batchHeader.Hash()).Hash())
	assert.Equal(t, batchHeader.Hash(), reader.GetHeader(batchHeader.Hash(), 100).Hash())
	assert.Equal(t, batchHeader.Hash(), reader.GetBlock(batchHeader.Hash(), 100).Hash())
	assert.Len(t, reader.GetBlock(batchHeader.Hash(), 100).Transactions(), 1)
	assert.Equal(t, baseHeader.Hash(), reader.GetBlock(baseHeader.Hash(), 100).Hash())
}

func TestVerifyChainReaderReusesExistingWrapper(t *testing.T) {
	firstTx := types.NewTransaction(1, common.Address{0x1}, big.NewInt(1), 21000, big.NewInt(1), []byte{0x1})
	secondTx := types.NewTransaction(2, common.Address{0x2}, big.NewInt(2), 21000, big.NewInt(1), []byte{0x2})
	firstBlock := makeTestBlock(100, 1, firstTx)
	secondBlock := makeTestBlock(101, 2, secondTx)

	reader := NewVerifyHeadersChainReader(nil, []*types.Header{firstBlock.Header()}, []*types.Block{firstBlock})
	reused := NewVerifyHeadersChainReader(reader, []*types.Header{secondBlock.Header()}, nil)

	assert.Same(t, reader, reused)
	wrapped := reused.(*verifyChainReader)
	assert.Len(t, wrapped.GetBlock(firstBlock.Hash(), firstBlock.NumberU64()).Transactions(), 1)
	assert.Nil(t, wrapped.GetHeaderByNumber(secondBlock.NumberU64()))
	assert.Nil(t, wrapped.GetBlock(secondBlock.Hash(), secondBlock.NumberU64()))

	reused = NewVerifyHeadersChainReader(reused, nil, []*types.Block{secondBlock})
	wrapped = reused.(*verifyChainReader)
	assert.Nil(t, wrapped.GetBlock(secondBlock.Hash(), secondBlock.NumberU64()))
}

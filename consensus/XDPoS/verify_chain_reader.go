package XDPoS

import (
	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/params"
)

type verifyChainReader struct {
	chain           consensus.ChainReader
	headersByHash   map[common.Hash]*types.Header
	headersByNumber map[uint64]*types.Header
	blocksByHashNo  map[hashAndNumber]*types.Block
}

type hashAndNumber struct {
	hash   common.Hash
	number uint64
}

var _ consensus.ChainReader = (*verifyChainReader)(nil)

func NewVerifyHeadersChainReader(chain consensus.ChainReader, headers []*types.Header, blocks []*types.Block) consensus.ChainReader {
	if reader, ok := chain.(*verifyChainReader); ok {
		return reader
	}
	reader := &verifyChainReader{
		chain:           chain,
		headersByHash:   make(map[common.Hash]*types.Header, len(headers)),
		headersByNumber: make(map[uint64]*types.Header, len(headers)),
		blocksByHashNo:  make(map[hashAndNumber]*types.Block, len(blocks)),
	}
	for _, header := range headers {
		if header == nil || header.Number == nil {
			continue
		}
		hash := header.Hash()
		number := header.Number.Uint64()
		reader.headersByHash[hash] = header
		if _, exists := reader.headersByNumber[number]; !exists {
			reader.headersByNumber[number] = header
		}
	}
	for _, block := range blocks {
		if block == nil {
			continue
		}
		reader.blocksByHashNo[hashAndNumber{hash: block.Hash(), number: block.NumberU64()}] = block
	}
	return reader
}

func (r *verifyChainReader) Config() *params.ChainConfig {
	if r.chain == nil {
		return nil
	}
	return r.chain.Config()
}

func (r *verifyChainReader) CurrentHeader() *types.Header {
	if r.chain == nil {
		return nil
	}
	return r.chain.CurrentHeader()
}

func (r *verifyChainReader) GetHeader(hash common.Hash, number uint64) *types.Header {
	if header, ok := r.headersByHash[hash]; ok && header.Number != nil && header.Number.Uint64() == number {
		return header
	}
	if r.chain == nil {
		return nil
	}
	return r.chain.GetHeader(hash, number)
}

func (r *verifyChainReader) GetHeaderByNumber(number uint64) *types.Header {
	if header, ok := r.headersByNumber[number]; ok {
		return header
	}
	if r.chain == nil {
		return nil
	}
	return r.chain.GetHeaderByNumber(number)
}

func (r *verifyChainReader) GetHeaderByHash(hash common.Hash) *types.Header {
	if header, ok := r.headersByHash[hash]; ok {
		return header
	}
	if r.chain == nil {
		return nil
	}
	return r.chain.GetHeaderByHash(hash)
}

func (r *verifyChainReader) GetBlock(hash common.Hash, number uint64) *types.Block {
	if block, ok := r.blocksByHashNo[hashAndNumber{hash: hash, number: number}]; ok {
		return block
	}
	if r.chain == nil {
		return nil
	}
	return r.chain.GetBlock(hash, number)
}

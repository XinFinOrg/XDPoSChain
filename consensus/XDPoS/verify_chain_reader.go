package XDPoS

import (
	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// verifyChainReader shadows chain lookups with headers in the current verify batch.
// This keeps verification deterministic when deep consensus paths query ancestors
// that are in-flight and not written to DB yet.
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

func newVerifyChainReader(chain consensus.ChainReader, headers []*types.Header) *verifyChainReader {
	reader := &verifyChainReader{
		chain:           chain,
		headersByHash:   make(map[common.Hash]*types.Header, len(headers)),
		headersByNumber: make(map[uint64]*types.Header, len(headers)),
		blocksByHashNo:  make(map[hashAndNumber]*types.Block, len(headers)),
	}
	for _, header := range headers {
		if header == nil || header.Number == nil {
			continue
		}
		h := header.Hash()
		n := header.Number.Uint64()
		reader.headersByHash[h] = header
		if _, exists := reader.headersByNumber[n]; !exists {
			reader.headersByNumber[n] = header
		}
		reader.blocksByHashNo[hashAndNumber{hash: h, number: n}] = types.NewBlockWithHeader(header)
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

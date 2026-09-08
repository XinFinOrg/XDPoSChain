package engine_v2

import (
	"math/big"
	"sync"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/stretchr/testify/assert"
)

// MockChainReader implements consensus.ChainReader and consensus.BlockStorer: a
// header added via AddHeader is both canonical at its height and a stored block
// (the mock stores headers only).
type MockChainReader struct {
	headers map[common.Hash]*types.Header
	numbers map[uint64]*types.Header
}

// NewMockChainReader creates a new mock chain reader
func NewMockChainReader() *MockChainReader {
	return &MockChainReader{
		headers: make(map[common.Hash]*types.Header),
		numbers: make(map[uint64]*types.Header),
	}
}

// AddHeader makes a header canonical at its height (last write wins).
func (m *MockChainReader) AddHeader(header *types.Header) {
	m.headers[header.Hash()] = header
	m.numbers[header.Number.Uint64()] = header
}

// Config implements consensus.ChainReader
func (m *MockChainReader) Config() *params.ChainConfig {
	return nil
}

// CurrentHeader implements consensus.ChainReader
func (m *MockChainReader) CurrentHeader() *types.Header {
	return nil
}

// GetHeader implements consensus.ChainReader
func (m *MockChainReader) GetHeader(hash common.Hash, number uint64) *types.Header {
	return nil
}

// GetHeaderByNumber implements consensus.ChainReader
func (m *MockChainReader) GetHeaderByNumber(number uint64) *types.Header {
	return m.numbers[number]
}

// HasBlock implements consensus.BlockStorer.
func (m *MockChainReader) HasBlock(hash common.Hash, number uint64) bool {
	return m.headers[hash] != nil
}

// GetHeaderByHash implements consensus.ChainReader
func (m *MockChainReader) GetHeaderByHash(hash common.Hash) *types.Header {
	return m.headers[hash]
}

// GetBlock implements consensus.ChainReader
func (m *MockChainReader) GetBlock(hash common.Hash, number uint64) *types.Block {
	return nil
}

// TestVerifyVoteMessage_VoteRoundTooOld tests that votes with rounds below
// the current round are rejected immediately
func TestVerifyVoteMessage_VoteRoundTooOld(t *testing.T) {
	mockChain := NewMockChainReader()

	engine := &XDPoS_v2{
		currentRound: 10,
		lock:         sync.RWMutex{},
	}

	// Create a vote with a round number less than current round
	vote := &types.Vote{
		ProposedBlockInfo: &types.BlockInfo{
			Hash:   common.StringToHash("some-block"),
			Round:  5, // Less than currentRound (10)
			Number: big.NewInt(50),
		},
		Signature: make([]byte, 65),
		GapNumber: 0,
	}

	verified, err := engine.VerifyVoteMessage(mockChain, vote)

	// Should reject the vote without error
	assert.False(t, verified, "Should return false for vote with round < currentRound")
	assert.NoError(t, err, "Should not return an error for old round votes")
}

// blockInfoOf builds the BlockInfo shape the voting rule walks.
func blockInfoOf(h *types.Header) *types.BlockInfo {
	return &types.BlockInfo{Hash: h.Hash(), Number: h.Number}
}

// TestIsExtendingFromAncestor covers the voting rule's parent walk directly:
// since the handler gates on canonicality, no handler-level test can reach the
// walk's positive branch. Both branches are safety-critical — a false positive
// votes off the locked chain, a false negative stalls the node.
func TestIsExtendingFromAncestor(t *testing.T) {
	// 1 <- 2 <- 3, with 2' a same-height fork of 2.
	mockChain := NewMockChainReader()
	h1 := &types.Header{Number: big.NewInt(1)}
	h2 := &types.Header{Number: big.NewInt(2), ParentHash: h1.Hash()}
	h3 := &types.Header{Number: big.NewInt(3), ParentHash: h2.Hash()}
	forkH2 := &types.Header{Number: big.NewInt(2), ParentHash: h1.Hash(), Coinbase: common.BytesToAddress([]byte{0x02})}
	for _, h := range []*types.Header{h1, h2, h3} {
		mockChain.AddHeader(h)
	}
	engine := &XDPoS_v2{}

	// Positive branch: two hops down to the locked ancestor.
	extended, err := engine.isExtendingFromAncestor(mockChain, blockInfoOf(h3), blockInfoOf(h1))
	assert.NoError(t, err)
	assert.True(t, extended, "h3 extends the locked ancestor h1")

	// Negative branch: h3's chain bottoms out at h1, not at the forked 2'.
	extended, err = engine.isExtendingFromAncestor(mockChain, blockInfoOf(h3), blockInfoOf(forkH2))
	assert.NoError(t, err)
	assert.False(t, extended, "h3 does not extend the forked ancestor 2'")

	// Zero-iteration mismatch: the proposed block sits below the locked
	// ancestor, so the walk never runs and only the direct hash comparison
	// can reject it. This is the geometry of
	// TestShouldNotSendVoteMsgIfBlockNotExtendedFromAncestor.
	extended, err = engine.isExtendingFromAncestor(mockChain, blockInfoOf(h1), blockInfoOf(h2))
	assert.NoError(t, err)
	assert.False(t, extended, "h1 is below the locked ancestor h2")

	// A missing parent aborts the walk with an error instead of silently
	// reporting false: the proposed block's own header is not in the chain.
	missing := &types.BlockInfo{Hash: common.StringToHash("missing"), Number: big.NewInt(3)}
	extended, err = engine.isExtendingFromAncestor(mockChain, missing, blockInfoOf(h1))
	assert.Error(t, err)
	assert.False(t, extended)
}

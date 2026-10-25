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

// MockChainReader is a mock implementation of consensus.ChainReader
type MockChainReader struct {
	headers map[common.Hash]*types.Header
}

// NewMockChainReader creates a new mock chain reader
func NewMockChainReader() *MockChainReader {
	return &MockChainReader{
		headers: make(map[common.Hash]*types.Header),
	}
}

// AddHeader adds a header to the mock chain
func (m *MockChainReader) AddHeader(header *types.Header) {
	m.headers[header.Hash()] = header
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
	return nil
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

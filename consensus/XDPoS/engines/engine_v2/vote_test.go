package engine_v2

import (
	"context"
	"log/slog"
	"math/big"
	"sync"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/log"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/stretchr/testify/assert"
)

// memoryHandler captures log records for inspection in tests.
type memoryHandler struct {
	mu      sync.Mutex
	attrs   []slog.Attr
	records []slog.Record
}

func newMemoryHandler() *memoryHandler {
	return &memoryHandler{}
}

func (h *memoryHandler) Enabled(_ context.Context, _ slog.Level) bool { return true }

func (h *memoryHandler) Handle(_ context.Context, r slog.Record) error {
	clone := r.Clone()
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, clone)
	return nil
}

func (h *memoryHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &memoryHandler{attrs: append(append([]slog.Attr{}, h.attrs...), attrs...)}
}

func (h *memoryHandler) WithGroup(_ string) slog.Handler { return h }

func (h *memoryHandler) Records() []slog.Record {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]slog.Record, len(h.records))
	copy(out, h.records)
	return out
}

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

// TestVerifyVoteMessage_HeaderNotPresent tests the behavior when a vote arrives
// before its corresponding block header is available.
//
// This test verifies that VerifyVoteMessage handles the normal timing condition
// where votes may arrive before the block header itself, returning (false, nil)
// and logging at Debug level rather than Error level.
func TestVerifyVoteMessage_HeaderNotPresent(t *testing.T) {
	// Create a mock chain reader with no headers
	mockChain := NewMockChainReader()

	// Capture logs to ensure Debug (and no Error) is emitted
	memHandler := newMemoryHandler()
	log.SetDefault(log.NewLogger(memHandler))
	defer log.SetDefault(log.NewLogger(log.DiscardHandler()))

	// Create the XDPoS_v2 engine
	engine := &XDPoS_v2{
		currentRound: 10,
		lock:         sync.RWMutex{},
	}

	// Create a vote for a block that doesn't exist in the chain
	vote := &types.Vote{
		ProposedBlockInfo: &types.BlockInfo{
			Hash:   common.StringToHash("nonexistent-block"),
			Round:  10,
			Number: big.NewInt(100),
		},
		Signature: make([]byte, 65),
		GapNumber: 0,
	}

	// Call VerifyVoteMessage
	verified, err := engine.VerifyVoteMessage(mockChain, vote)

	// Verify the expected behavior:
	// 1. Should return false (not verified)
	assert.False(t, verified, "Should return false when header is not present")

	// 2. Should return nil error (deferred verification)
	assert.NoError(t, err, "Should not error when header is absent; vote will be retried")

	// 3. Should log at Debug level and not emit Error-level logs
	records := memHandler.Records()
	var hasDebug, hasError bool
	for _, rec := range records {
		switch rec.Level {
		case slog.LevelDebug:
			hasDebug = true
		case slog.LevelError, log.LevelCrit:
			hasError = true
		}
	}
	assert.True(t, hasDebug, "Expected a debug log when header is missing")
	assert.False(t, hasError, "Should not emit error-level logs for missing header")
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

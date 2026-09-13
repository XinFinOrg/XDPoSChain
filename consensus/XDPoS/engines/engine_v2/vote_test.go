package engine_v2

import (
	"context"
	"log/slog"
	"math/big"
	"sync"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/types"
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
	headers       map[common.Hash]*types.Header
	currentHeader *types.Header
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

// SetCurrentHeader sets the header CurrentHeader returns.
func (m *MockChainReader) SetCurrentHeader(header *types.Header) {
	m.currentHeader = header
}

// CurrentHeader implements consensus.ChainReader
func (m *MockChainReader) CurrentHeader() *types.Header {
	return m.currentHeader
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

// TestSendVoteUnusableGapSchedule pins the sendVote guard: the gap lookup
// happens before the vote is signed, so no private key is needed. The epoch
// switch info comes from the cache getEpochSwitchInfo consults before it reads
// the chain, so a nil chain is enough.
func TestSendVoteUnusableGapSchedule(t *testing.T) {
	blockHash := common.HexToHash("0x2")
	tests := []struct {
		name   string
		config *params.XDPoSConfig
		want   []string
		// unsetEpoch marks the row whose defect is the caller's, not the schedule's.
		unsetEpoch bool
	}{
		{"missing config", nil, []string{"[sendVote]", "nil config", "number: 900"}, false},
		{"zero gap", gapScheduleConfig(900, 0), []string{"[sendVote]", "XDPoS.Gap 0 designates no gap block inside XDPoS.Epoch 900", "number: 900"}, false},
		{"gap equal to epoch", gapScheduleConfig(900, 900), []string{"[sendVote]", "XDPoS.Gap 900 designates no gap block of its own inside XDPoS.Epoch 900", "number: 900"}, false},
		{"gap above epoch", gapScheduleConfig(900, 1200), []string{"[sendVote]", "XDPoS.Gap 1200 designates no gap block inside XDPoS.Epoch 900", "number: 900"}, false},
		{"unset epoch", gapScheduleConfig(0, 450), []string{"[sendVote]", "XDPoS.Epoch is unset", "number: 900", "gap: 450"}, true},
		{"epoch one leaves no usable gap", gapScheduleConfig(1, 0), []string{"[sendVote]", "XDPoS.Epoch 1 designates no gap block", "number: 900"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			x := gapScheduleEngine(tt.config)
			seedEpochSwitch(x, blockHash, 900)
			blockInfo := &types.BlockInfo{Hash: blockHash, Number: big.NewInt(901), Round: 1}

			err := x.sendVote(nil, blockInfo)
			switch {
			case tt.unsetEpoch:
				assertUnsetEpochInGapPath(t, err, tt.want)
			case tt.config == nil:
				assertMissingXDPoSConfig(t, err, tt.want)
			default:
				assertUnusableGapSchedule(t, err, tt.want)
			}
		})
	}
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

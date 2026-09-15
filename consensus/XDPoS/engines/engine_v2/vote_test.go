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

// MockChainReader is a mock implementation of consensus.ChainReader that
// also satisfies consensus.BlockStorer, so handler-level tests can run
// consensus.ShouldHandleProposedBlock against it without the integration
// package. Headers registered via AddHeader serve as the canonical chain
// (GetHeaderByNumber) and count as stored blocks (HasBlock): the mock
// stores headers only, so header presence is its storage notion.
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

// AddHeader adds a header to the mock chain, making it the canonical
// header at its height (last write wins) and marking its block stored.
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

// HasBlock implements consensus.BlockStorer: a registered header counts as
// a stored block (the mock stores headers only).
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

// blockInfoOf turns a header into the BlockInfo shape the voting rule and
// forensics pass around. The round is irrelevant to isExtendingFromAncestor,
// which only walks hashes and numbers.
func blockInfoOf(h *types.Header) *types.BlockInfo {
	return &types.BlockInfo{Hash: h.Hash(), Number: h.Number}
}

// TestIsExtendingFromAncestor covers the parent walk of the HotStuff voting
// rule at the rule layer. The handler-level tests cannot reach the positive
// branch anymore: since ProposedBlockHandler gates on canonicality, a
// proposed block on the locked ancestor's own chain that passes the gate
// always outranks the lockQC round and returns before the walk (see
// TestShouldNotSendVoteMsgIfCanonicalBlockNotExtendedFromForkedAncestor),
// and the forensics caller's positive path is only exercised by a skipped
// test. Both branches of the walk are safety-critical — a false positive
// lets a node vote off the locked chain, a false negative stalls it — so
// the walk itself gets direct coverage here.
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

	// Positive branch: the walk runs two hops down the parent chain and
	// lands exactly on the locked ancestor.
	extended, err := engine.isExtendingFromAncestor(mockChain, blockInfoOf(h3), blockInfoOf(h1))
	assert.NoError(t, err)
	assert.True(t, extended, "h3 extends the locked ancestor h1")

	// Negative branch with the walk executed: h3's parent chain bottoms out
	// at h1, not at the forked ancestor 2', so the final hash comparison
	// rejects the block. This is the geometry
	// TestShouldNotSendVoteMsgIfCanonicalBlockNotExtendedFromForkedAncestor
	// exercises through verifyVotingRule.
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

package engine_v2

import (
	"errors"
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/stretchr/testify/assert"
)

// headReader reports a CurrentHeader (MockChainReader returns nil) and counts
// canonical header reads, so a test can tell whether a gate ran before
// getSnapshot.
type headReader struct {
	*MockChainReader
	head        *types.Header
	headerReads int
}

func (r *headReader) CurrentHeader() *types.Header { return r.head }

func (r *headReader) GetHeaderByNumber(number uint64) *types.Header {
	r.headerReads++
	return r.MockChainReader.GetHeaderByNumber(number)
}

// TestVerifyTCRejectsGapNumberBeforeSnapshot pins the DB-free part of the TC
// gate: a gap number that is not a gap block must be rejected before
// getSnapshot reads a canonical header.
func TestVerifyTCRejectsGapNumberBeforeSnapshot(t *testing.T) {
	chain := &headReader{MockChainReader: NewMockChainReader(), head: &types.Header{Number: big.NewInt(100000)}}
	engine := &XDPoS_v2{config: &params.XDPoSConfig{Epoch: 900, Gap: 450}}
	tc := &types.TimeoutCert{Round: 1, Signatures: []types.Signature{{1}}, GapNumber: 451}

	err := engine.verifyTC(chain, tc)

	assert.True(t, errors.Is(err, errGapNumberOutOfWindow))
	assert.Zero(t, chain.headerReads, "the gate must run before getSnapshot reads a header")
}

// TestTCGapNumberInWindow walks the gate itself: the chain-start fallback, gap
// blocks inside and outside epoch*3 of the head, a non-gap height, readers
// without a head, and a schedule that designates no gap block.
func TestTCGapNumberInWindow(t *testing.T) {
	engine := &XDPoS_v2{config: &params.XDPoSConfig{Epoch: 900, Gap: 450}}
	noSchedule := &XDPoS_v2{config: &params.XDPoSConfig{Epoch: 900, Gap: 0}}
	// 99450 and 98550 are gap blocks of the 900 schedule; 96750 is the next one
	// down, 3250 below the head and therefore outside the 2700 window. 96750 and
	// 102150 are the inclusive boundaries of the 2700 window around 99450. 450
	// and 4050 are gap blocks above smallHead 100: 350 and 3950 above it, the
	// second one outside the window.
	bigHead := &headReader{MockChainReader: NewMockChainReader(), head: &types.Header{Number: big.NewInt(100000)}}
	smallHead := &headReader{MockChainReader: NewMockChainReader(), head: &types.Header{Number: big.NewInt(100)}}
	headAtAheadBoundary := &headReader{MockChainReader: NewMockChainReader(), head: &types.Header{Number: big.NewInt(96750)}}
	headAtBehindBoundary := &headReader{MockChainReader: NewMockChainReader(), head: &types.Header{Number: big.NewInt(102150)}}
	headBeforeAheadBoundary := &headReader{MockChainReader: NewMockChainReader(), head: &types.Header{Number: big.NewInt(96749)}}
	headPastBehindBoundary := &headReader{MockChainReader: NewMockChainReader(), head: &types.Header{Number: big.NewInt(102151)}}
	noHead := NewMockChainReader()

	for _, test := range []struct {
		name   string
		engine *XDPoS_v2
		chain  consensus.ChainReader
		gap    uint64
		want   bool
	}{
		{name: "chain start fallback below the window", engine: engine, chain: smallHead, gap: 0, want: true},
		{name: "chain start fallback outside the window", engine: engine, chain: bigHead, gap: 0},
		{name: "gap block near the head", engine: engine, chain: bigHead, gap: 99450, want: true},
		{name: "gap block one epoch earlier", engine: engine, chain: bigHead, gap: 98550, want: true},
		{name: "gap block ahead of the head, inside the window", engine: engine, chain: smallHead, gap: 450, want: true},
		{name: "gap block ahead of the head, outside the window", engine: engine, chain: smallHead, gap: 4050},
		{name: "gap block outside the window", engine: engine, chain: bigHead, gap: 96750},
		{name: "gap block at the ahead window boundary", engine: engine, chain: headAtAheadBoundary, gap: 99450, want: true},
		{name: "gap block at the behind window boundary", engine: engine, chain: headAtBehindBoundary, gap: 99450, want: true},
		{name: "gap block just outside the ahead boundary", engine: engine, chain: headBeforeAheadBoundary, gap: 99450},
		{name: "gap block just outside the behind boundary", engine: engine, chain: headPastBehindBoundary, gap: 99450},
		{name: "non gap height inside the window", engine: engine, chain: bigHead, gap: 99451},
		{name: "reader without a head falls back to the schedule", engine: engine, chain: noHead, gap: 450, want: true},
		{name: "reader without a head still rejects a non gap height", engine: engine, chain: noHead, gap: 451},
		{name: "schedule without a gap block admits everything", engine: noSchedule, chain: bigHead, gap: 12345, want: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, test.engine.tcGapNumberInWindow(test.chain, test.gap))
		})
	}
}

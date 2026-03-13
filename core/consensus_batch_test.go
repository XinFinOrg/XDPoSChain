package core

import (
	"math/big"
	"reflect"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/params"
)

func TestSplitHeadersByConsensusVersion_XDPoS(t *testing.T) {
	makeHeaders := func(numbers ...int64) []*types.Header {
		headers := make([]*types.Header, 0, len(numbers))
		for _, n := range numbers {
			headers = append(headers, &types.Header{Number: big.NewInt(n)})
		}
		return headers
	}

	tests := []struct {
		name     string
		headers  []*types.Header
		expected []consensusHeaderBatch
	}{
		{
			name:     "zero blocks",
			headers:  makeHeaders(),
			expected: nil,
		},
		{
			name:     "single v1 block",
			headers:  makeHeaders(900),
			expected: []consensusHeaderBatch{{start: 0, end: 1}},
		},
		{
			name:     "single v2 block",
			headers:  makeHeaders(901),
			expected: []consensusHeaderBatch{{start: 0, end: 1}},
		},
		{
			name:     "multiple v1 blocks",
			headers:  makeHeaders(899, 900),
			expected: []consensusHeaderBatch{{start: 0, end: 2}},
		},
		{
			name:     "multiple v2 blocks",
			headers:  makeHeaders(901, 902),
			expected: []consensusHeaderBatch{{start: 0, end: 2}},
		},
		{
			name:     "single v1 and multiple v2 blocks",
			headers:  makeHeaders(900, 901, 902),
			expected: []consensusHeaderBatch{{start: 0, end: 1}, {start: 1, end: 3}},
		},
		{
			name:     "multiple v1 and single v2 block",
			headers:  makeHeaders(899, 900, 901),
			expected: []consensusHeaderBatch{{start: 0, end: 2}, {start: 2, end: 3}},
		},
		{
			name:     "multiple v1 and multiple v2 blocks",
			headers:  makeHeaders(899, 900, 901, 902),
			expected: []consensusHeaderBatch{{start: 0, end: 2}, {start: 2, end: 4}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := splitHeadersByConsensusVersion(params.TestXDPoSMockChainConfig, tt.headers)
			if !reflect.DeepEqual(got, tt.expected) {
				t.Fatalf("unexpected batch split, got=%+v expected=%+v", got, tt.expected)
			}
		})
	}
}

func TestSplitHeadersByConsensusVersion_NonXDPoS(t *testing.T) {
	headers := []*types.Header{
		{Number: big.NewInt(1)},
		{Number: big.NewInt(2)},
	}
	batches := splitHeadersByConsensusVersion(nil, headers)
	if len(batches) != 1 {
		t.Fatalf("expected 1 batch, got %d", len(batches))
	}
	if batches[0].start != 0 || batches[0].end != len(headers) {
		t.Fatalf("unexpected batch range: %+v", batches[0])
	}
}

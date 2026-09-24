package downloader

import (
	"math/big"
	"slices"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// configOnlyChain answers Config() for the split, which reads nothing else from
// the chain. The embedded interface is nil, so any other call on it panics
// instead of answering silently.
type configOnlyChain struct {
	BlockChain
	cfg *params.ChainConfig
}

func (c configOnlyChain) Config() *params.ChainConfig { return c.cfg }

func blocksInRange(from, to uint64) []*types.Block {
	blocks := make([]*types.Block, 0, to-from+1)
	for number := from; number <= to; number++ {
		blocks = append(blocks, types.NewBlockWithHeader(&types.Header{Number: new(big.Int).SetUint64(number)}))
	}
	return blocks
}

func numbersOf(blocks []*types.Block) []uint64 {
	numbers := make([]uint64, 0, len(blocks))
	for _, block := range blocks {
		numbers = append(numbers, block.NumberU64())
	}
	return numbers
}

// TestSplitBlocksForVerification pins where an import batch is cut before it is
// handed to InsertChain. The header verification of an epoch-switch block reads
// two things the executing node only writes while it runs: the snapshot its gap
// block writes, and (in the v1 validators check) the state of the block before
// it. VerifyHeaders verifies a whole batch up-front, so a segment must never
// leave a block of it depending on another block of the same segment having been
// executed.
func TestSplitBlocksForVerification(t *testing.T) {
	// TestXDPoSMockChainConfig runs Epoch 900 / Gap 450, so the gap blocks sit
	// at offset 450 and the epoch switches on 900, 1800, ...
	noGapSchedule := params.TestXDPoSMockChainConfig.Clone()
	noGapSchedule.XDPoS.Gap = 0

	for _, tc := range []struct {
		name   string
		cfg    *params.ChainConfig
		blocks []*types.Block
		want   [][2]uint64 // inclusive ranges, in order
	}{
		{
			name:   "epoch without a checkpoint inside",
			blocks: blocksInRange(451, 899),
			want:   [][2]uint64{{451, 899}},
		},
		{
			name:   "checkpoint with its parent in the batch",
			blocks: blocksInRange(451, 1350),
			want:   [][2]uint64{{451, 899}, {900, 1350}},
		},
		{
			name:   "gap block and the following checkpoint",
			blocks: blocksInRange(1350, 1800),
			want:   [][2]uint64{{1350, 1350}, {1351, 1799}, {1800, 1800}},
		},
		{
			name:   "batch starting on the checkpoint",
			blocks: blocksInRange(900, 1350),
			want:   [][2]uint64{{900, 1350}},
		},
		{
			name:   "two epochs",
			blocks: blocksInRange(451, 1800),
			want:   [][2]uint64{{451, 899}, {900, 1350}, {1351, 1799}, {1800, 1800}},
		},
		{
			name:   "single block",
			blocks: blocksInRange(900, 900),
			want:   [][2]uint64{{900, 900}},
		},
		{
			name:   "schedule without a usable gap offset: the epoch switch still cuts",
			cfg:    noGapSchedule,
			blocks: blocksInRange(451, 1350),
			want:   [][2]uint64{{451, 899}, {900, 1350}},
		},
		{
			name:   "chain without XDPoS",
			cfg:    params.TestChainConfig,
			blocks: blocksInRange(1, 10),
			want:   [][2]uint64{{1, 10}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tc.cfg
			if cfg == nil {
				cfg = params.TestXDPoSMockChainConfig
			}
			downloader := &Downloader{blockchain: configOnlyChain{cfg: cfg}}

			segments := downloader.splitBlocksForVerification(tc.blocks)

			got := make([][2]uint64, 0, len(segments))
			var flat []uint64
			for _, segment := range segments {
				if len(segment) == 0 {
					t.Fatalf("empty segment in %v", got)
				}
				got = append(got, [2]uint64{segment[0].NumberU64(), segment[len(segment)-1].NumberU64()})
				flat = append(flat, numbersOf(segment)...)
			}
			if !slices.Equal(got, tc.want) {
				t.Fatalf("segments %v, want %v", got, tc.want)
			}
			// Whatever the cuts are, every block has to be imported exactly once
			// and in order.
			if !slices.Equal(flat, numbersOf(tc.blocks)) {
				t.Fatalf("blocks %v, want %v", flat, numbersOf(tc.blocks))
			}
		})
	}
}

// recordingChain answers Config() for the split and records the batches handed
// to InsertChain, in the order they were handed over. The embedded interface is
// nil, so any other call on it panics instead of answering silently.
type recordingChain struct {
	BlockChain
	cfg      *params.ChainConfig
	segments [][]uint64
}

func (c *recordingChain) Config() *params.ChainConfig { return c.cfg }

func (c *recordingChain) InsertChain(blocks types.Blocks) (int, error) {
	c.segments = append(c.segments, numbersOf(blocks))
	return 0, nil
}

// TestImportBlockResultsSplitsBeforeVerification pins that the split reaches
// InsertChain, and that what reaches it keeps a batch from leaving an
// epoch-switch block in the same segment as the block whose state its
// verification reads.
//
// That invariant is what the split exists for, and it does not follow from the
// segment boundaries alone, so it is asserted directly: an epoch-switch block
// may only be the first block of the segment it is imported in.
func TestImportBlockResultsSplitsBeforeVerification(t *testing.T) {
	const epoch = uint64(900) // TestXDPoSMockChainConfig runs Epoch 900 / Gap 450

	chain := &recordingChain{cfg: params.TestXDPoSMockChainConfig}
	downloader := &Downloader{blockchain: chain, quitCh: make(chan struct{})}

	blocks := blocksInRange(451, 1800)
	results := make([]*fetchResult, 0, len(blocks))
	for _, block := range blocks {
		results = append(results, &fetchResult{Header: block.Header()})
	}
	if err := downloader.importBlockResults(results); err != nil {
		t.Fatalf("importBlockResults: %v", err)
	}

	want := [][2]uint64{{451, 899}, {900, 1350}, {1351, 1799}, {1800, 1800}}
	got := make([][2]uint64, 0, len(chain.segments))
	var flat []uint64
	for _, segment := range chain.segments {
		if len(segment) == 0 {
			t.Fatalf("empty segment handed to InsertChain: %v", chain.segments)
		}
		for i, number := range segment {
			if i > 0 && number%epoch == 0 {
				t.Fatalf("segment %v holds the epoch-switch block %d after the block whose state its verification reads", segment, number)
			}
		}
		got = append(got, [2]uint64{segment[0], segment[len(segment)-1]})
		flat = append(flat, segment...)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("segments %v, want %v", got, want)
	}
	if !slices.Equal(flat, numbersOf(blocks)) {
		t.Fatalf("blocks %v, want %v", flat, numbersOf(blocks))
	}
}

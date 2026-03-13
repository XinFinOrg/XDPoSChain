package core

import (
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/params"
)

type consensusHeaderBatch struct {
	start int
	end   int // [start, end)
}

// splitHeadersByConsensusVersion groups contiguous headers by consensus version.
// For non-XDPoS chains, the full input is returned as a single batch.
func splitHeadersByConsensusVersion(config *params.ChainConfig, headers []*types.Header) []consensusHeaderBatch {
	if len(headers) == 0 {
		return nil
	}
	if config == nil || config.XDPoS == nil {
		return []consensusHeaderBatch{{start: 0, end: len(headers)}}
	}

	versionOf := func(header *types.Header) string {
		if header == nil || header.Number == nil {
			return params.ConsensusEngineVersion1
		}
		return config.XDPoS.BlockConsensusVersion(header.Number)
	}

	batches := make([]consensusHeaderBatch, 0, 2)
	start := 0
	currentVersion := versionOf(headers[0])

	for i := 1; i < len(headers); i++ {
		version := versionOf(headers[i])
		if version != currentVersion {
			batches = append(batches, consensusHeaderBatch{start: start, end: i})
			start = i
			currentVersion = version
		}
	}
	batches = append(batches, consensusHeaderBatch{start: start, end: len(headers)})

	return batches
}

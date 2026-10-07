// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package consensus

import (
	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/types"
)

// These capability shapes are deliberately generic (no XDPoS-v2 semantics):
// they describe what any proposed-block judgment needs from a chain. The v2
// judgment itself, its skip reasons and counters live in the leaf package
// consensus/XDPoS/utils (see proposed_block.go there).

// CanonicalChain is the canonicality half of the proposed-block judgment.
type CanonicalChain interface {
	// GetHeaderByNumber retrieves the canonical header at the given height.
	GetHeaderByNumber(number uint64) *types.Header
}

// BlockStorer is the optional storage half. Header-only chains (e.g.
// *core.HeaderChain) deliberately lack it, so they fail loudly as SkipUnjudgeable
// instead of every block silently failing "not stored".
type BlockStorer interface {
	// HasBlock reports whether the block is stored in the database.
	HasBlock(hash common.Hash, number uint64) bool
}

// ProposedBlockChain is what a proposed-block entry point must be handed:
// the chain access the handler body needs plus the storage half of the
// judgment. Entry points take this instead of ChainReader so a wiring that
// passes a chain without HasBlock fails at compile time instead of skipping
// every proposed block as SkipUnjudgeable at runtime; ShouldHandleProposedBlock
// keeps the narrower CanonicalChain parameter with its runtime assertion.
type ProposedBlockChain interface {
	ChainReader
	BlockStorer
}

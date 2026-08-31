// Copyright 2025 The XDC Authors
// This file is part of the XDC library.
//
// The XDC library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The XDC library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the XDC library. If not, see <http://www.gnu.org/licenses/>.

package core

import (
	"math/big"

	"github.com/XinFinOrg/XDPoSChain/params"
)

// forkChoiceCmp compares the fork-choice weight of two competing chains. It
// returns a positive value if the candidate chain ending at (number, td)
// should replace the current chain ending at (currentNumber, currentTd), a
// negative value if it should not, and zero on a tie. Tie-breaking (random or
// otherwise) is left to the callers.
//
// In the XDPoS v2 region every block has difficulty one, so the total
// difficulty degenerates to the chain length and the fork choice reduces to a
// height comparison. In the v1 region the original heaviest-chain rule is
// retained. A missing total difficulty (legacy chaindata that predates the TD
// index) falls back to a height comparison: it is the exact rule for v2 blocks
// and a safe approximation for v1 blocks, where the total difficulty can no
// longer be reconstructed without walking the chain.
func forkChoiceCmp(cfg *params.ChainConfig, number uint64, td *big.Int, currentNumber uint64, currentTd *big.Int) int {
	// The v2 boundary lives in params.XDPoSConfig.IsV2Block, the single
	// source of truth shared with block validation. When both sides are in
	// the v2 region, where every difficulty is one, the fork choice reduces
	// to a height comparison.
	if cfg != nil && cfg.XDPoS != nil && cfg.XDPoS.IsV2Block(number) && cfg.XDPoS.IsV2Block(currentNumber) {
		return cmpHeight(number, currentNumber)
	}
	// v1 region (or chains without an XDPoS config): heaviest chain wins.
	// Missing TDs fall back to a height comparison.
	//
	// A mixed-region comparison (candidate and current head on opposite sides
	// of the switch block) also lands here and keeps the pure TD rule. That
	// is safe in practice: a canonical v2 head extends the TD-heaviest chain
	// through the switch block, so its TD dominates the TD of any v1
	// candidate that the v1 fork choice never preferred. The domination
	// relies on chaindata consistency (the canonical switch block is
	// TD-maximal among all v1 blocks), not on this function, so it holds for
	// every chain a node can actually observe.
	if td != nil && currentTd != nil {
		return td.Cmp(currentTd)
	}
	return cmpHeight(number, currentNumber)
}

// cmpHeight compares two block numbers as a fork-choice weight: positive when
// number should replace currentNumber, negative when it should not, and zero
// on a tie. Tie-breaking is left to the callers.
func cmpHeight(number, currentNumber uint64) int {
	switch {
	case number > currentNumber:
		return 1
	case number < currentNumber:
		return -1
	default:
		return 0
	}
}

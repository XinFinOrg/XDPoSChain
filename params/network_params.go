// Copyright 2017 The go-ethereum Authors
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

package params

// These are network parameters that need to be constant between clients, but
// aren't necesarilly consensus related.

const (
	// BloomBitsBlocks is the number of blocks a single bloom bit section vector
	// contains on the server side.
	BloomBitsBlocks uint64 = 4096

	// BloomConfirms is the number of confirmation blocks before a bloom section is
	// considered probably final and its rotated bits are calculated.
	BloomConfirms = 256
)

// DefaultFullImmutabilityThreshold is the number of blocks after which a chain
// segment is considered immutable (i.e. soft finality). It is used by the chain
// freezer as the cutoff threshold for moving chain segments into the ancient store.
const DefaultFullImmutabilityThreshold = 90000

// MinFullImmutabilityThreshold is the lowest value FullImmutabilityThreshold may
// be lowered to.
//
// XDPoS consensus reads block bodies and receipts up to 2*RewardCheckpoint blocks
// back - RewardCheckpoint is 900 on every network, so 1800 blocks - see
// contracts.GetRewardForCheckpoint. Freezing inside that window is harmless while
// frozen reads still resolve, but pruning inside it (minimal history mode) would
// leave the reward and penalty hooks dereferencing missing bodies.
//
// The floor is set well above that 1800-block depth rather than just clear of it,
// to leave room for deeper lookbacks (epoch/gap boundaries, penalty windows) that
// a future consensus change might introduce without anyone remembering to revisit
// this constant.
const MinFullImmutabilityThreshold = 10000

// FullImmutabilityThreshold is the effective freezer cutoff. It is a variable
// rather than a constant purely so tests and local devnets can lower it via
// --history.immutabilitythreshold; production nodes must leave it at the default.
var FullImmutabilityThreshold uint64 = DefaultFullImmutabilityThreshold

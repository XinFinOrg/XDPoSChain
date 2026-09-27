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

package consensus

import "errors"

var (
	// ErrUnknownAncestor is returned when validating a block requires an ancestor
	// that is unknown.
	ErrUnknownAncestor = errors.New("unknown ancestor")

	// ErrPrunedAncestor is returned when validating a block requires an ancestor
	// that is known, but the state of which is not available.
	ErrPrunedAncestor = errors.New("pruned ancestor")

	// ErrMissingCanonicalGapHeader is returned when XDPoS reads the gap block of an epoch
	// switch by canonical number (the snapshot walk) and this node holds no canonical header
	// for it. That happens when the gap block sits on a stored sidechain this node has not
	// imported, so the condition is this node's own chain rather than the batch under
	// verification: core's classification reads it as a local failure.
	ErrMissingCanonicalGapHeader = errors.New("missing canonical gap header")

	// ErrGapSnapshotUnavailable is returned when the snapshot of a gap block resolves by
	// canonical number (the snapshot walk) but the stored set cannot be loaded: no entry is
	// stored under the block's hash, the read was refused, or the blob does not decode. The
	// write path stores the set in the batch that makes the gap block canonical, so an entry
	// this node cannot read is a condition of its own database rather than of the batch under
	// verification: core's classification reads it as a local failure.
	ErrGapSnapshotUnavailable = errors.New("gap snapshot is unavailable")

	// ErrFutureBlock is returned when a block's timestamp is in the future according
	// to the current node.
	ErrFutureBlock = errors.New("block in the future")

	// ErrInvalidNumber is returned if a block's number doesn't equal it's parent's
	// plus one.
	ErrInvalidNumber = errors.New("invalid block number")

	ErrFailValidatorSignature = errors.New("missing validator in header")

	ErrNoValidatorSignature = errors.New("no validator in header")

	ErrNoValidatorSignatureV2 = errors.New("no validator in v2 header")

	ErrNotReadyToPropose = errors.New("not ready to propose, QC is not ready")

	ErrNotReadyToMine = errors.New("not ready to mine, it's not your turn")

	ErrCoinbaseMismatch = errors.New("block Coinbase address does not match its wallte address")
)

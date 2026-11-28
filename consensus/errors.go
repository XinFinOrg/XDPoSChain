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
	// canonical number (the snapshot walk) but the stored set cannot be served: no entry is
	// stored under the block's hash, the read was refused, the blob does not decode, or the
	// record carries no candidates. The write path stores the set in the batch that makes the
	// gap block canonical and refuses an empty one, so a record this node cannot serve is a
	// condition of its own database rather than of the batch under verification: core's
	// classification reads it as a local failure. A restart runs the repair that rebuilds at
	// most the two most recent gap snapshots from their gap block state when that state is
	// still readable (RepairGapSnapshots; initial() owns the V2 switch gap block).
	ErrGapSnapshotUnavailable = errors.New("gap snapshot is unavailable")

	// ErrMissingPenaltyBlock is returned when the v1 engine reads the penalty set of a recent
	// epoch checkpoint and this node holds no canonical header or no block body for it. The
	// penalty set decides the checkpoint signer list, so a missing block cannot be skipped as
	// "no penalties"; the read is a condition of this node's own chain, not of the batch under
	// verification: core's classification reads it as a local failure.
	ErrMissingPenaltyBlock = errors.New("missing epoch penalty block")

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

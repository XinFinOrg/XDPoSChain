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

package core

import (
	"errors"

	"github.com/XinFinOrg/XDPoSChain/consensus"
)

// insertErrClass says what a failed insertion means for its caller: whether the block may stay
// parked for a retry, whether the peer may be blamed for it, and whether the block must be
// recorded as a bad one. A sentinel is registered once, in insertErrClasses.
type insertErrClass struct {
	retryable bool // may stay parked in the future queue and be retried later
	local     bool // this node's condition, not the blocks' - never blame the peer
	badBlock  bool // the block must be recorded as a bad block
}

// insertErrClasses is the table classifyInsertErr reads: one entry per sentinel, in the order
// the sentinels are tested, first match wins. Each entry carries the reason it sits where it
// does next to itself, so adding a condition is one appended entry and nothing else in the
// table is rewritten.
//
// An error that is in no entry is the block's fault, which is the class of
// consensus.ErrUnknownAncestor and of everything this fork has not classified yet; see the
// default answer of classifyInsertErr.
var insertErrClasses = []struct {
	err   error
	class insertErrClass
}{
	// The block is on disk with the state this node executed; the next batch adopts it.
	{ErrKnownBlock, insertErrClass{local: true}},

	// This node no longer holds the ancestor's state.
	{consensus.ErrPrunedAncestor, insertErrClass{local: true}},

	// Ahead of this node's clock, so the block is queued rather than classified as a failure
	// of the block: retryable, and not local on its own.
	{consensus.ErrFutureBlock, insertErrClass{retryable: true}},
}

// classifyInsertErr reads the class of an insertion failure from the error alone. Whether a
// parked block may be retried also depends on its parent, which stays with procFutureBlocks.
func classifyInsertErr(err error) insertErrClass {
	for _, entry := range insertErrClasses {
		if errors.Is(err, entry.err) {
			return entry.class
		}
	}
	return insertErrClass{badBlock: true} // anything unrecognised is the block's fault
}

// IsLocalInsertError reports whether an insertion failed for a reason that lives in this
// node rather than in the blocks: an import needs an ancestor whose state this node no longer
// holds, or adopting an already stored block would need a reorg this node refuses. It is the
// local flag of classifyInsertErr, the single place that enumerates the local conditions.
//
// Callers that penalise peers on insertion failures - the downloader turns an unknown error
// into errInvalidChain, which drops the peer that served the batch - must exempt these:
// none of them says anything about the validity of the blocks.
//
// ErrUnknownAncestor is deliberately absent: a batch that cannot be linked to our chain is
// something the peer can be held accountable for, and the downloader drops the peer for it.
//
// consensus.ErrFutureBlock is absent for a different reason again: a future block is queued
// rather than classified as a failure of the block.
func IsLocalInsertError(err error) bool {
	return classifyInsertErr(err).local
}

// IsLocalInsertError mirrors the package function for eth/downloader, which abstracts the
// local chain behind its own BlockChain interface and must not import core.
func (bc *BlockChain) IsLocalInsertError(err error) bool {
	return IsLocalInsertError(err)
}

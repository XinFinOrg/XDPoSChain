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

// insertErrClass says what a failed insertion means for its caller. The insertion paths ask
// the same error four questions - may the block stay parked for a retry, may the peer be
// blamed for it, must it be recorded as a bad block, and is it worth a warning - and those
// questions used to be answered by four hand written errors.Is lists that had to be kept in
// step by hand. They are now three flags on one error, so a sentinel is registered once: in
// classifyInsertErr.
type insertErrClass struct {
	retryable bool // may stay parked in the future queue and be retried later
	local     bool // this node's condition, not the blocks' - never blame the peer
	badBlock  bool // the block must be recorded as a bad block
}

// classifyInsertErr reads the class of an insertion failure. It looks at the error only:
// whether a parked block may be retried also depends on whether its parent is itself still
// parked, and that is chain state, so it stays with the caller (procFutureBlocks).
//
// The table, and why each sentinel sits where it does:
//
//	ErrInsertionInterrupted  retryable, local  InterruptInsert cut the import short
//	ErrChainStopped          retryable, local  the chain is shutting down
//	ErrLocalInsertCondition  retryable, local  a block dated too far ahead of this node's
//	                                           clock, or a segment with nothing stored
//	ErrLocalInsertRefused    local            a reorg this node refuses; retrying it can only
//	                                           be refused again, so it must not stay parked
//	ErrKnownBlock            local            the block is on disk; the next batch adopts it
//	ErrPrunedAncestor        local            this node no longer holds the ancestor's state
//	ErrFutureBlock           retryable        ahead of this node's clock, so it is queued
//	ErrUnknownAncestor       bad block        a batch that cannot be linked is the peer's
//	anything else           bad block
//
// The four local sentinels that have no other class are marked as not bad blocks. They are
// only ever raised inside this package, so they never reach a caller through the engine's
// verification results. Writing a local interruption into the bad block database would
// outlive the condition that caused it - a shutdown, a cancel, a clock that steps back - so
// the code states the guarantee instead of relying on that reachability argument. IsLocalInsertError is the local flag, and ErrFutureBlock is the
// retryable error that is not local on its own: the one path that can hand it out wraps it
// as a local condition, see its comment there.
//
// ErrLocalInsertRefused is the one local sentinel that is not retryable as well; it is why
// the two flags are not a single column. See its comment for the retry loop that would
// otherwise re-run the refused reorg on every futureBlocksLoop tick.
func classifyInsertErr(err error) insertErrClass {
	class := insertErrClass{badBlock: true} // anything unrecognised is the block's fault
	switch {
	case errors.Is(err, ErrInsertionInterrupted),
		errors.Is(err, ErrChainStopped),
		errors.Is(err, ErrLocalInsertCondition):
		class.retryable, class.local, class.badBlock = true, true, false
	case errors.Is(err, ErrKnownBlock),
		errors.Is(err, consensus.ErrPrunedAncestor),
		errors.Is(err, ErrLocalInsertRefused):
		class.local, class.badBlock = true, false
	case errors.Is(err, consensus.ErrFutureBlock):
		class.retryable, class.badBlock = true, false
	}
	return class
}

// IsLocalInsertError reports whether an insertion failed for a reason that lives in this
// node rather than in the blocks: the chain has been stopped, the insertion was cut short by
// InterruptInsert, an import needs an ancestor whose state this node no longer holds, or
// adopting an already stored block would need a reorg this node refuses. It is the local flag
// of classifyInsertErr, the single place that enumerates the local conditions.
//
// Callers that penalise peers on insertion failures - the downloader turns an unknown error
// into errInvalidChain, which drops the peer that served the batch - must exempt these:
// none of them says anything about the validity of the blocks.
//
// ErrUnknownAncestor is deliberately absent: a batch that cannot be linked to our chain is
// something the peer can be held accountable for, and the downloader drops the peer for it.
//
// consensus.ErrFutureBlock is absent for a different reason again: a future block is queued
// and retried rather than turned into a consensus failure of the peer.
func IsLocalInsertError(err error) bool {
	return classifyInsertErr(err).local
}

// IsLocalInsertError mirrors the package function so that eth/downloader can ask the chain
// for the verdict without importing this package: the downloader abstracts the local chain
// behind its own BlockChain interface, and reaching into core would pull the whole
// implementation it abstracts back into its dependency tree.
func (bc *BlockChain) IsLocalInsertError(err error) bool {
	return IsLocalInsertError(err)
}

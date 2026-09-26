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
//	ErrLocalInsertAheadOfClock retryable, local  a block dated too far ahead of this node's
//	                                           clock to be queued; the clock catches up
//	ErrLocalInsertCondition  local            a segment with nothing stored, a refused
//	                                           receipt write, a stored block with no total
//	                                           difficulty record: the next tick reads the
//	                                           same records
//	ErrLocalInsertRefused    local            a reorg this node refuses; retrying it can only
//	                                           be refused again, so it must not stay parked
//	ErrKnownBlock            local            the block is on disk; the next batch adopts it
//	ErrPrunedAncestor        local            this node no longer holds the ancestor's state
//	errInvalidOldChain       local            reorg read a record of the chain it does not
//	                                           have or cannot have: the chain's own markers
//	                                           and records disagree with each other
//	errInvalidNewChain       local            the same, while adopting the other chain
//	ErrFutureBlock           retryable        ahead of this node's clock, so it is queued
//	ErrUnknownAncestor       bad block        a batch that cannot be linked is the peer's
//	anything else           bad block
//
// The local sentinels that have no other class are marked as not bad blocks. They are
// only ever raised inside this package, so they never reach a caller through the engine's
// verification results. Writing a local interruption into the bad block database would
// outlive the condition that caused it - a shutdown, a cancel, a clock that steps back - so
// the code states the guarantee instead of relying on that reachability argument. The local
// flag and ErrFutureBlock, the one retryable error that is not local on its own, are spelled
// out where they are asked: see IsLocalInsertError.
//
// ErrLocalInsertCondition, ErrLocalInsertRefused, errInvalidOldChain and errInvalidNewChain
// are the local sentinels that are not retryable as well; they are why the two flags are not
// a single column. See the comment on ErrLocalInsertCondition for the retry loop that would
// otherwise re-verify a block this node cannot import, on every futureBlocksLoop tick and
// forever, on ErrLocalInsertRefused for the one that would re-run the refused reorg, and on
// the two chain-record sentinels for why an inconsistent chain is not something a retry
// repairs. ErrLocalInsertAheadOfClock is the exception that proves the split: the one local
// condition that heals, so it is the one local condition a parked block may wait for.
func classifyInsertErr(err error) insertErrClass {
	class := insertErrClass{badBlock: true} // anything unrecognised is the block's fault
	switch {
	case errors.Is(err, ErrInsertionInterrupted),
		errors.Is(err, ErrChainStopped),
		errors.Is(err, ErrLocalInsertAheadOfClock):
		class.retryable, class.local, class.badBlock = true, true, false
	// Local and not retryable. ErrLocalInsertCondition belongs here rather than with the
	// sentinels above: every condition it carries - a segment with nothing stored, a refused
	// receipt write, a state or trie commit this node's own trie database refused, a parent
	// state it can no longer open, a stored block with no total difficulty record - is read
	// the same way on the next attempt, so a parked block that failed for one has to be
	// evicted instead of being re-verified ten times a second until the queue happens to
	// drop it.
	case errors.Is(err, ErrKnownBlock),
		errors.Is(err, consensus.ErrPrunedAncestor),
		errors.Is(err, ErrLocalInsertRefused),
		errors.Is(err, ErrLocalInsertCondition):
		class.local, class.badBlock = true, false
	case errors.Is(err, errInvalidOldChain),
		errors.Is(err, errInvalidNewChain):
		// reorg read a record of the chain and did not find it: the chain's own markers or
		// records disagree with each other. Not retryable - the same read sees the same
		// records - and never the block's fault, so neither the block nor the peer that
		// served the batch is held to it.
		class.local, class.badBlock = true, false
	case errors.Is(err, consensus.ErrFutureBlock):
		class.retryable, class.badBlock = true, false
	}
	return class
}

// IsLocalInsertError reports whether an insertion failed for a reason that lives in this
// node rather than in the blocks: the chain has been stopped, the insertion was cut short by
// InterruptInsert, an import needs an ancestor whose state this node no longer holds,
// adopting an already stored block would need a reorg this node refuses, or a reorg read a
// record of the chain it does not have. It is the local flag of classifyInsertErr, the single
// place that enumerates the local conditions.
//
// Callers that penalise peers on insertion failures - the downloader turns an unknown error
// into errInvalidChain, which drops the peer that served the batch - must exempt these:
// none of them says anything about the validity of the blocks.
//
// ErrUnknownAncestor is deliberately absent: a batch that cannot be linked to our chain is
// something the peer can be held accountable for, and the downloader drops the peer for it.
//
// consensus.ErrFutureBlock is absent for a different reason again: a future block is queued
// rather than classified as a failure of the block. The one path that can hand it out is the
// early return of insertSideChain, and it does not hand out the sentinel itself: a block dated
// ahead of the local clock is wrapped in ErrLocalInsertAheadOfClock there, because the only way
// a segment far below the head can carry one is this node's clock having stepped back - the
// monotonicity of block timestamps bounds such a block by the head, not by now. That is the same
// cause addFutureBlock raises ErrLocalInsertAheadOfClock for a block past the future queue's
// window, so the two paths agree - and the same cause that makes both retryable.
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

// DescribeLocalInsertFailure names why an insertion failed for a local condition, so that the
// callers which take their error message from the classification - the file importers - report
// the same reason for the same sentinel instead of each keeping its own copy of the list.
//
// ok is false for anything that is not local: those are the failures the caller reports in its
// own words, because they are about the blocks rather than about this node.
//
// The specific sentinels are asked before the local flag on purpose: ErrKnownBlock and
// ErrPrunedAncestor are local as well, so testing IsLocalInsertError first would mask their
// reasons and report every one of them as a plain interruption.
func DescribeLocalInsertFailure(err error) (string, bool) {
	switch {
	case errors.Is(err, ErrLocalInsertRefused), errors.Is(err, ErrLocalInsertCondition),
		errors.Is(err, ErrLocalInsertAheadOfClock):
		// None of them is a fault of the blocks, so blaming the file would report this
		// node's own state as a corrupt import. The message says the import cannot proceed
		// rather than that the file is bad, and claims nothing about a retry: a refused
		// reorg is refused again while the head does not move, a record this node is
		// missing is missing for this file as well, and a block dated ahead of the clock is
		// one this import cannot place even though a later retry could.
		return "cannot be imported", true
	case errors.Is(err, errInvalidOldChain), errors.Is(err, errInvalidNewChain):
		// The chain's own records disagree with each other, so the file is not at fault -
		// and this is not an interruption either: the import cannot proceed until the node's
		// chain is repaired, and saying that is what keeps an operator from re-running the
		// same file.
		return "the local chain is inconsistent", true
	case errors.Is(err, ErrKnownBlock):
		return "already imported", true
	case errors.Is(err, consensus.ErrPrunedAncestor):
		return "ancestor state is pruned", true
	case IsLocalInsertError(err):
		return "interrupted during import", true
	}
	return "", false
}

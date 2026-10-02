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
// insertErrClasses.
type insertErrClass struct {
	retryable bool // may stay parked in the future queue and be retried later
	local     bool // this node's condition, not the blocks' - never blame the peer
	badBlock  bool // the block must be recorded as a bad block
}

// insertErrClasses is the table classifyInsertErr reads: one entry per sentinel, in the order
// the sentinels are tested, first match wins. Each entry carries the reason it sits where it
// does next to itself, so adding a condition is one appended entry and nothing else in the
// table is rewritten. That is what the switch it replaced got wrong: every addition to one
// errors.Is list rewrote the lines the other sentinels of that list share, which is the shape
// that conflicts with any later change to the same list.
//
// An error that is in no entry is the block's fault, which is the class of
// consensus.ErrUnknownAncestor and of everything this fork has not classified yet; see the
// default answer of classifyInsertErr.
//
// Every local entry is also marked as not a bad block. Those sentinels are only ever raised
// inside this package, so they never reach a caller through the engine's verification results.
// Writing a local interruption into the bad block database would outlive the condition that
// caused it - a shutdown, a cancel, a clock that steps back - so the code states the guarantee
// instead of relying on that reachability argument.
//
// The two flags are not one column because the local conditions do not all heal, and the one
// retryable condition that is not local on its own - a block dated ahead of this node's clock -
// is spelled out where it is asked: see IsLocalInsertError and the entry below.
var insertErrClasses = []struct {
	err   error
	class insertErrClass
}{
	// InterruptInsert cut the import short. The caller is free to deliver the batch again.
	{ErrInsertionInterrupted, insertErrClass{retryable: true, local: true}},

	// The chain is shutting down.
	{ErrChainStopped, insertErrClass{retryable: true, local: true}},

	// A block dated too far ahead of this node's clock to be queued. The one local condition
	// that heals, because the clock catches up - which is why the retryable flag is not the
	// same column as the local one.
	{ErrLocalInsertAheadOfClock, insertErrClass{retryable: true, local: true}},

	// A segment with nothing stored, a refused receipt write, a state or trie commit this
	// node's own trie database refused, a parent state it can no longer open, a stored block
	// with no total difficulty record. Local and not retryable: every condition it carries is
	// read the same way on the next attempt, so a parked block that failed for one has to be
	// evicted instead of being re-verified ten times a second until the queue happens to drop
	// it.
	{ErrLocalInsertCondition, insertErrClass{local: true}},

	// A reorg this node refuses. Retrying it can only be refused again, so it must not stay
	// parked.
	{ErrLocalInsertRefused, insertErrClass{local: true}},

	// The block is on disk with the state this node executed; the next batch adopts it.
	{ErrKnownBlock, insertErrClass{local: true}},

	// This node no longer holds the ancestor's state.
	{consensus.ErrPrunedAncestor, insertErrClass{local: true}},

	// The gap block of an epoch switch is not on the canonical chain to be read by number.
	// Reading it keeps failing the same way until the sidechain it sits on is imported, so
	// keeping the batch parked would only re-verify it on every futureBlocksLoop tick.
	{consensus.ErrMissingCanonicalGapHeader, insertErrClass{local: true}},

	// reorg read a record of the chain it does not have or cannot have: the chain's own
	// markers and records disagree with each other. Not retryable - the same read sees the
	// same records.
	{errInvalidOldChain, insertErrClass{local: true}},

	// The same, while adopting the other chain.
	{errInvalidNewChain, insertErrClass{local: true}},

	// Ahead of this node's clock, so the block is queued rather than classified as a failure.
	// Not local on its own: the one path that can hand it out wraps it in
	// ErrLocalInsertAheadOfClock, for the reason that entry gives.
	{consensus.ErrFutureBlock, insertErrClass{retryable: true}},
}

// classifyInsertErr reads the class of an insertion failure. It looks at the error only:
// whether a parked block may be retried also depends on whether its parent is itself still
// parked, and that is chain state, so it stays with the caller (procFutureBlocks).
func classifyInsertErr(err error) insertErrClass {
	for _, entry := range insertErrClasses {
		if errors.Is(err, entry.err) {
			return entry.class
		}
	}
	return insertErrClass{badBlock: true} // anything unrecognised is the block's fault
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

// localFailureReasons is the table DescribeLocalInsertFailure reads: one entry per sentinel,
// in the order the sentinels are asked, so that a condition whose words are added later does
// not rewrite the entries around it.
//
// The specific sentinels are asked before the local flag on purpose: ErrKnownBlock and
// ErrPrunedAncestor are local as well, so testing IsLocalInsertError first would mask their
// reasons and report every one of them as a plain interruption. The local flag is what answers
// for the sentinels this table does not name - an interruption, a stopped chain - and those are
// the ones the reason "interrupted during import" is for.
//
// The reason is deliberately not a claim about a retry: a refused reorg is refused again while
// the head does not move, a record this node is missing is missing for this file as well, and a
// block dated ahead of the clock is one this import cannot place even though a later retry
// could. All of them only say that this very input cannot be imported now.
var localFailureReasons = []struct {
	err    error
	reason string
}{
	{ErrLocalInsertRefused, "cannot be imported"},
	{ErrLocalInsertCondition, "cannot be imported"},
	{ErrLocalInsertAheadOfClock, "cannot be imported"},

	// Not an interruption: an inconsistent local chain is not a state the file or a retry can
	// get past, and the message has to say so to keep an operator from re-running the same
	// file.
	{errInvalidOldChain, "the local chain is inconsistent"},
	{errInvalidNewChain, "the local chain is inconsistent"},

	{ErrKnownBlock, "already imported"},
	{consensus.ErrPrunedAncestor, "ancestor state is pruned"},

	// The gap block of an epoch switch is not on the canonical chain, so a batch that needs
	// it cannot be verified against this node's chain. Reported as a local condition rather
	// than as an interruption: retrying reads the same chain.
	{consensus.ErrMissingCanonicalGapHeader, "the epoch gap block is not canonical"},
}

// DescribeLocalInsertFailure names why an insertion failed for a local condition, so that the
// callers which take their error message from the classification - the file importers - report
// the same reason for the same sentinel instead of each keeping its own copy of the list.
//
// ok is false for anything that is not local: those are the failures the caller reports in its
// own words, because they are about the blocks rather than about this node.
func DescribeLocalInsertFailure(err error) (string, bool) {
	for _, entry := range localFailureReasons {
		if errors.Is(err, entry.err) {
			return entry.reason, true
		}
	}
	if IsLocalInsertError(err) {
		return "interrupted during import", true
	}
	return "", false
}

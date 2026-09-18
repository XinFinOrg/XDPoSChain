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
	"fmt"

	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/core/types"
)

// localConditionf marks a failure of this node and names the condition: the first part is the
// sentinel callers classify on, the wording after it is what the file importers report. It is
// the one place ErrLocalInsertCondition is attached.
//
// The wording is formatted by an inner fmt.Errorf that receives format untouched. That is what
// lets the vet printf checker read this function as a wrapper and keep checking the callers'
// verbs: prefixing the format here ("%w: "+format) makes the checker give up on all of them.
func localConditionf(format string, args ...interface{}) error {
	return fmt.Errorf("%w: %w", ErrLocalInsertCondition, fmt.Errorf(format, args...))
}

// wrapLocalCondition marks a failure of this node - a database or state commit it refused -
// so callers stop blaming the peer that delivered the blocks.
func wrapLocalCondition(err error) error {
	return localConditionf("%w", err)
}

// parentMissingTdError names the missing total difficulty of the parent a walk links through.
func parentMissingTdError(block *types.Block) error {
	return localConditionf("no total difficulty for the parent of block %d (%v)", block.NumberU64(), block.ParentHash())
}

// storedBlockMissingTdError names the missing total difficulty of a stored block. It is written
// with the receipts, so its absence is this node's condition, not the block's.
func storedBlockMissingTdError(block *types.Block) error {
	return localConditionf("no total difficulty for stored block %d (%v)", block.NumberU64(), block.Hash())
}

// insertErrClass says what a failed insertion means for its caller: whether the block may stay
// parked for a retry, whether the peer may be blamed for it, and whether the block must be
// recorded as a bad one. A sentinel is registered once, in insertErrClasses.
type insertErrClass struct {
	retryable bool // may stay parked in the future queue and be retried later
	local     bool // this node's condition, not the blocks' - never blame the peer
	badBlock  bool // the block must be recorded as a bad block
}

// insertErrClasses is the table classifyInsertErr reads: one entry per sentinel, in the order
// the sentinels are tested, first match wins. An entry carries its class and the wording the
// file importers report; an entry with no wording is named by the fallback of
// DescribeLocalInsertFailure. An error in no entry is the block's fault, the class of
// consensus.ErrUnknownAncestor and of everything this fork has not classified yet.
//
// Every local entry is also marked as not a bad block: those sentinels are only raised inside
// this package, and a local interruption written into the bad block database would outlive the
// condition that caused it - a shutdown, a cancel, a clock that steps back.
var insertErrClasses = []struct {
	err    error
	class  insertErrClass
	reason string // wording the file importers report; empty = the fallback names it
}{
	// InterruptInsert cut the import short; the caller may deliver the batch again.
	{ErrInsertionInterrupted, insertErrClass{retryable: true, local: true}, ""},

	// The chain is shutting down.
	{ErrChainStopped, insertErrClass{retryable: true, local: true}, ""},

	// A block dated too far ahead of this node's clock to be queued: the one local condition
	// that heals, because the clock catches up - hence retryable and local at once.
	{ErrLocalInsertAheadOfClock, insertErrClass{retryable: true, local: true}, "cannot be imported"},

	// A segment with nothing stored, a refused receipt write, a state or trie commit this
	// node's own trie database refused, a parent state it can no longer open, a stored block
	// with no total difficulty. Local and not retryable: every condition is read the same way
	// on the next attempt, so a parked block that failed for one has to be evicted.
	{ErrLocalInsertCondition, insertErrClass{local: true}, "cannot be imported"},

	// A reorg this node refuses; a retry is refused again, so it must not stay parked.
	{ErrLocalInsertRefused, insertErrClass{local: true}, "cannot be imported"},

	// reorg read a record of the chain it does not have or cannot have: the chain's own
	// markers and records disagree. Not retryable (the same read sees the same records) and
	// not an interruption, so the message keeps an operator from re-running the file.
	{errInvalidOldChain, insertErrClass{local: true}, "the local chain is inconsistent"},

	// The same, while adopting the other chain.
	{errInvalidNewChain, insertErrClass{local: true}, "the local chain is inconsistent"},

	// The block is on disk with the state this node executed; the next batch adopts it.
	{ErrKnownBlock, insertErrClass{local: true}, "already imported"},

	// This node no longer holds the ancestor's state.
	{consensus.ErrPrunedAncestor, insertErrClass{local: true}, "ancestor state is pruned"},

	// The gap block of an epoch switch is not on the canonical chain to be read by number.
	// Reading it keeps failing the same way until the sidechain it sits on is imported, so
	// keeping the batch parked would only re-verify it on every futureBlocksLoop tick.

	// Ahead of this node's clock, so the block is queued rather than failed. Not local on its
	// own: the one path that hands it out wraps it in ErrLocalInsertAheadOfClock.
	{consensus.ErrFutureBlock, insertErrClass{retryable: true}, ""},
}

// lookupInsertErr reads the table once for the two questions its callers ask: the class of
// the first entry the error matches - the table order is the order the sentinels are tested - and
// the wording of the first matching entry that carries one. The two answers come from the same
// pass but are not the same entry: a local sentinel with no wording of its own (an interruption,
// a stopped chain) decides the class, while a named entry the error also matches decides what the
// file importers report.
func lookupInsertErr(err error) (class insertErrClass, reason string, matched, named bool) {
	for _, entry := range insertErrClasses {
		if !errors.Is(err, entry.err) {
			continue
		}
		if !matched {
			class, matched = entry.class, true
		}
		if !named && entry.reason != "" {
			reason, named = entry.reason, true
		}
	}
	return class, reason, matched, named
}

// classifyInsertErr reads the class of an insertion failure from the error alone. Whether a
// parked block may be retried also depends on its parent, which stays with procFutureBlocks.
func classifyInsertErr(err error) insertErrClass {
	if class, _, matched, _ := lookupInsertErr(err); matched {
		return class
	}
	return insertErrClass{badBlock: true} // anything unrecognised is the block's fault
}

// IsLocalInsertError reports whether an insertion failed for a reason that lives in this node
// rather than in the blocks: the chain stopped, the insertion was cut short, a needed ancestor
// state is gone, a reorg is refused or read a record it does not have. It is the local flag of
// classifyInsertErr, the one place that enumerates these.
//
// Callers that penalise peers on insertion failures must exempt these: the downloader turns an
// unknown error into errInvalidChain, which drops the peer, and none of these says anything
// about the blocks. ErrUnknownAncestor is deliberately absent, since the peer can be held to
// it; consensus.ErrFutureBlock is absent because a future block is queued, not failed.
func IsLocalInsertError(err error) bool {
	return classifyInsertErr(err).local
}

// IsLocalInsertError mirrors the package function for eth/downloader, which abstracts the
// local chain behind its own BlockChain interface and must not import core.
func (bc *BlockChain) IsLocalInsertError(err error) bool {
	return IsLocalInsertError(err)
}

// DescribeLocalInsertFailure names why an insertion failed for a local condition, so the file
// importers report one reason per sentinel instead of keeping their own copy of the list.
//
// One pass over the table answers both questions: the class comes from the first entry the
// error matches, the wording from the first matching entry that carries one. An entry with no
// wording of its own - an interruption, a stopped chain - decides the class without naming the
// failure, so the fallback below answers for it; a named entry the error also matches still
// supplies the wording, which is what keeps ErrKnownBlock and ErrPrunedAncestor from being
// masked by the flag.
//
// The reason claims nothing about a retry - it only says this input cannot be imported now -
// and ok is false for anything that is not local, which the caller reports in its own words.
func DescribeLocalInsertFailure(err error) (string, bool) {
	class, reason, matched, named := lookupInsertErr(err)
	// The entries that carry a wording answer first, so a local sentinel with no wording of its
	// own does not mask the reason of a named entry the error also matches.
	if named {
		return reason, true
	}
	// The local conditions with no wording of their own fall through to the reason below.
	if matched && class.local {
		return "interrupted during import", true
	}
	return "", false
}

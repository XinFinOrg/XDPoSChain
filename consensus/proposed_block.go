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
	"github.com/XinFinOrg/XDPoSChain/log"
	"github.com/XinFinOrg/XDPoSChain/metrics"
)

// XDPoS v2 specific: the proposed-block gating judgment and the capability
// interfaces it needs live here, so consensus and eth can share them without an
// import cycle.

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
// every proposed block as SkipUnjudgeable at runtime. ShouldHandleProposedBlock
// still keeps the narrower CanonicalChain parameter with its runtime
// assertion as a defense, so the unjudgeable path cannot be silently
// removed from the judgment itself; in production wiring the assertion
// cannot fail, so the path is reachable only from test fakes.
type ProposedBlockChain interface {
	ChainReader
	BlockStorer
}

// SkipReason describes why a proposed block header was rejected; empty means accepted.
type SkipReason string

// The reasons a header can be rejected. Each is graded and counted by the
// skipReasons table below; register new reasons there.
const (
	// SkipNoCanonicalHeader: no canonical header exists at the height.
	SkipNoCanonicalHeader SkipReason = "no canonical header at height"

	// SkipNonCanonical: the header is not the canonical block at its height.
	SkipNonCanonical SkipReason = "non-canonical"

	// SkipBodyNotStored: the canonical block's body is not in the database yet (fast sync).
	SkipBodyNotStored SkipReason = "block body not stored"

	// SkipUnjudgeable: the chain lacks BlockStorer — a wiring bug: every block
	// is skipped, halting processQC and voting. Unreachable in production
	// (entry points take ProposedBlockChain); see skipReasons.
	SkipUnjudgeable SkipReason = "unjudgeable"

	// SkipNilHeader: a nil header or nil number — a caller bug.
	SkipNilHeader SkipReason = "nil header"
)

// IsJudgeableHeader reports whether a proposed-block header has the minimum
// shape the handlers dereference: a non-nil header with a non-nil number.
func IsJudgeableHeader(header *types.Header) bool {
	return header != nil && header.Number != nil
}

// SkipNilHeaderLog's call sites pass one of these constants instead of a string
// literal: mistyping a constant name is a compile error, whereas a mistyped
// literal would silently log a prefix nothing matches on.
const (
	// SkipSiteFetcher: the eth fetcher gate (eth/handler.go fast-sync path).
	SkipSiteFetcher = "[fetcher]"
	// SkipSiteProposedBlockHandler: the v2 engine's ProposedBlockHandler.
	SkipSiteProposedBlockHandler = "[ProposedBlockHandler]"
	// SkipSiteHandleProposedBlock: the XDPoS wrapper's HandleProposedBlock.
	SkipSiteHandleProposedBlock = "[HandleProposedBlock]"
)

// SkipNilHeaderLog logs a nil-shape skip: a nil header or nil number is a
// caller bug, not an observation about a block, so it logs at Error, counts
// nothing, and the caller returns nil. Its three call sites (the XDPoS wrapper,
// the v2 engine, the eth fetcher gate) must stay consistent: each passes one of
// the SkipSite* constants above, and the message keeps the literal "nil header"
// so tests can pin the guard without coupling to a site string.
func SkipNilHeaderLog(site string) {
	SkipLogLevel(SkipNilHeader)(site + " skip block: nil header")
}

// ShouldHandleProposedBlock reports whether a proposed block header should reach
// the consensus handler, plus the SkipReason and the canonical hash at that
// height (zero when the judgment fails before a canonical header is read). A
// header is handled only if it is the canonical block at its height — an
// existence check cannot distinguish a reorged-away fork, which stays in the
// database — and its body is stored (fast sync marks a height canonical before
// its body lands); HasBlock answers that half without decoding the body.
// The reads are not atomic — a reorg can land between or after them — so the v2
// engine re-checks before processQC and before sendVote. A chain without
// BlockStorer, or a nil header or number, fails before any chain read. Storage
// is graded at two strengths: this judgment and the engine gates require
// HasBlock only, the fetcher gate requires HasBlockAndExecutedState.
func ShouldHandleProposedBlock(chain CanonicalChain, header *types.Header) (bool, SkipReason, common.Hash) {
	if header == nil || header.Number == nil {
		return false, SkipNilHeader, common.Hash{}
	}
	storer, ok := chain.(BlockStorer)
	if !ok {
		// Not counted: production wiring cannot reach this branch — every
		// entry point takes ProposedBlockChain (compile-time BlockStorer) and
		// the downloader's BlockChain interface requires HasBlock. Only test
		// fakes get here; every gate still logs this reason at Error (see
		// skipReasons), which is the wiring-bug alarm.
		return false, SkipUnjudgeable, common.Hash{}
	}
	canonical := chain.GetHeaderByNumber(header.Number.Uint64())
	if canonical == nil {
		return false, SkipNoCanonicalHeader, common.Hash{}
	}
	if canonical.Hash() != header.Hash() {
		return false, SkipNonCanonical, canonical.Hash()
	}
	if !storer.HasBlock(header.Hash(), header.Number.Uint64()) {
		return false, SkipBodyNotStored, canonical.Hash()
	}
	return true, "", canonical.Hash()
}

// skipRegistration is the single registration for one SkipReason: its log grade
// at each call site and, when the reason can reach a counting gate, its own
// counter (nil means the reason logs but counts nothing).
type skipRegistration struct {
	handler   func(msg string, ctx ...interface{})
	preFilter func(msg string, ctx ...interface{})
	counter   *metrics.Counter
}

// skipReasons is the single registration table for every SkipReason: one entry
// grades a reason at both call sites and registers its counter, so a new
// reason cannot be missed for one grader or one counter. Unregistered reasons
// — including the misused empty reason — fall back to Warn and count nothing.
// The fetcher's gate is outside the table: it produces no SkipReason.
//
// The counters separate what the engine-gate total skipped-proposed-block
// cannot: a fast-sync burst of body-not-stored is transient, while a
// persistent non-canonical rate is a stall. Only the engine gates count (see
// the v2 engine's skipProposedBlock): the downloader pre-filter keeps its
// aggregate skipped-proposed-block/prefilter, and the eth fetcher gate skips
// before any judgment and carries no reason at all.
var skipReasons = map[SkipReason]skipRegistration{
	SkipUnjudgeable: {
		handler:   log.Error,
		preFilter: log.Error,
		// No counter: production wiring cannot reach this reason (see the
		// assertion in ShouldHandleProposedBlock), so a counter here would
		// stay silent forever and be false assurance in alerting. The Error
		// grades above are the wiring-bug alarm.
	},
	// SkipNilHeader logs but counts nothing: it is a caller bug, not an
	// observation about a block (see SkipNilHeaderLog).
	// No preFilter grade: the downloader's tail header is always built from
	// fetched results, so the pre-filter can never produce this reason;
	// PreFilterSkipLogLevel falls back to Warn if it ever did.
	SkipNilHeader:         {handler: log.Error},
	SkipNonCanonical:      {handler: log.Warn, preFilter: log.Info, counter: metrics.NewRegisteredCounter("skipped-proposed-block/non-canonical", nil)},
	SkipNoCanonicalHeader: {handler: log.Warn, preFilter: log.Info, counter: metrics.NewRegisteredCounter("skipped-proposed-block/no-canonical-header", nil)},
	SkipBodyNotStored:     {handler: log.Info, preFilter: log.Info, counter: metrics.NewRegisteredCounter("skipped-proposed-block/body-not-stored", nil)},
}

// SkipLogLevel grades a skip once the handler is reached: wiring and caller
// bugs are Errors, reorg races Warn, the expected fast-sync skip Info. See
// skipReasons.
func SkipLogLevel(reason SkipReason) func(msg string, ctx ...interface{}) {
	if g, ok := skipReasons[reason]; ok {
		return g.handler
	}
	return log.Warn
}

// PreFilterSkipLogLevel grades a skip at the downloader's pre-filter, where fork
// tails are routine noise (Info). Wiring bugs grade Error here too: the
// downloader's only unjudgeable path is the narrow CanonicalChain defense in
// ShouldHandleProposedBlock. A registration without a preFilter grade falls
// back to Warn — only SkipNilHeader, which the pre-filter cannot produce.
func PreFilterSkipLogLevel(reason SkipReason) func(msg string, ctx ...interface{}) {
	if g, ok := skipReasons[reason]; ok && g.preFilter != nil {
		return g.preFilter
	}
	return log.Warn
}

// IncSkipReasonCounter bumps the reason's own counter; reasons without a
// dedicated counter — unknown ones, or SkipNilHeader — count nothing here.
// Call it in addition to the engine-gate total consensus/skipped-proposed-
// block, never instead: the total is that gate's aggregate view and the
// per-reason counters are its breakdown, so their unjudgeable entry is the
// only unjudgeable counter.
func IncSkipReasonCounter(reason SkipReason) {
	if g, ok := skipReasons[reason]; ok && g.counter != nil {
		g.counter.Inc(1)
	}
}

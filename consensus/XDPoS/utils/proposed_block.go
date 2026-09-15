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

package utils

import (
	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/log"
	"github.com/XinFinOrg/XDPoSChain/metrics"
)

// XDPoS v2 specific: the proposed-block gating judgment, its skip reasons
// and their per-reason counters live here, a leaf package, so the engine and
// eth can share them without pulling the XDPoS engine into every importer.
// The judgment's capability shapes (CanonicalChain, BlockStorer,
// ProposedBlockChain) stay in the generic consensus package.

// SkipReason describes why a proposed block header was rejected; the zero value
// means accepted. A reason carries its own log grades and counter, so a reason
// cannot exist without them and there is no registration table to keep in sync
// with the reason list.
type SkipReason struct {
	name      string
	handler   skipGrade
	preFilter skipGrade
	counter   *metrics.Counter
}

// String returns the reason's name: log fields hold the reason itself
// ("reason", reason), and log/format.go prints a Stringer by its string.
func (r SkipReason) String() string { return r.name }

// skipGrade is a reason's log grade at one call site. It is an enum rather than
// a log function so SkipReason stays comparable: a judgment's reason is compared
// with == against the reasons declared below.
type skipGrade uint8

const (
	// gradeWarn is the zero value: a reason carrying no grade — including the
	// empty reason of a misused accept — warns rather than hiding at Info.
	gradeWarn skipGrade = iota
	gradeError
	gradeInfo
)

// logFunc maps a grade to its log function.
func (g skipGrade) logFunc() func(msg string, ctx ...interface{}) {
	switch g {
	case gradeError:
		return log.Error
	case gradeInfo:
		return log.Info
	default:
		return log.Warn
	}
}

// The reasons a header can be rejected, each declaring its own grades and, when
// it can reach a counting gate, its own counter (nil = logs but counts nothing).
var (
	// SkipNoCanonicalHeader: no canonical header exists at the height.
	SkipNoCanonicalHeader = SkipReason{name: "no canonical header at height", handler: gradeWarn, preFilter: gradeInfo, counter: metrics.NewRegisteredCounter("skipped-proposed-block/no-canonical-header", nil)}

	// SkipNonCanonical: the header is not the canonical block at its height.
	SkipNonCanonical = SkipReason{name: "non-canonical", handler: gradeWarn, preFilter: gradeInfo, counter: metrics.NewRegisteredCounter("skipped-proposed-block/non-canonical", nil)}

	// SkipBodyNotStored: the canonical block's body is not in the database yet (fast sync).
	SkipBodyNotStored = SkipReason{name: "block body not stored", handler: gradeInfo, preFilter: gradeInfo, counter: metrics.NewRegisteredCounter("skipped-proposed-block/body-not-stored", nil)}

	// SkipUnjudgeable: the chain lacks BlockStorer — a wiring bug, graded Error;
	// see ShouldHandleProposedBlock.
	SkipUnjudgeable = SkipReason{name: "unjudgeable", handler: gradeError, preFilter: gradeError}

	// SkipNilHeader: a nil header or nil number — a caller bug, graded Error;
	// see SkipNilHeaderLog.
	SkipNilHeader = SkipReason{name: "nil header", handler: gradeError}
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
func ShouldHandleProposedBlock(chain consensus.CanonicalChain, header *types.Header) (bool, SkipReason, common.Hash) {
	if header == nil || header.Number == nil {
		return false, SkipNilHeader, common.Hash{}
	}
	storer, ok := chain.(consensus.BlockStorer)
	if !ok {
		// The BlockStorer assertion: a chain without it cannot answer the
		// storage half, and judging every block "not stored" would halt
		// processQC and voting. Production wiring cannot get here (every entry
		// point takes ProposedBlockChain; the downloader's BlockChain requires
		// HasBlock), so it counts nothing — the Error grade on the reason above
		// is the wiring-bug alarm.
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
	return true, SkipReason{}, canonical.Hash()
}

// SkipLogLevel grades a skip once the handler is reached: wiring and caller bugs
// are Errors, reorg races Warn, the expected fast-sync skip Info. A reason
// declaring no grade warns.
func SkipLogLevel(reason SkipReason) func(msg string, ctx ...interface{}) {
	return reason.handler.logFunc()
}

// PreFilterSkipLogLevel grades a skip at the downloader's pre-filter, where fork
// tails are routine noise (Info); the one unjudgeable path grades Error there
// too. A reason declaring no pre-filter grade warns.
func PreFilterSkipLogLevel(reason SkipReason) func(msg string, ctx ...interface{}) {
	return reason.preFilter.logFunc()
}

// IncSkipReasonCounter bumps the reason's own counter. Call it in addition to
// the engine gates' total proposed-block-skip-total (declared in the v2 engine,
// named outside the skipped-proposed-block/ prefix so one alert regex on that
// prefix cannot double-count the total), never instead: the total is the gates'
// aggregate view and the per-reason counters are its breakdown. Reasons
// carrying no counter — SkipNilHeader, SkipUnjudgeable — count nothing.
func IncSkipReasonCounter(reason SkipReason) {
	if reason.counter != nil {
		reason.counter.Inc(1)
	}
}

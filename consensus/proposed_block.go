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

// This file is XDPoS v2 specific: the judgment and its capabilities are shared
// by the v2 engine and the eth/fetcher gate, and live in the consensus package
// both already import rather than in either of them.

import (
	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/log"
	"github.com/XinFinOrg/XDPoSChain/metrics"
	"github.com/XinFinOrg/XDPoSChain/rlp"
)

// unjudgeableProposedBlock counts SkipUnjudgeable; consensus/
// skipped-proposed-block counts the engine gates' skips, a separate alert.
var unjudgeableProposedBlock = metrics.NewRegisteredCounter("consensus/unjudgeable-proposed-block", nil)

// CanonicalChain is the canonicality half of the judgment.
type CanonicalChain interface {
	// GetHeaderByNumber returns the header at a height.
	GetHeaderByNumber(number uint64) *types.Header
}

// BlockStorer is the storage half. *core.HeaderChain deliberately does not
// implement it, so handing one in fails as SkipUnjudgeable.
type BlockStorer interface {
	// HasBlock reports whether the block is stored.
	HasBlock(hash common.Hash, number uint64) bool
}

// SkipReason describes why a proposed block header was rejected; the empty
// value means it was accepted. New reasons register in skipGrades.
type SkipReason string

const (
	// SkipNoCanonicalHeader: no canonical header exists at the height.
	SkipNoCanonicalHeader SkipReason = "no canonical header at height"

	// SkipNonCanonical: the header is not the canonical block at its height.
	SkipNonCanonical SkipReason = "non-canonical"

	// SkipBodyNotStored: the body has not landed yet, e.g. during fast sync.
	SkipBodyNotStored SkipReason = "block body not stored"

	// SkipUnjudgeable: the chain does not implement BlockStorer — a wiring bug.
	SkipUnjudgeable SkipReason = "unjudgeable"

	// SkipNilHeader: a nil header, or one without a number — a caller bug.
	SkipNilHeader SkipReason = "nil header"
)

// ShouldHandleProposedBlock reports whether a header may reach the consensus
// handler: it must be the canonical block at its height, or a newer proposal for
// that block's parent, with its body stored. The reads are not atomic, so the
// engine re-checks before processQC and before sendVote; a caller with a weaker
// storage guarantee must add its own gate.
func ShouldHandleProposedBlock(chain CanonicalChain, header *types.Header) (bool, SkipReason, common.Hash) {
	if header == nil || header.Number == nil {
		return false, SkipNilHeader, common.Hash{}
	}
	storer, ok := chain.(BlockStorer)
	if !ok {
		unjudgeableProposedBlock.Inc(1)
		return false, SkipUnjudgeable, common.Hash{}
	}
	canonical := chain.GetHeaderByNumber(header.Number.Uint64())
	if canonical == nil {
		return false, SkipNoCanonicalHeader, common.Hash{}
	}
	if canonical.Hash() != header.Hash() && !isNewerProposalForSameParent(header, canonical) {
		return false, SkipNonCanonical, canonical.Hash()
	}
	if !storer.HasBlock(header.Hash(), header.Number.Uint64()) {
		return false, SkipBodyNotStored, canonical.Hash()
	}
	return true, "", canonical.Hash()
}

// isNewerProposalForSameParent reports whether header is a later round's proposal
// for the parent of the canonical block at its height.
//
// A height keeps the first proposal of a round as its canonical block until a QC
// commits it, so a timeout round re-proposes the same parent and produces a
// sibling. Only one of them can be canonical — a same-height block never wins fork
// choice, since both carry the same total difficulty — and rejecting the sibling
// as non-canonical would leave the height without a QC for good: the canonical
// one's round is already over, so no vote can be collected for it any more.
func isNewerProposalForSameParent(header, canonical *types.Header) bool {
	if header.ParentHash != canonical.ParentHash {
		return false
	}
	proposalRound, ok := v2Round(header)
	if !ok {
		return false
	}
	canonicalRound, ok := v2Round(canonical)
	if !ok {
		return false
	}
	return proposalRound > canonicalRound
}

// v2Round decodes the round of a v2 header. A header that is not v2, or whose
// extra does not decode, reports false and keeps the strict judgment: a proposal
// this node cannot read the round of is not a re-proposal.
func v2Round(header *types.Header) (types.Round, bool) {
	// Version byte 2 marks the v2 extra; v1 headers and the v1 switch block carry
	// something else.
	if len(header.Extra) == 0 || header.Extra[0] != 2 {
		return 0, false
	}
	var extra types.ExtraFields_v2
	if err := rlp.DecodeBytes(header.Extra[1:], &extra); err != nil {
		return 0, false
	}
	return extra.Round, true
}

// skipGrades is the single registration table for every SkipReason; an
// unregistered reason logs at Warn. The fetcher gate produces no SkipReason.
var skipGrades = map[SkipReason]func(msg string, ctx ...interface{}){
	SkipUnjudgeable:       log.Error,
	SkipNilHeader:         log.Error,
	SkipNonCanonical:      log.Warn,
	SkipNoCanonicalHeader: log.Warn,
	SkipBodyNotStored:     log.Info,
}

// SkipLogLevel grades a skip once the handler is reached: wiring and caller
// bugs log Error, reorg races Warn, the expected fast-sync skip Info.
func SkipLogLevel(reason SkipReason) func(msg string, ctx ...interface{}) {
	if handler, ok := skipGrades[reason]; ok {
		return handler
	}
	return log.Warn
}

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
// handler: it must be the canonical block at its height, with its body stored.
// The reads are not atomic, so the engine re-checks before processQC and before
// sendVote; a caller with a weaker storage guarantee must add its own gate.
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
	if canonical.Hash() != header.Hash() {
		return false, SkipNonCanonical, canonical.Hash()
	}
	if !storer.HasBlock(header.Hash(), header.Number.Uint64()) {
		return false, SkipBodyNotStored, canonical.Hash()
	}
	return true, "", canonical.Hash()
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

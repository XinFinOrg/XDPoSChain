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
	"bytes"
	"math/big"
	"strings"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/log"
)

// stubCanonicalChain is the minimal chain the judgment needs: the canonical
// header per height, plus which hashes have a stored body.
type stubCanonicalChain struct {
	headers map[uint64]*types.Header
	bodies  map[common.Hash]bool
}

func (s *stubCanonicalChain) GetHeaderByNumber(number uint64) *types.Header {
	return s.headers[number]
}

func (s *stubCanonicalChain) HasBlock(hash common.Hash, number uint64) bool {
	return s.bodies[hash]
}

// stubHeaderOnlyChain is a CanonicalChain deliberately not a BlockStorer, the
// way a header-only chain looks to the judgment.
type stubHeaderOnlyChain struct {
	headers map[uint64]*types.Header
}

func (s *stubHeaderOnlyChain) GetHeaderByNumber(number uint64) *types.Header {
	return s.headers[number]
}

func TestShouldHandleProposedBlock(t *testing.T) {
	const height = uint64(906)
	canonical := &types.Header{Number: big.NewInt(int64(height)), Coinbase: common.BytesToAddress([]byte{0x01})}
	fork := &types.Header{Number: big.NewInt(int64(height)), Coinbase: common.BytesToAddress([]byte{0x02})}

	for _, c := range []struct {
		name          string
		headers       map[uint64]*types.Header
		bodies        map[common.Hash]bool
		header        *types.Header
		storerless    bool
		wantOK        bool
		wantReason    SkipReason
		wantCanonHash common.Hash
	}{
		{
			name:          "no canonical header at height",
			headers:       map[uint64]*types.Header{},
			bodies:        map[common.Hash]bool{},
			header:        canonical,
			wantOK:        false,
			wantReason:    SkipNoCanonicalHeader,
			wantCanonHash: common.Hash{},
		},
		{
			name:          "nil header is a caller bug, skipped before any chain read",
			headers:       map[uint64]*types.Header{},
			bodies:        map[common.Hash]bool{},
			header:        nil,
			wantOK:        false,
			wantReason:    SkipNilHeader,
			wantCanonHash: common.Hash{},
		},
		{
			name:          "header without number is a caller bug too",
			headers:       map[uint64]*types.Header{},
			bodies:        map[common.Hash]bool{},
			header:        &types.Header{Coinbase: common.BytesToAddress([]byte{0x03})},
			wantOK:        false,
			wantReason:    SkipNilHeader,
			wantCanonHash: common.Hash{},
		},
		{
			name: "non-canonical",
			headers: map[uint64]*types.Header{
				height: canonical,
			},
			bodies: map[common.Hash]bool{
				fork.Hash(): true,
			},
			header:        fork,
			wantOK:        false,
			wantReason:    SkipNonCanonical,
			wantCanonHash: canonical.Hash(),
		},
		{
			name: "canonical header without stored body",
			headers: map[uint64]*types.Header{
				height: canonical,
			},
			bodies:        map[common.Hash]bool{},
			header:        canonical,
			wantOK:        false,
			wantReason:    SkipBodyNotStored,
			wantCanonHash: canonical.Hash(),
		},
		{
			name: "canonical header with stored body",
			headers: map[uint64]*types.Header{
				height: canonical,
			},
			bodies: map[common.Hash]bool{
				canonical.Hash(): true,
			},
			header:        canonical,
			wantOK:        true,
			wantReason:    "",
			wantCanonHash: canonical.Hash(),
		},
		{
			name: "header-only chain cannot answer the storage half",
			headers: map[uint64]*types.Header{
				height: canonical,
			},
			header:     canonical,
			storerless: true,
			wantOK:     false,
			wantReason: SkipUnjudgeable,
		},
		{
			name:       "header-only chain, absent height still unjudgeable",
			headers:    map[uint64]*types.Header{},
			header:     canonical,
			storerless: true,
			wantOK:     false,
			wantReason: SkipUnjudgeable,
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			var chain CanonicalChain = &stubCanonicalChain{headers: c.headers, bodies: c.bodies}
			if c.storerless {
				chain = &stubHeaderOnlyChain{headers: c.headers}
			}
			// The counter is read before and after the call, so no case in this
			// file may run in parallel.
			before := unjudgeableProposedBlock.Snapshot().Count()
			ok, reason, canonicalHash := ShouldHandleProposedBlock(chain, c.header)
			if ok != c.wantOK {
				t.Errorf("ok = %v, want %v", ok, c.wantOK)
			}
			if reason != c.wantReason {
				t.Errorf("reason = %q, want %q", reason, c.wantReason)
			}
			if canonicalHash != c.wantCanonHash {
				t.Errorf("canonicalHash = %v, want %v", canonicalHash, c.wantCanonHash)
			}
			if c.storerless {
				if got := unjudgeableProposedBlock.Snapshot().Count(); got != before+1 {
					t.Errorf("unjudgeable counter = %d, want %d (+1 per SkipUnjudgeable)", got, before+1)
				}
			}
		})
	}
}

// TestSkipLogLevelGradesByReason pins the grading: wiring and caller bugs log
// Error, reorg races Warn, the routine fast-sync skip Info, and an unregistered
// reason Warn so a forgotten registration surfaces.

func TestSkipLogLevelGradesByReason(t *testing.T) {
	var logBuf bytes.Buffer
	glog := log.NewGlogHandler(log.NewTerminalHandlerWithLevel(&logBuf, log.LevelInfo, false))
	glog.Verbosity(log.LevelInfo)
	prevLog := log.Root()
	log.SetDefault(log.NewLogger(glog))
	defer log.SetDefault(prevLog)

	for _, c := range []struct {
		reason SkipReason
		want   string
	}{
		{
			SkipUnjudgeable,
			"ERROR",
		},
		{SkipNilHeader, "ERROR"},
		{SkipNonCanonical, "WARN"},
		{SkipNoCanonicalHeader, "WARN"},
		{SkipBodyNotStored, "INFO"},
		{SkipReason(""), "WARN"},
		// A forgotten registration must surface, not hide at Info.
		{SkipReason("unregistered-future-reason"), "WARN"},
	} {
		logBuf.Reset()
		SkipLogLevel(c.reason)("skip level probe")
		level := ""
		for _, line := range strings.Split(logBuf.String(), "\n") {
			if strings.Contains(line, "skip level probe") {
				level = strings.Fields(line)[0]
				// glog pads the level to five characters.
				if i := strings.IndexByte(level, '['); i >= 0 {
					level = level[:i]
				}
				break
			}
		}
		if level != c.want {
			t.Errorf("reason %q graded to %q, want %s (log: %q)", c.reason, level, c.want, logBuf.String())
		}
	}
}

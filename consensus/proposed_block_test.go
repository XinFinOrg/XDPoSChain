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
	"go/ast"
	"go/parser"
	"go/token"
	"math/big"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/log"
)

// stubCanonicalChain is the minimal chain the judgment needs: the canonical
// header per height and which hashes have a body stored behind them. It is
// both a CanonicalChain and a BlockStorer — the judgement must never look at
// anything else.
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

// stubHeaderOnlyChain is a CanonicalChain that is deliberately not a
// BlockStorer, the way a header-only chain (e.g. *core.HeaderChain) looks to
// the judgment: it must be skipped as SkipUnjudgeable, not judged "not stored".
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
		})
	}
}

// TestSkipLogLevelGradesByReason pins the skip-log grading contract at
// SkipLogLevel's definition site: SkipUnjudgeable — the wiring-bug skip that
// halts QC processing and voting — surfaces as Error and sits outside the
// Info/Warn discipline, the reorg-race skips (SkipNonCanonical,
// SkipNoCanonicalHeader) surface as Warn, while SkipBodyNotStored — the one
// routine sync skip — stays at Info, both here at the unit level and
// end-to-end at the handler level (TestProposedBlockHandlerGradesSkipLogLevelByReason).
// The empty reason means a misused accept — a caller bug — and grades Warn.
// Any other unregistered reason grades Warn: a future skip reason whose
// registration is forgotten must surface loudly, not hide at Info.
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
		// An unregistered reason must grade as the anomaly it most likely is,
		// so a future reason whose registration is forgotten surfaces loudly
		// instead of hiding at Info. The default branch is Warn for exactly
		// this case.
		{SkipReason("unregistered-future-reason"), "WARN"},
	} {
		logBuf.Reset()
		SkipLogLevel(c.reason)("skip level probe")
		level := ""
		for _, line := range strings.Split(logBuf.String(), "\n") {
			if strings.Contains(line, "skip level probe") {
				level = strings.Fields(line)[0]
				// glog pads the level to five characters, so "ERROR" carries
				// no trailing space and runs straight into the timestamp.
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

// TestPreFilterSkipLogLevelGradesByReason pins the downloader pre-filter's
// call-site grading: the three routine reasons are Info there (fork tails
// are expected sync noise, unlike the reorg races at the handler),
// SkipUnjudgeable stays Error, SkipNilHeader falls back to Warn (the
// pre-filter cannot produce it, so it carries no preFilter grade), and an
// unregistered reason grades Warn.
func TestPreFilterSkipLogLevelGradesByReason(t *testing.T) {
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
		{SkipUnjudgeable, "ERROR"},
		{SkipNilHeader, "WARN"}, // no preFilter grade; cannot reach the pre-filter anyway
		{SkipNonCanonical, "INFO"},
		{SkipNoCanonicalHeader, "INFO"},
		{SkipBodyNotStored, "INFO"},
		{SkipReason("unregistered-future-reason"), "WARN"},
	} {
		logBuf.Reset()
		PreFilterSkipLogLevel(c.reason)("pre-filter level probe")
		level := ""
		for _, line := range strings.Split(logBuf.String(), "\n") {
			if strings.Contains(line, "pre-filter level probe") {
				level = strings.Fields(line)[0]
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

// TestSkipReasonsTableCoversDeclaredReasons pins the single registration
// table in both directions: every SkipReason constant declared in this
// package must have an entry — otherwise both graders silently fall back to
// Warn and a new reason's intended level never applies — and the table must
// not hold entries beyond the declared constants. The declared set is
// enumerated from the package source with go/parser rather than a
// hand-maintained second list: two parallel lists only disagree loudly, but
// a new constant that skips both passes a list-vs-table comparison
// undetected. The AST enumeration has no second list to forget, so an
// unregistered constant cannot hide.
//
// Counting invariants: SkipNilHeader logs but counts nothing (see
// SkipNilHeaderLog), and SkipUnjudgeable also counts nothing — production
// wiring hands every entry point a ProposedBlockChain, so the reason cannot
// fire outside test fakes and a counter would be permanently silent in
// production, false assurance in alerting; the Error logs are the alarm.
// Every other declared reason can reach a counting gate and must carry one
// that IncSkipReasonCounter moves.
func TestSkipReasonsTableCoversDeclaredReasons(t *testing.T) {
	declared := declaredSkipReasons(t)

	for _, c := range declared {
		entry, ok := skipReasons[c.reason]
		if !ok {
			t.Errorf("skipReasons has no entry for SkipReason constant %s = %q; register it in the skipReasons table", c.name, c.reason)
			continue
		}
		if c.reason == SkipNilHeader || c.reason == SkipUnjudgeable {
			if entry.counter != nil {
				t.Errorf("%s must not carry a counter: it counts nothing (see skipReasons)", c.name)
			}
			continue
		}
		if entry.counter == nil {
			t.Errorf("SkipReason constant %s can reach a counting gate but has no counter; register it in the skipReasons table", c.name)
			continue
		}
		before := entry.counter.Snapshot().Count()
		IncSkipReasonCounter(c.reason)
		if got := entry.counter.Snapshot().Count(); got != before+1 {
			t.Errorf("IncSkipReasonCounter(%s) did not move its counter: before = %d, after = %d", c.name, before, got)
		}
	}
	if len(skipReasons) != len(declared) {
		t.Errorf("skipReasons holds %d entries for %d declared SkipReasons; a table entry is not a declared constant", len(skipReasons), len(declared))
	}
}

// declaredSkipReasons enumerates every constant of type SkipReason declared in
// this package's non-test source files by parsing the AST. skipReasons is keyed
// by the constants' values, so the walk collects each spec's string literal.
// Only the shape the package actually uses — an explicit SkipReason type with
// a string-literal value — is supported; any other shape is a loud failure,
// never a silent skip or a panic.
func declaredSkipReasons(t *testing.T) []struct {
	name   string
	reason SkipReason
} {
	t.Helper()

	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("failed to read consensus package directory: %v", err)
	}
	var declared []struct {
		name   string
		reason SkipReason
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, entry.Name(), nil, 0)
		if err != nil {
			t.Fatalf("failed to parse %s: %v", entry.Name(), err)
		}
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.CONST {
				continue
			}
			typed := false
			for _, spec := range gen.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				// Go's grouped-const rule: a spec without its own type inherits the
				// previous spec's type, so track it across the block. A spec whose
				// value is a SkipReason(...) conversion carries no type and stays
				// unsupported — it either Fatalfs on its value shape below or is
				// caught by the declared-vs-table count check.
				if vs.Type != nil {
					id, ok := vs.Type.(*ast.Ident)
					typed = ok && id.Name == "SkipReason"
				}
				if !typed {
					continue
				}
				if len(vs.Values) != len(vs.Names) {
					t.Fatalf("SkipReason const %s has %d names for %d values; omitted values are not supported", vs.Names[0].Name, len(vs.Names), len(vs.Values))
				}
				for i, name := range vs.Names {
					lit, ok := vs.Values[i].(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						t.Fatalf("SkipReason constant %s has an unsupported value expression; declaredSkipReasons only supports string literals", name.Name)
					}
					value, err := strconv.Unquote(lit.Value)
					if err != nil {
						t.Fatalf("SkipReason constant %s has an unquotable value %s: %v", name.Name, lit.Value, err)
					}
					declared = append(declared, struct {
						name   string
						reason SkipReason
					}{name.Name, SkipReason(value)})
				}
			}
		}
	}
	if len(declared) == 0 {
		t.Fatal("no SkipReason constants found in the consensus package; the AST walk itself is broken")
	}
	return declared
}

// TestIsJudgeableHeader pins the nil-shape half of the proposed-block header
// contract at its single implementation: a nil header and a nil number are
// both unjudgeable, and a real header with a number is judgeable. The three
// call sites (XDPoS wrapper, v2 engine, eth fetcher gate) must reject the
// same shapes — log Error, no counter, return nil.
func TestIsJudgeableHeader(t *testing.T) {
	if IsJudgeableHeader(nil) {
		t.Error("nil header must not be judgeable")
	}
	if IsJudgeableHeader(&types.Header{}) {
		t.Error("header with nil number must not be judgeable")
	}
	if !IsJudgeableHeader(&types.Header{Number: big.NewInt(1)}) {
		t.Error("header with a number must be judgeable")
	}
}

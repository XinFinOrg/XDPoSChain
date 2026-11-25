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

package native

import (
	"encoding/json"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/core/tracing"
	"github.com/XinFinOrg/XDPoSChain/eth/tracers"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// v1GasTracer returns a child tracer exposing only the V1 gas hook.
func v1GasTracer(events *[]uint64) *tracers.Tracer {
	return &tracers.Tracer{Hooks: &tracing.Hooks{
		OnGasChange: func(old, new uint64, _ tracing.GasChangeReason) {
			*events = append(*events, old, new)
		},
	}}
}

// TestMuxTracerGasChangeV1Fallback pins that a child which only implements the
// V1 hook still receives events when the mux fans a V2 event out.
func TestMuxTracerGasChangeV1Fallback(t *testing.T) {
	var events []uint64
	mux := &muxTracer{names: []string{"v1"}, tracers: []*tracers.Tracer{v1GasTracer(&events)}}
	mux.OnGasChangeV2(tracing.Gas{Regular: 10, State: 1}, tracing.Gas{Regular: 5, State: 2}, tracing.GasChangeCallOpCode)
	if len(events) != 2 || events[0] != 10 || events[1] != 5 {
		t.Fatalf("V1-only child got %v, want [10 5]", events)
	}
}

// TestMuxTracerGasChangeV2Preference pins that a child implementing both hook
// variants is only called through V2.
func TestMuxTracerGasChangeV2Preference(t *testing.T) {
	var v1, v2 []tracing.Gas
	mux := &muxTracer{names: []string{"both"}, tracers: []*tracers.Tracer{{Hooks: &tracing.Hooks{
		OnGasChange: func(old, new uint64, _ tracing.GasChangeReason) {
			v1 = append(v1, tracing.Gas{Regular: old}, tracing.Gas{Regular: new})
		},
		OnGasChangeV2: func(old, new tracing.Gas, _ tracing.GasChangeReason) { v2 = append(v2, old, new) },
	}}}}
	mux.OnGasChangeV2(tracing.Gas{Regular: 10, State: 1}, tracing.Gas{Regular: 5, State: 2}, tracing.GasChangeCallOpCode)
	if len(v1) != 0 {
		t.Fatalf("V1 hook called alongside V2: %v", v1)
	}
	if want := []tracing.Gas{{Regular: 10, State: 1}, {Regular: 5, State: 2}}; len(v2) != 2 || v2[0] != want[0] || v2[1] != want[1] {
		t.Fatalf("V2 hook got %v, want %v", v2, want)
	}
}

// TestMuxTracerExposesGasV2 pins that the mux registers the V2 hook on the
// Hooks it exposes upward, and that the fanout reaches a V1-only child.
func TestMuxTracerExposesGasV2(t *testing.T) {
	var events []uint64
	tracers.DefaultDirectory.Register("testGasV1", func(*tracers.Context, json.RawMessage, *params.ChainConfig) (*tracers.Tracer, error) {
		return v1GasTracer(&events), nil
	}, false)
	tracer, err := newMuxTracer(&tracers.Context{}, json.RawMessage(`{"testGasV1":{}}`), params.TestChainConfig)
	if err != nil {
		t.Fatalf("failed to build mux tracer: %v", err)
	}
	if tracer.Hooks.OnGasChangeV2 == nil {
		t.Fatal("mux tracer does not expose OnGasChangeV2 upward")
	}
	tracer.Hooks.EmitGasChange(tracing.Gas{Regular: 10}, tracing.Gas{Regular: 5}, tracing.GasChangeCallOpCode)
	if len(events) != 2 || events[0] != 10 || events[1] != 5 {
		t.Fatalf("child got %v through the mux, want [10 5]", events)
	}
}

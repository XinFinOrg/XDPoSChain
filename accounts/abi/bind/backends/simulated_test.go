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

package backends

import (
	"errors"
	"strings"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// TestCommitPanicsWithTheCause pins why this deprecated wrapper overrides Commit at all: its
// callers ignore the returned hash, so a chain it cannot write to has to fail loudly - and the
// panic has to name the local condition that stopped the write. Without the cause an operator
// cannot tell a stopped chain from an interrupted import, which is the only thing the panic is
// good for.
func TestCommitPanicsWithTheCause(t *testing.T) {
	sim := NewXDCSimulatedBackend(types.GenesisAlloc{}, 10_000_000, params.TestXDPoSMockChainConfig)
	sim.Close()

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("Commit must fail loudly on a chain that cannot be written to")
		}
		err, ok := r.(error)
		if !ok {
			t.Fatalf("unexpected panic value: %v", r)
		}
		if !errors.Is(err, core.ErrChainStopped) {
			t.Fatalf("the panic must carry the cause: have %v want %v", err, core.ErrChainStopped)
		}
		if !strings.Contains(err.Error(), "backends: Commit on a chain that cannot be written to") {
			t.Fatalf("the panic must keep this wrapper's own wording: %v", err)
		}
	}()
	sim.Commit()
}

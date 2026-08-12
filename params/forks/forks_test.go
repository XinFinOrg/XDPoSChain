// Copyright 2023 The go-ethereum Authors
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

package forks

import "testing"

// TestForkToStringCoversEveryFork guards against adding a fork constant without
// a label, which String would otherwise report as "Unknown fork (n)".
func TestForkToStringCoversEveryFork(t *testing.T) {
	for f := Frontier; f < lastFork; f++ {
		if _, ok := forkToString[f]; !ok {
			t.Fatalf("fork %d has no label", int(f))
		}
	}
	if len(forkToString) != int(lastFork) {
		t.Fatalf("forkToString has %d entries, want %d", len(forkToString), int(lastFork))
	}
}

// TestGasTierForksAreOrdered pins the relative order of the gas schedule tiers.
func TestGasTierForksAreOrdered(t *testing.T) {
	if Gas50x >= Gas2500x {
		t.Fatalf("Gas50x (%d) must precede Gas2500x (%d)", Gas50x, Gas2500x)
	}
}

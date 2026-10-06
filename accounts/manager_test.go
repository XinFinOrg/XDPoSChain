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

package accounts

import (
	"slices"
	"testing"
)

type managerTestWallet struct {
	Wallet
	url URL
}

func (w managerTestWallet) URL() URL {
	return w.url
}

func TestDropMissingWallet(t *testing.T) {
	t.Parallel()

	wallets := []Wallet{
		managerTestWallet{url: URL{Scheme: "test", Path: "a"}},
		managerTestWallet{url: URL{Scheme: "test", Path: "c"}},
	}
	dropped := drop(wallets, managerTestWallet{url: URL{Scheme: "test", Path: "b"}})

	if len(dropped) != len(wallets) {
		t.Fatalf("drop removed wallet for missing URL: got %d wallets, want %d", len(dropped), len(wallets))
	}
	for i := range dropped {
		if got, want := dropped[i].URL(), wallets[i].URL(); got != want {
			t.Fatalf("wallet %d mismatch: got %v, want %v", i, got, want)
		}
	}
}

// TestDropPresentWallets covers the other half of drop: a wallet that is in the
// cache must actually leave it, and only that wallet. TestDropMissingWallet only
// pins the direction where nothing may be removed, so an implementation that
// never removes anything passes that one.
func TestDropPresentWallets(t *testing.T) {
	t.Parallel()

	// wallets builds a fresh cache for the given URL paths. Every case needs its
	// own slice: drop compacts in place and zeroes the obsolete tail, so cases
	// sharing one backing array would hand the later ones nil elements.
	wallets := func(paths ...string) []Wallet {
		ws := make([]Wallet, 0, len(paths))
		for _, path := range paths {
			ws = append(ws, managerTestWallet{url: URL{Scheme: "test", Path: path}})
		}
		return ws
	}
	pathsOf := func(ws []Wallet) []string {
		paths := make([]string, 0, len(ws))
		for _, w := range ws {
			paths = append(paths, w.URL().Path)
		}
		return paths
	}

	tests := []struct {
		name  string
		cache []string // wallet paths in the cache, already sorted by URL
		drop  []string // wallet paths handed to drop
		want  []string // paths that must remain, in their original order
	}{
		{"single present", []string{"a", "b", "c"}, []string{"b"}, []string{"a", "c"}},
		{"multiple present", []string{"a", "b", "c"}, []string{"a", "c"}, []string{"b"}},
		{"all present", []string{"a", "b", "c"}, []string{"a", "b", "c"}, []string{}},
		{"absent below range", []string{"b", "c"}, []string{"a"}, []string{"b", "c"}},
		{"absent above range", []string{"a", "b", "c"}, []string{"d"}, []string{"a", "b", "c"}},
		{"absent from empty cache", nil, []string{"a"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cache := wallets(tt.cache...)
			got := pathsOf(drop(cache, wallets(tt.drop...)...))

			if !slices.Equal(got, tt.want) {
				t.Fatalf("drop(%v, %v) = %v, want %v", tt.cache, tt.drop, got, tt.want)
			}
		})
	}
}

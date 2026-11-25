// Copyright 2022 The go-ethereum Authors
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

package lru

import "testing"

func TestRemoveIf(t *testing.T) {
	t.Run("matching value", func(t *testing.T) {
		cache := NewCache[string, *int](4)
		owned := new(int)
		cache.Add("k", owned)

		if !cache.RemoveIf("k", func(v *int) bool { return v == owned }) {
			t.Fatal("RemoveIf did not drop the matching entry")
		}
		if cache.Contains("k") {
			t.Fatal("the matching entry is still cached")
		}
	})
	t.Run("other value", func(t *testing.T) {
		cache := NewCache[string, *int](4)
		owned := new(int)
		cache.Add("k", owned)

		if cache.RemoveIf("k", func(v *int) bool { return v != owned }) {
			t.Fatal("RemoveIf dropped an entry another calculation owns")
		}
		if !cache.Contains("k") {
			t.Fatal("the entry another calculation owns was dropped")
		}
	})
	t.Run("missing key", func(t *testing.T) {
		cache := NewCache[string, *int](4)
		if cache.RemoveIf("k", func(*int) bool { return true }) {
			t.Fatal("RemoveIf reported a removal for a missing key")
		}
	})
	t.Run("incomparable value", func(t *testing.T) {
		cache := NewCache[string, []byte](4)
		cache.Add("k", []byte{1})

		if !cache.RemoveIf("k", func([]byte) bool { return true }) {
			t.Fatal("RemoveIf did not drop an entry with an incomparable value")
		}
	})
}

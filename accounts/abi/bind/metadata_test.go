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

package bind

import "testing"

// metaDataABI is a minimal valid ABI: one constant getter without arguments.
const metaDataABI = `[{"constant":true,"inputs":[],"name":"value","outputs":[{"name":"","type":"uint256"}],"type":"function"}]`

// TestMetaDataGetAbiCachesParse checks that the parsed ABI of a MetaData is
// computed once and then handed out from the cache. Generated v1 bindings call
// this method on every New<Contract>Caller and friends, so a cache that is
// bypassed turns each construction into another full JSON parse.
//
// The second call is compared by pointer, and the parse result is checked as
// well: a cache that returns one shared error or one zero value for every call
// would satisfy the error check alone.
func TestMetaDataGetAbiCachesParse(t *testing.T) {
	t.Parallel()

	meta := &MetaData{ABI: metaDataABI}

	first, err := meta.GetAbi()
	if err != nil {
		t.Fatalf("first GetAbi failed: %v", err)
	}
	second, err := meta.GetAbi()
	if err != nil {
		t.Fatalf("second GetAbi failed: %v", err)
	}
	if first != second {
		t.Error("GetAbi returned a different instance on the second call, want the cached one")
	}
	if len(first.Methods) != 1 {
		t.Fatalf("parsed ABI has %d methods, want 1", len(first.Methods))
	}
	if _, ok := first.Methods["value"]; !ok {
		t.Errorf("parsed ABI does not contain the value method: %v", first.Methods)
	}
}

// TestMetaDataGetAbiDoesNotCacheErrors checks that a failed parse is not cached:
// a binding whose ABI is rejected keeps reporting the error, and a binding whose
// ABI is corrected afterwards parses successfully. Caching the failure would
// pin the first result forever, because the cache is keyed on nothing but the
// MetaData it belongs to.
func TestMetaDataGetAbiDoesNotCacheErrors(t *testing.T) {
	t.Parallel()

	meta := &MetaData{ABI: `[{"type":"function",`}

	if _, err := meta.GetAbi(); err == nil {
		t.Fatal("GetAbi accepted a truncated ABI")
	}
	if meta.parsedABI != nil {
		t.Error("GetAbi cached the result of a failed parse")
	}
	meta.ABI = metaDataABI

	parsed, err := meta.GetAbi()
	if err != nil {
		t.Fatalf("GetAbi failed after the ABI was corrected: %v", err)
	}
	if len(parsed.Methods) != 1 {
		t.Errorf("parsed ABI has %d methods, want 1", len(parsed.Methods))
	}
}

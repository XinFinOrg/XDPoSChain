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

import (
	"sync"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/accounts/abi"
)

// metaDataABI is a minimal valid ABI: one constant getter without arguments.
const metaDataABI = `[{"constant":true,"inputs":[],"name":"value","outputs":[{"name":"","type":"uint256"}],"type":"function"}]`

// otherMetaDataABI is metaDataABI under another method name. The two differ so
// that a cache handing the same parsed ABI to every MetaData cannot pass the
// per-instance checks below.
const otherMetaDataABI = `[{"constant":true,"inputs":[],"name":"other","outputs":[{"name":"","type":"uint256"}],"type":"function"}]`

// TestMetaDataParseABICachesParse checks that the parsed ABI of a MetaData is
// computed once and then handed out from the cache. Every generated
// New<Contract> constructor calls this method, and the instance wrappers reuse
// the parsed ABI it caches, so a cache that is bypassed turns each construction
// into another full JSON parse.
//
// The second call is compared by pointer, and the parse result is checked as
// well: a cache that returns one shared error or one zero value for every call
// would satisfy the error check alone.
func TestMetaDataParseABICachesParse(t *testing.T) {
	t.Parallel()

	meta := &MetaData{ABI: metaDataABI}

	first, err := meta.ParseABI()
	if err != nil {
		t.Fatalf("first ParseABI failed: %v", err)
	}
	second, err := meta.ParseABI()
	if err != nil {
		t.Fatalf("second ParseABI failed: %v", err)
	}
	if first != second {
		t.Error("ParseABI returned a different instance on the second call, want the cached one")
	}
	if len(first.Methods) != 1 {
		t.Fatalf("parsed ABI has %d methods, want 1", len(first.Methods))
	}
	if _, ok := first.Methods["value"]; !ok {
		t.Errorf("parsed ABI does not contain the value method: %v", first.Methods)
	}
}

// TestMetaDataParseABIDoesNotCacheErrors checks that a failed parse is not
// cached: the rejected ABI must report an error and leave the cache empty, and
// once the ABI is corrected the same binding parses successfully. Caching the
// failure would pin the first result forever, because the cache is keyed on
// nothing but the MetaData it belongs to.
//
// The corrected ABI carries another method name, so that a cache ignoring its
// receiver cannot pass the second half either.
func TestMetaDataParseABIDoesNotCacheErrors(t *testing.T) {
	t.Parallel()

	meta := &MetaData{ABI: `[{"type":"function",`}

	parsed, err := meta.ParseABI()
	if err == nil {
		t.Fatal("ParseABI accepted a truncated ABI")
	}
	if parsed != nil {
		t.Error("ParseABI returned a parsed ABI alongside the parse error")
	}
	meta.mu.Lock()
	cached := meta.parsedABI
	meta.mu.Unlock()
	if cached != nil {
		t.Error("ParseABI cached the result of a failed parse")
	}
	meta.ABI = otherMetaDataABI

	parsed, err = meta.ParseABI()
	if err != nil {
		t.Fatalf("ParseABI failed after the ABI was corrected: %v", err)
	}
	if len(parsed.Methods) != 1 {
		t.Fatalf("parsed ABI has %d methods, want 1", len(parsed.Methods))
	}
	if _, ok := parsed.Methods["other"]; !ok {
		t.Errorf("parsed ABI does not contain the other method: %v", parsed.Methods)
	}
}

// TestMetaDataParseABIKeepsPerInstanceCache checks that the cache belongs to the
// MetaData holding it: two bindings must not share one parsed result, whether
// or not they carry the same ABI. A cache hoisted to package level, or keyed on
// something other than the instance, would hand them whichever ABI happened to
// be parsed first and go unnoticed otherwise.
func TestMetaDataParseABIKeepsPerInstanceCache(t *testing.T) {
	t.Parallel()

	value := &MetaData{ABI: metaDataABI}
	other := &MetaData{ABI: otherMetaDataABI}

	valueABI, err := value.ParseABI()
	if err != nil {
		t.Fatalf("ParseABI on the first metadata failed: %v", err)
	}
	otherABI, err := other.ParseABI()
	if err != nil {
		t.Fatalf("ParseABI on the second metadata failed: %v", err)
	}
	if valueABI == otherABI {
		t.Fatal("two MetaData values share one parsed ABI, want one cache per instance")
	}
	if _, ok := valueABI.Methods["value"]; !ok {
		t.Errorf("the first metadata did not parse its own ABI: %v", valueABI.Methods)
	}
	if _, ok := otherABI.Methods["other"]; !ok {
		t.Errorf("the second metadata did not parse its own ABI: %v", otherABI.Methods)
	}

	same := &MetaData{ABI: metaDataABI}
	sameABI, err := same.ParseABI()
	if err != nil {
		t.Fatalf("ParseABI on the third metadata failed: %v", err)
	}
	if valueABI == sameABI {
		t.Fatal("two MetaData values carrying the same ABI share one parsed ABI, want one cache per instance")
	}
}

// TestMetaDataParseABIConcurrentFirstCall checks that concurrent first calls
// still hand out a single parsed ABI. Generated bindings keep their MetaData in a
// package-level variable, so several goroutines reach ParseABI with an empty
// cache at the same time; without the mutex each of them would parse and cache
// its own instance. Every round builds a fresh MetaData and releases all callers
// at once through a closed channel.
//
// Under -race the concurrent write to the cache field is caught outright; without
// it the pointer comparison turns the failure into a matter of scheduling, which
// is what the number of rounds is there to make overwhelmingly likely.
func TestMetaDataParseABIConcurrentFirstCall(t *testing.T) {
	t.Parallel()

	const (
		callers = 32
		rounds  = 16
	)
	for round := 0; round < rounds; round++ {
		meta := &MetaData{ABI: metaDataABI}

		start := make(chan struct{})
		parsed := make([]*abi.ABI, callers)
		errs := make([]error, callers)

		var wg sync.WaitGroup
		for i := 0; i < callers; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				parsed[i], errs[i] = meta.ParseABI()
			}(i)
		}
		close(start)
		wg.Wait()

		for i, err := range errs {
			if err != nil {
				t.Fatalf("round %d: concurrent ParseABI call %d failed: %v", round, i, err)
			}
		}
		for i, got := range parsed[1:] {
			if got != parsed[0] {
				t.Fatalf("round %d: concurrent call %d returned an instance of its own, want the cached one", round, i+1)
			}
		}
	}
}

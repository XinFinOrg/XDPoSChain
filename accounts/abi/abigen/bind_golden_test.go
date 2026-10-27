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

package abigen

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

// TestBindingV1Golden regenerates every contract of the v1 binding test table
// and compares the result against the output checked in under testdata/v1.
//
// TestBindings already generates the same contracts, but it only compiles and
// runs them, so a v1 template change that still produces working code goes
// unnoticed: the template can drop a caching layer, emit a different helper or
// stop generating a deprecation alias and every test stays green. The checked-in
// bindings under contracts/ shipped for eight months in that state. Comparing
// the text catches it in CI instead.
//
// go-ethereum keeps golden output for the v2 bindings only, so there is nothing
// upstream to port here; the mechanism (one file per test case, regenerated
// under WRITE_TEST_FILES) follows testdata/v2 and TestBindingV2ConvertedV1Tests.
func TestBindingV1Golden(t *testing.T) {
	for _, tt := range bindTests {
		t.Run(tt.name, func(t *testing.T) {
			types := tt.types
			if types == nil {
				types = []string{tt.name}
			}
			have, err := Bind(types, tt.abi, tt.bytecode, tt.fsigs, "bindtest", tt.libs, tt.aliases)
			if err != nil {
				t.Fatalf("failed to generate binding: %v", err)
			}
			fname := fmt.Sprintf("testdata/v1/%v.go.txt", strings.ToLower(tt.name))
			// Set this environment variable to regenerate the test outputs.
			if os.Getenv("WRITE_TEST_FILES") != "" {
				if err := os.WriteFile(fname, []byte(have), 0666); err != nil {
					t.Fatalf("err writing expected output to file: %v\n", err)
				}
			}
			// Verify the generated code
			want, err := os.ReadFile(fname)
			if err != nil {
				t.Fatalf("failed to read file %v", fname)
			}
			if have != string(want) {
				t.Fatalf("wrong output: %v", prettyDiff(have, string(want)))
			}
		})
	}
}

// TestBindingV1IdentifierOrder pins which of two colliding names keeps the
// unsuffixed identifier and that repeated runs agree on it. TestBindingV1Golden
// compares a single run against a file, so a walk that reverted to map order
// would only fail that comparison when the map happened to yield the other
// order; repeating the generation turns the race into a deterministic failure.
func TestBindingV1IdentifierOrder(t *testing.T) {
	const runs = 64

	var numericABI, numericBin []string
	for _, tt := range bindTests {
		if tt.name == "NumericMethodName" {
			numericABI, numericBin = tt.abi, tt.bytecode
		}
	}
	if numericABI == nil {
		t.Fatal("NumericMethodName case not found in bindTests")
	}
	check := func(t *testing.T, types, abis, bytecodes []string, wants ...string) {
		t.Helper()
		first, err := Bind(types, abis, bytecodes, nil, "bindtest", nil, nil)
		if err != nil {
			t.Fatalf("failed to generate binding: %v", err)
		}
		for _, needle := range wants {
			if !strings.Contains(first, needle) {
				t.Fatalf("missing %q in the generated binding", needle)
			}
		}
		for i := 1; i < runs; i++ {
			have, err := Bind(types, abis, bytecodes, nil, "bindtest", nil, nil)
			if err != nil {
				t.Fatalf("run %d: failed to generate binding: %v", i, err)
			}
			if have != first {
				t.Fatalf("run %d differs from the first run: %v", i, prettyDiff(have, first))
			}
		}
	}
	// _1test and __1test both normalize to 1test; the lexicographically first
	// original name keeps the unsuffixed identifier, as abigen v2 does.
	check(t, []string{"NumericMethodName"}, numericABI, numericBin,
		"// M1test is a free data retrieval call binding the contract method 0xffa02795.",
		"// M1test0 is a free data retrieval call binding the contract method 0xd02767c7.",
	)
	// Same for events: _1TestEvent and __1TestEvent both normalize to 1TestEvent.
	// The topic in the doc comment ties the identifier to the event; the
	// FilterLogs needles only name the original event, which is the same
	// whichever identifier it ends up with.
	eventABI := []string{`[{"anonymous":false,"inputs":[],"name":"_1TestEvent","type":"event"},{"anonymous":false,"inputs":[],"name":"__1TestEvent","type":"event"}]`}
	check(t, []string{"Evt"}, eventABI, []string{""},
		"// FilterE1TestEvent is a free log retrieval operation binding the contract event 0x983246db5965e6650853a11cef415e873dec5a34bb334e39fceca10664482e94.",
		"// FilterE1TestEvent0 is a free log retrieval operation binding the contract event 0x2f3a910e3f05b5461e754363cf49ab5396f84c9e8d3c79152158e998404c57ce.",
		"FilterLogs(opts, \"_1TestEvent\")",
		"FilterE1TestEvent0(",
		"FilterLogs(opts, \"__1TestEvent\")",
	)
	// Anonymous tuple types are numbered in the order the walk first meets them,
	// so their names must be stable too: aaa's tuple is Struct0, bbb's Struct1.
	structABI := []string{`[{"inputs":[],"name":"aaa","outputs":[{"components":[{"name":"x","type":"uint256"}],"name":"s","type":"tuple"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"bbb","outputs":[{"components":[{"name":"y","type":"string"}],"name":"t","type":"tuple"}],"stateMutability":"view","type":"function"}]`}
	check(t, []string{"StructNum"}, structABI, []string{""},
		"// Struct0 is an auto generated low-level Go binding around an user-defined struct.\ntype Struct0 struct {\n\tX *big.Int",
		"// Struct1 is an auto generated low-level Go binding around an user-defined struct.\ntype Struct1 struct {\n\tY string",
	)
}

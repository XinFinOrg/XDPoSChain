// Copyright 2026 The XDPoSChain Authors
// This file is part of the XDPoSChain library.
//
// The XDPoSChain library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The XDPoSChain library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the XDPoSChain library. If not, see <http://www.gnu.org/licenses/>.

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

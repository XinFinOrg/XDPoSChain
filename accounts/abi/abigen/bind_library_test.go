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
	"strings"
	"testing"
)

// TestBindLibraryDeploymentWait tests that a generated binding waits for the
// deployment of a library dependency to be accepted before linking the library
// address into the bytecode of the contract that depends on it.
func TestBindLibraryDeploymentWait(t *testing.T) {
	libPattern := "deadbeefdeadbeefdeadbeefdeadbeefde"
	types := []string{"Lib", "Main"}
	abis := []string{`[]`, `[]`}
	bins := []string{
		"0x6000",
		"0x6000__$" + libPattern + "$__6000",
	}
	tests := []struct {
		name string
		libs map[string]string
		want bool
	}{
		{"with library dependencies", map[string]string{libPattern: "Lib"}, true},
		{"without library dependencies", nil, false},
	}
	for _, test := range tests {
		code, err := Bind(types, abis, bins, nil, "bindtest", test.libs, nil)
		if err != nil {
			t.Fatalf("test %q: failed to generate binding: %v", test.name, err)
		}
		found := strings.Contains(code, "bind.WaitAccepted(ctx, backend, tx)")
		if found != test.want {
			t.Errorf("test %q: generated binding waits for the library deployment: got %v, want %v\n%s", test.name, found, test.want, code)
		}
		if !test.want {
			continue
		}
		for _, want := range []string{
			"libAddr, tx, _, err := DeployLib(auth, backend)",
			"if !auth.NoSend {",
			"waitCtx := context.Background()",
			"if auth.Context != nil {",
			"waitCtx = auth.Context",
			"ctx, cancel := context.WithTimeout(waitCtx, 5*time.Second)",
			"defer cancel()",
			"if err := bind.WaitAccepted(ctx, backend, tx); err != nil {",
			"return common.Address{}, nil, nil, err",
		} {
			if !strings.Contains(code, want) {
				t.Errorf("test %q: generated binding does not contain %q\n%s", test.name, want, code)
			}
		}
		// The library deployment error must be handled before the transaction is polled,
		// because a failed deployment returns a nil transaction and WaitAccepted
		// dereferences it.
		deploy := strings.Index(code, "libAddr, tx, _, err := DeployLib(auth, backend)")
		wait := strings.Index(code, "if err := bind.WaitAccepted(ctx, backend, tx); err != nil {")
		if deploy < 0 || wait < deploy {
			t.Errorf("test %q: generated binding does not deploy the library before waiting\n%s", test.name, code)
		} else if !strings.Contains(code[deploy:wait], "if err != nil {") {
			t.Errorf("test %q: generated binding does not check the library deployment error before waiting\n%s", test.name, code)
		}
		// A transaction that is not submitted at all can never be accepted, so
		// the wait must be skipped when the binding is asked not to send it, and
		// it has to sit inside the guard's block rather than after it, where it
		// would run for NoSend deployments as well.
		guard := strings.Index(code, "if !auth.NoSend {")
		guardEnd := -1
		if guard >= 0 {
			depth := 0
			for i := guard; i < len(code); i++ {
				switch code[i] {
				case '{':
					depth++
				case '}':
					depth--
					if depth == 0 {
						guardEnd = i
					}
				}
				if guardEnd >= 0 {
					break
				}
			}
		}
		if guard < 0 || guardEnd < 0 || wait < guard || wait > guardEnd {
			t.Errorf("test %q: generated binding does not skip the acceptance wait for NoSend transactions\n%s", test.name, code)
		}
		// The wait has to honor the caller's context, so the timeout is derived from
		// auth.Context when it is set and the nil check comes before it.
		waitCtx := strings.Index(code, "waitCtx := context.Background()")
		authCtx := strings.Index(code, "waitCtx = auth.Context")
		timeout := strings.Index(code, "ctx, cancel := context.WithTimeout(waitCtx, 5*time.Second)")
		if waitCtx < 0 || authCtx < waitCtx || timeout < authCtx {
			t.Errorf("test %q: generated binding does not derive the acceptance wait timeout from auth.Context\n%s", test.name, code)
		}
	}
}

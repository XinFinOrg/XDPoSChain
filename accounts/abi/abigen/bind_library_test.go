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
	lib2Pattern := "feedfacefeedfacefeedfacefeedfacefe"
	types := []string{"Lib", "Lib2", "Main"}
	abis := []string{`[]`, `[]`, `[]`}
	bins := []string{
		"0x6000",
		"0x6000",
		"0x6000__$" + libPattern + "$__6000__$" + lib2Pattern + "$__6000",
	}
	tests := []struct {
		name     string
		libs     map[string]string
		want     bool
		libCount int
	}{
		{"with library dependencies", map[string]string{libPattern: "Lib"}, true, 1},
		{"with several library dependencies", map[string]string{libPattern: "Lib", lib2Pattern: "Lib2"}, true, 2},
		{"without library dependencies", nil, false, 0},
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
		// Library addresses must be substituted into a function-local copy of the
		// bytecode. The package-level MainBin is shared by every caller, so
		// substituting in it would leave any later deployment linked to the
		// addresses substituted by an earlier one, and concurrent deployments
		// would race on it. The local copy is needed even without libraries,
		// because the deployment call reads it unconditionally.
		for _, want := range []string{
			"linkedBin := MainBin",
			"common.FromHex(linkedBin)",
		} {
			if !strings.Contains(code, want) {
				t.Errorf("test %q: generated binding does not contain %q\n%s", test.name, want, code)
			}
		}
		if strings.Contains(code, "MainBin = strings.ReplaceAll(") {
			t.Errorf("test %q: generated binding substitutes library addresses into the package-level bytecode\n%s", test.name, code)
		}
		if !test.want {
			// Without library dependencies there is no nonce to chain and no
			// opts to copy.
			for _, unwanted := range []string{
				"opts := *auth",
				"auth.Nonce = new(big.Int).SetUint64(tx.Nonce() + 1)",
			} {
				if strings.Contains(code, unwanted) {
					t.Errorf("test %q: generated binding contains %q without library dependencies\n%s", test.name, unwanted, code)
				}
			}
			// The library block's trim markers keep a binding without libraries
			// byte-for-byte identical to the pre-#35888 output: the ABI guard has
			// to be followed directly by the linking comment, without the blank
			// line an untrimmed {{if}} would leave behind. A blank line here would
			// make every regenerated binding stale.
			if want := "errors.New(\"GetABI returned nil\")\n\t}\n\t// Library addresses are substituted"; !strings.Contains(code, want) {
				t.Errorf("test %q: generated binding does not keep the pre-#35888 layout without library dependencies\n%s", test.name, code)
			}
			if strings.Contains(code, "\n\n\t// Library addresses are substituted") {
				t.Errorf("test %q: generated binding keeps the library block's untrimmed blank line\n%s", test.name, code)
			}
			continue
		}
		if want := `linkedBin = strings.ReplaceAll(linkedBin, "__$` + libPattern + `$__", libAddr.String0x()[2:])`; !strings.Contains(code, want) {
			t.Errorf("test %q: generated binding does not substitute the library address into the local bytecode copy\n%s", test.name, code)
		}
		if local, replace := strings.Index(code, "linkedBin := MainBin"), strings.Index(code, "linkedBin = strings.ReplaceAll("); local < 0 || replace < local {
			t.Errorf("test %q: generated binding substitutes library addresses before taking the local copy\n%s", test.name, code)
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
			"libAddr.String0x()[2:]",
		} {
			if !strings.Contains(code, want) {
				t.Errorf("test %q: generated binding does not contain %q\n%s", test.name, want, code)
			}
		}
		// The linked address must be the bare hex form. common.Address.String() is
		// xdc-prefixed on this fork, so slicing it would inject a 41-character
		// string into the bytecode and corrupt the linked contract.
		if strings.Contains(code, "libAddr.String()[2:]") {
			t.Errorf("test %q: generated binding links the library address via the xdc-prefixed String()\n%s", test.name, code)
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
		lines := strings.Split(code, "\n")
		lineOf := func(needle string) int {
			for i, line := range lines {
				if strings.Contains(line, needle) {
					return i
				}
			}
			return -1
		}
		lastLineOf := func(needle string) int {
			for i := len(lines) - 1; i >= 0; i-- {
				if strings.Contains(lines[i], needle) {
					return i
				}
			}
			return -1
		}
		guardLine := lineOf("if !auth.NoSend {")
		guardEnd := -1
		for i := guardLine + 1; guardLine >= 0 && i < len(lines); i++ {
			// abigen formats the generated code, so the guard's closing brace is
			// the first line holding a lone closing brace at one tab of
			// indentation. Anything nested deeper belongs to the block, and braces
			// inside strings or comments no longer shift the boundary.
			if lines[i] == "\t}" {
				guardEnd = i
				break
			}
		}
		waitLine := lineOf("if err := bind.WaitAccepted(ctx, backend, tx); err != nil {")
		if guardLine < 0 || guardEnd < 0 || waitLine < guardLine || waitLine > guardEnd {
			t.Errorf("test %q: generated binding does not skip the acceptance wait for NoSend transactions\n%s", test.name, code)
		}
		// The wait's error branch is the block opened by the wait's if; abigen
		// formats the generated code, so it ends at the first lone closing brace
		// at two tabs of indentation (one for the function body, one for the
		// NoSend guard). The nonce bump has to follow that whole block.
		waitEnd := -1
		for i := waitLine + 1; waitLine >= 0 && i < len(lines); i++ {
			if lines[i] == "\t\t}" {
				waitEnd = i
				break
			}
		}
		// The wait has to honor the caller's context, so the timeout is derived from
		// auth.Context when it is set and the nil check comes before it.
		waitCtx := strings.Index(code, "waitCtx := context.Background()")
		authCtx := strings.Index(code, "waitCtx = auth.Context")
		timeout := strings.Index(code, "ctx, cancel := context.WithTimeout(waitCtx, 5*time.Second)")
		if waitCtx < 0 || authCtx < waitCtx || timeout < authCtx {
			t.Errorf("test %q: generated binding does not derive the acceptance wait timeout from auth.Context\n%s", test.name, code)
		}
		// Deploying a chain of library dependencies has to advance the nonce
		// itself: the pool updates its pending nonce asynchronously, so asking it
		// for the next one can hand back the library's nonce and fail with
		// "replacement transaction underpriced" (geth #35888). Advancing the nonce
		// must not touch the caller's opts, hence the copy, and it must only
		// happen for transactions that were actually submitted.
		//
		// The copy block has two halves that only work together: opts := *auth
		// snapshots the opts and auth = &opts redirects the deployment to them.
		// Both have to precede the library deployment and the bump, otherwise the
		// bump writes through the caller's opts.
		copyLine := lineOf("opts := *auth")
		redirectLine := lineOf("auth = &opts")
		deployLine := lineOf("libAddr, tx, _, err := DeployLib(auth, backend)")
		bumpLine := lineOf("auth.Nonce = new(big.Int).SetUint64(tx.Nonce() + 1)")
		if copyLine < 0 || redirectLine < 0 || deployLine < 0 || redirectLine < copyLine || copyLine > deployLine || redirectLine > deployLine {
			t.Errorf("test %q: generated binding does not copy the opts and redirect the deployment to them before deploying the library\n%s", test.name, code)
		}
		// The bump has to sit after the acceptance wait's error branch: the library
		// transaction is only known to be in the chain once accepted, and the next
		// deployment must not ask the pool for a stale nonce. All sides are line
		// numbers, and the ordering checks only run on markers that were found: a
		// -1 sentinel must not be read as an order and blame the wrong line.
		switch {
		case bumpLine < 0:
			t.Errorf("test %q: generated binding does not advance the nonce\n%s", test.name, code)
		case bumpLine < waitEnd:
			t.Errorf("test %q: generated binding advances the nonce before the acceptance wait completes\n%s", test.name, code)
		case copyLine > bumpLine || redirectLine > bumpLine:
			t.Errorf("test %q: generated binding copies the opts after advancing the nonce\n%s", test.name, code)
		// A transaction that is not submitted at all cannot move the pool, so the
		// bump belongs inside the NoSend guard rather than after it.
		case guardLine >= 0 && guardEnd >= 0 && (bumpLine < guardLine || bumpLine > guardEnd):
			t.Errorf("test %q: generated binding chains the nonce outside the NoSend guard\n%s", test.name, code)
		}
		// A binding with several libraries has to copy the opts once and advance
		// the nonce after every library transaction, not just the last one. The
		// single-occurrence checks above only pin the first iteration.
		if got := strings.Count(code, "opts := *auth"); got != 1 {
			t.Errorf("test %q: generated binding copies the opts %d times, want 1\n%s", test.name, got, code)
		}
		if got := strings.Count(code, "auth.Nonce = new(big.Int).SetUint64(tx.Nonce() + 1)"); got != test.libCount {
			t.Errorf("test %q: generated binding advances the nonce %d times, want %d\n%s", test.name, got, test.libCount, code)
		}
		// The last bump has to follow the last acceptance wait's error branch too.
		lastWaitLine := lastLineOf("if err := bind.WaitAccepted(ctx, backend, tx); err != nil {")
		lastWaitEnd := -1
		for i := lastWaitLine + 1; lastWaitLine >= 0 && i < len(lines); i++ {
			if lines[i] == "\t\t}" {
				lastWaitEnd = i
				break
			}
		}
		if lastBumpLine := lastLineOf("auth.Nonce = new(big.Int).SetUint64(tx.Nonce() + 1)"); lastBumpLine >= 0 && lastWaitEnd >= 0 && lastBumpLine < lastWaitEnd {
			t.Errorf("test %q: generated binding advances the nonce before the last acceptance wait completes\n%s", test.name, code)
		}
	}
}

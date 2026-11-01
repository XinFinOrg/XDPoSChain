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

package main

import (
	"runtime"
	"strings"
	"testing"
)

// This test checks that --netrestrict is registered and reaches the node
// configuration, and that an unparsable netrestrict list aborts at startup.
func TestNetrestrictFlag(t *testing.T) {
	const invalidCIDR = `Option "netrestrict": invalid CIDR address`

	XDC := runXDC(t, "--netrestrict", "10.0.0.0/8", "dumpconfig")
	XDC.ExpectRegexp(`(?s)\[\[Node\.P2P\.NetRestrict\]\]\r?\nIP = "10\.0\.0\.0"`)
	XDC.WaitExit()
	if have, want := XDC.ExitStatus(), 0; have != want {
		t.Fatalf("exit error, have %d want %d", have, want)
	}

	XDC = runXDC(t, "--netrestrict", "not-a-cidr", "dumpconfig")
	if runtime.GOOS == "windows" {
		// cmd/utils.Fatalf writes to stdout on Windows: the SameFile check it
		// uses to choose a stream does not work there.
		XDC.ExpectRegexp(invalidCIDR)
	}
	XDC.WaitExit()
	if have, want := XDC.ExitStatus(), 1; have != want {
		t.Errorf("bad CIDR: exit error, have %d want %d", have, want)
	}
	if runtime.GOOS != "windows" {
		if stderr := XDC.StderrText(); !strings.Contains(stderr, invalidCIDR) {
			t.Errorf("bad CIDR: missing parse error, stderr:\n%s", stderr)
		}
	}
}

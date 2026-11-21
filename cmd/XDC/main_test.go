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
	"fmt"
	"os"
	"path/filepath"
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

// This test checks that dumpconfig keeps the configured password environment
// variable names and never prints the keystore passwords they resolve to.
func TestDumpConfigDoesNotResolvePasswords(t *testing.T) {
	const (
		envVar   = "DUMPCONFIG_TEST_PASSWORD"
		password = "hunter2-secret"
	)
	t.Setenv(envVar, password)

	path := filepath.Join(t.TempDir(), "config.toml")
	config := fmt.Sprintf("[Account]\nPasswords = [%q]\n", envVar)
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	XDC := runXDC(t, "--config", path, "dumpconfig")
	_, groups := XDC.ExpectRegexp(`(?s)(.*)`)
	XDC.ExpectExit()
	if have, want := XDC.ExitStatus(), 0; have != want {
		t.Fatalf("exit status %d, want %d", have, want)
	}
	out := groups[1]
	if strings.Contains(out, password) {
		t.Errorf("dumpconfig printed the resolved password:\n%s", out)
	}
	if want := fmt.Sprintf(`Passwords = [%q]`, envVar); !strings.Contains(out, want) {
		t.Errorf("dumpconfig does not keep the password environment variable:\n%s", out)
	}
}

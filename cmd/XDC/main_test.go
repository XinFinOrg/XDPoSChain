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
	"slices"
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

// This test checks that the environment variable names in [Account] Passwords
// are resolved on the node startup path: a config-file unlock must work without
// --unlock or --password.
func TestStartupResolvesPasswordEnvs(t *testing.T) {
	const (
		envVar   = "XDC_TEST_UNLOCK_PASSWORD"
		password = "foobar" // password of the f466859e... keystore fixture
	)
	t.Setenv(envVar, password)

	datadir := tmpDatadirWithKeystore(t)
	path := filepath.Join(datadir, "config.toml")
	config := fmt.Sprintf("[Account]\nUnlocks = [\"f466859ead1932d743d622cb74fc058882e8648a\"]\nPasswords = [%q]\n", envVar)
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	XDC := runXDC(t,
		"--nat", "none", "--nodiscover", "--maxpeers", "0", "--port", "0", "--nousb", "--ipcdisable",
		"--datadir", datadir, "--config", path,
		"console", "--exec", "loadScript('testdata/empty.js')")
	// Closing stdin makes a fallback to the interactive password prompt fail
	// instead of blocking until the test times out.
	XDC.CloseStdin()
	XDC.WaitExit()
	if have, want := XDC.ExitStatus(), 0; have != want {
		t.Fatalf("exit status %d, want %d\nstderr:\n%s", have, want, XDC.StderrText())
	}
	if stderr := XDC.StderrText(); !strings.Contains(stderr, "Unlocked account") {
		t.Errorf("account was not unlocked, stderr:\n%s", stderr)
	}
}

// This test checks how the [Account] Passwords environment variable names are
// expanded: comma separated values are split, surrounding whitespace is trimmed
// and entries naming an unset variable are dropped.
func TestResolvePasswordEnvs(t *testing.T) {
	const (
		single = "XDC_TEST_RESOLVE_SINGLE"
		multi  = "XDC_TEST_RESOLVE_MULTI"
	)
	t.Setenv(single, "s3cret")
	t.Setenv(multi, "first, second ,, third")

	tests := []struct {
		name string
		envs []string
		want []string
	}{
		{name: "nil", envs: nil, want: []string{}},
		{name: "empty and whitespace", envs: []string{"", "   "}, want: []string{}},
		{name: "single value", envs: []string{single}, want: []string{"s3cret"}},
		{name: "comma separated and trimmed", envs: []string{multi}, want: []string{"first", "second", "third"}},
		{name: "unset variable is dropped", envs: []string{"XDC_TEST_RESOLVE_UNSET"}, want: []string{}},
		{name: "mixed", envs: []string{single, "XDC_TEST_RESOLVE_UNSET", multi}, want: []string{"s3cret", "first", "second", "third"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if have := resolvePasswordEnvs(tt.envs); !slices.Equal(have, tt.want) {
				t.Errorf("resolvePasswordEnvs(%q) = %q, want %q", tt.envs, have, tt.want)
			}
		})
	}
}

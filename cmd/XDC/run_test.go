// Copyright 2016 The go-ethereum Authors
// This file is part of go-ethereum.
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with go-ethereum. If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/XinFinOrg/XDPoSChain/internal/cmdtest"
	"github.com/XinFinOrg/XDPoSChain/rpc"
	"github.com/docker/docker/pkg/reexec"
)

type testXDC struct {
	*cmdtest.TestCmd

	// template variables for expect
	Datadir   string
	Etherbase string
}

func init() {
	// Run the app if we've been exec'd as "XDC-test" in runGeth.
	reexec.Register("XDC-test", func() {
		if err := app.Run(os.Args); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	})
}

func TestMain(m *testing.M) {
	// check if we have been reexec'd
	if reexec.Init() {
		return
	}
	os.Exit(m.Run())
}

// spawns XDC with the given command line args. If the args don't set --datadir, the
// child g gets a temporary data directory.
func runXDC(t *testing.T, args ...string) *testXDC {
	tt := &testXDC{}
	tt.TestCmd = cmdtest.NewTestCmd(t, tt)
	for i, arg := range args {
		switch arg {
		case "--datadir":
			if i < len(args)-1 {
				tt.Datadir = args[i+1]
			}
		case "--miner-etherbase":
			if i < len(args)-1 {
				tt.Etherbase = args[i+1]
			}
		}
	}
	if tt.Datadir == "" {
		// The temporary datadir will be removed automatically if something fails below.
		tt.Datadir = t.TempDir()
		tt.Cleanup = func() { os.RemoveAll(tt.Datadir) }
		args = append([]string{"--datadir", tt.Datadir}, args...)
	}

	// Boot "XDC". This actually runs the test binary but the TestMain
	// function will prevent any tests from running.
	tt.Run("XDC-test", args...)

	return tt
}

// waitForEndpoint blocks until the given RPC endpoint accepts connections and
// answers rpc_modules, or until the timeout expires. Node startup takes an
// unpredictable amount of time under load, so tests must not rely on a fixed
// sleep before attaching to a freshly started node.
//
// The endpoint is dialled as given by rpc.DialContext, so it must be a bare IPC
// path or a URL carrying a scheme rpc knows (http, https, ws, wss, stdio). The
// legacy "ipc:" and "rpc:" prefixes are not accepted here even though the attach
// command accepts them: resolveConsoleEndpoint strips those prefixes for
// dialRPC, and this helper goes through neither.
//
// A node that cannot start exits before it opens the endpoint, so the helper
// gives up as soon as the process logs a fatal error instead of polling a dead
// endpoint until the timeout runs out.
func waitForEndpoint(t *testing.T, node *testXDC, endpoint string, timeout time.Duration) {
	probeTimeout := 10 * time.Second
	if probeTimeout > timeout {
		probeTimeout = timeout
	}
	probe := func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
		defer cancel()
		c, err := rpc.DialContext(ctx, endpoint)
		if c != nil {
			_, err = c.SupportedModules()
			c.Close()
		}
		return err == nil
	}

	start := time.Now()
	for {
		if probe() {
			return
		}
		if out := node.StderrText(); strings.Contains(out, "Fatal: ") {
			t.Fatalf("endpoint %s was never opened, the node failed to start:\n%s", endpoint, lastLines(out, 20))
		}
		if time.Since(start) > timeout {
			t.Fatalf("endpoint %s did not open within %s", endpoint, timeout)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// waitForPort waits for the node to report the address it listens on and returns
// the port. Tests pass --http-port 0 / --ws-port 0 so the kernel picks a free
// port: guessing one can land on a port another package under test is already
// using (Linux hands out ephemeral ports from 32768-60999, and the race shards
// run four packages at once), and the node then dies with "bind: address
// already in use".
//
// The marker is the log field carrying the address: "endpoint=" for the HTTP
// server and "url=ws://" for the websocket one.
func waitForPort(t *testing.T, node *testXDC, marker string, timeout time.Duration) string {
	start := time.Now()
	for {
		out := node.StderrText()
		if port := scanPort(out, marker); port != "" {
			return port
		}
		if strings.Contains(out, "Fatal: ") {
			t.Fatalf("the node never reported a listening address, it failed to start:\n%s", lastLines(out, 20))
		}
		if time.Since(start) > timeout {
			t.Fatalf("the node did not report a listening address matching %q within %s", marker, timeout)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// scanPort returns the port from the address that follows marker, e.g. from
// "endpoint=127.0.0.1:41234" or "url=ws://[::1]:41234". A marker whose address
// has not been fully written yet is skipped, so the caller can poll.
func scanPort(log, marker string) string {
	for _, chunk := range strings.Split(log, marker)[1:] {
		// The address is complete only once it is followed by whitespace. A
		// chunk that runs to the end of the buffer may be a partial write, and
		// taking a truncated port would point the test at the wrong endpoint.
		i := strings.IndexAny(chunk, " \t\n")
		if i < 0 {
			continue
		}
		addr := chunk[:i]
		if j := strings.LastIndexByte(addr, ':'); j >= 0 {
			if port, err := strconv.Atoi(addr[j+1:]); err == nil && port > 0 && port < 65536 {
				return strconv.Itoa(port)
			}
		}
	}
	return ""
}

// lastLines returns at most n trailing lines of s, keeping failure messages
// readable when the node logged a full startup banner before dying.
func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

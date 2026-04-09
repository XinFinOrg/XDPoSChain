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
	"crypto/rand"
	"math/big"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/XinFinOrg/XDPoSChain/internal/version"
)

const (
	ipcAPIs  = "XDPoS:1.0 admin:1.0 debug:1.0 eth:1.0 miner:1.0 net:1.0 rpc:1.0 txpool:1.0 web3:1.0"
	httpAPIs = "eth:1.0 net:1.0 rpc:1.0 web3:1.0"
)

// Tests that a node embedded within a console can be started up properly and
// then terminated by closing the input stream.
func TestConsoleWelcome(t *testing.T) {
	coinbase := "0x8605cdbbdb6d264aa742e77020dcbc58fcdce182"
	datadir := t.TempDir()

	// Start a XDC console, make sure it's cleaned up and terminate the console
	XDC := runXDC(t,
		"console", "--datadir", datadir, "--XDCx-datadir", datadir+"/XDCx",
		"--port", "0", "--maxpeers", "0", "--nodiscover", "--nat", "none",
		"--miner-etherbase", coinbase)

	// Gather all the infos the welcome message needs to contain
	XDC.SetTemplateFunc("goos", func() string { return runtime.GOOS })
	XDC.SetTemplateFunc("goarch", func() string { return runtime.GOARCH })
	XDC.SetTemplateFunc("gover", runtime.Version)
	XDC.SetTemplateFunc("XDCver", func() string {
		git, _ := version.VCS()
		return version.WithCommit(git.Commit, git.Date)
	})
	XDC.SetTemplateFunc("niltime", func() string {
		return time.Unix(1559211559, 0).Format("Mon Jan 02 2006 15:04:05 GMT-0700 (MST)")
	})
	XDC.SetTemplateFunc("apis", func() string { return ipcAPIs })

	// Verify the actual welcome message to the required template
	XDC.Expect(`
Welcome to the XDC JavaScript console!

instance: XDC/v{{XDCver}}/{{goos}}-{{goarch}}/{{gover}}
coinbase: {{.Etherbase}}
at block: 0 ({{niltime}})
 datadir: {{.Datadir}}
 modules: {{apis}}

To exit, press ctrl-d or type exit
> {{.InputLine "exit"}}
`)
	XDC.ExpectExit()
}

// Tests that a console can be attached to a running node via various means.
func TestIPCAttachWelcome(t *testing.T) {
	// Configure the instance for IPC attachement
	coinbase := "0x8605cdbbdb6d264aa742e77020dcbc58fcdce182"
	datadir := t.TempDir()
	var ipc string
	if runtime.GOOS == "windows" {
		ipc = `\\.\pipe\XDC` + strconv.Itoa(trulyRandInt(100000, 999999))
	} else {
		ipc = filepath.Join(datadir, "XDC.ipc")
	}
	XDC := runXDC(t,
		"--datadir", datadir, "--XDCx-datadir", datadir+"/XDCx",
		"--port", "0", "--maxpeers", "0", "--nodiscover", "--nat", "none",
		"--miner-etherbase", coinbase, "--ipcpath", ipc)

	time.Sleep(2 * time.Second) // Simple way to wait for the RPC endpoint to open
	testAttachWelcome(t, XDC, "ipc:"+ipc, ipcAPIs)

	XDC.Interrupt()
	XDC.ExpectExit()
}

func TestHTTPAttachWelcome(t *testing.T) {
	coinbase := "0x8605cdbbdb6d264aa742e77020dcbc58fcdce182"
	port := strconv.Itoa(trulyRandInt(1024, 65536)) // Yeah, sometimes this will fail, sorry :P
	datadir := t.TempDir()
	XDC := runXDC(t,
		"--datadir", datadir, "--XDCx-datadir", datadir+"/XDCx",
		"--port", "0", "--maxpeers", "0", "--nodiscover", "--nat", "none",
		"--miner-etherbase", coinbase, "--http", "--http-port", port, "--http-api", "eth,net,rpc,web3")

	time.Sleep(2 * time.Second) // Simple way to wait for the RPC endpoint to open
	testAttachWelcome(t, XDC, "http://localhost:"+port, httpAPIs)

	XDC.Interrupt()
	XDC.ExpectExit()
}

func TestWSAttachWelcome(t *testing.T) {
	coinbase := "0x8605cdbbdb6d264aa742e77020dcbc58fcdce182"
	port := strconv.Itoa(trulyRandInt(1024, 65536)) // Yeah, sometimes this will fail, sorry :P
	datadir := t.TempDir()
	XDC := runXDC(t,
		"--datadir", datadir, "--XDCx-datadir", datadir+"/XDCx",
		"--port", "0", "--maxpeers", "0", "--nodiscover", "--nat", "none",
		"--miner-etherbase", coinbase, "--ws", "--ws-port", port, "--ws-api", "eth,net,rpc,web3")

	time.Sleep(2 * time.Second) // Simple way to wait for the RPC endpoint to open
	testAttachWelcome(t, XDC, "ws://localhost:"+port, httpAPIs)

	XDC.Interrupt()
	XDC.ExpectExit()
}

func testAttachWelcome(t *testing.T, XDC *testXDC, endpoint, apis string) {
	// Attach to a running XDC note and terminate immediately
	attach := runXDC(t, "attach", endpoint)
	defer attach.ExpectExit()
	attach.CloseStdin()

	// Gather all the infos the welcome message needs to contain
	attach.SetTemplateFunc("goos", func() string { return runtime.GOOS })
	attach.SetTemplateFunc("goarch", func() string { return runtime.GOARCH })
	attach.SetTemplateFunc("gover", runtime.Version)
	attach.SetTemplateFunc("XDCver", func() string {
		git, _ := version.VCS()
		return version.WithCommit(git.Commit, git.Date)
	})
	attach.SetTemplateFunc("etherbase", func() string { return XDC.Etherbase })
	attach.SetTemplateFunc("niltime", func() string {
		return time.Unix(1559211559, 0).Format("Mon Jan 02 2006 15:04:05 GMT-0700 (MST)")
	})
	attach.SetTemplateFunc("ipc", func() bool { return strings.HasPrefix(endpoint, "ipc") })
	attach.SetTemplateFunc("datadir", func() string { return XDC.Datadir })
	attach.SetTemplateFunc("apis", func() string { return apis })

	// Verify the actual welcome message to the required template
	attach.Expect(`
Welcome to the XDC JavaScript console!

instance: XDC/v{{XDCver}}/{{goos}}-{{goarch}}/{{gover}}
coinbase: {{etherbase}}
at block: 0 ({{niltime}}){{if ipc}}
 datadir: {{datadir}}{{end}}
 modules: {{apis}}

To exit, press ctrl-d or type exit
> {{.InputLine "exit" }}
`)
	attach.ExpectExit()
}

func TestResolveConsoleEndpoint(t *testing.T) {
	tests := []struct {
		name         string
		endpoint     string
		wantEndpoint string
		wantLocal    bool
	}{
		{name: "default ipc endpoint", endpoint: "", wantEndpoint: "", wantLocal: true},
		{name: "plain ipc path", endpoint: "/tmp/XDC.ipc", wantEndpoint: "/tmp/XDC.ipc", wantLocal: true},
		{name: "legacy ipc prefix", endpoint: "ipc:/tmp/XDC.ipc", wantEndpoint: "/tmp/XDC.ipc", wantLocal: true},
		{name: "legacy rpc prefix", endpoint: "rpc:/tmp/XDC.ipc", wantEndpoint: "/tmp/XDC.ipc", wantLocal: true},
		{name: "windows drive path stays unsupported", endpoint: `C:\\Users\\tester\\XDC.ipc`, wantEndpoint: `C:\\Users\\tester\\XDC.ipc`, wantLocal: false},
		{name: "windows drive slash path stays unsupported", endpoint: "C:/Users/tester/XDC.ipc", wantEndpoint: "C:/Users/tester/XDC.ipc", wantLocal: false},
		{name: "legacy rpc windows drive path stays unsupported", endpoint: `rpc:C:\\Users\\tester\\XDC.ipc`, wantEndpoint: `C:\\Users\\tester\\XDC.ipc`, wantLocal: false},
		{name: "legacy rpc http endpoint", endpoint: "rpc:http://localhost:8545", wantEndpoint: "http://localhost:8545", wantLocal: false},
		{name: "legacy rpc ws endpoint", endpoint: "rpc:ws://localhost:8546", wantEndpoint: "ws://localhost:8546", wantLocal: false},
		{name: "stdio endpoint", endpoint: "stdio", wantEndpoint: "stdio", wantLocal: false},
		{name: "legacy rpc stdio endpoint", endpoint: "rpc:stdio", wantEndpoint: "stdio", wantLocal: false},
		{name: "http endpoint", endpoint: "http://localhost:8545", wantEndpoint: "http://localhost:8545", wantLocal: false},
		{name: "ws endpoint", endpoint: "ws://localhost:8546", wantEndpoint: "ws://localhost:8546", wantLocal: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gotEndpoint, gotLocal := resolveConsoleEndpoint(test.endpoint)
			if gotLocal != test.wantLocal {
				t.Fatalf("unexpected local transport classification: got %v want %v", gotLocal, test.wantLocal)
			}
			if test.wantEndpoint == "" {
				if !strings.HasSuffix(gotEndpoint, "XDC.ipc") {
					t.Fatalf("expected default IPC endpoint, got %q", gotEndpoint)
				}
				return
			}
			if gotEndpoint != test.wantEndpoint {
				t.Fatalf("unexpected resolved endpoint: got %q want %q", gotEndpoint, test.wantEndpoint)
			}
		})
	}
}

func TestDialRPCRejectsWindowsDrivePaths(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
	}{
		{name: "windows drive path", endpoint: `C:\\Users\\tester\\XDC.ipc`},
		{name: "windows drive slash path", endpoint: "C:/Users/tester/XDC.ipc"},
		{name: "legacy rpc windows drive path", endpoint: `rpc:C:\\Users\\tester\\XDC.ipc`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, local, err := dialRPC(test.endpoint)
			if client != nil {
				client.Close()
				t.Fatal("expected dialRPC to reject Windows drive-letter path")
			}
			if err == nil {
				t.Fatal("expected dialRPC to fail for Windows drive-letter path")
			}
			if local {
				t.Fatal("expected Windows drive-letter path to stay classified as non-local")
			}
			if !strings.Contains(err.Error(), `no known transport for URL scheme "c"`) {
				t.Fatalf("unexpected dialRPC error: %v", err)
			}
		})
	}
}

// trulyRandInt generates a crypto random integer used by the console tests to
// not clash network ports with other tests running cocurrently.
func trulyRandInt(lo, hi int) int {
	num, _ := rand.Int(rand.Reader, big.NewInt(int64(hi-lo)))
	return int(num.Int64()) + lo
}

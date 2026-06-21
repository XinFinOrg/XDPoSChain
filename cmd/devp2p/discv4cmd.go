// Copyright 2026 XDC Network

package main

import (
	"bufio"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/p2p/discover"
	"github.com/XinFinOrg/XDPoSChain/p2p/enode"
	"github.com/urfave/cli/v2"
)

var (
	discv4Command = &cli.Command{
		Name:  "discv4",
		Usage: "Node Discovery v4 tools (XDC pingXDC variant)",
		Subcommands: []*cli.Command{
			discv4PingCommand,
			discv4CheckCommand,
		},
	}

	discv4PingCommand = &cli.Command{
		Name:      "ping",
		Usage:     "Sends a discv4 ping and waits for pong",
		Action:    discv4Ping,
		ArgsUsage: "<enode>",
		Flags:     discoveryFlags,
	}

	discv4CheckCommand = &cli.Command{
		Name:      "check",
		Usage:     "Ping every enode listed in a file and report UDP reachability",
		Action:    discv4Check,
		ArgsUsage: "<nodes-file>",
		Flags:     append(discoveryFlags, checkParallelFlag, checkOutputFlag),
	}
)

var (
	listenAddrFlag = &cli.StringFlag{
		Name:  "addr",
		Usage: "Local UDP listen address",
		Value: "0.0.0.0:0",
	}
	nodekeyFlag = &cli.StringFlag{
		Name:  "nodekey",
		Usage: "Hex-encoded node private key (generated if unset)",
	}
	timeoutFlag = &cli.DurationFlag{
		Name:  "timeout",
		Usage: "Total time to wait for a pong reply",
		Value: 3 * time.Second,
	}
	checkParallelFlag = &cli.IntFlag{
		Name:  "parallel",
		Usage: "Number of concurrent ping checks",
		Value: 8,
	}
	checkOutputFlag = &cli.StringFlag{
		Name:  "output",
		Usage: "Write results to this file (stdout if unset)",
	}
)

var discoveryFlags = []cli.Flag{
	listenAddrFlag,
	nodekeyFlag,
	timeoutFlag,
}

func discv4Ping(ctx *cli.Context) error {
	n, err := parseNodeArg(ctx)
	if err != nil {
		return err
	}
	tab, cleanup, err := startDiscovery(ctx)
	if err != nil {
		return err
	}
	defer cleanup()

	start := time.Now()
	rtt, err := pingUntil(tab, n, ctx.Duration(timeoutFlag.Name))
	if err != nil {
		return fmt.Errorf("%s did not respond: %v", nodeEndpoint(n), err)
	}
	fmt.Printf("%s responded to ping (RTT %v, elapsed %v)\n", nodeEndpoint(n), rtt, time.Since(start))
	return nil
}

func discv4Check(ctx *cli.Context) error {
	if ctx.NArg() < 1 {
		return errors.New("need nodes file as argument")
	}
	nodes, err := loadNodeFile(ctx.Args().First())
	if err != nil {
		return err
	}
	if len(nodes) == 0 {
		return errors.New("nodes file is empty")
	}

	timeout := ctx.Duration(timeoutFlag.Name)
	parallel := ctx.Int(checkParallelFlag.Name)
	if parallel < 1 {
		return errors.New("parallel must be at least 1")
	}

	type job struct {
		index int
		node  *enode.Node
	}
	type result struct {
		index int
		line  string
	}

	tabs := make([]*discover.Table, parallel)
	cleanups := make([]func(), parallel)
	for i := 0; i < parallel; i++ {
		tab, cleanup, err := startDiscovery(ctx)
		if err != nil {
			for j := 0; j < i; j++ {
				cleanups[j]()
			}
			return err
		}
		tabs[i] = tab
		cleanups[i] = cleanup
	}
	defer func() {
		for _, cleanup := range cleanups {
			cleanup()
		}
	}()

	jobs := make(chan job)
	results := make([]result, len(nodes))
	var wg sync.WaitGroup

	worker := func(tab *discover.Table) {
		defer wg.Done()
		for j := range jobs {
			start := time.Now()
			rtt, pingErr := pingUntil(tab, j.node, timeout)
			elapsed := time.Since(start)
			if pingErr != nil {
				results[j.index] = result{j.index, formatCheckLine(j.index+1, j.node, "UDP_TIMEOUT", elapsed, pingErr)}
				continue
			}
			results[j.index] = result{j.index, formatCheckLine(j.index+1, j.node, "UDP_PONG", rtt, nil)}
		}
	}

	for i := 0; i < parallel; i++ {
		wg.Add(1)
		go worker(tabs[i])
	}
	for i, n := range nodes {
		jobs <- job{index: i, node: n}
	}
	close(jobs)
	wg.Wait()

	var out *os.File = os.Stdout
	if path := ctx.String(checkOutputFlag.Name); path != "" {
		f, err := os.Create(path)
		if err != nil {
			return err
		}
		defer f.Close()
		out = f
	}

	var ok, fail int
	for _, r := range results {
		fmt.Fprintln(out, r.line)
		if strings.Contains(r.line, "UDP_PONG") {
			ok++
		} else {
			fail++
		}
	}
	fmt.Fprintf(os.Stderr, "checked %d nodes: %d ok, %d failed\n", len(nodes), ok, fail)
	if fail > 0 {
		return fmt.Errorf("%d of %d nodes failed UDP ping", fail, len(nodes))
	}
	return nil
}

func startDiscovery(ctx *cli.Context) (*discover.Table, func(), error) {
	key, err := discoveryPrivateKey(ctx)
	if err != nil {
		return nil, nil, err
	}
	conn, err := net.ListenPacket("udp4", ctx.String(listenAddrFlag.Name))
	if err != nil {
		return nil, nil, err
	}
	udpConn := conn.(*net.UDPConn)
	db, err := enode.OpenDB("")
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	ln := enode.NewLocalNode(db, key)
	tab, err := discover.ListenUDP(udpConn, ln, discover.Config{PrivateKey: key})
	if err != nil {
		conn.Close()
		db.Close()
		return nil, nil, err
	}
	cleanup := func() {
		tab.Close()
		conn.Close()
		db.Close()
	}
	return tab, cleanup, nil
}

func discoveryPrivateKey(ctx *cli.Context) (*ecdsa.PrivateKey, error) {
	if ctx.IsSet(nodekeyFlag.Name) {
		return crypto.HexToECDSA(ctx.String(nodekeyFlag.Name))
	}
	return crypto.GenerateKey()
}

func parseNodeArg(ctx *cli.Context) (*enode.Node, error) {
	if ctx.NArg() < 1 {
		return nil, errors.New("missing node as command-line argument")
	}
	return enode.ParseV4(ctx.Args().First())
}

func loadNodeFile(path string) ([]*enode.Node, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var nodes []*enode.Node
	sc := bufio.NewScanner(f)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		n, err := enode.ParseV4(line)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, lineNo, err)
		}
		nodes = append(nodes, n)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return nodes, nil
}

func pingUntil(tab *discover.Table, n *enode.Node, timeout time.Duration) (time.Duration, error) {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		start := time.Now()
		err := tab.Ping(n)
		if err == nil {
			return time.Since(start), nil
		}
		lastErr = err
		if !errors.Is(err, discover.ErrTimeout) {
			return 0, err
		}
	}
	if lastErr == nil {
		lastErr = discover.ErrTimeout
	}
	return timeout, lastErr
}

func nodeEndpoint(n *enode.Node) string {
	if n.Incomplete() {
		return n.ID().String()
	}
	if n.UDP() == n.TCP() {
		return fmt.Sprintf("%s:%d", n.IP(), n.TCP())
	}
	return fmt.Sprintf("%s:%d", n.IP(), n.UDP())
}

func formatCheckLine(index int, n *enode.Node, status string, elapsed time.Duration, err error) string {
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	return fmt.Sprintf("%02d|%s|%s|%s|%s", index, nodeEndpoint(n), status, elapsed.Round(time.Millisecond), msg)
}

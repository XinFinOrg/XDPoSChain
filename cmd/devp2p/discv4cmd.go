// Copyright 2019 The go-ethereum Authors
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
	"bufio"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/rpc"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/XinFinOrg/XDPoSChain/cmd/devp2p/internal/v4test"
	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/log"
	"github.com/XinFinOrg/XDPoSChain/p2p/discover"
	"github.com/XinFinOrg/XDPoSChain/p2p/enode"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/urfave/cli/v2"
)

var (
	discv4Command = &cli.Command{
		Name:  "discv4",
		Usage: "Node Discovery v4 tools",
		Subcommands: []*cli.Command{
			discv4PingCommand,
			discv4CheckCommand,
			discv4RequestRecordCommand,
			discv4ResolveCommand,
			discv4ResolveJSONCommand,
			discv4CrawlCommand,
			discv4TestCommand,
			discv4ListenCommand,
		},
	}
	discv4PingCommand = &cli.Command{
		Name:      "ping",
		Usage:     "Sends ping to a node",
		Action:    discv4Ping,
		ArgsUsage: "<node>",
		Flags:     discoveryNodeFlags,
	}
	discv4CheckCommand = &cli.Command{
		Name:      "check",
		Usage:     "Ping every enode listed in a file and report UDP reachability",
		Action:    discv4Check,
		ArgsUsage: "<nodes-file>",
		Flags:     slices.Concat(discoveryNodeFlags, []cli.Flag{pingTimeoutFlag, crawlParallelismFlag, checkOutputFlag}),
	}
	discv4RequestRecordCommand = &cli.Command{
		Name:      "requestenr",
		Usage:     "Requests a node record using EIP-868 enrRequest",
		Action:    discv4RequestRecord,
		ArgsUsage: "<node>",
		Flags:     discoveryNodeFlags,
	}
	discv4ResolveCommand = &cli.Command{
		Name:      "resolve",
		Usage:     "Finds a node in the DHT",
		Action:    discv4Resolve,
		ArgsUsage: "<node>",
		Flags:     discoveryNodeFlags,
	}
	discv4ResolveJSONCommand = &cli.Command{
		Name:      "resolve-json",
		Usage:     "Re-resolves nodes in a nodes.json file",
		Action:    discv4ResolveJSON,
		Flags:     discoveryNodeFlags,
		ArgsUsage: "<nodes.json file>",
	}
	discv4ListenCommand = &cli.Command{
		Name:   "listen",
		Usage:  "Runs a discovery node",
		Action: discv4Listen,
		Flags: slices.Concat(discoveryNodeFlags, []cli.Flag{
			httpAddrFlag,
		}),
	}
	discv4CrawlCommand = &cli.Command{
		Name:   "crawl",
		Usage:  "Updates a nodes.json file with random nodes found in the DHT",
		Action: discv4Crawl,
		Flags:  slices.Concat(discoveryNodeFlags, []cli.Flag{crawlTimeoutFlag, crawlParallelismFlag}),
	}
	discv4TestCommand = &cli.Command{
		Name:   "test",
		Usage:  "Runs tests against a node",
		Action: discv4Test,
		Flags: []cli.Flag{
			remoteEnodeFlag,
			testPatternFlag,
			testTAPFlag,
			testListen1Flag,
			testListen2Flag,
		},
	}
)

var (
	bootnodesFlag = &cli.StringFlag{
		Name:  "bootnodes",
		Usage: "Comma separated nodes used for bootstrapping",
	}
	nodekeyFlag = &cli.StringFlag{
		Name:  "nodekey",
		Usage: "Hex-encoded node key",
	}
	nodedbFlag = &cli.StringFlag{
		Name:  "nodedb",
		Usage: "Nodes database location",
	}
	listenAddrFlag = &cli.StringFlag{
		Name:  "addr",
		Usage: "Listening address",
	}
	extAddrFlag = &cli.StringFlag{
		Name:  "extaddr",
		Usage: "UDP endpoint announced in ENR. You can provide a bare IP address or IP:port as the value of this flag. Provide a comma-separated pair to announce both an IPv4 and an IPv6 endpoint.",
	}
	crawlTimeoutFlag = &cli.DurationFlag{
		Name:  "timeout",
		Usage: "Time limit for the crawl.",
		Value: 30 * time.Minute,
	}
	crawlParallelismFlag = &cli.IntFlag{
		Name:  "parallel",
		Usage: "How many parallel discoveries to attempt.",
		Value: 16,
	}
	remoteEnodeFlag = &cli.StringFlag{
		Name:    "remote",
		Usage:   "Enode of the remote node under test",
		EnvVars: []string{"REMOTE_ENODE"},
	}
	httpAddrFlag = &cli.StringFlag{
		Name:  "rpc",
		Usage: "HTTP server listening address",
	}
	pingTimeoutFlag = &cli.DurationFlag{
		Name:  "ping-timeout",
		Usage: "Total time to wait for a pong reply",
		Value: 3 * time.Second,
	}
	checkOutputFlag = &cli.StringFlag{
		Name:  "output",
		Usage: "Write results to this file (stdout if unset)",
	}
)

var discoveryNodeFlags = []cli.Flag{
	bootnodesFlag,
	nodekeyFlag,
	nodedbFlag,
	listenAddrFlag,
	extAddrFlag,
}

func discv4Ping(ctx *cli.Context) error {
	n := getNodeArg(ctx)
	disc, _ := startV4(ctx)
	defer disc.Close()

	start := time.Now()
	if err := disc.Ping(n); err != nil {
		return fmt.Errorf("node didn't respond: %v", err)
	}
	fmt.Printf("node responded to ping (RTT %v).\n", time.Since(start))
	return nil
}

func discv4Listen(ctx *cli.Context) error {
	disc, _ := startV4(ctx)
	defer disc.Close()

	fmt.Println(disc.Self())

	httpAddr := ctx.String(httpAddrFlag.Name)
	if httpAddr == "" {
		// Non-HTTP mode.
		select {}
	}

	api := &discv4API{disc}
	log.Info("Starting RPC API server", "addr", httpAddr)
	srv := rpc.NewServer()
	srv.RegisterName("discv4", api)
	http.DefaultServeMux.Handle("/", srv)
	httpsrv := http.Server{Addr: httpAddr, Handler: http.DefaultServeMux}
	return httpsrv.ListenAndServe()
}

func discv4RequestRecord(ctx *cli.Context) error {
	n := getNodeArg(ctx)
	disc, _ := startV4(ctx)
	defer disc.Close()

	respN, err := disc.RequestENR(n)
	if err != nil {
		return fmt.Errorf("can't retrieve record: %v", err)
	}
	fmt.Println(respN.String())
	return nil
}

func discv4Resolve(ctx *cli.Context) error {
	n := getNodeArg(ctx)
	disc, _ := startV4(ctx)
	defer disc.Close()

	resolved := disc.Resolve(n)
	if resolved == nil {
		fmt.Println("unresolved")
		return fmt.Errorf("could not resolve node %s", n.ID())
	}
	fmt.Println(resolved.String())
	return nil
}

func discv4ResolveJSON(ctx *cli.Context) error {
	if ctx.NArg() < 1 {
		return errors.New("need nodes file as argument")
	}
	nodesFile := ctx.Args().Get(0)
	inputSet := make(nodeSet)
	if common.FileExist(nodesFile) {
		inputSet = loadNodesJSON(nodesFile)
	}

	// Add extra nodes from command line arguments.
	var nodeargs []*enode.Node
	for i := 1; i < ctx.NArg(); i++ {
		n, err := parseNode(ctx.Args().Get(i))
		if err != nil {
			exit(err)
		}
		nodeargs = append(nodeargs, n)
	}

	disc, config := startV4(ctx)
	defer disc.Close()

	c, err := newCrawler(inputSet, config.Bootnodes, disc, enode.IterNodes(nodeargs))
	if err != nil {
		return err
	}
	c.revalidateInterval = 0
	output := c.run(0, 1)
	writeNodesJSON(nodesFile, output)
	return nil
}

func discv4Crawl(ctx *cli.Context) error {
	if ctx.NArg() < 1 {
		return errors.New("need nodes file as argument")
	}
	nodesFile := ctx.Args().First()
	inputSet := make(nodeSet)
	if common.FileExist(nodesFile) {
		inputSet = loadNodesJSON(nodesFile)
	}

	disc, config := startV4(ctx)
	defer disc.Close()

	c, err := newCrawler(inputSet, config.Bootnodes, disc, disc.RandomNodes())
	if err != nil {
		return err
	}
	c.revalidateInterval = 10 * time.Minute
	output := c.run(ctx.Duration(crawlTimeoutFlag.Name), ctx.Int(crawlParallelismFlag.Name))
	writeNodesJSON(nodesFile, output)
	return nil
}

// discv4Test runs the protocol test suite.
func discv4Test(ctx *cli.Context) error {
	// Configure test package globals.
	if !ctx.IsSet(remoteEnodeFlag.Name) {
		return fmt.Errorf("missing -%v", remoteEnodeFlag.Name)
	}
	v4test.Remote = ctx.String(remoteEnodeFlag.Name)
	v4test.Listen1 = ctx.String(testListen1Flag.Name)
	v4test.Listen2 = ctx.String(testListen2Flag.Name)
	return runTests(ctx, v4test.AllTests)
}

// startV4 starts an ephemeral discovery V4 node.
func startV4(ctx *cli.Context) (*discover.UDPv4, discover.Config) {
	ln, config := makeDiscoveryConfig(ctx)
	socket := listen(ctx, ln)
	disc, err := discover.ListenV4(socket, ln, config)
	if err != nil {
		exit(err)
	}
	return disc, config
}

func makeDiscoveryConfig(ctx *cli.Context) (*enode.LocalNode, discover.Config) {
	var cfg discover.Config

	if ctx.IsSet(nodekeyFlag.Name) {
		key, err := crypto.HexToECDSA(ctx.String(nodekeyFlag.Name))
		if err != nil {
			exit(fmt.Errorf("-%s: %v", nodekeyFlag.Name, err))
		}
		cfg.PrivateKey = key
	} else {
		var err error
		cfg.PrivateKey, err = crypto.GenerateKey()
		if err != nil {
			exit(err)
		}
	}

	if commandHasFlag(ctx, bootnodesFlag) {
		bn, err := parseBootnodes(ctx)
		if err != nil {
			exit(err)
		}
		cfg.Bootnodes = bn
	}

	dbpath := ctx.String(nodedbFlag.Name)
	db, err := enode.OpenDB(dbpath)
	if err != nil {
		exit(err)
	}
	ln := enode.NewLocalNode(db, cfg.PrivateKey)
	return ln, cfg
}

func parseExtAddr(spec string) (ip net.IP, port int, ok bool) {
	ip = net.ParseIP(spec)
	if ip != nil {
		return ip, 0, true
	}
	host, portstr, err := net.SplitHostPort(spec)
	if err != nil {
		return nil, 0, false
	}
	ip = net.ParseIP(host)
	if ip == nil {
		return nil, 0, false
	}
	port, err = strconv.Atoi(portstr)
	if err != nil {
		return nil, 0, false
	}
	return ip, port, true
}

func listen(ctx *cli.Context, ln *enode.LocalNode) *net.UDPConn {
	addr := ctx.String(listenAddrFlag.Name)
	extAddr := ctx.String(extAddrFlag.Name)
	var (
		socket net.PacketConn
		err    error
	)
	if addr == "" {
		// Dual-stack socket, falling back to IPv4-only where IPv6 is unavailable.
		if socket, err = net.ListenPacket("udp", "[::]:0"); err != nil {
			socket, err = net.ListenPacket("udp", "0.0.0.0:0")
		}
	} else {
		socket, err = net.ListenPacket("udp", addr)
	}
	if err != nil {
		exit(err)
	}

	// Configure the ENR endpoint from the listener address, but only without an
	// explicit -extaddr: otherwise we'd announce a fallback IP for an address
	// family the user didn't specify (e.g. loopback IPv4 on an IPv6-only node).
	usocket := socket.(*net.UDPConn)
	uaddr := socket.LocalAddr().(*net.UDPAddr)
	if extAddr == "" {
		if uaddr.IP.IsUnspecified() {
			ln.SetFallbackIP(net.IP{127, 0, 0, 1})
		} else {
			ln.SetFallbackIP(uaddr.IP)
		}
	}
	ln.SetFallbackUDP(uaddr.Port)

	// Override with explicit -extaddr address(es). A static IP is set per family,
	// and all specs share one UDP port because the node has a single socket.
	if extAddr != "" {
		var extPort int
		for spec := range strings.SplitSeq(extAddr, ",") {
			spec = strings.TrimSpace(spec)
			if spec == "" {
				continue
			}
			ip, port, ok := parseExtAddr(spec)
			if !ok {
				exit(fmt.Errorf("-%s: invalid external address %q", extAddrFlag.Name, spec))
			}
			ln.SetStaticIP(ip)
			if port != 0 {
				if extPort != 0 && port != extPort {
					exit(fmt.Errorf("-%s: all addresses must announce the same UDP port, got %d and %d", extAddrFlag.Name, extPort, port))
				}
				extPort = port
			}
		}
		if extPort != 0 {
			ln.SetFallbackUDP(extPort)
		}
	}

	return usocket
}

func parseBootnodes(ctx *cli.Context) ([]*enode.Node, error) {
	s := params.MainnetBootnodes
	if ctx.IsSet(bootnodesFlag.Name) {
		input := ctx.String(bootnodesFlag.Name)
		if input == "" {
			return nil, nil
		}
		s = strings.Split(input, ",")
	}
	nodes := make([]*enode.Node, len(s))
	var err error
	for i, record := range s {
		nodes[i], err = parseNode(record)
		if err != nil {
			return nil, fmt.Errorf("invalid bootstrap node: %v", err)
		}
	}
	return nodes, nil
}

type discv4API struct {
	host *discover.UDPv4
}

func (api *discv4API) LookupRandom(n int) (ns []*enode.Node) {
	it := api.host.RandomNodes()
	defer it.Close()
	for len(ns) < n && it.Next() {
		ns = append(ns, it.Node())
	}
	return ns
}

func (api *discv4API) Self() *enode.Node {
	return api.host.Self()
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

	timeout := ctx.Duration(pingTimeoutFlag.Name)
	if timeout <= 0 {
		return errors.New("ping-timeout must be greater than 0")
	}
	parallel := ctx.Int(crawlParallelismFlag.Name)
	if parallel < 1 {
		return errors.New("parallel must be at least 1")
	}
	if parallel > len(nodes) {
		parallel = len(nodes)
	}
	if parallel > 1 {
		if dbpath := ctx.String(nodedbFlag.Name); dbpath != "" {
			return errors.New("parallel > 1 cannot be used with --nodedb (shared DB path)")
		}
		addrStr := ctx.String(listenAddrFlag.Name)
		if addrStr == "" {
			addrStr = "0.0.0.0:0"
		}
		addr, err := net.ResolveUDPAddr("udp4", addrStr)
		if err != nil {
			return err
		}
		if addr.Port != 0 {
			return errors.New("parallel > 1 requires --addr to use port 0 (or leave --addr unset)")
		}
	}

	type job struct {
		index int
		node  *enode.Node
	}
	type result struct {
		index int
		line  string
		ok    bool
	}

	discs := make([]*discover.UDPv4, parallel)
	for i := 0; i < parallel; i++ {
		discs[i], _ = startV4(ctx)
	}
	defer func() {
		for _, disc := range discs {
			disc.Close()
		}
	}()

	jobs := make(chan job)
	results := make([]result, len(nodes))
	var wg sync.WaitGroup

	worker := func(disc *discover.UDPv4) {
		defer wg.Done()
		for j := range jobs {
			start := time.Now()
			rtt, pingErr := pingUntil(disc, j.node, timeout)
			elapsed := time.Since(start)
			if pingErr != nil {
				status := "UDP_TIMEOUT"
				if !errors.Is(pingErr, discover.ErrTimeout) {
					status = "UDP_ERROR"
				}
				results[j.index] = result{j.index, formatCheckLine(j.index+1, j.node, status, elapsed, pingErr), false}
				continue
			}
			results[j.index] = result{j.index, formatCheckLine(j.index+1, j.node, "UDP_PONG", rtt, nil), true}
		}
	}

	for i := 0; i < parallel; i++ {
		wg.Add(1)
		go worker(discs[i])
	}
	for i, n := range nodes {
		jobs <- job{index: i, node: n}
	}
	close(jobs)
	wg.Wait()

	out := os.Stdout
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
		if _, err := fmt.Fprintln(out, r.line); err != nil {
			return err
		}
		if r.ok {
			ok++
		} else {
			fail++
		}
	}
	if _, err := fmt.Fprintf(os.Stderr, "checked %d nodes: %d ok, %d failed\n", len(nodes), ok, fail); err != nil {
		return err
	}
	if fail > 0 {
		return fmt.Errorf("%d of %d nodes failed UDP ping", fail, len(nodes))
	}
	return nil
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

func pingUntil(disc *discover.UDPv4, n *enode.Node, timeout time.Duration) (time.Duration, error) {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		start := time.Now()
		err := disc.Ping(n)
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
	if !n.IPAddr().IsValid() {
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

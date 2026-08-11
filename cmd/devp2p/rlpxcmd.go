// Copyright 2020 The go-ethereum Authors
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
	"bytes"
	"errors"
	"fmt"
	"net"

	"github.com/XinFinOrg/XDPoSChain/cmd/devp2p/internal/ethtest"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/p2p"
	"github.com/XinFinOrg/XDPoSChain/p2p/enode"
	"github.com/XinFinOrg/XDPoSChain/p2p/rlpx"
	"github.com/XinFinOrg/XDPoSChain/rlp"
	"github.com/urfave/cli/v2"
)

var (
	rlpxCommand = &cli.Command{
		Name:  "rlpx",
		Usage: "RLPx Commands",
		Subcommands: []*cli.Command{
			rlpxPingCommand,
			rlpxEthTestCommand,
		},
	}
	rlpxPingCommand = &cli.Command{
		Name:   "ping",
		Usage:  "Perform a RLPx handshake",
		Action: rlpxPing,
	}
	rlpxEthTestCommand = &cli.Command{
		Name:   "eth-test",
		Usage:  "Runs a minimal RLPx/devp2p compatibility test subset against a node",
		Action: rlpxEthTest,
		Flags: []cli.Flag{
			testPatternFlag,
			testTAPFlag,
			testChainDirFlag,
			testNodeFlag,
			testNodeJWTFlag,
			testNodeEngineFlag,
		},
	}
)

func rlpxPing(ctx *cli.Context) error {
	n := getNodeArg(ctx)
	tcpEndpoint, ok := n.TCPEndpoint()
	if !ok {
		return errors.New("node has no TCP endpoint")
	}
	fd, err := net.Dial("tcp", tcpEndpoint.String())
	if err != nil {
		return err
	}
	defer fd.Close()

	conn := rlpx.NewConn(fd, n.Pubkey())
	ourKey, err := crypto.GenerateKey()
	if err != nil {
		return err
	}
	_, err = conn.Handshake(ourKey)
	if err != nil {
		return err
	}
	code, data, _, err := conn.Read()
	if err != nil {
		return err
	}
	switch code {
	case 0:
		var h ethtest.Hello
		if err := rlp.DecodeBytes(data, &h); err != nil {
			return fmt.Errorf("invalid handshake: %v", err)
		}
		fmt.Printf("%+v\n", h)
	case 1:
		// The disconnect message is specified as a list containing the reason,
		// but some implementations (including older geth) send the reason as a
		// single byte. Handle both forms, and on failure include the raw payload
		// so the operator can see what was actually sent.
		reason, decErr := decodeRLPxDisconnect(data)
		if decErr != nil {
			return fmt.Errorf("invalid disconnect message: %v (raw=0x%x)", decErr, data)
		}
		return fmt.Errorf("received disconnect message: %v", reason)
	default:
		return fmt.Errorf("invalid message code %d, expected handshake (code zero) or disconnect (code one)", code)
	}
	return nil
}

// rlpxEthTest runs the local compatibility subset for RLPx/devp2p behavior.
func rlpxEthTest(ctx *cli.Context) error {
	p := cliTestParams(ctx)
	suite, err := ethtest.NewSuite(p.node, p.chainDir, p.engineAPI, p.jwt)
	if err != nil {
		exit(err)
	}
	return runTests(ctx, suite.EthTests())
}

// decodeRLPxDisconnect parses a disconnect message payload. Per the RLPx spec
// the payload is a list containing a single reason, but some implementations
// (including older geth) sent the reason as a bare byte. Accept both forms.
func decodeRLPxDisconnect(data []byte) (p2p.DiscReason, error) {
	s := rlp.NewStream(bytes.NewReader(data), uint64(len(data)))
	k, _, err := s.Kind()
	if err != nil {
		return 0, err
	}
	var reason p2p.DiscReason
	if k == rlp.List {
		if _, err := s.List(); err != nil {
			return 0, err
		}
		if err := s.Decode(&reason); err != nil {
			return 0, err
		}
		return reason, nil
	}
	if err := s.Decode(&reason); err != nil {
		return 0, err
	}
	return reason, nil
}

type testParams struct {
	node      *enode.Node
	engineAPI string
	jwt       string
	chainDir  string
}

func cliTestParams(ctx *cli.Context) *testParams {
	nodeStr := ctx.String(testNodeFlag.Name)
	node, err := parseNode(nodeStr)
	if err != nil {
		exit(err)
	}
	p := testParams{
		node:      node,
		engineAPI: ctx.String(testNodeEngineFlag.Name),
		jwt:       ctx.String(testNodeJWTFlag.Name),
		chainDir:  ctx.String(testChainDirFlag.Name),
	}
	return &p
}

// Copyright 2026 XDC Network

package main

import (
	"fmt"
	"os"

	"github.com/urfave/cli/v2"
)

var app = &cli.App{
	Name:  "devp2p",
	Usage: "XDC devp2p tools",
	Commands: []*cli.Command{
		discv4Command,
	},
}

func main() {
	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// Copyright 2014 The go-ethereum Authors
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

// evm executes EVM code snippets.
package main

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"

	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/tracing"
	"github.com/XinFinOrg/XDPoSChain/eth/tracers/logger"
	"github.com/XinFinOrg/XDPoSChain/internal/debug"
	"github.com/XinFinOrg/XDPoSChain/internal/flags"
	"github.com/urfave/cli/v2"
)

// Some other nice-to-haves:
// * accumulate traces into an object to bundle with test
// * write tx identifier for trace before hand (blocktest only)
// * combine blocktest and statetest runner logic using unified test interface

const traceCategory = "TRACING"

var (
	// Test running flags.
	RunFlag = &cli.StringFlag{
		Name:     "run",
		Value:    ".*",
		Usage:    "Run only those tests matching the regular expression.",
		Category: flags.VMCategory,
	}
	BenchFlag = &cli.BoolFlag{
		Name:     "bench",
		Usage:    "benchmark the execution",
		Category: flags.VMCategory,
	}

	// Debugging flags.
	DumpFlag = &cli.BoolFlag{
		Name:     "dump",
		Usage:    "dumps the state after the run",
		Category: flags.VMCategory,
	}
	HumanReadableFlag = &cli.BoolFlag{
		Name:  "human",
		Usage: "\"Human-readable\" output",
	}
	StatDumpFlag = &cli.BoolFlag{
		Name:     "statdump",
		Usage:    "displays stack and heap memory information",
		Category: flags.VMCategory,
	}

	// Tracing flags.
	TraceFlag = &cli.BoolFlag{
		Name:     "trace",
		Usage:    "Enable tracing and output trace log.",
		Category: traceCategory,
	}
	TraceFormatFlag = &cli.StringFlag{
		Name:     "trace.format",
		Usage:    "Trace output format to use (json|struct|md)",
		Value:    "json",
		Category: traceCategory,
	}
	TraceDisableMemoryFlag = &cli.BoolFlag{
		Name:     "trace.nomemory",
		Aliases:  []string{"nomemory"},
		Value:    true,
		Usage:    "disable memory output",
		Category: traceCategory,
	}
	TraceDisableStackFlag = &cli.BoolFlag{
		Name:     "trace.nostack",
		Aliases:  []string{"nostack"},
		Usage:    "disable stack output",
		Category: traceCategory,
	}
	TraceDisableStorageFlag = &cli.BoolFlag{
		Name:     "trace.nostorage",
		Aliases:  []string{"nostorage"},
		Usage:    "disable storage output",
		Category: traceCategory,
	}
	TraceDisableReturnDataFlag = &cli.BoolFlag{
		Name:     "trace.noreturndata",
		Aliases:  []string{"noreturndata"},
		Value:    true,
		Usage:    "disable return data output",
		Category: traceCategory,
	}

	// Deprecated flags.
	DebugFlag = &cli.BoolFlag{
		Name:     "debug",
		Usage:    "output full trace logs (deprecated)",
		Hidden:   true,
		Category: traceCategory,
	}
	MachineFlag = &cli.BoolFlag{
		Name:     "json",
		Usage:    "output trace logs in machine readable format, json (deprecated)",
		Hidden:   true,
		Category: traceCategory,
	}
)

// traceFlags contains flags that configure tracing output.
var traceFlags = []cli.Flag{
	TraceFlag,
	TraceFormatFlag,
	TraceDisableStackFlag,
	TraceDisableMemoryFlag,
	TraceDisableStorageFlag,
	TraceDisableReturnDataFlag,

	// deprecated
	DebugFlag,
	MachineFlag,
}

var app = flags.NewApp("the evm command line interface")

func init() {
	app.Flags = debug.Flags
	app.Commands = []*cli.Command{
		runCommand,
		stateTestCommand,
	}
	app.Before = func(ctx *cli.Context) error {
		flags.MigrateGlobalFlags(ctx)
		return debug.Setup(ctx)
	}
	app.After = func(ctx *cli.Context) error {
		debug.Exit()
		return nil
	}
}

func main() {
	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// tracerFromFlags parses the cli flags and returns the specified tracer, or an error for unknown formats.
func tracerFromFlags(ctx *cli.Context) (*tracing.Hooks, error) {
	config := &logger.Config{
		EnableMemory:     !ctx.Bool(TraceDisableMemoryFlag.Name),
		DisableStack:     ctx.Bool(TraceDisableStackFlag.Name),
		DisableStorage:   ctx.Bool(TraceDisableStorageFlag.Name),
		EnableReturnData: !ctx.Bool(TraceDisableReturnDataFlag.Name),
	}
	switch {
	case ctx.Bool(TraceFlag.Name):
		switch format := ctx.String(TraceFormatFlag.Name); format {
		case "struct":
			return logger.NewStreamingStructLogger(config, os.Stderr).Hooks(), nil
		case "json":
			return logger.NewJSONLogger(config, os.Stderr), nil
		case "md", "markdown":
			return logger.NewMarkdownLogger(config, os.Stderr).Hooks(), nil
		default:
			return nil, cli.Exit(fmt.Sprintf("unknown trace format: %q", format), 1)
		}
	// Deprecated ways of configuring tracing.
	case ctx.Bool(MachineFlag.Name):
		return logger.NewJSONLogger(config, os.Stderr), nil
	case ctx.Bool(DebugFlag.Name):
		return logger.NewStreamingStructLogger(config, os.Stderr).Hooks(), nil
	default:
		return nil, nil
	}
}

// collectFiles walks the given path. If the path is a directory, it returns
// a list of all .json files found recursively under the directory.
// Otherwise, if path points to a file, it returns that path.
func collectFiles(path string) ([]string, error) {
	var out []string
	if info, err := os.Stat(path); err == nil && !info.IsDir() {
		// User explicitly pointed out a file, ignore extension.
		return []string{path}, nil
	}
	err := filepath.Walk(path, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && filepath.Ext(info.Name()) == ".json" {
			out = append(out, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to collect files from %q: %v", path, err)
	}
	if len(out) > 1 {
		slices.Sort(out)
	}
	return out, nil
}

// dump returns a state dump for the most current trie.
func dump(s *state.StateDB) *state.Dump {
	root := s.IntermediateRoot(false)
	cpy, err := state.New(root, s.Database())
	if err != nil {
		return nil
	}
	dump := cpy.RawDump(nil)
	return &dump
}

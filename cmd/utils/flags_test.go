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

// Package utils contains internal helper functions for go-ethereum commands.
package utils

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/node"
	"github.com/XinFinOrg/XDPoSChain/p2p"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/urfave/cli/v2"
)

// Test_SplitTagsFlag tests split tags flag.
func Test_SplitTagsFlag(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		args string
		want map[string]string
	}{
		{
			"2 tags case",
			"host=localhost,bzzkey=123",
			map[string]string{
				"host":   "localhost",
				"bzzkey": "123",
			},
		},
		{
			"1 tag case",
			"host=localhost123",
			map[string]string{
				"host": "localhost123",
			},
		},
		{
			"empty case",
			"",
			map[string]string{},
		},
		{
			"garbage",
			"smth=smthelse=123",
			map[string]string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := SplitTagsFlag(tt.args); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("splitTagsFlag() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestWalkMatch tests walk match.
func TestWalkMatch(t *testing.T) {
	type args struct {
		root    string
		pattern string
	}
	test1Dir := t.TempDir()
	test2Dir := t.TempDir()

	err := os.WriteFile(filepath.Join(test1Dir, "test1.ldb"), []byte("hello"), os.ModePerm)
	if err != nil {
		log.Fatal(err)
	}
	err = os.WriteFile(filepath.Join(test2Dir, "test2.abc"), []byte("hello"), os.ModePerm)
	if err != nil {
		log.Fatal(err)
	}

	tests := []struct {
		name    string
		args    args
		want    []string
		wantErr bool
	}{
		{
			"match test",
			args{
				root:    test1Dir,
				pattern: "*ldb",
			},
			[]string{filepath.Join(test1Dir, "test1.ldb")},
			false,
		},
		{
			"mismatch test",
			args{
				root:    test2Dir,
				pattern: "*ldb",
			},
			[]string{},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := WalkMatch(tt.args.root, tt.args.pattern)
			if (err != nil) != tt.wantErr {
				t.Errorf("WalkMatch() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("WalkMatch() got = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestMakeChainWriteModePassesCompatRewindToCore tests make chain write mode passes compat rewind to core.
func TestMakeChainWriteModePassesCompatRewindToCore(t *testing.T) {
	stack, err := node.New(&node.Config{Name: "makechain-test", DataDir: t.TempDir()})
	if err != nil {
		t.Fatalf("failed to create node: %v", err)
	}
	defer stack.Close()

	chainDb, err := stack.OpenDatabase("chaindata", 0, 0, "", false)
	if err != nil {
		t.Fatalf("failed to open chain database: %v", err)
	}

	genesis := core.DefaultTestnetGenesisBlock()
	genesisBlock := genesis.MustCommit(chainDb)
	storedCfg := params.TestnetChainConfig.Clone()
	storedCfg.BerlinBlock = big.NewInt(100)
	rawdb.WriteChainConfig(chainDb, genesisBlock.Hash(), storedCfg)

	head := types.NewBlockWithHeader(&types.Header{
		Number:     big.NewInt(101),
		ParentHash: genesisBlock.Hash(),
		Root:       genesisBlock.Root(),
		Time:       genesisBlock.Time() + 2,
		Difficulty: big.NewInt(1),
	})
	rawdb.WriteBlock(chainDb, head)
	rawdb.WriteCanonicalHash(chainDb, genesisBlock.Hash(), 0)
	rawdb.WriteCanonicalHash(chainDb, head.Hash(), head.NumberU64())
	rawdb.WriteHeadHeaderHash(chainDb, head.Hash())
	rawdb.WriteHeadBlockHash(chainDb, head.Hash())
	rawdb.WriteHeadFastBlockHash(chainDb, head.Hash())
	rawdb.WriteTd(chainDb, head.Hash(), head.NumberU64(), new(big.Int).Add(genesisBlock.Difficulty(), head.Difficulty()))

	resolvedCfg, _, compatErr, err := core.SetupGenesisBlock(chainDb, genesis)
	if err != nil {
		chainDb.Close()
		t.Fatalf("failed to prepare compat fixture: %v", err)
	}
	if compatErr == nil {
		chainDb.Close()
		t.Fatal("expected compatibility error")
	}
	if compatErr.RewindTo != 99 {
		chainDb.Close()
		t.Fatalf("unexpected rewind target: have %d want 99", compatErr.RewindTo)
	}
	if resolvedCfg == nil || resolvedCfg.BerlinBlock == nil || resolvedCfg.BerlinBlock.Cmp(params.TestnetChainConfig.BerlinBlock) != 0 {
		chainDb.Close()
		t.Fatalf("unexpected resolved config: have %v want %v", resolvedCfg, params.TestnetChainConfig)
	}
	if err := chainDb.Close(); err != nil {
		t.Fatalf("failed to close prepared chain database: %v", err)
	}

	ctx := newMakeChainTestCLIContext(t, map[string]string{
		TestnetFlag.Name:                   "true",
		GCModeFlag.Name:                    "full",
		ChainConfigMismatchPolicyFlag.Name: core.MismatchRewindAndUpdate.String(),
	})
	chain, reopenedDb := MakeChain(ctx, stack, false, "")
	defer chain.Stop()
	defer reopenedDb.Close()

	if got := chain.CurrentBlock().Number.Uint64(); got != 0 {
		t.Fatalf("unexpected head after MakeChain rewind: have %d want 0", got)
	}
	if got := chain.Config().BerlinBlock; got == nil || got.Cmp(params.TestnetChainConfig.BerlinBlock) != 0 {
		t.Fatalf("unexpected chain config after MakeChain: have %v want %v", got, params.TestnetChainConfig.BerlinBlock)
	}
	persistedCfg, err := rawdb.ReadChainConfig(reopenedDb, genesisBlock.Hash())
	if err != nil {
		t.Fatalf("failed to read persisted config: %v", err)
	}
	if persistedCfg.BerlinBlock == nil || persistedCfg.BerlinBlock.Cmp(params.TestnetChainConfig.BerlinBlock) != 0 {
		t.Fatalf("unexpected persisted berlin block: have %v want %v", persistedCfg.BerlinBlock, params.TestnetChainConfig.BerlinBlock)
	}
}

// TestMakeChainReadOnlyModeSurfacesCompatRewind tests make chain read only mode surfaces compat rewind.
func TestMakeChainReadOnlyModeSurfacesCompatRewind(t *testing.T) {
	stack, err := node.New(&node.Config{Name: "makechain-readonly-test", DataDir: t.TempDir()})
	if err != nil {
		t.Fatalf("failed to create node: %v", err)
	}
	defer stack.Close()

	chainDb, err := stack.OpenDatabase("chaindata", 0, 0, "", false)
	if err != nil {
		t.Fatalf("failed to open chain database: %v", err)
	}

	genesis := core.DefaultTestnetGenesisBlock()
	genesisBlock := genesis.MustCommit(chainDb)
	storedCfg := params.TestnetChainConfig.Clone()
	storedCfg.BerlinBlock = big.NewInt(100)
	rawdb.WriteChainConfig(chainDb, genesisBlock.Hash(), storedCfg)

	head := types.NewBlockWithHeader(&types.Header{
		Number:     big.NewInt(101),
		ParentHash: genesisBlock.Hash(),
		Root:       genesisBlock.Root(),
		Time:       genesisBlock.Time() + 2,
		Difficulty: big.NewInt(1),
	})
	rawdb.WriteBlock(chainDb, head)
	rawdb.WriteCanonicalHash(chainDb, genesisBlock.Hash(), 0)
	rawdb.WriteCanonicalHash(chainDb, head.Hash(), head.NumberU64())
	rawdb.WriteHeadHeaderHash(chainDb, head.Hash())
	rawdb.WriteHeadBlockHash(chainDb, head.Hash())
	rawdb.WriteHeadFastBlockHash(chainDb, head.Hash())
	rawdb.WriteTd(chainDb, head.Hash(), head.NumberU64(), new(big.Int).Add(genesisBlock.Difficulty(), head.Difficulty()))

	if err := chainDb.Close(); err != nil {
		t.Fatalf("failed to close prepared chain database: %v", err)
	}

	readonlyDb, err := stack.OpenDatabase("chaindata", 0, 0, "", true)
	if err != nil {
		t.Fatalf("failed to reopen chain database readonly: %v", err)
	}
	defer readonlyDb.Close()

	config, ghash, compatErr, err := core.LoadChainConfigWithCompat(readonlyDb, genesis)
	if err != nil {
		t.Fatalf("LoadChainConfigWithCompat failed: %v", err)
	}
	if compatErr == nil {
		t.Fatal("expected compatibility error")
	}

	chain, err := core.NewBlockChainReadOnlyResolved(readonlyDb, nil, genesis, ethash.NewFaker(), vm.Config{}, config, ghash, compatErr, core.MismatchRewindAndUpdate)
	if chain != nil {
		chain.Stop()
		t.Fatal("expected readonly blockchain open to fail")
	}
	if !errors.Is(err, core.ErrReadOnlyConfigRewind) {
		t.Fatalf("unexpected error: have %v want %v", err, core.ErrReadOnlyConfigRewind)
	}
}

func TestMakeChainReadOnlyModeFormatsCompatRewindForOperators(t *testing.T) {
	stack, err := node.New(&node.Config{Name: "makechain-readonly-fatal-test", DataDir: t.TempDir()})
	if err != nil {
		t.Fatalf("failed to create node: %v", err)
	}
	defer stack.Close()

	chainDb, err := stack.OpenDatabase("chaindata", 0, 0, "", false)
	if err != nil {
		t.Fatalf("failed to open chain database: %v", err)
	}

	genesis := core.DefaultTestnetGenesisBlock()
	genesisBlock := genesis.MustCommit(chainDb)
	storedCfg := params.TestnetChainConfig.Clone()
	storedCfg.BerlinBlock = big.NewInt(100)
	rawdb.WriteChainConfig(chainDb, genesisBlock.Hash(), storedCfg)

	head := types.NewBlockWithHeader(&types.Header{
		Number:     big.NewInt(101),
		ParentHash: genesisBlock.Hash(),
		Root:       genesisBlock.Root(),
		Time:       genesisBlock.Time() + 2,
		Difficulty: big.NewInt(1),
	})
	rawdb.WriteBlock(chainDb, head)
	rawdb.WriteCanonicalHash(chainDb, genesisBlock.Hash(), 0)
	rawdb.WriteCanonicalHash(chainDb, head.Hash(), head.NumberU64())
	rawdb.WriteHeadHeaderHash(chainDb, head.Hash())
	rawdb.WriteHeadBlockHash(chainDb, head.Hash())
	rawdb.WriteHeadFastBlockHash(chainDb, head.Hash())
	rawdb.WriteTd(chainDb, head.Hash(), head.NumberU64(), new(big.Int).Add(genesisBlock.Difficulty(), head.Difficulty()))

	if err := chainDb.Close(); err != nil {
		t.Fatalf("failed to close prepared chain database: %v", err)
	}

	ctx := newMakeChainTestCLIContext(t, map[string]string{
		TestnetFlag.Name:                   "true",
		GCModeFlag.Name:                    "full",
		ChainConfigMismatchPolicyFlag.Name: core.MismatchRewindAndUpdate.String(),
	})

	const sentinel = "fatal called"
	var got string
	originalFatalf := makeChainFatalf
	makeChainFatalf = func(format string, args ...interface{}) {
		got = fmt.Sprintf(format, args...)
		panic(sentinel)
	}
	defer func() { makeChainFatalf = originalFatalf }()

	defer func() {
		if recovered := recover(); recovered != sentinel {
			t.Fatalf("expected sentinel panic, have %v", recovered)
		}
		want := "Can't open blockchain in readonly mode: the selected chain-config mismatch policy requires rewind. Reopen in writable mode, or use --chain-config-mismatch-policy=ignore-mismatch to avoid rewind in readonly mode."
		if got != want {
			t.Fatalf("unexpected fatal message: have %q want %q", got, want)
		}
	}()

	MakeChain(ctx, stack, true, "")
	t.Fatal("expected MakeChain to terminate via fatal hook")
}

// TestFormatBlockChainOpenErrorReadOnly tests format block chain open error read only.
func TestFormatBlockChainOpenErrorReadOnly(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "genesis recovery",
			err:  core.ErrReadOnlyGenesisStateRecovery,
			want: "Can't open blockchain in readonly mode: genesis state is missing and requires recovery. Reopen the database in writable mode to recover the missing genesis state, then retry.",
		},
		{
			name: "head repair",
			err:  core.ErrReadOnlyHeadStateRepair,
			want: "Can't open blockchain in readonly mode: head state is missing and requires repair. Reopen the database in writable mode to repair the missing head state, then retry.",
		},
		{
			name: "bad hash rewind",
			err:  core.ErrReadOnlyBadHashRewind,
			want: "Can't open blockchain in readonly mode: the local chain contains a denylisted hash and requires rewind. Reopen the database in writable mode so the chain can rewind past the denylisted hash, then retry.",
		},
		{
			name: "config rewind",
			err:  core.ErrReadOnlyConfigRewind,
			want: "Can't open blockchain in readonly mode: the selected chain-config mismatch policy requires rewind. Reopen in writable mode, or use --chain-config-mismatch-policy=ignore-mismatch to avoid rewind in readonly mode.",
		},
		{
			name: "config update",
			err:  core.ErrReadOnlyConfigUpdate,
			want: "Can't open blockchain in readonly mode: the selected chain-config mismatch policy requires writing chain config. Reopen in writable mode, or use --chain-config-mismatch-policy=ignore-mismatch in readonly mode.",
		},
		{
			name: "config exit",
			err:  core.ErrConfigMismatchPolicyExit,
			want: "Can't open blockchain: " + ChainConfigMismatchPolicyExitHint,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := formatBlockChainOpenError(tt.err, true); got != tt.want {
				t.Fatalf("unexpected readonly error message: have %q want %q", got, tt.want)
			}
		})
	}

	if got := formatBlockChainOpenError(core.ErrReadOnlyGenesisStateRecovery, false); got != "Can't create BlockChain: readonly blockchain open requires genesis state recovery" {
		t.Fatalf("unexpected writable fallback message: %q", got)
	}

	wrappedUnavailable := fmt.Errorf("live blockchain tracer requires genesis alloc to be set: %w", core.ErrGenesisAllocUnavailable)
	if got := formatBlockChainOpenError(wrappedUnavailable, false); got != "Can't create BlockChain: "+core.GenesisAllocUnavailableRecoveryMessage {
		t.Fatalf("unexpected genesis alloc unavailable message: %q", got)
	}
}

func TestResolveChainConfigMismatchPolicyHonorsConfiguredWhenFlagNotSet(t *testing.T) {
	t.Parallel()

	set := flag.NewFlagSet("resolve-policy-test", flag.ContinueOnError)
	set.String(ChainConfigMismatchPolicyFlag.Name, core.DefaultChainConfigMismatchPolicy.String(), "")
	ctx := cli.NewContext(cli.NewApp(), set, nil)

	got, err := resolveChainConfigMismatchPolicy(ctx, core.MismatchIgnoreMismatch.String())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != core.MismatchIgnoreMismatch.String() {
		t.Fatalf("unexpected policy: have %q want %q", got, core.MismatchIgnoreMismatch.String())
	}
}

func TestResolveChainConfigMismatchPolicyFlagOverridesConfigured(t *testing.T) {
	t.Parallel()

	set := flag.NewFlagSet("resolve-policy-override-test", flag.ContinueOnError)
	set.String(ChainConfigMismatchPolicyFlag.Name, core.DefaultChainConfigMismatchPolicy.String(), "")
	if err := set.Set(ChainConfigMismatchPolicyFlag.Name, core.MismatchUpdateConfigOnly.String()); err != nil {
		t.Fatalf("failed to set policy flag: %v", err)
	}
	ctx := cli.NewContext(cli.NewApp(), set, nil)

	got, err := resolveChainConfigMismatchPolicy(ctx, core.MismatchIgnoreMismatch.String())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != core.MismatchUpdateConfigOnly.String() {
		t.Fatalf("unexpected policy: have %q want %q", got, core.MismatchUpdateConfigOnly.String())
	}
}

func TestResolveChainConfigMismatchPolicyRejectsInvalidConfiguredValue(t *testing.T) {
	t.Parallel()

	set := flag.NewFlagSet("resolve-policy-invalid-test", flag.ContinueOnError)
	set.String(ChainConfigMismatchPolicyFlag.Name, core.DefaultChainConfigMismatchPolicy.String(), "")
	ctx := cli.NewContext(cli.NewApp(), set, nil)

	_, err := resolveChainConfigMismatchPolicy(ctx, "not-a-policy")
	if err == nil {
		t.Fatal("expected error for invalid configured policy")
	}
	const want = "invalid ChainConfigMismatchPolicy in config"
	if !strings.HasPrefix(err.Error(), want) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSetBootstrapNodesV5UsesStrictEmptyDefaults(t *testing.T) {
	tests := []struct {
		name  string
		flags map[string]string
	}{
		{
			name:  "mainnet defaults",
			flags: map[string]string{},
		},
		{
			name: "testnet defaults",
			flags: map[string]string{
				TestnetFlag.Name: "true",
			},
		},
		{
			name: "devnet defaults",
			flags: map[string]string{
				DevnetFlag.Name: "true",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			set := flag.NewFlagSet("set-bootstrapnodesv5-test", flag.ContinueOnError)
			set.Bool(TestnetFlag.Name, false, "")
			set.Bool(DevnetFlag.Name, false, "")
			set.String(BootnodesFlag.Name, "", "")
			set.String(LegacyBootnodesV5Flag.Name, "", "")
			for name, value := range tt.flags {
				if err := set.Set(name, value); err != nil {
					t.Fatalf("failed to set flag %s: %v", name, err)
				}
			}

			ctx := cli.NewContext(cli.NewApp(), set, nil)
			cfg := new(p2p.Config)
			setBootstrapNodesV5(ctx, cfg)

			if len(cfg.BootstrapNodesV5) != 0 {
				t.Fatalf("expected empty v5 defaults, got %d entries", len(cfg.BootstrapNodesV5))
			}
		})
	}
}

// newMakeChainTestCLIContext builds a minimal CLI context for MakeChain tests.
func newMakeChainTestCLIContext(t *testing.T, values map[string]string) *cli.Context {
	t.Helper()
	set := flag.NewFlagSet("make-chain-test", flag.ContinueOnError)
	set.Bool(TestnetFlag.Name, false, "")
	set.Bool(AllowBuiltInConfigOverrideFlag.Name, false, "")
	set.String(ChainConfigMismatchPolicyFlag.Name, core.DefaultChainConfigMismatchPolicy.String(), "")
	set.String(GCModeFlag.Name, "full", "")
	for name, value := range values {
		if err := set.Set(name, value); err != nil {
			t.Fatalf("failed to set flag %s: %v", name, err)
		}
	}
	return cli.NewContext(cli.NewApp(), set, nil)
}

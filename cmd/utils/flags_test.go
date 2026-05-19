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
	"log"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/node"
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
		TestnetFlag.Name: "true",
		GCModeFlag.Name:  "full",
	})
	chain, reopenedDb := MakeChain(ctx, stack, false)
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

	chain, err := core.NewBlockChainReadOnlyResolved(readonlyDb, nil, genesis, ethash.NewFaker(), vm.Config{}, config, ghash, compatErr)
	if chain != nil {
		chain.Stop()
		t.Fatal("expected readonly blockchain open to fail")
	}
	if !errors.Is(err, core.ErrReadOnlyConfigRewind) {
		t.Fatalf("unexpected error: have %v want %v", err, core.ErrReadOnlyConfigRewind)
	}
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
			want: "Can't open blockchain in readonly mode: the local chain configuration requires rewind. Use the correct --networkid/--datadir combination, or reopen the database in writable mode so the chain can rewind, then retry.",
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
}

// newMakeChainTestCLIContext builds a minimal CLI context for MakeChain tests.
func newMakeChainTestCLIContext(t *testing.T, values map[string]string) *cli.Context {
	t.Helper()
	set := flag.NewFlagSet("make-chain-test", flag.ContinueOnError)
	set.Bool(TestnetFlag.Name, false, "")
	set.Bool(AllowBuiltInConfigOverrideFlag.Name, false, "")
	set.String(GCModeFlag.Name, "full", "")
	for name, value := range values {
		if err := set.Set(name, value); err != nil {
			t.Fatalf("failed to set flag %s: %v", name, err)
		}
	}
	return cli.NewContext(cli.NewApp(), set, nil)
}

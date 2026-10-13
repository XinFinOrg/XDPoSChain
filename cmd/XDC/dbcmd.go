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
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"time"

	"github.com/XinFinOrg/XDPoSChain/cmd/utils"
	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/common/hexutil"
	"github.com/XinFinOrg/XDPoSChain/console/prompt"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/ethdb"
	"github.com/XinFinOrg/XDPoSChain/log"
	"github.com/XinFinOrg/XDPoSChain/trie"
	"github.com/urfave/cli/v2"
)

var (
	removeStateDataFlag = &cli.BoolFlag{
		Name:  "remove.state",
		Usage: "If set, selects the state data for removal",
	}
	removeChainDataFlag = &cli.BoolFlag{
		Name:  "remove.chain",
		Usage: "If set, selects the ancient chain data for removal",
	}

	removedbCommand = &cli.Command{
		Action:    removeDB,
		Name:      "removedb",
		Usage:     "Remove blockchain and state databases",
		ArgsUsage: " ",
		Flags: slices.Concat(utils.DatabaseFlags,
			[]cli.Flag{removeStateDataFlag, removeChainDataFlag}),
		Description: `
Remove blockchain and state databases. The key-value store (recent blocks and
state) and the ancient chain store are confirmed separately.`,
	}
	dbCommand = &cli.Command{
		Name:      "db",
		Usage:     "Low level database operations",
		ArgsUsage: "",
		Subcommands: []*cli.Command{
			dbInspectCmd,
			dbStatCmd,
			dbCompactCmd,
			dbGetCmd,
			dbDeleteCmd,
			dbPutCmd,
			dbGetSlotsCmd,
			dbDumpFreezerIndex,
		},
	}
	dbInspectCmd = &cli.Command{
		Action:    inspect,
		Name:      "inspect",
		ArgsUsage: "<prefix> <start>",
		Flags: slices.Concat([]cli.Flag{
			utils.SyncModeFlag,
		}, utils.NetworkFlags, utils.DatabaseFlags),
		Usage:       "Inspect the storage size for each type of data in the database",
		Description: `This commands iterates the entire database. If the optional 'prefix' and 'start' arguments are provided, then the iteration is limited to the given subset of data.`,
	}
	dbStatCmd = &cli.Command{
		Action: dbStats,
		Name:   "stats",
		Usage:  "Print leveldb statistics",
		Flags: slices.Concat([]cli.Flag{
			utils.SyncModeFlag,
		}, utils.NetworkFlags, utils.DatabaseFlags),
	}
	dbCompactCmd = &cli.Command{
		Action: dbCompact,
		Name:   "compact",
		Usage:  "Compact leveldb database. WARNING: May take a very long time",
		Flags: slices.Concat([]cli.Flag{
			utils.SyncModeFlag,
			utils.CacheFlag,
			utils.CacheDatabaseFlag,
		}, utils.NetworkFlags, utils.DatabaseFlags),
		Description: `This command performs a database compaction.
WARNING: This operation may take a very long time to finish, and may cause database
corruption if it is aborted during execution'!`,
	}
	dbGetCmd = &cli.Command{
		Action:    dbGet,
		Name:      "get",
		Usage:     "Show the value of a database key",
		ArgsUsage: "<hex-encoded key>",
		Flags: slices.Concat([]cli.Flag{
			utils.SyncModeFlag,
		}, utils.NetworkFlags, utils.DatabaseFlags),
		Description: "This command looks up the specified database key from the database.",
	}
	dbDeleteCmd = &cli.Command{
		Action:    dbDelete,
		Name:      "delete",
		Usage:     "Delete a database key (WARNING: may corrupt your database)",
		ArgsUsage: "<hex-encoded key>",
		Flags: slices.Concat([]cli.Flag{
			utils.SyncModeFlag,
		}, utils.NetworkFlags, utils.DatabaseFlags),
		Description: `This command deletes the specified database key from the database.
WARNING: This is a low-level operation which may cause database corruption!`,
	}
	dbPutCmd = &cli.Command{
		Action:    dbPut,
		Name:      "put",
		Usage:     "Set the value of a database key (WARNING: may corrupt your database)",
		ArgsUsage: "<hex-encoded key> <hex-encoded value>",
		Flags: slices.Concat([]cli.Flag{
			utils.SyncModeFlag,
		}, utils.NetworkFlags, utils.DatabaseFlags),
		Description: `This command sets a given database key to the given value.
WARNING: This is a low-level operation which may cause database corruption!`,
	}
	dbGetSlotsCmd = &cli.Command{
		Action:    dbDumpTrie,
		Name:      "dumptrie",
		Usage:     "Show the storage key/values of a given storage trie",
		ArgsUsage: "<hex-encoded state root> <hex-encoded account hash> <hex-encoded storage trie root> <hex-encoded start (optional)> <int max elements (optional)>",
		Flags: slices.Concat([]cli.Flag{
			utils.SyncModeFlag,
		}, utils.NetworkFlags, utils.DatabaseFlags),
		Description: "This command looks up the specified database key from the database.",
	}
	dbDumpFreezerIndex = &cli.Command{
		Action:      freezerInspect,
		Name:        "freezer-index",
		Usage:       "Dump out the index of a specific freezer table",
		ArgsUsage:   "<freezer-type> <table-type> <start (int)> <end (int)>",
		Flags:       slices.Concat(utils.NetworkFlags, utils.DatabaseFlags),
		Description: "This command displays information about the freezer index.",
	}
)

func removeDB(ctx *cli.Context) error {
	stack, config := makeConfigNode(ctx)

	// Delete the key-value store. removeFolder leaves subfolders alone, so the
	// default ancient location inside chaindata survives this step.
	confirmAndRemoveDB(stack.ResolvePath("chaindata"), "state data", ctx, removeStateDataFlag.Name)

	// Delete the ancient chain
	ancientDir := stack.ResolveAncient("chaindata", config.Eth.DatabaseFreezer)
	confirmAndRemoveDB(filepath.Join(ancientDir, rawdb.ChainFreezerName), "ancient chain", ctx, removeChainDataFlag.Name)
	return nil
}

// removeFolder deletes all files (not folders) inside the directory 'dir' (but
// not files in subfolders).
func removeFolder(dir string) {
	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		// If we're at the top level folder, recurse into
		if path == dir {
			return nil
		}
		// Delete all the files, but not subfolders
		if !info.IsDir() {
			os.Remove(path)
			return nil
		}
		return filepath.SkipDir
	})
}

// confirmAndRemoveDB prompts the user for a last confirmation and removes the
// folder if accepted. If the flag removeFlagName is set, its value is used as
// the answer instead of prompting.
func confirmAndRemoveDB(path string, kind string, ctx *cli.Context, removeFlagName string) {
	if !common.FileExist(path) {
		log.Info("Database doesn't exist, skipping", "kind", kind, "path", path)
		return
	}
	var (
		confirm bool
		err     error
	)
	if ctx.IsSet(removeFlagName) {
		confirm = ctx.Bool(removeFlagName)
	} else {
		confirm, err = prompt.Stdin.PromptConfirm(fmt.Sprintf("Remove %s (%s)?", kind, path))
	}
	switch {
	case err != nil:
		utils.Fatalf("%v", err)
	case !confirm:
		log.Warn("Database deletion skipped", "kind", kind, "path", path)
	default:
		start := time.Now()
		removeFolder(path)
		log.Info("Database successfully deleted", "kind", kind, "path", path, "elapsed", common.PrettyDuration(time.Since(start)))
	}
}

func inspect(ctx *cli.Context) error {
	var (
		prefix []byte
		start  []byte
	)
	if ctx.NArg() > 2 {
		return fmt.Errorf("max 2 arguments: %v", ctx.Command.ArgsUsage)
	}
	if ctx.NArg() >= 1 {
		if d, err := hexutil.Decode(ctx.Args().Get(0)); err != nil {
			return fmt.Errorf("failed to hex-decode 'prefix': %v", err)
		} else {
			prefix = d
		}
	}
	if ctx.NArg() >= 2 {
		if d, err := hexutil.Decode(ctx.Args().Get(1)); err != nil {
			return fmt.Errorf("failed to hex-decode 'start': %v", err)
		} else {
			start = d
		}
	}
	stack, _ := makeConfigNode(ctx)
	defer stack.Close()

	db := utils.MakeChainDatabase(ctx, stack, true)
	defer db.Close()

	return rawdb.InspectDatabase(db, prefix, start)
}

func showLeveldbStats(db ethdb.Stater) {
	if stats, err := db.Stat("leveldb.stats"); err != nil {
		log.Warn("Failed to read database stats", "error", err)
	} else {
		fmt.Println(stats)
	}
	if ioStats, err := db.Stat("leveldb.iostats"); err != nil {
		log.Warn("Failed to read database iostats", "error", err)
	} else {
		fmt.Println(ioStats)
	}
}

func dbStats(ctx *cli.Context) error {
	stack, _ := makeConfigNode(ctx)
	defer stack.Close()

	db := utils.MakeChainDatabase(ctx, stack, true)
	defer db.Close()

	showLeveldbStats(db)
	return nil
}

func dbCompact(ctx *cli.Context) error {
	stack, _ := makeConfigNode(ctx)
	defer stack.Close()

	db := utils.MakeChainDatabase(ctx, stack, false)
	defer db.Close()

	log.Info("Stats before compaction")
	showLeveldbStats(db)

	log.Info("Triggering compaction")
	if err := db.Compact(nil, nil); err != nil {
		log.Info("Compact err", "error", err)
		return err
	}

	log.Info("Stats after compaction")
	showLeveldbStats(db)
	return nil
}

// dbGet shows the value of a given database key
func dbGet(ctx *cli.Context) error {
	if ctx.NArg() != 1 {
		return fmt.Errorf("required arguments: %v", ctx.Command.ArgsUsage)
	}
	stack, _ := makeConfigNode(ctx)
	defer stack.Close()

	db := utils.MakeChainDatabase(ctx, stack, true)
	defer db.Close()

	key, err := common.ParseHexOrString(ctx.Args().Get(0))
	if err != nil {
		log.Info("Could not decode the key", "error", err)
		return err
	}

	data, err := db.Get(key)
	if err != nil {
		log.Info("Get operation failed", "key", fmt.Sprintf("%#x", key), "error", err)
		return err
	}
	fmt.Printf("key %#x:\n\t%#x\n", key, data)
	return nil
}

// dbDelete deletes a key from the database
func dbDelete(ctx *cli.Context) error {
	if ctx.NArg() != 1 {
		return fmt.Errorf("required arguments: %v", ctx.Command.ArgsUsage)
	}
	stack, _ := makeConfigNode(ctx)
	defer stack.Close()

	db := utils.MakeChainDatabase(ctx, stack, false)
	defer db.Close()

	key, err := common.ParseHexOrString(ctx.Args().Get(0))
	if err != nil {
		log.Info("Could not decode the key", "error", err)
		return err
	}
	data, err := db.Get(key)
	if err == nil {
		fmt.Printf("Previous value: %#x\n", data)
	}
	if err = db.Delete(key); err != nil {
		log.Info("Delete operation returned an error", "key", fmt.Sprintf("%#x", key), "error", err)
		return err
	}
	return nil
}

// dbPut overwrite a value in the database
func dbPut(ctx *cli.Context) error {
	if ctx.NArg() != 2 {
		return fmt.Errorf("required arguments: %v", ctx.Command.ArgsUsage)
	}
	stack, _ := makeConfigNode(ctx)
	defer stack.Close()

	db := utils.MakeChainDatabase(ctx, stack, false)
	defer db.Close()

	var (
		key   []byte
		value []byte
		data  []byte
		err   error
	)
	key, err = common.ParseHexOrString(ctx.Args().Get(0))
	if err != nil {
		log.Info("Could not decode the key", "error", err)
		return err
	}
	value, err = hexutil.Decode(ctx.Args().Get(1))
	if err != nil {
		log.Info("Could not decode the value", "error", err)
		return err
	}
	data, err = db.Get(key)
	if err == nil {
		fmt.Printf("Previous value:\n%#x\n", data)
	}
	return db.Put(key, value)
}

// dbDumpTrie shows the key-value slots of a given storage trie
func dbDumpTrie(ctx *cli.Context) error {
	if ctx.NArg() < 3 {
		return fmt.Errorf("required arguments: %v", ctx.Command.ArgsUsage)
	}
	stack, _ := makeConfigNode(ctx)
	defer stack.Close()

	db := utils.MakeChainDatabase(ctx, stack, true)
	defer db.Close()

	var (
		state   []byte
		storage []byte
		account []byte
		start   []byte
		max     = int64(-1)
		err     error
	)
	if state, err = hexutil.Decode(ctx.Args().Get(0)); err != nil {
		log.Info("Could not decode the state root", "error", err)
		return err
	}
	if account, err = hexutil.Decode(ctx.Args().Get(1)); err != nil {
		log.Info("Could not decode the account hash", "error", err)
		return err
	}
	if storage, err = hexutil.Decode(ctx.Args().Get(2)); err != nil {
		log.Info("Could not decode the storage trie root", "error", err)
		return err
	}
	if ctx.NArg() > 3 {
		if start, err = hexutil.Decode(ctx.Args().Get(3)); err != nil {
			log.Info("Could not decode the seek position", "error", err)
			return err
		}
	}
	if ctx.NArg() > 4 {
		if max, err = strconv.ParseInt(ctx.Args().Get(4), 10, 64); err != nil {
			log.Info("Could not decode the max count", "error", err)
			return err
		}
	}
	id := trie.StorageTrieID(common.BytesToHash(state), common.BytesToHash(account), common.BytesToHash(storage))
	theTrie, err := trie.New(id, trie.NewDatabase(db))
	if err != nil {
		return err
	}
	trieIt, err := theTrie.NodeIterator(start)
	if err != nil {
		return err
	}
	var count int64
	it := trie.NewIterator(trieIt)
	for it.Next() {
		if max > 0 && count == max {
			fmt.Printf("Exiting after %d values\n", count)
			break
		}
		fmt.Printf("  %d. key %#x: %#x\n", count, it.Key, it.Value)
		count++
	}
	return it.Err
}

func freezerInspect(ctx *cli.Context) error {
	if ctx.NArg() < 4 {
		return fmt.Errorf("required arguments: %v", ctx.Command.ArgsUsage)
	}
	var (
		freezer = ctx.Args().Get(0)
		table   = ctx.Args().Get(1)
	)
	start, err := strconv.ParseInt(ctx.Args().Get(2), 10, 64)
	if err != nil {
		log.Info("Could not read start-param", "err", err)
		return err
	}
	end, err := strconv.ParseInt(ctx.Args().Get(3), 10, 64)
	if err != nil {
		log.Info("Could not read count param", "err", err)
		return err
	}
	stack, _ := makeConfigNode(ctx)
	ancient := stack.ResolveAncient("chaindata", ctx.String(utils.AncientFlag.Name))
	stack.Close()
	return rawdb.InspectFreezerTable(ancient, freezer, table, start, end)
}

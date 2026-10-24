// Copyright 2026 The XDPoSChain Authors
// This file is part of the XDPoSChain library.
//
// The XDPoSChain library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The XDPoSChain library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the XDPoSChain library. If not, see <http://www.gnu.org/licenses/>.

package eth

import (
	"errors"
	"fmt"

	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/eth/ethconfig"
	"github.com/XinFinOrg/XDPoSChain/ethdb"
	"github.com/XinFinOrg/XDPoSChain/log"
)

var (
	// errHistoryModeArchive is returned when minimal history mode is combined
	// with an archive node, a self-contradictory configuration.
	errHistoryModeArchive = errors.New("--history.mode minimal cannot be combined with --gcmode archive")

	// errHistoryModeDowngrade is returned when a datadir that runs in minimal
	// history mode is started in full mode.
	errHistoryModeDowngrade = errors.New("this datadir has pruned history and cannot be run in full mode; resync required")
)

// setupHistoryMode validates the configured history mode against the one the
// database runs in, and records it. Switching a full datadir to minimal mode is
// allowed, pruning starts with the next freeze cycle; the opposite is refused,
// since the pruned history cannot be restored.
//
// The chain freezer prunes based on the stored mode, not on the configuration,
// so tools that open the database (import, export, ...) keep a minimal datadir
// minimal without being told.
func setupHistoryMode(db ethdb.KeyValueStore, config *ethconfig.Config) error {
	mode := config.HistoryMode
	if !mode.IsValid() {
		return fmt.Errorf("invalid history mode %d", uint32(mode))
	}
	if mode == rawdb.HistoryModeMinimal && config.NoPruning {
		return errHistoryModeArchive
	}
	switch stored := rawdb.ReadHistoryMode(db); {
	case stored == rawdb.HistoryModeMinimal && mode == rawdb.HistoryModeFull:
		return errHistoryModeDowngrade
	case stored == rawdb.HistoryModeFull && mode == rawdb.HistoryModeMinimal:
		log.Warn("Switching datadir to minimal history mode, frozen block bodies and receipts will be pruned. This cannot be undone")
		rawdb.WriteHistoryMode(db, mode)
	}
	if mode == rawdb.HistoryModeMinimal {
		log.Warn("Node running in minimal history mode")
		log.Warn("This node prunes block bodies and receipts and CANNOT serve historical chain data to syncing peers")
		log.Warn("A network needs at least one full-history node to bootstrap new members")
		log.Warn("Pruning is irreversible for this datadir")
	}
	return nil
}

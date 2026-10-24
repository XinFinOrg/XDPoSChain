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

package rawdb

import (
	"fmt"

	"github.com/XinFinOrg/XDPoSChain/ethdb"
	"github.com/XinFinOrg/XDPoSChain/log"
)

// HistoryMode configures how much block history a node retains.
type HistoryMode uint32

const (
	// HistoryModeFull retains the bodies and receipts of every block.
	HistoryModeFull HistoryMode = iota

	// HistoryModeMinimal retains the full header chain, but prunes the frozen
	// bodies and receipts down to the newest data file of each ancient table.
	// Pruning is irreversible for a datadir.
	HistoryModeMinimal
)

// IsValid reports whether mode is a known history mode.
func (mode HistoryMode) IsValid() bool {
	return mode == HistoryModeFull || mode == HistoryModeMinimal
}

// String implements the stringer interface.
func (mode HistoryMode) String() string {
	switch mode {
	case HistoryModeFull:
		return "full"
	case HistoryModeMinimal:
		return "minimal"
	default:
		return fmt.Sprintf("unknown(%d)", uint32(mode))
	}
}

// MarshalText implements encoding.TextMarshaler.
func (mode HistoryMode) MarshalText() ([]byte, error) {
	if !mode.IsValid() {
		return nil, fmt.Errorf("unknown history mode %d", uint32(mode))
	}
	return []byte(mode.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (mode *HistoryMode) UnmarshalText(text []byte) error {
	switch string(text) {
	case "full":
		*mode = HistoryModeFull
	case "minimal":
		*mode = HistoryModeMinimal
	default:
		return fmt.Errorf(`unknown history mode %q, want "full" or "minimal"`, text)
	}
	return nil
}

// ReadHistoryMode retrieves the history mode the database runs in. A database
// that never stored one runs in full mode.
func ReadHistoryMode(db ethdb.KeyValueReader) HistoryMode {
	data, _ := db.Get(historyModeKey)
	if len(data) == 0 {
		return HistoryModeFull
	}
	var mode HistoryMode
	if err := mode.UnmarshalText(data); err != nil {
		// Never treat an unreadable marker as full mode: a minimal database
		// opened as a full one would serve a history it no longer has.
		log.Crit("Invalid history mode in database", "mode", string(data), "err", err)
	}
	return mode
}

// WriteHistoryMode stores the history mode the database runs in.
func WriteHistoryMode(db ethdb.KeyValueWriter, mode HistoryMode) {
	data, err := mode.MarshalText()
	if err != nil {
		log.Crit("Failed to encode history mode", "err", err)
	}
	if err := db.Put(historyModeKey, data); err != nil {
		log.Crit("Failed to store history mode", "err", err)
	}
}

// IsBlockDataPruned reports whether the body and receipts of the canonical
// block at the given number have been pruned from the ancient store. A
// database without a freezer never prunes.
func IsBlockDataPruned(db ethdb.AncientReader, number uint64) bool {
	tail, err := db.Tail(ChainFreezerBlockDataGroup)
	return err == nil && number < tail
}

// PrunedHistoryError is returned when the requested block data has been pruned
// by minimal history mode.
type PrunedHistoryError struct{}

// ErrPrunedHistory is the error value of PrunedHistoryError.
var ErrPrunedHistory error = &PrunedHistoryError{}

func (e *PrunedHistoryError) Error() string {
	return "block body pruned; node runs in minimal history mode"
}

// ErrorCode implements rpc.Error. The code matches the one go-ethereum returns
// for pruned history.
func (e *PrunedHistoryError) ErrorCode() int { return 4444 }

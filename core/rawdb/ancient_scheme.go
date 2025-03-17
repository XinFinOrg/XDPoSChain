// Copyright 2022 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package rawdb

// The list of table names of chain freezer.
const (
	// chainFreezerHeaderTable indicates the name of the freezer header table.
	chainFreezerHeaderTable = "headers"

	// chainFreezerHashTable indicates the name of the freezer canonical hash table.
	chainFreezerHashTable = "hashes"

	// chainFreezerBodiesTable indicates the name of the freezer block body table.
	chainFreezerBodiesTable = "bodies"

	// chainFreezerReceiptTable indicates the name of the freezer receipts table.
	chainFreezerReceiptTable = "receipts"

	// chainFreezerDifficultyTable indicates the name of the freezer total difficulty table.
	chainFreezerDifficultyTable = "diffs"
)

// chainFreezerTableConfigs configures the settings for tables in the chain freezer.
// Compression is disabled for hashes as they don't compress well. Additionally,
// tail truncation is disabled for the header and hash tables, as these are intended
// to be retained long-term.
var chainFreezerTableConfigs = map[string]freezerTableConfig{
	chainFreezerHeaderTable:     {noSnappy: false, prunable: false},
	chainFreezerHashTable:       {noSnappy: true, prunable: false},
	chainFreezerBodiesTable:     {noSnappy: false, prunable: true},
	chainFreezerReceiptTable:    {noSnappy: false, prunable: true},
	chainFreezerDifficultyTable: {noSnappy: true, prunable: true},
}

// freezerTableConfig contains the settings for a freezer table.
type freezerTableConfig struct {
	noSnappy bool // disables item compression
	prunable bool // true for tables that can be pruned by TruncateTail
}

// The list of identifiers of ancient stores.
var (
	chainFreezerName = "chain" // the folder name of chain segment ancient store.
)

// freezers the collections of all builtin freezers.
var freezers = []string{chainFreezerName}
